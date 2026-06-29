"""Security checks — the trust layer of nene-whatsapp-guard.

Every send passes through `evaluate()` which runs, in order:
  1. recipient allowlist resolution     (who can we message at all)
  2. secret / PII scanning on the text  (don't leak credentials)
  3. file validation + filename sanitize (safe attachments)
  4. rate limiting                       (no runaway sends)
  5. confirmation-gate decision          (require an explicit token for risky sends)

It NEVER sends anything itself — it returns a verdict the server acts on.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config, Recipient

# --- secret / PII signatures -------------------------------------------------
# Tuple: (label, severity, compiled-regex). severity high => credential leak.
_SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("private_key_block", "high", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret", "high", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*\S{20,}")),
    ("slack_token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("github_pat", "high", re.compile(r"\bghp_[0-9A-Za-z]{30,}\b")),
    ("openai_key", "high", re.compile(r"\bsk-[0-9A-Za-z]{20,}\b")),
    ("bearer_token", "high", re.compile(r"\bBearer\s+[0-9A-Za-z._\-]{20,}")),
    ("generic_secret_assignment", "high", re.compile(
        r"(?i)\b(api[_-]?key|secret|access[_-]?token|password|passwd|pwd|private[_-]?key)\b\s*[:=]\s*['\"]?\S{8,}")),
    ("jwt", "medium", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("thai_national_id", "medium", re.compile(r"(?<!\d)\d{13}(?!\d)")),
]


def scan_secrets(text: str | None) -> list[dict[str, str]]:
    """Return a list of {label, severity, sample} for anything that looks like a
    credential or sensitive PII. Empty list => clean."""
    if not text:
        return []
    findings: list[dict[str, str]] = []
    for label, severity, rx in _SECRET_PATTERNS:
        m = rx.search(text)
        if not m:
            continue
        if label == "thai_national_id" and not _luhn_like_13(m.group(0)):
            # keep it as a soft PII flag regardless; thai ID has its own checksum
            pass
        sample = m.group(0)
        masked = sample[:4] + "…" + sample[-2:] if len(sample) > 8 else "…"
        findings.append({"label": label, "severity": severity, "sample": masked})
    # credit-card: digits 13-19 that pass Luhn
    for cand in re.findall(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)", text):
        digits = re.sub(r"\D", "", cand)
        if 13 <= len(digits) <= 19 and _luhn(digits):
            findings.append({"label": "credit_card", "severity": "high", "sample": "…" + digits[-4:]})
            break
    return findings


def _luhn(num: str) -> bool:
    total, alt = 0, False
    for ch in reversed(num):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _luhn_like_13(num: str) -> bool:
    return len(num) == 13 and num.isdigit()


# --- filename sanitisation ---------------------------------------------------
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str) -> str:
    """Produce an ASCII-safe basename. Non-ASCII (e.g. Thai) is transliterated
    away or replaced with '_' so WhatsApp shows a real filename instead of
    'Untitled', and so no path traversal is possible."""
    base = Path(name).name  # strip any directory component (traversal guard)
    stem = Path(base).stem
    suffix = Path(base).suffix
    ascii_stem = unicodedata.normalize("NFKD", stem).encode("ascii", "ignore").decode("ascii")
    ascii_stem = _SAFE_CHARS.sub("_", ascii_stem).strip("._-")
    if not ascii_stem:
        ascii_stem = "file_" + hashlib.sha1(stem.encode("utf-8")).hexdigest()[:8]
    ascii_suffix = _SAFE_CHARS.sub("", suffix)
    return ascii_stem + ascii_suffix


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --- verdict types -----------------------------------------------------------
@dataclass
class Verdict:
    ok: bool
    recipient_jid: str | None = None
    recipient_name: str | None = None
    is_listed: bool = False
    blocked_reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    secret_findings: list[dict] = field(default_factory=list)
    needs_confirm: bool = False
    confirm_token: str | None = None
    send_path: str | None = None      # sanitized temp path to hand the bridge
    display_filename: str | None = None
    file_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "recipient": {"name": self.recipient_name, "jid": _mask_jid(self.recipient_jid), "allowlisted": self.is_listed},
            "blocked_reason": self.blocked_reason,
            "warnings": self.warnings,
            "secret_findings": self.secret_findings,
            "needs_confirm": self.needs_confirm,
            "confirm_token": self.confirm_token,
            "display_filename": self.display_filename,
        }


def _mask_jid(jid: str | None) -> str | None:
    if not jid:
        return jid
    if "@" in jid:
        return jid
    return jid[:4] + "…" + jid[-3:] if len(jid) > 7 else jid


def _payload_token(jid: str, message: str | None, file_hash: str | None) -> str:
    h = hashlib.sha256()
    h.update((jid or "").encode())
    h.update(b"|")
    h.update((message or "").encode())
    h.update(b"|")
    h.update((file_hash or "").encode())
    return h.hexdigest()[:10]


# --- rate limiting (sliding window persisted to disk) -----------------------
def check_and_record_rate(cfg: Config, state_path: Path, *, dry: bool) -> tuple[bool, str | None]:
    now = time.time()
    try:
        events = json.loads(state_path.read_text()) if state_path.exists() else []
    except Exception:
        events = []
    events = [t for t in events if now - t < 3600]
    per_min = cfg.rate_limit.get("per_minute", 10)
    per_hour = cfg.rate_limit.get("per_hour", 60)
    in_min = sum(1 for t in events if now - t < 60)
    if in_min >= per_min:
        return False, f"rate limit: {per_min} sends/min reached"
    if len(events) >= per_hour:
        return False, f"rate limit: {per_hour} sends/hour reached"
    if not dry:
        events.append(now)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(events))
    return True, None


# --- the gate ----------------------------------------------------------------
def evaluate(
    cfg: Config,
    *,
    recipient: str,
    message: str | None = None,
    file_path: str | None = None,
    confirm_token: str | None = None,
    state_path: Path,
    dry_run: bool = False,
) -> Verdict:
    """Run all checks and return a Verdict. dry_run=True never mutates rate state
    and never copies files for sending (preview only)."""
    v = Verdict(ok=False)

    # 1) recipient allowlist
    rec: Recipient | None = cfg.find_recipient(recipient)
    if rec:
        v.recipient_jid, v.recipient_name, v.is_listed = rec.normalized_jid, rec.name, True
    else:
        # unlisted: accept a raw JID/number only if policy allows
        looks_like_jid = "@" in recipient or recipient.lstrip("+").isdigit()
        if not looks_like_jid:
            v.blocked_reason = (f"recipient '{recipient}' is not in the allowlist and is not a "
                                f"valid number/JID. Add them to config/allowlist.yaml.")
            return v
        if not cfg.allow_unlisted:
            v.blocked_reason = (f"recipient '{recipient}' is not allowlisted and allow_unlisted=false. "
                                f"Add them to config/allowlist.yaml or enable allow_unlisted to send.")
            return v
        v.recipient_jid = recipient.lstrip("+") if "@" not in recipient else recipient
        v.recipient_name = "(unlisted)"
        v.is_listed = False
        v.warnings.append("recipient is NOT allowlisted (allowed only because allow_unlisted=true)")

    # 2) secret / PII scan on message text
    findings = scan_secrets(message)
    if findings:
        v.secret_findings = findings
        high = [f for f in findings if f["severity"] == "high"]
        mode = cfg.secrets.get("on_detect", "block")
        if high and mode == "block":
            v.blocked_reason = ("message appears to contain secrets/credentials: "
                                + ", ".join(f["label"] for f in high)
                                + ". Remove them or set secrets.on_detect=warn to override.")
            return v
        v.warnings.append("possible sensitive content: " + ", ".join(f["label"] for f in findings))

    # 3) file validation + sanitisation
    if file_path:
        p = Path(file_path).expanduser()
        if not p.is_file():
            v.blocked_reason = f"file not found: {file_path}"
            return v
        ext = p.suffix.lower()
        allowed = [e.lower() for e in cfg.files.get("allowed_ext", [])]
        if allowed and ext not in allowed:
            v.blocked_reason = f"file type '{ext}' not allowed. Allowed: {', '.join(allowed)}"
            return v
        max_mb = float(cfg.files.get("max_size_mb", 100))
        size_mb = p.stat().st_size / (1024 * 1024)
        if size_mb > max_mb:
            v.blocked_reason = f"file is {size_mb:.1f} MB, over the {max_mb:.0f} MB limit"
            return v
        v.display_filename = sanitize_filename(p.name)
        v.file_sha256 = file_sha256(p)
        if not dry_run:
            tmp_dir = Path(tempfile.mkdtemp(prefix="waguard_"))
            safe = tmp_dir / v.display_filename
            shutil.copy2(p, safe)
            v.send_path = str(safe)
        else:
            v.send_path = str(p)

    # 4) rate limit
    ok, reason = check_and_record_rate(cfg, state_path, dry=dry_run)
    if not ok:
        v.blocked_reason = reason
        return v

    # 5) confirmation gate
    token = _payload_token(v.recipient_jid or "", message, v.file_sha256)
    triggers = set(cfg.require_confirm_for or [])
    needs = (
        "all" in triggers
        or ("unlisted" in triggers and not v.is_listed)
        or ("files" in triggers and bool(file_path))
        or ("messages" in triggers and message is not None and not file_path)
    )
    if needs and confirm_token != token:
        v.needs_confirm = True
        v.confirm_token = token
        v.blocked_reason = ("confirmation required for this send. Re-call with confirm_token to proceed "
                            "(this proves the send was previewed, not accidental).")
        return v

    v.ok = True
    return v
