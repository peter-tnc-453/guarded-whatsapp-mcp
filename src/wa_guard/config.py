"""Configuration loading for guarded-whatsapp-mcp.

Settings + recipient allowlist live in a YAML file. Resolution order:
  1. $WA_GUARD_CONFIG (explicit path)
  2. ./config/allowlist.yaml  (next to the repo)
  3. ~/.guarded-whatsapp-mcp/allowlist.yaml

The real allowlist is intentionally git-ignored; ship allowlist.example.yaml instead.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

STATE_DIR = Path(os.path.expanduser("~/.guarded-whatsapp-mcp"))
DEFAULT_AUDIT_PATH = STATE_DIR / "audit.jsonl"
DEFAULT_RATE_STATE = STATE_DIR / "ratestate.json"

# Sensible defaults so a missing/partial config still fails safe (closed).
_DEFAULTS: dict[str, Any] = {
    "bridge_url": "http://localhost:8080/api",
    "allow_unlisted": False,            # fail-closed: only known recipients
    "require_confirm_for": ["unlisted"],  # subset of: unlisted, files, messages, all
    "rate_limit": {"per_minute": 10, "per_hour": 60},
    "files": {
        "max_size_mb": 100,
        "allowed_ext": [
            ".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
            ".png", ".jpg", ".jpeg", ".gif", ".webp",
            ".txt", ".md", ".csv", ".json", ".zip",
            ".mp3", ".ogg", ".mp4", ".mov",
        ],
    },
    "secrets": {"on_detect": "block"},   # block | warn
    "recipients": [],
}


@dataclass
class Recipient:
    name: str
    jid: str
    note: str = ""

    @property
    def normalized_jid(self) -> str:
        """Bridge accepts a bare number or a full JID. Keep groups (@g.us) as-is,
        strip a leading + from phone numbers."""
        j = self.jid.strip()
        if "@" in j:
            return j
        return j.lstrip("+")


@dataclass
class Config:
    bridge_url: str
    allow_unlisted: bool
    require_confirm_for: list[str]
    rate_limit: dict[str, int]
    files: dict[str, Any]
    secrets: dict[str, Any]
    recipients: list[Recipient] = field(default_factory=list)
    source_path: str = ""

    # ---- lookup helpers -------------------------------------------------
    def find_recipient(self, query: str) -> Recipient | None:
        """Match an allowlist entry by friendly name (case-insensitive,
        substring) or by exact/numeric JID."""
        q = (query or "").strip()
        if not q:
            return None
        ql = q.lower()
        q_digits = "".join(ch for ch in q if ch.isdigit())
        for r in self.recipients:
            if r.name.lower() == ql or ql in r.name.lower():
                return r
            rj = r.normalized_jid
            if rj == q or rj.lstrip("+") == q.lstrip("+"):
                return r
            r_digits = "".join(ch for ch in rj if ch.isdigit())
            if q_digits and r_digits and q_digits == r_digits:
                return r
        return None


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _candidate_paths() -> list[Path]:
    paths = []
    env = os.environ.get("WA_GUARD_CONFIG")
    if env:
        paths.append(Path(os.path.expanduser(env)))
    repo_cfg = Path(__file__).resolve().parents[2] / "config" / "allowlist.yaml"
    paths.append(repo_cfg)
    paths.append(STATE_DIR / "allowlist.yaml")
    return paths


def load_config() -> Config:
    raw: dict[str, Any] = {}
    found = ""
    for p in _candidate_paths():
        if p.is_file():
            with open(p, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            found = str(p)
            break

    merged = _deep_merge(_DEFAULTS, raw)
    recipients = [
        Recipient(name=str(r["name"]), jid=str(r["jid"]), note=str(r.get("note", "")))
        for r in merged.get("recipients", [])
        if r.get("name") and r.get("jid")
    ]
    return Config(
        bridge_url=str(merged["bridge_url"]).rstrip("/"),
        allow_unlisted=bool(merged["allow_unlisted"]),
        require_confirm_for=list(merged["require_confirm_for"]),
        rate_limit=dict(merged["rate_limit"]),
        files=dict(merged["files"]),
        secrets=dict(merged["secrets"]),
        recipients=recipients,
        source_path=found,
    )
