#!/usr/bin/env python3
"""Self-contained demo of the guard in action — for the README gif.

SAFE: it never touches WhatsApp. It runs the REAL security gate
(`wa_guard.guard.evaluate`) against a throwaway allowlist + temp state, and
simulates the bridge so a "sent" result sends nothing. Every verdict shown is
produced by the actual gate code.
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wa_guard import audit, guard  # noqa: E402
from wa_guard.config import Config, Recipient  # noqa: E402

# ---- pretty printing --------------------------------------------------------
G, R, Y, B, DIM, BOLD, X = "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[2m", "\033[1m", "\033[0m"
PAUSE = 1.1


def step(title: str) -> None:
    time.sleep(PAUSE)
    print(f"\n{DIM}${X} {BOLD}{title}{X}")
    time.sleep(0.5)


def ok(msg: str) -> None:
    print(f"  {G}✓ {msg}{X}")


def blocked(msg: str) -> None:
    print(f"  {R}✗ BLOCKED{X} — {msg}")


def info(msg: str) -> None:
    print(f"  {DIM}{msg}{X}")


# ---- throwaway environment --------------------------------------------------
TMP = Path(tempfile.mkdtemp(prefix="waguard_demo_"))
RATE = TMP / "rate.json"
AUDIT = TMP / "audit.jsonl"

CFG = Config(
    bridge_url="http://localhost:8080/api",
    allow_unlisted=False,
    require_confirm_for=["files"],
    rate_limit={"per_minute": 20, "per_hour": 100},
    files={"max_size_mb": 100, "allowed_ext": [".pdf", ".png", ".txt"]},
    secrets={"on_detect": "block"},
    recipients=[
        Recipient("Alex (teammate)", "66800000001", "design"),
        Recipient("Team group", "120363000000000000@g.us", "ops"),
    ],
)


def simulated_send(v, *, tool, message=None, fname=None):
    """Stand-in for the bridge. Records to audit exactly like the server, but
    sends nothing."""
    base = {"tool": tool, "recipient_name": v.recipient_name,
            "recipient_jid": guard._mask_jid(v.recipient_jid), "allowlisted": v.is_listed}
    if fname:
        base["display_filename"] = fname
    if message:
        base.update(audit.preview_text(message))
    audit.record(AUDIT, {**base, "result": "sent"})


def main() -> None:
    print(f"{BOLD}{B}guarded-whatsapp-mcp{X}  {DIM}— every send passes the gate{X}")

    step("wa_list_recipients()")
    for r in CFG.recipients:
        info(f"• {r.name:<18} {guard._mask_jid(r.normalized_jid)}")

    step('wa_send_message("Alex", "Standup notes are up 👍")')
    v = guard.evaluate(CFG, recipient="Alex", message="Standup notes are up", state_path=RATE)
    if v.ok:
        simulated_send(v, tool="wa_send_message", message="Standup notes are up")
        ok(f"sent to {v.recipient_name}")

    step('wa_send_message("Alex", "deploy key AKIA... sk-...")   # oops, a secret')
    v = guard.evaluate(CFG, recipient="Alex",
                       message="here is the key api_key = sk-ABCD1234EFGH5678IJKL", state_path=RATE)
    blocked(v.blocked_reason) if not v.ok else ok("sent")
    audit.record(AUDIT, {"tool": "wa_send_message", "recipient_name": "Alex",
                         "result": "blocked", "reason": "secret detected"})

    step('wa_send_message("+66999999999", "hi")   # a number nobody allowlisted')
    v = guard.evaluate(CFG, recipient="66999999999", message="hi", state_path=RATE)
    blocked(v.blocked_reason) if not v.ok else ok("sent")
    audit.record(AUDIT, {"tool": "wa_send_message", "recipient_name": "(unlisted)",
                         "result": "blocked", "reason": "not allowlisted"})

    # a real temp file to send
    f = TMP / "เอกสาร-report.pdf"
    f.write_bytes(b"%PDF-1.4 demo")

    step('wa_send_file("Team group", "เอกสาร-report.pdf")   # files need a preview')
    v = guard.evaluate(CFG, recipient="Team group", file_path=str(f), state_path=RATE)
    if v.needs_confirm:
        print(f"  {Y}⧗ confirmation required{X} — preview first")
        info(f"safe filename: {v.display_filename}   (was Thai → ASCII)")
        info(f"confirm_token: {v.confirm_token}")
        token = v.confirm_token

        step(f'wa_send_file("Team group", "...", confirm_token="{token}")')
        v2 = guard.evaluate(CFG, recipient="Team group", file_path=str(f),
                            confirm_token=token, state_path=RATE)
        if v2.ok:
            simulated_send(v2, tool="wa_send_file", fname=v2.display_filename)
            ok(f"sent {v2.display_filename} to {v2.recipient_name}")

    step("wa_audit_tail(5)")
    for e in audit.tail(AUDIT, 5):
        mark = f"{G}sent{X}" if e.get("result") == "sent" else f"{R}blocked{X}"
        info(f"{e['ts'][11:19]}  [{mark}{DIM}]  {e['tool']:<16} → {e.get('recipient_name','')}")

    time.sleep(PAUSE)
    print(f"\n{G}{BOLD}✓ good sends through · bad sends blocked · all of it logged.{X}\n")


if __name__ == "__main__":
    main()
