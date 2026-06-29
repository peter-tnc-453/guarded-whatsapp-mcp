"""guarded-whatsapp-mcp — a governed WhatsApp MCP server.

Wraps the authenticated whatsapp-bridge transport with an allowlist, secret
scanning, file validation, rate limiting, a confirmation gate, and an append-only
audit log. Read tools are safe; send tools are gated.

Run (stdio):  python -m wa_guard
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import audit, guard
from .bridge import Bridge, BridgeError
from .config import DEFAULT_AUDIT_PATH, DEFAULT_RATE_STATE, load_config

mcp = FastMCP("guarded-whatsapp-mcp")

CFG = load_config()
BRIDGE = Bridge(CFG.bridge_url)
AUDIT_PATH = Path(DEFAULT_AUDIT_PATH)
RATE_PATH = Path(DEFAULT_RATE_STATE)


def _reload() -> None:
    """Pick up edits to the allowlist without restarting the server."""
    global CFG, BRIDGE
    CFG = load_config()
    BRIDGE = Bridge(CFG.bridge_url)


# --- read-only tools ---------------------------------------------------------
@mcp.tool()
def wa_list_recipients() -> dict[str, Any]:
    """List the allowlisted WhatsApp recipients this engine is permitted to message.
    Read-only. Numbers are masked. Use the returned `name` as the `recipient`
    argument to wa_preview / wa_send_message / wa_send_file."""
    _reload()
    return {
        "config_source": CFG.source_path or "(defaults — no config file found)",
        "allow_unlisted": CFG.allow_unlisted,
        "require_confirm_for": CFG.require_confirm_for,
        "recipients": [
            {"name": r.name, "jid_masked": guard._mask_jid(r.normalized_jid), "note": r.note}
            for r in CFG.recipients
        ],
    }


@mcp.tool()
def wa_preview(recipient: str, message: str | None = None, file_path: str | None = None) -> dict[str, Any]:
    """Dry-run a send: run every security check and report exactly what WOULD
    happen, WITHOUT sending. Returns a verdict and, when the send needs
    confirmation, a `confirm_token` to pass back to the send tool.
    Use this before any send you are unsure about."""
    _reload()
    v = guard.evaluate(
        CFG, recipient=recipient, message=message, file_path=file_path,
        state_path=RATE_PATH, dry_run=True,
    )
    return v.to_dict()


@mcp.tool()
def wa_audit_tail(limit: int = 20) -> list[dict[str, Any]]:
    """Return the most recent send-attempt audit records (allowed, blocked, or
    failed). Read-only. Message bodies are stored as a short preview + hash only."""
    return audit.tail(AUDIT_PATH, limit=max(1, min(limit, 200)))


# --- gated send tools --------------------------------------------------------
@mcp.tool()
def wa_send_message(recipient: str, message: str, confirm_token: str | None = None) -> dict[str, Any]:
    """Send a WhatsApp text message to an allowlisted recipient. Passes through the
    full security gate (allowlist, secret scan, rate limit, confirmation). If the
    result has needs_confirm=true, re-call with the returned confirm_token."""
    _reload()
    v = guard.evaluate(
        CFG, recipient=recipient, message=message, confirm_token=confirm_token,
        state_path=RATE_PATH, dry_run=False,
    )
    base = {"tool": "wa_send_message", **audit.preview_text(message),
            "recipient_name": v.recipient_name, "recipient_jid": guard._mask_jid(v.recipient_jid),
            "allowlisted": v.is_listed}
    if not v.ok:
        audit.record(AUDIT_PATH, {**base, "result": "blocked", "reason": v.blocked_reason,
                                  "warnings": v.warnings})
        return {"sent": False, **v.to_dict()}
    try:
        sent, msg = BRIDGE.send_message(v.recipient_jid, message)
    except BridgeError as e:
        audit.record(AUDIT_PATH, {**base, "result": "error", "reason": str(e)})
        return {"sent": False, "error": str(e), **v.to_dict()}
    audit.record(AUDIT_PATH, {**base, "result": "sent" if sent else "failed", "bridge_msg": msg})
    return {"sent": sent, "bridge_message": msg, **v.to_dict()}


@mcp.tool()
def wa_send_file(recipient: str, file_path: str, caption: str = "",
                 confirm_token: str | None = None) -> dict[str, Any]:
    """Send a file to an allowlisted recipient. The filename is auto-sanitized to
    an ASCII-safe name (so WhatsApp shows a real name, not 'Untitled', and no path
    traversal is possible), the type/size are validated, and the caption is
    secret-scanned. Sending files may require a confirm_token (see wa_preview)."""
    _reload()
    v = guard.evaluate(
        CFG, recipient=recipient, message=caption or None, file_path=file_path,
        confirm_token=confirm_token, state_path=RATE_PATH, dry_run=False,
    )
    base = {"tool": "wa_send_file", "recipient_name": v.recipient_name,
            "recipient_jid": guard._mask_jid(v.recipient_jid), "allowlisted": v.is_listed,
            "display_filename": v.display_filename, "file_sha256": v.file_sha256,
            **({"caption": audit.preview_text(caption)} if caption else {})}
    if not v.ok:
        audit.record(AUDIT_PATH, {**base, "result": "blocked", "reason": v.blocked_reason,
                                  "warnings": v.warnings})
        return {"sent": False, **v.to_dict()}
    try:
        sent, msg = BRIDGE.send_file(v.recipient_jid, v.send_path, caption=caption)
    except BridgeError as e:
        audit.record(AUDIT_PATH, {**base, "result": "error", "reason": str(e)})
        return {"sent": False, "error": str(e), **v.to_dict()}
    audit.record(AUDIT_PATH, {**base, "result": "sent" if sent else "failed", "bridge_msg": msg})
    return {"sent": sent, "bridge_message": msg, **v.to_dict()}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
