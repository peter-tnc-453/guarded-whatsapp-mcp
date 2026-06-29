"""Append-only audit log. Every send attempt — allowed, blocked, or failed —
is recorded as one JSON line. This is what lets Peter trust autonomous sending:
nothing happens without a trace.

Message bodies are stored as a short preview + sha256, not in full, to avoid the
log itself becoming a place secrets leak to.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def record(audit_path: Path, entry: dict[str, Any]) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"ts": _now_iso(), **entry}
    with open(audit_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def preview_text(message: str | None) -> dict[str, Any]:
    if not message:
        return {"preview": None, "len": 0, "sha256": None}
    sha = hashlib.sha256(message.encode("utf-8")).hexdigest()[:16]
    preview = message if len(message) <= 80 else message[:77] + "..."
    return {"preview": preview, "len": len(message), "sha256": sha}


def tail(audit_path: Path, limit: int = 20) -> list[dict[str, Any]]:
    if not audit_path.exists():
        return []
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    out: list[dict[str, Any]] = []
    for ln in lines[-limit:]:
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out
