"""Thin client to the WhatsApp bridge REST API (the Go process from whatsapp-mcp
that holds the authenticated session). We deliberately do NOT re-implement the
WhatsApp protocol — we govern access to this transport.
"""
from __future__ import annotations

import httpx


class BridgeError(RuntimeError):
    pass


class Bridge:
    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _post_send(self, payload: dict) -> tuple[bool, str]:
        url = f"{self.base_url}/send"
        try:
            resp = httpx.post(url, json=payload, timeout=self.timeout)
        except httpx.HTTPError as e:
            raise BridgeError(
                f"cannot reach WhatsApp bridge at {url}: {e}. "
                f"Is the Go bridge running? (cd ~/whatsapp-mcp/whatsapp-bridge && ./whatsapp-bridge)"
            ) from e
        if resp.status_code != 200:
            raise BridgeError(f"bridge returned HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            data = resp.json()
        except Exception:
            return True, resp.text
        return bool(data.get("success", False)), str(data.get("message", ""))

    def send_message(self, recipient: str, message: str) -> tuple[bool, str]:
        return self._post_send({"recipient": recipient, "message": message})

    def send_file(self, recipient: str, media_path: str, caption: str = "") -> tuple[bool, str]:
        return self._post_send({"recipient": recipient, "message": caption, "media_path": media_path})

    def health(self) -> bool:
        try:
            httpx.get(f"{self.base_url}/", timeout=3.0)
            return True
        except httpx.HTTPError:
            return False
