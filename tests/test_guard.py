"""Unit tests for the security gate. These exercise the trust-critical logic
without touching WhatsApp or the bridge."""
from pathlib import Path

import pytest

from wa_guard.config import Config, Recipient
from wa_guard import guard


def make_cfg(**over) -> Config:
    base = dict(
        bridge_url="http://localhost:8080/api",
        allow_unlisted=False,
        require_confirm_for=[],
        rate_limit={"per_minute": 100, "per_hour": 1000},
        files={"max_size_mb": 100, "allowed_ext": [".pdf", ".png", ".txt"]},
        secrets={"on_detect": "block"},
        recipients=[Recipient(name="Alex", jid="15551230001", note="vendor"),
                    Recipient(name="Team Alpha", jid="120363000000000000@g.us")],
    )
    base.update(over)
    return Config(**base)


# ---- filename sanitisation -------------------------------------------------
def test_sanitize_thai_filename_becomes_ascii():
    out = guard.sanitize_filename("เขาชะงุ้ม-RFQ-โดรน.pdf")
    assert out.endswith(".pdf")
    assert out.encode("ascii")  # pure ascii, no exception
    assert "/" not in out and "\\" not in out


def test_sanitize_blocks_path_traversal():
    out = guard.sanitize_filename("../../etc/passwd")
    assert out == "passwd"
    assert ".." not in out


def test_sanitize_empty_after_strip_gets_hash_name():
    out = guard.sanitize_filename("ไทยล้วน.docx")
    assert out.endswith(".docx")
    assert len(Path(out).stem) > 0


# ---- secret scanning -------------------------------------------------------
@pytest.mark.parametrize("text", [
    "api_key = sk-ABCD1234EFGH5678IJKL",
    "AKIAIOSFODNN7EXAMPLE here",
    "-----BEGIN RSA PRIVATE KEY-----",
    "password: hunter2hunter2",
    "Bearer abcdefghij0123456789ABCDEFGH",
])
def test_scan_detects_secrets(text):
    assert guard.scan_secrets(text), f"should flag: {text}"


def test_scan_clean_text_is_empty():
    assert guard.scan_secrets("สวัสดีครับAlex ส่งไฟล์ RFQ ให้นะครับ") == []


def test_credit_card_luhn():
    assert any(f["label"] == "credit_card" for f in guard.scan_secrets("card 4242424242424242"))
    assert not any(f["label"] == "credit_card" for f in guard.scan_secrets("num 1234567890123456"))


# ---- allowlist enforcement -------------------------------------------------
def test_unlisted_blocked_when_closed(tmp_path):
    cfg = make_cfg(allow_unlisted=False)
    v = guard.evaluate(cfg, recipient="66999999999", message="hi",
                       state_path=tmp_path / "r.json")
    assert not v.ok and "not allowlisted" in v.blocked_reason


def test_unlisted_allowed_when_open(tmp_path):
    cfg = make_cfg(allow_unlisted=True)
    v = guard.evaluate(cfg, recipient="66999999999", message="hi",
                       state_path=tmp_path / "r.json")
    assert v.ok and not v.is_listed and v.warnings


def test_allowlisted_by_name(tmp_path):
    cfg = make_cfg()
    v = guard.evaluate(cfg, recipient="Alex", message="hi",
                       state_path=tmp_path / "r.json")
    assert v.ok and v.is_listed and v.recipient_jid == "15551230001"


def test_secret_in_message_blocks(tmp_path):
    cfg = make_cfg()
    v = guard.evaluate(cfg, recipient="Alex", message="key: sk-ABCD1234EFGH5678IJKL",
                       state_path=tmp_path / "r.json")
    assert not v.ok and "secret" in v.blocked_reason.lower()


# ---- file validation -------------------------------------------------------
def test_file_type_rejected(tmp_path):
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ")
    cfg = make_cfg()
    v = guard.evaluate(cfg, recipient="Alex", file_path=str(f),
                       state_path=tmp_path / "r.json")
    assert not v.ok and "not allowed" in v.blocked_reason


def test_file_too_big(tmp_path):
    f = tmp_path / "big.pdf"
    f.write_bytes(b"0" * 2048)
    cfg = make_cfg(files={"max_size_mb": 0.001, "allowed_ext": [".pdf"]})
    v = guard.evaluate(cfg, recipient="Alex", file_path=str(f),
                       state_path=tmp_path / "r.json")
    assert not v.ok and "limit" in v.blocked_reason


def test_file_ok_gets_sanitized_name(tmp_path):
    f = tmp_path / "เอกสารไทย.pdf"
    f.write_bytes(b"%PDF-1.4 test")
    cfg = make_cfg()
    v = guard.evaluate(cfg, recipient="Alex", file_path=str(f),
                       state_path=tmp_path / "r.json")
    assert v.ok and v.display_filename.endswith(".pdf")
    assert v.display_filename.encode("ascii")
    assert v.file_sha256


# ---- confirmation gate -----------------------------------------------------
def test_confirm_required_then_accepted(tmp_path):
    cfg = make_cfg(require_confirm_for=["all"])
    rp = tmp_path / "r.json"
    v1 = guard.evaluate(cfg, recipient="Alex", message="hello", state_path=rp)
    assert not v1.ok and v1.needs_confirm and v1.confirm_token
    v2 = guard.evaluate(cfg, recipient="Alex", message="hello",
                        confirm_token=v1.confirm_token, state_path=rp)
    assert v2.ok


# ---- rate limiting ---------------------------------------------------------
def test_rate_limit_per_minute(tmp_path):
    cfg = make_cfg(rate_limit={"per_minute": 2, "per_hour": 100})
    rp = tmp_path / "r.json"
    assert guard.evaluate(cfg, recipient="Alex", message="1", state_path=rp).ok
    assert guard.evaluate(cfg, recipient="Alex", message="2", state_path=rp).ok
    v3 = guard.evaluate(cfg, recipient="Alex", message="3", state_path=rp)
    assert not v3.ok and "rate limit" in v3.blocked_reason
