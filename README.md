# guarded-whatsapp-mcp

**Govern & automate WhatsApp safely for AI agents.**

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent (or any MCP client)
send WhatsApp messages and files — but only through a security gate you control: a
recipient **allowlist**, **secret scanning**, **file validation**, **rate limiting**, a
**confirmation gate**, and an append-only **audit log**.

Most WhatsApp bridges will send anything, anywhere, with no record. That is fine for a
human clicking *send*. It is not fine for an autonomous agent. This project is the missing
**governance layer** that makes agent-driven WhatsApp safe enough to trust.

```
MCP client ──> guarded-whatsapp-mcp ──> whatsapp bridge ──> WhatsApp
                     │
                     └ allowlist · secret scan · file checks · rate limit · confirm · audit
```

> **This is not a Slack replacement.** It does not give you channels, threads, or a
> workspace UI. It makes the WhatsApp you *already use* safe to automate.

---

## ⚠️ Read this first — unofficial transport & WhatsApp Terms

This server governs access to a transport; by default that transport is the **unofficial
[whatsmeow](https://github.com/tulir/whatsmeow)-based bridge** (e.g. from
[`whatsapp-mcp`](https://github.com/lharries/whatsapp-mcp)), which talks to WhatsApp Web's
private protocol.

- Using an unofficial client **violates WhatsApp's Terms of Service** and **can get a phone
  number banned**. There is no way around this with a reverse-engineered client.
- **Use a secondary / non-critical number.** Do not connect your primary personal or
  business-critical number.
- **Do not use this for production customer messaging.** For that, use the official
  [WhatsApp Business Cloud API](https://developers.facebook.com/docs/whatsapp). An official
  Cloud-API backend adapter is on the [roadmap](#roadmap) — the guard layer is designed to
  sit in front of either transport.

We are deliberately loud about this so you can make an informed choice. The guardrails in
this repo reduce *operational* risk (wrong recipient, leaked secret, spam); they do not
change the *Terms-of-Service* risk of the underlying bridge.

---

## Security controls

| Control | What it does |
|---|---|
| **Recipient allowlist** | Fail-closed. With `allow_unlisted: false`, only people/groups in `config/allowlist.yaml` can be messaged — even a raw number is refused. |
| **Secret / PII scan** | Message text + file captions are scanned for API keys, private keys, AWS/Slack/GitHub/OpenAI tokens, JWTs, credit cards (Luhn), national IDs. `block` or `warn`. |
| **File validation** | Extension allowlist + size cap. Filenames are sanitized to ASCII (no `Untitled`, no path traversal); the file is copied to a safe name before sending. |
| **Rate limiting** | Sliding window (per-minute + per-hour) stops a runaway loop from spamming. |
| **Confirmation gate** | Risky sends (unlisted / files / all) require a `confirm_token` from `wa_preview` — proving the send was previewed, not accidental. |
| **Audit log** | Every attempt (sent / blocked / failed) is appended to `~/.guarded-whatsapp-mcp/audit.jsonl`. Bodies are stored as a preview + hash, never in full. |

## Tools

| Tool | Gated? | Purpose |
|---|---|---|
| `wa_list_recipients` | read-only | Show the allowlist (numbers masked). |
| `wa_preview` | read-only | Dry-run a send: run every check, return the verdict + a `confirm_token` if needed. Nothing is sent. |
| `wa_send_message` | **send** | Send text to an allowlisted recipient through the full gate. |
| `wa_send_file` | **send** | Send a file (auto ASCII-safe name, type/size checked, caption scanned). |
| `wa_audit_tail` | read-only | Recent audit records. |

## Setup

```bash
git clone https://github.com/peter-tnc-453/guarded-whatsapp-mcp
cd guarded-whatsapp-mcp

# deps (Python 3.10+; uv recommended)
uv venv --python 3.11 && source .venv/bin/activate
uv pip install -e .

# config — copy the example and edit your allowlist (the real file is git-ignored)
cp config/allowlist.example.yaml config/allowlist.yaml

# a WhatsApp bridge providing POST /api/send must be running (the authenticated session).
# See https://github.com/lharries/whatsapp-mcp for the whatsmeow bridge (first run = QR scan).

# run the MCP server (stdio)
python -m wa_guard
```

### Register with Claude Code / any MCP client

```json
{
  "mcpServers": {
    "guarded-whatsapp-mcp": {
      "command": "/ABSOLUTE/PATH/guarded-whatsapp-mcp/.venv/bin/python",
      "args": ["-m", "wa_guard"],
      "env": {
        "PYTHONPATH": "/ABSOLUTE/PATH/guarded-whatsapp-mcp/src",
        "WA_GUARD_CONFIG": "/ABSOLUTE/PATH/guarded-whatsapp-mcp/config/allowlist.yaml"
      }
    }
  }
}
```

## Configuration

See [`config/allowlist.example.yaml`](config/allowlist.example.yaml). Key knobs:
`allow_unlisted` (the fail-closed switch), `require_confirm_for`, `rate_limit`, `files`,
`secrets.on_detect`, and the `recipients` allowlist. Edits are hot-reloaded on each call.

## Roadmap

- **Pluggable backend** — abstract the transport so the same guard layer fronts either the
  unofficial bridge *or* the official **WhatsApp Business Cloud API** (compliant path).
- **Inbound routing** — expose incoming messages to agents (read + classify + route).
- **Scheduled / templated sends** with the same gate.
- **Per-recipient policy** (different rate limits / confirm rules per contact or group).

## Tests

```bash
uv pip install pytest && PYTHONPATH=src python -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE). Security model & honest limitations in [SECURITY.md](SECURITY.md).
Contributions welcome; please keep the fail-closed posture and add a test for any new check.
