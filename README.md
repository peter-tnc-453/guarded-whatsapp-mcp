# nene-whatsapp-guard

A **governed WhatsApp MCP server**. It lets an AI assistant (or any MCP client) send
WhatsApp messages and files to your team — but only through a security gate you control:
an allowlist, secret scanning, file validation, rate limiting, a confirmation gate, and
an append-only audit log.

The goal is trust: you can let the assistant send to the team autonomously, because it
*cannot* message a stranger, leak a credential, blast 200 messages, or attach the wrong
file without it being blocked or recorded.

It does **not** re-implement WhatsApp. It wraps the authenticated bridge from
[`whatsapp-mcp`](https://github.com/lharries/whatsapp-mcp) (a Go process that holds the
session and exposes `POST /api/send`) and governs access to it.

```
MCP client ──> nene-whatsapp-guard ──> whatsapp-bridge (:8080) ──> WhatsApp
                    │
                    └── allowlist · secret scan · file checks · rate limit · confirm · audit
```

## Why it exists

The plain bridge will send anything, anywhere, with no record. That is fine for a human
clicking send; it is not fine for an autonomous agent. This layer adds the controls that
make autonomous sending safe.

## Security controls

| Control | What it does |
|---|---|
| **Recipient allowlist** | Fail-closed. With `allow_unlisted: false`, only people/groups in `config/allowlist.yaml` can be messaged — even a raw number is refused. |
| **Secret / PII scan** | Message text is scanned for API keys, private keys, AWS/Slack/GitHub/OpenAI tokens, JWTs, credit cards (Luhn), Thai national IDs. `block` or `warn`. |
| **File validation** | Extension allowlist + size cap. Filenames are sanitized to ASCII (no `Untitled`, no path traversal); the file is copied to a safe temp name before sending. |
| **Rate limiting** | Sliding window (per-minute + per-hour) stops a runaway loop from spamming the team. |
| **Confirmation gate** | Risky sends (unlisted / files / all) require a `confirm_token` obtained from `wa_preview` — proving the send was previewed, not accidental. |
| **Audit log** | Every attempt (sent / blocked / failed) is appended to `~/.nene-whatsapp-guard/audit.jsonl` as one JSON line. Bodies stored as preview + hash, not in full. |

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
# 1. deps (Python 3.10+; uv recommended)
uv venv --python 3.11 && source .venv/bin/activate
uv pip install -e .

# 2. config — copy the example and edit your allowlist (the real file is git-ignored)
cp config/allowlist.example.yaml config/allowlist.yaml

# 3. the WhatsApp bridge must be running (provides the authenticated session)
#    cd ~/whatsapp-mcp/whatsapp-bridge && ./whatsapp-bridge   (first run scans a QR)

# 4. run the MCP server (stdio)
python -m wa_guard
```

### Register with Claude Code

```json
{
  "mcpServers": {
    "nene-whatsapp-guard": {
      "command": "/ABSOLUTE/PATH/nene-whatsapp-guard/.venv/bin/python",
      "args": ["-m", "wa_guard"],
      "env": { "PYTHONPATH": "/ABSOLUTE/PATH/nene-whatsapp-guard/src",
               "WA_GUARD_CONFIG": "/ABSOLUTE/PATH/nene-whatsapp-guard/config/allowlist.yaml" }
    }
  }
}
```

## Configuration

See [`config/allowlist.example.yaml`](config/allowlist.example.yaml). Key knobs:
`allow_unlisted` (fail-closed switch), `require_confirm_for`, `rate_limit`, `files`,
`secrets.on_detect`, and the `recipients` allowlist. Edits are hot-reloaded on each call.

## Tests

```bash
uv pip install pytest && PYTHONPATH=src python -m pytest -q
```

## License

MIT. See [LICENSE](LICENSE). Security model in [SECURITY.md](SECURITY.md).
