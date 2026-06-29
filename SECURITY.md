# Security model

`guarded-whatsapp-mcp` exists so that an autonomous assistant can be trusted to send
WhatsApp to a team. This document states what it defends against and what it does not.

## Threats it addresses

1. **Sending to the wrong person.** Fail-closed allowlist (`allow_unlisted: false`).
   A typo'd number, a hallucinated contact, or a stranger's JID is refused before it
   ever reaches the bridge.
2. **Leaking secrets.** Outgoing text (and file captions) are scanned for credentials
   and sensitive PII. High-severity matches (private keys, cloud/API tokens, credit
   cards) are blocked by default.
3. **Runaway / spam loops.** A sliding-window rate limit caps sends per minute and per
   hour. A stuck agent cannot flood the team.
4. **Accidental sends.** The confirmation gate forces risky categories (files, unlisted,
   or all) through `wa_preview` first; the send only proceeds with the matching
   `confirm_token`, proving a human-or-agent intentionally reviewed it.
5. **Malicious / messy filenames.** Filenames are reduced to an ASCII-safe basename,
   stripping directory components (path-traversal guard) and non-ASCII (which also fixed
   the bridge's "Untitled" display bug). The original file is never handed to the bridge
   under an attacker-controlled path.
6. **No accountability.** Every attempt is appended to an audit log with timestamp,
   recipient, result, and a body *preview + hash* (never the full secret-bearing body).

## Design choices

- **Fail closed.** Missing or partial config resolves to the safe defaults
  (`allow_unlisted: false`, `secrets.on_detect: block`). Doing nothing is safer than
  sending.
- **Least privilege transport.** The server talks only to `localhost` bridge endpoints;
  it never opens the network itself.
- **Secrets stay out of git.** The real `config/allowlist.yaml` and the audit log
  (`~/.guarded-whatsapp-mcp/`) are git-ignored. Only `allowlist.example.yaml` ships.
- **Read/write separation.** `wa_list_recipients`, `wa_preview`, `wa_audit_tail` are
  read-only and side-effect-free; only `wa_send_*` mutate the world, and only through
  the gate.

## Known limitations (be honest)

- Secret scanning is **heuristic** (regex + Luhn). It will miss novel secret formats and
  can false-positive on any 13-digit number. Treat `warn` mode accordingly.
- The allowlist trusts the bridge's session. Anyone who can reach `localhost:8080`
  bypasses this layer entirely — protect the host.
- No end-to-end authentication between MCP client and server beyond the stdio process
  boundary; run it as the same trusted user.
- Rate-limit and audit state are local files; deleting them resets the limits.

## Reporting

This is an internal tool. Raise issues to the maintainer (Peter / FutureFarm AI).
