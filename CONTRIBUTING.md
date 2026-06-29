# Contributing

Thanks for considering a contribution. This project has one job — make agent-driven
WhatsApp **safe** — so contributions are reviewed through that lens.

## The one rule: stay fail-closed

Every change must preserve the fail-closed posture: when in doubt, **do not send**. A
missing or partial config must resolve to safe defaults (`allow_unlisted: false`,
`secrets.on_detect: block`). New behaviour that can send must pass through `guard.evaluate`.

## Dev setup

```bash
uv venv --python 3.11 && source .venv/bin/activate
uv pip install -e ".[dev]"
PYTHONPATH=src python -m pytest -q
```

## Adding a new check

1. Implement it in `src/wa_guard/guard.py` so it runs inside `evaluate()`.
2. Make it **deny by default** and return an actionable `blocked_reason`.
3. Add a test in `tests/test_guard.py` (both a blocked case and an allowed case).
4. Update the README security table.

## Good first issues

- More secret/PII signatures (with a test each).
- An official **WhatsApp Cloud API** backend adapter behind the same interface.
- Inbound message routing tools.
- Per-recipient policy in config.

## Pull requests

- Keep PRs focused. One concern per PR.
- Tests must pass; new send-paths need a guard test.
- No real numbers, tokens, or `allowlist.yaml` in commits (the secret-leak check in CI
  and `.gitignore` guard against this — don't bypass them).

## Reporting security issues

Please open a private report rather than a public issue for anything that could let the
guard be bypassed.
