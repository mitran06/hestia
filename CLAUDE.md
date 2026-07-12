# CLAUDE.md

This repository is **Hestia** — a confined-agent + capability-broker system.

If you are setting it up, read **[AGENTS.md](AGENTS.md)** and follow it. It is the driver: what to collect from the user, which scripts to run on which machine, in what order, and how each step proves itself.

Key facts before you touch anything:
- It is security-sensitive and touches root on two machines. Show the user each root script; let them run/approve it.
- All site-specific values live in `config/hestia.env` (copy from `config/hestia.env.example`). Never hardcode ids, tokens, IPs, or usernames into files.
- `tests/` (~139 offline tests) is the regression gate: `cd tests && for t in test_*.py; do python3 "$t"; done`.
- Threat model and rationale: `docs/security-model.md`, `docs/architecture.md`, `docs/broker.md`.
