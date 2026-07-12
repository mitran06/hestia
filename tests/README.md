# tests/ — the Hestia test suites

Pure-logic proofs of the security-critical pieces. They mock Telegram and the
SSH relay, so they need **no root and no network** — run them anywhere the
source is importable.

Runs on: anywhere (developer machine, CI). No privileges required.

| Suite | Proves |
|-------|--------|
| `test_broker.py` | The policy engine (`broker.py`): free-zone auto-run, default-DENY-to-button, malformed → REJECT, canonicalization determinism + injection resistance. |
| `test_brokerd.py` | The daemon state machine (`brokerd.py`) with mocked Telegram + relay: owner-filter drop, single-use nonce / no double-exec on replay, auto-deny timeout, deny path, full session lifecycle. |
| `test_relay.py` | The box-side client (`hestia-relay.py`) round-trip against a temp outbox/inbox. |
| `test_elevation_crypto.py` | The broker and the target wrapper agree on the HMAC elevation ticket: a valid ticket verifies; every tamper / forgery / expiry is rejected. |

## Running them

```bash
cd tests
python3 test_broker.py
python3 test_brokerd.py
python3 test_relay.py
python3 test_elevation_crypto.py
```

Each prints per-check PASS/FAIL and exits non-zero if any check fails.
