# Long-term memory (Hindsight)

Hestia's third memory tier. Layer 1 is the agent's built-in `MEMORY.md`; layer 2 is Hindsight;
layer 3 is the vaults (see `../vault/`).

## Why a standalone server, not embedded mode

`hindsight-api-slim` requires `cryptography>=48.0.1` and `pillow>=12.3.0`. hermes-agent 0.18.0 pins
`cryptography==46.0.7` and `Pillow==12.2.0` **exactly**. No version satisfies both, and the plugin's
embedded-mode check imports `hindsight`, which chains to `hindsight_api` at module level — so
embedded mode needs the conflicting packages *in the agent's venv*.

Run the server from its **own virtualenv** and point the plugin at it with `mode: local_external`.
The agent venv then needs only `hindsight-client`.

## Setup

```bash
python3 -m venv $HESTIA_MEMORY_HOME/venv
$HESTIA_MEMORY_HOME/venv/bin/pip install 'hindsight-api==0.8.6'
```

Bind **explicitly** — the upstream default is `0.0.0.0`, which exposes the memory store to the LAN:

```
ExecStart=$HESTIA_MEMORY_HOME/venv/bin/hindsight-api --host 127.0.0.1 --port 8888
```

Pin `hindsight-client==0.6.1` in the agent venv: the lazy-dependency allowlist pins that exact
version and will otherwise downgrade it mid-session.

## Healthcheck

`hindsight-healthcheck.sh` runs on a timer. `/health` returning 200 does not prove memory works —
the server can be up while extraction is broken — so it also runs a **canary**: retain a token into
a throwaway bank, recall it, delete the bank.

Design rule: **every unknown resolves to loud.** Unparseable JSON, a missing field, a non-200, an
unreadable credential, a failed alert send — all are problems, never a silent "OK".
