# agent/ — the box-side relay client and broker skill

The confined agent's interface to the capability broker. These live **inside
the box** (as the `hestia` user) — they are the ONLY way the agent can request
an action on the owner's target machine. The agent holds no key and no route;
it can only REQUEST, and the owner's Telegram button decides.

Runs on: **inside the box** (`hestia-box`), as the agent user.

| File | What it is |
|------|------------|
| `hestia-relay.py` | The box-side client. Drops a request in the outbox and waits for the broker's result via the inbox. Interface: `hestia-relay [--cwd DIR] [--elevate] [--timeout S] -- CMD [ARG...]`. Exit codes: `0`/command-exit on success, `77` refused (owner denied or policy), `78` rejected (malformed request), `75` revoked, `70` error, `124` timeout. Install it on `PATH` in the box as `hestia-relay`. |
| `hermes-skill/DESCRIPTION.md` | Describes the "broker" skill category (Nous skill format). |
| `hermes-skill/omen-relay/SKILL.md` | The skill that teaches the agent to use `hestia-relay`: free zone (`/srv/projects`, no button) vs. elevated (owner files, red button), the approval flow, exit codes, base64 for binary files, and reporting results back to the owner on Telegram. |

Install the skill into your agent's skills directory so it knows the relay
exists. See `agent/hermes-skill/omen-relay/SKILL.md` for the agent-facing
instructions, and the broker docs (Phase 2) for how the request is actually
gated and executed.
