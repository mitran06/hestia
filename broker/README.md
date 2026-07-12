# broker/ — the host-side capability broker (Phase 2)

The **broker** is the only gated path from the confined box to the owner's
target machine. It reads requests the box drops (shuttled in by the mover),
decides free-zone vs. needs-a-button vs. reject, shows the owner a **Telegram
button enforced outside the LLM**, and on approval runs the command on the
target over Tailscale SSH. The box holds no key and no route — it can only ask.

Runs on: the **host** (a dedicated `hestia-broker` user with no lxd/docker/sudo;
the mover runs as its own `hestia-mover` user).

| File | What it is |
|------|------------|
| `broker.py` | The policy engine: validate → canonicalize → hash → classify (`IN_SCOPE` / `NEEDS_BUTTON` / `REJECT`). Default-deny-to-button. Append-only audit log. No network, no exec. |
| `brokerd.py` | The daemon: imports `broker.py` and adds the Telegram approval boundary (owner-id filtered, single-use nonce), session lifecycle, and execution on the target via `tailscale ssh`. Fail-closed on restart. |
| `mover.sh` | The mailbox mover (dumb pipe): shuttles opaque, size-bounded, UUID-named blobs box↔host spool. Parses no content; validates only filename == UUID and size ≤ 64 KiB. |
| `hestia-fw-backstop.sh` | Firewall backstop self-test: proves the box still cannot reach the host/tailnet (uses the optional `*_TAILSCALE_IP` config probes). |
| `hestia-broker-audit.logrotate` | logrotate config for the broker's append-only audit log. |

Configure via `config/hestia.env` (the Telegram bot token is a secret and lives
only in the broker's `0600` EnvironmentFile, never in that file). See the broker
docs and `network/tailscale-acl.example.hujson` for the target SSH path.
