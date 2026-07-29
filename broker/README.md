# broker/ — the host-side capability broker (Phase 2)

The **broker** is the only gated path from the confined box to the owner's
target machine. It reads requests the box drops (shuttled in by the mover),
puts each through a **deterministic policy-tier floor** and (for the middle
tiers) a **fail-closed LLM reviewer**, shows the owner a **Telegram button
enforced outside the LLM** whenever a human tap is required, and on approval
runs the command on the target over Tailscale SSH. The box holds no key and no
route — it can only ask.

Runs on: the **host** (a dedicated `hestia-broker` user with no lxd/docker/sudo;
the mover runs as its own `hestia-mover` user).

| File | What it is |
|------|------------|
| `broker.py` | The policy-tier engine: validate → canonicalize → hash → `policy_tier()`, the deterministic floor in strict priority `REFUSE > HARD_DENY > FREE_ZONE > SOFT_DENY > ALLOW`. Append-only audit log. No network, no exec. |
| `reviewer.py` | Layer 2 — the stateless, fail-closed LLM reviewer. Judges FREE_ZONE / SOFT_DENY / ALLOW middle commands against the session's stated intent; can only ever *tighten* (remove a tap), never lower the floor. Includes retries, a circuit breaker, and tier-adaptive thinking. Reviewer key is a secret. |
| `brokerd.py` | The daemon: imports `broker.py` + `reviewer.py` and adds the Telegram approval boundary (owner-id filtered, single-use nonce), session lifecycle, the startup preflight, runtime confinement of auto-run commands, the exfil cap, and execution on the target via `tailscale ssh`. Fail-closed on restart. |
| `mover.sh` | The mailbox mover (dumb pipe): shuttles opaque, size-bounded, UUID-named blobs box↔host spool. Parses no content; validates only filename == UUID and size ≤ 64 KiB. |
| `hestia-fw-backstop.sh` | Firewall backstop self-test: proves the box still cannot reach the host/tailnet (uses the optional `*_TAILSCALE_IP` config probes). |
| `hestia-broker-audit.logrotate` | logrotate config for the broker's append-only audit log. |

Configure via `config/hestia.env` (the Telegram bot token **and** the reviewer
API key are secrets and live only in the broker's `0600` EnvironmentFile, never
in that file). See the broker docs and
`network/tailscale-acl.example.hujson` for the target SSH path.
