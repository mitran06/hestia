# target/ — the target-machine executor (Phase 2)

What runs on the owner's **target machine** (their laptop/host) when the broker
relays an approved command. The broker reaches it over Tailscale SSH as the
restricted `hestia-agent` user; the box cannot reach it at all (firewalled off
the tailnet). These wrappers INDEPENDENTLY re-enforce the rules — they do not
trust the broker as the sole gate.

Runs on: the **target machine**. `exec-argv` runs as the restricted
`hestia-agent` user; `exec-argv-elevated` starts as root (via one narrow
sudoers line) and permanently drops to the owner's own user.

| File | What it is |
|------|------------|
| `exec-argv` | The free-zone / owner-approved executor. Decodes the broker's base64 payload and execs the argv with `shell=False` and a scrubbed env. For free-zone (`workspace_only=true`) it re-checks: bare read-only allowlisted command, no out-of-tree path flags, cwd + operands resolve (realpath, symlink-aware) inside `/srv/projects`, and runs it inside a bubblewrap jail where only the workspace exists. Install to `/usr/local/lib/hestia/exec-argv`. |
| `exec-argv-elevated` | The privileged wrapper for owner-APPROVED elevated commands. Verifies a broker-signed HMAC ticket (unforgeable + TTL + single-use + caller check), then permanently drops to the configured owner user and execs the approved argv — reaching the owner's own files. Install to `/usr/local/lib/hestia/exec-argv-elevated`. |
| `hestia-elevated.sudoers` | The single narrow `NOPASSWD` sudoers rule: `hestia-agent` may run ONLY the elevated wrapper (no argument wildcard). Install `0440 root:root` to `/etc/sudoers.d/hestia-elevated`; validate with `visudo -cf`. |

`@OWNER_RUNAS@` in `exec-argv-elevated` is rendered at install to
`OWNER_UNIX_USER` from `config/hestia.env`. See `network/tailscale-acl.example.hujson`
for the broker→target SSH grant and the broker docs for the full flow.
