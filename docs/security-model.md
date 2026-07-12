# Security model

Read this before you run Hestia. It describes what Hestia defends against, what it does **not**, and where each guarantee is enforced. Hestia is provided with no warranty — you are responsible for reviewing the code and operating it safely.

## What we assume

- **The agent is hostile.** Treat the language model as fully prompt-injectable: a web page it reads, a file it opens, or a message it receives may contain instructions that hijack it. Every guarantee below must hold *even if the agent is completely under an attacker's control.*
- **The owner is the trust anchor.** Security rests on you actually reading the command (argv + hash) before you tap **Approve**. Hestia makes the true command visible and un-spoofable; it cannot stop you from approving a bad one.
- **The host and the tailnet are trusted.** The broker host, the LXD/`lxc` tooling, and Tailscale's ACLs are inside the trust boundary. Hestia does not defend against a compromise of the host root or of your Tailscale account.
- **Under attack, the trade is availability, not confidentiality/integrity.** Every failure path is *fail-closed*: when something is wrong, the box loses the ability to act — it never gains an un-approved capability.

## What Hestia guarantees (and where)

| Property | Enforced by | Where |
|---|---|---|
| The injected agent cannot reach your host, LAN, laptop, or tailnet | egress firewall (v4+v6) + independent nftables backstop | Phase-1 box; `box/egress-firewall.sh`, `broker/hestia-fw-backstop.sh` |
| The agent cannot invoke the broker or press the button | the box holds no token and no route; approvals bot token is host-only | architecture (INV-2, INV-3) |
| The command you approve is the command that runs | length-prefixed canonicalization + `cmd_hash`, executed from the broker's stored copy, re-checked at dispatch | `broker/broker.py`, `broker/brokerd.py` |
| Un-buttoned auto-run is limited to safe, read-only inspection inside one directory | default-DENY-to-button classifier + strict per-binary flag allowlist | `broker/broker.py` |
| Free-zone commands cannot read outside the workspace (even via symlinks a recursive tool follows) | bubblewrap mount-namespace jail (only `/srv/projects` visible), fail-closed if unavailable | `target/exec-argv` |
| No command is ever passed through a shell | `shell=False` / `os.execvpe` with a scrubbed env | `target/exec-argv`, `target/exec-argv-elevated` |
| Reaching *your* private files requires an unforgeable, single-use, expiring capability | broker-signed HMAC ticket; permanent `setresuid` drop to you; single-use marker; TTL | `target/exec-argv-elevated` |
| History cannot be rewritten by the agent or the broker | append-only audit log (`chattr +a`, root-set) in a dir the broker cannot write | `broker/broker.py`, `install/host/3-broker-policy.sh` |
| A crash never resumes an open window | broker state is purely in-memory → restart = all sessions closed | `broker/brokerd.py` |

## The boundaries, top to bottom

1. **Blast-radius wall (confinement).** The agent, its tools, and its `execute_code` all live inside an unprivileged LXD container. Even a full container compromise yields only what the container can reach — which the egress firewall limits to the public internet. A second, independent nftables table (its own hook, before Docker's rules) drops box→tailnet with no drift window.
2. **The mailbox, not a socket.** The box talks to the host only by writing opaque, UUID-named, size-bounded files that a dumb mover shuttles with `lxc file`. There is no listening port on the host for the box to attack, and the mover parses nothing.
3. **The policy gate.** The broker validates and classifies every request. The default is *deny to a button*. The free-zone (auto-run) is deliberately tiny: read-only inspectors, safe flags only, paths confined to `/srv/projects`, never elevated, and only while a session you opened is live.
4. **The human gate.** Anything outside the free-zone shows you the exact argv + hash on a second Telegram bot. Nothing crosses to your machines without your tap. Display-spoofing is blocked (control chars escaped; argv rendered as a single JSON line), so the box cannot show you a benign command while running another.
5. **The executor.** On the target, a fixed wrapper runs the command with no shell, a realpath scope check, and (for the free-zone) a bubblewrap jail. Elevation to your own account is a separate, HMAC-gated wrapper with a permanent privilege drop.

## Residual risks (accept + mitigate)

These are real and documented; decide if they are acceptable for you.

1. **The free-zone is a genuine capability.** While a session is open, whitelisted read-only commands run in `/srv/projects` without a button. **Keep nothing sensitive in `/srv/projects`.**
2. **Output returns to the box.** stdout of approved/free commands flows back to the agent, which has internet — so it is an exfiltration channel. Approve mindfully; do not fetch secrets you would not want the agent to see.
3. **Approval fatigue.** The security rests on you reading argv + hash each time. If you rubber-stamp buttons, you defeat the model.
4. **Trusted tailnet + LXD.** The host→target path trusts Tailscale SSH ACLs; the mover trusts `lxc`. Tighten the Tailscale ACL to broker-host → target-user only (see `network/tailscale-acl.example.hujson`).
5. **A broker crash mid-command orphans that one in-flight command** on the target (it runs to completion; its revoke mapping is lost). New work is fail-closed.
6. **Host root / your Tailscale account are out of scope.** If either is compromised, Hestia cannot help — those are above its boundary.

## Reporting issues

This is a personal project shared as-is. If you find a security problem, please open an issue describing the class of problem (avoid posting working exploits against others' deployments).
