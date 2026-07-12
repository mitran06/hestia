# box/ — the confined-agent container (Phase 1)

Everything for **Phase 1**: running the agent inside the network-isolated
`hestia-box` LXD container and firewalling it to the public internet only.

Runs on: the **host** (the server that hosts the container). The example agent
assets are installed **inside the box** as the `hestia` user.

| File | What it is | Where it goes |
|------|------------|---------------|
| `egress-firewall.sh` | The egress firewall. Restricts the box to the public IPv4 internet — blocks host, LAN, RFC1918, tailnet (v4 + v6). Idempotent, fail-closed. Run as root on the host. | `/usr/local/sbin/hestia-box-egress.sh` (host) |
| `egress-firewall.service` | systemd oneshot that re-applies the firewall on boot (Docker recreates `DOCKER-USER` empty on reboot). | `/etc/systemd/system/` (host) |
| `agent-config.example.yaml` | Sanitized Nous Hermes config: OpenAI-compatible provider, `terminal.backend: local`, in-box approval gate, points at the broker skill. | agent config dir in the box (`~/.hermes/config.yaml` for Nous Hermes) |
| `SOUL.example.md` | Generic safety-first agent persona (identity-free). | agent persona file in the box (`~/.hermes/SOUL.md`) |
| `MEMORY.example.md` | Infra-notes template with example entries to replace. | agent infra-memory in the box (`~/.hermes/memories/MEMORY.md`) |

See `docs/confinement.md` for the full Phase 1 walkthrough (create the
container, install the agent, apply the firewall, verify internet-only, reboot
persistence, optional vault sync).
