# Phase 1 — Confining the agent (the blast-radius wall)

This guide sets up **Phase 1**: run your entire personal AI agent inside an
unprivileged LXD container (`hestia-box`) whose network is firewalled to the
**public internet only**. Even a fully prompt-injected, hijacked agent then has
**no network path** to your host, your LAN, your tailnet, or your other
machines. The only way across that boundary is the capability broker (Phase 2),
which the box cannot invoke on its own.

Phase 2 (the host-side broker + target executor, gated by a second Telegram
bot) is covered in its own docs — this guide gets the confinement right first.

Throughout, replace `<PLACEHOLDER>` values and set your site config in
`config/hestia.env` (copy from `config/hestia.env.example`). Commands marked
**(host, root)** run on the server that hosts the container.

---

## Why confine

Your agent ingests untrusted content — web pages, news, email, chat, file
contents, tool output. Assume any of it **can carry prompt-injection** and make
the agent behave adversarially. Pattern/regex gates inside the agent are
heuristics — evadable by a hijacked LLM. The only durable boundary is the one
enforced **outside** the LLM by the operating system and the network.

So Phase 1 makes the container itself the blast radius:

- All agent execution (terminal, `execute_code`, sub-agents, cron) runs **inside
  the box** as the unprivileged `hestia` user (`terminal.backend: local`).
- The box is recoverable — snapshot or rebuild it if it's ever wrecked.
- An **egress firewall** on the host restricts the box to the public internet.
  It cannot reach the host, the LAN (`192.168.0.0/16` etc.), the tailnet
  (`100.64.0.0/10` + `fd7a:115c:a1e0::/48`), or any RFC1918 range — over **both
  IPv4 and IPv6**. IPv6 egress is locked fail-closed (v6 internet isn't needed).

The wall is fail-closed: if the firewall rules are ever lost, the box loses
internet, not the other way around.

---

## Prerequisites

- A Linux host with **LXD** installed (`snap install lxd` and `lxd init` if you
  haven't). The reference host runs Ubuntu with Docker present as well; the
  firewall is written to coexist with Docker's `DOCKER-USER` chain.
- `iptables` (and ideally `ip6tables`) on the host.
- Your model provider details (an OpenAI-compatible `<LLM_BASE_URL>`,
  `<MODEL_NAME>`, and the ENV-VAR NAME holding the API key).
- Your numeric Telegram user id for the agent's chat bot.

---

## 1. Create the unprivileged container

**(host, root)** Launch an unprivileged container named `hestia-box`
(`CONTAINER_NAME` in your config). "Unprivileged" (the LXD default) means an
isolated user-id map, no nesting, no host mounts, and no access to the Docker
socket — a compromise inside the box stays inside the box.

```bash
lxc launch ubuntu:24.04 hestia-box

# Keep it unprivileged and locked down (these are the safe defaults; set them
# explicitly so nobody loosens them by accident):
lxc config set hestia-box security.privileged     false
lxc config set hestia-box security.nesting        false
lxc config set hestia-box security.idmap.isolated true
# Do NOT add host disk mounts or the docker socket. The box owns only itself.

# Give it a comfortable footprint (tune to taste):
lxc config set hestia-box limits.cpu    2
lxc config set hestia-box limits.memory 6GiB
```

Note which bridge the container is on (`HESTIA_BRIDGE`, default `lxdbr0`) — the
firewall keys off it:

```bash
lxc network list          # find the bridge, e.g. lxdbr0
```

Create the agent's user inside the box (`AGENT_BOX_USER`, default `hestia`):

```bash
lxc exec hestia-box -- adduser --disabled-password --gecos "" hestia
lxc exec hestia-box -- usermod -aG sudo hestia     # the box is the blast radius; in-box sudo is fine
```

---

## 2. Install your agent inside the box

The reference agent is **Nous Research "Hermes"**
(https://github.com/NousResearch/Hermes), but any OpenAI-compatible agent works
the same way — the confinement is agent-agnostic. Install and run the agent
**as the `hestia` user, inside the box**:

```bash
lxc exec hestia-box -- sudo -iu hestia
# ...now inside the box as `hestia`: install your agent per its own docs...
```

Configure it from the sanitized examples in `box/`:

- `box/agent-config.example.yaml` → the agent's config (for Nous Hermes:
  `~/.hermes/config.yaml`). Set `terminal.backend: local`, your provider block,
  and the owner's Telegram id. Fill every `<PLACEHOLDER>`.
- `box/SOUL.example.md` → the agent's safety persona (`~/.hermes/SOUL.md`).
- `box/MEMORY.example.md` → the infra-notes template
  (`~/.hermes/memories/MEMORY.md`).

The API key and any bot token are read from **environment variables** (by name),
never written into these files. Point the box's environment at your key using
the env-var NAME you set in the config (`<LLM_API_KEY_ENV>`).

Later, once Phase 2 is up, add the broker skill
(`agent/hermes-skill/omen-relay/SKILL.md`) into the agent's skills dir so it
knows to request target actions via `hestia-relay`.

---

## 3. Apply the egress firewall (host)

The firewall is `box/egress-firewall.sh` — run as **root on the host**. It is
idempotent (safe to re-run) and fail-closed. It auto-detects the bridge's
addressing from the live bridge; override in `config/hestia.env` only if
detection fails.

Install it to a stable path and make it reboot-persistent with the provided
systemd unit:

```bash
# 1) copy the script into place (name it to match the service's ExecStart)
install -m 0755 box/egress-firewall.sh /usr/local/sbin/hestia-box-egress.sh

# 2) (optional) site overrides for the unit's EnvironmentFile
#    e.g. HESTIA_BRIDGE, CONTAINER_SUBNET_V4 — usually NOT needed
install -d /etc/hestia
# $EDITOR /etc/hestia/box.env

# 3) install and enable the systemd oneshot
install -m 0644 box/egress-firewall.service /etc/systemd/system/hestia-box-egress.service
systemctl daemon-reload
systemctl enable --now hestia-box-egress.service
```

What it does, briefly: all of Hestia's rules live in dedicated child chains
(`HST_FWD`/`HST_IN` for v4, `HST6_FWD`/`HST6_IN` for v6), jumped from
`DOCKER-USER`/`INPUT`. The box may reach the **public IPv4 internet only**;
the host (except DHCP + DNS to the bridge gateway), the LAN, RFC1918, and the
tailnet are dropped, v4 and v6.

Check it applied:

```bash
systemctl status hestia-box-egress.service
iptables  -S HST_FWD
ip6tables -S HST6_FWD 2>/dev/null || true
```

---

## 4. Verify: internet yes, everything-inside no

From **inside the box**, prove the wall. Public internet should work; the host,
LAN, and tailnet should all fail (hang/timeout, not connect):

```bash
# internet — should SUCCEED
lxc exec hestia-box -- getent hosts example.com
lxc exec hestia-box -- curl -sS -m 8 https://example.com -o /dev/null && echo "internet OK"

# the host's own IP (bridge gateway aside) — should FAIL
lxc exec hestia-box -- curl -sS -m 5 http://<HOST_LAN_IP>/    ; echo "exit=$?"

# the LAN — should FAIL
lxc exec hestia-box -- ping -c1 -W2 <A_LAN_HOST_IP>           ; echo "exit=$?"

# the tailnet (the target machine) — should FAIL, v4 and v6
lxc exec hestia-box -- curl -sS -m 5 http://100.<x>.<y>.<z>/  ; echo "exit=$?"
```

Every "inside" probe must fail. If any succeeds, do **not** proceed to Phase 2 —
re-check the bridge name, re-run the firewall, and confirm the child chains are
populated. (Set `HOMESERVER_TAILSCALE_IP` / `TARGET_TAILSCALE_IP` in
`config/hestia.env` to let the Phase-2 firewall backstop self-test probe these
automatically.)

---

## 5. Reboot persistence

The systemd unit re-applies the firewall on every boot. This matters because a
host reboot recreates Docker's `DOCKER-USER` chain **empty** — the unit re-adds
Hestia's jump after Docker and the bridge come up. If the jump is ever missing,
the box merely loses internet (fail-closed), never gains a path inward.

Reboot and re-verify:

```bash
sudo reboot
# after it's back:
systemctl status hestia-box-egress.service     # active (exited)
iptables -S HST_FWD                            # rules present
# then re-run the box verification from step 4
```

---

## 6. (Optional) Vault / notes sync, box ↔ host

If your agent keeps an Obsidian-style vault or notes you want on your other
devices, sync them **box ↔ host** with **Syncthing** rather than a host mount —
a mount would let box damage survive a container rebuild, and re-add a
host/box coupling. Syncthing keeps a versioned copy on the host that you can
fan out to your devices, and its file versioning gives you a rollback if the
agent (or an injection) writes something malicious.

Sketch:

- Run Syncthing inside the box, sharing the vault folder (e.g.
  `/home/hestia/vault`).
- Run Syncthing on the host, accepting that folder into a host-side directory.
- Treat **anything the agent ever wrote** as agent-authored; rely on Syncthing
  versioning (and, ideally later, an append-only backup the agent can't reach)
  to recover from bad writes.

Syncthing uses the internet for peer discovery/relays, which the egress
firewall already permits — so this does not weaken the wall.

---

## Done — what you have now

- The whole agent runs inside `hestia-box` as the unprivileged `hestia` user.
- The box reaches the **public internet only**; host, LAN, and tailnet are
  firewalled off, v4 and v6, reboot-persistent and fail-closed.
- (Optional) a versioned vault sync box ↔ host.

The box has **no key and no route** to your other machines. The only way it can
ever act on your laptop/host is **Phase 2**: the capability broker, where every
crossing needs a Telegram button enforced below the LLM — see the broker docs
and `agent/hermes-skill/omen-relay/SKILL.md`.
