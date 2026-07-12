# Hestia

**An add-on to your AI agent that actually does what it was supposed to, minus the safety issues.**

Stock agent setups (Hermes, OpenClaw, etc) give you a bad choice: run the agent **on your host** (it can do anything a hijacked prompt tells it to) or lock it in a **sandbox** (it can't touch anything real, hindering functionality). Hestia gives your agent the best of both worlds, with a **real computer and real reach**, where every dangerous action requires a **physical tap on your phone that the AI cannot fake, forge, or bypass.**

---

## Repository layout

```
config/    hestia.env.example — every site-specific value (copy to hestia.env)
box/       Phase 1: the LXD container's egress firewall + example agent config/persona
broker/    Phase 2 (host): policy engine, daemon, dumb-pipe mover, systemd units, backstop
target/    Phase 2 (laptop): the executor (+ bubblewrap jail) and HMAC-gated elevated wrapper
agent/     the box-side client (hestia-relay) + a skill teaching the agent to use the broker
install/   ordered, self-proving install scripts (host/ and target/)
network/   example Tailscale ACL scoping broker-host -> target-user
tests/     ~139 offline tests (policy, daemon, relay, elevation crypto) — no root/network needed
docs/      architecture, security model, broker internals, install, config, operations, confinement
```

## What you need

- A **host** (a home server / always-on Linux box) with **LXD** and **Docker**, where the container and the broker run.
- A **target** machine (your laptop) reachable over **Tailscale SSH**.
- **Telegram**, and two bots from **@BotFather** (your agent's chat bot + a dedicated approvals bot).
- An agent to confine. The reference is **[Nous Research's Hermes Agent](https://github.com/NousResearch/hermes-agent)**, but the broker is agent-agnostic — the box side is just a small client (`hestia-relay`).

## Installation
### Point your agent at this repo

If you already run a capable coding agent (Claude Code, or a Hermes/other agent with shell access), let it do the work:

1. Clone the repo where your agent can read it:
   ```bash
   git clone https://github.com/mitran06/hestia && cd hestia
   ```
2. Tell your agent: **"Read `AGENTS.md` and set up Hestia for me."**

Your agent will provide you with instructions on whatever it needs from you.

> `CLAUDE.md` points Claude Code at `AGENTS.md` automatically.

### Manual Installation

Follow **[docs/installation.md](docs/installation.md)** — an ordered runbook where every step prints its own proof. In short:

```bash
# 0. configure
cp config/hestia.env.example config/hestia.env && $EDITOR config/hestia.env   # see docs/configuration.md

# 1. confinement (host, root): create the box, install your agent, apply the egress firewall
#    -> docs/confinement.md

# 2. the broker — TARGET machine first (root), because the host imports its key:
sudo install/target/1-users.sh        # restricted user + /srv/projects free-zone
sudo install/target/2-exec-argv.sh    # the executor + bubblewrap jail (self-proves)
sudo install/target/3-elevation.sh    # HMAC-gated elevated wrapper + key (self-proves)

# 3. the broker — HOST machine (root):
sudo install/host/1-users.sh              # fenced mover + broker users
sudo install/host/2-mover.sh              # the dumb pipe
sudo install/host/3-broker-policy.sh      # policy engine + append-only audit (runs tests)
sudo install/host/4-import-elevation-key.sh
sudo install/host/5-broker-service.sh     # the daemon (needs your approvals-bot token)
sudo install/host/6-fw-backstop.sh        # independent box->tailnet firewall backstop
```

Then do the live checks in [docs/operations.md](docs/operations.md)

## Tests

```bash
cd tests && for t in test_*.py; do python3 "$t"; done
```
All four suites run offline (no root, no network, no Telegram). They are the regression gate — if you change the policy or the daemon, they must stay green.

---

## Why it's safe even if the agent is hijacked

The design principle: **the component that can be prompt-injected holds no secret and no route.**

- The agent lives in a box that is firewalled to internet-only — it cannot reach the broker, your laptop, or the tailnet.
- It can only *write a request file*. A dumb pipe shuttles opaque, size-bounded blobs to the host.
- The broker (a separate user with no `lxd`/`docker`/`sudo`) validates and classifies every request, then asks **you** on a *second* Telegram bot whose token the box never sees.
- What runs equals what you approved — commands are hashed and executed from the broker's own copy, never a re-read of a file the box could swap.
- Reaching *your* private files needs an unforgeable, single-use, expiring capability the box cannot mint.

See **[docs/architecture.md](docs/architecture.md)** for the five trust domains and **[docs/security-model.md](docs/security-model.md)** for the threat model and residual risks. **Read the code before you run it.**

It has two layers:

- **Confinement** — the whole agent runs inside an unprivileged LXD container that can reach the public internet and *nothing else* (not your host, LAN, laptop, or tailnet).
- **The capability broker** — the single gated path from that confined agent to your laptop/host. Every crossing pops a **Telegram button, enforced outside the language model.** A prompt-injected agent holds no key and no route, so it has nothing to bypass.

---


## Status & disclaimer

This is a personal project, shared as-is under the [MIT license](LICENSE), with **no warranty**. It is security-sensitive: it mediates an AI agent's access to your machines. Understand the [threat model](docs/security-model.md), review the code, and operate it at your own risk.

## Credits

Built to confine and empower [Nous Research Hermes](https://github.com/NousResearch/Hermes); transport by [Tailscale](https://tailscale.com); free-zone jail by [bubblewrap](https://github.com/containers/bubblewrap).
