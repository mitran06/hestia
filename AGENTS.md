# AGENTS.md — setting up Hestia (read this first)

You are an AI agent helping a user deploy **Hestia**: a confined-agent + capability-broker system. This file is your driver. Follow it top to bottom. Prefer reading the linked docs over guessing.

**What you are building:** an unprivileged LXD container that runs an AI agent with internet-only egress, plus a host-side "broker" that is the only gated path from that box to the user's laptop/host — where every crossing requires a Telegram button the user taps. Full rationale: [docs/architecture.md](docs/architecture.md), [docs/security-model.md](docs/security-model.md).

## Ground rules

1. **This is security-sensitive and touches root on two machines.** Show the user each root script before running it and let them run it (or approve it). Never pipe a script straight into `sudo` without the user seeing it.
2. **Never invent secrets or values.** Collect them from the user (below). Do not hardcode anything into files — everything site-specific lives in `config/hestia.env`.
3. **Every install step self-proves.** Run it, then confirm its PASS output before moving on. If a step fails, stop and diagnose; do not proceed.
4. **Order matters** (there is a cross-machine key dependency): configure → confinement → **target** track → **host** track → live checks.
5. Read a file before you edit it. Keep changes minimal.

## Step 0 — collect these from the user

Ask for, and record into `config/hestia.env` (start from `config/hestia.env.example`; see [docs/configuration.md](docs/configuration.md)):

- **Telegram user id** (`HESTIA_OWNER_ID`) — numeric; the user gets it from **@userinfobot**.
- **Approvals bot token** — the user makes a *new* bot with **@BotFather**; this token is a secret. It does **not** go in `hestia.env`; it goes in `/etc/hestia-broker/broker.env` (0600) at Step 3. Have the user message that bot once so Telegram delivers updates.
- **Target host** (`HESTIA_TARGET_HOST`) — `hestia-agent@<laptop-tailscale-name-or-100.x-ip>`. Confirm the target runs Tailscale with SSH enabled.
- **Owner unix user on the target** (`OWNER_UNIX_USER`) — the user's own account (for 🔴 elevated commands that reach their files). Optional; blank disables elevation.
- **Agent model endpoint** (`LLM_BASE_URL`, `MODEL_NAME`, `LLM_API_KEY_ENV`) — any OpenAI-compatible endpoint; an open-weight model is recommended. Used only to render the Phase-1 agent config.
- Confirm defaults are fine: `CONTAINER_NAME=hestia-box`, `HESTIA_BRIDGE=lxdbr0`, `WORKSPACE=/srv/projects`.

Then: `cp config/hestia.env.example config/hestia.env` and fill it in. Verify `git status` shows `hestia.env` ignored (never commit it).

## Step 1 — confinement (host, root)

Follow [docs/confinement.md](docs/confinement.md): create the unprivileged LXD container, install the user's agent inside it (Nous Hermes is the reference; use `box/agent-config.example.yaml`, `box/SOUL.example.md`, `box/MEMORY.example.md` as templates), then apply the egress firewall and enable its service:

```bash
sudo install -m 0755 box/egress-firewall.sh /usr/local/sbin/hestia-box-egress.sh
sudo install -m 0644 box/egress-firewall.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now hestia-box-egress
```

**Prove it:** from inside the box, the public internet works but the host/LAN/tailnet do **not** (the firewall script prints its rules; confinement.md has the reachability checks). Do not continue until the box is internet-only.

## Step 2 — the broker: TARGET machine (root)

Run on the user's laptop (the target). Do this **before** the host track — the host imports a key generated here.

```bash
sudo install/target/1-users.sh      # creates hestia-agent + /srv/projects free-zone
sudo install/target/2-exec-argv.sh  # installs the executor + bubblewrap jail; self-proves the jail
sudo install/target/3-elevation.sh  # installs the HMAC-gated elevated wrapper + generates the key; 5 proofs
```

Confirm each script's PASS lines (jail hides `/etc`; a forged elevation ticket is rejected; a valid one runs as the owner user; replay rejected; non-sudo refused).

## Step 3 — the broker: HOST machine (root)

```bash
sudo install/host/1-users.sh              # fenced hestia-mover (lxd only) + hestia-broker (no lxd/docker/sudo)
sudo install/host/2-mover.sh              # the dumb pipe + its service
sudo install/host/3-broker-policy.sh      # policy engine + append-only (chattr +a) audit; runs tests/test_broker.py
sudo install/host/4-import-elevation-key.sh   # pulls the key from the target -> /etc/hestia-broker/ (0640)
sudo install/host/5-broker-service.sh     # installs the daemon; writes /etc/hestia-broker/broker.env (asks for the bot token)
sudo install/host/6-fw-backstop.sh        # independent nft box->tailnet DROP (no drift window)
```

Confirm the broker service is active and stable (`systemctl status hestia-broker`, `NRestarts=0`).

## Step 4 — live end-to-end checks

Have the user drive these from the agent (via `hestia-relay`) or you can submit test requests. Confirm all three (details in [docs/operations.md](docs/operations.md)):

1. **Free-zone:** `hestia-relay -- ls -la` in `/srv/projects` → a 🟡 session button → approve → runs (inside the jail).
2. **Elevated:** `hestia-relay --elevate --cwd /home/<owner> -- ls -la` → a 🔴 button → approve → lists the owner's private files (proves elevation works and the HMAC keys match).
3. **Injection drill:** `hestia-relay -- cat /etc/passwd` → a 🔵 button → **Deny** → the box gets `refused` (exit 77), nothing ran.

## Step 5 — teach the agent to use the broker

Install the skill so the confined agent knows the `hestia-relay` interface: copy `agent/hermes-skill/` into the agent's skills directory (for Nous Hermes: `~/.hermes/skills/broker/`), and add a memory note that the broker is live and `hestia-relay` is the tool. See `agent/README.md`.

## If something is off

- Tests are the ground truth: `cd tests && for t in test_*.py; do python3 "$t"; done` must be all-green.
- Nothing should ever run on the user's machines without a button. If it does, **stop** and re-read [docs/security-model.md](docs/security-model.md).
- Report back to the user what passed, what failed, and exactly which root steps you want them to run.
