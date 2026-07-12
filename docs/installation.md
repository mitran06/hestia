# Hestia — Phase 2 installation runbook

This is the ordered, manual install for the **broker / relay** half of Hestia: the
capability broker that gates every command the agent wants to run outside its confined
box, the Telegram approval loop, and the restricted **target** executor it drives over
Tailscale SSH.

Every step is **idempotent** and **self-proving**: each script installs its artifact and
then runs live tests that print `PASS`/`FAIL` (or `FENCE VIOLATION`) and exit non-zero if
any proof fails. Nothing is trusted on assertion; each fence is demonstrated.

> Phase 1 (the confined LXD agent box + egress firewall) is covered separately. This
> runbook assumes the box already exists and is reachable via `lxc`.

---

## 0. The three machines / identities

| Term | What it is |
|------|------------|
| **HOST** (broker machine) | Runs the broker, the mover, and the append-only audit log. This is where you run everything under `install/host/`. |
| **TARGET** | The laptop/host the agent acts on, over Tailscale SSH. Runs `exec-argv`, the elevation wrapper, and the restricted `hestia-agent` user. Everything under `install/target/`. |
| **BOX** | The confined LXD container the agent itself runs in. It is firewalled off the tailnet and can only talk to the host through the spool mailbox. |

Two unix trust domains are created on the HOST — `hestia-mover` (a dumb pipe, in group
`lxd` only) and `hestia-broker` (policy + token, in **no** privileged group). On the
TARGET, `hestia-agent` is the sole restricted execution identity.

---

## 1. Prerequisites

**On the HOST**
- `lxd` (snap), with the confined box already created and RUNNING (`lxc info <box>` works).
- `python3`, `sudo`, `chattr`/`lsattr` (e2fsprogs), `systemd`.
- `tailscale` installed and logged in; the TARGET reachable via `tailscale ssh`.
- `nft` (nftables) if you want the firewall backstop (step host-6).
- A **Telegram bot token** for the broker's approval bot, and your numeric Telegram
  user id (message `@userinfobot`).

**On the TARGET**
- `python3`, `sudo`, `bubblewrap` (the exec-argv step installs it if your package
  manager is `dnf`/`apt`/`pacman`).
- Your own unix account already present (this becomes `OWNER_UNIX_USER`).
- `tailscaled` running and logged into the same tailnet as the HOST.

**Kernel/security:** unprivileged user namespaces must be enabled (bubblewrap needs
them). The exec-argv step proves this positively; if it fails, free-zone auto-run will
correctly **refuse** rather than run un-jailed.

---

## 2. Configure the site (do this once, on both machines)

```bash
cp config/hestia.env.example config/hestia.env
$EDITOR config/hestia.env
```

Fill in at minimum:

- `HESTIA_OWNER_ID` — your numeric Telegram user id (the ONLY id whose taps are honored).
- `HESTIA_TARGET_HOST` — `hestia-agent@<target-tailscale-host>`.
- `OWNER_UNIX_USER` — your own account on the TARGET (elevated, owner-approved commands
  run **as** this user; it is rendered into the elevated wrapper's allowlist). Required
  only if you want the elevation feature, but the target scripts expect it.
- `CONTAINER_NAME` / `AGENT_BOX_USER` — the box container and the agent's user inside it.
- `HESTIA_BRIDGE` — the LXD bridge the box is on (for the firewall backstop).

The bot token is **not** put in this file — it is prompted for (and written 0600
root:root) by the broker-service step. `config/hestia.env` is git-ignored.

The install scripts source `../../config/hestia.env` relative to themselves, so run them
from within a checkout that also contains your filled-in `config/hestia.env`. (Copy the
repo — including `config/hestia.env` — to each machine, or clone and re-create the env
file on each.)

Required values are enforced with `${VAR:?message}`; a missing one aborts the script
before any change with a clear error.

---

## 3. Install order (dependency-driven)

The TARGET side is installed **first** so that by the time the HOST broker starts, the
executor, the sudoers grant, and the elevation key already exist. Within each machine,
run the numbered scripts in order. Every script must be run **as root** on the machine
named.

### TARGET track (run as root on the TARGET)

| Step | Script | Installs | Proves (self-test) |
|------|--------|----------|--------------------|
| T1 | `install/target/1-users.sh` | `hestia-agent`, group `projects`, `/srv/projects` (2770 root:projects), adds `OWNER_UNIX_USER` to `projects` | exact group set `{hestia-agent, projects}`, no-sudo fence, home 0700, workspace 2770, and that `hestia-agent` is **not** in the owner's group. |
| T2 | `install/target/2-exec-argv.sh` | `exec-argv` → `/usr/local/lib/hestia/`, installs bubblewrap | The realpath scope check (symlink-cwd escape → 40, symlink/abs arg escape → 41, interpreter argv[0] → 44), approved-mode reads a world-readable file but is DAC-fenced from the owner's home, `hestia-agent` cannot sudo, the `--kill` revoke tears down a whole process group, and a **positive** bubblewrap-jail proof that a recursive grep cannot follow an in-workspace symlink out to `/etc`. |
| T3 | `install/target/3-elevation.sh` | `exec-argv-elevated` (renders `@OWNER_RUNAS@` → `OWNER_UNIX_USER`), the narrow NOPASSWD sudoers (`visudo -c` validated), root-only rundir, and generates `/etc/hestia/elevation.key` (0400) | 5 proofs: forged ticket **rejected**, a valid broker-HMAC ticket runs `id` **as the owner**, replay **rejected** (single-use), direct (non-sudo) invocation **refused** (not root), and an elevated `kill` terminates the owner-owned process group. |

After **T3**, copy the elevation key to the HOST:

```bash
sudo tailscale file cp /etc/hestia/elevation.key host:      # or: scp
```

### HOST track (run as root on the HOST)

| Step | Script | Installs | Proves (self-test) |
|------|--------|----------|--------------------|
| H1 | `install/host/1-users.sh` | `hestia-mover` (group `lxd` only), `hestia-broker` (no supplementary groups) | exact group sets (allowlist), no-sudo fence for both, not uid 0, homes 0700. |
| H2 | `install/host/2-mover.sh` | `mover.sh` → `/usr/local/lib/hestia/`, the spool group + `/var/lib/hestia-spool/{incoming,outgoing}` (2770), the box-side mailbox, and the `hestia-mover.service` unit (started) | broker still has **no** lxd/docker/sudo after joining `hestia-spool`, spool dir perms, that `hestia-mover` can actually drive `lxc` and see the box RUNNING, the box mailbox exists, and the service is active. |
| H3 | `install/host/3-broker-policy.sh` | `broker.py` → `/usr/local/lib/hestia/`, the append-only audit log (`chattr +a`) | runs `tests/test_broker.py` (the full decision-engine test), then proves the broker can **append** to the audit log but **cannot** rewrite/truncate (append-only) or unlink it (dir not broker-writable), and re-checks the no-sudo fence. |
| H4 | `install/host/4-import-elevation-key.sh [path]` | the elevation key copied from the TARGET → `/etc/hestia-broker/elevation.key` (0640 root:hestia-broker) | key perms, that `hestia-broker` can read it (→ elevation **enabled**), key length sane. **Skip this step to leave elevation disabled — a safe default.** |
| H5 | `install/host/5-broker-service.sh` | `broker.py` + `brokerd.py` → `/usr/local/lib/hestia/`, the `/etc/hestia-broker/broker.env` EnvironmentFile (0600 root:root, prompts for the bot token), and the **hardened** `hestia-broker.service` unit | code parses, EnvironmentFile perms are `600 root:root` and contain the token line (value never printed), the broker fence is intact, and `systemd-analyze verify` on the unit. Does **not** start the service unless `HESTIA_START=1`. |
| H6 | `install/host/6-fw-backstop.sh` | the independent nftables `hestia_backstop` table (hook priority -300, before Docker) + its boot service | box → tailnet is BLOCKED (probed from inside the box for each configured tailnet IP) while box → public internet stays OPEN. |

Start the broker last, once the mover and TARGET pieces are confirmed:

```bash
sudo HESTIA_START=1 bash install/host/5-broker-service.sh
#   or, if already installed:
sudo systemctl enable --now hestia-broker
```

If you imported the elevation key (H4) **after** the broker was already running, restart
it so it loads the key:

```bash
sudo systemctl restart hestia-broker
```

---

## 4. Why this order

- `hestia-broker` joins the `hestia-spool` group in **H2**. A long-running broker would
  not pick that up, so the broker service (H5) is started **after** H2.
- The broker relays to `exec-argv` / `exec-argv-elevated` on the TARGET, and mints
  elevation tickets with the shared key. All three must already exist on the TARGET
  (T2/T3) and the key imported (H4) before the broker can usefully run.
- Elevation is **disabled by default**: if the key is never imported (H4 skipped), the
  broker refuses elevated requests and the target wrapper refuses to run without a valid
  ticket. This is intentional fail-closed behavior.

---

## 5. After install — smoke test

From the HOST:

```bash
tailscale ssh hestia-agent@<target-tailscale-host> hostname     # SSH path works
sudo systemctl status hestia-mover hestia-broker                # both active
```

Then drive one command through the box → mover → broker → Telegram loop and confirm you
receive an approval button in Telegram. Free-zone read-only commands inside
`/srv/projects` auto-run; everything else waits for your tap. See `docs/operations.md`
for day-2 operations.
