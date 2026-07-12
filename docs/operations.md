# Hestia — day-2 operations

Operating the running broker/relay: starting and stopping the services, reading the
tamper-evident audit log, revoking in-flight work, checking the firewall, and rolling
back. Assumes the install runbook (`docs/installation.md`) has completed.

---

## 1. The three host services

| Service | Runs as | What it does |
|---------|---------|--------------|
| `hestia-mover` | `hestia-mover` | Dumb pipe: moves opaque UUID-named blobs between the confined box and the host spool. No policy, no secrets. |
| `hestia-broker` | `hestia-broker` | Policy engine + Telegram approval + relay to the target over Tailscale SSH. Holds the bot token and (optionally) the elevation key. |
| `hestia-fw-backstop` | root (oneshot) | Loads the independent nftables table that fences the box off the tailnet. `RemainAfterExit` — it applies rules at boot, not a long-running process. |

### Start / stop / status

```bash
sudo systemctl status  hestia-mover hestia-broker
sudo systemctl start   hestia-broker
sudo systemctl stop    hestia-broker
sudo systemctl restart hestia-broker          # e.g. after importing the elevation key
sudo systemctl enable  --now hestia-mover     # enable at boot + start now
```

### Logs

```bash
journalctl -u hestia-broker -f                # follow the broker (approvals, relays, errors)
journalctl -u hestia-mover  -n 50 --no-pager  # recent mover activity
```

The broker also emits structured decisions to the **audit log** (below); the journal is
the operational view, the audit log is the tamper-evident record.

---

## 2. Reading the append-only audit log

Location: `/var/lib/hestia-broker/log/audit.log`. It is **append-only** (`chattr +a`):
the broker can add lines but cannot rewrite or delete history. Each line is one JSON
record (a decision, a session event, or a start marker).

```bash
sudo tail -f /var/lib/hestia-broker/log/audit.log            # watch live decisions
sudo tail -n 50 /var/lib/hestia-broker/log/audit.log | python3 -m json.tool --json-lines 2>/dev/null \
  || sudo tail -n 50 /var/lib/hestia-broker/log/audit.log    # pretty-print if your python supports it
```

Fields you will see include `decision` (`IN_SCOPE` = auto-run free-zone, `NEEDS_BUTTON`
= waited for your tap, `REJECT` = malformed/blocked), `reason`, `cmd_hash`,
`session_id`, `request_id`, `cwd`, `elevate`, `argv`, plus lifecycle events like
`BROKER_START`, `SESSION_OPENED`, and elevated `run_as`.

**Verify it is still append-only:**

```bash
lsattr /var/lib/hestia-broker/log/audit.log     # the 'a' attribute must be present
```

**Rotation** is handled by `broker/hestia-broker-audit.logrotate` (install it to
`/etc/logrotate.d/hestia-broker`). It drops `+a`, rotates create-style, and re-applies
`+a` to both the new and rotated files so history stays tamper-evident. To rotate by
hand once:

```bash
sudo logrotate -f /etc/logrotate.d/hestia-broker
```

---

## 3. Revoke: `/panic` and STOP

Every relayed command runs in its **own process group**, keyed by an exec token, so it
can be torn down remotely even though the local SSH client exiting would not kill the
remote tree.

- **`/panic`** — send `/panic` (or tap the session STOP button) to the broker bot in
  Telegram. The broker closes the open session, kills every in-flight command tree (via
  `exec-argv --kill <token>` on the target, or the elevated `kill` for owner-owned
  trees), and denies all pending approval buttons.
- A single command can also be denied at its button; if it was already running, the
  broker issues the kill for that token.

Elevated (owner-owned) process groups cannot be signalled by `hestia-agent`, so their
revoke goes through `sudo -n exec-argv-elevated kill <ticket>` — a broker-minted,
HMAC-signed kill ticket. Both paths are idempotent (safe to retry).

To confirm nothing lingers after a panic, check for leftover pgid markers:

```bash
# on the target
sudo ls -la /home/hestia-agent/.hestia-run/     # free-zone pgid files (should drain)
sudo ls -la /var/lib/hestia-elevated/           # elevated pgid + single-use markers
```

---

## 4. Checking the firewall backstop

The backstop is an **independent** nftables table (`hestia_backstop`, hook priority
-300) that DROPs any forward from the box bridge to the tailnet, so a Docker/iptables
flush cannot open a drift window.

```bash
sudo nft list table inet hestia_backstop        # the DROP rules must be present
sudo systemctl status hestia-fw-backstop        # RemainAfterExit=yes -> "active (exited)"
```

Re-run the self-testing installer any time to re-apply **and re-prove** (box cannot
reach the tailnet, box still reaches the internet):

```bash
sudo bash install/host/6-fw-backstop.sh
```

The Phase-1 egress firewall (box → internet policy) is separate; this backstop only
closes the box → tailnet weakest-link window.

---

## 5. Rollback / uninstall

Each piece is independently reversible. Stop services before removing their files.

**HOST**

```bash
# broker service
sudo systemctl disable --now hestia-broker
sudo rm -f /etc/systemd/system/hestia-broker.service /etc/hestia-broker/broker.env \
           /usr/local/lib/hestia/broker.py /usr/local/lib/hestia/brokerd.py
# elevation key (disables elevation)
sudo rm -f /etc/hestia-broker/elevation.key
# mover
sudo systemctl disable --now hestia-mover
sudo rm -f /etc/systemd/system/hestia-mover.service /usr/local/lib/hestia/mover.sh
sudo rm -rf /var/lib/hestia-spool
sudo groupdel hestia-spool 2>/dev/null || true
# audit log (drop append-only first)
sudo chattr -a /var/lib/hestia-broker/log/audit.log 2>/dev/null || true
sudo rm -rf /var/lib/hestia-broker/log
# firewall backstop
sudo systemctl disable --now hestia-fw-backstop
sudo nft delete table inet hestia_backstop 2>/dev/null || true
sudo rm -f /etc/nftables.d/hestia-backstop.nft /etc/systemd/system/hestia-fw-backstop.service
# users (WARNING: -r deletes the home; do not use once broker state you care about lives there)
sudo userdel -r hestia-mover  2>/dev/null || true
sudo userdel -r hestia-broker 2>/dev/null || true
sudo systemctl daemon-reload
```

**TARGET**

```bash
sudo rm -f /usr/local/lib/hestia/exec-argv /usr/local/lib/hestia/exec-argv-elevated
sudo rm -f /etc/sudoers.d/hestia-elevated /etc/hestia/elevation.key
sudo rm -rf /var/lib/hestia-elevated
sudo userdel -r hestia-agent 2>/dev/null || true
sudo groupdel projects 2>/dev/null || true
sudo rm -rf /srv/projects            # only if you do not want the workspace contents
```

Re-running any installer is safe (idempotent); prefer re-running over hand-editing when
you want to restore a known-good state.

---

## 6. Troubleshooting

**Broker won't start / dies immediately.** `journalctl -u hestia-broker -n 40`. Common
causes: missing/blank bot token (re-run `install/host/5-broker-service.sh`), or the
sandbox blocking Tailscale/Telegram. To loosen the sandbox, follow the tuning note in
`broker/hestia-broker.service`: drop `RestrictNamespaces`, then `ProtectSystem=strict`
→ `full`, then widen `ReadWritePaths` — verifying after each change.

**No Telegram button appears.** Confirm `HESTIA_OWNER_ID` is your numeric id (not a
username) and that you have messaged the bot at least once. The broker honors taps
**only** from that id; a wrong id fails closed (matches nobody).

**Free-zone commands refuse to run.** `exec-argv` fails closed if bubblewrap can't spawn
a user-namespace sandbox. Re-run `install/target/2-exec-argv.sh` and read the bwrap
proof; enable unprivileged user namespaces if your kernel/AppArmor disables them.

**Elevated commands rejected.** Check the key is imported on the HOST
(`/etc/hestia-broker/elevation.key`, readable by `hestia-broker`) **and** present on the
TARGET (`/etc/hestia/elevation.key`) — they must be the same bytes. Restart the broker
after importing. Tickets are single-use and TTL-bounded (300s); clock skew between HOST
and TARGET will expire them.

**Mover shows nothing moving.** Confirm the box is RUNNING (`lxc info <box>`) and that
`hestia-mover` can drive `lxc` (`sudo runuser -u hestia-mover -- lxc list`). The mover
silently drops non-UUID / oversize blobs by design; check `journalctl -u hestia-mover`.

**Audit log lost its append-only flag** (e.g. after a bad restore). Re-apply:

```bash
sudo chattr +a /var/lib/hestia-broker/log/audit.log
```
