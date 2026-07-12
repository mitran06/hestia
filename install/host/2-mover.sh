#!/usr/bin/env bash
# install/host/2-mover.sh — HOST (broker machine) step 2, run as root
# Installs the mailbox mover: spool group + dirs, box-side outbox/inbox, mover.sh, systemd unit.
# Installs FROM the repo:  broker/mover.sh  and  broker/hestia-mover.service.
# Idempotent + structurally self-verifying.
# Reversible: systemctl disable --now hestia-mover; rm -f /etc/systemd/system/hestia-mover.service
#             /usr/local/lib/hestia/mover.sh; rm -rf /var/lib/hestia-spool; groupdel hestia-spool
set -euo pipefail

# --- load site config (values may also come straight from the environment) ---
HESTIA_ENV="${HESTIA_ENV:-$(cd "$(dirname "$0")" && pwd)/../../config/hestia.env}"
[[ -f "$HESTIA_ENV" ]] && . "$HESTIA_ENV"

REPO="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"   # repo root (install/host/ -> ../../)

MOVER=hestia-mover
BROKER=hestia-broker
SPOOLGRP=hestia-spool
SPOOL="${HESTIA_SPOOL:-/var/lib/hestia-spool}"
LXC="${HESTIA_LXC:-/usr/sbin/lxc}"
BOX="${CONTAINER_NAME:?set CONTAINER_NAME in config/hestia.env}"
BOX_USER="${AGENT_BOX_USER:?set AGENT_BOX_USER in config/hestia.env}"
SRC_MOVER="$REPO/broker/mover.sh"
DST_MOVER=/usr/local/lib/hestia/mover.sh
SRC_UNIT="$REPO/broker/hestia-mover.service"
UNIT=/etc/systemd/system/hestia-mover.service

if [[ $EUID -ne 0 ]]; then echo "FATAL: run as root (sudo)." >&2; exit 1; fi
id "$MOVER"  &>/dev/null || { echo "FATAL: user $MOVER missing (run 1-users.sh first)." >&2; exit 1; }
id "$BROKER" &>/dev/null || { echo "FATAL: user $BROKER missing (run 1-users.sh first)." >&2; exit 1; }
[[ -x "$LXC" ]] || { echo "FATAL: $LXC not found." >&2; exit 1; }
[[ -f "$SRC_MOVER" ]] || { echo "FATAL: mover.sh not found at $SRC_MOVER." >&2; exit 1; }
[[ -f "$SRC_UNIT" ]] || { echo "FATAL: hestia-mover.service not found at $SRC_UNIT." >&2; exit 1; }
"$LXC" info "$BOX" >/dev/null 2>&1 || { echo "FATAL: cannot reach box $BOX via lxc." >&2; exit 1; }

echo "== Host step 2: spool group + members =="
getent group "$SPOOLGRP" >/dev/null || { groupadd "$SPOOLGRP"; echo "-- created group $SPOOLGRP"; }
id -nG "$MOVER"  | tr ' ' '\n' | grep -qx "$SPOOLGRP" || { gpasswd -a "$MOVER"  "$SPOOLGRP" >/dev/null; echo "-- added $MOVER to $SPOOLGRP"; }
id -nG "$BROKER" | tr ' ' '\n' | grep -qx "$SPOOLGRP" || { gpasswd -a "$BROKER" "$SPOOLGRP" >/dev/null; echo "-- added $BROKER to $SPOOLGRP"; }

echo "== host spool dirs =="
mkdir -p "$SPOOL/incoming" "$SPOOL/outgoing"
chown root:"$SPOOLGRP"    "$SPOOL";            chmod 0750 "$SPOOL"
chown "$MOVER":"$SPOOLGRP" "$SPOOL/incoming";  chmod 2770 "$SPOOL/incoming"   # mover writes, broker reads/deletes
chown "$BROKER":"$SPOOLGRP" "$SPOOL/outgoing"; chmod 2770 "$SPOOL/outgoing"   # broker writes, mover reads/deletes

echo "== box-side mailbox (owned by the in-box agent user) =="
"$LXC" exec "$BOX" -- install -d -o "$BOX_USER" -g "$BOX_USER" -m 0700 \
    "/home/$BOX_USER/broker" "/home/$BOX_USER/broker/outbox" "/home/$BOX_USER/broker/inbox"

echo "== install mover.sh =="
install -d -o root -g root -m 0755 /usr/local/lib/hestia
install -o root -g root -m 0755 "$SRC_MOVER" "$DST_MOVER"

echo "== install systemd unit =="
# NOTE: the `lxc` client is a snap app (/usr/sbin/lxc -> /snap/bin/lxc). systemd sandboxing
# (ProtectHome/ProtectSystem/NoNewPrivileges/PrivateTmp) can break snap's runtime, so this unit is
# MINIMAL and snap-safe. HOME is pinned in the unit so snap/lxc can write client state under the
# (0700) mover home in /home. The unit ships CONTAINER_NAME/AGENT_BOX_USER/HESTIA_SPOOL from config.
install -o root -g root -m 0644 "$SRC_UNIT" "$UNIT"
# Render this deployment's site values into the unit's Environment= lines (defaults match config).
sed -i \
  -e "s|^Environment=CONTAINER_NAME=.*|Environment=CONTAINER_NAME=$BOX|" \
  -e "s|^Environment=AGENT_BOX_USER=.*|Environment=AGENT_BOX_USER=$BOX_USER|" \
  -e "s|^Environment=HESTIA_SPOOL=.*|Environment=HESTIA_SPOOL=$SPOOL|" \
  "$UNIT"

systemctl daemon-reload
systemctl enable --now hestia-mover.service || true   # don't abort before VERIFY; diagnose below

echo
echo "== VERIFY (structural) =="
fail=0
# security fence still intact: broker gained hestia-spool but MUST NOT have lxd/docker/sudo
brk=$(id -nG "$BROKER" | tr ' ' '\n' | sort | paste -sd,)
echo "-- $BROKER groups now: {$brk}"
for g in lxd docker sudo adm wheel; do
  if id -nG "$BROKER" | tr ' ' '\n' | grep -qx "$g"; then echo "  FENCE VIOLATION: $BROKER in $g"; fail=1; fi
done
id -nG "$BROKER" | tr ' ' '\n' | grep -qx "$SPOOLGRP" || { echo "  ERROR: $BROKER not in $SPOOLGRP"; fail=1; }
id -nG "$MOVER"  | tr ' ' '\n' | grep -qx lxd         || { echo "  ERROR: $MOVER lost lxd"; fail=1; }
id -nG "$MOVER"  | tr ' ' '\n' | grep -qx "$SPOOLGRP" || { echo "  ERROR: $MOVER not in $SPOOLGRP"; fail=1; }

# dir perms
for d in "$SPOOL/incoming" "$SPOOL/outgoing"; do
  p=$(stat -c '%a' "$d"); [[ "$p" == 2770 ]] || { echo "  ERROR: $d is $p want 2770"; fail=1; }
done

# hestia-mover can actually drive lxc (prove the effect, not just group membership)
if runuser -u "$MOVER" -- "$LXC" list "$BOX" -c ns --format csv 2>/dev/null | grep -q RUNNING; then
  echo "-- $MOVER can drive lxc and see $BOX RUNNING (good)"
else
  echo "  ERROR: $MOVER cannot drive lxc"; fail=1
fi

# box-side mailbox exists
if "$LXC" exec "$BOX" -- test -d "/home/$BOX_USER/broker/outbox" && "$LXC" exec "$BOX" -- test -d "/home/$BOX_USER/broker/inbox"; then
  echo "-- box outbox+inbox exist (good)"
else
  echo "  ERROR: box mailbox dirs missing"; fail=1
fi

# service active (this is the ONLY check that exercises the real systemd sandbox — the runuser
# check above proves group+socket but NOT the unit's runtime env; trust the journal here).
sleep 3
if systemctl is-active --quiet hestia-mover.service; then
  echo "-- hestia-mover.service active (good). Recent log:"
  journalctl -u hestia-mover.service -n 6 --no-pager | sed 's/^/     /'
else
  echo "  ERROR: service not active. Journal:"; journalctl -u hestia-mover.service -n 25 --no-pager | sed 's/^/     /'; fail=1
fi

# NOTE: hestia-broker just joined hestia-spool. The (later) broker SERVICE must be started AFTER
# this so it inherits the group; a long-running broker would need a restart.

echo
if [[ $fail -eq 0 ]]; then
  echo "HOST STEP 2 (structural): OK — mover pipe installed and active."
else
  echo "HOST STEP 2 (structural): PROBLEMS — see above" >&2; exit 2
fi
