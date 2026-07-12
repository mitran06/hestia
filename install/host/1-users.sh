#!/usr/bin/env bash
# install/host/1-users.sh  —  HOST (broker machine) step 1
# Creates the two host trust-domain users with STRICT privilege fences.
#   - hestia-mover : supplementary group `lxd` ONLY (dumb pipe; no secrets, no policy)
#   - hestia-broker: NO supplementary groups (policy+token; must have no lxd/docker/sudo)
# Idempotent + self-verifying (exact-set group allowlist, not a denylist). Run as root
# ON the host (the broker machine), via sudo.
# Reversible:  userdel -r hestia-mover ; userdel -r hestia-broker
#   (WARNING: -r deletes the home; do not use once the broker's token/state lives there.)
set -euo pipefail

# --- load site config (values may also come straight from the environment) ---
HESTIA_ENV="${HESTIA_ENV:-$(cd "$(dirname "$0")" && pwd)/../../config/hestia.env}"
[[ -f "$HESTIA_ENV" ]] && . "$HESTIA_ENV"

MOVER=hestia-mover
BROKER=hestia-broker
MOVER_HOME=/home/hestia-mover   # MUST be under /home: mover runs the snap `lxc` client, and snap
                                # refuses homes outside /home. (broker below never runs a snap tool.)
BROKER_HOME=/var/lib/hestia-broker
NOLOGIN=/usr/sbin/nologin

if [[ $EUID -ne 0 ]]; then echo "FATAL: must run as root (sudo)." >&2; exit 1; fi
[[ -x "$NOLOGIN" ]] || { echo "FATAL: $NOLOGIN not found." >&2; exit 1; }
getent group lxd >/dev/null || { echo "FATAL: group 'lxd' does not exist." >&2; exit 1; }
command -v sudo >/dev/null || { echo "FATAL: sudo not installed; cannot verify the sudo fence." >&2; exit 1; }

echo "== Host step 1: creating fenced users =="

# --- hestia-mover : own private primary group + supplementary lxd, nothing else ---
if id "$MOVER" &>/dev/null; then
  echo "-- $MOVER exists; enforcing shell + groups (lxd only)"
  usermod --shell "$NOLOGIN" "$MOVER"
  usermod --groups lxd "$MOVER"          # REPLACE (no -a) supplementary groups with exactly {lxd}
  MOVER_HOME="$(getent passwd "$MOVER" | cut -d: -f6)"
else
  useradd --system --user-group --create-home --home-dir "$MOVER_HOME" \
          --shell "$NOLOGIN" --groups lxd "$MOVER"
  echo "-- created $MOVER"
fi
usermod -L "$MOVER" 2>/dev/null || true   # lock password auth (exec is via lxd group only)

# --- hestia-broker : own private primary group, NO supplementary groups ---
if id "$BROKER" &>/dev/null; then
  echo "-- $BROKER exists; enforcing shell + groups (none)"
  usermod --shell "$NOLOGIN" "$BROKER"
  usermod --groups "" "$BROKER"          # REPLACE (no -a) supplementary groups with exactly {}
  BROKER_HOME="$(getent passwd "$BROKER" | cut -d: -f6)"
else
  useradd --system --user-group --create-home --home-dir "$BROKER_HOME" \
          --shell "$NOLOGIN" "$BROKER"
  echo "-- created $BROKER"
fi
usermod -L "$BROKER" 2>/dev/null || true

chmod 0700 "$MOVER_HOME" "$BROKER_HOME"
chown "$MOVER":"$MOVER"   "$MOVER_HOME"
chown "$BROKER":"$BROKER" "$BROKER_HOME"

echo
echo "== VERIFY privilege fences (script exits non-zero if any fence is wrong) =="
fail=0

# EXACT-SET group check: the group set must be EXACTLY what we expect (allowlist, not denylist).
# id -nG lists primary + supplementary, so this also pins the primary group.
assert_exact_groups() {  # $1=user  $2=comma-joined-SORTED-expected
  local u="$1" want="$2" got
  got=$(id -nG "$u" | tr ' ' '\n' | sort | paste -sd,)
  if [[ "$got" == "$want" ]]; then
    echo "-- $u: groups = {$got}  (exactly as required)"
  else
    echo "  FENCE VIOLATION: $u groups are {$got}, want {$want}"; fail=1
  fi
}

check_no_sudo() {  # $1=user — fail-closed: only a positive "not allowed" passes
  local u="$1" out
  out="$(sudo -n -l -U "$u" 2>&1 || true)"
  if echo "$out" | grep -Eq '\(ALL|NOPASSWD|may run'; then
    echo "  FENCE VIOLATION: $u has sudo entries:"; echo "$out" | sed 's/^/     /'; fail=1
  elif echo "$out" | grep -q 'not allowed to run sudo'; then
    echo "-- $u: no sudo privileges (good)"
  else
    echo "  FENCE VIOLATION: could not positively confirm $u has NO sudo. Output:"; echo "$out" | sed 's/^/     /'; fail=1
  fi
}

# mover: exactly {its private group, lxd}    broker: exactly {its private group}
assert_exact_groups "$MOVER"  "$(printf '%s\n%s\n' "$MOVER" lxd | sort | paste -sd,)"
assert_exact_groups "$BROKER" "$BROKER"

# primary group must equal the username (own private group)
for u in "$MOVER" "$BROKER"; do
  if [[ "$(id -gn "$u")" != "$u" ]]; then echo "  FENCE VIOLATION: $u primary group is $(id -gn "$u"), want $u"; fail=1; fi
done

check_no_sudo "$MOVER"
check_no_sudo "$BROKER"

# neither may be uid 0
for u in "$MOVER" "$BROKER"; do
  if [[ "$(id -u "$u")" -eq 0 ]]; then echo "  FENCE VIOLATION: $u is uid 0"; fail=1; fi
done

# homes must be 0700
for h in "$MOVER_HOME" "$BROKER_HOME"; do
  perm=$(stat -c '%a' "$h"); if [[ "$perm" != 700 ]]; then echo "  FENCE VIOLATION: $h is $perm, want 700"; fail=1; fi
done

echo
if [[ $fail -eq 0 ]]; then
  echo "HOST STEP 1: ALL FENCES VERIFIED OK"
else
  echo "HOST STEP 1: FENCE VIOLATIONS PRESENT — see above" >&2; exit 2
fi
