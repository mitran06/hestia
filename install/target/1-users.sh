#!/usr/bin/env bash
# install/target/1-users.sh  —  TARGET machine step 1, run as root
# Creates the restricted target execution user + the shared free-zone workspace.
#   - group   projects        : shared-access group (the owner + hestia-agent)
#   - user    hestia-agent     : member of `projects` ONLY; home 0700; NO sudo; password locked
#   - dir     /srv/projects    : 2770 root:projects (setgid) — the un-buttoned free zone
# Idempotent + self-verifying (exact-set group allowlist, not a denylist). Run as root ON the TARGET (sudo).
# Reversible:  userdel -r hestia-agent ; groupdel projects ; rm -rf /srv/projects
set -euo pipefail

# --- load site config (values may also come straight from the environment) ---
HESTIA_ENV="${HESTIA_ENV:-$(cd "$(dirname "$0")" && pwd)/../../config/hestia.env}"
[[ -f "$HESTIA_ENV" ]] && . "$HESTIA_ENV"

AGENT=hestia-agent
AGENT_HOME=/home/hestia-agent
PGROUP=projects
WORKSPACE="${WORKSPACE:-/srv/projects}"
OWNER="${OWNER_UNIX_USER:?set OWNER_UNIX_USER in config/hestia.env (your own account on this target)}"
SHELL_BIN=/bin/bash          # needed so `tailscale ssh hestia-agent@<target> -- <cmd>` can exec

if [[ $EUID -ne 0 ]]; then echo "FATAL: must run as root (sudo)." >&2; exit 1; fi
id "$OWNER" &>/dev/null || { echo "FATAL: owner user '$OWNER' not found on this target." >&2; exit 1; }
command -v sudo >/dev/null || { echo "FATAL: sudo not installed; cannot verify the sudo fence." >&2; exit 1; }

echo "== Target step 1: shared group, restricted user, free-zone workspace =="

# --- shared group ---
getent group "$PGROUP" >/dev/null || { groupadd "$PGROUP"; echo "-- created group $PGROUP"; }

# --- restricted execution user ---
if id "$AGENT" &>/dev/null; then
  echo "-- $AGENT exists; enforcing shell + groups (projects only)"
  usermod --shell "$SHELL_BIN" "$AGENT"
  usermod --groups "$PGROUP" "$AGENT"    # REPLACE (no -a) supplementary groups with exactly {projects}
  AGENT_HOME="$(getent passwd "$AGENT" | cut -d: -f6)"
else
  useradd --user-group --create-home --home-dir "$AGENT_HOME" \
          --shell "$SHELL_BIN" --groups "$PGROUP" "$AGENT"
  echo "-- created $AGENT"
fi
usermod -L "$AGENT" 2>/dev/null || true   # lock password auth; reach it only via Tailscale SSH
chmod 0700 "$AGENT_HOME"
chown "$AGENT":"$AGENT" "$AGENT_HOME"
command -v restorecon >/dev/null && restorecon -R "$AGENT_HOME" || true

# --- owner joins projects (takes effect in NEW sessions; re-login for current shells) ---
if ! id -nG "$OWNER" | tr ' ' '\n' | grep -qx "$PGROUP"; then
  gpasswd -a "$OWNER" "$PGROUP" >/dev/null; echo "-- added $OWNER to $PGROUP"
fi

# --- the shared free-zone workspace ---
mkdir -p "$WORKSPACE"
chown root:"$PGROUP" "$WORKSPACE"
chmod 2770 "$WORKSPACE"            # rwxrws--- : owner root, group projects, setgid, no 'other'
command -v restorecon >/dev/null && restorecon -R "$WORKSPACE" || true

echo
echo "== VERIFY (script exits non-zero if any fence is wrong) =="
fail=0

# EXACT-SET group check (allowlist): closes the whole class of "unexpected extra group".
assert_exact_groups() {  # $1=user  $2=comma-joined-SORTED-expected
  local u="$1" want="$2" got
  got=$(id -nG "$u" | tr ' ' '\n' | sort | paste -sd,)
  if [[ "$got" == "$want" ]]; then
    echo "-- $u: groups = {$got}  (exactly as required)"
  else
    echo "  FENCE VIOLATION: $u groups are {$got}, want {$want}"; fail=1
  fi
}

check_no_sudo() {  # fail-closed: only a positive "not allowed" passes
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

# hestia-agent must be in EXACTLY {hestia-agent, projects}
assert_exact_groups "$AGENT" "$(printf '%s\n%s\n' "$AGENT" "$PGROUP" | sort | paste -sd,)"
# primary group must be its own private group
if [[ "$(id -gn "$AGENT")" != "$AGENT" ]]; then echo "  FENCE VIOLATION: $AGENT primary group is $(id -gn "$AGENT"), want $AGENT"; fail=1; fi
check_no_sudo "$AGENT"

# home must be 0700
perm=$(stat -c '%a' "$AGENT_HOME"); if [[ "$perm" != 700 ]]; then echo "  FENCE VIOLATION: $AGENT_HOME is $perm, want 700"; fail=1; fi

# workspace must be 2770 root:projects
wperm=$(stat -c '%a' "$WORKSPACE"); wown=$(stat -c '%U:%G' "$WORKSPACE")
if [[ "$wperm" != 2770 ]]; then echo "  FENCE VIOLATION: $WORKSPACE is $wperm, want 2770"; fail=1; fi
if [[ "$wown"  != "root:$PGROUP" ]]; then echo "  FENCE VIOLATION: $WORKSPACE owned $wown, want root:$PGROUP"; fail=1; fi

# owner must be in projects (so he can use the workspace)
if ! id -nG "$OWNER" | tr ' ' '\n' | grep -qx "$PGROUP"; then
  echo "  NOTE: $OWNER not yet showing in $PGROUP in THIS shell — added to /etc/group; effective on next login."
fi

# informational: hestia-agent must not be able to read the owner's home
mperm=$(stat -c '%a' /home/"$OWNER" 2>/dev/null || echo "?")
echo "-- /home/$OWNER perms = $mperm (want NOT world/group readable; hestia-agent is not in $OWNER's group)"

echo
if [[ $fail -eq 0 ]]; then
  echo "TARGET STEP 1: ALL FENCES VERIFIED OK"
  echo "NEXT: from the HOST run  'tailscale ssh $AGENT@<target-tailscale-host> hostname'  to smoke-test SSH for the new user."
else
  echo "TARGET STEP 1: FENCE VIOLATIONS PRESENT — see above" >&2; exit 2
fi
