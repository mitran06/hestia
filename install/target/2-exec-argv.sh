#!/usr/bin/env bash
# install/target/2-exec-argv.sh — TARGET machine step 2, run as root
# Installs the exec-argv wrapper (the free-zone executor), installs bubblewrap, and PROVES:
#   (Part 4) the authoritative realpath (symlink-aware) scope check + the wrapper's OWN allowlist,
#            by invoking it AS hestia-agent (the real execution identity) with crafted payloads;
#   (Part 7) the process-group `--kill` revoke primitive terminates a running command tree, the scope
#            check still holds after redeploy, and the bubblewrap free-zone JAIL positively hides /etc.
# Installs FROM the repo:  target/exec-argv.  Idempotent; the wrapper is overwritten in place.
# Reversible: rm -f /usr/local/lib/hestia/exec-argv
set -uo pipefail

# --- load site config (values may also come straight from the environment) ---
HESTIA_ENV="${HESTIA_ENV:-$(cd "$(dirname "$0")" && pwd)/../../config/hestia.env}"
[[ -f "$HESTIA_ENV" ]] && . "$HESTIA_ENV"

REPO="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"

AGENT=hestia-agent
OWNER="${OWNER_UNIX_USER:?set OWNER_UNIX_USER in config/hestia.env (your own account on this target)}"
WS="${WORKSPACE:-/srv/projects}"
SRC="$REPO/target/exec-argv"
DST=/usr/local/lib/hestia/exec-argv
RUNDIR=/home/hestia-agent/.hestia-run

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
id "$AGENT" &>/dev/null || { echo "FATAL: $AGENT missing (run install/target/1-users.sh)"; exit 1; }
id "$OWNER" &>/dev/null || { echo "FATAL: owner user '$OWNER' not found on this target"; exit 1; }
[[ -f "$SRC" ]] || { echo "FATAL: exec-argv not found ($SRC)"; exit 1; }
python3 -c 'import sys' || { echo "FATAL: python3 missing"; exit 1; }

echo "== install exec-argv + ensure revoke rundir =="
install -d -o root -g root -m 0755 /usr/local/lib/hestia
install -o root -g root -m 0755 "$SRC" "$DST"
install -d -o "$AGENT" -g "$AGENT" -m 0700 "$RUNDIR"

echo "== free-zone JAIL prerequisite: bubblewrap MUST be installed (exec-argv fails closed without it) =="
if ! command -v bwrap >/dev/null; then
  echo "-- installing bubblewrap"
  if   command -v dnf     >/dev/null; then dnf install -y bubblewrap
  elif command -v apt-get >/dev/null; then apt-get update && apt-get install -y bubblewrap
  elif command -v pacman  >/dev/null; then pacman -Sy --noconfirm bubblewrap
  else echo "  (install bubblewrap manually — free-zone auto-run will REFUSE until present)"; fi
fi

# helpers
b64(){ python3 -c 'import base64,json,sys;print(base64.b64encode(json.dumps(json.loads(sys.argv[1])).encode()).decode())' "$1"; }
run(){ sudo -u "$AGENT" "$DST" "$(b64 "$1")"; }   # returns exec-argv exit code
runa(){ sudo -u "$AGENT" "$DST" "$@"; }
count(){ pgrep -u "$AGENT" -f "$1" | wc -l | tr -d ' '; }

pass=0; fail=0
ok(){ echo "  PASS: $*"; pass=$((pass+1)); }
bad(){ echo "  FAIL: $*"; fail=$((fail+1)); }
expect(){ local want=$1 got=$2 name=$3; [[ "$got" == "$want" ]] && ok "$name (exit $got)" || bad "$name: got exit $got want $want"; }

# seed a workspace file + a hostile symlink escaping to /etc
install -d -o "$AGENT" -g projects -m 2770 "$WS" 2>/dev/null || true
sudo -u "$AGENT" sh -c "echo hello-workspace > $WS/probe.txt" 2>/dev/null || echo "hello-workspace" > "$WS/probe.txt"
ln -sfn /etc "$WS/evil"

echo
echo "== VERIFY exec-argv scope enforcement (as $AGENT) =="

echo "-- A: free-zone ls INSIDE workspace -> runs (exit 0)"
out=$(run "{\"cwd\":\"$WS\",\"argv\":[\"ls\",\"-la\"],\"workspace_only\":true}" 2>&1); rc=$?
expect 0 $rc "free-zone ls in workspace"; echo "$out" | grep -q probe.txt && ok "output shows probe.txt" || bad "no probe.txt in output"

echo "-- B: cwd is a SYMLINK escaping to /etc -> REFUSED (exit 40)"
run "{\"cwd\":\"$WS/evil\",\"argv\":[\"ls\"],\"workspace_only\":true}" >/dev/null 2>&1; expect 40 $? "symlink cwd escape refused"

echo "-- C: ARG resolves through symlink to /etc -> REFUSED (exit 41)"
run "{\"cwd\":\"$WS\",\"argv\":[\"cat\",\"evil/hostname\"],\"workspace_only\":true}" >/dev/null 2>&1; expect 41 $? "symlink arg escape refused"

echo "-- D: absolute arg outside workspace, workspace_only -> REFUSED (exit 41)"
run "{\"cwd\":\"$WS\",\"argv\":[\"cat\",\"/etc/hostname\"],\"workspace_only\":true}" >/dev/null 2>&1; expect 41 $? "abs arg outside workspace refused"

echo "-- D2: interpreter as argv[0] in free-zone -> REFUSED by exec-argv's OWN allowlist (exit 44)"
run "{\"cwd\":\"$WS\",\"argv\":[\"/bin/sh\",\"-c\",\"cat /etc/hostname\"],\"workspace_only\":true}" >/dev/null 2>&1; expect 44 $? "interpreter argv[0] refused independently"

echo "-- D3: flag carrying an out-of-tree path (--file=/etc/hostname) -> REFUSED (exit 41)"
run "{\"cwd\":\"$WS\",\"argv\":[\"cat\",\"--file=/etc/hostname\"],\"workspace_only\":true}" >/dev/null 2>&1; expect 41 $? "glued flag-path refused"

echo "-- E: APPROVED mode (workspace_only=false) may read a WORLD-readable outside file -> runs (0)"
run "{\"cwd\":\"$WS\",\"argv\":[\"cat\",\"/etc/hostname\"],\"workspace_only\":false}" >/dev/null 2>&1; expect 0 $? "approved-mode reads /etc/hostname"

echo "-- F: even APPROVED (non-elevated) is DAC-fenced from the owner's private files -> nonzero"
run "{\"cwd\":\"$WS\",\"argv\":[\"cat\",\"/home/$OWNER/.bashrc\"],\"workspace_only\":false}" >/tmp/hestia-f.out 2>&1; rc=$?
[[ $rc -ne 0 ]] && ok "approved-mode CANNOT read /home/$OWNER (DAC; needs sudoers-elevation, later) exit=$rc" || bad "read $OWNER home as hestia-agent!"

echo "-- G: hestia-agent still cannot sudo"
sudo -u "$AGENT" sudo -n true 2>/dev/null && bad "hestia-agent can sudo!" || ok "hestia-agent cannot sudo"

rm -f "$WS/evil" "$WS/probe.txt" /tmp/hestia-f.out

echo
echo "== PROVE revoke: launch a command TREE, kill its process group, confirm it dies =="
# restore the free-zone workspace to root-owned (the seed above left it hestia-agent-owned; root
# ownership stops the untrusted exec user from chmod'ing/restructuring the workspace root).
chown root:projects "$WS" 2>/dev/null && chmod 2770 "$WS" && echo "-- workspace $WS -> root:projects 2770" || true
MARK=$(( (RANDOM % 5000) + 4000 ))      # unique-ish marker for the sleep tree
TOK=$(cat /proc/sys/kernel/random/uuid)
PAY=$(b64 "{\"cwd\":\"$WS\",\"argv\":[\"bash\",\"-c\",\"sleep $MARK & sleep $MARK & wait\"],\"workspace_only\":false,\"exec_token\":\"$TOK\"}")
runa "$PAY" >/dev/null 2>&1 &            # backgrounds bash + 2 sleeps, all in one process group
BG=$!
sleep 2
before=$(count "sleep $MARK")
[[ "$before" -ge 2 ]] && ok "command tree running (matched $before procs)" || bad "tree not running (matched $before)"
[[ -f "$RUNDIR/$TOK.pgid" ]] && ok "pgid file written ($(cat "$RUNDIR/$TOK.pgid"))" || bad "no pgid file"
echo "-- revoke via: exec-argv --kill $TOK"
runa --kill "$TOK"
sleep 1
after=$(count "sleep $MARK")
[[ "$after" -eq 0 ]] && ok "ENTIRE process group killed (0 procs remain)" || bad "$after procs survived revoke"
[[ ! -f "$RUNDIR/$TOK.pgid" ]] && ok "pgid file cleaned up after kill" || bad "pgid file lingered"
wait "$BG" 2>/dev/null

echo
echo "== regression: scope enforcement still holds after redeploy =="
sudo -u "$AGENT" sh -c "echo hi > $WS/probe.txt" 2>/dev/null || echo hi > "$WS/probe.txt"
runa "$(b64 "{\"cwd\":\"$WS\",\"argv\":[\"ls\"],\"workspace_only\":true,\"exec_token\":\"$(cat /proc/sys/kernel/random/uuid)\"}")" >/dev/null 2>&1
[[ $? -eq 0 ]] && ok "free-zone ls (with token) runs (exit 0)" || bad "free-zone ls failed"
ln -sfn /etc "$WS/evil"
runa "$(b64 "{\"cwd\":\"$WS/evil\",\"argv\":[\"ls\"],\"workspace_only\":true}")" >/dev/null 2>&1
[[ $? -eq 40 ]] && ok "symlink cwd escape still refused (exit 40)" || bad "scope check regressed (exit $?)"
rm -f "$WS/evil" "$WS/probe.txt"

echo
echo "== free-zone JAIL: bwrap MUST be usable + POSITIVE proof it hides /etc =="
# probe the REAL jail shape (bind /usr + the /bin.. symlinks + --proc), running an absolute-path /usr/bin/true
if bwrap --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
        --symlink usr/sbin /sbin --proc /proc --dev /dev --tmpfs /tmp --unshare-all --die-with-parent -- /usr/bin/true 2>/dev/null; then
  ok "bwrap can spawn the free-zone userns sandbox"
else
  bad "bwrap cannot spawn a userns sandbox (userns disabled / AppArmor) — free-zone auto-run will REFUSE"
fi
# POSITIVE jail test: a recursive free-zone grep must NOT read through an in-workspace symlink to /etc,
# BECAUSE the jail hides /etc (not merely because a scope exit code fired).
sudo -u "$AGENT" sh -c "ln -sfn /etc $WS/evil; echo needle > $WS/real.txt" 2>/dev/null || { ln -sfn /etc "$WS/evil"; echo needle > "$WS/real.txt"; }
JOUT=$(runa "$(b64 "{\"cwd\":\"$WS\",\"argv\":[\"grep\",\"-rl\",\"root\",\".\"],\"workspace_only\":true,\"exec_token\":\"$(cat /proc/sys/kernel/random/uuid)\"}")" 2>/dev/null)
echo "$JOUT" | grep -q "evil" && bad "JAIL LEAK: recursive grep followed evil->/etc ($JOUT)" || ok "jail hid /etc: recursive grep found no out-of-tree data"
rm -f "$WS/evil" "$WS/real.txt"

echo
if [[ $fail -eq 0 ]]; then
  echo "TARGET STEP 2 (exec-argv scope + revoke + jail): ALL PROOFS PASS ($pass)."
  echo "exec-argv is scope-enforcing, revocable, and free-zone jailed (fail-closed)."
else
  echo "TARGET STEP 2: $fail FAILURES above" >&2; exit 2
fi
