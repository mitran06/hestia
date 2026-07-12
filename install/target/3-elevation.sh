#!/usr/bin/env bash
# install/target/3-elevation.sh — TARGET machine step 3 ELEVATION, run as root
# Installs exec-argv-elevated + the narrow NOPASSWD sudoers line + the root rundir + generates the shared
# HMAC key, then PROVES the whole elevated path: forged ticket rejected, valid broker-signed ticket runs
# as the owner, replay rejected, non-sudo invocation refused, and an elevated kill terminates the group.
# After this, copy /etc/hestia/elevation.key to the HOST (broker) and run install/host/4-import-elevation-key.sh.
#
# Installs FROM the repo:  target/exec-argv-elevated  (RENDERS @OWNER_RUNAS@ -> $OWNER_UNIX_USER at install),
#                          target/hestia-elevated.sudoers.
# Reversible: rm /usr/local/lib/hestia/exec-argv-elevated /etc/sudoers.d/hestia-elevated
#             /etc/hestia/elevation.key; rm -rf /var/lib/hestia-elevated
set -uo pipefail

# --- load site config (values may also come straight from the environment) ---
HESTIA_ENV="${HESTIA_ENV:-$(cd "$(dirname "$0")" && pwd)/../../config/hestia.env}"
[[ -f "$HESTIA_ENV" ]] && . "$HESTIA_ENV"

REPO="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"

AGENT=hestia-agent
OWNER="${OWNER_UNIX_USER:?set OWNER_UNIX_USER in config/hestia.env (elevated commands run AS this user)}"
SRC="$REPO/target/exec-argv-elevated"
DST=/usr/local/lib/hestia/exec-argv-elevated
SRC_SUDOERS="$REPO/target/hestia-elevated.sudoers"
SUDOERS=/etc/sudoers.d/hestia-elevated
RUNDIR=/var/lib/hestia-elevated
KEY=/etc/hestia/elevation.key

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
id "$AGENT" &>/dev/null && id "$OWNER" &>/dev/null || { echo "FATAL: users missing ($AGENT / $OWNER)"; exit 1; }
[[ -f "$SRC" ]] || { echo "FATAL: exec-argv-elevated not found ($SRC)"; exit 1; }
[[ -f "$SRC_SUDOERS" ]] || { echo "FATAL: hestia-elevated.sudoers not found ($SRC_SUDOERS)"; exit 1; }
command -v python3 >/dev/null || { echo "FATAL: python3 missing"; exit 1; }

echo "== install wrapper (render @OWNER_RUNAS@ -> $OWNER) + rundir =="
install -d -o root -g root -m 0755 /usr/local/lib/hestia
# Render the owner run-as into the wrapper's ALLOWED_RUNAS, then install the rendered copy 0755 root:root.
tmpw="$(mktemp)"
sed "s/@OWNER_RUNAS@/$OWNER/g" "$SRC" > "$tmpw"
grep -q '@OWNER_RUNAS@' "$tmpw" && { echo "FATAL: placeholder still present after render"; rm -f "$tmpw"; exit 2; }
install -o root -g root -m 0755 "$tmpw" "$DST"; rm -f "$tmpw"
install -d -o root -g root -m 0700 "$RUNDIR"            # root-only: agent CANNOT tamper pgid/used markers
install -d -o root -g root -m 0755 /etc/hestia

echo "== generate shared HMAC key (if absent) =="
if [[ ! -f "$KEY" ]]; then
  ( umask 377; head -c 48 /dev/urandom | base64 -w0 > "$KEY" ); chown root:root "$KEY"; chmod 0400 "$KEY"
  echo "-- generated $KEY (root 0400) — COPY IT to the HOST next"
else
  echo "-- $KEY already exists (kept)"
fi

echo "== install narrow sudoers (one binary, no wildcards; the HMAC ticket is the real gate) =="
install -o root -g root -m 0440 "$SRC_SUDOERS" "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null && echo "-- sudoers valid" || { echo "  ERROR: sudoers invalid"; rm -f "$SUDOERS"; exit 2; }

# ---- proofs ----
pass=0; fail=0; ok(){ echo "  PASS: $*"; pass=$((pass+1)); }; bad(){ echo "  FAIL: $*"; fail=$((fail+1)); }
mint(){ python3 - "$1" "$2" <<'PY'
import sys,json,base64,hmac,hashlib,time
action, fields = sys.argv[1], json.loads(sys.argv[2])
key=open("/etc/hestia/elevation.key","rb").read().strip()
t={"v":1,"action":action, **fields, "issued":int(time.time())}
t["sig"]=hmac.new(key, json.dumps(t,sort_keys=True,separators=(",",":")).encode(), hashlib.sha256).hexdigest()
print(base64.b64encode(json.dumps(t).encode()).decode())
PY
}
asagent(){ sudo -u "$AGENT" sudo -n "$DST" "$@"; }   # exactly how the broker reaches it (agent -> sudo -> root wrapper)

echo
echo "== PROVE the elevated path =="
RID=$(cat /proc/sys/kernel/random/uuid); ETK=$(cat /proc/sys/kernel/random/uuid); SID=$(cat /proc/sys/kernel/random/uuid)

echo "-- A: forged ticket (attacker without the key) -> REJECTED"
asagent run "$(python3 -c 'import base64,json;print(base64.b64encode(json.dumps({"v":1,"action":"run","request_id":"x","sig":"deadbeef"}).encode()).decode())')" >/dev/null 2>&1
[[ $? -ne 0 ]] && ok "forged ticket refused (nonzero)" || bad "forged ticket RAN"

echo "-- B: valid broker-signed ticket -> runs 'id' as $OWNER (drops privilege)"
T=$(mint run "{\"session_id\":\"$SID\",\"request_id\":\"$RID\",\"cwd\":\"/tmp\",\"run_as\":\"$OWNER\",\"argv\":[\"id\"],\"exec_token\":\"$ETK\"}")
OUT=$(asagent run "$T" 2>&1)
echo "$OUT" | grep -q "uid=$(id -u "$OWNER")($OWNER)" && ok "elevated command ran AS $OWNER: $OUT" || bad "did not run as $OWNER: $OUT"

echo "-- C: replay the SAME ticket -> REJECTED (single-use)"
asagent run "$T" >/dev/null 2>&1; [[ $? -ne 0 ]] && ok "replay refused (single-use)" || bad "replay RAN"

echo "-- D: invoke wrapper directly as hestia-agent (NOT via sudo) -> refuses (not root)"
RID2=$(cat /proc/sys/kernel/random/uuid); ETK2=$(cat /proc/sys/kernel/random/uuid)
T2=$(mint run "{\"session_id\":\"$SID\",\"request_id\":\"$RID2\",\"cwd\":\"/tmp\",\"run_as\":\"$OWNER\",\"argv\":[\"id\"],\"exec_token\":\"$ETK2\"}")
sudo -u "$AGENT" "$DST" run "$T2" >/dev/null 2>&1; [[ $? -ne 0 ]] && ok "non-root invocation refused" || bad "ran without root"

echo "-- E: elevated kill terminates the $OWNER-owned process group"
RID3=$(cat /proc/sys/kernel/random/uuid); ETK3=$(cat /proc/sys/kernel/random/uuid); MARK=$(( (RANDOM%9000)+1000 ))
T3=$(mint run "{\"session_id\":\"$SID\",\"request_id\":\"$RID3\",\"cwd\":\"/tmp\",\"run_as\":\"$OWNER\",\"argv\":[\"bash\",\"-c\",\"sleep $MARK & sleep $MARK & wait\"],\"exec_token\":\"$ETK3\"}")
asagent run "$T3" >/dev/null 2>&1 & sleep 2
before=$(pgrep -u "$OWNER" -f "sleep $MARK" | wc -l)
KT=$(mint kill "{\"exec_token\":\"$ETK3\"}")
asagent kill "$KT" >/dev/null 2>&1; sleep 1
after=$(pgrep -u "$OWNER" -f "sleep $MARK" | wc -l)
[[ "$before" -ge 2 && "$after" -eq 0 ]] && ok "elevated group killed ($before -> $after)" || bad "kill failed ($before -> $after)"
pkill -u "$OWNER" -f "sleep $MARK" 2>/dev/null

echo
if [[ $fail -eq 0 ]]; then
  echo "TARGET STEP 3 (elevation): ALL PROOFS PASS ($pass)."
  echo "NEXT: copy the key to the HOST, e.g.:"
  echo "   sudo tailscale file cp $KEY host:   (or scp)   then run install/host/4-import-elevation-key.sh there"
else
  echo "TARGET STEP 3 (elevation): $fail FAILURES above" >&2; exit 2
fi
