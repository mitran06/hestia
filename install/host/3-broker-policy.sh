#!/usr/bin/env bash
# install/host/3-broker-policy.sh — HOST (broker machine) step 3, run as root
# Installs the broker policy engine (broker.py) + the append-only audit log, and PROVES:
#   - the decision engine works (runs tests/test_broker.py against the repo copy)
#   - the audit log is append-only (chattr +a): hestia-broker can APPEND but CANNOT rewrite/unlink
#   - the security fence is intact (hestia-broker still has NO lxd/docker/sudo)
# Installs FROM the repo:  broker/broker.py.  Idempotent + self-verifying.
# Reversible: rm -f /usr/local/lib/hestia/broker.py; chattr -a <log>; rm -rf /var/lib/hestia-broker/log
set -euo pipefail

# --- load site config (values may also come straight from the environment) ---
HESTIA_ENV="${HESTIA_ENV:-$(cd "$(dirname "$0")" && pwd)/../../config/hestia.env}"
[[ -f "$HESTIA_ENV" ]] && . "$HESTIA_ENV"

REPO="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"

BROKER=hestia-broker
BHOME=/var/lib/hestia-broker
LOGDIR="$BHOME/log"
AUDIT="$LOGDIR/audit.log"
SRC="$REPO/broker/broker.py"
DST=/usr/local/lib/hestia/broker.py
TEST="$REPO/tests/test_broker.py"

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
id "$BROKER" &>/dev/null || { echo "FATAL: $BROKER missing (run 1-users.sh)"; exit 1; }
command -v python3 >/dev/null || { echo "FATAL: python3 missing"; exit 1; }
[[ -f "$SRC" ]] || { echo "FATAL: broker.py not found at $SRC"; exit 1; }

echo "== install broker.py =="
install -d -o root -g root -m 0755 /usr/local/lib/hestia
install -o root -g root -m 0755 "$SRC" "$DST"

echo "== audit log (root-owned dir, append-only file) =="
# dir: root:hestia-broker 0750 -> broker can enter+read but NOT create/unlink/rename inside it
install -d -o root -g "$BROKER" -m 0750 "$LOGDIR"
# file: root:hestia-broker 0660 -> broker has group-write to APPEND; chattr +a blocks rewrite/truncate
[[ -e "$AUDIT" ]] || install -o root -g "$BROKER" -m 0660 /dev/null "$AUDIT"
chattr +a "$AUDIT"
lsattr "$AUDIT" | grep -q 'a' && echo "-- chattr +a set on $AUDIT" || { echo "  ERROR: chattr +a not supported here"; exit 2; }

echo
echo "== VERIFY =="
fail=0

echo "-- decision engine (repo test against the ported broker.py):"
if [[ -f "$TEST" ]]; then
  # test_broker.py imports ../broker/broker.py relative to itself, so run it in place from the repo.
  ( cd "$REPO/tests" && python3 test_broker.py >/tmp/hestia-tb.out 2>&1 ) \
     && echo "   $(tail -1 /tmp/hestia-tb.out)" || { echo "   test_broker FAILED:"; cat /tmp/hestia-tb.out; fail=1; }
else
  echo "   (tests/test_broker.py not present; skipping engine self-test)"
fi

echo "-- APPEND as $BROKER must WORK:"
SID=11111111-1111-4111-8111-111111111111
RID=$(cat /proc/sys/kernel/random/uuid)
REQ=$(mktemp /tmp/hestia-step3-XXXXXX)
printf '{"v":1,"session_id":"%s","request_id":"%s","cwd":"/srv/projects","elevate":false,"argv":["ls","-la"]}' "$SID" "$RID" > "$REQ"
chmod 0644 "$REQ"
before=$(wc -l < "$AUDIT")
sudo -u "$BROKER" env HESTIA_AUDIT="$AUDIT" python3 "$DST" classify "$REQ" "$RID" >/tmp/hestia-p3.out 2>&1 || true
after=$(wc -l < "$AUDIT")
if (( after > before )) && grep -q "$RID" "$AUDIT"; then echo "   appended audit line (good): $(grep "$RID" "$AUDIT" | tail -1 | cut -c1-120)..."; else echo "   ERROR: append did not land"; cat /tmp/hestia-p3.out; fail=1; fi

echo "-- REWRITE/TRUNCATE as $BROKER must FAIL (append-only):"
if sudo -u "$BROKER" python3 -c "open('$AUDIT','w').write('TAMPER')" 2>/tmp/hestia-rw.err; then
  echo "   ERROR: rewrite SUCCEEDED — audit log is NOT tamper-proof"; fail=1
else
  echo "   rewrite denied (good): $(tail -1 /tmp/hestia-rw.err)"
fi

echo "-- UNLINK as $BROKER must FAIL (log dir not broker-writable):"
if sudo -u "$BROKER" rm -f "$AUDIT" 2>/dev/null && [[ ! -e "$AUDIT" ]]; then
  echo "   ERROR: broker deleted the audit log"; fail=1
else
  [[ -e "$AUDIT" ]] && echo "   unlink denied, log intact (good)" || { echo "   ERROR: log vanished"; fail=1; }
fi

echo "-- security fence (broker must have NO lxd/docker/sudo):"
for g in lxd docker sudo adm wheel; do
  if id -nG "$BROKER" | tr ' ' '\n' | grep -qx "$g"; then echo "   FENCE VIOLATION: $BROKER in $g"; fail=1; fi
done
out="$(sudo -n -l -U "$BROKER" 2>&1 || true)"
echo "$out" | grep -q 'not allowed to run sudo' && echo "   no sudo (good)" || { echo "   ERROR: cannot confirm no-sudo: $out"; fail=1; }

rm -f "$REQ"
echo
if [[ $fail -eq 0 ]]; then echo "HOST STEP 3: OK — decision engine + append-only audit proven."; else echo "HOST STEP 3: PROBLEMS above" >&2; exit 2; fi
