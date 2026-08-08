#!/bin/sh
# hindsight-healthcheck.sh (v2) — detect Hindsight failure, especially the SILENT kind.
#
# Failure mode this exists to catch (community-reported):
#   "it can silently fail and then your memories are not processed for days
#    unless you notice it"
# /health returning 200 does NOT prove memory works. So this also does an ACTIVE
# canary retain->recall round-trip.
#
# DESIGN RULE (from review): every UNKNOWN must resolve to LOUD, not quiet.
# Unparseable JSON, missing fields, non-200 status, unreadable creds, failed
# Telegram send -> all are PROBLEMS, never silently "OK".
#
# Tiers:
#   every run       : unit active, /health, bank exists, failed/stuck counters
#   >= CANARY_EVERY : retain -> recall -> delete on a throwaway bank (2 LLM calls)

set -u
umask 077

API="http://127.0.0.1:8888"
BANK="hermes"                                  # real bank — READ ONLY here
CANARY_BANK="hestia-healthcheck-canary"     # created + deleted by this script ONLY
DIR="$HESTIA_MEMORY_HOME"
STATE="$DIR/health-state"
LOG="$DIR/health.log"
ENVFILE="$HERMES_HOME/.env"
CANARY_EVERY_H=3
CURL_MAX=120

# systemctl --user needs this when run without a login session
bank_note=""
: "${XDG_RUNTIME_DIR:=/run/user/$(id -u)}"
export XDG_RUNTIME_DIR

mkdir -p "$DIR" || { echo "FATAL: cannot create $DIR" >&2; exit 1; }

now=$(date +%s)
stamp=$(date '+%Y-%m-%d %H:%M:%S')
problems=""
canary_ran="no"; canary_ok="n/a"

add() { problems="${problems}
  - $1"; }

# read an integer state file; anything non-numeric resets to 0 rather than aborting
readnum() {
  v=0
  [ -f "$1" ] && v=$(cat "$1" 2>/dev/null || echo 0)
  case "$v" in ''|*[!0-9]*) v=0 ;; esac
  printf '%s' "$v"
}

# HTTP helper. Command substitution runs this in a SUBSHELL, so it cannot export
# a variable — it prints "body\ncode" and the caller splits with code_of/body_of.
req() { # req METHOD URL [JSON_BODY]
  _m="$1"; _u="$2"; _b="${3:-}"
  if [ -n "$_b" ]; then
    curl -s --path-as-is --max-time "$CURL_MAX" -w '\n%{http_code}' \
         -X "$_m" "$_u" -H 'Content-Type: application/json' -d "$_b" 2>/dev/null
  else
    curl -s --path-as-is --max-time "$CURL_MAX" -w '\n%{http_code}' \
         -X "$_m" "$_u" 2>/dev/null
  fi
}
code_of() { c=$(printf '%s' "$1" | tail -n1); case "$c" in ''|*[!0-9]*) c=0 ;; esac; printf '%s' "$c"; }
body_of() { printf '%s' "$1" | sed '$d'; }

# ---------- tier 1 ----------
if ! timeout 10 systemctl --user is-active --quiet hindsight 2>/dev/null; then
  add "systemd unit 'hindsight' is NOT active"
fi

r=$(req GET "$API/health"); hc=$(code_of "$r"); health=$(body_of "$r")
if [ "$hc" != 200 ]; then
  add "/health returned HTTP $hc (server down or wedged)"
else
  hs=$(printf '%s' "$health" | jq -r '.status // "MISSING"' 2>/dev/null || echo PARSE_FAIL)
  [ "$hs" = "healthy" ] || add "/health status = '$hs' (expected healthy)"
fi

# Does the real bank exist? /stats returns 200 + all zeros for a bank that does
# NOT exist, so stats alone can never detect a wrong/missing bank.
if [ -z "$problems" ]; then
  r=$(req GET "$API/v1/default/banks"); hc=$(code_of "$r"); banks=$(body_of "$r")
  if [ "$hc" != 200 ]; then
    add "GET /banks returned HTTP $hc"
  else
    has=$(printf '%s' "$banks" | jq -r --arg b "$BANK" '[.banks[]?.bank_id] | index($b) // "no"' 2>/dev/null || echo PARSE_FAIL)
    seen_before=$(readnum "$STATE.bankseen")
    if [ "$has" = "no" ]; then
      if [ "$seen_before" = "1" ]; then
        add "real bank '$BANK' has DISAPPEARED (it existed on a previous run)"
      else
        # Never existed. Quiet on day 1 is fine (lazy creation on first retain), but
        # staying quiet FOREVER is the exact "unknown resolves to quiet" bug this script
        # exists to prevent. Escalate after a grace period.
        first_absent=$(readnum "$STATE.bankabsent")
        [ "$first_absent" = "0" ] && { echo "$now" > "$STATE.bankabsent"; first_absent=$now; }
        absent_days=$(( (now - first_absent) / 86400 ))
        if [ "$absent_days" -ge 7 ]; then
          add "bank '$BANK' has NEVER been created (${absent_days}d). auto_retain is on, so either nothing has been said to the agent in ${absent_days} days, or retains are silently not landing."
        else
          bank_note=" bank=absent(${absent_days}d,grace)"
        fi
      fi
    else
      rm -f "$STATE.bankabsent" 2>/dev/null
      echo 1 > "$STATE.bankseen"
      r=$(req GET "$API/v1/default/banks/$BANK/stats"); hc=$(code_of "$r"); stats=$(body_of "$r")
      if [ "$hc" != 200 ]; then
        add "stats for '$BANK' returned HTTP $hc"
      else
        for f in failed_operations failed_consolidation; do
          v=$(printf '%s' "$stats" | jq -r --arg f "$f" '.[$f] // "MISSING"' 2>/dev/null || echo PARSE_FAIL)
          case "$v" in
            MISSING|PARSE_FAIL) add "stats field $f is $v (API contract changed?)" ;;
            0) : ;;
            *[!0-9]*) add "stats field $f non-numeric: $v" ;;
            *) add "$f = $v" ;;
          esac
        done
        pend=$(printf '%s' "$stats" | jq -r '.pending_operations // "MISSING"' 2>/dev/null || echo PARSE_FAIL)
        case "$pend" in
          MISSING|PARSE_FAIL) add "stats field pending_operations is $pend" ;;
          *[!0-9]*) add "pending_operations non-numeric: $pend" ;;
          *) [ "$pend" -gt 25 ] && add "pending_operations = $pend (queue backing up)" ;;
        esac
      fi
    fi
  fi
fi

# ---------- tier 2: canary ----------
# Validate the bank name by WHITELIST. An inequality guard is not enough: curl
# normalises '..' segments, so 'x/../hermes' would pass a != test and hit the
# real bank. Reject anything that is not [a-z0-9-] and not marked as a canary.
canary_safe=no
case "$CANARY_BANK" in
  ""|"$BANK"|*[!a-z0-9-]*) canary_safe=no ;;
  *healthcheck-canary*)    canary_safe=yes ;;
esac

last_canary=$(readnum "$STATE.canary")
if [ "$canary_safe" != yes ]; then
  add "FATAL: unsafe CANARY_BANK '$CANARY_BANK' — canary disabled"
elif [ $(( now - last_canary )) -ge $(( CANARY_EVERY_H * 3600 )) ]; then
  canary_ran="yes"; canary_ok="no"
  echo "$now" > "$STATE.canary"          # stamp the ATTEMPT, not the success
  token="canary-token-alpaca-$now"
  rbody=$(printf '{"items":[{"content":"Healthcheck canary probe. The canary token is %s."}],"async":false}' "$token")
  r=$(req POST "$API/v1/default/banks/$CANARY_BANK/memories" "$rbody"); hc=$(code_of "$r"); rout=$(body_of "$r")
  if [ "$hc" != 200 ]; then
    add "canary RETAIN rejected: HTTP $hc $(printf '%s' "$rout" | head -c 200)"
  else
    r=$(req POST "$API/v1/default/banks/$CANARY_BANK/memories/recall" \
            '{"query":"what is the canary token","budget":"low"}'); hc=$(code_of "$r"); rec=$(body_of "$r")
    if [ "$hc" != 200 ]; then
      add "canary RECALL failed: HTTP $hc"
    else
      n=$(printf '%s' "$rec" | jq -r '.results | length' 2>/dev/null || echo 0)
      case "$rec" in
        *"$token"*) canary_ok="yes" ;;
        *) if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
             canary_ok="partial"   # engine works, token paraphrased — not an outage
           else
             fails=$(readnum "$STATE.canaryfail"); fails=$((fails+1)); echo "$fails" > "$STATE.canaryfail"
             [ "$fails" -ge 2 ] && add "CANARY FAILED x$fails: retained OK but recall returned nothing. Extraction/retrieval is broken — memory is silently not recording."
           fi ;;
      esac
    fi
  fi
  [ "$canary_ok" = "no" ] || echo 0 > "$STATE.canaryfail"
  # always clean up; report failure to delete rather than swallowing it
  r=$(req DELETE "$API/v1/default/banks/$CANARY_BANK"); hc=$(code_of "$r")
  [ "$hc" = 200 ] || [ "$hc" = 404 ] || \
    add "canary bank cleanup returned HTTP $hc (stale canary bank may remain)"
fi

# ---------- report ----------
[ -n "$problems" ] && status="SICK" || status="OK"
prev="unknown"; [ -f "$STATE" ] && prev=$(cat "$STATE" 2>/dev/null || echo unknown)
echo "$status" > "$STATE" || add "cannot write state file"
printf '%s [%s] canary=%s/%s%s%s\n' "$stamp" "$status" "$canary_ran" "$canary_ok" "$bank_note" \
  "$(printf '%s' "${problems:+ problems:$problems}" | tr '\n' ' ')" >> "$LOG"
tail -n 2000 "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"

# returns 0 ONLY on a confirmed send
notify() {
  [ -r "$ENVFILE" ] || return 1
  tok=$(sed -n 's/^[[:space:]]*\(export[[:space:]]\+\)\?TELEGRAM_BOT_TOKEN=//p' "$ENVFILE" | head -1 | tr -d '"'"'"'\r')
  chat=$(sed -n 's/^[[:space:]]*\(export[[:space:]]\+\)\?TELEGRAM_HOME_CHANNEL=//p' "$ENVFILE" | head -1 | tr -d '"'"'"'\r')
  [ -n "$tok" ] && [ -n "$chat" ] || return 1
  # token via stdin config, NOT argv — argv is world-readable in /proc
  curl -s --max-time 20 -o /dev/null -w '%{http_code}' -K - <<EOF | grep -q '^200$'
url = "https://api.telegram.org/bot$tok/sendMessage"
data-urlencode = "chat_id=$chat"
data-urlencode = "text=$1"
EOF
}

last_alert=$(readnum "$STATE.alert")
if [ "$status" = "SICK" ]; then
  if [ "$prev" != "SICK" ] || [ $(( now - last_alert )) -ge 86400 ]; then
    if notify "🔴 Hindsight memory unhealthy on the box ($stamp):$problems

Long-term memory may be silently not recording.
  systemctl --user status hindsight
  journalctl --user -u hindsight -n 50
  tail $LOG"; then
      echo "$now" > "$STATE.alert"      # stamp ONLY on confirmed delivery
    else
      printf '%s [ALERT-SEND-FAILED] telegram notify failed; will retry next run\n' "$stamp" >> "$LOG"
    fi
  fi
elif [ "$prev" = "SICK" ]; then
  notify "🟢 Hindsight memory recovered on the box ($stamp)." && echo 0 > "$STATE.alert"
fi

exit 0   # never exit non-zero: a failed unit can hit systemd's start limit and
         # silence the monitor exactly when it is needed. Alerting is the channel.
