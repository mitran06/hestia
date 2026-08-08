#!/bin/bash
# Daily threshold alarm. Prints ONLY when something is wrong — empty stdout means silent.
N=$HESTIA_VAULT_RUNBOOK
J=$HESTIA_VAULT_OWNER
P=""
age_days() { f=$(find "$1" -type f -name '*.md' -printf '%T@\n' 2>/dev/null | sort -rn | head -1); [ -z "$f" ] && { echo 9999; return; }; echo $(( ( $(date +%s) - ${f%.*} ) / 86400 )); }
NC=$(find $N -type f -name '*.md' 2>/dev/null | wc -l)
[ "$NC" -gt 0 ] && [ "$(age_days $N)" -ge 21 ] && P="$P
- notes/ has had no write in $(age_days $N) days"
JC=$(find $J -type f -name '*.md' 2>/dev/null | wc -l)
[ "$JC" -gt 0 ] && [ "$(age_days $J)" -ge 4 ] && P="$P
- journal/ has had no write in $(age_days $J) days"
B=$(find $J/_inbox -type f 2>/dev/null | wc -l); [ "$B" -gt 20 ] && P="$P
- inbox backlog is $B captures"
C=$(find $N $J -name '*sync-conflict*' 2>/dev/null | wc -l); [ "$C" -gt 0 ] && P="$P
- $C sync-conflict file(s) present"
STALE=$(find $J/_inbox -type f -mtime +2 2>/dev/null | wc -l); [ "$STALE" -gt 0 ] && P="$P
- $STALE inbox capture(s) older than 2 days (rollup not running?)"
[ -n "$P" ] && echo "Vault alarm — $(date '+%Y-%m-%d %H:%M')$P"
exit 0
