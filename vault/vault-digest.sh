#!/bin/bash
# Weekly vault digest. ALWAYS prints — a silent week is the failure we are watching for,
# and a missing message is far harder to notice than one reading "0 new, last write 34d ago".
N=$HESTIA_VAULT_RUNBOOK
J=$HESTIA_VAULT_OWNER
age_days() { [ -e "$1" ] || { echo "-"; return; }; f=$(find "$1" -type f -name '*.md' -printf '%T@\n' 2>/dev/null | sort -rn | head -1); [ -z "$f" ] && { echo "never"; return; }; echo $(( ( $(date +%s) - ${f%.*} ) / 86400 )); }
fmt_age() { a=$(age_days "$1"); case "$a" in never|-) echo "never (not yet in use)";; *) echo "${a}d ago";; esac; }
cnt() { find "$1" -type f -name '*.md' 2>/dev/null | wc -l; }
new7() { find "$1" -type f -name '*.md' -mtime -7 2>/dev/null | wc -l; }

echo "Vault digest — week to $(date '+%Y-%m-%d')"
echo
echo "notes/   $(new7 $N) new in 7d · $(cnt $N) total · last write $(fmt_age $N)"
find $N -type f -name '*.md' -mtime -7 2>/dev/null | grep -v '/_stale/' | sed "s|$N/|    + |" | head -10
echo "journal/ $(new7 $J) new in 7d · $(cnt $J) total · last write $(fmt_age $J)"
echo
echo "inbox backlog:    $(find $J/_inbox -type f 2>/dev/null | wc -l)"
echo "sync conflicts:   $(find $N $J -name '*sync-conflict*' 2>/dev/null | wc -l)"
# schema check: every note under a content dir needs the 5 required keys
VIOL=0
for f in $(find $N/how-to $N/systems $N/decisions -name '*.md' 2>/dev/null); do
  for k in title type updated source status; do
    grep -qE "^$k:" "$f" || { VIOL=$((VIOL+1)); break; }
  done
done
echo "schema violations: $VIOL"
echo "oversized notes:   $(find $N -name '*.md' -exec awk 'END{if(NR>200) print FILENAME}' {} \; 2>/dev/null | wc -l)"
echo
# the monitor must report on itself — the agent created these jobs and could delete them
D=$(hermes cron list 2>/dev/null | grep -c 'vault-digest')
A=$(hermes cron list 2>/dev/null | grep -c 'vault-alarm')
echo "cron alive: digest=$([ "$D" -gt 0 ] && echo yes || echo MISSING) alarm=$([ "$A" -gt 0 ] && echo yes || echo MISSING)"
