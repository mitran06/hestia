#!/usr/bin/env bash
# mover.sh — Hestia mailbox mover (DUMB PIPE).  Runs as user `hestia-mover` (groups: lxd, hestia-spool).
#
# Moves opaque, size-bounded, UUID-named blobs between the UNTRUSTED box and the host spool:
#     box  /home/hestia/broker/outbox/<uuid>   --(pull)-->  host /var/lib/hestia-spool/incoming/<uuid>
#     host /var/lib/hestia-spool/outgoing/<uuid> --(push)-->  box  /home/hestia/broker/inbox/<uuid>
#
# SECURITY CONTRACT (see phase2 notes):
#   * Parses NO content. Validates ONLY: filename == strict UUID, size <= 64 KiB. Bounded batch per tick.
#   * Filenames are read NUL-delimited with a '/' size separator (a filename cannot contain '/' or NUL),
#     so a crafted name (newline/space/glob/`..`/`;`/`$()`/leading `-`) is ONE record that fails the
#     anchored UUID regex and is dropped. Everything reaches lxc as argv (never a host shell), so no
#     injection / glob / path-escape. [verified 2026-07-09: newline-forged phantom-UUID line is neutralized]
#   * Transfer is bounded by `head -c` regardless of the reported size, so a size-lie/TOCTOU (report small,
#     grow huge before transfer) cannot fill the spool FS; the post-copy size recheck drops anything > cap.
#   * ATOMICITY: mover writes `<uuid>.part` then same-FS rename to `<uuid>`; downstream readers (broker /
#     box) MUST ignore `*.part`/`*.tmp`. Box side MUST write `<uuid>.tmp` then rename to `<uuid>`.
#   * ACCEPTED RISK (per plan): a box that floods its OWN outbox faster than the bounded batch drains it
#     starves its OWN delivery (availability, fail-closed). The host is unaffected (work is capped per tick:
#     <=BATCH records read, <=BATCH lxc calls). This is the box harming only itself.
set -uo pipefail          # deliberately NOT -e: one bad file must never kill the loop
shopt -s nullglob
umask 007                 # spool files must be group-readable (broker reads them) regardless of service UMask

# Site config may come from the environment (the systemd unit sets these); sensible defaults otherwise.
LXC="${HESTIA_LXC:-/usr/sbin/lxc}"
BOX="${CONTAINER_NAME:-hestia-box}"           # the confined-agent container name
BOX_USER="${AGENT_BOX_USER:-hestia}"          # the agent's unix user inside the box
BOX_OUT="/home/$BOX_USER/broker/outbox"
BOX_IN="/home/$BOX_USER/broker/inbox"
SPOOL="${HESTIA_SPOOL:-/var/lib/hestia-spool}"
IN="$SPOOL/incoming"
OUT="$SPOOL/outgoing"
MAXSIZE=65536             # 64 KiB hard per-file cap
BATCH=25                  # max records handled per direction per tick
POLL=1                    # seconds between ticks
UUID='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

log(){ printf 'mover: %s\n' "$*"; }   # journald adds the timestamp

# NUL-delimited "<size>/<name>" records; '/' is a safe separator (never in a basename).
box_ls(){ "$LXC" exec "$BOX" -- find "$BOX_OUT" -maxdepth 1 -type f -printf '%s/%f\0' 2>/dev/null; }
box_rm(){ "$LXC" exec "$BOX" -- rm -f -- "$BOX_OUT/$1" 2>/dev/null; }

pull_dir(){   # box outbox -> host incoming
  local n=0 rec size name got
  while IFS= read -r -d '' rec; do
    if (( n >= BATCH )); then break; fi
    n=$((n+1))
    size=${rec%%/*}; name=${rec#*/}
    if ! [[ "$name" =~ $UUID ]]; then log "reject non-uuid outbox entry; dropping"; box_rm "$name"; continue; fi
    if ! [[ "$size" =~ ^[0-9]+$ ]] || (( size > MAXSIZE )); then log "reject oversize $name ($size B); dropping"; box_rm "$name"; continue; fi
    # bounded transfer: cap the copy at MAXSIZE+1 regardless of the real/growing file size
    "$LXC" exec "$BOX" -- cat -- "$BOX_OUT/$name" 2>/dev/null | head -c $((MAXSIZE+1)) > "$IN/$name.part"
    got=$(stat -c '%s' "$IN/$name.part" 2>/dev/null || echo $((MAXSIZE+1)))
    if (( got == 0 )); then rm -f "$IN/$name.part"; log "empty/failed transfer $name; dropped"; box_rm "$name"; continue; fi
    if (( got > MAXSIZE )); then rm -f "$IN/$name.part"; log "post-copy oversize $name; dropped"; box_rm "$name"; continue; fi
    mv -f "$IN/$name.part" "$IN/$name"       # atomic rename within the spool FS
    box_rm "$name"
    log "pulled $name ($got B)"
  done < <(box_ls)
}

push_dir(){   # host outgoing -> box inbox
  local n=0 base
  for f in "$OUT"/*; do
    if (( n >= BATCH )); then break; fi
    n=$((n+1))
    base=$(basename -- "$f")
    [[ "$base" == *.part ]] && continue                       # broker still writing this one
    if ! [[ "$base" =~ $UUID ]]; then log "outgoing non-uuid $base; removing"; rm -f "$f"; continue; fi
    if (( $(stat -c '%s' "$f" 2>/dev/null || echo $((MAXSIZE+1))) > MAXSIZE )); then log "outgoing oversize $base; removing"; rm -f "$f"; continue; fi
    if "$LXC" file push "$f" "$BOX$BOX_IN/$base.part" 2>/dev/null && \
       "$LXC" exec "$BOX" -- mv -f -- "$BOX_IN/$base.part" "$BOX_IN/$base" 2>/dev/null; then
      rm -f "$f"; log "pushed $base"
    else
      log "push failed $base"
    fi
  done
}

rm -f "$IN"/*.part 2>/dev/null           # startup sweep: mover-owned scratch only
log "started (batch=$BATCH maxsize=${MAXSIZE}B poll=${POLL}s)"
while true; do
  pull_dir
  push_dir
  sleep "$POLL"
done
