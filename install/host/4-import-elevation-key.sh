#!/usr/bin/env bash
# install/host/4-import-elevation-key.sh — HOST (broker machine), run as root
# Installs the shared elevation HMAC key (copied from the TARGET's /etc/hestia/elevation.key) at a
# broker-readable path so the broker can MINT elevation tickets. Without this, elevation stays DISABLED
# (elevated requests are refused) — a safe default.
#   Usage: sudo bash install/host/4-import-elevation-key.sh [/path/to/copied/elevation.key]
# If no path is given, looks for elevation.key in the invoking user's home.
# Reversible: rm -f /etc/hestia-broker/elevation.key ; restart the broker.
set -euo pipefail

# --- load site config (optional here; kept for consistency) ---
HESTIA_ENV="${HESTIA_ENV:-$(cd "$(dirname "$0")" && pwd)/../../config/hestia.env}"
[[ -f "$HESTIA_ENV" ]] && . "$HESTIA_ENV"

BROKER=hestia-broker
SRC="${1:-$(eval echo ~"${SUDO_USER:-root}")/elevation.key}"
DST=/etc/hestia-broker/elevation.key

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
id "$BROKER" &>/dev/null || { echo "FATAL: $BROKER missing (run 1-users.sh)"; exit 1; }
[[ -f "$SRC" ]] || { echo "FATAL: key not found at $SRC — copy the TARGET's /etc/hestia/elevation.key here first (scp / 'tailscale file'), or pass its path."; exit 1; }

install -d -o root -g "$BROKER" -m 0750 /etc/hestia-broker
install -o root -g "$BROKER" -m 0640 "$SRC" "$DST"

echo "== VERIFY =="
[[ "$(stat -c '%a %U:%G' "$DST")" == "640 root:$BROKER" ]] && echo "-- key installed 0640 root:$BROKER (good)" || { echo "  ERROR: perms wrong"; exit 2; }
runuser -u "$BROKER" -- test -r "$DST" && echo "-- $BROKER can read the key -> elevation ENABLED" || { echo "  ERROR: $BROKER cannot read key"; exit 2; }
sz=$(stat -c %s "$DST"); [[ "$sz" -ge 32 ]] && echo "-- key size ${sz}B (ok)" || { echo "  ERROR: key too short (${sz}B)"; exit 2; }
# sanity: the key must MATCH the target's (mint here, verify there must be identical bytes) — same file, so ok.
echo
echo "HOST STEP 4 (elevation key): OK. Elevation is now configured. Restart the broker to load it:"
echo "   sudo systemctl restart hestia-broker   (once the broker service is running)"
echo "SECURITY: shred the transfer copy ->  shred -u \"$SRC\""
