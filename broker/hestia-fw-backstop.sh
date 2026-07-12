#!/usr/bin/env bash
# hestia-fw-backstop.sh — Phase 2 WEAKEST-LINK: zero-window box->tailnet firewall backstop.
# The Phase-1 egress firewall is parasitic on Docker/iptables and re-applied by a drift timer, so a
# Docker flush can open a brief window. This adds an INDEPENDENT nftables table (its own hook, priority
# -300, BEFORE Docker's rules) that DROPs any forward from the box bridge to the tailnet — Docker cannot
# flush a separate nft table, so there is no drift window. It does NOT touch the host's own tailnet traffic
# (that is OUTPUT, not forward-from-the-bridge). Persists via a tiny boot service.
#
# CAUTION: this edits the live firewall. It only ADDS a DROP for box->tailnet; it cannot break the host or
# the box's normal internet. The script SELF-TESTS after applying. Reversible: nft delete table inet hestia_backstop
set -euo pipefail

# --- load site config (values may also come straight from the environment) ---
HESTIA_ENV="${HESTIA_ENV:-$(cd "$(dirname "$0")" && pwd)/../config/hestia.env}"
[[ -f "$HESTIA_ENV" ]] && . "$HESTIA_ENV"

BRIDGE="${HESTIA_BRIDGE:-lxdbr0}"          # the LXD bridge the box is on
BOX="${CONTAINER_NAME:-hestia-box}"        # the confined-agent container name
TAILNET4=100.64.0.0/10                      # Tailscale CGNAT range (standard, not site-specific)
TAILNET6=fd7a:115c:a1e0::/48                # Tailscale ULA range (standard, not site-specific)
NFT_FILE=/etc/nftables.d/hestia-backstop.nft
UNIT=/etc/systemd/system/hestia-fw-backstop.service
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
command -v nft >/dev/null || { echo "FATAL: nft (nftables) not installed"; exit 1; }
ip link show "$BRIDGE" >/dev/null 2>&1 || { echo "FATAL: bridge $BRIDGE not found (set HESTIA_BRIDGE)"; exit 1; }

echo "== write + load the independent backstop table =="
install -d -m 0755 /etc/nftables.d
cat > "$NFT_FILE" <<NFTEOF
# Hestia box->tailnet zero-window backstop (independent of Docker/iptables; hook BEFORE Docker).
table inet hestia_backstop {
    chain forward {
        type filter hook forward priority -300; policy accept;
        iifname "$BRIDGE" ip  daddr $TAILNET4 drop
        iifname "$BRIDGE" ip6 daddr $TAILNET6 drop
    }
}
NFTEOF
nft -f "$NFT_FILE"
echo "-- loaded table inet hestia_backstop"

echo "== persist across reboot =="
cat > "$UNIT" <<UNITEOF
[Unit]
Description=Hestia box->tailnet firewall backstop (independent nft table)
After=nftables.service network-pre.target
Before=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $NFT_FILE
ExecStop=/usr/sbin/nft delete table inet hestia_backstop
[Install]
WantedBy=multi-user.target
UNITEOF
systemctl daemon-reload; systemctl enable hestia-fw-backstop.service >/dev/null

echo
echo "== SELF-TEST (prove: box CANNOT reach tailnet, box CAN still reach the internet) =="
pass=0; fail=0; ok(){ echo "  PASS: $*"; pass=$((pass+1)); }; bad(){ echo "  FAIL: $*"; fail=$((fail+1)); }
# reachability probe from INSIDE the box (python3 TCP connect, 3s timeout)
boxprobe(){ lxc exec "$BOX" -- python3 -c "
import socket,sys
try:
    s=socket.create_connection((sys.argv[1], int(sys.argv[2])), 3); s.close(); print('OPEN')
except Exception: print('BLOCKED')
" "$1" "$2" 2>/dev/null; }

# Probe your own tailnet nodes if configured; otherwise probe a representative in-range tailnet address.
for ip in "${HOMESERVER_TAILSCALE_IP:-}" "${TARGET_TAILSCALE_IP:-}" "100.64.0.1"; do
  [[ -n "$ip" ]] || continue
  t=$(boxprobe "$ip" 22); [[ "$t" == "BLOCKED" ]] && ok "box -> tailnet $ip:22 BLOCKED" || bad "box reached tailnet $ip ($t)"
done
t=$(boxprobe 1.1.1.1 443); [[ "$t" == "OPEN" ]] && ok "box -> public internet (1.1.1.1:443) still OPEN" || bad "box lost internet ($t)"

echo
if [[ $fail -eq 0 ]]; then
  echo "FW BACKSTOP: OK — box is fenced off the tailnet with no drift window; internet intact."
else
  echo "FW BACKSTOP: PROBLEMS — review; to revert: nft delete table inet hestia_backstop" >&2; exit 2
fi
