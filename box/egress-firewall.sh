#!/usr/bin/env bash
###############################################################################
# egress-firewall.sh — egress firewall for the confined-agent LXD container.
#
# Run as ROOT on the host (Ubuntu with Docker + LXD). Idempotent.
# Reboot-persistent via egress-firewall.service.
#
# GOAL: the container may reach the PUBLIC IPv4 INTERNET only. It must NOT reach
#   the host, the LAN, other RFC1918 nets, or the tailnet (v4 AND v6). This is
#   the blast-radius wall for a prompt-injectable agent: even if fully hijacked,
#   the box has no network path to your other machines — the only crossing is the
#   broker's Telegram-gated relay (which the box cannot invoke; see docs/).
#
# DESIGN — dedicated child chains (robust vs. the nft backend):
#   All of OUR rules live in four custom chains, flushed with `-F` on each run:
#       iptables :  HST_FWD  (v4 container->off-box)   HST_IN  (v4 container->host)
#       ip6tables:  HST6_FWD (v6 container->off-box)   HST6_IN (v6 container->host)
#   Each parent gets a jump into ours, added only-if-absent (checked with `-C`
#   before `-I`). FORWARD parents get TWO jumps — `-i <bridge>` (container->off-box)
#   AND `-o <bridge>` (the return path: WAN->container replies must reach our
#   ESTABLISHED,RELATED ACCEPT or Docker's FORWARD-policy DROP eats them).
#   Re-apply = `-F` + repopulate in natural top->bottom order. `-F` is
#   quote-agnostic, so we never parse `iptables -S` output (whose comment quoting
#   is inconsistent under iptables-nft) — removing the mid-session restart
#   failure/duplication risk. Every child chain ends in a TERMINAL verdict.
#
# POLICY (container may reach): PUBLIC IPv4 INTERNET only. Denied:
#     - the host itself (bridge gateway, host LAN IP, docker nets, host tailnet)
#       EXCEPT DHCP + DNS to the bridge gateway
#     - LAN            192.168.0.0/16
#     - tailnet        100.64.0.0/10           and  fd7a:115c:a1e0::/48
#     - RFC1918        10/8 (except the bridge's own subnet), 172.16/12
#     - link-local     169.254.0.0/16          and  fe80::/10
#   IPv6 to the internet is NOT needed -> v6 egress is locked fail-closed.
#
# NETFILTER FACTS THIS SCRIPT RELIES ON (all VERIFIED):
#   * Docker jumps FORWARD -> DOCKER-USER first; never touches user rules there.
#   * A DROP verdict is TERMINAL across every base chain on a hook regardless of
#     table/priority (wiki.nftables.org) => our DROP is authoritative.
#   * Docker sets filter/FORWARD policy DROP; ACCEPT in DOCKER-USER (via HST_FWD)
#     is terminal for the filter table so WAN works.
#   * LXD keeps DHCP/DNS accepts in a SEPARATE `inet lxd` table; our INPUT ACCEPTs
#     for 53/67 sit above our INPUT DROP so the box's DHCP/DNS survive.
#   * NDP/ICMPv6 (133-136) is essential for the v6 link (RFC 4890) — allowed in HST6_IN.
#
# NOTE — Docker DAEMON restart preserves DOCKER-USER + our jump; a host reboot
#   recreates it EMPTY (we re-add on boot via the systemd unit). Every "lost jump"
#   case is fail-closed: without our jump the box hits Docker's FORWARD policy DROP
#   and merely loses WAN — never a hole. Re-apply: systemctl restart hestia-box-egress
###############################################################################
set -euo pipefail

# --- load site config (values may also come straight from the environment) ---
HESTIA_ENV="${HESTIA_ENV:-$(cd "$(dirname "$0")" && pwd)/../config/hestia.env}"
[[ -f "$HESTIA_ENV" ]] && . "$HESTIA_ENV"

BR="${HESTIA_BRIDGE:-lxdbr0}"                 # the LXD bridge the container is on

# Bridge addressing — auto-detected from the live bridge; override in config if needed.
# (iptables masks host bits, so the gateway addr WITH prefix works as the subnet match.)
OWN4="${CONTAINER_SUBNET_V4:-$(ip -4 -o addr show "$BR" 2>/dev/null | awk '{print $4}' | head -1)}"
GW4="${LXDBR_GW4:-${OWN4%%/*}}"               # bridge IPv4 gateway = DHCP+DNS server
OWN6="${CONTAINER_SUBNET_V6:-$(ip -6 -o addr show "$BR" scope global 2>/dev/null | awk '{print $4}' | head -1)}"
GW6="${LXDBR_GW6:-${OWN6%%/*}}"               # bridge IPv6 gateway = DNS server

# child chain names
C4_FWD="HST_FWD"   ; C4_IN="HST_IN"
C6_FWD="HST6_FWD"  ; C6_IN="HST6_IN"

log() { printf '[hestia-box-egress] %s\n' "$*"; }

# ---------------------------------------------------------------------------
# primitives (quote-agnostic; no `-S` parsing)
# ---------------------------------------------------------------------------
chain_exists()   { "$1" -S "$2" >/dev/null 2>&1; }          # $1=ipt $2=chain
ensure_chain()   { chain_exists "$1" "$2" || "$1" -N "$2"; } # create-if-absent
flush_chain()    { "$1" -F "$2"; }                           # empty our chain

# ensure_jump ipt parent  <match-args...> -j CHILD
# Adds the jump only if an identical one isn't already present. `-C` is guarded
# with `|| true` so a "not found" (rc!=0) never aborts under set -e.
ensure_jump() {
  local ipt="$1" parent="$2"; shift 2
  local exists=0
  "$ipt" -C "$parent" "$@" >/dev/null 2>&1 && exists=1 || true
  if [[ "$exists" -eq 0 ]]; then
    "$ipt" -I "$parent" "$@"
  fi
}

###############################################################################
# IPv4
###############################################################################
apply_v4() {
  ensure_chain iptables DOCKER-USER            # harmless fallback if Docker momentarily absent
  ensure_chain iptables "$C4_FWD"
  ensure_chain iptables "$C4_IN"

  # ---- HST_FWD : container -> off-box (jumped from DOCKER-USER) ------------
  flush_chain iptables "$C4_FWD"
  iptables -A "$C4_FWD" -i "$BR" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  # return out
  iptables -A "$C4_FWD" -o "$BR" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  # return in
  iptables -A "$C4_FWD" -i "$BR" -d "$OWN4"        -j ACCEPT   # own subnet (gw DHCP/DNS handled in INPUT)
  iptables -A "$C4_FWD" -i "$BR" -d 169.254.0.0/16 -j DROP     # link-local / metadata
  iptables -A "$C4_FWD" -i "$BR" -d 192.168.0.0/16 -j DROP     # LAN (host LAN IP + target laptop)
  iptables -A "$C4_FWD" -i "$BR" -d 172.16.0.0/12  -j DROP     # docker nets / RFC1918
  iptables -A "$C4_FWD" -i "$BR" -d 100.64.0.0/10  -j DROP     # tailnet CGNAT (host + target tailnet IPs)
  iptables -A "$C4_FWD" -i "$BR" -d 10.0.0.0/8     -j DROP     # RFC1918 10/8 (own subnet ACCEPTed above)
  iptables -A "$C4_FWD" -i "$BR"                   -j ACCEPT   # catch-all -> WAN (terminal)

  # ---- HST_IN : container -> HOST's own IPs (jumped from INPUT) ------------
  flush_chain iptables "$C4_IN"
  iptables -A "$C4_IN" -i "$BR" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  # host replies to allowed flows
  iptables -A "$C4_IN" -i "$BR"           -p udp --dport 67 -j ACCEPT  # DHCPv4 (broadcast; not dst-scoped)
  iptables -A "$C4_IN" -i "$BR" -d "$GW4" -p udp --dport 53 -j ACCEPT  # DNS to gateway
  iptables -A "$C4_IN" -i "$BR" -d "$GW4" -p tcp --dport 53 -j ACCEPT  # DNS/TCP to gateway
  iptables -A "$C4_IN" -i "$BR"                            -j DROP     # everything else to host (sshd:22, services)

  # ---- jumps (only-if-absent): outbound (-i) AND the return path (-o) ------
  ensure_jump iptables DOCKER-USER -i "$BR" -j "$C4_FWD"
  ensure_jump iptables DOCKER-USER -o "$BR" -j "$C4_FWD"
  ensure_jump iptables INPUT       -i "$BR" -j "$C4_IN"

  log "IPv4 $C4_FWD:"; iptables -S "$C4_FWD" | sed 's/^/    /'
  log "IPv4 $C4_IN:";  iptables -S "$C4_IN"  | sed 's/^/    /'
}

###############################################################################
# IPv6 — lock egress fail-closed (v6 internet not needed). The box may have a v6
# default route + global ULA and could otherwise forward v6 toward the host (and
# thence into the tailnet). Deny v6 forward except own subnet+established; lock v6
# INPUT to NDP + DHCPv6 + DNS-to-gateway. ip6tables/DOCKER-USER may be absent.
###############################################################################
apply_v6() {
  if ! command -v ip6tables >/dev/null 2>&1; then
    log "ip6tables not found — skipping IPv6."; return 0
  fi
  if ! ip6tables -S >/dev/null 2>&1; then
    log "ip6tables present but non-functional — skipping IPv6."; return 0
  fi

  ensure_chain ip6tables "$C6_FWD"
  ensure_chain ip6tables "$C6_IN"

  local V6_PARENT="FORWARD"
  if chain_exists ip6tables DOCKER-USER; then
    V6_PARENT="DOCKER-USER"; log "ip6tables DOCKER-USER present — jumping v6 fwd from it."
  else
    log "ip6tables DOCKER-USER absent — jumping v6 fwd from base FORWARD."
  fi

  # ---- HST6_FWD : container -> off-box (fail-closed) ----------------------
  flush_chain ip6tables "$C6_FWD"
  ip6tables -A "$C6_FWD" -i "$BR" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A "$C6_FWD" -o "$BR" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  [[ -n "$OWN6" ]] && ip6tables -A "$C6_FWD" -i "$BR" -d "$OWN6" -j ACCEPT     # intra-subnet /64
  ip6tables -A "$C6_FWD" -i "$BR"            -j DROP       # tailnet fd7a, LAN, WAN v6 — all denied (terminal)

  # ---- HST6_IN : container -> HOST ---------------------------------------
  flush_chain ip6tables "$C6_IN"
  ip6tables -A "$C6_IN" -i "$BR" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A "$C6_IN" -i "$BR" -p ipv6-icmp                -j ACCEPT   # NDP / RS-RA / NS-NA / PMTU
  ip6tables -A "$C6_IN" -i "$BR" -p udp --dport 547         -j ACCEPT   # DHCPv6 server
  ip6tables -A "$C6_IN" -i "$BR" -p udp --dport 546         -j ACCEPT   # DHCPv6 client
  [[ -n "$GW6" ]] && ip6tables -A "$C6_IN" -i "$BR" -d "$GW6" -p udp --dport 53 -j ACCEPT  # DNS to gateway over v6
  [[ -n "$GW6" ]] && ip6tables -A "$C6_IN" -i "$BR" -d "$GW6" -p tcp --dport 53 -j ACCEPT  # DNS/TCP to gateway over v6
  ip6tables -A "$C6_IN" -i "$BR"                            -j DROP     # all other host-bound v6

  # ---- jumps (only-if-absent) --------------------------------------------
  ensure_jump ip6tables "$V6_PARENT" -i "$BR" -j "$C6_FWD"
  ensure_jump ip6tables "$V6_PARENT" -o "$BR" -j "$C6_FWD"
  ensure_jump ip6tables INPUT        -i "$BR" -j "$C6_IN"

  log "IPv6 $C6_FWD (parent=$V6_PARENT):"; ip6tables -S "$C6_FWD" | sed 's/^/    /'
  log "IPv6 $C6_IN:"; ip6tables -S "$C6_IN" | sed 's/^/    /'
}

###############################################################################
main() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "must run as root" >&2; exit 1
  fi
  ip link show "$BR" >/dev/null 2>&1 || { echo "FATAL: bridge $BR not found (set HESTIA_BRIDGE)" >&2; exit 1; }
  [[ -n "$OWN4" ]] || { echo "FATAL: could not determine $BR IPv4 subnet (set CONTAINER_SUBNET_V4)" >&2; exit 1; }
  log "bridge=$BR own4=$OWN4 gw4=$GW4 own6=${OWN6:-none} gw6=${GW6:-none}"
  apply_v4
  apply_v6
  log "done."
}
main "$@"
