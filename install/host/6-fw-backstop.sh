#!/usr/bin/env bash
# install/host/6-fw-backstop.sh — HOST (broker/box machine), run as root
# Thin wrapper: runs the proven, self-testing box->tailnet firewall backstop shipped in the repo
# (broker/hestia-fw-backstop.sh). That script installs an INDEPENDENT nftables table (priority -300,
# BEFORE Docker's rules) that DROPs any forward from the box bridge to the tailnet — no drift window —
# persists it via a boot service, and self-tests (box CANNOT reach the tailnet; internet intact).
# Site values (HESTIA_BRIDGE, CONTAINER_NAME, optional *_TAILSCALE_IP) come from config/hestia.env.
# Reversible: nft delete table inet hestia_backstop ; systemctl disable --now hestia-fw-backstop
set -euo pipefail

HESTIA_ENV="${HESTIA_ENV:-$(cd "$(dirname "$0")" && pwd)/../../config/hestia.env}"
export HESTIA_ENV
REPO="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"
BACKSTOP="$REPO/broker/hestia-fw-backstop.sh"

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
[[ -f "$BACKSTOP" ]] || { echo "FATAL: backstop script not found at $BACKSTOP"; exit 1; }

# The backstop script sources config relative to ITS own location (broker/../config); we also export
# HESTIA_ENV so it finds this deployment's config regardless of where it was copied.
exec bash "$BACKSTOP" "$@"
