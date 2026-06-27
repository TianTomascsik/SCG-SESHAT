#!/usr/bin/env bash
#
# Remove the kernel WireGuard benchmark topology created by wg_setup.sh.
# Safe to run repeatedly; missing pieces are ignored.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/wg_env.sh
source "$HERE/wg_env.sh"

# Deleting the netns removes WG_IF_B and the peer veth end with it.
ip link del "$WG_IF_A" 2>/dev/null || true
ip netns del "$WG_PEER_NS" 2>/dev/null || true
ip link del "$WG_VETH_HOST" 2>/dev/null || true

wg_info "WireGuard benchmark topology removed"
