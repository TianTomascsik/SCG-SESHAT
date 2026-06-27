#!/usr/bin/env bash
#
# Provision the kernel WireGuard tunnel used by the SCG WireGuard benchmark:
# a peer network namespace + veth pair, a WireGuard interface on each side, and
# a connectivity check (ping over the tunnel). Idempotent — re-running tears the
# previous topology down first.
#
# Requires: root / CAP_NET_ADMIN, the `wireguard` kernel module, and
# wireguard-tools (`wg`). On Arch: `sudo pacman -S wireguard-tools iproute2`.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/wg_env.sh
source "$HERE/wg_env.sh"

if ! wg_prereqs_ok; then
  wg_err "missing prerequisites: $(wg_prereqs_reason)"
  wg_err "On Arch: sudo pacman -S wireguard-tools iproute2, and run as root."
  exit 2
fi

wg_info "loading the wireguard kernel module"
modprobe wireguard 2>/dev/null || {
  wg_err "could not load the wireguard module (modprobe wireguard)"
  exit 2
}

# Idempotency: remove any leftover topology from a previous run.
"$HERE/wg_teardown.sh" >/dev/null 2>&1 || true

wg_info "creating peer netns '$WG_PEER_NS' and veth pair"
ip netns add "$WG_PEER_NS"
ip link add "$WG_VETH_HOST" type veth peer name "$WG_VETH_PEER"
ip link set "$WG_VETH_PEER" netns "$WG_PEER_NS"
ip addr add "$WG_VETH_HOST_IP/$WG_VETH_PREFIX" dev "$WG_VETH_HOST"
ip link set "$WG_VETH_HOST" up
ip netns exec "$WG_PEER_NS" ip addr add "$WG_VETH_PEER_IP/$WG_VETH_PREFIX" dev "$WG_VETH_PEER"
ip netns exec "$WG_PEER_NS" ip link set "$WG_VETH_PEER" up
ip netns exec "$WG_PEER_NS" ip link set lo up

# Keys are passed to `wg` via process substitution (a /dev/fd path), never on
# argv. They are non-secret test material, but this keeps the pattern correct.
wg_info "configuring local WireGuard interface '$WG_IF_A'"
ip link add "$WG_IF_A" type wireguard
wg set "$WG_IF_A" \
  private-key <(printf '%s' "$WG_PRIV_A") \
  listen-port "$WG_PORT_A" \
  peer "$WG_PUB_B" endpoint "$WG_VETH_PEER_IP:$WG_PORT_B" allowed-ips "$WG_TUN_B/32"
ip addr add "$WG_TUN_A/$WG_TUN_PREFIX" dev "$WG_IF_A"
ip link set "$WG_IF_A" up

wg_info "configuring peer WireGuard interface '$WG_IF_B' (in $WG_PEER_NS)"
ip netns exec "$WG_PEER_NS" ip link add "$WG_IF_B" type wireguard
ip netns exec "$WG_PEER_NS" wg set "$WG_IF_B" \
  private-key <(printf '%s' "$WG_PRIV_B") \
  listen-port "$WG_PORT_B" \
  peer "$WG_PUB_A" endpoint "$WG_VETH_HOST_IP:$WG_PORT_A" allowed-ips "$WG_TUN_A/32"
ip netns exec "$WG_PEER_NS" ip addr add "$WG_TUN_B/$WG_TUN_PREFIX" dev "$WG_IF_B"
ip netns exec "$WG_PEER_NS" ip link set "$WG_IF_B" up

wg_info "verifying tunnel (ping $WG_TUN_B over WireGuard)"
if ping -c 2 -W 2 "$WG_TUN_B" >/dev/null 2>&1; then
  wg_info "WireGuard tunnel UP: $WG_TUN_A <-> $WG_TUN_B (peer in $WG_PEER_NS)"
else
  wg_err "tunnel verification failed (no reply from $WG_TUN_B)"
  exit 1
fi
