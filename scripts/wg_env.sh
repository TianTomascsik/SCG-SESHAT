#!/usr/bin/env bash
# Shared configuration + helpers for the SCG kernel-WireGuard benchmark harness.
#
# A single host cannot host two mutually-reachable WireGuard interfaces in one
# network namespace (their /32 tunnel routes collide), so the peer side lives in
# a dedicated netns connected by a veth pair — the canonical WireGuard test
# topology. setup/smoke/teardown all source this file so they agree on names,
# addresses, and keys.
#
# The keys below are fixed X25519 TEST material (derived with OpenSSL). They are
# NOT secret and exist only so the benchmark is reproducible; never reuse them
# for anything real.

# Peer network namespace + veth (real-network transport for the WG packets).
WG_PEER_NS="scg-wg-peer"
WG_VETH_HOST="scg-wgh"
WG_VETH_PEER="scg-wgp"
WG_VETH_HOST_IP="192.168.241.1"
WG_VETH_PEER_IP="192.168.241.2"
WG_VETH_PREFIX="24"

# WireGuard interfaces + tunnel (inner) addresses.
WG_IF_A="wg-scg-a"            # local interface (default netns)
WG_IF_B="wg-scg-b"            # peer interface (inside WG_PEER_NS)
WG_PORT_A="51820"
WG_PORT_B="51821"
WG_TUN_A="10.0.0.1"
WG_TUN_B="10.0.0.2"
WG_TUN_PREFIX="24"

# X25519 test keypairs (NOT secret; throwaway). Generated fresh with
# `wg genkey` when this file is sourced, unless the caller pins WG_PRIV_A /
# WG_PRIV_B in the environment (e.g. to keep one pair across a sweep).
# Public keys are always derived from the private keys, so A pairs with B.
if command -v wg >/dev/null 2>&1; then
  WG_PRIV_A="${WG_PRIV_A:-$(wg genkey)}"
  WG_PUB_A="$(printf '%s' "$WG_PRIV_A" | wg pubkey)"
  WG_PRIV_B="${WG_PRIV_B:-$(wg genkey)}"
  WG_PUB_B="$(printf '%s' "$WG_PRIV_B" | wg pubkey)"
fi

wg_info() { printf '[wg] %s\n' "$*"; }
wg_err() { printf '[wg] ERROR: %s\n' "$*" >&2; }

# True when the privileged WireGuard prerequisites are all present.
wg_prereqs_ok() {
  [[ "$(id -u)" -eq 0 ]] || return 1
  command -v wg >/dev/null 2>&1 || return 1
  command -v ip >/dev/null 2>&1 || return 1
  return 0
}

# Human-readable list of missing prerequisites (for skip/error messages).
wg_prereqs_reason() {
  local missing=()
  [[ "$(id -u)" -eq 0 ]] || missing+=("root/CAP_NET_ADMIN")
  command -v wg >/dev/null 2>&1 || missing+=("wireguard-tools (wg)")
  command -v ip >/dev/null 2>&1 || missing+=("iproute2 (ip)")
  printf '%s' "${missing[*]:-none}"
}
