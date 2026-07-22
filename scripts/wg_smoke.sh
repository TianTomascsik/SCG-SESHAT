#!/usr/bin/env bash
#
# Drive plaintext UDP through the SCG kernel-WireGuard data path and gate on
# packet loss. Exercises the real gateway WireGuard provider (relay + return
# path) over a genuine kernel WireGuard tunnel:
#
#   probe → [SCG encrypt gateway, default netns] → wg-scg-a (ENCRYPT)
#         → veth → wg-scg-b (DECRYPT, peer netns) → UDP echo → back
#
# The gateway attaches to the already-provisioned tunnel (manage_interface=false),
# so the kernel does the cryptography. Requires wg_setup.sh to have run (it is
# invoked automatically if the tunnel is absent).
#
# Tunables (env): WG_INGRESS_PORT, WG_RECV_PORT, WG_PROBE_COUNT,
# WG_LOSS_THRESHOLD_PCT, GATEWAY_BIN.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/wg_env.sh
source "$HERE/wg_env.sh"

GATEWAY_BIN="${GATEWAY_BIN:-$HERE/../../SCG/target/release/gateway}"
INGRESS_PORT="${WG_INGRESS_PORT:-12200}"
RECV_PORT="${WG_RECV_PORT:-12300}"
COUNT="${WG_PROBE_COUNT:-200}"
LOSS_THRESHOLD_PCT="${WG_LOSS_THRESHOLD_PCT:-5}"

if ! wg_prereqs_ok; then
  wg_err "missing prerequisites: $(wg_prereqs_reason)"
  exit 2
fi
command -v python3 >/dev/null 2>&1 || {
  wg_err "python3 is required for the smoke probe"
  exit 2
}
if [[ ! -x "$GATEWAY_BIN" ]]; then
  wg_err "gateway binary not found at $GATEWAY_BIN"
  wg_err "build it: (cd ../SCG && cargo build --release -p gateway)"
  exit 2
fi

# Ensure the tunnel exists.
ip link show "$WG_IF_A" >/dev/null 2>&1 || "$HERE/wg_setup.sh"

WORK="$(mktemp -d)"
GW_PID=""
ECHO_PID=""
cleanup() {
  [[ -n "$GW_PID" ]] && kill "$GW_PID" 2>/dev/null || true
  [[ -n "$ECHO_PID" ]] && kill "$ECHO_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# SCG encrypt gateway: relays plaintext UDP from the ingress port through the
# kernel WireGuard tunnel (manage_interface=false → attaches to wg-scg-a).
cat >"$WORK/encrypt.json" <<JSON
{ "policy": { "default_action": "allow", "whitelist": [] },
  "rules": [ {
  "name": "wg-smoke-encrypt",
  "direction": "encrypt",
  "listen_addr": "127.0.0.1:$INGRESS_PORT",
  "listen_proto": "udp",
  "upstream_addr": "$WG_TUN_B:$RECV_PORT",
  "upstream_proto": "udp",
  "security_provider": "wireguard",
  "manage_interface": false,
  "wg_interface": "$WG_IF_A",
  "wg_listen_port": $WG_PORT_A,
  "private_key": "$WG_PRIV_A",
  "peer_public_key": "$WG_PUB_B",
  "peer_endpoint": "$WG_VETH_PEER_IP:$WG_PORT_B",
  "tunnel_local_ip": "$WG_TUN_A/$WG_TUN_PREFIX",
  "peer_allowed_ips": "$WG_TUN_B/32"
} ] }
JSON

# UDP echo behind the tunnel (the gateway's upstream), in the peer netns.
ip netns exec "$WG_PEER_NS" python3 - "$WG_TUN_B" "$RECV_PORT" <<'PY' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    data, peer = s.recvfrom(65535)
    s.sendto(data, peer)
PY
ECHO_PID=$!

"$GATEWAY_BIN" --config "$WORK/encrypt.json" --log-stdout >"$WORK/gw.log" 2>&1 &
GW_PID=$!
sleep 1   # let the gateway bind and the tunnel settle

wg_info "probing $COUNT datagrams through the SCG WireGuard data path"
LOSS="$(python3 - "127.0.0.1" "$INGRESS_PORT" "$COUNT" <<'PY'
import socket, sys
host, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((host, port))
s.settimeout(0.5)
recv = 0
for i in range(count):
    payload = b"wg-smoke-%08d" % i
    try:
        s.send(payload)
        if s.recv(65535) == payload:
            recv += 1
    except OSError:
        pass
lost = count - recv
print(f"{100.0 * lost / count:.2f}")
PY
)"

wg_info "loss = ${LOSS}% (threshold ${LOSS_THRESHOLD_PCT}%)"
if awk -v l="$LOSS" -v t="$LOSS_THRESHOLD_PCT" 'BEGIN { exit (l + 0 <= t + 0) ? 0 : 1 }'; then
  wg_info "WireGuard smoke gate PASSED"
else
  wg_err "WireGuard smoke gate FAILED: loss ${LOSS}% exceeds ${LOSS_THRESHOLD_PCT}%"
  echo "---- gateway log ----" >&2
  cat "$WORK/gw.log" >&2 || true
  exit 1
fi
