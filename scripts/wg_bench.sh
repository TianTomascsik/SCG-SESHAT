#!/usr/bin/env bash
#
# Benchmark the SCG kernel-WireGuard data path (gateway-to-gateway) and print a
# results row: sustained throughput, p99 latency, and loss.
#
#   probe → [SCG encrypt gw, host ns] → wg-scg-a ──tunnel──> wg-scg-b
#         → [SCG decrypt gw, peer ns] → probe sink/echo
#
# Both SCG gateways attach to the kernel tunnel provisioned by wg_setup.sh
# (manage_interface=false), so the kernel does the cryptography and we measure
# the SCG WireGuard relay overhead end-to-end.
#
# Why a custom UDP probe and not `seshat sender`/`receiver`: SESHAT's distributed
# sender/receiver are TCP-only (TcpStream/TcpListener) and cannot drive a UDP
# datagram path. WireGuard is UDP-only, so we use scripts/wg_probe.py — a
# dependency-free UDP load/latency probe. Throughput is rate-swept (UDP has no
# flow control, so an unthrottled blast just finds where the relay starts
# dropping); the reported figure is the highest offered rate sustained under the
# loss threshold.
#
# Tunables (env): GATEWAY_BIN, WG_RATES_MBPS, WG_LOSS_THRESHOLD_PCT, WG_MSG_BYTES,
# WG_DURATION_S, WG_LAT_SAMPLES, WG_INGRESS_PORT, WG_MID_PORT, WG_RECV_PORT.
set +e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/wg_env.sh
source "$HERE/wg_env.sh"

GATEWAY_BIN="${GATEWAY_BIN:-$HERE/../../SCG/target/release/gateway}"
PROBE="$HERE/wg_probe.py"
INGRESS_PORT="${WG_INGRESS_PORT:-12200}"
MID_PORT="${WG_MID_PORT:-12300}"
RECV_PORT="${WG_RECV_PORT:-12400}"
MSG="${WG_MSG_BYTES:-1400}"
DUR="${WG_DURATION_S:-3}"
LAT_SAMPLES="${WG_LAT_SAMPLES:-1000}"
LOSS_THRESHOLD_PCT="${WG_LOSS_THRESHOLD_PCT:-1}"
RATES="${WG_RATES_MBPS:-250 500 1000 2000 4000}"

if ! wg_prereqs_ok; then
  wg_err "missing prerequisites: $(wg_prereqs_reason)"
  exit 2
fi
command -v python3 >/dev/null 2>&1 || { wg_err "python3 is required"; exit 2; }
[[ -x "$GATEWAY_BIN" ]] || { wg_err "gateway binary not found at $GATEWAY_BIN"; exit 2; }

# (Re)provision a fresh, ping-verified tunnel.
"$HERE/wg_setup.sh" || { wg_err "tunnel setup failed"; exit 1; }

W="$(mktemp -d)"
ENC=""; DEC=""
cleanup() {
  [[ -n "$ENC" ]] && kill "$ENC" 2>/dev/null
  [[ -n "$DEC" ]] && kill "$DEC" 2>/dev/null
  pkill -f 'wg_probe.py' 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

wg_gw_config() { # dir listen upstream iface port priv peerpub endpoint tun allowed
  cat <<JSON
{ "api": { "enabled": false },
  "policy": { "default_action": "allow", "whitelist": [] },
  "rules": [ {
  "name": "$1", "direction": "$2",
  "listen_addr": "$3", "listen_proto": "udp",
  "upstream_addr": "$4", "upstream_proto": "udp",
  "security_provider": "wireguard", "manage_interface": false,
  "wg_interface": "$5", "wg_listen_port": $6,
  "private_key": "$7", "peer_public_key": "$8",
  "peer_endpoint": "$9", "tunnel_local_ip": "${10}", "peer_allowed_ips": "${11}"
} ] }
JSON
}

wg_gw_config wg-bench-encrypt encrypt "127.0.0.1:$INGRESS_PORT" "$WG_TUN_B:$MID_PORT" \
  "$WG_IF_A" "$WG_PORT_A" "$WG_PRIV_A" "$WG_PUB_B" "$WG_VETH_PEER_IP:$WG_PORT_B" \
  "$WG_TUN_A/$WG_TUN_PREFIX" "$WG_TUN_B/32" >"$W/enc.json"
wg_gw_config wg-bench-decrypt decrypt "$WG_TUN_B:$MID_PORT" "127.0.0.1:$RECV_PORT" \
  "$WG_IF_B" "$WG_PORT_B" "$WG_PRIV_B" "$WG_PUB_A" "$WG_VETH_HOST_IP:$WG_PORT_A" \
  "$WG_TUN_B/$WG_TUN_PREFIX" "$WG_TUN_A/32" >"$W/dec.json"

# The SCG WireGuard relay pins to its FIRST source and rejects any second source
# port — it is a single logical gateway-to-gateway flow, so a stray second client
# must not be forwarded or receive the first client's return traffic
# (SCG/gateway/src/security/wireguard_engine.rs, TRA #39). The latency probe and
# each throughput-rate probe open a fresh socket (a new source port), so the
# gateway pair is restarted per measurement to re-pin to that measurement's source.
start_gws() {
  : >"$W/enc.log"; : >"$W/dec.log"
  ip netns exec "$WG_PEER_NS" "$GATEWAY_BIN" --config "$W/dec.json" --log-stdout >>"$W/dec.log" 2>&1 & DEC=$!
  "$GATEWAY_BIN" --config "$W/enc.json" --log-stdout >>"$W/enc.log" 2>&1 & ENC=$!
  for _ in $(seq 1 50); do
    grep -q "UDP socket on 127.0.0.1:$INGRESS_PORT" "$W/enc.log" 2>/dev/null \
      && grep -q "UDP socket on $WG_TUN_B:$MID_PORT" "$W/dec.log" 2>/dev/null && break
    sleep 0.2
  done
  if ! grep -q "UDP socket on 127.0.0.1:$INGRESS_PORT" "$W/enc.log" 2>/dev/null; then
    wg_err "encrypt gateway did not bind"; cat "$W/enc.log" >&2; exit 1
  fi
}
stop_gws() {
  [[ -n "$ENC" ]] && kill "$ENC" 2>/dev/null
  [[ -n "$DEC" ]] && kill "$DEC" 2>/dev/null
  wait "$ENC" "$DEC" 2>/dev/null
  ENC=""; DEC=""
}

wg_info "starting gateways"
start_gws

# ── Latency (closed-loop RTT) ────────────────────────────────────────────────
wg_info "measuring latency ($LAT_SAMPLES samples)"
ip netns exec "$WG_PEER_NS" python3 "$PROBE" receiver 127.0.0.1 "$RECV_PORT" echo "$((DUR + 4))" >"$W/le.out" 2>"$W/le.err" &
sleep 0.6
LAT="$(python3 "$PROBE" latency 127.0.0.1 "$INGRESS_PORT" "$MSG" "$LAT_SAMPLES" 2>&1)"
pkill -f 'wg_probe.py receiver' 2>/dev/null; sleep 0.3
P50="$(printf '%s' "$LAT" | sed -nE 's/.*p50=([0-9.]+).*/\1/p')"
P99="$(printf '%s' "$LAT" | sed -nE 's/.*p99=([0-9.]+).*/\1/p')"
stop_gws  # the latency source pinned the relay; each throughput rate needs a fresh pin

# ── Throughput (rate sweep, find highest offered rate under the loss bar) ─────
best_tp="0.0"; best_loss="n/a"; best_offer="0"
for R in $RATES; do
  : >"$W/ts.err"
  start_gws  # fresh gateways so the relay pins to THIS rate's sender source (#39)
  ip netns exec "$WG_PEER_NS" python3 "$PROBE" receiver 127.0.0.1 "$RECV_PORT" sink "$((DUR + 2))" >"$W/ts.out" 2>"$W/ts.err" &
  SINK=$!
  sleep 0.5
  SENT="$(python3 "$PROBE" throughput 127.0.0.1 "$INGRESS_PORT" "$MSG" "$DUR" "$R" 2>&1 | grep -oE 'SENT [0-9]+' | grep -oE '[0-9]+')"
  # Wait for the sink's alarm-driven report() to flush 'count=' before grepping.
  wait "$SINK" 2>/dev/null
  RECV="$(grep -oE 'count=[0-9]+' "$W/ts.err" | grep -oE '[0-9]+')"; RECV="${RECV:-0}"; SENT="${SENT:-0}"
  if [[ "$RECV" == "0" ]]; then
    echo "[wg][debug] SENT=$SENT ts.out=[$(cat "$W/ts.out" 2>/dev/null)] ts.err=[$(cat "$W/ts.err" 2>/dev/null)]"
    for L in "$W"/*.log; do echo "[wg][debug] ${L##*/}:"; tail -n 6 "$L"; done
  fi
  DELIV="$(awk -v r="$RECV" -v d="$DUR" -v m="$MSG" 'BEGIN{printf "%.3f", r*m*8/d/1e9}')"
  LOSS="$(awk -v s="$SENT" -v r="$RECV" 'BEGIN{if(s>0)printf "%.2f",100*(s-r)/s; else print 100}')"
  wg_info "  offer ${R} Mbit/s -> delivered ${DELIV} Gbit/s, loss ${LOSS}%"
  under="$(awk -v l="$LOSS" -v t="$LOSS_THRESHOLD_PCT" 'BEGIN{print (l+0<=t+0)?1:0}')"
  if [[ "$under" == 1 ]]; then
    best_tp="$DELIV"; best_loss="$LOSS"; best_offer="$R"
  fi
  stop_gws
done

# ── Report ───────────────────────────────────────────────────────────────────
printf '\n'
printf ' +----------------------------------+-----------------+-------------+--------+\n'
printf ' | Path                             | Throughput      | p99 Latency | Loss   |\n'
printf ' +----------------------------------+-----------------+-------------+--------+\n'
printf ' | %-32s | %9s Gbit/s | %8s us | %5s%% |\n' \
  "wireguard scg->scg (${MSG}B, 1-stream)" "$best_tp" "${P99:-n/a}" "$best_loss"
printf ' +----------------------------------+-----------------+-------------+--------+\n'
printf '   (sustained throughput = highest offered rate with loss <= %s%%; p50 latency %s us)\n\n' \
  "$LOSS_THRESHOLD_PCT" "${P50:-n/a}"

if [[ -z "$P99" ]]; then
  wg_err "latency measurement produced no samples"; cat "$W/enc.log" "$W/dec.log" >&2; exit 1
fi
if awk -v t="$best_tp" 'BEGIN{exit (t+0>0)?0:1}'; then
  wg_info "WireGuard benchmark complete"
else
  wg_err "no offered rate stayed under the ${LOSS_THRESHOLD_PCT}% loss bar (try lower WG_RATES_MBPS)"
  exit 1
fi
