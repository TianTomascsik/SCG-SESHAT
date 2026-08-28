#!/usr/bin/env bash
#
# Two-host ("wire") benchmark for the SCG: run the same cells over a physical
# Ethernet link and over loopback on the same machine, changing exactly one
# variable — the inter-gateway hop address.
#
#   --mode loopback   mid hop = 127.0.0.1, both gateways local (the baseline)
#   --mode wire       mid hop = $WIRE_PEER_IP, decrypt gateway on the peer
#
# The instrumented side (load generator, encrypt gateway, all metric
# collection) stays on this host so every number comes from one machine's
# clock and one machine's /proc. The peer only terminates the tunnel.
#
# Start the peer first, on the other machine:
#     ./wire_peer.sh --local-ip 10.9.0.2
#
# Then here:
#     ./wire_bench.sh --mode loopback              # baseline half
#     ./wire_bench.sh --mode wire --peer 10.9.0.2  # wire half
#
# Tunables live in wire_env.sh (ports, message shapes, sweep grid, timings).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/wire_env.sh
source "$HERE/wire_env.sh"

MODE=""
GROUP="all"
OUT_DIR=""
QUICK=0
FRESH_PKI=0
GATEWAY_BIN="${SCG_GATEWAY_BIN:-$HERE/../../SCG/target/release/gateway}"
SESHAT_BIN="${SESHAT_BIN:-$HERE/../target/release/seshat}"
PROBE="$HERE/wire_probe.py"

usage() {
  sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --peer) WIRE_PEER_IP="$2"; shift 2 ;;
    --local-ip) WIRE_LOCAL_IP="$2"; shift 2 ;;
    --dev) WIRE_DEV="$2"; shift 2 ;;
    --group) GROUP="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --quick) QUICK=1; shift ;;
    --fresh-pki) FRESH_PKI=1; shift ;;
    -h|--help) usage 0 ;;
    *) wire_err "unknown argument: $1"; usage 2 ;;
  esac
done

[[ "$MODE" == "loopback" || "$MODE" == "wire" ]] || { wire_err "--mode must be loopback or wire"; usage 2; }
if [[ "$MODE" == "wire" && -z "$WIRE_DEV" ]]; then
  wire_err "--dev (or WIRE_DEV) is required in wire mode: the egress NIC for tc/tcpdump"
  usage 2
fi
if [[ $QUICK == 1 ]]; then
  WIRE_MEASURE_S=3; WIRE_WARMUP_S=1; WIRE_RUNS=1
  WIRE_SWEEP_MEASURE_S=2; WIRE_SWEEP_STEP_MBPS=300
fi

# In loopback mode the "peer" is this machine, so the mid hop and the peer-side
# sinks are all on 127.0.0.1. This is the single variable under test.
if [[ "$MODE" == "loopback" ]]; then
  MID_HOST="127.0.0.1"
  SINK_HOST="127.0.0.1"
else
  MID_HOST="$WIRE_PEER_IP"
  SINK_HOST="$WIRE_PEER_IP"
fi

[[ -x "$GATEWAY_BIN" ]] || { wire_err "gateway binary not found at $GATEWAY_BIN (set SCG_GATEWAY_BIN)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { wire_err "python3 is required"; exit 2; }

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$HERE/../results/wire-$MODE-$TS}"
mkdir -p "$OUT_DIR"
# Absolute, so the emitted configs do not depend on the caller's working
# directory — a relative cert_path silently breaks the moment the config is read
# from anywhere else, which is exactly what happens to the peer bundle.
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
WORK="$OUT_DIR/work"; mkdir -p "$WORK"
PKI="$OUT_DIR/wire-pki"
CSV="$OUT_DIR/wire_summary.csv"

ENC_PID=""; DEC_PID=""; PEER_PIDS=()
# The gateway treats the first SIGTERM as a graceful shutdown request and only
# exits on a second ("send again to force quit"), so a bare `wait` here would
# hang the script forever. Escalate instead, and never block unbounded.
cleanup() {
  local pids=("$ENC_PID" "$DEC_PID" "${PEER_PIDS[@]:-}")
  for p in "${pids[@]}"; do [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null; done
  sleep 0.3
  for p in "${pids[@]}"; do [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null; done
  sleep 0.3
  for p in "${pids[@]}"; do [[ -n "$p" ]] && kill -KILL "$p" 2>/dev/null; done
  pkill -f "$PROBE" 2>/dev/null
  return 0
}
trap cleanup EXIT

# ── PKI ──────────────────────────────────────────────────────────────────────
# M-13 makes verify:mutual mandatory once the decrypt listener is non-loopback,
# so both ends need CA-signed identities. The server leaf carries IP SANs for
# both link addresses because the encrypt side dials by IP literal.
mint_pki() {
  # Reuse an existing bundle. This is not an optimisation: in wire mode the peer
  # already holds the server leaf that was distributed to it, so reminting here
  # would leave the two ends on different CAs and every handshake would fail with
  # "self-signed certificate in certificate chain" — a confusing way to discover
  # that the identities drifted. Pass --fresh-pki to force new material, and
  # redistribute the peer bundle when you do.
  if [[ $FRESH_PKI -eq 0 && -f "$PKI/ca.crt" && -f "$PKI/client.crt" && -f "$PKI/server.crt" ]]; then
    if openssl x509 -in "$PKI/server.crt" -noout -checkend 300 >/dev/null 2>&1; then
      wire_info "reusing existing PKI in $PKI (the peer already holds this identity)"
      return 0
    fi
    wire_err "existing PKI in $PKI expires within 5 minutes — reminting"
    wire_err "redistribute the peer bundle after this run starts, or the peer will not verify"
  fi
  rm -rf "$PKI"
  if [[ -x "$SESHAT_BIN" ]]; then
    "$SESHAT_BIN" pki --out "$PKI" --days 2 \
      --san "IP:$WIRE_PEER_IP" --san "IP:$WIRE_LOCAL_IP" >/dev/null || return 1
  else
    wire_err "seshat binary not found at $SESHAT_BIN (cargo build --release), needed for 'seshat pki'"
    return 1
  fi
  wire_info "minted mutual-TLS bundle in $PKI (2-day validity, single-purpose)"
}

# ── Gateway configs ──────────────────────────────────────────────────────────
emit_configs() {
  local enc=() dec=()
  enc+=("$(wire_rule wire-enc-bulk encrypt "127.0.0.1:$WIRE_INGRESS_BULK" tcp \
        "$MID_HOST:$WIRE_MID_BULK" tcp tls normal - "$PKI" client "$MID_HOST")")
  enc+=("$(wire_rule wire-enc-safety encrypt "127.0.0.1:$WIRE_INGRESS_SAFETY" tcp \
        "$MID_HOST:$WIRE_MID_SAFETY" tcp tls safety "$WIRE_SAFETY_DSCP" "$PKI" client "$MID_HOST")")
  enc+=("$(wire_rule wire-enc-dgram encrypt "127.0.0.1:$WIRE_INGRESS_DGRAM" udp \
        "$MID_HOST:$WIRE_MID_DGRAM" udp dtls safety "$WIRE_SAFETY_DSCP" "$PKI" client "$MID_HOST")")
  enc+=("$(wire_rule wire-enc-nprobe encrypt "127.0.0.1:$WIRE_INGRESS_NPROBE" tcp \
        "$MID_HOST:$WIRE_MID_NPROBE" tcp tls normal "$WIRE_NORMAL_DSCP" "$PKI" client "$MID_HOST")")
  wire_config "$PKI" "${enc[@]}" > "$WORK/enc.json"

  dec+=("$(wire_rule wire-dec-bulk decrypt "$MID_HOST:$WIRE_MID_BULK" tcp \
        "127.0.0.1:$WIRE_SINK_BULK" tcp tls normal - "$PKI" server "$MID_HOST")")
  dec+=("$(wire_rule wire-dec-safety decrypt "$MID_HOST:$WIRE_MID_SAFETY" tcp \
        "127.0.0.1:$WIRE_SINK_SAFETY" tcp tls safety "$WIRE_SAFETY_DSCP" "$PKI" server "$MID_HOST")")
  dec+=("$(wire_rule wire-dec-dgram decrypt "$MID_HOST:$WIRE_MID_DGRAM" udp \
        "127.0.0.1:$WIRE_SINK_DGRAM" udp dtls safety "$WIRE_SAFETY_DSCP" "$PKI" server "$MID_HOST")")
  dec+=("$(wire_rule wire-dec-nprobe decrypt "$MID_HOST:$WIRE_MID_NPROBE" tcp \
        "127.0.0.1:$WIRE_SINK_NPROBE" tcp tls normal "$WIRE_NORMAL_DSCP" "$PKI" server "$MID_HOST")")
  wire_config "$PKI" "${dec[@]}" > "$WORK/dec.json"

  # Fail before opening any socket if either side is misconfigured. On host A
  # the decrypt config's binds are not local, so only check it in loopback mode.
  "$GATEWAY_BIN" --config "$WORK/enc.json" --validate >"$WORK/validate-enc.log" 2>&1 || {
    wire_err "encrypt config failed validation:"; grep -i error "$WORK/validate-enc.log" >&2; return 1; }
  if [[ "$MODE" == "loopback" ]]; then
    "$GATEWAY_BIN" --config "$WORK/dec.json" --validate >"$WORK/validate-dec.log" 2>&1 || {
      wire_err "decrypt config failed validation:"; grep -i error "$WORK/validate-dec.log" >&2; return 1; }
  fi
  wire_info "gateway configs validated"
}

# Everything the peer machine needs, so it can be copied in one go.
emit_peer_bundle() {
  local bundle="$OUT_DIR/peer-bundle"
  mkdir -p "$bundle/wire-pki"
  cp "$WORK/dec.json" "$bundle/dec.json"
  cp "$PKI/ca.crt" "$PKI/server.crt" "$PKI/server.key" "$bundle/wire-pki/"
  chmod 600 "$bundle/wire-pki/server.key"
  cp "$HERE/wire_peer.sh" "$HERE/wire_env.sh" "$HERE/wire_probe.py" "$bundle/"
  # Ship the gateway too, so the bundle is self-contained. It is dynamically
  # linked against OpenSSL 3 and glibc, so this only runs on a peer with a
  # compatible runtime; otherwise build the gateway on the peer and point
  # wire_peer.sh at it with --gateway PATH.
  if cp "$GATEWAY_BIN" "$bundle/gateway" 2>/dev/null; then
    chmod +x "$bundle/gateway"
    wire_info "peer bundle ready: $bundle (includes the gateway binary)"
  else
    wire_info "peer bundle ready: $bundle (NO gateway binary — pass --gateway PATH on the peer)"
  fi
  wire_info "copy it over, then on the peer:  ./wire_peer.sh --local-ip $WIRE_PEER_IP --dev <nic> --capture"
}

# ── Process lifecycle ────────────────────────────────────────────────────────
start_gateways() {
  : >"$WORK/enc.log"
  "$GATEWAY_BIN" --config "$WORK/enc.json" --log-stdout >>"$WORK/enc.log" 2>&1 &
  ENC_PID=$!
  if [[ "$MODE" == "loopback" ]]; then
    : >"$WORK/dec.log"
    "$GATEWAY_BIN" --config "$WORK/dec.json" --log-stdout >>"$WORK/dec.log" 2>&1 &
    DEC_PID=$!
    wire_wait_tcp 127.0.0.1 "$WIRE_MID_BULK" || { wire_err "decrypt gateway did not bind"; tail -20 "$WORK/dec.log" >&2; return 1; }
  else
    wire_wait_tcp "$WIRE_PEER_IP" "$WIRE_MID_BULK" || {
      wire_err "peer decrypt gateway is not reachable at $WIRE_PEER_IP:$WIRE_MID_BULK"
      wire_err "start it on the peer first:  ./wire_peer.sh --local-ip $WIRE_PEER_IP"
      return 1; }
  fi
  wire_wait_tcp 127.0.0.1 "$WIRE_INGRESS_BULK" || { wire_err "encrypt gateway did not bind"; tail -20 "$WORK/enc.log" >&2; return 1; }
  wire_info "gateways up (encrypt pid $ENC_PID${DEC_PID:+, decrypt pid $DEC_PID})"
}

# In loopback mode we also host the far-side endpoints; in wire mode wire_peer.sh
# does. Only the *echo* endpoints are persistent: the bulk sink is started per
# cell so each cell gets its own delivered/loss/DSCP report. Running a
# persistent sink as well would double-bind the port and leave every cell
# without a sink report.
start_local_peer_endpoints() {
  [[ "$MODE" == "loopback" ]] || return 0
  python3 "$PROBE" echo --proto tcp --bind "127.0.0.1:$WIRE_SINK_SAFETY" \
    --msg "$WIRE_SAFETY_MSG" --duration 0 >/dev/null 2>&1 &
  PEER_PIDS+=($!)
  python3 "$PROBE" echo --proto tcp --bind "127.0.0.1:$WIRE_SINK_NPROBE" \
    --msg "$WIRE_SAFETY_MSG" --duration 0 >/dev/null 2>&1 &
  PEER_PIDS+=($!)
  sleep 1
}

# Prove the end-to-end path actually carries data before committing to a full
# campaign. Without this a mismatched identity, an unreachable sink or a stale
# peer bundle yields a complete run of structurally empty cells — the failure is
# silent because every cell "succeeds" at doing nothing.
preflight_path_check() {
  local probe_json="$WORK/preflight.json"
  rm -f "$probe_json"
  python3 "$PROBE" --report-file "$probe_json" point --proto tcp \
    --duration 2 --warmup 1 \
    --rtt-target "127.0.0.1:$WIRE_INGRESS_SAFETY" --rtt-msg "$WIRE_SAFETY_MSG" \
    --rtt-interval-us 0 >/dev/null 2>&1
  local n
  n="$(python3 -c "
import json,sys
try:
    print(json.load(open('$probe_json')).get('rtt_n', 0))
except Exception:
    print(0)
" 2>/dev/null)"
  if [[ "${n:-0}" -gt 0 ]]; then
    wire_info "preflight: end-to-end path carries traffic ($n round trips in 2 s)"
    return 0
  fi
  wire_err "preflight FAILED: no traffic completed the path — aborting before a full run"
  wire_err "the most common causes, in order:"
  wire_err "  1. the peer holds a different PKI than this run (redistribute the peer bundle)"
  wire_err "  2. the peer's sinks/echo endpoints are not running"
  wire_err "  3. the peer gateway is up but its upstream sink is unreachable"
  local errs
  errs="$(grep -iE "error|handshake|verify" "$WORK/enc.log" 2>/dev/null | tail -3)"
  [[ -n "$errs" ]] && { wire_err "encrypt gateway says:"; printf '%s\n' "$errs" >&2; }
  return 1
}

# ── CPU accounting for the local encrypt gateway ─────────────────────────────
cpu_ticks() { # pid -> utime+stime in clock ticks
  local pid="$1"
  [[ -r "/proc/$pid/stat" ]] || { echo 0; return; }
  awk '{print $14 + $15}' "/proc/$pid/stat" 2>/dev/null || echo 0
}

# ── CSV ──────────────────────────────────────────────────────────────────────
# Column names mirror SESHAT's own summary.csv (src/report/results.rs) so
# seshat-viz, which keys by name, loads this file unchanged. Columns that are
# structurally unmeasurable here are left EMPTY rather than zero-filled:
# one-way latency and jitter need a shared clock the two hosts do not have.
csv_header() {
  cat >"$CSV" <<'HDR'
scenario,mode,transport,protocol,traffic_class,message_bytes,connections,runs,offered_mbps,throughput_gbps_mean,delivered_gbps,rtt_us_mean,rtt_us_ci95,rtt_us_p50,rtt_us_p99,latency_mean_us,latency_p99_us_mean,jitter_us_mean,loss_pct,total_lost,send_lag_mean_us,send_lag_max_us,rtt_resyncs,cpu_pct_mean,gbps_per_core,dscp_observed,dscp_matched,dscp_preserved,ceiling_gbps,link_limited,bottleneck,measurement_side,dut
HDR
}

# Merge one probe RESULT (sender side) with an optional sink report and append
# a row. Empty fields stay empty on purpose.
emit_row() { # scenario proto class msg conns offered sender_json sink_json cpu_pct
  python3 - "$@" <<'PY' >>"$CSV"
import json, sys
scenario, proto, klass, msg, conns, offered, sender_p, sink_p, cpu_pct, ceiling, mode = sys.argv[1:12]

def load(path):
    if not path or path == "-":
        return {}
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}

s = load(sender_p)
k = load(sink_p)


def g(d, key, default=""):
    v = d.get(key, default)
    return "" if v is None else v


delivered = g(k, "delivered_gbps")
sender_gbps = g(s, "sender_gbps")
cpu = float(cpu_pct) if cpu_pct not in ("", "-") else 0.0
# Cores consumed = cpu% / 100; report goodput per core when both are known.
# Prefer the far-side delivered figure; fall back to the sender-side one, which
# for TCP is equivalent within a socket buffer. Without the fallback every wire
# row would be blank here, because delivered only arrives with the peer's burst
# reports — and CPU-per-Gbit at matched load is the whole supportive half of the
# loopback-realism comparison.
per_core = ""
basis = delivered if delivered != "" else sender_gbps
try:
    if basis != "" and cpu > 0:
        per_core = round(float(basis) / (cpu / 100.0), 4)
except (TypeError, ValueError):
    per_core = ""

# The reference for a wire cell is the link's goodput ceiling, not the loopback
# null-transport ceiling SESHAT uses for single-host runs. `link_limited` is a
# separate field from `harness_limited` on purpose: that term already has a
# published meaning in the thesis and must not be reused for a different cause.
link_limited = ""
bottleneck = ""
try:
    if delivered != "" and mode == "wire":
        link_limited = "true" if float(delivered) >= 0.90 * float(ceiling) else "false"
        bottleneck = "link" if link_limited == "true" else "unclassified"
except (TypeError, ValueError):
    pass

dscp_pres = k.get("dscp_preserved")
row = [
    scenario, mode, proto, ("dtls" if proto == "udp" else "tls"), klass, msg, conns,
    g(s, "runs", 1), offered, sender_gbps, delivered,
    g(s, "rtt_us_mean"), g(s, "rtt_us_ci95"), g(s, "rtt_us_p50"), g(s, "rtt_us_p99"),
    "", "", "",                      # one-way latency/jitter: no shared clock
    g(k, "loss_pct"), g(k, "lost"),
    g(s, "send_lag_mean_us"), g(s, "send_lag_max_us"), g(s, "rtt_resyncs"),
    round(cpu, 2) if cpu else "", per_core,
    g(k, "dscp_observed"), g(k, "dscp_matched"),
    "" if dscp_pres is None else ("true" if dscp_pres else "false"),
    ceiling, link_limited, bottleneck, "sender", "scg-over-wire",
]
print(",".join(str(c) for c in row))
PY
}

# ── Cell runner ──────────────────────────────────────────────────────────────
# One measured cell: start a fresh far-side sink when we own it, run the probe,
# collect both halves plus the local gateway's CPU, append a CSV row.
run_cell() { # scenario proto class msg conns rate duration extra_probe_args...
  local base="$1"
  local run
  # WIRE_RUNS repeats per cell, each emitted as its own CSV row. A single shot
  # cannot separate a real effect from run-to-run variance, which matters most
  # for the prioritisation cells where the whole claim is a delta between two
  # conditions.
  for ((run = 1; run <= WIRE_RUNS; run++)); do
    if [[ $WIRE_RUNS -gt 1 ]]; then
      run_cell_once "${base}#r${run}" "${@:2}"
    else
      run_cell_once "$@"
    fi
  done
}

run_cell_once() {
  local scenario="$1" proto="$2" klass="$3" msg="$4" conns="$5" rate="$6" dur="$7"; shift 7
  local sink_json="$WORK/$scenario.sink.json"
  local send_json="$WORK/$scenario.send.json"
  rm -f "$sink_json" "$send_json"

  local sink_pid=""
  if [[ "$MODE" == "loopback" && "$conns" != "0" ]]; then
    local dscp_arg=()
    [[ "$proto" == "udp" ]] && dscp_arg=(--expect-dscp "$WIRE_SAFETY_DSCP")
    local sink_port="$WIRE_SINK_BULK"
    [[ "$proto" == "udp" ]] && sink_port="$WIRE_SINK_DGRAM"
    python3 "$PROBE" --report-file "$sink_json" sink --proto "$proto" \
      --bind "127.0.0.1:$sink_port" --msg "$msg" --conns "$conns" \
      --duration "$((dur + WIRE_WARMUP_S + 3))" "${dscp_arg[@]}" >/dev/null 2>&1 &
    sink_pid=$!
    sleep 0.7
  fi

  local t0 t1 ticks_before ticks_after cpu_pct
  ticks_before="$(cpu_ticks "$ENC_PID")"; t0="$(date +%s.%N)"
  python3 "$PROBE" --report-file "$send_json" point --proto "$proto" \
    --duration "$dur" --warmup "$WIRE_WARMUP_S" "$@" >/dev/null 2>&1
  t1="$(date +%s.%N)"; ticks_after="$(cpu_ticks "$ENC_PID")"
  cpu_pct="$(awk -v a="$ticks_before" -v b="$ticks_after" -v t0="$t0" -v t1="$t1" \
    'BEGIN{hz=100; d=t1-t0; if(d>0) printf "%.2f", 100*(b-a)/hz/d; else print 0}')"

  [[ -n "$sink_pid" ]] && wait "$sink_pid" 2>/dev/null
  emit_row "$scenario" "$proto" "$klass" "$msg" "$conns" "$rate" \
    "$send_json" "$sink_json" "$cpu_pct" "$(wire_goodput_ceiling_gbps)" "$MODE"
  wire_info "  $scenario done"
}

# ── Groups ───────────────────────────────────────────────────────────────────
group_qos() {
  wire_info "group: QOS-001 prioritisation (safety alone / contended as safety / as normal)"
  # (a) safety alone — the uncontended reference
  run_cell "qos-safety-alone" tcp safety "$WIRE_SAFETY_MSG" 0 0 "$WIRE_MEASURE_S" \
    --rtt-target "127.0.0.1:$WIRE_INGRESS_SAFETY" --rtt-msg "$WIRE_SAFETY_MSG" \
    --rtt-interval-us "$WIRE_SAFETY_INTERVAL_US" --rtt-dscp "$WIRE_SAFETY_DSCP"
  # (b) safety contended, classified safety — sent through the safety rule
  run_cell "qos-safety-contended" tcp safety "$WIRE_SAFETY_MSG" "$WIRE_BULK_CONNS" 0 "$WIRE_MEASURE_S" \
    --bulk-target "127.0.0.1:$WIRE_INGRESS_BULK" --bulk-conns "$WIRE_BULK_CONNS" \
    --bulk-msg "$WIRE_BULK_MSG" --bulk-rate-mbps 0 \
    --rtt-target "127.0.0.1:$WIRE_INGRESS_SAFETY" --rtt-msg "$WIRE_SAFETY_MSG" \
    --rtt-interval-us "$WIRE_SAFETY_INTERVAL_US" --rtt-dscp "$WIRE_SAFETY_DSCP"
  # (c) the classification control: identical probe and identical contending
  # load, but carried by a NORMAL-classified rule, so any p99 difference against
  # (b) is attributable to classification alone.
  run_cell "qos-normal-contended" tcp normal "$WIRE_SAFETY_MSG" "$WIRE_BULK_CONNS" 0 "$WIRE_MEASURE_S" \
    --bulk-target "127.0.0.1:$WIRE_INGRESS_BULK" --bulk-conns "$WIRE_BULK_CONNS" \
    --bulk-msg "$WIRE_BULK_MSG" --bulk-rate-mbps 0 \
    --rtt-target "127.0.0.1:$WIRE_INGRESS_NPROBE" --rtt-msg "$WIRE_SAFETY_MSG" \
    --rtt-interval-us "$WIRE_SAFETY_INTERVAL_US" --rtt-dscp "$WIRE_NORMAL_DSCP"
}

group_rtt() {
  wire_info "group: closed-loop RTT (clock-skew-immune)"
  for size in 64 1024 16384; do
    run_cell "rtt-tls-$size" tcp safety "$size" 0 0 "$WIRE_MEASURE_S" \
      --rtt-target "127.0.0.1:$WIRE_INGRESS_SAFETY" --rtt-msg "$size" --rtt-interval-us 0
  done
}

group_throughput() {
  wire_info "group: sender-side throughput against line rate"
  for conns in 1 4; do
    run_cell "tput-tls-c$conns" tcp normal "$WIRE_BULK_MSG" "$conns" 0 "$WIRE_MEASURE_S" \
      --bulk-target "127.0.0.1:$WIRE_INGRESS_BULK" --bulk-conns "$conns" \
      --bulk-msg "$WIRE_BULK_MSG" --bulk-rate-mbps 0
  done
}

group_dtls() {
  wire_info "group: DTLS datagram path (the only in-process DSCP observation)"
  # Paced just under the link ceiling, not blasted. UDP has no flow control, so
  # an unthrottled datagram blast only finds where the relay starts dropping
  # (~32% loss on loopback) instead of measuring the AEAD path — the same reason
  # wg_bench.sh rate-sweeps rather than blasting.
  run_cell "dtls-dgram" udp safety "$WIRE_DGRAM_MSG" 1 "$WIRE_DTLS_RATE_MBPS" "$WIRE_MEASURE_S" \
    --bulk-target "127.0.0.1:$WIRE_INGRESS_DGRAM" --bulk-conns 1 \
    --bulk-msg "$WIRE_DGRAM_MSG" --bulk-rate-mbps "$WIRE_DTLS_RATE_MBPS" \
    --bulk-dscp "$WIRE_SAFETY_DSCP"
}

# Claim 4: the same offered-load grid on both media. Each point carries a
# concurrent low-rate closed-loop RTT probe, because the sweep's own latency
# column would be a cross-host one-way figure and therefore meaningless.
group_sweep() {
  wire_info "group: offered-load sweep ${WIRE_SWEEP_START_MBPS}..${WIRE_SWEEP_MAX_MBPS} Mbit/s"
  local rate="$WIRE_SWEEP_START_MBPS"
  while (( $(awk -v r="$rate" -v m="$WIRE_SWEEP_MAX_MBPS" 'BEGIN{print (r<=m)?1:0}') )); do
    run_cell "sweep-tcp-${rate}" tcp normal "$WIRE_BULK_MSG" 1 "$rate" "$WIRE_SWEEP_MEASURE_S" \
      --bulk-target "127.0.0.1:$WIRE_INGRESS_BULK" --bulk-conns 1 \
      --bulk-msg "$WIRE_BULK_MSG" --bulk-rate-mbps "$rate" \
      --rtt-target "127.0.0.1:$WIRE_INGRESS_SAFETY" --rtt-msg "$WIRE_SAFETY_MSG" \
      --rtt-interval-us "$WIRE_SAFETY_INTERVAL_US"
    run_cell "sweep-udp-${rate}" udp safety "$WIRE_DGRAM_MSG" 1 "$rate" "$WIRE_SWEEP_MEASURE_S" \
      --bulk-target "127.0.0.1:$WIRE_INGRESS_DGRAM" --bulk-conns 1 \
      --bulk-msg "$WIRE_DGRAM_MSG" --bulk-rate-mbps "$rate" --bulk-dscp "$WIRE_SAFETY_DSCP"
    rate="$(awk -v r="$rate" -v s="$WIRE_SWEEP_STEP_MBPS" 'BEGIN{print r+s}')"
  done
}

# ── Main ─────────────────────────────────────────────────────────────────────
wire_info "mode=$MODE mid-hop=$MID_HOST out=$OUT_DIR"
mint_pki || exit 1
emit_configs || exit 1
[[ "$MODE" == "wire" ]] && emit_peer_bundle
start_gateways || exit 1
start_local_peer_endpoints
preflight_path_check || exit 1
csv_header

case "$GROUP" in
  all) group_qos; group_rtt; group_throughput; group_dtls; group_sweep ;;
  qos) group_qos ;;
  rtt) group_rtt ;;
  throughput) group_throughput ;;
  dtls) group_dtls ;;
  sweep) group_sweep ;;
  *) wire_err "unknown --group: $GROUP"; exit 2 ;;
esac

wire_info "wrote $CSV"
wire_info "goodput ceiling reference: $(wire_goodput_ceiling_gbps) Gbit/s (1 GbE, 1500 B MTU)"
if [[ "$MODE" == "wire" ]]; then
  wire_info "remember: the QOS-001 evidence is the FAR-SIDE capture, taken on the peer"
fi
