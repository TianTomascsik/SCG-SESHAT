#!/usr/bin/env bash
#
# Peer (host B) side of the two-host wire benchmark. Run this on the machine at
# the far end of the cable, from the `peer-bundle/` directory that
# wire_bench.sh emits, then start wire_bench.sh --mode wire on host A.
#
#   ./wire_peer.sh --local-ip 10.9.0.2 [--dev enp3s0] [--capture]
#
# It brings up the decrypt gateway plus the plaintext sinks it feeds, and stays
# in the foreground until interrupted. There is deliberately no control channel
# and no SSH: adding remote code execution to a security product would be a
# heavy change for zero measurement value, so the operator starts this by hand
# and host A merely probes the listener for readiness.
#
# --capture starts the tcpdump that produces the QOS-001 evidence. That capture
# is the *point* of the whole experiment: it is the only artefact that shows the
# DS field survived a physical interface, which loopback can never demonstrate.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/wire_env.sh
source "$HERE/wire_env.sh"

GATEWAY_BIN="${SCG_GATEWAY_BIN:-$HERE/gateway}"
PROBE="$HERE/wire_probe.py"
CONFIG="$HERE/dec.json"
CAPTURE=0
OUT_DIR="$HERE/peer-out"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local-ip) WIRE_PEER_IP="$2"; shift 2 ;;   # this host's address on the link
    --dev) WIRE_DEV="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --gateway) GATEWAY_BIN="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --capture) CAPTURE=1; shift ;;
    -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) wire_err "unknown argument: $1"; exit 2 ;;
  esac
done

[[ -n "$WIRE_DEV" || $CAPTURE == 0 ]] || { wire_err "--dev (or WIRE_DEV) is required with --capture"; exit 2; }
[[ -x "$GATEWAY_BIN" ]] || { wire_err "gateway binary not found at $GATEWAY_BIN (--gateway PATH)"; exit 2; }
[[ -f "$CONFIG" ]] || { wire_err "decrypt config not found at $CONFIG (--config PATH)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { wire_err "python3 is required"; exit 2; }
mkdir -p "$OUT_DIR"

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
  pkill -f "$PROBE" 2>/dev/null
  wait 2>/dev/null
  wire_info "peer stopped"
}
trap cleanup EXIT INT TERM

# The bundle's dec.json was written on host A and carries host A's cert paths.
# Rewrite them to this machine's layout before anything reads the config:
# otherwise the listeners bind happily and then every handshake dies with
# "failed to read cert_path ... No such file or directory", which looks like a
# TLS fault rather than a file-location one.
RUNTIME_CONFIG="$OUT_DIR/dec.runtime.json"
if ! python3 - "$CONFIG" "$HERE/wire-pki" "$RUNTIME_CONFIG" <<'PY'
import json, os, sys

src, pki, dst = sys.argv[1:4]
with open(src) as fh:
    cfg = json.load(fh)
missing = []
for rule in cfg.get("rules", []):
    for key in ("cert_path", "key_path", "ca_path"):
        if key in rule:
            rule[key] = os.path.join(pki, os.path.basename(rule[key]))
            if not os.path.isfile(rule[key]):
                missing.append(rule[key])
with open(dst, "w") as fh:
    json.dump(cfg, fh, indent=2)
if missing:
    sys.exit("missing certificate material: " + ", ".join(sorted(set(missing))))
PY
then
  wire_err "could not localise the certificate paths — is wire-pki/ next to this script?"
  exit 1
fi
CONFIG="$RUNTIME_CONFIG"
wire_info "certificate paths localised to $HERE/wire-pki"

# The decrypt listener is non-loopback, so the gateway's preflight refuses
# to start it without verify:mutual. Confirm before binding anything.
"$GATEWAY_BIN" --config "$CONFIG" --validate >"$OUT_DIR/validate.log" 2>&1 || {
  wire_err "decrypt config failed validation:"; grep -i error "$OUT_DIR/validate.log" >&2; exit 1; }
wire_info "decrypt config validated (mutual TLS, required off loopback)"

if [[ $CAPTURE == 1 ]]; then
  if command -v tcpdump >/dev/null 2>&1; then
    # -s 96 keeps only headers: the DS field is all we need, and capturing
    # payload would both slow the link and record plaintext-adjacent bytes.
    # All four mid-hop flows, including the nprobe classification control —
    # its whole purpose is to differ from the safety flow only in class, so the
    # evidentiary capture must show its DSCP alongside the other three.
    tcpdump -i "$WIRE_DEV" -s 96 -w "$OUT_DIR/wire.pcap" \
      "tcp port $WIRE_MID_SAFETY or tcp port $WIRE_MID_BULK or udp port $WIRE_MID_DGRAM or tcp port $WIRE_MID_NPROBE" \
      >"$OUT_DIR/tcpdump.log" 2>&1 &
    PIDS+=($!)
    wire_info "capturing on $WIRE_DEV -> $OUT_DIR/wire.pcap"
  else
    wire_err "tcpdump not installed — the QOS-001 evidence cannot be captured"
    exit 2
  fi
fi

"$GATEWAY_BIN" --config "$CONFIG" --log-stdout >"$OUT_DIR/dec.log" 2>&1 &
PIDS+=($!)
wire_wait_tcp "$WIRE_PEER_IP" "$WIRE_MID_BULK" || {
  wire_err "decrypt gateway did not bind $WIRE_PEER_IP:$WIRE_MID_BULK"; tail -20 "$OUT_DIR/dec.log" >&2; exit 1; }

# Plaintext endpoints the gateway relays into. These stay on loopback: the
# decrypted side must never be reachable from the link.
# The sinks live for the whole session, but each cell is separated by an idle
# gap, so --burst-report emits one record per cell in order. That is how
# delivered goodput, loss and the DSCP verdict get attributed per cell without a
# control channel — copy peer-out/ back to host A and merge by burst index.
python3 "$PROBE" sink --proto tcp --bind "127.0.0.1:$WIRE_SINK_BULK" \
  --msg "$WIRE_BULK_MSG" --duration 0 \
  --burst-report "$OUT_DIR/sink-bulk.jsonl" >/dev/null 2>&1 &
PIDS+=($!)
python3 "$PROBE" sink --proto udp --bind "127.0.0.1:$WIRE_SINK_DGRAM" \
  --msg "$WIRE_DGRAM_MSG" --duration 0 --expect-dscp "$WIRE_SAFETY_DSCP" \
  --burst-report "$OUT_DIR/sink-dgram.jsonl" >/dev/null 2>&1 &
PIDS+=($!)
python3 "$PROBE" echo --proto tcp --bind "127.0.0.1:$WIRE_SINK_SAFETY" \
  --msg "$WIRE_SAFETY_MSG" --duration 0 >/dev/null 2>&1 &
PIDS+=($!)
python3 "$PROBE" echo --proto tcp --bind "127.0.0.1:$WIRE_SINK_NPROBE" \
  --msg "$WIRE_SAFETY_MSG" --duration 0 >/dev/null 2>&1 &
PIDS+=($!)

wire_info "peer ready on $WIRE_PEER_IP (mid ports $WIRE_MID_BULK/$WIRE_MID_SAFETY/$WIRE_MID_DGRAM)"
wire_info "now run on host A:  ./wire_bench.sh --mode wire --peer $WIRE_PEER_IP"
wire_info "Ctrl-C to stop"
wait
