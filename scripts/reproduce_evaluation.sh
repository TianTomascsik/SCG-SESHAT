#!/usr/bin/env bash
# reproduce_evaluation.sh — run every benchmark the published SCG evaluation
# cites, and only those, then render the figure set from the fresh data.
#
# Evidence map (what each stage backs — figure IDs per the seshat-viz index):
#   main    → F2/F3/F7/F11/F15/F16/F19 (matrix), F8 (saturation), F18 (hot
#             reload), F23 + the handshake/connrate numbers — procfs backend
#   perf    → hardware counters (cycles, cache misses) for the F9 efficiency
#             panels
#   ebpf    → copies/msg + splice syscalls (kTLS zero-copy proof), F9 panel [root]
#   qos     → F24 priority isolation; run under sudo so the gateway gets
#             CAP_SYS_NICE and the reserved safety workers can raise priority [root]
#   wg      → WireGuard throughput/latency via the netns script harness      [root]
#   queue   → the priority-queue study (../mpsc_priority_bench → caption.txt)
#   relay   → relay-backend A/B (io_uring) — needs the experiment/io-uring-relay
#             branch checked out in SCG and SCG-SESHAT
#   figures → print-variant renders via ../seshat-viz
#
# Not covered here (separate, two-host / special campaigns — see REPRODUCING.md):
#   the wire campaign (scripts/wire_bench.sh) and the kernel-scope perf ladder
#   that feeds F26–F28 and F30.
#
# Usage:  sudo scripts/reproduce_evaluation.sh [options]
#   --quick             smoke run (suite --quick: 1 run, 2s duration) to validate the pipeline
#   --full-perf         run the perf pass over the whole config set (default: canonical tier)
#   --skip-main --skip-perf --skip-ebpf --skip-qos --skip-wg --skip-queue --skip-relay
#   --skip-figures      skip rendering (e.g. when only collecting data)
#   --main-run <dir>    reuse an existing main-campaign INNER run dir (skips main)
#   --qos-run <dir>     reuse an existing qos INNER run dir
#
# Environment overrides: SCG_DIR, SCG_GATEWAY_BIN, QUEUE_DIR, VIZ_DIR, OUT_ROOT.
set -uo pipefail

SESHAT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCG="${SCG_DIR:-$SESHAT/../SCG}"
QUEUE="${QUEUE_DIR:-$SESHAT/../mpsc_priority_bench}"
VIZ="${VIZ_DIR:-$SESHAT/../seshat-viz}"
OUT_ROOT="${OUT_ROOT:-$SESHAT/results}"

# ── Args ────────────────────────────────────────────────────────────────────
QUICK=0; FULL_PERF=0
SKIP_MAIN=0; SKIP_PERF=0; SKIP_EBPF=0; SKIP_QOS=0; SKIP_WG=0; SKIP_QUEUE=0
SKIP_RELAY=0; SKIP_FIGS=0
MAIN_INNER=""; QOS_INNER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) QUICK=1 ;;
    --full-perf) FULL_PERF=1 ;;
    --skip-main) SKIP_MAIN=1 ;;
    --skip-perf) SKIP_PERF=1 ;;
    --skip-ebpf) SKIP_EBPF=1 ;;
    --skip-qos) SKIP_QOS=1 ;;
    --skip-wg) SKIP_WG=1 ;;
    --skip-queue) SKIP_QUEUE=1 ;;
    --skip-relay) SKIP_RELAY=1 ;;
    --skip-figures) SKIP_FIGS=1 ;;
    --main-run) MAIN_INNER="$2"; SKIP_MAIN=1; shift ;;
    --qos-run) QOS_INNER="$2"; SKIP_QOS=1; shift ;;
    -h|--help) sed -n '2,31p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

# Canonicalise caller-supplied run dirs: later stages cd into sibling repos,
# so a relative --main-run/--qos-run would stop resolving.
[[ -n "$MAIN_INNER" ]] && MAIN_INNER="$(cd "$MAIN_INNER" && pwd)"
[[ -n "$QOS_INNER" ]] && QOS_INNER="$(cd "$QOS_INNER" && pwd)"

TS="$(date +%Y%m%d-%H%M%S)"
MAIN="$OUT_ROOT/$TS-eval-procfs"
PERF="$OUT_ROOT/$TS-eval-perf"
EBPF="$OUT_ROOT/$TS-eval-ebpf"
QOS="$OUT_ROOT/$TS-eval-qos"
WG_OUT="$OUT_ROOT/wireguard-$TS"

QUICKFLAG=""; [[ "$QUICK" == "1" ]] && QUICKFLAG="--quick"
echo "== reproduce_evaluation $TS (quick=$QUICK full-perf=$FULL_PERF) =="
if [[ "$SKIP_QOS$SKIP_WG$SKIP_EBPF" != "111" && "$(id -u)" != "0" ]]; then
  echo "NOTE: not running as root — the qos (CAP_SYS_NICE), wireguard (netns), and ebpf"
  echo "      stages need sudo. Re-run under sudo or pass --skip-qos --skip-wg --skip-ebpf."
fi

# ── 1. Build gateway + harness (the harness never builds the gateway itself) ─
[[ -d "$SCG" ]] || { echo "FATAL: SCG checkout not found at $SCG (set SCG_DIR)"; exit 1; }
( cd "$SCG" && cargo build --release ) || { echo "FATAL: SCG build failed"; exit 1; }
( cd "$SESHAT" && cargo build --release --bin seshat ) || { echo "FATAL: SESHAT build failed"; exit 1; }
export SCG_GATEWAY_BIN="${SCG_GATEWAY_BIN:-$SCG/target/release/gateway}"
command -v openssl >/dev/null || { echo "FATAL: openssl CLI missing (test certs)"; exit 1; }
cd "$SESHAT"

# The evaluation config set: full_matrix plus the dedicated suites the figures
# and the published numbers read. Order is cheap-first.
EVAL_CONFIGS=(
  configs/latency.json                    # paced-load latency (lat_*)
  configs/pingpong.json                   # closed-loop RTT fallback (pp_*)
  configs/connrate.json                   # connection-establishment + handshake-vs-accept
  configs/saturation.json                 # F8 overload knees (sat_* → saturation.csv)
  configs/hotreload_matrix.json           # F18 reload ledger (hotreload_*)
  configs/datagram_encrypted_paced.json   # paced encrypted datagram path
  configs/full_matrix.json                # the exhaustive generated matrix
)
CFGFLAGS=(); for c in "${EVAL_CONFIGS[@]}"; do CFGFLAGS+=(--config "$c"); done

# ── 2. Main campaign — procfs backend (headline numbers, no sampling overhead) ─
if [[ "$SKIP_MAIN" == "0" ]]; then
  ./target/release/seshat suite "${CFGFLAGS[@]}" $QUICKFLAG --output-dir "$MAIN" \
    || echo "WARN: main suite exited non-zero (partial data may still be usable)"
fi
[[ -z "$MAIN_INNER" ]] && MAIN_INNER=$(find "$MAIN" -maxdepth 1 -mindepth 1 -type d -name '2*' 2>/dev/null | sort | tail -1)

# ── 3. Perf pass — hardware counters (cycles/byte, cache misses; F9) ────────
if [[ "$SKIP_PERF" == "0" ]]; then
  if [[ "$FULL_PERF" == "1" ]]; then
    ./target/release/seshat suite "${CFGFLAGS[@]}" $QUICKFLAG --metrics-backend perf --output-dir "$PERF" \
      || echo "WARN: perf suite exited non-zero"
  else
    ./target/release/seshat suite --tier canonical $QUICKFLAG --metrics-backend perf --output-dir "$PERF" \
      || echo "WARN: perf suite exited non-zero"
  fi
fi
PERF_INNER=$(find "$PERF" -maxdepth 1 -mindepth 1 -type d -name '2*' 2>/dev/null | sort | tail -1)

# ── 4. eBPF cell — copies/msg + splice syscalls at the matched TCP 16KB cell ─
if [[ "$SKIP_EBPF" == "0" ]]; then
  EBPF_CFG="$OUT_ROOT/ebpf-copies-$TS.json"
  python3 - "$SESHAT/configs/full_matrix.json" "$EBPF_CFG" <<'PYEOF'
import json, sys
full = json.load(open(sys.argv[1]))
def keep(s):
    return (s.get("name", "").startswith("matrix_")
            and s.get("sender", {}).get("interface") == "tcp"
            and s.get("message_size_bytes") == 16384
            and s.get("connections") == 1
            and s.get("gateway", {}).get("chain") == "scg-direct")
picked = [s for s in full["scenarios"] if keep(s)]
json.dump({"suite": {**full.get("suite", {}),
                     "description": "eBPF copy-avoidance (TCP crypto ladder @16KB, 1-gw, 1c)"},
           "defaults": full["defaults"], "scenarios": picked},
          open(sys.argv[2], "w"), indent=2)
print(f"eBPF copy-avoidance config: {len(picked)} scenarios -> {sys.argv[2]}")
PYEOF
  ./target/release/seshat suite --config "$EBPF_CFG" $QUICKFLAG --metrics-backend ebpf --output-dir "$EBPF" \
    || echo "WARN: ebpf suite exited non-zero (bpftrace/root missing? F9 copy panel degrades gracefully)"
fi
EBPF_INNER=$(find "$EBPF" -maxdepth 1 -mindepth 1 -type d -name '2*' 2>/dev/null | sort | tail -1)

# ── 5. QoS isolation (F24) — under sudo the gateway gets CAP_SYS_NICE, so the
#      reserved safety workers CAN raise their scheduling priority. ─────────
if [[ "$SKIP_QOS" == "0" ]]; then
  ./target/release/seshat suite --config configs/qos_isolation.json $QUICKFLAG --output-dir "$QOS" \
    || echo "WARN: qos suite exited non-zero"
fi
[[ -z "$QOS_INNER" ]] && QOS_INNER=$(find "$QOS" -maxdepth 1 -mindepth 1 -type d -name '2*' 2>/dev/null | sort | tail -1)

# ── 6. WireGuard — privileged netns script harness; persist the output ──────
if [[ "$SKIP_WG" == "0" ]]; then
  mkdir -p "$WG_OUT"
  if scripts/wg_setup.sh >"$WG_OUT/wg_setup.log" 2>&1; then
    scripts/wg_bench.sh 2>&1 | tee "$WG_OUT/wg_bench.txt" \
      || echo "WARN: wg_bench failed (see $WG_OUT/wg_bench.txt)"
  else
    echo "WARN: wg_setup failed (module/netns?); skipping WireGuard (see $WG_OUT/wg_setup.log)"
  fi
  scripts/wg_teardown.sh >>"$WG_OUT/wg_setup.log" 2>&1 || true
fi

# ── 7. Queue study — Criterion bench → records.csv → caption.txt ────────────
if [[ "$SKIP_QUEUE" == "0" ]]; then
  if [[ -d "$QUEUE" ]]; then
    ( cd "$QUEUE" \
      && cargo bench --bench mpsc_priority \
      && python3 criterion_insights.py \
      && python3 criterion_caption.py ) \
      || echo "WARN: queue study failed (stale analysis_out/ persists)"
  else
    echo "SKIP: queue study — mpsc_priority_bench not found at $QUEUE (set QUEUE_DIR)"
  fi
fi

# ── 8. Relay-backend A/B (io_uring) — branch-gated apparatus ────────────────
if [[ "$SKIP_RELAY" == "0" ]]; then
  if [[ -f "$SESHAT/configs/relay_backend_ab.json" && -x "$SESHAT/scripts/run_relay_backend_ab.sh" ]]; then
    "$SESHAT/scripts/run_relay_backend_ab.sh" \
      || echo "WARN: relay A/B failed"
  else
    echo "SKIP: relay A/B apparatus not in this checkout — check out the"
    echo "      'experiment/io-uring-relay' branch in BOTH SCG and SCG-SESHAT"
    echo "      (see REPRODUCING.md); committed results/relay-backend-ab-*/ stand."
  fi
fi

# ── 9. Figures — print-variant renders via ../seshat-viz ────────────────────
if [[ "$SKIP_FIGS" == "0" ]]; then
  if [[ -d "$VIZ" ]]; then
    PY="$VIZ/.venv/bin/python"; [[ -x "$PY" ]] || PY=python3
    if [[ -n "$MAIN_INNER" && -d "$MAIN_INNER" ]]; then
      ( cd "$VIZ" && "$PY" -m seshat_viz "$MAIN_INNER" --variant print --no-chrome \
          --out figures-print --format pdf,png ) \
        || echo "WARN: main figure render failed"
      # F9 efficiency panels from the perf pass, then the eBPF copy panel, in order.
      for RUN in "$PERF_INNER" "$EBPF_INNER"; do
        [[ -n "$RUN" && -d "$RUN" ]] || continue
        ( cd "$VIZ" && "$PY" -m seshat_viz "$RUN" --variant print --no-chrome --only F9 \
            --out figures-print --format pdf,png ) \
          || echo "WARN: F9 re-render from $RUN failed"
      done
    else
      echo "WARN: no main run dir — skipped main figures (pass --main-run <inner dir>)"
    fi
    if [[ -n "$QOS_INNER" && -d "$QOS_INNER" ]]; then
      ( cd "$VIZ" && "$PY" -m seshat_viz "$QOS_INNER" --variant print --no-chrome --only F24 \
          --out figures-print --format pdf,png ) \
        || echo "WARN: F24 render failed"
    else
      echo "WARN: no qos run dir — F24 not refreshed"
    fi
    echo "NOTE: for the staged multi-campaign print export (incl. F26–F28 wire and"
    echo "      F30 perf-ladder inputs) see $VIZ/scripts/export_print_figures.sh."
  else
    echo "SKIP: figures — seshat-viz not found at $VIZ (set VIZ_DIR)"
  fi
fi

# ── 10. chown-back (sudo runs must be side-effect-free for later user builds) ─
if [[ -n "${SUDO_USER:-}" ]]; then
  chown -R "$SUDO_USER:$(id -gn "$SUDO_USER")" \
    "$SESHAT/target" "$OUT_ROOT" "$SCG/target" \
    "$QUEUE/target" "$QUEUE/analysis_out" "$VIZ/figures-print" 2>/dev/null \
    || echo "WARN: chown-back failed; some trees may stay root-owned"
fi

echo "== done $TS =="
echo "main (procfs):   ${MAIN_INNER:-<none>}"
echo "perf counters:   ${PERF_INNER:-<none>}"
echo "ebpf cell:       ${EBPF_INNER:-<none>}"
echo "qos (F24):       ${QOS_INNER:-<none>}"
[[ "$SKIP_WG" == "0" ]] && echo "wireguard:       $WG_OUT/wg_bench.txt" || echo "wireguard:       <skipped>"
echo "figures:         $VIZ/figures-print (captions.txt = the citation source)"
