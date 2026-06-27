#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

MODE="quick"
PERF=false
SKIP_TESTS=false
SKIP_RUN=false
CONFIG="configs/profile_regression.json"
OUTPUT_DIR="${SCG_PERF_GATE_OUTPUT_DIR:-results/perf-gate}"

usage() {
  cat <<'USAGE'
Usage: scripts/perf_gate.sh [--quick|--strict] [--perf] [--skip-tests] [--skip-run]

Runs the SCG profile-regression gate:
  1. targeted gateway and SESHAT unit tests
  2. configs/profile_regression.json
  3. CSV threshold checks against the same-run direct loopback baseline

Quick thresholds:
  throughput profile >= 95% of direct loopback

Strict thresholds:
  throughput profile >= 98% of direct loopback
  fail throughput rows whose harness_limited flag is true
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) MODE="quick"; shift ;;
    --strict) MODE="strict"; shift ;;
    --perf) PERF=true; shift ;;
    --skip-tests) SKIP_TESTS=true; shift ;;
    --skip-run) SKIP_RUN=true; shift ;;
    --config) CONFIG="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$MODE" != "quick" && "$MODE" != "strict" ]]; then
  echo "invalid mode: $MODE" >&2
  exit 2
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "config not found: $CONFIG" >&2
  exit 2
fi

info() { printf '[perf-gate] %s\n' "$*"; }
fail() { printf '[perf-gate] FAIL: %s\n' "$*" >&2; }

SESHAT_TARGET_DIR="${CARGO_TARGET_DIR:-}"
if [[ -z "$SESHAT_TARGET_DIR" ]]; then
  if [[ -e target && ! -w target ]]; then
    SESHAT_TARGET_DIR="${TMPDIR:-/tmp}/scg-seshat-target-${USER:-codex}"
    info "target/ is not writable; using CARGO_TARGET_DIR=$SESHAT_TARGET_DIR"
  elif [[ ! -e target && ! -w . ]]; then
    SESHAT_TARGET_DIR="${TMPDIR:-/tmp}/scg-seshat-target-${USER:-codex}"
    info "workspace is not writable for target/; using CARGO_TARGET_DIR=$SESHAT_TARGET_DIR"
  fi
fi

if [[ -n "$SESHAT_TARGET_DIR" ]]; then
  mkdir -p "$SESHAT_TARGET_DIR"
  SESHAT_ENV=(env CARGO_TARGET_DIR="$SESHAT_TARGET_DIR")
  SESHAT_BIN="$SESHAT_TARGET_DIR/release/seshat"
else
  SESHAT_ENV=(env)
  SESHAT_BIN="./target/release/seshat"
fi

GATEWAY_TARGET_DIR="${SCG_CARGO_TARGET_DIR:-}"
if [[ -z "$GATEWAY_TARGET_DIR" ]]; then
  if [[ -e ../SCG/target && ! -w ../SCG/target ]]; then
    GATEWAY_TARGET_DIR="${TMPDIR:-/tmp}/scg-gateway-target-${USER:-codex}"
    info "../SCG/target is not writable; using SCG CARGO_TARGET_DIR=$GATEWAY_TARGET_DIR"
  elif [[ -e ../SCG/target ]] && find ../SCG/target -type f ! -writable -print -quit | grep -q .; then
    GATEWAY_TARGET_DIR="${TMPDIR:-/tmp}/scg-gateway-target-${USER:-codex}"
    info "../SCG/target contains unwritable artifacts; using SCG CARGO_TARGET_DIR=$GATEWAY_TARGET_DIR"
  elif [[ ! -e ../SCG/target && ! -w ../SCG ]]; then
    GATEWAY_TARGET_DIR="${TMPDIR:-/tmp}/scg-gateway-target-${USER:-codex}"
    info "../SCG is not writable for target/; using SCG CARGO_TARGET_DIR=$GATEWAY_TARGET_DIR"
  fi
fi

if [[ -n "$GATEWAY_TARGET_DIR" ]]; then
  mkdir -p "$GATEWAY_TARGET_DIR"
  GATEWAY_ENV=(env CARGO_TARGET_DIR="$GATEWAY_TARGET_DIR")
  GATEWAY_BIN="$GATEWAY_TARGET_DIR/release/gateway"
else
  GATEWAY_ENV=(env)
  GATEWAY_BIN="../SCG/target/release/gateway"
fi

if [[ "$OUTPUT_DIR" == results/* || "$OUTPUT_DIR" == "results" ]]; then
  if [[ -e results && ! -w results ]]; then
    OUTPUT_DIR="${TMPDIR:-/tmp}/scg-seshat-perf-gate-${USER:-codex}"
    info "results/ is not writable; using output dir $OUTPUT_DIR"
  fi
fi

if [[ "$PERF" == true ]]; then
  if ! command -v perf >/dev/null 2>&1; then
    fail "--perf requested but perf is not installed"
    exit 2
  fi
  if ! perf stat -x, -e task-clock -- true >/dev/null 2>&1; then
    fail "--perf requested but perf events are not permitted on this host"
    exit 2
  fi
fi

run_seshat_cargo() {
  "${SESHAT_ENV[@]}" cargo "$@"
}

run_gateway_cargo() {
  (cd ../SCG && "${GATEWAY_ENV[@]}" cargo "$@")
}

if [[ "$SKIP_TESTS" == false ]]; then
  info "running targeted gateway tests"
  run_gateway_cargo test -p gateway perf_knobs_tests
  run_gateway_cargo test -p gateway crypto_provider_tests
  run_gateway_cargo test -p gateway resumption
  run_gateway_cargo test -p gateway poll_two_fds_with_spin_observes_ready_fd
  run_gateway_cargo test -p gateway set_notsent_lowat_roundtrip
  # WireGuard provider: unit tests + the unprivileged relay round-trip. The
  # real-interface provisioning test auto-skips when unprivileged.
  run_gateway_cargo test -p gateway wireguard

  info "running targeted SESHAT tests"
  run_seshat_cargo test perf_profile
  run_seshat_cargo test profile_regression_config_validates
  run_seshat_cargo test tls_resumption_flag_is_validated
  run_seshat_cargo test low_level_perf_overrides_serialize_when_set
fi

info "building SESHAT and gateway"
run_seshat_cargo build --release
run_gateway_cargo build --release -p gateway

if [[ ! -x "$GATEWAY_BIN" ]]; then
  fail "gateway binary was not built"
  exit 2
fi
export SCG_GATEWAY_BIN="$GATEWAY_BIN"

info "validating $CONFIG"
"$SESHAT_BIN" validate --config "$CONFIG" >/dev/null

if [[ "$SKIP_RUN" == true ]]; then
  info "skipping benchmark execution (--skip-run)"
  exit 0
fi

RUN_BASE="${OUTPUT_DIR}/${MODE}-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_BASE"

RUN_ARGS=(run --config "$CONFIG" --output-dir "$RUN_BASE")
if [[ "$MODE" == "quick" ]]; then
  RUN_ARGS+=(--duration 2s --warmup 1s --runs 1)
fi
if [[ "$PERF" == true ]]; then
  RUN_ARGS+=(--metrics-backend perf)
fi

info "running profile regression suite ($MODE)"
"$SESHAT_BIN" "${RUN_ARGS[@]}"

RESULT_DIR=""
while IFS= read -r summary_path; do
  candidate="$(dirname "$summary_path")"
  if [[ -f "$candidate/meta.csv" ]]; then
    RESULT_DIR="$candidate"
  fi
done < <(find "$RUN_BASE" -mindepth 2 -maxdepth 2 -type f -name summary.csv 2>/dev/null | sort)

if [[ -z "$RESULT_DIR" ]]; then
  fail "no result directory with summary.csv and meta.csv created under $RUN_BASE"
  exit 1
fi

SUMMARY="$RESULT_DIR/summary.csv"
META="$RESULT_DIR/meta.csv"
if [[ ! -s "$SUMMARY" ]]; then
  fail "empty or missing summary.csv at $SUMMARY"
  exit 1
fi
if [[ ! -s "$META" ]]; then
  fail "empty or missing meta.csv at $META"
  exit 1
fi
if [[ "$(wc -l < "$SUMMARY")" -le 1 ]]; then
  fail "summary.csv has no scenario rows"
  exit 1
fi

meta_value() {
  local key="$1"
  awk -F, -v key="$key" '$1 == key { sub(/\r$/, "", $2); print $2; found = 1; exit } END { if (!found) exit 1 }' "$META"
}

csv_value() {
  local scenario="$1"
  local column="$2"
  awk -F, -v scenario="$scenario" -v column="$column" '
    NR == 1 {
      for (i = 1; i <= NF; i++) {
        sub(/\r$/, "", $i)
        h[$i] = i
      }
      idx = h[column]
      if (!idx) {
        status = 3
        exit
      }
      next
    }
    $1 == scenario {
      v = $idx
      sub(/\r$/, "", v)
      print v
      found = 1
      exit
    }
    END {
      if (status) exit status
      if (!found) exit 4
    }
  ' "$SUMMARY"
}

has_scenario() {
  local scenario="$1"
  awk -F, -v scenario="$scenario" 'NR > 1 && $1 == scenario { found = 1; exit } END { exit(found ? 0 : 1) }' "$SUMMARY"
}

gate_failures=0

record_failure() {
  fail "$*"
  gate_failures=$((gate_failures + 1))
}

require_scenario() {
  local scenario="$1"
  if ! has_scenario "$scenario"; then
    record_failure "required scenario did not execute: $scenario"
  fi
}

require_value() {
  local __var="$1"
  local scenario="$2"
  local column="$3"
  local value
  if ! value="$(csv_value "$scenario" "$column")" || [[ -z "$value" ]]; then
    record_failure "missing $column for $scenario"
    printf -v "$__var" '%s' ""
    return 1
  fi
  printf -v "$__var" '%s' "$value"
}

float_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit !((a + 0) >= (b + 0)) }'
}

float_le() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit !((a + 0) <= (b + 0)) }'
}

mul() {
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%.9f", (a + 0) * (b + 0) }'
}

add() {
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%.9f", (a + 0) + (b + 0) }'
}

if ! awk -F, '
  NR == 1 {
    for (i = 1; i <= NF; i++) h[$i] = i
    next
  }
  $1 ~ /^profile_/ && $(h["transport"]) == "tcp" {
    loss = $(h["loss_pct"]) + 0
    lost = $(h["total_lost"]) + 0
    if (loss != 0 || lost != 0) {
      printf "%s loss_pct=%s total_lost=%s\n", $1, $(h["loss_pct"]), $(h["total_lost"]) > "/dev/stderr"
      bad = 1
    }
  }
  END { exit(bad ? 1 : 0) }
' "$SUMMARY"; then
  record_failure "TCP profile scenarios reported packet loss"
fi

for scenario in \
  profile_direct_throughput_1KB \
  profile_direct_latency_1KB \
  profile_direct_pingpong_1KB; do
  require_scenario "$scenario"
done

require_value direct_throughput profile_direct_throughput_1KB throughput_gbps_mean || true
require_value direct_latency_p99 profile_direct_latency_1KB latency_p99_us_mean || true
require_value direct_rtt_p99 profile_direct_pingpong_1KB rtt_us_p99 || true
if [[ -n "${direct_rtt_p99:-}" ]] && ! float_ge "$direct_rtt_p99" 0.001; then
  record_failure "direct pingpong rtt_us_p99 is not positive"
fi

throughput_ratio="0.95"
if [[ "$MODE" == "strict" ]]; then
  throughput_ratio="0.98"
fi

validate_profile_group() {
  local prefix="$1"
  local direct_thr="$2"
  local direct_p99="$3"

  for profile in latency balanced throughput; do
    require_scenario "${prefix}_${profile}_throughput_1KB"
    require_scenario "${prefix}_${profile}_latency_1KB"
    require_scenario "${prefix}_${profile}_pingpong_1KB"
  done

  local thr_profile thr_balanced latency_p99 balanced_p99 pingpong_p99 threshold
  require_value thr_profile "${prefix}_throughput_throughput_1KB" throughput_gbps_mean || return
  require_value thr_balanced "${prefix}_balanced_throughput_1KB" throughput_gbps_mean || return
  require_value latency_p99 "${prefix}_latency_latency_1KB" latency_p99_us_mean || return
  require_value balanced_p99 "${prefix}_balanced_latency_1KB" latency_p99_us_mean || return

  threshold="$(mul "$direct_thr" "$throughput_ratio")"
  if ! float_ge "$thr_profile" "$threshold"; then
    record_failure "${prefix}: throughput profile ${thr_profile} Gbit/s < ${throughput_ratio}x direct loopback (${threshold} Gbit/s)"
  fi

  threshold="$(mul "$thr_profile" "0.95")"
  if ! float_ge "$thr_balanced" "$threshold"; then
    record_failure "${prefix}: balanced throughput ${thr_balanced} Gbit/s < 95% of throughput profile (${threshold} Gbit/s)"
  fi

  threshold="$(add "$direct_p99" "1000")"
  if ! float_le "$latency_p99" "$threshold"; then
    record_failure "${prefix}: latency profile p99 ${latency_p99} us > direct p99 + 1 ms (${threshold} us)"
  fi

  threshold="$(add "$latency_p99" "2000")"
  if ! float_le "$balanced_p99" "$threshold"; then
    record_failure "${prefix}: balanced p99 ${balanced_p99} us > latency p99 + 2 ms (${threshold} us)"
  fi

  for profile in latency balanced throughput; do
    require_value pingpong_p99 "${prefix}_${profile}_pingpong_1KB" rtt_us_p99 || return
    if ! float_ge "$pingpong_p99" 0.001; then
      record_failure "${prefix}_${profile}_pingpong_1KB: rtt_us_p99 is not positive"
    fi
  done
}

if [[ -n "${direct_throughput:-}" && -n "${direct_latency_p99:-}" ]]; then
  validate_profile_group "profile_routing" "$direct_throughput" "$direct_latency_p99"
  validate_profile_group "profile_tls13" "$direct_throughput" "$direct_latency_p99"

  ktls_usable="$(meta_value ktls_usable || true)"
  if [[ "$ktls_usable" == "true" ]]; then
    validate_profile_group "profile_ktls13" "$direct_throughput" "$direct_latency_p99"
  elif has_scenario "profile_ktls13_throughput_throughput_1KB"; then
    validate_profile_group "profile_ktls13" "$direct_throughput" "$direct_latency_p99"
  else
    info "kTLS unavailable; kTLS profile rows skipped by host requirements"
  fi
fi

if [[ "$MODE" == "strict" ]]; then
  if ! awk -F, '
    NR == 1 {
      for (i = 1; i <= NF; i++) h[$i] = i
      next
    }
    $1 ~ /^profile_.*_throughput_1KB$/ && $(h["harness_limited"]) == "true" {
      print $1 > "/dev/stderr"
      bad = 1
    }
    END { exit(bad ? 1 : 0) }
  ' "$SUMMARY"; then
    record_failure "strict mode does not allow harness_limited=true on throughput rows"
  fi
fi

if [[ "$PERF" == true ]]; then
  metrics_backend="$(meta_value metrics_backend || true)"
  if [[ "$metrics_backend" != "perf" ]]; then
    record_failure "--perf requested but meta.csv reports metrics_backend=$metrics_backend"
  fi
  if ! awk -F, '
    NR == 1 {
      for (i = 1; i <= NF; i++) h[$i] = i
      next
    }
    NR > 1 && $(h["perf_task_clock_ms"]) != "" {
      found = 1
      exit
    }
    END { exit(found ? 0 : 1) }
  ' "$SUMMARY"; then
    record_failure "--perf requested but no perf_task_clock_ms values were recorded"
  fi
fi

# --- WireGuard kernel data-path gate (privileged; auto-skips otherwise) ---
# Kernel WireGuard needs CAP_NET_ADMIN, the wireguard module, and a peer netns,
# so this section only runs when those prerequisites are present. It stands up a
# real kernel WireGuard tunnel (scripts/wg_setup.sh) and drives plaintext UDP
# through the SCG WireGuard provider, gating on packet loss (scripts/wg_smoke.sh).
WG_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/wg_env.sh
source "$WG_DIR/wg_env.sh"
if wg_prereqs_ok; then
  info "running WireGuard kernel data-path benchmark"
  # wg_bench.sh provisions the tunnel itself and measures via the UDP probe
  # (SESHAT's sender/receiver are TCP-only and cannot drive a UDP path).
  if GATEWAY_BIN="$GATEWAY_BIN" "$WG_DIR/wg_bench.sh"; then
    info "WireGuard data-path benchmark passed (throughput/latency printed above)"
  else
    record_failure "WireGuard kernel data-path benchmark failed"
  fi
  "$WG_DIR/wg_teardown.sh" >/dev/null 2>&1 || true
else
  info "[SKIPPED] WireGuard benchmark — needs $(wg_prereqs_reason); see scripts/wg_setup.sh"
fi

if [[ "$gate_failures" -ne 0 ]]; then
  fail "$gate_failures gate check(s) failed; result dir: $RESULT_DIR"
  exit 1
fi

info "profile regression gate passed; result dir: $RESULT_DIR"
