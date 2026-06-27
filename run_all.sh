#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SESHAT — Full Benchmark Execution & Performance Consolidation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Usage:
#   ./run_all.sh                        # Run everything (release build)
#   ./run_all.sh --debug                # Debug build (slower, assertions on)
#   ./run_all.sh --output-dir ./my_run  # Custom output directory
#   ./run_all.sh --quick                # Shortened runs (2s measure, 1 run)
#   ./run_all.sh --scenario-filter tcp  # Only run suite files with 'tcp' in name
#   ./run_all.sh --skip-build           # Skip cargo build
#   ./run_all.sh --perf                 # Enable perf stat collection
#   ./run_all.sh --nightly              # Run the exhaustive generated matrix
#   ./run_all.sh --safety-tests         # Run safety-isolation checks only
#
# This script:
#  1. Builds SESHAT (release) and the SCG gateway
#  2. Dumps system info for reproducibility
#  3. Runs the non-overlapping canonical suites (feature matrix, profile gate,
#     latency, saturation, RTT, connrate)
#  4. Consolidates all results into a performance overview
#  5. Generates a human-readable summary report
#
set -euo pipefail
cd "$(dirname "$0")"

# ─── Configuration ───────────────────────────────────────────────────────────
PROFILE="release"
OUTPUT_DIR="results"
EXTRA_ARGS=()
QUICK=false
SKIP_BUILD=false
FILTER=""
PERF=false
SAFETY_TESTS=false
TIER="canonical"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)          PROFILE="debug"; shift ;;
    --output-dir)     OUTPUT_DIR="$2"; shift 2 ;;
    --quick)          QUICK=true; shift ;;
    --skip-build)     SKIP_BUILD=true; shift ;;
    --scenario-filter) FILTER="$2"; shift 2 ;;
    --perf)           PERF=true; shift ;;
    --nightly)        TIER="nightly"; shift ;;
    --safety-tests|--isolation-tests)
                      SAFETY_TESTS=true; shift ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | grep '^#' | cut -c3-
      exit 0 ;;
    *)                EXTRA_ARGS+=("$1"); shift ;;
  esac
done

RUN_DIR="${OUTPUT_DIR}/${TIMESTAMP}"
# Environment overrides make it possible to validate an alternate build without
# copying it into the default Cargo target directory.
BIN="${SESHAT_BIN:-./target/${PROFILE}/seshat}"
GW_BIN="${SCG_GATEWAY_BIN:-../SCG/target/${PROFILE}/gateway}"

# Quick mode overrides: 2s measure, 1s warmup, 1 run
if [[ "$QUICK" == true ]]; then
  EXTRA_ARGS+=(--duration 2s --warmup 1s --runs 1)
fi

# Perf backend
if [[ "$PERF" == true && "$SAFETY_TESTS" == false ]]; then
  if ! command -v perf >/dev/null 2>&1; then
    echo "--perf requires the 'perf' executable (install linux-tools/perf first)" >&2
    exit 2
  fi
  if ! perf stat -x, -e task-clock -- true >/dev/null 2>&1; then
    echo "--perf requires permission to collect perf events; check perf_event_paranoid/capabilities" >&2
    exit 2
  fi
  EXTRA_ARGS+=(--metrics-backend perf)
elif [[ "$PERF" == true ]]; then
  echo "--perf is ignored in --safety-tests mode (no benchmark/perf run is executed)" >&2
fi

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}▶${NC} $*"; }
ok()    { echo -e "${GREEN}✔${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
fail()  { echo -e "${RED}✖${NC} $*"; }

# Section rules matching the Rust binary's style (72 chars)
rule()  {
  local title="$*"
  local prefix="═══ ${title} "
  local len=${#prefix}
  local fill=$((72 - len))
  (( fill < 0 )) && fill=0
  local line="${prefix}$(printf '═%.0s' $(seq 1 $fill))"
  echo -e "\n${BOLD}${line}${NC}"
}
subrule() {
  local title="$*"
  local prefix=" ── ${title} "
  local len=${#prefix}
  local fill=$((72 - len))
  (( fill < 0 )) && fill=0
  echo -e "${DIM}${prefix}$(printf '─%.0s' $(seq 1 $fill))${NC}"
}

configure_test_targets() {
  SESHAT_TEST_ENV=(env)
  if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    SESHAT_TEST_ENV=(env CARGO_TARGET_DIR="$CARGO_TARGET_DIR")
  elif [[ -e target && ! -w target ]]; then
    local seshat_target="${TMPDIR:-/tmp}/scg-seshat-target-${USER:-codex}"
    mkdir -p "$seshat_target"
    SESHAT_TEST_ENV=(env CARGO_TARGET_DIR="$seshat_target")
    info "target/ is not writable; using CARGO_TARGET_DIR=$seshat_target"
  elif [[ ! -e target && ! -w . ]]; then
    local seshat_target="${TMPDIR:-/tmp}/scg-seshat-target-${USER:-codex}"
    mkdir -p "$seshat_target"
    SESHAT_TEST_ENV=(env CARGO_TARGET_DIR="$seshat_target")
    info "workspace is not writable for target/; using CARGO_TARGET_DIR=$seshat_target"
  fi

  GATEWAY_TEST_ENV=(env)
  if [[ -n "${SCG_CARGO_TARGET_DIR:-}" ]]; then
    GATEWAY_TEST_ENV=(env CARGO_TARGET_DIR="$SCG_CARGO_TARGET_DIR")
  elif [[ -e ../SCG/target && ! -w ../SCG/target ]]; then
    local gateway_target="${TMPDIR:-/tmp}/scg-gateway-target-${USER:-codex}"
    mkdir -p "$gateway_target"
    GATEWAY_TEST_ENV=(env CARGO_TARGET_DIR="$gateway_target")
    info "../SCG/target is not writable; using SCG CARGO_TARGET_DIR=$gateway_target"
  elif [[ ! -e ../SCG/target && ! -w ../SCG ]]; then
    local gateway_target="${TMPDIR:-/tmp}/scg-gateway-target-${USER:-codex}"
    mkdir -p "$gateway_target"
    GATEWAY_TEST_ENV=(env CARGO_TARGET_DIR="$gateway_target")
    info "../SCG is not writable for target/; using SCG CARGO_TARGET_DIR=$gateway_target"
  fi
}

run_seshat_cargo() {
  "${SESHAT_TEST_ENV[@]}" cargo "$@"
}

run_gateway_cargo() {
  (cd ../SCG && "${GATEWAY_TEST_ENV[@]}" cargo "$@")
}

run_safety_tests() {
  rule "SAFETY ISOLATION TESTS"
  configure_test_targets

  info "Running SCG connection-pool isolation tests..."
  run_gateway_cargo test -p gateway conn_pool

  info "Running SCG endpoint class-key tests..."
  run_gateway_cargo test -p gateway template_and_owner_keys_are_distinct

  info "Running SCG QoS and Safety scheduling tests..."
  run_gateway_cargo test -p gateway safety_defaults_to_ef_and_priority
  run_gateway_cargo test -p gateway normal_defaults_to_none_and_zero_priority
  run_gateway_cargo test -p gateway safety_priority_never_deprioritizes_and_normal_is_noop

  info "Running SESHAT UDS/SHM class-provisioning tests..."
  run_seshat_cargo test rules_are_created_per_traffic_class
  run_seshat_cargo test class_labels_accept_legacy_safety_names

  if [[ -x ../SCG/scripts/scg-host-qos.sh ]]; then
    info "Validating host QoS helper syntax and dry-run commands..."
    bash -n ../SCG/scripts/scg-host-qos.sh
    ../SCG/scripts/scg-host-qos.sh apply --dev eth0 --normal-rate 800mbit --dry-run >/dev/null
  else
    warn "SCG host QoS helper not found; skipping shell dry-run"
  fi

  ok "Safety isolation tests completed"
}

if [[ "$SAFETY_TESTS" == true ]]; then
  run_safety_tests
  exit 0
fi

# ─── Box-Drawing Table Helpers ───────────────────────────────────────────────
# Usage: draw_border "top"|"mid"|"bot" width1 width2 ...
draw_border() {
  local style="$1"; shift
  local corners
  case "$style" in
    top) corners="┌ ┬ ┐" ;;
    mid) corners="├ ┼ ┤" ;;
    bot) corners="└ ┴ ┘" ;;
  esac
  local left="${corners%% *}"
  local rest="${corners#* }"
  local mid="${rest%% *}"
  local right="${rest##* }"
  local out="${left}"
  local first=true
  for w in "$@"; do
    if [[ "$first" != true ]]; then
      out+="${mid}"
    fi
    first=false
    out+="$(printf '─%.0s' $(seq 1 $((w + 2))))"
  done
  out+="${right}"
  echo "$out"
}

# Usage: draw_row "l|r" width1 width2 ... -- val1 val2 ...
# Alignments: string of l/r per column (e.g. "lrrr")
draw_row() {
  local aligns="$1"; shift
  local widths=()
  while [[ "$1" != "--" ]]; do
    widths+=("$1"); shift
  done
  shift # consume --
  local out="│"
  local i=0
  for val in "$@"; do
    local w="${widths[$i]}"
    local a="${aligns:$i:1}"
    if [[ "$a" == "r" ]]; then
      out+="$(printf ' %*s │' "$w" "$val")"
    else
      out+="$(printf ' %-*s │' "$w" "$val")"
    fi
    i=$((i + 1))
  done
  echo "$out"
}

# ─── Step 1: Build ───────────────────────────────────────────────────────────
rule "BUILD"

if [[ "$SKIP_BUILD" == false ]]; then
  info "Building SESHAT (${PROFILE})..."
  cargo build --profile "${PROFILE/#release/release}" --quiet 2>&1
  ok "SESHAT binary: ${BIN}"

  if [[ -d "../SCG/gateway" ]]; then
    info "Building SCG gateway (${PROFILE})..."
    (cd ../SCG && cargo build --profile "${PROFILE/#release/release}" -p gateway --quiet 2>&1) || true
    if [[ -x "$GW_BIN" ]]; then
      ok "Gateway binary: ${GW_BIN}"
    else
      warn "Gateway binary not found — SCG scenarios will be skipped"
    fi
  fi
else
  info "Skipping build (--skip-build)"
fi

if [[ ! -x "$BIN" ]]; then
  fail "SESHAT binary not found at ${BIN}"
  exit 1
fi

# ─── Step 2: System Info ─────────────────────────────────────────────────────
rule "SYSTEM INFO"
mkdir -p "${RUN_DIR}"
"$BIN" sysinfo --format json > "${RUN_DIR}/sysinfo.json" 2>/dev/null || true
"$BIN" sysinfo 2>/dev/null || true

# ─── Step 3: Run Benchmarks ──────────────────────────────────────────────────
rule "BENCHMARK EXECUTION"

# Generated suites are the source of canonical coverage.  The default tier is
# intentionally compact; `--nightly` exercises every compatible generated
# protocol/payload/connection combination.
declare -A CONFIG_DESC
if [[ "$TIER" == "nightly" ]]; then
  CONFIGS=(
    configs/full_matrix.json
    configs/interface_comparison.json
    configs/hotreload_matrix.json
    configs/profile_regression.json
    configs/latency.json
    configs/saturation.json
    configs/pingpong.json
    configs/connrate.json
  )
  CONFIG_DESC=(
    [configs/full_matrix.json]="Exhaustive generated protocol, payload, topology, and scalability matrix"
    [configs/interface_comparison.json]="Matched loopback, SCG TCP, TPROXY, UDS, and SHM comparison"
    [configs/hotreload_matrix.json]="Generated compatible hot-reload matrix"
    [configs/profile_regression.json]="SCG latency, balanced, and throughput profile regression gate"
    [configs/latency.json]="Paced sub-saturation one-way latency"
    [configs/saturation.json]="Offered-load sweep (find loss-free ceiling)"
    [configs/pingpong.json]="Closed-loop round-trip time"
    [configs/connrate.json]="Connection establishment rate"
  )
else
  CONFIGS=(
    configs/canonical_matrix.json
    configs/interface_comparison.json
    configs/profile_regression.json
    configs/latency.json
    configs/saturation.json
    configs/pingpong.json
    configs/connrate.json
  )
  CONFIG_DESC=(
    [configs/canonical_matrix.json]="Generated compact protocol and transport matrix"
    [configs/interface_comparison.json]="Matched loopback, SCG TCP, TPROXY, UDS, and SHM comparison"
    [configs/profile_regression.json]="SCG latency, balanced, and throughput profile regression gate"
    [configs/latency.json]="Paced sub-saturation one-way latency"
    [configs/saturation.json]="Offered-load sweep (find loss-free ceiling)"
    [configs/pingpong.json]="Closed-loop round-trip time"
    [configs/connrate.json]="Connection establishment rate"
  )
fi

# Fail before touching the machine if future config edits accidentally schedule
# the same benchmark shape twice. Target addresses are deliberately ignored:
# they only prevent port collisions and do not change the measured path.
if command -v jq >/dev/null 2>&1; then
  duplicate_scenarios="$(jq -s -r '
    [ .[] | .scenarios[]
      | select(.enabled != false)
      | { name,
          shape: (
            del(.name, .disabled_reason, .sender.target_addr)
            | if .streams then .streams |= map(del(.target_addr)) else . end
          )
        }
    ]
    | sort_by(.shape | tojson)
    | group_by(.shape | tojson)[]
    | select(length > 1)
    | map(.name) | join(", ")
  ' "${CONFIGS[@]}")"
  if [[ -n "$duplicate_scenarios" ]]; then
    fail "duplicate benchmark shape(s) in execution plan: ${duplicate_scenarios}"
    exit 2
  fi
else
  warn "jq unavailable — cannot verify duplicate scenario shapes before running"
fi

PASSED=0
FAILED=0
SKIPPED=0
SCENARIOS_EXECUTED=0
SCENARIOS_SKIPPED=0
PERF_INCOMPLETE=false
RESULT_DIRS=()
declare -A TIMING

total=${#CONFIGS[@]}
idx=0

for cfg in "${CONFIGS[@]}"; do
  idx=$((idx + 1))
  name="$(basename "$cfg" .json)"

  # Apply filter if set
  if [[ -n "$FILTER" && "$name" != *"$FILTER"* ]]; then
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  if [[ ! -f "$cfg" ]]; then
    warn "[${idx}/${total}] ${name}: config not found, skipping"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  desc="${CONFIG_DESC[$cfg]:-}"
  echo ""
  echo -e "${BOLD}[${idx}/${total}]${NC} ${name} ${DIM}— ${desc}${NC}"
  subrule "${name}"

  start_time=$SECONDS
  # Snapshot existing subdirs before run
  mapfile -t _before < <(find "${RUN_DIR}" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort)
  if "$BIN" run --config "$cfg" --output-dir "${RUN_DIR}" "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"; then
    elapsed=$((SECONDS - start_time))
    TIMING[$name]="${elapsed}s"
    PASSED=$((PASSED + 1))
    ok "${name} completed (${elapsed}s)"
    # Capture newly created result sub-directory (diff before/after)
    mapfile -t _after < <(find "${RUN_DIR}" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort)
    for _d in "${_after[@]}"; do
      if [[ ! " ${_before[*]} " =~ " ${_d} " ]]; then
        RESULT_DIRS+=("$_d")
        meta="${_d}/meta.csv"
        if [[ -f "$meta" ]]; then
          executed="$(awk -F, '$1 == "scenarios_executed" { sub(/\r$/, "", $2); print $2 }' "$meta")"
          skipped="$(awk -F, '$1 == "scenarios_skipped" { sub(/\r$/, "", $2); print $2 }' "$meta")"
          SCENARIOS_EXECUTED=$((SCENARIOS_EXECUTED + ${executed:-0}))
          SCENARIOS_SKIPPED=$((SCENARIOS_SKIPPED + ${skipped:-0}))
        fi
      fi
    done
  else
    elapsed=$((SECONDS - start_time))
    TIMING[$name]="${elapsed}s (FAILED)"
    fail "${name} exited with error (${elapsed}s)"
    FAILED=$((FAILED + 1))
  fi
done

# ─── Step 4: Consolidate Results ─────────────────────────────────────────────
rule "CONSOLIDATION"

COMBINED="${RUN_DIR}/combined_summary.csv"
HEADER_WRITTEN=false

for dir in "${RESULT_DIRS[@]}"; do
  csv="${dir}/summary.csv"
  [[ -f "$csv" ]] || continue
  if [[ "$HEADER_WRITTEN" == false ]]; then
    cp "$csv" "$COMBINED"
    HEADER_WRITTEN=true
  else
    tail -n +2 "$csv" >> "$COMBINED"
  fi
done

TOTAL_SCENARIOS=0
if [[ -f "$COMBINED" ]]; then
  TOTAL_SCENARIOS=$(( $(wc -l < "$COMBINED") - 1 ))
  ok "Combined CSV: ${COMBINED} (${TOTAL_SCENARIOS} scenarios)"

  # A requested perf run is only valid when each gateway-backed scenario has
  # every requested counter. Do not produce a superficially successful report
  # with blank hardware metrics.
  if [[ "$PERF" == true ]]; then
    if ! awk -F',' '
      NR == 1 {
        for (i = 1; i <= NF; i++) col[$i] = i
        next
      }
      # Gateway scenarios have a procfs CPU aggregate; loopback-only cases do
      # not have a gateway PID and are intentionally outside perf attachment.
      col["cpu_pct_peak"] && $(col["cpu_pct_peak"]) != "" {
        split("perf_cycles perf_instructions perf_ipc perf_cache_references perf_cache_misses perf_context_switches perf_syscalls perf_task_clock_ms perf_duration_s", required, " ")
        missing = ""
        for (i in required) {
          field = required[i]
          if (!col[field] || $(col[field]) == "") {
            missing = missing (missing == "" ? "" : ",") field
          }
        }
        if (missing != "") {
          print "  " $(col["scenario"]) ": " missing
          invalid = 1
        }
      }
      END { exit invalid }
    ' "$COMBINED"; then
      fail "perf collection was incomplete for the scenario(s) above"
      PERF_INCOMPLETE=true
    else
      ok "All requested perf counters were collected for gateway scenarios"
    fi
  fi
else
  warn "No summary.csv files found in result directories"
fi

# ─── Step 5: Generate Performance Overview ───────────────────────────────────
rule "PERFORMANCE OVERVIEW"

OVERVIEW="${RUN_DIR}/PERFORMANCE_OVERVIEW.txt"
{
  echo "══════════════════════════════════════════════════════════════════════════"
  echo " SESHAT — Scientific Performance Report"
  echo "══════════════════════════════════════════════════════════════════════════"
  echo ""
  echo " Generated : $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
  echo " Host      : $(hostname) ($(uname -r))"
  echo " Profile   : ${PROFILE}"
  echo " Configs   : ${PASSED} passed / ${FAILED} failed / ${SKIPPED} skipped"
  echo " Scenarios : ${TOTAL_SCENARIOS} recorded / ${SCENARIOS_SKIPPED} skipped"
  echo " Directory : ${RUN_DIR}/"
  if [[ "$QUICK" == true ]]; then
    echo " Mode      : QUICK (shortened runs — not for publication)"
  fi
  echo ""

  # ── Timing
  echo " ── Execution Timing ────────────────────────────────────────────────────"
  echo ""
  local_w1=25; local_w2=12
  draw_border top $local_w1 $local_w2
  draw_row "lr" $local_w1 $local_w2 -- "Config" "Duration"
  draw_border mid $local_w1 $local_w2
  for name in "${!TIMING[@]}"; do
    draw_row "lr" $local_w1 $local_w2 -- "$name" "${TIMING[$name]}"
  done
  draw_border bot $local_w1 $local_w2
  echo ""

  if [[ ! -f "$COMBINED" ]] || ! command -v awk &>/dev/null; then
    echo " (no CSV data available for detailed tables)"
  else
    # ══════════════════════════════════════════════════════════════════════════
    # TABLE 1: Throughput Results
    # ══════════════════════════════════════════════════════════════════════════
    echo " ── Table 1: Throughput ──────────────────────────────────────────────────"
    echo ""
    awk -F',' '
    NR==1 {
      for(i=1;i<=NF;i++) {
        gsub(/^[ \t]+|[ \t]+$/, "", $i)
        if($i=="scenario") sc=i
        if($i=="throughput_gbps_mean") tg=i
        if($i=="latency_p99_us_mean") lp=i
        if($i=="loss_pct") lc=i
        if($i=="bottleneck") bn=i
      }
      printf " ┌──────────────────────────────────────┬──────────────┬───────────┬────────┬────────────────┐\n"
      printf " │ %-36s │ %12s │ %9s │ %6s │ %-14s │\n", "Scenario", "Tput (Gb/s)", "p99 (µs)", "Loss %", "Bottleneck"
      printf " ├──────────────────────────────────────┼──────────────┼───────────┼────────┼────────────────┤\n"
      next
    }
    tg && $tg+0 > 0.1 {
      scenario = (sc ? $sc : "-")
      tput = (tg ? $tg+0 : 0)
      p99  = (lp ? $lp+0 : 0)
      loss = (lc ? $lc+0 : 0)
      bneck = (bn ? $bn : "-")
      gsub(/^[ \t]+|[ \t]+$/, "", scenario)
      gsub(/^[ \t]+|[ \t]+$/, "", bneck)
      printf " │ %-36s │ %12.3f │ %9.1f │ %6.1f │ %-14s │\n", \
        substr(scenario,1,36), tput, p99, loss, substr(bneck,1,14)
    }
    END {
      printf " └──────────────────────────────────────┴──────────────┴───────────┴────────┴────────────────┘\n"
    }
    ' "$COMBINED"
    echo ""

    # ══════════════════════════════════════════════════════════════════════════
    # TABLE 2: Latency (paced scenarios only, identified by "lat_" prefix)
    # ══════════════════════════════════════════════════════════════════════════
    if grep -q "^lat_" "$COMBINED" 2>/dev/null; then
      echo " ── Table 2: One-Way Latency (paced, sub-saturation) ────────────────────"
      echo ""
      awk -F',' '
      NR==1 {
        for(i=1;i<=NF;i++) {
          gsub(/^[ \t]+|[ \t]+$/, "", $i)
          if($i=="scenario") sc=i
          if($i=="latency_mean_us") lm=i
          if($i=="latency_mean_ci95") lmc=i
          if($i=="latency_p99_us_mean") lp=i
          if($i=="latency_p99_us_ci95") lpc=i
        }
        printf " ┌────────────────────────────────────┬──────────────────────┬──────────────────────┐\n"
        printf " │ %-34s │ %20s │ %20s │\n", "Scenario", "Mean Latency", "p99 Latency"
        printf " ├────────────────────────────────────┼──────────────────────┼──────────────────────┤\n"
        next
      }
      /^lat_/ {
        scenario = $sc
        mean_l = (lm ? $lm+0 : 0)
        mean_c = (lmc ? $lmc+0 : 0)
        p99_l  = (lp ? $lp+0 : 0)
        p99_c  = (lpc ? $lpc+0 : 0)
        gsub(/^[ \t]+|[ \t]+$/, "", scenario)
        if(mean_c > 0.05)
          ms = sprintf("%8.1f ± %5.1f µs", mean_l, mean_c)
        else
          ms = sprintf("%8.1f µs         ", mean_l)
        if(p99_c > 0.05)
          ps = sprintf("%8.1f ± %5.1f µs", p99_l, p99_c)
        else
          ps = sprintf("%8.1f µs         ", p99_l)
        printf " │ %-34s │ %20s │ %20s │\n", substr(scenario,1,34), ms, ps
      }
      END {
        printf " └────────────────────────────────────┴──────────────────────┴──────────────────────┘\n"
      }
      ' "$COMBINED"
      echo ""
    fi

    # ══════════════════════════════════════════════════════════════════════════
    # TABLE 3: Round-Trip Time (ping-pong scenarios, "pp_" prefix)
    # ══════════════════════════════════════════════════════════════════════════
    if grep -q "^pp_" "$COMBINED" 2>/dev/null; then
      echo " ── Table 3: Round-Trip Time (ping-pong) ────────────────────────────────"
      echo ""
      awk -F',' '
      NR==1 {
        for(i=1;i<=NF;i++) {
          gsub(/^[ \t]+|[ \t]+$/, "", $i)
          if($i=="scenario") sc=i
          if($i=="rtt_us_mean") rm=i
          if($i=="rtt_us_ci95") rc=i
          if($i=="rtt_us_p50") rp50=i
          if($i=="rtt_us_p99") rp99=i
        }
        printf " ┌──────────────────────────────┬────────────────────┬──────────┬──────────┐\n"
        printf " │ %-28s │ %18s │ %8s │ %8s │\n", "Scenario", "Mean RTT", "p50", "p99"
        printf " ├──────────────────────────────┼────────────────────┼──────────┼──────────┤\n"
        next
      }
      /^pp_/ {
        scenario = $sc
        mean_r = (rm ? $rm+0 : 0)
        ci_r   = (rc ? $rc+0 : 0)
        p50_r  = (rp50 ? $rp50+0 : 0)
        p99_r  = (rp99 ? $rp99+0 : 0)
        gsub(/^[ \t]+|[ \t]+$/, "", scenario)
        if(ci_r > 0.05)
          ms = sprintf("%6.1f ± %4.1f µs", mean_r, ci_r)
        else
          ms = sprintf("%6.1f µs       ", mean_r)
        printf " │ %-28s │ %18s │ %6.1f µs │ %6.1f µs │\n", \
          substr(scenario,1,28), ms, p50_r, p99_r
      }
      END {
        printf " └──────────────────────────────┴────────────────────┴──────────┴──────────┘\n"
      }
      ' "$COMBINED"
      echo ""
    fi

    # ══════════════════════════════════════════════════════════════════════════
    # TABLE 4: Saturation Sweep (scenarios with saturation_gbps > 0)
    # ══════════════════════════════════════════════════════════════════════════
    if awk -F',' 'NR==1{for(i=1;i<=NF;i++){gsub(/^[ \t]+|[ \t]+$/,"",$i);if($i=="saturation_gbps")sg=i}} NR>1&&sg&&$sg+0>0{found=1;exit} END{exit !found}' "$COMBINED" 2>/dev/null; then
      echo " ── Table 4: Saturation Sweep ───────────────────────────────────────────"
      echo ""
      awk -F',' '
      NR==1 {
        for(i=1;i<=NF;i++) {
          gsub(/^[ \t]+|[ \t]+$/, "", $i)
          if($i=="scenario") sc=i
          if($i=="saturation_gbps") sg=i
          if($i=="max_lossfree_gbps") ml=i
        }
        printf " ┌──────────────────────────────────┬────────────────┬────────────────────┐\n"
        printf " │ %-32s │ %14s │ %18s │\n", "Scenario", "Ceiling", "Loss-Free Max"
        printf " ├──────────────────────────────────┼────────────────┼────────────────────┤\n"
        next
      }
      sg && $sg+0 > 0 {
        scenario = $sc
        ceil_g = $sg + 0
        free_g = (ml ? $ml+0 : 0)
        gsub(/^[ \t]+|[ \t]+$/, "", scenario)
        printf " │ %-32s │ %10.3f Gb/s │ %14.3f Gb/s │\n", \
          substr(scenario,1,32), ceil_g, free_g
      }
      END {
        printf " └──────────────────────────────────┴────────────────┴────────────────────┘\n"
      }
      ' "$COMBINED"
      echo ""
    fi

    # ══════════════════════════════════════════════════════════════════════════
    # TABLE 5: Connection Rate ("conn_" prefix)
    # ══════════════════════════════════════════════════════════════════════════
    if grep -q "^conn_" "$COMBINED" 2>/dev/null; then
      echo " ── Table 5: Connection Establishment Rate ──────────────────────────────"
      echo ""
      awk -F',' '
      NR==1 {
        for(i=1;i<=NF;i++) {
          gsub(/^[ \t]+|[ \t]+$/, "", $i)
          if($i=="scenario") sc=i
          if($i=="conns_per_sec") cr=i
          if($i=="conns_per_sec_ci95") cc=i
          if($i=="conn_handshake_p50_us") hp50=i
          if($i=="conn_handshake_p99_us") hp99=i
        }
        printf " ┌──────────────────────────────────┬──────────────────┬───────────┬───────────┐\n"
        printf " │ %-32s │ %16s │ %9s │ %9s │\n", "Scenario", "Rate", "hs p50", "hs p99"
        printf " ├──────────────────────────────────┼──────────────────┼───────────┼───────────┤\n"
        next
      }
      /^conn_/ {
        scenario = $sc
        rate = (cr ? $cr+0 : 0)
        ci   = (cc ? $cc+0 : 0)
        p50  = (hp50 ? $hp50+0 : 0)
        p99  = (hp99 ? $hp99+0 : 0)
        gsub(/^[ \t]+|[ \t]+$/, "", scenario)
        if(ci > 0.5)
          rs = sprintf("%8.0f ± %5.0f", rate, ci)
        else
          rs = sprintf("%8.0f        ", rate)
        printf " │ %-32s │ %13s c/s │ %7.1f µs │ %7.1f µs │\n", \
          substr(scenario,1,32), rs, p50, p99
      }
      END {
        printf " └──────────────────────────────────┴──────────────────┴───────────┴───────────┘\n"
      }
      ' "$COMBINED"
      echo ""
    fi

    # ══════════════════════════════════════════════════════════════════════════
    # SUMMARY STATISTICS
    # ══════════════════════════════════════════════════════════════════════════
    echo " ── Summary Statistics ─────────────────────────────────────────────────"
    echo ""
    awk -F',' '
    NR==1 {
      for(i=1;i<=NF;i++) {
        gsub(/^[ \t]+|[ \t]+$/, "", $i)
        if($i=="scenario") sc=i
        if($i=="throughput_gbps_mean") tg=i
        if($i=="latency_p99_us_mean") lp=i
        if($i=="protocol") pr=i
        if($i=="transport") tr=i
      }
      next
    }
    tg && $tg+0 > 0 {
      val = $tg + 0
      if(best_n == "" || val > best_v) { best_v=val; best_n=$sc }
      if(worst_n == "" || val < worst_v) { worst_v=val; worst_n=$sc }
      sum_t += val; cnt_t++
      lat = (lp ? $lp+0 : 0)
      if(lat > 0) {
        if(best_ln == "" || lat < best_lv) { best_lv=lat; best_ln=$sc }
        if(worst_ln == "" || lat > worst_lv) { worst_lv=lat; worst_ln=$sc }
      }
      # Per-protocol aggregation
      p = (pr ? $pr : "none")
      gsub(/^[ \t]+|[ \t]+$/, "", p)
      proto_sum[p] += val; proto_cnt[p]++
    }
    END {
      gsub(/^[ \t]+|[ \t]+$/, "", best_n)
      gsub(/^[ \t]+|[ \t]+$/, "", worst_n)
      gsub(/^[ \t]+|[ \t]+$/, "", best_ln)
      gsub(/^[ \t]+|[ \t]+$/, "", worst_ln)
      printf " ┌────────────────────────┬──────────────────────────────────────────────┐\n"
      printf " │ %-22s │ %-44s │\n", "Metric", "Value"
      printf " ├────────────────────────┼──────────────────────────────────────────────┤\n"
      if(best_n != "")
        printf " │ %-22s │ %10.3f Gbit/s  %-27s │\n", "Best throughput", best_v, "("best_n")"
      if(worst_n != "")
        printf " │ %-22s │ %10.3f Gbit/s  %-27s │\n", "Worst throughput", worst_v, "("worst_n")"
      if(cnt_t > 0)
        printf " │ %-22s │ %10.3f Gbit/s  %-27s │\n", "Mean throughput", sum_t/cnt_t, "("cnt_t" scenarios)"
      if(best_ln != "")
        printf " │ %-22s │ %10.1f µs      %-27s │\n", "Best p99 latency", best_lv, "("best_ln")"
      if(worst_ln != "")
        printf " │ %-22s │ %10.1f µs      %-27s │\n", "Worst p99 latency", worst_lv, "("worst_ln")"
      printf " └────────────────────────┴──────────────────────────────────────────────┘\n"
      printf "\n"

      # Per-protocol comparison
      printf " ┌────────────────────────┬────────────────┬───────────┐\n"
      printf " │ %-22s │ %14s │ %9s │\n", "Protocol", "Avg Throughput", "Scenarios"
      printf " ├────────────────────────┼────────────────┼───────────┤\n"
      for(p in proto_sum) {
        printf " │ %-22s │ %10.3f Gb/s │ %9d │\n", p, proto_sum[p]/proto_cnt[p], proto_cnt[p]
      }
      printf " └────────────────────────┴────────────────┴───────────┘\n"
    }
    ' "$COMBINED"
  fi

  echo ""
  echo "══════════════════════════════════════════════════════════════════════════"
  echo " CSV data : ${COMBINED}"
  echo " Reproduce: seshat report --input ${RUN_DIR}"
  echo "══════════════════════════════════════════════════════════════════════════"
} | tee "${OVERVIEW}"

# ─── Final Summary ───────────────────────────────────────────────────────────
echo ""
rule "COMPLETE"
echo ""
echo -e "  Configs    : ${GREEN}${PASSED} passed${NC} / ${RED}${FAILED} failed${NC} / ${DIM}${SKIPPED} skipped${NC}"
echo -e "  Scenarios  : ${BOLD}${TOTAL_SCENARIOS} recorded${NC} / ${DIM}${SCENARIOS_SKIPPED} skipped${NC}"
echo -e "  Results    : ${BOLD}${RUN_DIR}/${NC}"
echo -e "  Overview   : ${BOLD}${OVERVIEW}${NC}"
[[ -f "$COMBINED" ]] && echo -e "  CSV        : ${BOLD}${COMBINED}${NC}"
echo ""

# Exit with failure if any config failed
[[ "$FAILED" -eq 0 && "$PERF_INCOMPLETE" == false ]] || exit 1

# ── Ranked Leaderboard ──
if [[ -f "$COMBINED" ]]; then
  echo ""
  rule "LEADERBOARD"
  echo ""
  echo " Ranked by throughput (descending). Latency/RTT/Connrate scenarios excluded."
  echo ""
  awk -F',' '
  NR==1 {
    for(i=1;i<=NF;i++) {
      gsub(/^[ \t]+|[ \t]+$/, "", $i)
      if($i=="scenario") sc=i
      if($i=="throughput_gbps_mean") tg=i
      if($i=="latency_p99_us_mean") lp=i
      if($i=="loss_pct") lc=i
    }
    next
  }
  tg && $tg+0 > 0.1 {
    name = $sc
    gsub(/^[ \t]+|[ \t]+$/, "", name)
    # Skip lat_, pp_, conn_ scenarios (they measure different things)
    if(name ~ /^lat_/ || name ~ /^pp_/ || name ~ /^conn_/) next
    n++
    tput[n] = $tg+0
    p99[n]  = (lp ? $lp+0 : 0)
    loss[n] = (lc ? $lc+0 : 0)
    names[n] = name
  }
  END {
    # Sort descending by throughput (insertion sort)
    for(i=2; i<=n; i++) {
      j=i
      while(j>1 && tput[j] > tput[j-1]) {
        tmp=tput[j]; tput[j]=tput[j-1]; tput[j-1]=tmp
        tmp=p99[j]; p99[j]=p99[j-1]; p99[j-1]=tmp
        tmp=loss[j]; loss[j]=loss[j-1]; loss[j-1]=tmp
        tmp=names[j]; names[j]=names[j-1]; names[j-1]=tmp
        j--
      }
    }
    printf " ┌────┬────────────────────────────────────┬──────────────┬───────────┬────────┐\n"
    printf " │ %2s │ %-34s │ %12s │ %9s │ %6s │\n", "#", "Scenario", "Tput (Gb/s)", "p99 (µs)", "Loss %"
    printf " ├────┼────────────────────────────────────┼──────────────┼───────────┼────────┤\n"
    for(i=1; i<=n; i++) {
      printf " │ %2d │ %-34s │ %12.3f │ %9.1f │ %6.1f │\n", \
        i, substr(names[i],1,34), tput[i], p99[i], loss[i]
    }
    printf " └────┴────────────────────────────────────┴──────────────┴───────────┴────────┘\n"
  }
  ' "$COMBINED"
fi
