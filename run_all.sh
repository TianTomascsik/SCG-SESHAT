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
#   ./run_all.sh --scenario-filter tcp  # Only run configs with 'tcp' in name
#   ./run_all.sh --skip-build           # Skip cargo build
#   ./run_all.sh --perf                 # Enable perf stat collection
#
# This script:
#  1. Builds SESHAT (release) and the SCG gateway
#  2. Dumps system info for reproducibility
#  3. Runs every benchmark config (throughput, latency, saturation, RTT, connrate)
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
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)          PROFILE="debug"; shift ;;
    --output-dir)     OUTPUT_DIR="$2"; shift 2 ;;
    --quick)          QUICK=true; shift ;;
    --skip-build)     SKIP_BUILD=true; shift ;;
    --scenario-filter) FILTER="$2"; shift 2 ;;
    --perf)           PERF=true; shift ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | grep '^#' | cut -c3-
      exit 0 ;;
    *)                EXTRA_ARGS+=("$1"); shift ;;
  esac
done

RUN_DIR="${OUTPUT_DIR}/${TIMESTAMP}"
BIN="./target/${PROFILE}/seshat"
GW_BIN="../SCG/target/${PROFILE}/gateway"

# Quick mode overrides: 2s measure, 1s warmup, 1 run
if [[ "$QUICK" == true ]]; then
  EXTRA_ARGS+=(--duration 2s --warmup 1s --runs 1)
fi

# Perf backend
if [[ "$PERF" == true ]]; then
  EXTRA_ARGS+=(--metrics-backend perf)
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

# All available configs in execution order
declare -A CONFIG_DESC
CONFIGS=(
  configs/gateway_smoke.json
  configs/full_matrix.json
  configs/latency.json
  configs/saturation.json
  configs/pingpong.json
  configs/connrate.json
)
CONFIG_DESC=(
  [configs/gateway_smoke.json]="Quick smoke test (routing + TLS baseline)"
  [configs/full_matrix.json]="Full protocol/transport matrix (throughput)"
  [configs/latency.json]="Paced sub-saturation one-way latency"
  [configs/saturation.json]="Offered-load sweep (find loss-free ceiling)"
  [configs/pingpong.json]="Closed-loop round-trip time"
  [configs/connrate.json]="Connection establishment rate"
)

PASSED=0
FAILED=0
SKIPPED=0
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
  echo " Scenarios : ${TOTAL_SCENARIOS}"
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
echo -e "  Scenarios  : ${BOLD}${TOTAL_SCENARIOS}${NC}"
echo -e "  Results    : ${BOLD}${RUN_DIR}/${NC}"
echo -e "  Overview   : ${BOLD}${OVERVIEW}${NC}"
[[ -f "$COMBINED" ]] && echo -e "  CSV        : ${BOLD}${COMBINED}${NC}"
echo ""

# Exit with failure if any config failed
[[ "$FAILED" -eq 0 ]] || exit 1

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
