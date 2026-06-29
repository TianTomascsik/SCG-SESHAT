#!/usr/bin/env bash
# collect_perf_data.sh — one-shot SCG performance data collector.
#
# Produces a single bundle with everything needed to diagnose and improve SCG
# latency/throughput: host fingerprint, harness calibration (so harness-bound
# results are distinguishable from SCG-bound ones), per-path throughput/latency,
# A/B optimization-knob comparisons, saturation degradation curves, handshake
# cost, perf hardware counters (IPC/cache/syscalls), memory-copies-per-message
# (root + bpftrace), and a CPU flamegraph of the gateway under load (root/perf).
#
# The flamegraph stage profiles a *symbolised* gateway (built with the `profiling`
# cargo profile so frames resolve, not bare hex), reports per-thread CPU% so the
# hot data-plane thread (`rule-*`) is identified mechanically, emits a data-plane-
# only report, and flags [LOW-LOAD] when no thread saturates a core (i.e. the
# profile is harness-limited rather than SCG-bound).
#
# Everything degrades gracefully: unprivileged runs still yield the full CSV
# dataset; perf/eBPF/flamegraph stages print [SKIPPED] with the reason.
#
# Usage:
#   scripts/collect_perf_data.sh [OUT_DIR]
# Env overrides:
#   SCOPE=diagnostic|full|matrix   (default diagnostic)
#     diagnostic — curated A/B knobs + per-path + saturation + paced latency + connrate (fast)
#     full       — + full_suite.json  (UDS/SHM/TPROXY interfaces; TLS/mTLS/kTLS/DTLS/
#                    integrity/ALE/raw/subset146 protocols; multistream QoS + DSCP priority;
#                    hot-reload; veth/netns topologies) + interface_comparison.json (transports)
#     matrix     — + generated size×connections×protocol×transport sweep (long).
#                  MATRIX_FILE=full_matrix.json for the exhaustive ~1.6k-row sweep (hours).
#   RUNS=3 DURATION=6s PROFILE_SECS=30 PROFILE_FREQ=4000 PROFILE_SCENARIO=path_routing_4KB
#   GATEWAY_BIN=/path/to/gateway   SKIP_FLAMEGRAPH=1   SKIP_BUILD=1
set -uo pipefail

# ── Locations ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESHAT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCG_DIR="$(cd "$SESHAT_DIR/../SCG" 2>/dev/null && pwd || true)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${1:-$SESHAT_DIR/perf-data/$STAMP}"
mkdir -p "$OUT_DIR"
MANIFEST="$OUT_DIR/MANIFEST.txt"

RUNS="${RUNS:-3}"
DURATION="${DURATION:-6s}"
PROFILE_SECS="${PROFILE_SECS:-30}"
PROFILE_FREQ="${PROFILE_FREQ:-4000}"
PROFILE_SCENARIO="${PROFILE_SCENARIO:-path_routing_4KB}"
CONFIG="$SESHAT_DIR/configs/perf_investigation.json"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
man()  { printf '%s\n' "$*" >>"$MANIFEST"; }

# Snapshot per-thread CPU jiffies for a live process — "tid comm utime+stime"
# per thread. `comm` may contain spaces/parens, so we split on the last ')'.
snapshot_thread_jiffies() {
  local pid="$1" t
  for t in /proc/"$pid"/task/*/stat; do
    [ -r "$t" ] || continue
    awk '{
      tid=$1; line=$0
      lp=index(line,"(")
      rp=0; for(i=length(line);i>0;i--){ if(substr(line,i,1)==")"){ rp=i; break } }
      comm=substr(line, lp+1, rp-lp-1)
      n=split(substr(line, rp+2), f, " ")   # f[1]=state(field3) ... utime=field14=>f[12], stime=field15=>f[13]
      print tid, comm, f[12]+f[13]
    }' "$t"
  done
}

# Turn two jiffie snapshots into a CSV of per-thread CPU% of one core over `secs`,
# busiest first. Lets us flag a flamegraph taken on an idle (harness-limited) gateway.
thread_cpu_report() {
  local before="$1" after="$2" secs="$3" clk
  clk="$(getconf CLK_TCK 2>/dev/null || echo 100)"
  echo "tid,comm,cpu_pct_of_one_core"
  awk -v secs="$secs" -v clk="$clk" '
    NR==FNR { j0[$1]=$3; next }
    { d=$3-j0[$1]; if(d<0)d=0; printf "%s,%s,%.2f\n",$1,$2,(d/clk)/secs*100 }
  ' "$before" "$after" | sort -t, -k3 -nr
}

: >"$MANIFEST"
man "SCG performance data bundle — $STAMP"
man "seshat dir: $SESHAT_DIR"
man "config:     $CONFIG  (runs=$RUNS duration=$DURATION)"
man ""

# ── Preflight: required tools & capabilities ─────────────────────────────────
log "Preflight — tools & capabilities (what gets collected vs [skip]ped)"
have() { command -v "$1" >/dev/null 2>&1 && echo 1 || echo 0; }
chk() { # chk <label> <ok:0|1> <gates...>
  local label="$1" ok="$2"; shift 2
  if [ "$ok" -eq 1 ]; then printf '    \033[1;32m[ ok ]\033[0m %-11s %s\n' "$label" "$*"
  else printf '    \033[1;33m[skip]\033[0m %-11s %s\n' "$label" "$*"; fi
  man "tool $label: $([ "$ok" -eq 1 ] && echo ok || echo MISSING) — $*"
}

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
HAVE_CARGO=$(have cargo)
HAVE_OPENSSL=$(have openssl)
HAVE_PERF=0; command -v perf >/dev/null 2>&1 && perf stat -e task-clock true >/dev/null 2>&1 && HAVE_PERF=1
HAVE_BPFTRACE=$(have bpftrace)
HAVE_IP=$(have ip); HAVE_TC=$(have tc); HAVE_IPTABLES=$(have iptables)
HAVE_TASKSET=$(have taskset); HAVE_CPUPOWER=$(have cpupower)
PARANOID="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 99)"
# CAP_NET_ADMIN is bit 12 of the effective-capability mask.
caphex="$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null)"
HAVE_NETADMIN=0
{ [ "$IS_ROOT" -eq 1 ] || { [ -n "$caphex" ] && (( (0x$caphex >> 12) & 1 )); }; } && HAVE_NETADMIN=1
PERF_RECORD_OK=0
{ [ "$IS_ROOT" -eq 1 ] || [ "${PARANOID:-99}" -le 1 ]; } && [ "$HAVE_PERF" -eq 1 ] && PERF_RECORD_OK=1
EBPF_OK=0; [ "$IS_ROOT" -eq 1 ] && [ "$HAVE_BPFTRACE" -eq 1 ] && EBPF_OK=1

if [ "${SKIP_BUILD:-0}" = "1" ]; then chk cargo 1 "(SKIP_BUILD set — using prebuilt binaries)"
else chk cargo "$HAVE_CARGO" "build gateway + seshat (REQUIRED unless SKIP_BUILD=1)"; fi
chk openssl   "$HAVE_OPENSSL"  "TLS/mTLS/DTLS runtime cert generation (REQUIRED for crypto scenarios)"
chk perf      "$HAVE_PERF"     "HW counters: IPC, cache-misses, context-switches (paranoid=$PARANOID)"
chk perf-rec  "$PERF_RECORD_OK" "gateway CPU flamegraph (needs root or perf_event_paranoid<=1)"
chk bpftrace  "$HAVE_BPFTRACE" "memory-copies-per-message probe (also needs root)"
chk root      "$IS_ROOT"       "unlocks eBPF + flamegraph + CAP_NET_ADMIN scenarios"
chk net-admin "$HAVE_NETADMIN" "kTLS, TPROXY, veth/netns topology, netem impairment"
chk ip        "$HAVE_IP"       "veth/netns topology scenarios"
chk tc        "$HAVE_TC"       "netem latency/loss impairment scenarios"
chk iptables  "$HAVE_IPTABLES" "TPROXY transparent-interception scenarios"
chk taskset   "$HAVE_TASKSET"  "CPU pinning for low-noise results (reproducibility)"
chk cpupower  "$HAVE_CPUPOWER" "governor=performance for stable clocks (reproducibility)"

# Hard requirement: cargo, unless prebuilt binaries are provided.
if [ "${SKIP_BUILD:-0}" != "1" ] && [ "$HAVE_CARGO" -eq 0 ]; then
  echo "FATAL: cargo not found and SKIP_BUILD!=1 — install Rust, or pass GATEWAY_BIN + SKIP_BUILD=1"; exit 1
fi
[ "$HAVE_OPENSSL" -eq 0 ] && note "WARN: openssl missing — every TLS/mTLS/DTLS scenario will fail cert setup and be skipped"
note "seshat also skips any scenario whose host prerequisite is unmet (per-scenario reason in the run output)"
man "capabilities: root=$IS_ROOT perf=$HAVE_PERF paranoid=$PARANOID bpftrace=$HAVE_BPFTRACE perf_record=$PERF_RECORD_OK ebpf=$EBPF_OK net_admin=$HAVE_NETADMIN openssl=$HAVE_OPENSSL"

# ── Build ────────────────────────────────────────────────────────────────────
SESHAT_BIN="$SESHAT_DIR/target/release/seshat"
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  log "Building seshat (release)"
  ( cd "$SESHAT_DIR" && cargo build --release --quiet ) || { echo "seshat build failed"; exit 1; }
fi
[ -x "$SESHAT_BIN" ] || SESHAT_BIN="$(command -v seshat || echo "$SESHAT_BIN")"

# Locate / build the gateway binary. Prefer an explicit override, then a release
# build, then a release build into a writable alt target dir (the shared
# target/ may be permission-locked), then any existing debug binary.
GW="${GATEWAY_BIN:-}"
GW_TARGET_DIR=""   # cargo target dir used for the release build; reused for the profiling build (Stage 5)
if [ -z "$GW" ] && [ -n "$SCG_DIR" ] && [ "${SKIP_BUILD:-0}" != "1" ]; then
  log "Building SCG gateway (release)"
  if ( cd "$SCG_DIR" && cargo build --release -p gateway --quiet ) 2>/dev/null && [ -x "$SCG_DIR/target/release/gateway" ]; then
    GW="$SCG_DIR/target/release/gateway"; GW_TARGET_DIR="$SCG_DIR/target"
  else
    note "shared target/ not writable — building into $OUT_DIR/scg-target"
    if ( cd "$SCG_DIR" && CARGO_TARGET_DIR="$OUT_DIR/scg-target" cargo build --release -p gateway --quiet ) && [ -x "$OUT_DIR/scg-target/release/gateway" ]; then
      GW="$OUT_DIR/scg-target/release/gateway"; GW_TARGET_DIR="$OUT_DIR/scg-target"
    fi
  fi
fi
# Fall back to any prebuilt binary.
for cand in "$GW" "$SCG_DIR/target/release/gateway" "$SCG_DIR/target/debug/gateway"; do
  [ -n "$cand" ] && [ -x "$cand" ] && { GW="$cand"; break; }
done
[ -n "$GW" ] && [ -x "$GW" ] || { echo "no usable gateway binary; set GATEWAY_BIN"; exit 1; }
export SCG_GATEWAY_BIN="$GW"
note "seshat:  $SESHAT_BIN"
note "gateway: $GW"
man "seshat_bin:  $SESHAT_BIN"
man "gateway_bin: $GW"

run_seshat() { "$SESHAT_BIN" "$@"; }

# ── Stage 1: host fingerprint ────────────────────────────────────────────────
log "Stage 1/5 — host fingerprint"
run_seshat sysinfo --format json >"$OUT_DIR/host.json" 2>/dev/null && note "host.json"
run_seshat sysinfo 2>/dev/null | tee "$OUT_DIR/host.txt" >/dev/null

# ── Stage 2: harness calibration ─────────────────────────────────────────────
log "Stage 2/5 — harness calibration (NFR-PERF ceilings)"
run_seshat calibrate --output-dir "$OUT_DIR/calibration" 2>&1 | tail -20 || note "[SKIPPED] calibrate failed"

# ── Stage 3: measurement suites (perf counters) ──────────────────────────────
BACKEND="procfs"; [ "$HAVE_PERF" -eq 1 ] && BACKEND="perf"
SCOPE="${SCOPE:-diagnostic}"
# Build the list of suites to run for this scope. The diagnostic config is
# always included; `full` adds the all-features + all-transports suites; `matrix`
# adds the generated size×connections×protocol×transport sweep.
SUITES=( "diagnostic|$CONFIG" )
case "$SCOPE" in
  full|matrix)
    SUITES+=( "features|$SESHAT_DIR/configs/full_suite.json" \
              "interfaces|$SESHAT_DIR/configs/interface_comparison.json" ) ;;
esac
if [ "$SCOPE" = "matrix" ]; then
  log "Generating combinatorial matrix from configs/matrix_spec.json"
  run_seshat matrix generate --spec "$SESHAT_DIR/configs/matrix_spec.json" \
    --out-dir "$OUT_DIR/generated" --quiet 2>&1 | tail -2 || true
  MATRIX_FILE="${MATRIX_FILE:-$OUT_DIR/generated/canonical_matrix.json}"
  [ -f "$MATRIX_FILE" ] && SUITES+=( "matrix|$MATRIX_FILE" ) \
    || note "[SKIPPED] matrix — $MATRIX_FILE not generated"
fi

log "Stage 3/5 — measurement (scope=$SCOPE, backend=$BACKEND, runs=$RUNS, duration=$DURATION)"
for entry in "${SUITES[@]}"; do
  label="${entry%%|*}"; cfg="${entry#*|}"
  if [ ! -f "$cfg" ]; then note "[SKIPPED] suite '$label' — $cfg not found"; man "measure-$label: SKIPPED (config missing)"; continue; fi
  log "  suite '$label'  ($(basename "$cfg"))"
  run_seshat run --config "$cfg" --output-dir "$OUT_DIR/measure-$label" \
    --runs "$RUNS" --duration "$DURATION" --metrics-backend "$BACKEND" 2>&1 | tail -25
  man "measure-$label/: per-scenario summary.csv + scenarios/<name>/{runs,system_metrics,saturation}.csv"
done

# ── Stage 4: memory-copies-per-message (root + bpftrace) ─────────────────────
log "Stage 4/5 — memory copies per message (eBPF)"
if [ "$EBPF_OK" -eq 1 ]; then
  run_seshat run --config "$CONFIG" --output-dir "$OUT_DIR/measure-ebpf" \
    --runs 1 --duration "$DURATION" --metrics-backend ebpf \
    --scenario path_routing_4KB 2>&1 | tail -8
  run_seshat run --config "$CONFIG" --output-dir "$OUT_DIR/measure-ebpf" \
    --runs 1 --duration "$DURATION" --metrics-backend ebpf \
    --scenario path_tls13_4KB 2>&1 | tail -8
  man "measure-ebpf/: mem_copies_per_msg for routing (splice, ~0) vs userspace TLS (>0)"
else
  note "[SKIPPED] needs root + bpftrace (counts copy_to/from_user per message)"
  man "measure-ebpf: SKIPPED (needs root + bpftrace)"
fi

# ── Stage 5: CPU flamegraph of the gateway under load ────────────────────────
log "Stage 5/5 — gateway CPU profile (flamegraph)"
if [ "$PERF_RECORD_OK" -eq 1 ] && [ "${SKIP_FLAMEGRAPH:-0}" != "1" ]; then
  PROF_DIR="$OUT_DIR/profile"; mkdir -p "$PROF_DIR"

  # Profile a *symbolised* gateway so frames resolve instead of bare hex. Build
  # the `profiling` profile (release codegen + DWARF + frame pointers) into the
  # same target dir the release build used; fall back to $GW if we can't rebuild.
  GW_PROFILE="$GW"
  if [ -n "$GW_TARGET_DIR" ] && [ -n "$SCG_DIR" ] && [ "${SKIP_BUILD:-0}" != "1" ]; then
    note "building symbolised gateway (--profile profiling, force-frame-pointers)"
    if ( cd "$SCG_DIR" && RUSTFLAGS="-C force-frame-pointers=yes" CARGO_TARGET_DIR="$GW_TARGET_DIR" \
           cargo build --profile profiling -p gateway --quiet ) && [ -x "$GW_TARGET_DIR/profiling/gateway" ]; then
      GW_PROFILE="$GW_TARGET_DIR/profiling/gateway"
    else
      note "WARN: profiling build failed — recording stripped $GW (gateway frames may stay unresolved)"
    fi
  else
    note "WARN: no rebuild available (SKIP_BUILD / GATEWAY_BIN) — gateway frames may stay unresolved"
  fi
  man "profile gateway_bin: $GW_PROFILE"
  SESHAT_PID=""   # defined up-front so the trailing `wait` is safe under `set -u`

  # Resolve which config actually contains PROFILE_SCENARIO: the default
  # (diagnostic) config first, then any other configs/*.json. Lets a UDP/DTLS or
  # features scenario be profiled without the caller knowing which suite owns it,
  # and fails loudly on a typo instead of silently driving nothing.
  PROFILE_CONFIG="$CONFIG"
  if ! grep -q "\"$PROFILE_SCENARIO\"" "$CONFIG" 2>/dev/null; then
    for c in "$SESHAT_DIR"/configs/*.json; do
      grep -q "\"$PROFILE_SCENARIO\"" "$c" 2>/dev/null && { PROFILE_CONFIG="$c"; break; }
    done
  fi
  GWPID=""
  if ! grep -q "\"$PROFILE_SCENARIO\"" "$PROFILE_CONFIG" 2>/dev/null; then
    note "[SKIPPED] PROFILE_SCENARIO '$PROFILE_SCENARIO' not found in any configs/*.json — set a valid scenario name"
    man  "profile: SKIPPED (PROFILE_SCENARIO '$PROFILE_SCENARIO' not in any config)"
  else
  note "driving '$PROFILE_SCENARIO' ($(basename "$PROFILE_CONFIG")) and recording the gateway for ${PROFILE_SECS}s @ ${PROFILE_FREQ}Hz"
  # Pre-existing gateways (a system service, a stray dev run) must NOT be profiled
  # by mistake — record the set that exists *before* the load so we can pick the
  # new, seshat-spawned one afterwards.
  PRE_GW=" $(pgrep -x gateway 2>/dev/null | tr '\n' ' ')"

  # Long single-scenario run in the background; attach perf to the live gateway.
  # `export` (not a prefix) so seshat's child actually launches the *symbolised*
  # binary; the global export at Stage 0 otherwise pins it to the stripped release.
  export SCG_GATEWAY_BIN="$GW_PROFILE"
  run_seshat run --config "$PROFILE_CONFIG" --output-dir "$PROF_DIR/load" \
    --runs 1 --duration "$((PROFILE_SECS + 8))s" --warmup 3s \
    --scenario "$PROFILE_SCENARIO" >"$PROF_DIR/load.log" 2>&1 &
  SESHAT_PID=$!
  # Pick the gateway PID that appeared *after* the load started (the one under test),
  # never a pre-existing idle gateway. Prefer one whose /proc/<pid>/exe matches the
  # symbolised binary; fall back to the newest non-pre-existing gateway.
  for _ in $(seq 1 150); do
    # Stop early if the load run already failed on a fatal config/bind error.
    grep -qiE 'no scenario named|Failed to bind|address already in use' "$PROF_DIR/load.log" 2>/dev/null && break
    for p in $(pgrep -x gateway 2>/dev/null | sort -rn); do
      case "$PRE_GW" in *" $p "*) continue;; esac          # skip pre-existing
      exe="$(readlink -f "/proc/$p/exe" 2>/dev/null || true)"
      if [ "$exe" = "$(readlink -f "$GW_PROFILE" 2>/dev/null)" ]; then GWPID="$p"; break; fi
      [ -z "$GWPID" ] && GWPID="$p"                          # fallback: newest fresh gateway
    done
    [ -n "$GWPID" ] && break
    sleep 0.2
  done
  [ -n "$GWPID" ] && note "profiling gateway pid $GWPID (exe: $(readlink -f /proc/$GWPID/exe 2>/dev/null || echo '?'))"
  fi
  if [ -n "$GWPID" ]; then
    sleep 2  # let it reach steady state

    # Per-thread CPU% across the record window, so the hot data-plane thread is
    # identified mechanically and an idle (harness-limited) profile is flagged.
    snapshot_thread_jiffies "$GWPID" >"$PROF_DIR/.threads.before" 2>/dev/null || true

    perf record -F "$PROFILE_FREQ" -g --call-graph dwarf -p "$GWPID" \
      -o "$PROF_DIR/perf.data" -- sleep "$PROFILE_SECS" 2>"$PROF_DIR/perf-record.log" \
      || note "perf record returned nonzero"

    snapshot_thread_jiffies "$GWPID" >"$PROF_DIR/.threads.after" 2>/dev/null || true
    thread_cpu_report "$PROF_DIR/.threads.before" "$PROF_DIR/.threads.after" "$PROFILE_SECS" \
      >"$PROF_DIR/threads.csv" 2>/dev/null || true
    rm -f "$PROF_DIR/.threads.before" "$PROF_DIR/.threads.after"

    # Generate perf reports first; we derive the hot data-plane thread from perf's
    # own per-comm overhead (robust), not from /proc CPU% — the zero-copy splice
    # relay shows near-zero utime+stime even when it is the bottleneck.
    perf report --stdio -i "$PROF_DIR/perf.data" >"$PROF_DIR/perf-report.txt" 2>/dev/null && note "perf-report.txt"
    perf report --stdio -i "$PROF_DIR/perf.data" --sort comm,dso >"$PROF_DIR/perf-report-by-thread.txt" 2>/dev/null \
      && note "perf-report-by-thread.txt"

    # Busiest comm overall, and busiest *data-plane* comm (rule-*/-pool-*/relay), per perf.
    HOT_COMM="$(awk '/^[[:space:]]+[0-9.]+%/{print $3; exit}' "$PROF_DIR/perf-report-by-thread.txt" 2>/dev/null)"
    DP_COMM="$(awk '/^[[:space:]]+[0-9.]+%/{ if($3 ~ /rule-|pool|relay/){print $3; exit} }' "$PROF_DIR/perf-report-by-thread.txt" 2>/dev/null)"
    [ -z "$DP_COMM" ] && DP_COMM="$HOT_COMM"
    DP_CPU="$(awk -F, 'NR>1 && $2 ~ /rule-|pool|relay/{print $3; exit}' "$PROF_DIR/threads.csv" 2>/dev/null)"

    # Authoritative SCG-bound-vs-harness signal: seshat's own calibration-based
    # headroom verdict from the load run (our CPU% is only supporting evidence).
    HEADROOM_LINE="$(grep -aE 'Headroom|bottleneck' "$PROF_DIR/load.log" 2>/dev/null | tail -1 | sed 's/^[[:space:]]*//')"
    note "busiest thread: ${HOT_COMM:-?}; data-plane: ${DP_COMM:-?} (~${DP_CPU:-?}% of a core)"
    [ -n "$HEADROOM_LINE" ] && note "seshat verdict: $HEADROOM_LINE"
    if printf '%s' "$HEADROOM_LINE" | grep -q 'HARNESS-LIMITED'; then
      note "[HARNESS-LIMITED] load did not saturate SCG — flamegraph shows the I/O-bound regime, not a CPU bottleneck"
      man "profile load: [HARNESS-LIMITED] busiest=$HOT_COMM data-plane=$DP_COMM (~${DP_CPU:-?}% core) — $HEADROOM_LINE"
    elif printf '%s' "$HEADROOM_LINE" | grep -qiE 'bottleneck:?[[:space:]]*scg'; then
      man "profile load: OK (SCG-bound) — data-plane $DP_COMM ~${DP_CPU:-?}% core — $HEADROOM_LINE"
    else
      man "profile load: data-plane $DP_COMM ~${DP_CPU:-?}% core — ${HEADROOM_LINE:-no headroom line}"
    fi

    # Data-plane-only view, filtered to the busiest data-plane thread per perf.
    if [ -n "$DP_COMM" ]; then
      perf report --stdio -i "$PROF_DIR/perf.data" --comms "$DP_COMM" \
        >"$PROF_DIR/perf-report-dataplane.txt" 2>/dev/null \
        && note "perf-report-dataplane.txt (thread $DP_COMM)"
    else
      note "no data-plane thread sampled — check PROFILE_SCENARIO / load / pid selection"
    fi

    # Folded stacks + SVG when a flamegraph tool is present.
    if perf script -i "$PROF_DIR/perf.data" >"$PROF_DIR/perf-script.txt" 2>/dev/null; then
      if command -v inferno-collapse-perf >/dev/null 2>&1 && command -v inferno-flamegraph >/dev/null 2>&1; then
        inferno-collapse-perf <"$PROF_DIR/perf-script.txt" | inferno-flamegraph >"$PROF_DIR/flamegraph.svg" 2>/dev/null && note "flamegraph.svg"
      elif command -v stackcollapse-perf.pl >/dev/null 2>&1 && command -v flamegraph.pl >/dev/null 2>&1; then
        stackcollapse-perf.pl "$PROF_DIR/perf-script.txt" | flamegraph.pl >"$PROF_DIR/flamegraph.svg" 2>/dev/null && note "flamegraph.svg"
      else
        note "no flamegraph tool (inferno/FlameGraph); perf-script.txt is foldable later"
      fi
    fi
    man "profile/: perf.data, perf-report.txt, perf-report-by-thread.txt, perf-report-dataplane.txt, threads.csv[, flamegraph.svg]"
  else
    note "[SKIPPED] could not find the gateway PID under load"
    man "profile: SKIPPED (no gateway pid)"
  fi
  wait "$SESHAT_PID" 2>/dev/null || true
else
  note "[SKIPPED] needs perf with paranoid<=1 or root (SKIP_FLAMEGRAPH to force off)"
  man "profile: SKIPPED (perf record unavailable)"
fi

# ── Bundle ───────────────────────────────────────────────────────────────────
log "Bundling"
man ""
man "Hand this whole directory (or the tarball) to the analysis. Key files:"
man "  host.txt / host.json        — CPU, governor, turbo, NUMA, isolcpus, git hashes"
man "  calibration/                — harness ceilings (trust SCG numbers only with headroom)"
man "  measure-*/summary.csv       — one row per scenario, all metrics + caveat columns"
man "  measure-*/scenarios/<name>/ — per-run, system_metrics, saturation (degradation) CSVs"
man "  profile/flamegraph.svg      — gateway hot path (if captured)"
TARBALL="$OUT_DIR.tar.gz"
( cd "$(dirname "$OUT_DIR")" && tar czf "$TARBALL" "$(basename "$OUT_DIR")" ) 2>/dev/null && note "tarball: $TARBALL"

log "Done"
note "bundle: $OUT_DIR"
[ -f "$TARBALL" ] && note "tarball: $TARBALL"
cat "$MANIFEST"

Resets in 18h