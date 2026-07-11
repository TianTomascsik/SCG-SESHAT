#!/usr/bin/env bash
#
# run_relay_backend_ab.sh — full io_uring-vs-poll relay-backend benchmark (thesis Ch. 8).
#
# Answers §5.11.4: compares four fd<->fd relay backends of the SCG gateway
#   splice          poll(2) + splice(2)        zero-copy (the default)
#   readwrite       poll(2) + read/write       copy-based baseline
#   iouring_splice  io_uring IORING_OP_SPLICE  zero-copy, but io-wq offloaded
#   iouring_rw      io_uring recv/send         copy-based, fast-poll path
#
# across the routing + kTLS splice paths, a 1/4/16/64-connection sweep and 64B/16KB/256KB
# sizes, with two metric passes:
#   procfs  — throughput + context switches (the headline; ctxsw exposes the io-wq penalty)
#   ebpf    — per-message syscalls: mem_io_uring_enter vs mem_splice_syscalls/mem_poll_syscalls
#
# MUST be run as root: the eBPF (bpftrace) pass needs it. Cargo builds are run as the
# invoking user so target/ ownership is preserved. Results + an aggregate.csv + a summary
# table land under SCG-SESHAT/results/relay-backend-ab-<timestamp>/.
#
# Quick pass (a few minutes) instead of the full sweep:
#   RUNS=1 DURATION=2 sudo -E ./scripts/run_relay_backend_ab.sh
# Narrow scope, e.g. routing only:
#   SCEN_GREP=routing sudo -E ./scripts/run_relay_backend_ab.sh
# Add the perf (cycles/IPC) pass:
#   METRICS="procfs perf ebpf" sudo -E ./scripts/run_relay_backend_ab.sh
#
set -uo pipefail

# ── configuration (all overridable via the environment) ───────────────────────
SESHAT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JANUS="${JANUS:-$(cd "$SESHAT/.." && pwd)}"
SCG="${SCG_DIR:-$JANUS/SCG}"
RUN_USER="${SUDO_USER:-$(stat -c %U "$SESHAT" 2>/dev/null || echo "$USER")}"
CONFIG="${CONFIG:-$SESHAT/configs/relay_backend_ab.json}"
BACKENDS="${BACKENDS:-splice readwrite iouring_splice iouring_rw}"
METRICS="${METRICS:-procfs ebpf}"          # subset of: procfs perf ebpf
RUNS="${RUNS:-3}"
DURATION="${DURATION:-5}"
WARMUP="${WARMUP:-2}"
SCEN_GREP="${SCEN_GREP:-.}"                 # regex filter over scenario names
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$SESHAT/results/relay-backend-ab-$STAMP}"

die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (the eBPF pass needs it):  sudo -E $0"
[ -f "$CONFIG" ] || die "config not found: $CONFIG"
command -v python3 >/dev/null || die "python3 required"

run_as_user() { sudo -u "$RUN_USER" bash -lc "source ~/.cargo/env 2>/dev/null; $1"; }

# ── build (as the invoking user, so target/ stays user-owned) ─────────────────
echo "== building gateway (release, io_uring feature) + seshat as user '$RUN_USER' =="
run_as_user "cd '$SCG' && cargo build -p gateway --release --features io_uring" \
    || die "gateway build failed"
run_as_user "cd '$SESHAT' && cargo build --release" || die "seshat build failed"

GW="$SCG/target/release/gateway"
SESHAT_BIN="$SESHAT/target/release/seshat"
[ -x "$GW" ] || die "gateway binary missing: $GW"
[ -x "$SESHAT_BIN" ] || die "seshat binary missing: $SESHAT_BIN"
export SCG_GATEWAY_BIN="$GW"

# ── tool availability ─────────────────────────────────────────────────────────
have_bpftrace=1; command -v bpftrace >/dev/null || have_bpftrace=0
have_perf=1;     command -v perf     >/dev/null || have_perf=0

# ── scenario list ─────────────────────────────────────────────────────────────
mapfile -t SCENARIOS < <(python3 -c "
import json, re
for s in json.load(open('$CONFIG'))['scenarios']:
    if re.search('$SCEN_GREP', s['name']): print(s['name'])
")
[ "${#SCENARIOS[@]}" -gt 0 ] || die "no scenarios matched SCEN_GREP='$SCEN_GREP'"

nbe=$(echo "$BACKENDS" | wc -w)
nmet=$(echo "$METRICS" | wc -w)
TOTAL=$(( ${#SCENARIOS[@]} * nbe * nmet ))
est_min=$(( TOTAL * (RUNS*DURATION + WARMUP + 4) / 60 ))
echo "== plan =="
echo "   scenarios : ${#SCENARIOS[@]}   backends: $BACKENDS   metrics: $METRICS"
echo "   per run   : runs=$RUNS duration=${DURATION}s warmup=${WARMUP}s"
echo "   total     : $TOTAL scenario-runs  (~${est_min} min rough)"
echo "   output    : $OUT"
[ $have_bpftrace -eq 0 ] && echo "   NOTE: bpftrace not found — the ebpf pass will be skipped"
[ $have_perf -eq 0 ]     && echo "   NOTE: perf not found — the perf pass will be skipped"
mkdir -p "$OUT"

# ── run ───────────────────────────────────────────────────────────────────────
i=0
for m in $METRICS; do
    mflag=""
    case "$m" in
        procfs) mflag="" ;;
        ebpf)   [ $have_bpftrace -eq 1 ] || { echo "== skip metric=ebpf (no bpftrace) =="; continue; }; mflag="--metrics-backend ebpf" ;;
        perf)   [ $have_perf -eq 1 ]     || { echo "== skip metric=perf (no perf) =="; continue; };     mflag="--metrics-backend perf" ;;
        *)      echo "== skip unknown metric='$m' =="; continue ;;
    esac
    for be in $BACKENDS; do
        for s in "${SCENARIOS[@]}"; do
            i=$((i+1))
            od="$OUT/$m/$be/$s"
            mkdir -p "$od"
            printf '[%d/%d] metric=%s backend=%-14s scenario=%s\n' "$i" "$TOTAL" "$m" "$be" "$s"
            SCG_RELAY_BACKEND="$be" "$SESHAT_BIN" run \
                --config "$CONFIG" --scenario "$s" $mflag \
                --runs "$RUNS" --duration "$DURATION" --warmup "$WARMUP" \
                --output-dir "$od" --quiet >"$od/run.log" 2>&1 \
                || echo "     (scenario failed — see $od/run.log; continuing)"
        done
    done
done

# ── aggregate + verdict table ─────────────────────────────────────────────────
echo "== aggregating =="
python3 - "$OUT" <<'PY'
import csv, glob, os, sys
from collections import defaultdict
out = sys.argv[1]
rows = []
for f in glob.glob(os.path.join(out, "*", "*", "*", "*", "summary.csv")):
    rel = os.path.relpath(f, out).split(os.sep)
    if len(rel) < 5:
        continue
    metric, backend, scenario = rel[0], rel[1], rel[2]
    try:
        r = next(csv.DictReader(open(f)))
    except Exception:
        continue
    if "throughput_gbps_mean" not in r:
        continue
    # io-wq diagnostics from the per-PID timeseries (why io_uring is slow / whether
    # it can be improved): voluntary vs involuntary context switches distinguishes
    # blocking/io-wq waits from CPU preemption, and the peak thread count exposes
    # io-wq worker proliferation. Cumulative counters → take the max sample.
    vol = nonv = thr = ""
    ts_dir = os.path.dirname(f)
    vmax = nmax = tmax = None
    for pc in glob.glob(os.path.join(ts_dir, "scenarios", "*", "system_metrics", "gateway_pid_*.csv")):
        try:
            for prow in csv.DictReader(open(pc)):
                for key, tag in (("voluntary_ctxt_switches", "v"),
                                 ("nonvoluntary_ctxt_switches", "n"),
                                 ("threads", "t")):
                    try:
                        iv = float(prow.get(key, ""))
                    except (TypeError, ValueError):
                        continue
                    if tag == "v":
                        vmax = iv if vmax is None else max(vmax, iv)
                    elif tag == "n":
                        nmax = iv if nmax is None else max(nmax, iv)
                    else:
                        tmax = iv if tmax is None else max(tmax, iv)
        except Exception:
            pass
    if vmax is not None: vol = "%d" % vmax
    if nmax is not None: nonv = "%d" % nmax
    if tmax is not None: thr = "%d" % tmax
    rows.append(dict(
        metric=metric, backend=backend, scenario=scenario,
        throughput_gbps=r.get("throughput_gbps_mean", ""),
        throughput_ci95=r.get("throughput_gbps_ci95", ""),
        ctx_switches=r.get("ctx_switches_total", ""),
        vol_ctxsw=vol, nonvol_ctxsw=nonv, peak_threads=thr,
        harness_limited=r.get("harness_limited", ""),
        latency_p99_us=r.get("latency_p99_us_mean", ""),
        mem_splice=r.get("mem_splice_syscalls", ""),
        mem_poll=r.get("mem_poll_syscalls", ""),
        mem_io_uring_enter=r.get("mem_io_uring_enter", ""),
        perf_cycles=r.get("perf_cycles", ""),
        perf_ipc=r.get("perf_ipc", ""),
    ))
if not rows:
    print("no summaries found under", out); sys.exit(0)
agg = os.path.join(out, "aggregate.csv")
with open(agg, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)
print("wrote", agg, "(%d rows)" % len(rows))

def fnum(x):
    try: return float(x)
    except Exception: return None

# procfs verdict + io-wq diagnostics (the "can io_uring be improved" signals)
piv = defaultdict(lambda: defaultdict(list))
for r in rows:
    if r["metric"] != "procfs": continue
    for k, col in (("tput", "throughput_gbps"), ("ctx", "ctx_switches"), ("p99", "latency_p99_us"),
                   ("vol", "vol_ctxsw"), ("nonvol", "nonvol_ctxsw"), ("thr", "peak_threads")):
        v = fnum(r[col])
        if v is not None: piv[r["backend"]][k].append(v)
order = ["splice", "readwrite", "iouring_splice", "iouring_rw"]
def mean(xs): return sum(xs)/len(xs) if xs else 0.0
print("\n== procfs verdict + io-wq diagnostics (mean over %d scenarios) ==" % len({r['scenario'] for r in rows if r['metric']=='procfs'}))
print("%-16s %10s %13s %8s %10s %8s" % ("backend", "tput Gb/s", "ctx_switches", "p99 us", "vol_ctx%", "threads"))
for be in order:
    if be in piv:
        d = piv[be]
        vol, nonvol = mean(d["vol"]), mean(d["nonvol"])
        volpct = 100.0 * vol / (vol + nonvol) if (vol + nonvol) > 0 else 0.0
        print("%-16s %10.2f %13.0f %8.1f %10.1f %8.0f" % (
            be, mean(d["tput"]), mean(d["ctx"]), mean(d["p99"]), volpct, mean(d["thr"])))
print("  vol_ctx% near 100 + many threads => io-wq blocking dominates (the io_uring splice")
print("  overhead is structural, not CPU contention); low threads => fast-poll path, no io-wq.")

# scaling: does the io_uring penalty shrink with concurrency? (batching headroom)
import re
def conns(name):
    m = re.search(r"_(\d+)c$", name)
    return int(m.group(1)) if m else None
by_cc = defaultdict(lambda: defaultdict(list))
for r in rows:
    if r["metric"] != "procfs": continue
    cc, c = conns(r["scenario"]), fnum(r["ctx_switches"])
    if cc is not None and c is not None: by_cc[cc][r["backend"]].append(c)
if by_cc:
    print("\n== scaling: ctx_switches relative to poll+splice, by connection count ==")
    print("  a SHRINKING iouring_splice ratio as connections rise => a shared-ring / batched")
    print("  design would reclaim it; a flat/high ratio => per-connection io-wq cost is the wall.")
    print("%-8s %12s %16s %12s" % ("conns", "readwrite", "iouring_splice", "iouring_rw"))
    for cc in sorted(by_cc):
        base = mean(by_cc[cc].get("splice", []))
        def ratio(be):
            v = by_cc[cc].get(be, [])
            return "%.2fx" % (mean(v) / base) if v and base > 0 else "  -"
        print("%-8d %12s %16s %12s" % (cc, ratio("readwrite"), ratio("iouring_splice"), ratio("iouring_rw")))

# ebpf syscall verdict
esys = defaultdict(lambda: defaultdict(list))
for r in rows:
    if r["metric"] != "ebpf": continue
    for k, col in (("splice", "mem_splice"), ("poll", "mem_poll"), ("uring", "mem_io_uring_enter")):
        v = fnum(r[col])
        if v is not None: esys[r["backend"]][k].append(v)
if esys:
    print("\n== ebpf syscalls (mean total over run) ==")
    print("%-16s %14s %12s %16s" % ("backend", "splice", "poll", "io_uring_enter"))
    for be in order:
        if be in esys:
            s, p, u = esys[be]["splice"], esys[be]["poll"], esys[be]["uring"]
            print("%-16s %14.0f %12.0f %16.0f" % (
                be, sum(s)/len(s) if s else 0, sum(p)/len(p) if p else 0, sum(u)/len(u) if u else 0))
print()
PY

# ── hand results back to the user ─────────────────────────────────────────────
chown -R "$RUN_USER":"$RUN_USER" "$OUT" 2>/dev/null || true
echo "== done =="
echo "raw runs + aggregate.csv: $OUT"
echo "next: point seshat-viz at $OUT (backend factor) for the figures."
