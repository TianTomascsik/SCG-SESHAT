#!/usr/bin/env bash
# Re-run the RE-RUNNABLE skipped scenarios of a completed SESHAT run and merge the
# recovered results back into that run's consolidated report.
#
#   scripts/rerun_missing.sh <master-run-dir> [tcp|tproxy|all]
#
# Which skips are re-runnable (see the 2026-07-07 skip taxonomy of run
# 20260705-011302-procfs; 448 skips total):
#   tcp     54  matrix_integrity_tls13_tcp_tcp_* (+matrix_lat_) — TCP accept-window timeouts,
#               genuinely transient. NO root needed. This is the default.
#   tproxy  60  matrix_integrity_tls13_tproxy_tproxy_* (+matrix_lat_) + matrix_routing_tproxy_*_64c
#               — "gateway did not forward". Need root + CAP_NET_ADMIN + iptables TPROXY rules
#               (run the whole script under sudo, with the TPROXY divert rules already in place).
#   shmuds ~154 previously zero-metric multi-connection SHM/UDS crypto scenarios, fixed by the
#               connection-aware UDS/SHM transport (distinct app_id + upstream port per connection).
#               Requires the REBUILT gateway binary: export SCG_GATEWAY_BIN=<repo>/SCG/target/release/gateway.
#               NB: integrity×TLS1.3 SHM/UDS is NOT here — it is excluded from the matrix (impossible).
#   all         tcp + tproxy (not shmuds; run shmuds explicitly).
# NOT re-run (permanent / would hang): the 51 by-design DTLS/UDP RTT skips and the 283 SHM/UDS
# zero-metric skips (108 of which — integrity×TLS1.3 SHM/UDS — DEADLOCK). Those are handled by
# the separate SHM/UDS fix, not by re-running.
#
# The re-run goes into a FRESH --output-dir on purpose: `suite --resume` treats a per-scenario
# skip.csv as "already recorded" and would re-skip these, never retrying them.
set -uo pipefail

SESHAT="${SESHAT:-<repo>/SCG-SESHAT}"
BIN="${SCG_SESHAT_BIN:-$SESHAT/target/release/seshat}"
MASTER_CFG="$SESHAT/configs/full_matrix.json"

RUN="${1:?usage: rerun_missing.sh <master-run-dir> [tcp|tproxy|all]}"
WHICH="${2:-tcp}"
[[ -f "$RUN/skipped.csv" ]] || { echo "FATAL: $RUN/skipped.csv not found"; exit 1; }
[[ -x "$BIN" ]] || { echo "FATAL: seshat binary not found at $BIN (build it or set SCG_SESHAT_BIN)"; exit 1; }

TS="$(date +%Y%m%d-%H%M%S)"
FRESH="$SESHAT/results/$TS-rerun"
ONEOFF="/tmp/rerun_${WHICH}_${TS}.json"

# 1. Select scenario names present in this run's skipped.csv AND in the re-runnable set,
#    then emit a one-off suite config carrying exactly those scenario objects from the matrix.
python3 - "$RUN/skipped.csv" "$MASTER_CFG" "$WHICH" "$ONEOFF" <<'PY'
import csv, json, sys
skipped_csv, master, which, out = sys.argv[1:5]
skipped = {r["scenario"] for r in csv.DictReader(open(skipped_csv))}

def is_tcp(n):
    return n.startswith("matrix_integrity_tls13_tcp_tcp_") or \
           n.startswith("matrix_lat_integrity_tls13_tcp_tcp_")

def is_tproxy(n):
    return ("_tproxy_tproxy_" in n and "integrity_tls13" in n) or \
           (n.startswith("matrix_routing_tproxy_") and n.endswith("_64c"))

def is_shmuds(n):
    # Multi-connection SHM/UDS zero-metric scenarios fixed by the connection-aware
    # transport. integrity×TLS1.3 is excluded from the matrix (impossible), so it
    # will not appear here anyway.
    return ("_shm_shm_" in n or "_uds_unix_" in n) and "integrity_tls13" not in n

def rerunnable(n):
    return {"tcp": is_tcp(n), "tproxy": is_tproxy(n), "shmuds": is_shmuds(n),
            "all": is_tcp(n) or is_tproxy(n)}.get(which, False)

want = {n for n in skipped if rerunnable(n)}
full = json.load(open(master))
picked = [s for s in full["scenarios"] if s.get("name") in want]
json.dump({"suite": {**full.get("suite", {}), "description": f"re-run missing ({which})"},
           "defaults": full["defaults"], "scenarios": picked},
          open(out, "w"), indent=2)
missing = sorted(want - {s.get("name") for s in picked})
print(f"selected {len(picked)}/{len(want)} skipped '{which}' scenario(s) -> {out}")
if missing:
    print(f"  WARNING: {len(missing)} wanted name(s) not in {master} (matrix drift): {missing[:5]}...")
PY
[[ -s "$ONEOFF" ]] || { echo "FATAL: no scenarios selected"; exit 1; }

# 2. Run into a FRESH dir with a longer warmup (the TCP failures are accept-window timeouts).
echo "== re-running into $FRESH =="
"$BIN" suite --config "$ONEOFF" --warmup 3s --output-dir "$FRESH" \
  || echo "WARN: re-run suite exited non-zero (partial recovery may still be usable)"

# 3. Merge the RECOVERED scenarios (now have summary.csv and no skip.csv) into the master tree.
merged=0
shopt -s nullglob
for d in "$FRESH"/*/scenarios/*/; do
  name="$(basename "$d")"
  if [[ -f "$d/summary.csv" && ! -f "$d/skip.csv" ]]; then
    rm -rf "$RUN/scenarios/$name"
    cp -a "$d" "$RUN/scenarios/$name"
    merged=$((merged + 1))
  fi
done
echo "== merged $merged recovered scenario(s) into $RUN/scenarios/ =="

# 4. Rebuild the consolidated summary.csv / skipped.csv from the per-scenario files.
"$BIN" report --input "$RUN"
echo "== done: re-count skips with:  wc -l < '$RUN/skipped.csv' =="
