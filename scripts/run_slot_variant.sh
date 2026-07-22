#!/usr/bin/env bash
# Run the SHM fixed-slot-ring variant scenarios and merge them into an existing
# campaign run, so seshat-viz draws a distinct "SHM (slot)" series next to the
# default byte-stream SHM in every transport-keyed figure (F2/F3/F15/F16/...).
#
#   scripts/run_slot_variant.sh [master-run-dir]
#
# The slot scenarios (matrix_*_shmslot_*) come from the regenerated matrix, so FIRST:
#   seshat matrix generate --spec configs/matrix_spec.json --out-dir configs
# and export SCG_GATEWAY_BIN=<repo>/SCG/target/release/gateway. The `tls` kernel
# module must be loaded for the kTLS slot profiles (sudo modprobe tls).
#
# It runs into a FRESH results/<ts>-slot dir (NOT --resume), then merges the
# recovered scenario dirs into the campaign by basename (names are disjoint from
# the campaign, so the merge is purely additive), and forces the consolidated
# summary.csv/skipped.csv rebuild (`seshat report` only rebuilds when summary.csv
# is absent). Mirrors scripts/rerun_missing.sh.
#
# NOTE: this is the FULL 540-scenario slot mirror (~4-5 h real; the printed
# estimate undercounts ~3-4x). To run a faster subset, narrow $FILTER below
# (e.g. 'routing_shmslot|tls13_shmslot|ktls_shmslot').
set -uo pipefail

SESHAT="${SESHAT:-<repo>/SCG-SESHAT}"
BIN="${SCG_SESHAT_BIN:-$SESHAT/target/release/seshat}"
FULL="$SESHAT/configs/full_matrix.json"
FILTER="${SLOT_FILTER:-shmslot}"   # scenario-name substring selecting the slot rows
RUN="${1:-$SESHAT/results/20260717-002659-thesis-procfs/20260716-222659}"

[[ -x "$BIN" ]] || { echo "FATAL: seshat binary not found at $BIN (build it or set SCG_SESHAT_BIN)"; exit 1; }
[[ -f "$FULL" ]] || { echo "FATAL: $FULL not found — run 'seshat matrix generate' first"; exit 1; }
[[ -f "$RUN/summary.csv" || -d "$RUN/scenarios" ]] || { echo "FATAL: master run $RUN not found"; exit 1; }
: "${SCG_GATEWAY_BIN:?export SCG_GATEWAY_BIN=<repo>/SCG/target/release/gateway}"

TS="$(date +%Y%m%d-%H%M%S)"
FRESH="$SESHAT/results/$TS-slot"
ONEOFF="/tmp/slot_${TS}.json"

# 1. Select the matrix slot scenarios into a one-off suite config.
python3 - "$FULL" "$FILTER" "$ONEOFF" <<'PY'
import json, sys
full, flt, out = sys.argv[1], sys.argv[2], sys.argv[3]
doc = json.load(open(full))
picked = [s for s in doc["scenarios"] if flt in s.get("name", "")]
json.dump({"suite": {**doc.get("suite", {}), "description": f"SHM slot-ring variant ({flt})"},
           "defaults": doc["defaults"], "scenarios": picked},
          open(out, "w"), indent=2)
print(f"selected {len(picked)} slot scenario(s) matching '{flt}' -> {out}")
PY
[[ -s "$ONEOFF" ]] || { echo "FATAL: no scenarios selected"; exit 1; }

# 2. Run into a FRESH dir (procfs backend = campaign default; 3s warmup like rerun_missing.sh).
echo "== running slot variant into $FRESH =="
"$BIN" suite --config "$ONEOFF" --warmup 3s --output-dir "$FRESH" \
  || echo "WARN: suite exited non-zero (partial recovery may still be usable)"

# 3. Merge the RECOVERED scenarios (summary.csv, no skip.csv) into the master tree.
merged=0
shopt -s nullglob
for d in "$FRESH"/*/scenarios/*/; do
  name="$(basename "$d")"
  [[ -n "$name" && "$name" != "scenarios" ]] || { echo "SKIP bad dir: $d"; continue; }
  if [[ -f "$d/summary.csv" && ! -f "$d/skip.csv" ]]; then
    rm -rf "$RUN/scenarios/$name"
    cp -a "$d" "$RUN/scenarios/$name"
    merged=$((merged + 1))
  fi
done
echo "== merged $merged recovered slot scenario(s) into $RUN/scenarios/ =="

# 4. Force the consolidated rebuild (report only rebuilds when summary.csv is ABSENT).
rm -f "$RUN/summary.csv" "$RUN/skipped.csv"
"$BIN" report --input "$RUN"
echo "== done. slot rows now in $RUN/summary.csv."
echo "   Re-export figures:  seshat-viz/scripts/export_thesis_figures.sh '$RUN'"
echo "   Then RE-RESTORE F9 from the ebpf run (the export overwrites eval_memory)."