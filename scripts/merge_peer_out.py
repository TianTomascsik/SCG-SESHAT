#!/usr/bin/env python3
"""Merge the peer machine's sink reports into a wire campaign's summary CSV.

The wire benchmark measures on host A only, so every wire row of
``wire_summary.csv`` is sender-side: ``delivered_gbps``, ``loss_pct``,
``total_lost`` and the DSCP columns are empty until the peer's ``peer-out/``
directory comes back. The peer's long-lived sinks write one JSON line per
traffic *burst* (``sink-bulk.jsonl`` for the TCP path, ``sink-dgram.jsonl`` for
the UDP path), bursts being separated by >=1.5 s of silence — which is how a
cell boundary looks from the far side, because there is deliberately no control
channel between the hosts.

Alignment is therefore positional: burst k is the k-th cell that drove that
sink. That is also the failure mode — a cell that produced no traffic writes no
burst, and everything after it would silently shift by one. This tool refuses
to merge unless every aligned pair's byte counts corroborate:

  * TCP: sink bytes must match the sender's ``sent_bytes`` within 5 % (the
    stream backpressures, so they can only differ by in-flight buffers);
  * UDP: the sink's window includes warmup and losses are legitimate, so only
    a sanity band applies — but a sink can never have received MORE than the
    sender sent (ratio > 1.05 means mis-alignment, hard refuse).

On success it writes ``wire_summary_merged.csv`` NEXT TO the original (never
overwriting it; seshat-viz prefers the merged file automatically) with the
delivered/loss/DSCP columns filled and ``link_limited``/``bottleneck``
recomputed by the same rule ``wire_bench.sh`` uses.

Usage:
    python3 scripts/merge_peer_out.py --results-dir results/wire-run \
            --peer-out /path/to/peer-out [--out wire_summary_merged.csv] [--force]
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

# Which cells drive which peer sink, in CSV (= execution) order.
_BULK_CELL_RE = re.compile(r"^(qos-(safety|normal)-contended|tput-|sweep-tcp-)")
_DGRAM_CELL_RE = re.compile(r"^(dtls-dgram|sweep-udp-)")

# The link-limited rule, mirroring wire_bench.sh's emit_row.
_LINK_LIMITED_FRACTION = 0.90


def _read_rows(csv_path: Path) -> tuple[list[dict], list[str]]:
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader), list(reader.fieldnames or [])


def _read_jsonl(path: Path) -> list[dict]:
    records = []
    if not path.is_file():
        return records
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except ValueError as exc:
            raise SystemExit(f"error: torn record in {path}: {exc}")
    return records


def _sender_bytes(results_dir: Path, scenario: str, row: dict) -> tuple[float | None, str]:
    """Best available sender-side byte count for one cell, with its source label."""
    sidecar = results_dir / "work" / f"{scenario}.send.json"
    if sidecar.is_file():
        try:
            data = json.loads(sidecar.read_text())
            if "sent_bytes" in data:
                return float(data["sent_bytes"]), "send.json"
        except (OSError, ValueError):
            pass
    # Paced cells without a sidecar: offered rate x window is the design intent.
    try:
        offered = float(row.get("offered_mbps") or 0)
        # measure window is not in the CSV; warn-level estimate only.
        if offered > 0:
            return None, "estimate-unavailable"
    except ValueError:
        pass
    return None, "unavailable"


def _align(
    label: str,
    cells: list[tuple[int, dict]],
    bursts: list[dict],
    results_dir: Path,
    is_udp: bool,
) -> list[tuple[int, dict, dict]]:
    """Pair (row-index, row) cells with burst records, refusing on any doubt."""
    if len(cells) != len(bursts):
        print(f"\n{label}: burst-count mismatch — {len(bursts)} burst record(s) "
              f"for {len(cells)} traffic-bearing cell(s).", file=sys.stderr)
        print("expected cell sequence:", file=sys.stderr)
        for _, row in cells:
            print(f"  {row['scenario']}", file=sys.stderr)
        print("burst records:", file=sys.stderr)
        for b in bursts:
            print(f"  burst={b.get('burst')} count={b.get('count')} bytes={b.get('bytes')}",
                  file=sys.stderr)
        raise SystemExit(
            f"error: cannot align {label} — a zero-traffic cell on either side "
            "shifts every later record; refusing to guess."
        )

    aligned = []
    problems = []
    table = []
    for (idx, row), burst in zip(cells, bursts):
        scenario = row["scenario"]
        sender, source = _sender_bytes(results_dir, scenario, row)
        sink = float(burst.get("bytes") or 0)
        ratio = (sink / sender) if sender else None
        table.append((scenario, sender, sink, ratio, source))
        if ratio is None:
            print(f"  warn: {scenario}: no sender byte count ({source}); "
                  "alignment unverified for this cell", file=sys.stderr)
        elif is_udp:
            if ratio > 1.05:
                problems.append((scenario, ratio, "sink received more than sender sent"))
            elif not 0.5 <= ratio <= 1.05:
                print(f"  warn: {scenario}: sink/sender byte ratio {ratio:.3f} outside "
                      "[0.5, 1.05] (heavy loss or window mismatch)", file=sys.stderr)
        else:
            if abs(ratio - 1.0) > 0.05:
                problems.append((scenario, ratio, "TCP byte counts disagree > 5%"))
        aligned.append((idx, row, burst))

    if problems:
        print(f"\n{label}: aligned table (cell, sender bytes, sink bytes, ratio):",
              file=sys.stderr)
        for scenario, sender, sink, ratio, source in table:
            mark = " <-- MISMATCH" if any(p[0] == scenario for p in problems) else ""
            print(f"  {scenario:28} {sender or '-':>14} {sink:>14.0f} "
                  f"{f'{ratio:.3f}' if ratio else '-':>7} [{source}]{mark}", file=sys.stderr)
        raise SystemExit(
            f"error: {label} alignment rejected — the sequences appear shifted; "
            "nothing was written."
        )
    return aligned


def merge(results_dir: Path, peer_out: Path, out_name: str, force: bool) -> Path:
    csv_path = results_dir / "wire_summary.csv"
    if not csv_path.is_file():
        raise SystemExit(f"error: {csv_path} not found")
    out_path = results_dir / out_name
    if out_path.exists() and not force:
        raise SystemExit(f"error: {out_path} exists; pass --force to replace it")

    rows, fieldnames = _read_rows(csv_path)

    bulk_cells = [(i, r) for i, r in enumerate(rows) if _BULK_CELL_RE.match(r["scenario"])]
    dgram_cells = [(i, r) for i, r in enumerate(rows) if _DGRAM_CELL_RE.match(r["scenario"])]
    bulk_bursts = _read_jsonl(peer_out / "sink-bulk.jsonl")
    dgram_bursts = _read_jsonl(peer_out / "sink-dgram.jsonl")

    if not bulk_bursts and not dgram_bursts:
        raise SystemExit(f"error: no sink-*.jsonl records under {peer_out}")

    merged = 0
    ceiling = None
    for pairs, is_udp in (
        (_align("sink-bulk (TCP)", bulk_cells, bulk_bursts, results_dir, False)
         if bulk_bursts else [], False),
        (_align("sink-dgram (UDP)", dgram_cells, dgram_bursts, results_dir, True)
         if dgram_bursts else [], True),
    ):
        for idx, row, burst in pairs:
            row["delivered_gbps"] = f"{float(burst['delivered_gbps']):.6f}"
            row["loss_pct"] = f"{float(burst.get('loss_pct', 0)):.4f}"
            row["total_lost"] = str(int(burst.get("lost", 0)))
            if is_udp:
                if "dscp_observed" in burst:
                    row["dscp_observed"] = str(int(burst["dscp_observed"]))
                    row["dscp_matched"] = str(int(burst["dscp_matched"]))
                if "dscp_preserved" in burst:  # tri-state: absent stays absent
                    row["dscp_preserved"] = "true" if burst["dscp_preserved"] else "false"
            # link_limited / bottleneck, per the wire_bench.sh rule.
            try:
                ceiling = float(row.get("ceiling_gbps") or 0)
            except ValueError:
                ceiling = 0
            if row.get("medium", row.get("mode")) == "wire" and ceiling:
                limited = float(burst["delivered_gbps"]) >= _LINK_LIMITED_FRACTION * ceiling
                row["link_limited"] = "true" if limited else "false"
                row["bottleneck"] = "link" if limited else "unclassified"
            merged += 1
            print(f"  merged {row['scenario']:28} delivered={row['delivered_gbps']} "
                  f"loss={row['loss_pct']}%")

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nwrote {out_path} ({merged} cell(s) merged; original untouched)")
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--results-dir", required=True, type=Path,
                        help="campaign dir holding wire_summary.csv (e.g. results/wire-run)")
    parser.add_argument("--peer-out", required=True, type=Path,
                        help="the peer's peer-out/ directory (copied back from the far host)")
    parser.add_argument("--out", default="wire_summary_merged.csv",
                        help="output file name inside the results dir")
    parser.add_argument("--force", action="store_true",
                        help="replace an existing merged file")
    args = parser.parse_args(argv)
    merge(args.results_dir, args.peer_out, args.out, args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
