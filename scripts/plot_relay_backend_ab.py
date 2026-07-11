#!/usr/bin/env python3
"""Render the 4-panel relay-backend A/B figure for the thesis (Ch. 8).

Reads two SESHAT result trees (no hardcoded numbers) and emits a 2x2 figure:

  A  routing throughput by message size          (procfs run, unperturbed)
  B  peak io-wq worker threads vs connections     (procfs run)
  C  context switches vs connections              (procfs run)
  D  system calls per message by size             (eBPF run, syscall counts)

Panels A/B/C use the procfs pass because eBPF tracing depresses throughput a
few percent. Panel D needs the eBPF pass, which is the only one that carries the
per-syscall counters. read()/write() are outside the eBPF probe set
(mem_syscalls.bt counts sendmsg/recvmsg/splice/poll/ppoll/io_uring_enter), so
the copying poll+read/write backend cannot be shown fairly on panel D and is
omitted there; the zero-copy pair (splice vs io_uring-splice) and io_uring
recv/send are fully counted.

Usage:
  plot_relay_backend_ab.py [PROCFS_DIR] [EBPF_DIR] [OUT_PNG]
"""
import csv
import glob
import os
import sys
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

# ── inputs ──────────────────────────────────────────────────────────────────
PROCFS_DIR = sys.argv[1] if len(sys.argv) > 1 else \
    "results/relay-backend-ab-20260710-085539"
EBPF_DIR = sys.argv[2] if len(sys.argv) > 2 else \
    "results/relay-backend-ab-20260710-214450"
OUT_PNG = sys.argv[3] if len(sys.argv) > 3 else \
    "results/relay-backend-ab-figs/relay_backend_ab.png"

# ── identity: fixed backend order + CVD-safe Okabe-Ito palette (validated) ────
BACKENDS = ["splice", "readwrite", "iouring_splice", "iouring_rw"]
LABEL = {
    "splice": "poll+splice",
    "readwrite": "poll+read/write",
    "iouring_splice": "io_uring splice",
    "iouring_rw": "io_uring recv/send",
}
COLOR = {
    "splice": "#0072B2",          # blue  (shipped baseline)
    "readwrite": "#009E73",       # green (copy baseline)
    "iouring_splice": "#D55E00",  # vermilion (the rejected zero-copy variant)
    "iouring_rw": "#CC79A7",      # purple (copy io_uring)
}
SIZES = [("64B", 64), ("16KB", 16384), ("256KB", 262144)]
CONNS = [1, 4, 16, 64]


def parse_scenario(name):
    """relaybackend_<path>_tcp_<size>_<conns>c -> (path, size, conns)."""
    parts = name.split("_")
    # parts: relaybackend, <path>, tcp, <size>, <conns>c
    path = parts[1]
    size = parts[3]
    conns = int(parts[4].rstrip("c"))
    return path, size, conns


def load_aggregate(path, metric):
    """Return list of dicts for rows whose metric column == metric."""
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if r["metric"] == metric:
                rows.append(r)
    return rows


def fnum(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return float("nan")


# ── load procfs rows (A/B/C) ──────────────────────────────────────────────────
procfs = load_aggregate(os.path.join(PROCFS_DIR, "aggregate.csv"), "procfs")
# ── load eBPF rows (D, syscall counters) ──────────────────────────────────────
ebpf = load_aggregate(os.path.join(EBPF_DIR, "aggregate.csv"), "ebpf")

# messages per scenario from the eBPF run's runs.csv (authoritative count)
msgs_by_scen = defaultdict(float)
for rc in glob.glob(os.path.join(EBPF_DIR, "ebpf", "*", "*", "*",
                                 "scenarios", "*", "runs.csv")):
    scen = os.path.basename(os.path.dirname(rc))
    with open(rc, newline="") as f:
        for r in csv.DictReader(f):
            msgs_by_scen[scen] += fnum(r.get("messages"))

# ── Panel A: routing throughput by size (mean over conns) ─────────────────────
thr = defaultdict(list)  # (backend, size) -> [gbps]
for r in procfs:
    p, s, c = parse_scenario(r["scenario"])
    if p == "routing":
        thr[(r["backend"], s)].append(fnum(r["throughput_gbps"]))
thrA = {k: np.mean(v) for k, v in thr.items()}

# ── Panel B/C: threads + ctxsw vs conns (mean over all sizes+paths) ───────────
threads = defaultdict(list)  # (backend, conns) -> [peak_threads]
ctxsw = defaultdict(list)    # (backend, conns) -> [ctx_switches]
for r in procfs:
    p, s, c = parse_scenario(r["scenario"])
    threads[(r["backend"], c)].append(fnum(r["peak_threads"]))
    ctxsw[(r["backend"], c)].append(fnum(r["ctx_switches"]))
threadsB = {k: np.mean(v) for k, v in threads.items()}
ctxswC = {k: np.mean(v) for k, v in ctxsw.items()}

# ── Panel D: syscalls per message by size (eBPF, all paths pooled) ────────────
sysc = defaultdict(float)  # (backend, size) -> summed syscalls
msgs = defaultdict(float)  # (backend, size) -> summed messages
for r in ebpf:
    p, s, c = parse_scenario(r["scenario"])
    b = r["backend"]
    if b == "splice":
        n = fnum(r["mem_splice"]) + fnum(r["mem_poll"])
    else:  # iouring_* driven through io_uring_enter; readwrite handled below
        n = fnum(r["mem_io_uring_enter"])
    if not np.isnan(n):
        sysc[(b, s)] += n
    msgs[(b, s)] += msgs_by_scen.get(r["scenario"], 0.0)
D_BACKENDS = ["splice", "iouring_splice", "iouring_rw"]  # readwrite: r/w uncounted
syscD = {}
for b in D_BACKENDS:
    for s, _ in SIZES:
        m = msgs.get((b, s), 0.0)
        syscD[(b, s)] = (sysc.get((b, s), 0.0) / m) if m else float("nan")

# ── report (verification) ─────────────────────────────────────────────────────
print("== Panel A routing throughput Gb/s (mean over conns) ==")
for b in BACKENDS:
    print(f"  {b:16s} " + "  ".join(f"{s}={thrA.get((b, s), float('nan')):6.1f}"
                                     for s, _ in SIZES))
print("== Panel B peak threads by conns ==")
for b in BACKENDS:
    print(f"  {b:16s} " + "  ".join(f"{c}c={threadsB.get((b, c), float('nan')):6.1f}"
                                    for c in CONNS))
print("== Panel C ctx switches by conns (millions) ==")
for b in BACKENDS:
    print(f"  {b:16s} " + "  ".join(f"{c}c={ctxswC.get((b, c), float('nan'))/1e6:6.2f}"
                                    for c in CONNS))
print("== Panel D syscalls per message by size ==")
for b in D_BACKENDS:
    print(f"  {b:16s} " + "  ".join(f"{s}={syscD.get((b, s), float('nan')):7.3f}"
                                    for s, _ in SIZES))

# ── plot ──────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    "font.size": 11, "axes.titlesize": 12, "axes.titleweight": "bold",
    "axes.grid": True, "grid.alpha": 0.25, "axes.axisbelow": True,
    "figure.dpi": 150,
})
fig, axes = plt.subplots(2, 2, figsize=(13.0, 9.2))
(axA, axB), (axC, axD) = axes


def grouped_bars(ax, groups, backends, value, ylabel, title, logy=False,
                 label_fmt="{:.0f}"):
    x = np.arange(len(groups))
    w = 0.8 / len(backends)
    for i, b in enumerate(backends):
        vals = [value.get((b, g), float("nan")) for g in groups]
        bars = ax.bar(x + (i - (len(backends) - 1) / 2) * w, vals, w,
                      color=COLOR[b], label=LABEL[b], edgecolor="white",
                      linewidth=0.6)
        for rect, v in zip(bars, vals):
            if v == v:  # not NaN
                ax.annotate(label_fmt.format(v),
                            (rect.get_x() + rect.get_width() / 2, v),
                            ha="center", va="bottom", fontsize=7.5,
                            xytext=(0, 1), textcoords="offset points")
    ax.set_xticks(x)
    ax.set_xticklabels(groups)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if logy:
        ax.set_yscale("log")
    else:
        ax.margins(y=0.20)


def lines(ax, xs, backends, value, ylabel, title, yscale_m=1.0):
    for b in backends:
        ys = [value.get((b, x), float("nan")) / yscale_m for x in xs]
        ax.plot(xs, ys, "-o", color=COLOR[b], label=LABEL[b], lw=2.0, ms=6)
        # direct end-label
        ax.annotate(f"{ys[-1]:.0f}" if yscale_m == 1 else f"{ys[-1]:.1f}",
                    (xs[-1], ys[-1]), color=COLOR[b], fontsize=8,
                    xytext=(4, 0), textcoords="offset points", va="center")
    ax.set_xscale("log", base=2)
    ax.set_xticks(xs)
    ax.set_xticklabels([str(x) for x in xs])
    ax.set_xlabel("concurrent connections")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.margins(x=0.12)


# A — throughput by size
grouped_bars(axA, [s for s, _ in SIZES], BACKENDS, thrA,
             "throughput (Gbit/s)", "A  Routing throughput by message size",
             label_fmt="{:.0f}")
axA.legend(fontsize=8.5, ncol=2, loc="upper left", framealpha=0.9)

# B — threads vs conns
lines(axB, CONNS, BACKENDS, threadsB, "peak worker threads",
      "B  io-wq worker threads vs connections")
axB.legend(fontsize=8.5, loc="upper left", framealpha=0.9)

# C — ctxsw vs conns (millions)
lines(axC, CONNS, BACKENDS, ctxswC, "context switches (millions)",
      "C  Context switches vs connections", yscale_m=1e6)
axC.legend(fontsize=8.5, loc="upper left", framealpha=0.9)

# D — syscalls per message by size (log y)
grouped_bars(axD, [s for s, _ in SIZES], D_BACKENDS, syscD,
             "system calls per message", "D  System calls per message by size",
             logy=True, label_fmt="{:.2g}")
axD.set_ylim(top=axD.get_ylim()[1] * 6)  # headroom for the note above the bars
axD.legend(fontsize=8.5, loc="upper left", framealpha=0.9)
axD.text(0.985, 0.965,
         "read/write is outside the eBPF probe set,\nso poll+read/write is omitted here",
         transform=axD.transAxes, ha="right", va="top", fontsize=7,
         color="#555555")

fig.suptitle(
    "Relay-backend A/B on the SCG routing path (loopback).  "
    "Panels A to C: procfs pass.  Panel D: eBPF pass",
    fontsize=12.5, fontweight="bold", y=0.995)
fig.tight_layout(rect=(0, 0, 1, 0.97))
fig.savefig(OUT_PNG, bbox_inches="tight")
print(f"\nwrote {OUT_PNG}")
