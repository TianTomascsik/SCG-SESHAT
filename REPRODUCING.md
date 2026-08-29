# Reproducing the published SCG evaluation

This document is the end-to-end recipe for regenerating every benchmark number
and figure the published SCG evaluation cites, using this harness plus its
sibling repositories.

## Repository layout

Clone the repos as siblings (the harness probes `../SCG` for the gateway
binary; the figure and queue stages probe `../seshat-viz` and
`../mpsc_priority_bench`):

```
parent/
├── SCG/                   <- github.com/TianTomascsik/SCG
├── SCG-SESHAT/            <- this repository
├── seshat-viz/            <- github.com/TianTomascsik/seshat-viz   (figures)
└── mpsc_priority_bench/   <- github.com/TianTomascsik/mpsc-priority-bench (queue study)
```

## The measured state — check out the evaluation tag

The published numbers were measured at the annotated tag **`thesis-2026-07-22`**
("Frozen state evaluated in the master thesis"), which exists in **both** SCG
and SCG-SESHAT:

```bash
git -C ../SCG checkout thesis-2026-07-22
git checkout thesis-2026-07-22
```

Current `main` deliberately differs: it contains the later harness fast-path
work (see [CHANGELOG.md](CHANGELOG.md)) that raises the harness's own loopback
ceiling by up to ~62×, so previously harness-limited rows measure higher on
`main`. Reproduce **at the tag** to compare against the published values;
run **`main`** to get the best current measurements.

## Environment prerequisites

The original evaluation host: **AMD Ryzen 9 5950X (16C/32T), Arch Linux**,
loopback (single host). Numbers scale with hardware; the qualitative findings
(ordering, knees, payload-size collapse) are the transferable result.

- Rust stable toolchain + the `openssl` CLI (runtime test-cert minting).
- **kTLS**: `sudo modprobe tls` — without the TLS ULP module, every
  kTLS-over-UDS/SHM row silently skips with "usable kTLS unavailable".
- **perf pass**: `kernel.perf_event_paranoid` ≤ 2 (or run as root) for
  `perf stat` hardware counters; the harness preflights this and degrades.
- **eBPF pass**: root + `bpftrace` (copies-per-message, splice syscalls).
- **qos stage**: run under `sudo` so the gateway receives `CAP_SYS_NICE` and
  the reserved safety workers can raise their scheduling priority.
- **WireGuard stage**: root + `wireguard-tools iproute2` (netns + kernel module).
- Measurement hygiene: a fixed CPU governor and disabled turbo make per-run
  clocks comparable; the harness emits preflight WARNs when the environment
  drifts (see `docs/methodology.md` §3).

## One command

```bash
sudo scripts/reproduce_evaluation.sh            # the full single-host evaluation
scripts/reproduce_evaluation.sh --quick \
  --skip-perf --skip-ebpf --skip-qos --skip-wg \
  --skip-queue --skip-relay                     # unprivileged plumbing smoke test
```

The script header documents the stage → evidence map (which stage backs which
figure ID / result family) and the `--skip-*` / `--main-run` reuse flags. Each
stage degrades with a WARN/SKIP note instead of aborting the rest.

Figures land in `../seshat-viz/figures-print/`; that directory's
`captions.txt` + `manifest.json` are the citation source — every number quoted
from a figure is recomputed there.

## What the one command does NOT cover

- **Two-host wire campaign (F26–F28)**: needs a second machine on a
  point-to-point Ethernet link plus root for `tc`/`tcpdump`. See the
  "Two-host wire benchmark" section of the [README](README.md)
  (`scripts/wire_bench.sh`, `scripts/wire_peer.sh`,
  `scripts/merge_peer_out.py`), then render F26–F28 with
  `--wire-results` (see `../seshat-viz/scripts/export_print_figures.sh`).
- **Kernel-scope perf ladder (F30)**: a dedicated `perf` campaign over the
  crypto ladder at kernel scope; the export script consumes its run dir as its
  fourth input.
- **Relay-backend A/B (io_uring)**: the apparatus lives on the
  `experiment/io-uring-relay` branch of **both** SCG and SCG-SESHAT — check
  that branch out in both repos and the `relay` stage runs it
  (`configs/relay_backend_ab.json` + `scripts/run_relay_backend_ab.sh`).
  The committed `results/relay-backend-ab-*/` trees are the records the
  published comparison used.

## Verifying a rerun

- Every run directory carries `sysinfo` (host fingerprint), the generated
  gateway configs, logs, and per-scenario raw samples — compare
  `summary.csv` between your run and the published values.
- `scripts/perf_gate.sh` compares fixed cells against baselines
  (`configs/profile_regression.json`) for regression checking between two of
  your own runs.
- The harness-vs-gateway attribution rules (headroom gate, `harness_limited`,
  validity flags) are specified in [docs/methodology.md](docs/methodology.md).
