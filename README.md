# SESHAT

> **S**CG **E**valuation, **S**tress & **H**arness **A**nalysis **T**oolkit

SESHAT is the benchmark harness for the **SCG** (Secure Communication Gateway)
project. It spawns the *real* `gateway` binary, drives traffic through it
end-to-end across every transport and crypto mode the SCG supports, and emits
reproducible, spreadsheet-ready CSV results.

It orchestrates everything end to end: it generates gateway configurations,
spawns and tears down real gateway processes, drives calibrated load through
them, and reports every metric with provenance.

A central design rule (**NFR-PERF**) is that *the harness must never be the
bottleneck* — only the SCG under test. Every measurement is gated by a
self-calibration step that proves the harness has ample headroom over the
result it reports.

**Reproducing the published evaluation end to end** — every campaign, its
prerequisites, and the figure pipeline — is documented in
[REPRODUCING.md](REPRODUCING.md) (one command:
`sudo scripts/reproduce_evaluation.sh`).

---

## Status

SESHAT drives real end-to-end benchmarks across the full interface × protocol
matrix below.

| Area | State |
| --- | --- |
| CLI, config model, validation, `sysinfo` | ✅ done |
| Core measurement engine (wire format, clock, stats, CSV) | ✅ done |
| Loopback transports (TCP, UDP) + calibration gate | ✅ done |
| Gateway lifecycle (spawn/readiness/teardown, both topologies) | ✅ done |
| Gateway TCP: routing, TLS 1.2/1.3, kTLS, mTLS, integrity-only | ✅ done |
| Gateway UDP: DTLS 1.2 (server-auth + mutual) | ✅ done |
| System metrics (`/proc` CPU/RSS/ctx-switches/IO per SCG PID) | ✅ done |
| System metrics (`perf stat` hardware counters: IPC, cache-misses) | ✅ done |
| Paced sub-saturation latency + per-scenario saturation sweep | ✅ done |
| Effective-protocol detection (kTLS→userspace fallback labeling) | ✅ done |
| Auto-affinity, gateway CPU%, bottleneck/headroom verdict | ✅ done |
| kTLS auto-detect (`TCP_ULP` probe) + WSL2 awareness | ✅ done |
| Ping-pong RTT + connection-establishment-rate traffic modes | ✅ done |
| UDS / SHM transports (via `scg-client` gRPC provisioning) | ✅ done |
| ALE / RAW (UDP-over-TLS), TLS-PSK / Subset-146 SecuritySpec | ✅ done |
| TPROXY transparent proxy transport | ✅ done |
| Multi-stream scheduling/QoS (fairness, starvation verdicts) | ✅ done |
| Hot-reload event injection (SIGHUP mid-measurement) | ✅ done |
| Distributed `sender`/`receiver` (multi-host TCP) | ✅ done |
| Virtual topology `setup`/`teardown` (veth, netns) | ✅ done |
| Network impairment (`tc netem` latency/loss/jitter/bandwidth) | ✅ done |
| `report` subcommand (regenerate CSV from result dirs) | ✅ done |
| SCG gateway `zero_copy` + `spin_wait_us` config fields | ✅ done |
| WireGuard (kernel offload) | ✅ via the privileged harness (`scripts/wg_setup.sh` + `perf_gate.sh`) — needs CAP_NET_ADMIN + a netns; the generic `run` path skips it |
| IPSec/IKEv2 | 🚫 disabled by design (SCG stub) |

---

## How it works

For a crypto scenario the harness generates a **pair of gateway rules** — an
`encrypt` rule and a `decrypt` rule — and the SCG performs the TLS/DTLS session
*internally* between them. SESHAT therefore only ever speaks **plaintext**:

```
                       (SCG does crypto internally)
 sender ──plaintext──▶ encrypt-rule ══TLS/DTLS══▶ decrypt-rule ──plaintext──▶ receiver
 (SESHAT)              (TLS client)               (TLS server)               (SESHAT)
```

- **`scg-direct`** topology — one gateway process holds both rules.
- **`scg-scg`** topology — two gateway processes (`client ↔ SCG ↔ SCG ↔ client`).

The gateway is launched as a child process; readiness is detected by
socket-polling its listeners (and, for pure-UDP/DTLS configs, its management
UDS) rather than scraping logs. Configs, logs, and generated certs are archived
per scenario, and the process is always reaped via `SIGTERM`→`SIGKILL` with a
`Drop` guard.

Test certificates are minted at runtime with the `openssl` CLI (EC keys); there
is no Rust crypto dependency.

---

## Building

Requires a recent stable Rust toolchain. Gateway-backed scenarios additionally
need a built `gateway` binary and the `openssl` CLI on `PATH`.

```bash
cargo build --release        # optimized harness binary at ./target/release/seshat
cargo build                  # debug build at ./target/debug/seshat
cargo test                   # unit + gated end-to-end tests
cargo clippy --all-targets   # lint
```

The gateway binary is auto-detected from `SCG/gateway/target/{release,debug}` or
`SCG/target/{release,debug}`; override with the `SCG_GATEWAY_BIN` environment
variable. SCG scenarios are skipped (not failed) when no suitable binary or
`openssl` is available.

> **Build the gateway with `--features dev`.** The harness drives the gateway
> with the unsigned single-file `--config`, which is a development-only build
> feature. A default (production) gateway build accepts only the signed
> `--config-dir` configuration and will refuse the harness's config. Build the
> gateway you point SESHAT at with:
>
> ```bash
> (cd ../SCG && cargo build --release -p gateway --features dev)
> ```

---

## Quick start

```bash
# 1. Validate a config without running anything
./target/release/seshat validate --config configs/gateway_smoke.json

# 2. List the scenarios a config expands to
./target/release/seshat list --config configs/gateway_smoke.json

# 3. Measure the harness's own loopback ceiling (NFR-PERF baseline)
./target/release/seshat calibrate --duration 1s

# 4. Run the suite (results land in ./results/<timestamp>/)
./target/release/seshat run --config configs/gateway_smoke.json

# 5. Snapshot the host (hardware/kernel fingerprint)
./target/release/seshat sysinfo
```

Ready-made configs ship in [`configs/`](configs):

- [`configs/gateway_smoke.json`](configs/gateway_smoke.json) — short routing +
  TLS runs through the real SCG plus a loopback baseline (quick validation).
- [`configs/example.json`](configs/example.json) — a broader representative
  suite (performance, scheduling, a WireGuard example skipped in the generic path).
- [`configs/wireguard.json`](configs/wireguard.json) — kernel-WireGuard scenarios
  for the privileged WireGuard harness (see the WireGuard section below).
- [`configs/matrix_spec.json`](configs/matrix_spec.json) — declarative source
  for all generated matrix suites; regenerate with `seshat matrix generate`.
- [`configs/profile_regression.json`](configs/profile_regression.json) — the
  fixed cells `scripts/perf_gate.sh` compares against its baselines.
- [`configs/shm_zerocopy.json`](configs/shm_zerocopy.json) — SHM zero-copy vs
  copy-path A/B cells.
- [`configs/qos_isolation.json`](configs/qos_isolation.json) — multi-stream QoS
  isolation (safety-class latency under bulk load).
- [`configs/udp_baseline.json`](configs/udp_baseline.json) — plaintext UDP
  loopback baselines.
- [`configs/datagram_encrypted_paced.json`](configs/datagram_encrypted_paced.json)
  — paced (sub-saturation) encrypted datagram cells for large sizes.
- [`configs/canonical_matrix.json`](configs/canonical_matrix.json) — compact
  generated default protocol/transport matrix.
- [`configs/full_matrix.json`](configs/full_matrix.json) — generated nightly
  matrix across compatible protocols, sizes, chains, and connection sweeps.
- [`configs/matrix_catalog.json`](configs/matrix_catalog.json) — generated
  catalog including explicitly disabled technical limitations. Every generated
  matrix tier (catalog, full, canonical, everything, and the smoke matrix) also
  carries the disabled `blocked_*` limitation rows — including
  `blocked_wireguard_script_orchestrated`, which records that WireGuard is
  benchmarked only by the privileged `scripts/wg_bench.sh` orchestration — so
  deliberate non-coverage is visible in the suite definition itself; the runner
  never executes disabled rows.
- [`configs/smoke_matrix.json`](configs/smoke_matrix.json) — generated **minimal
  per-capability** matrix: every profile path once at the canonical size / 1
  connection, plus one representative of each cross-cutting dimension (latency,
  cipher, handshake, resumption, hot-reload, loopback baseline, multi-stream).
  It sweeps no payload sizes — its job is "does every path still run". Run it
  with `seshat suite --tier smoke` (a few minutes).
- [`configs/everything_matrix.json`](configs/everything_matrix.json) — generated
  **exhaustive executable** matrix: every compatible profile in every valid
  combination (full message-size range × the catalog connection ladder) plus the
  latency, cipher, and handshake sweeps. Run it with
  `seshat suite --tier everything` — this is very long (hours to days); use
  `--quick`, `--runs`, `--scenario-filter`, and `--resume` to bound or resume it.
- [`configs/interface_comparison.json`](configs/interface_comparison.json) —
  matched direct TCP loopback, SCG TCP, TPROXY, UDS, and SHM measurements.
- [`configs/hotreload_matrix.json`](configs/hotreload_matrix.json) — generated
  compatible hot-reload combinations for the nightly tier.
- [`configs/full_suite.json`](configs/full_suite.json) — all features: UDS, SHM,
  TPROXY, ALE/RAW, hot-reload, veth/netns topology, tc-netem impairment,
  optimization flags (zero_copy, spin_wait), multi-stream DSCP scheduling,
  connection-rate, and disabled/pending capability examples.
- [`configs/latency.json`](configs/latency.json) — **paced** sub-saturation
  one-way latency (periodic senders, so buffers stay empty).
- [`configs/saturation.json`](configs/saturation.json) — offered-load sweeps
  that find each path's saturation knee and loss-free ceiling.
- [`configs/pingpong.json`](configs/pingpong.json) — closed-loop round-trip
  time (`mode: pingpong`), loopback TCP/UDP.
- [`configs/connrate.json`](configs/connrate.json) — loopback and gateway
  completed-path connection-establishment rate/latency (`mode: connrate`).
- [`configs/perf_investigation.json`](configs/perf_investigation.json) — curated
  **diagnostic** suite for improving SCG latency/throughput: per-path baselines,
  A/B optimization-knob pairs (zero_copy, spin_wait, perf_profile), saturation
  degradation curves, paced latency, RTT, and handshake cost. Driven by
  [`scripts/collect_perf_data.sh`](scripts/collect_perf_data.sh) (below).

---

## Benchmark matrix and measurements

A full evaluation runs straight from the binary — build once, then run the
`suite` subcommand:

```bash
cargo build --release                              # build seshat (and ../SCG gateway)
./target/release/seshat suite                      # canonical tier (default)
./target/release/seshat suite --tier smoke         # minimal per-capability check (~minutes)
./target/release/seshat suite --tier nightly       # broad generated matrix
./target/release/seshat suite --tier everything    # EVERY capability × combination (very long)
./target/release/seshat suite --quick              # 2s/1-run override, applies to any tier
./target/release/seshat suite --scenario-filter tcp  # only configs whose name matches
```

`--tier smoke` verifies every capability path once; it is a different (much
smaller) row set than `--quick`, which merely shortens whichever tier you run.
`--tier everything` is the exhaustive "test everything in every combination"
run — expect hours to days at the default rigor; pair it with `--quick` for a
fast full-coverage pass or `--resume <dir>` to continue an interrupted one.

`suite` runs the generated `canonical_matrix` plus the matched
`interface_comparison`, profile-regression, latency, saturation, ping-pong,
connection-rate, and SHM zero-copy suites (the tier → config-file map lives in
[`configs/suites.json`](configs/suites.json)), consolidates every scenario into
one timestamped result tree, and renders the performance overview to the
terminal and `PERFORMANCE_OVERVIEW.txt`. Scenario names must be unique across a
suite run; collisions are rejected before any benchmark starts.

The console view is **compact by default** — a live progress bar (elapsed timer,
spinner, current test) with one result line per scenario. Add `-v`/`--verbose`
for the full per-run/calibration/result detail, `--describe` to show each
scenario's one-line description, or `--quiet` for warnings plus the final report
only (also the non-TTY/CI default). These global flags apply to `run` too.

The safety-isolation unit checks run as
plain `cargo test`.

### What is measured

| Measurement | How it is driven | Primary result |
| --- | --- | --- |
| Baseline throughput | Direct TCP or UDP loopback, without SCG | Harness ceiling used to identify harness-limited runs |
| Gateway throughput and one-way latency | Sustained or paced framed traffic through one or two real gateway processes | Gbit/s, latency percentiles, jitter, loss/duplicates/reordering |
| Sub-saturation latency | Periodic, rate-limited traffic kept below the saturation knee | One-way latency without queueing/bufferbloat dominating the result |
| Saturation | Increasing offered-load sweep for each path | Loss-free ceiling, saturation knee, and headroom |
| Round-trip time | Closed-loop request/echo with one message in flight | RTT percentiles and samples |
| Interface comparison | Matched routing-only TCP loopback, SCG TCP, TPROXY, UDS, and SHM paths | Absolute throughput/latency plus direct-TCP and gateway-TCP deltas |
| Connection establishment | TCP connect/accept/close churn across configurable connector threads | Connections/second and completed-path establishment latency percentiles |
| Multi-stream QoS | Concurrent safety, monitoring, and bulk streams with DSCP/traffic-class settings | Per-stream throughput/latency/loss, fairness, and safety-starvation verdict |
| Reliability and reload | Traffic continues while an endpoint is added/removed or a configuration reload is triggered | Drop count and continuity verdict during the event |
| System resource use | Samples attached gateway PIDs during every gateway-backed run | CPU, RSS/PSS, **process-wide context switches** (summed across threads), I/O; `--perf` additionally records cycles, instructions, IPC, cache references/misses, syscalls, task-clock, and elapsed time |
| Memory copies per message | `--metrics-backend ebpf` runs a `bpftrace` probe over the gateway PIDs (needs root) | `mem_copies_per_msg` — user↔kernel payload copies ÷ messages; ~0 on the splice/kTLS zero-copy paths, >0 on userspace TLS |
| Session resumption | The gateway logs `resumed=` per TLS/kTLS accept; the log scan counts them | `resumed_fraction` — ground-truth resumed-vs-full handshakes, alongside the timing-based first/resumed handshake latency |

CPU-seconds and context-switch **totals are exact** (cumulative-counter deltas,
independent of the sample rate); only peaks come from the timeseries. Open-loop
**latency is coordinated-omission-corrected** for paced senders (each row carries
`co_corrected` and the `send_lag_*` magnitude). `perf` metrics are collected only
when the host can attach `perf stat`; `ebpf`/flamegraph stages need root. The full
methodology and its limitations are documented in
[`docs/methodology.md`](docs/methodology.md).

### Full feature suite coverage

The exact definitions live in [`configs/full_suite.json`](configs/full_suite.json).
The groups below make the scenario names and intent visible at a glance.

| Coverage | Scenarios |
| --- | --- |
| Loopback baselines | `baseline_tcp_loopback_1KB`, `baseline_tcp_loopback_64KB`, `fullsuite_baseline_udp_1400B` |
| TCP routing, topology, and optimization | `scg_routing_tcp_4KB`, `scg_routing_tcp_4KB_zerocopy`, `scg_routing_tcp_scgscg_4KB`, `scg_routing_tcp_256conn`, `scg_ktls13_tcp_4KB`, `scg_ktls13_tcp_4KB_zerocopy` |
| TLS and security profiles | `scg_tls12_tcp_4KB`, `scg_tls13_tcp_4KB`, `scg_tls13_tcp_scgscg_4KB`, `scg_mtls13_tcp_4KB`, `scg_integrity_tls12_tcp_4KB`, `scg_subset146_pki_tls12_tcp_4KB`, `scg_subset146_psk_tls12_tcp_4KB` |
| DTLS and UDP-over-TLS applications | `scg_dtls12_udp_1400B`, `scg_dtls12_mtls_udp_1400B`, `scg_ale_udp_over_tls13_1400B`, `scg_raw_udp_over_tls13_1400B` |
| Local interfaces | `scg_uds_routing_4KB`, `scg_uds_tls13_4KB`, `scg_shm_routing_4KB`, `scg_shm_routing_4KB_spinwait` |
| Transparent proxy | `scg_tproxy_tls13_4KB` (requires `CAP_NET_ADMIN`) |
| Payload and connection scaling | TLS 1.3 TCP at 64B, 256B, 1KB, 4KB, 16KB, and 64KB (`scg_tls13_tcp_*`); plus `scg_tls13_tcp_1024conn` and the routing 256-connection case above |
| Gateway RTT | `scg_tls13_pingpong_rtt_1KB`, `scg_routing_pingpong_rtt_1KB` |
| Scheduling and DSCP | `multistream_safety_bulk`, `multistream_dscp_preservation` |
| Hot reload | `hotreload_add_connection`, `hotreload_remove_connection`, `hotreload_invalid_config` (generated nightly) |
| Virtual topology and impairment | `scg_routing_veth_4KB`, `scg_tls13_netns_4KB`, `scg_routing_netem_50ms_4KB`, `scg_routing_netem_1pct_loss_4KB` (all require `CAP_NET_ADMIN`) |

The generated catalog explicitly marks technical limitations that would
otherwise misrepresent a result: DTLS multi-connection reporting (the gateway
demuxes by peer, but all sessions share one backend socket so the harness cannot
attribute per-connection metrics) and TLS-profile reload (the gateway's config
diff is field-aware, but the harness reload action only sends SIGHUP without
rewriting the config file, so the swap is a harness-side no-op — flagged
`change_applied=false`). kTLS+mTLS is fully benchmarked (handshake concerns
complete before kTLS activates); if kTLS cannot be enabled at runtime the
gateway falls back to userspace TLS and the row is labelled via
`effective_protocol`. Session resumption
*is* now reported as ground truth via the gateway's `resumed=` log
(`resumed_fraction`). IPSec is outside the benchmark scope. A missing gateway
binary, OpenSSL, kTLS, perf permission, or required privileges produces a
recorded skip rather than a fabricated result.

### Performance data collection (one-shot)

To gather everything needed to diagnose and improve SCG latency/throughput in a
single bundle, run [`scripts/collect_perf_data.sh`](scripts/collect_perf_data.sh):

```bash
# fast, curated diagnostic (per-path + A/B knobs + saturation + latency + connrate)
scripts/collect_perf_data.sh
# run as root to also capture memory-copies-per-message and a gateway CPU flamegraph
sudo scripts/collect_perf_data.sh
# broaden coverage: all features/transports/QoS, then the combinatorial sweep
sudo SCOPE=full   scripts/collect_perf_data.sh
# exhaustive combinations — triage-grade; shorten the per-point window to stay tractable,
# then re-measure the interesting points at full rigor. MATRIX_FILE=full_matrix.json = largest tier.
sudo SCOPE=matrix RUNS=3 DURATION=4s scripts/collect_perf_data.sh
```

It first **preflights every prerequisite** (cargo, openssl, perf + paranoid level,
bpftrace, root, `CAP_NET_ADMIN`, ip/tc/iptables, taskset/cpupower) and prints a
checklist of what each gates, then builds both binaries, captures the host
fingerprint and harness calibration, runs the selected suite(s) with `perf`
hardware counters (and `ebpf` memory-copies when root), profiles the gateway
under load into a flamegraph (root/perf), and writes a timestamped bundle plus
`MANIFEST.txt` under `perf-data/`. Privileged stages degrade to `[SKIPPED]` with a
reason rather than failing. Knobs: `SCOPE`, `RUNS`, `DURATION`, `PROFILE_SECS`,
`GATEWAY_BIN`, `SKIP_BUILD`, `SKIP_FLAMEGRAPH` (see the script header).

### WireGuard (kernel offload)

WireGuard is a real SCG crypto provider, but it offloads to the in-kernel
`wireguard` module and so needs `CAP_NET_ADMIN`, the module loaded, and a
separate network namespace for the peer gateway — which the generic, unprivileged
`seshat run` path cannot set up. The generic path therefore records WireGuard
scenarios as skipped.

The dedicated, privileged harness lives in `scripts/`:

```bash
sudo scripts/wg_setup.sh      # modprobe + peer netns + veth + kernel WG tunnel (verifies with ping)
sudo scripts/wg_bench.sh      # benchmark: throughput (rate sweep) + p99 latency through SCG→SCG
sudo scripts/wg_smoke.sh      # lighter functional probe (loss only)
sudo scripts/wg_teardown.sh   # remove the topology
```

`wg_bench.sh` drives plaintext UDP through a pair of SCG WireGuard gateways
(encrypt in the host netns, decrypt in the peer netns) and prints a results row:

```
 | wireguard scg->scg (1400B, 1-stream) |   ~1.0 Gbit/s |   ~90 us p50 |  0.00% |
```

Representative loopback numbers (single 1400 B stream): sustained **~1 Gbit/s at
0 % loss**, **p50 ≈ 90 µs**. Throughput is **rate-swept** — UDP has no flow
control, so an unthrottled blast just finds where the single-threaded relay
starts dropping; the reported figure is the highest offered rate sustained under
the loss bar (the same idea as SESHAT's calibration). p99 latency is jitter-prone
under the userspace probe; p50 and throughput are stable.

The load is generated by [`scripts/wg_probe.py`](scripts/wg_probe.py), a
dependency-free UDP probe, **not** `seshat sender`/`receiver`: those are TCP-only
(`TcpStream`/`TcpListener`) and structurally cannot drive a UDP datagram path.

`scripts/perf_gate.sh` runs this benchmark automatically when the prerequisites
are present (printing the row inline) and prints `[SKIPPED]` otherwise. Scenario
metadata lives in [`configs/wireguard.json`](configs/wireguard.json). On Arch:
`sudo pacman -S wireguard-tools iproute2`.

> WireGuard is measured by this dedicated harness rather than appearing in the
> generic `seshat run` summary table, because (a) kernel WireGuard needs a peer
> network namespace that SESHAT's in-process gateway launcher does not yet set up,
> and (b) the standalone `seshat sender`/`receiver` are TCP-only.

### Two-host wire benchmark

The single-host suite runs everything on loopback, which cannot show that a
DSCP mark survives a physical interface or that a real queueing discipline
acts on it. The `scripts/wire_*.sh` orchestration closes that gap with two
machines on a point-to-point Ethernet link (privileged; catalogued as a
`blocked_*` limitation row in the generated matrices):

```bash
# host B (the peer / decrypt end), from the peer-bundle/ dir wire_bench.sh emits:
./wire_peer.sh --local-ip 10.9.0.2 --dev <NIC> --capture

# host A (the instrumented side):
scripts/wire_bench.sh --mode loopback                 # baseline half
scripts/wire_bench.sh --mode wire --peer 10.9.0.2 --dev <NIC>

# afterwards: copy the peer's peer-out/ back to host A and merge the far-side
# records (delivered goodput, loss, DSCP verdict) into the wire summary CSV
# (writes wire_summary_merged.csv next to the original):
python3 scripts/merge_peer_out.py --results-dir <run-dir> --peer-out <copied-peer-out-dir>
```

Shared tunables (ports, message shapes, sweep grid) live in
`scripts/wire_env.sh`; `scripts/wire_probe.py` is the traffic source/sink both
sides use.

### Focused suites

| Suite | Scenarios and purpose |
| --- | --- |
| [`latency.json`](configs/latency.json) | `lat_tcp_loopback_1KB`, `lat_udp_loopback_1KB`, `lat_scg_routing_tcp_1KB`, `lat_scg_tls13_tcp_1KB`, `lat_scg_dtls12_udp_1KB`: paced one-way latency comparisons |
| [`saturation.json`](configs/saturation.json) | `sat_tcp_loopback_1KB`, `sat_udp_loopback_1KB`, `sat_scg_routing_tcp_1KB`, `sat_scg_dtls12_udp_1KB`: offered-load sweeps and loss-free ceilings |
| [`pingpong.json`](configs/pingpong.json) | `pp_tcp_loopback_64B`, `pp_tcp_loopback_1KB`, `pp_udp_loopback_64B`, `pp_udp_loopback_1KB`: loopback closed-loop RTT controls |
| [`connrate.json`](configs/connrate.json) | `conn_tcp_loopback_1thread`, `conn_tcp_loopback_4thread`: TCP connection/handshake rate controls |
| [`perf_investigation.json`](configs/perf_investigation.json) | `path_*`, `ab_*` (zero_copy/spin_wait/perf_profile A/B), `sat_*`, `lat_*`, `connrate_tls13`: diagnostic suite driven by `scripts/collect_perf_data.sh` |

---

## CLI reference

```
seshat [--log-level error|warn|info|debug|trace] [--quiet] [--verbose] [--describe] <command>
```

The global `--verbose`/`--describe`/`--quiet` flags control the console view for
`run` and `suite` (see [Benchmark matrix and measurements](#benchmark-matrix-and-measurements)).

| Command | Purpose | State |
| --- | --- | --- |
| `run` | Execute a single config's benchmark suite | ✅ |
| `suite` | Run a whole evaluation tier (many configs) + consolidated overview | ✅ |
| `validate` | Parse + validate a config, report errors, do not run | ✅ |
| `list` | Expand and list every scenario with its parameters | ✅ |
| `calibrate` | Sweep the harness null-loopback throughput ceiling | ✅ |
| `sysinfo` | Dump host hardware/kernel info (`--format table\|json`) | ✅ |
| `sender` / `receiver` | Distributed (two-host) TCP mode | ✅ |
| `setup` / `teardown` | Create/remove a `veth`/`netns` topology | ✅ |
| `impair` | Apply `tc netem` latency/loss/jitter to an interface | ✅ |
| `report` | Re-generate CSV from an existing result directory | ✅ |
| `matrix` | Regenerate the generated matrix suites from `configs/matrix_spec.json` (`seshat matrix generate`) | ✅ |
| `pki` | Mint a benchmark CA + client/server certificates (used by the wire scripts) | ✅ |

Key `run` flags (all optional; they override config `defaults`):

| Flag | Effect |
| --- | --- |
| `--config <PATH>` | Config file to run (required) |
| `--output-dir <DIR>` | Result root (default `./results`) |
| `--runs <N>` | Repetitions per scenario |
| `--duration <D>` / `--warmup <D>` / `--cooldown <D>` | Phase lengths (`30s`, `500ms`, `2m`, …) |
| `--scenario <NAME>` | Run a single named scenario |
| `--tag <LABEL>` | Custom label written into result metadata |
| `--cpu-affinity <C,…>` | Pin harness threads to specific cores |
| `--no-system-metrics` | Skip `/proc` SCG sampling |
| `--scg-pid <PID>` | SCG PID for metrics (default: auto-detect) |
| `--dry-run` | Validate + print the plan, but execute nothing |

---

## Configuration

Configs are JSON: a `suite` block (metadata), a `defaults` block (applied to
every scenario), and a `scenarios` array. Unknown fields are rejected so typos
fail fast at `validate` time.

```jsonc
{
  "$schema": "seshat-config-v1",
  "suite":    { "name": "…", "description": "…", "author": "…", "version": "1.0.0" },
  "defaults": {
    "runs": 5, "duration_secs": 30, "warmup_secs": 5, "cooldown_secs": 2,
    "cpu_affinity_sender": [0, 1], "cpu_affinity_receiver": [2, 3],
    "scg_process_name": "gateway",
    "collect_system_metrics": true,
    "metrics_backend": "procfs",      // procfs | perf | ebpf | none
    "metrics_sample_rate_hz": 1,
    "outlier_removal": "iqr",         // none | iqr | percentile
    "confidence_level": 0.95
  },
  "scenarios": [ /* … */ ]
}
```

### Scenario fields

| Field | Meaning |
| --- | --- |
| `name` | Unique scenario name (also the result sub-directory) |
| `category` | Free-form label (`performance`, `latency-rtt`, `connection`, …) |
| `mode` | Traffic mode: `throughput` (default), `pingpong` (closed-loop RTT), or `connrate` (connection-establishment rate) — see [Traffic modes](#traffic-modes) |
| `enabled` / `disabled_reason` | Toggle a scenario without deleting it |
| `message_size_bytes` | Total on-wire size incl. the 24-byte SESHAT header |
| `connections` | Parallel connections (in `connrate` mode, the connector thread count) |
| `sender` | Single-stream traffic source (see below) |
| `protocol` | Security / app-protocol configuration (see below) |
| `gateway` | `{ "enabled": true, "chain": "scg-direct" \| "scg-scg" }` |
| `topology` | Network topology (loopback by default) |
| `streams` | Multi-stream definition for scheduling scenarios |
| `reload_event` | Hot-reload event (SIGHUP mid-measurement) |
| `optimization_flags` | SCG perf toggles — zero-copy, spin-wait, … |
| `runs` / `duration_secs` / `warmup_secs` / `cooldown_secs` | Per-scenario overrides |

### Traffic modes

The `mode` field selects what a scenario measures. All three reuse the same
warmup→measure→cooldown clock and CSV machinery, but report different headline
metrics:

| `mode` | Drives | Headline metric | Notes |
| --- | --- | --- | --- |
| `throughput` *(default)* | Open-loop blast/paced sender → receiver | Gbit/s + one-way latency | The standard path; runs calibration + the optional saturation sweep. Pace it (`periodic`, `rate_limit_mbps`) to measure latency **below** saturation — an unthrottled sender reports bufferbloat, not the gateway's real latency. |
| `pingpong` | Closed-loop request/echo, one message in flight per connection | Round-trip time (`rtt_us_*`) | The client sends one message and waits for the echo, timing the round trip locally. Skips calibration/saturation (latency, not bandwidth, is the point). Loopback TCP/UDP and the TCP gateway; DTLS/UDP gateway is skipped. See [`configs/pingpong.json`](configs/pingpong.json). |
| `connrate` | Connection open/close churn across `connections` connector threads | Connections/second + handshake latency | Measures `accept()`/handshake cost rather than data movement. Loopback TCP only — UDP is connectionless and the gateway harness is not wired yet (both are skipped with a notice). See [`configs/connrate.json`](configs/connrate.json). |

### Sender

```jsonc
"sender": {
  "interface": "tcp",                 // tcp | udp | unix | shm
  "target_addr": "127.0.0.1:10000",
  "pattern": "sustained",             // sustained | periodic | burst | ramp
  "interval_us": 1000,                // periodic
  "burst_count": 64, "burst_pause_us": 500,   // burst
  "rate_limit_mbps": 1000.0,
  "ramp_start_mbps": 100, "ramp_step_mbps": 100, "ramp_step_interval_secs": 1  // ramp
}
```

### Protocol

```jsonc
"protocol": {
  "type": "tls",            // none | tls | dtls | wireguard | ipsec | custom
  "version": "1.3",         // TLS: 1.2 | 1.3; DTLS: 1.0 | 1.2
  "kernel": false,          // true → kTLS (kernel TLS)
  "mutual_auth": false,     // true → mTLS / mutual DTLS
  "protection_mode": "full",// full | integrity-only | routing-only
  "app_protocol": "none",   // none | ale | raw   (UDP-over-TLS framing)
  "cipher_suite": null,
  "resumption": false,
  "security_provider": null, // required when type=custom (see Customizing SESHAT)
  "provider_params": {},     // custom-provider params, passed through verbatim
  "certificates": {
    "server_cert": "/path/server.pem",
    "server_key": "/path/server.key",
    "client_cert": "/path/client.pem",
    "client_key": "/path/client.key",
    "ca_cert": "/path/ca.pem",
    "server_name": "localhost"
  }
}
```

| `type` | Transport | Notes |
| --- | --- | --- |
| `none` | tcp | Plaintext / routing-only baseline through the SCG |
| `tls` | tcp | Userspace TLS 1.2/1.3; `kernel:true` → kTLS; `mutual_auth` → mTLS; `protection_mode:integrity-only` → NULL-cipher authenticated TLS |
| `dtls` | udp | DTLS 1.0/1.2, server-auth or `mutual_auth`; single logical flow |
| `wireguard` / `ipsec` | — | **Disabled** (SCG provides stubs only); kept for forward-compat |
| `custom` | udp *(tcp)* | Any out-of-tree crypto provider, named via `security_provider` — see [Customizing SESHAT](#customizing-seshat-benchmarking-a-new-provider) |

### Customizing SESHAT: benchmarking a new provider

SESHAT knows the built-in gateway providers by name (`tls`, `dtls`, `ktls`,
`routing`, …). To benchmark a provider it does **not** know about — for example a
provider registered out-of-tree via `gateway::run(extra_crypto, …)` — use the
generic `custom` protocol type instead of adding a new enum variant:

```jsonc
{
  "name": "myprovider_udp_throughput_1400B",
  "category": "protocol",
  "message_size_bytes": 1400,
  "connections": 1,
  "gateway": { "enabled": true, "chain": "scg-scg" },
  "protocol": {
    "type": "custom",
    "security_provider": "myprovider",     // becomes the rule's security_provider
    "provider_params": {                    // flattened into the rule verbatim
      "my_key_hex": "00112233…",             // string
      "my_window_ms": 60000,                 // integer
      "my_flag": true                        // boolean
    }
  },
  "sender": { "interface": "udp", "target_addr": "127.0.0.1:12300", "pattern": "sustained" }
}
```

How it maps to the gateway config:

- `security_provider` → the rule's `security_provider` string. The gateway binary
  you run **must** have a provider registered under that exact name (point SESHAT
  at it with `SCG_GATEWAY_BIN=/path/to/your-gateway`).
- `provider_params` → flattened into the rule's top-level params (the same channel
  `cert_path`, `verify`, `max_sessions`, … use). Values may be strings, integers,
  or booleans.
- `sender.interface` picks the transport: `udp` → a UDP rule (the usual case for
  datagram providers), anything else → a TCP rule. UDS/SHM/TPROXY interfaces also
  work and route through the same custom provider.

This keeps proprietary provider *names and parameters* out of the open harness:
the hook is generic, and the specifics live only in your own suite JSON. A
worked example is the `custom` scenario in `src/config/mod.rs`'s tests, which
drives an out-of-tree `vendor-udp` provider purely through `provider_params`.

---

## Output

Every invocation writes a self-contained, timestamped directory. Output is
**CSV-only** by design — the tree opens directly in any spreadsheet.

```text
results/<YYYYMMDD-HHMMSS>/
  meta.csv                       suite + run metadata
  sysinfo.csv                    host hardware/kernel fingerprint
  summary.csv                    one columnar row per executed scenario
  scenarios/<name>/
    config.csv                   resolved scenario configuration
    summary.csv                  cross-run aggregated metrics (key/value)
    runs.csv                     one row per measurement run
    system_metrics/
      gateway_pid_<pid>.csv      per-SCG-PID /proc timeseries
    <gateway config/logs/certs archived here>
```

The top-level `summary.csv` columns include: `scenario`, `transport`,
`protocol`, `message_bytes`, `connections`, `runs`, throughput
(`mean`/`ci95`/`min`/`max` Gbit/s), latency (`mean`, `p99` µs + CI), `jitter_us`,
`handshake_us_mean`, `loss_pct`, `total_lost`, and the NFR-PERF cells
`ceiling_gbps`, `headroom`, `harness_limited`, `dut` (`loopback` or `scg`).
Additional columns surface the later improvements:

| Column(s) | Meaning |
| --- | --- |
| `saturation_gbps`, `max_lossfree_gbps` | Saturation-sweep knee and highest loss-free offered load (when a sweep ran) |
| `effective_protocol` | What the gateway **actually** negotiated, e.g. `tls/1.3 (ktls→userspace)` when kTLS was requested but fell back |
| `cpu_pct_peak`, `cpu_pct_mean`, `rss_peak_kib`, `pss_peak_kib`, `gbps_per_core` | Gateway CPU/memory utilisation (from `/proc`) and throughput efficiency |
| `integrity_failures`, `boundary_violations` | Rejected deterministic payload/header frames and unexpected message/datagram sizes |
| `encapsulation_overhead_bytes_analytical`, `encapsulation_overhead_capture_verified` | Protocol-header estimate; always labelled unverified unless a future packet-capture backend supplies observed bytes |
| `perf_cycles`, `perf_instructions`, `perf_ipc`, `perf_cache_*`, `perf_context_switches`, `perf_task_clock_ms`, `perf_duration_s` | Scenario-wide `perf stat` hardware/software counters when the `perf` backend is enabled |
| `bottleneck` | Calibration verdict: `scg-cpu` (gateway pool **or** hottest gateway thread saturated — trusted), `scg` (≥3× headroom — trusted), `host-saturated` (whole host ≥90 % busy — a lower bound, still harness-limited), `harness-io` (residual: suspect), `n/a` (baseline) |
| `ceiling_transport` | Which null-loopback transport measured the ceiling: `tcp`, `udp`, `uds-null`, `shm-null` (interface-true; a failed null probe falls back to `tcp` and says so) |
| `cpu_hot_thread_pct_p95` | p95 CPU% of the hottest single gateway thread (100 = one core) — the serial-data-plane saturation signal |
| `host_busy_frac_p95` | p95 whole-host busy fraction (0..1) — the loopback co-saturation signal |
| `rtt_us_mean/ci95/p50/p99` | Closed-loop round-trip time (populated only for `pingpong` scenarios) |
| `conns_per_sec`, `conns_per_sec_ci95`, `conn_handshake_p50_us`, `conn_handshake_p99_us` | Connection rate + handshake latency (populated only for `connrate` scenarios) |
| `perf_syscalls` | System calls during the scenario (from `raw_syscalls:sys_enter` tracepoint via `perf stat`) |

Each `runs.csv` adds the full latency percentile spread
(`p50/p90/p95/p99/p999/min/max`) and duplicate/reordered/outlier counts. For
`pingpong` rows the latency columns carry the RTT distribution; for `connrate`
rows they carry the per-connection handshake distribution.

---

## NFR-PERF — the harness must not be the bottleneck

The hard requirement is that SESHAT always saturates *after* the SCG, so every
number reflects the gateway's limit. This is enforced two ways:

1. **Engineering** — batched/vectored I/O on *every* path (UDP `sendmmsg`/
   `recvmmsg`; TCP/UDS `writev` batches of up to 1024 messages with a
   cursor-based frame reassembler that memmoves once per buffer-full, not once
   per message; SHM ring batches), block-wise payload fill/verify against a
   static ramp table (memcpy/memcmp-class, never per-byte), pre-allocated
   reusable buffers, immediate receive-side timestamping, statistics computed
   off the hot path, and harness threads pinnable to cores *separate* from the
   SCG.
2. **A calibration gate** — before trusting a gateway result, the harness
   measures its own null-loopback ceiling for that exact message shape **under
   the scenario's own conditions**: same access interface (`tcp`/`udp`/
   `uds-null`/`shm-null`, recorded in `ceiling_transport`), same sender/receiver
   core pools, 500 ms warmup, 1 s measure, best of 2 probes. The console and CSV
   surface the `headroom` (ceiling ÷ measured) and flag any scenario
   `[HARNESS-LIMITED]` when the margin is under 3× — unless the gateway's core
   pool or its hottest single thread is saturated (`scg-cpu`, trusted), or the
   whole host is ≥90 % busy (`host-saturated`: kept harness-limited as an honest
   lower bound, but labeled so figures can distinguish single-host physics from
   harness slowness). A measured throughput far above the ceiling (headroom
   < 0.85) logs a `suspect ceiling` warning; a *slight* overshoot on
   passthrough paths is expected — a sender→gateway→receiver relay pipelines
   across more cores than the two-thread probe. Run the probe standalone with
   `seshat calibrate` (`--warmup`, `--probes` match the in-suite gate).

### Harness fast-path engineering

The load-generation fast path batches aggressively (vectored `writev` sends,
cursor-based frame reassembly, block-wise payload verification) so the harness
is never the bottleneck; the before/after numbers are recorded in
[CHANGELOG.md](CHANGELOG.md). Why a batched generator remains representative —
and for exactly which metrics — is treated in
[docs/methodology.md](docs/methodology.md) (limitations §4.10): throughput rows
are capacity measurements, while latency/ETCS-like modes deliberately stay
one-message-per-event.

---

## Project layout

```
src/main.rs                 dispatch
src/cli.rs                  clap CLI definitions
src/commands.rs             subcommand implementations + run orchestration
src/config/                 config model, schema, validation
src/proto/wire.rs           SESHAT packet header / payload format
src/workload/               sender + receiver traffic generators
src/workload/streams.rs     multi-stream scheduling (fairness, QoS)
src/transport/              tcp, udp, uds, shm, tproxy, and gateway-backed transports
src/gateway/                gateway config-gen, process lifecycle, topology
src/gateway/grpc_client.rs  gRPC management API client (UDS/SHM provisioning)
src/gateway/reload.rs       hot-reload injection (SIGHUP + gRPC endpoint mgmt)
src/topology/               virtual network topology (veth, netns) + tc netem
src/pki.rs                  runtime EC cert minting via the openssl CLI
src/metrics/                app metrics, /proc system metrics, perf stat, statistics
src/run/                    measurement engine + calibration + distributed mode
src/report/                 CSV writer + result-directory tree
src/sysinfo.rs              host fingerprint
src/{console,logging,time}.rs   support
configs/                    example suites + suites.json tier manifest
docs/methodology.md         measurement methodology & validity notes
```

---

## Relationship to other repos

- **System under test:** [`SCG`](https://github.com/TianTomascsik/SCG) — the
  gateway binary and its `scg-client` / `scg-ipc` / `scg-proto` crates. A
  sibling checkout at `../SCG` is the default the harness probes for the
  gateway binary; `SCG_GATEWAY_BIN` overrides it.

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
