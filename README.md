# SESHAT

> **S**CG **E**valuation, **S**tress & **H**arness **A**nalysis **T**oolkit

SESHAT is the benchmark harness for the **SCG** (Secure Communication Gateway)
project. It spawns the *real* `gateway` binary, drives traffic through it
end-to-end across every transport and crypto mode the SCG supports, and emits
reproducible, spreadsheet-ready CSV results.

It is the next-generation replacement for the legacy benchmark orchestration in
[`SCG-Interface-benchmarks`](../SCG-Interface-benchmarks) (loose scripts,
container compose files, and ad-hoc visualization).

A central design rule (**NFR-PERF**) is that *the harness must never be the
bottleneck* — only the SCG under test. Every measurement is gated by a
self-calibration step that proves the harness has ample headroom over the
result it reports.

---

## Status

SESHAT is under active development. The implemented surface already drives real
end-to-end benchmarks; the remaining work is tracked in [PLAN.md](PLAN.md).

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
| WireGuard, IPSec/IKEv2 | 🚫 disabled by design (SCG stubs) |

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

---

## Quick start

```bash
# 1. Validate a config without running anything
seshat validate --config configs/gateway_smoke.json

# 2. List the scenarios a config expands to
seshat list --config configs/gateway_smoke.json

# 3. Measure the harness's own loopback ceiling (NFR-PERF baseline)
seshat calibrate --duration 1s

# 4. Run the suite (results land in ./results/<timestamp>/)
seshat run --config configs/gateway_smoke.json

# 5. Snapshot the host (hardware/kernel fingerprint)
seshat sysinfo
```

Ready-made configs ship in [`configs/`](configs):

- [`configs/gateway_smoke.json`](configs/gateway_smoke.json) — short routing +
  TLS runs through the real SCG plus a loopback baseline (quick validation).
- [`configs/example.json`](configs/example.json) — a broader representative
  suite (performance, scheduling, a disabled WireGuard example).
- [`configs/full_matrix.json`](configs/full_matrix.json) — every
  protocol/transport/topology path SESHAT can currently drive end-to-end.
- [`configs/full_suite.json`](configs/full_suite.json) — all features: UDS, SHM,
  TPROXY, ALE/RAW, hot-reload, veth/netns topology, tc-netem impairment,
  optimization flags (zero_copy, spin_wait), multi-stream DSCP scheduling,
  session-resumption connrate, and disabled WireGuard/IPSec stubs.
- [`configs/latency.json`](configs/latency.json) — **paced** sub-saturation
  one-way latency (periodic senders, so buffers stay empty).
- [`configs/saturation.json`](configs/saturation.json) — offered-load sweeps
  that find each path's saturation knee and loss-free ceiling.
- [`configs/pingpong.json`](configs/pingpong.json) — closed-loop round-trip
  time (`mode: pingpong`), loopback TCP/UDP.
- [`configs/connrate.json`](configs/connrate.json) — connection-establishment
  rate and handshake latency (`mode: connrate`), loopback TCP.

---

## Benchmark matrix and measurements

[`run_all.sh`](run_all.sh) is the canonical non-overlapping execution plan. It
runs `full_suite`, `latency`, `saturation`, `pingpong`, and `connrate`—not
`gateway_smoke` or `full_matrix`, because those focused suites duplicate shapes
already covered by the canonical plan. At present this schedules **57 enabled
scenarios** (42 in the full feature suite, plus 5 latency, 4 saturation, 4
loopback RTT, and 2 connection-rate scenarios). The runner rejects duplicate
enabled benchmark shapes before it starts a run when `jq` is available.

### What is measured

| Measurement | How it is driven | Primary result |
| --- | --- | --- |
| Baseline throughput | Direct TCP or UDP loopback, without SCG | Harness ceiling used to identify harness-limited runs |
| Gateway throughput and one-way latency | Sustained or paced framed traffic through one or two real gateway processes | Gbit/s, latency percentiles, jitter, loss/duplicates/reordering |
| Sub-saturation latency | Periodic, rate-limited traffic kept below the saturation knee | One-way latency without queueing/bufferbloat dominating the result |
| Saturation | Increasing offered-load sweep for each path | Loss-free ceiling, saturation knee, and headroom |
| Round-trip time | Closed-loop request/echo with one message in flight | RTT percentiles and samples |
| Connection establishment | TCP connect/accept/close churn across configurable connector threads | Connections/second and handshake latency percentiles |
| Multi-stream QoS | Concurrent safety and bulk streams with DSCP/traffic-class settings | Per-stream throughput/latency/loss, Jain fairness, and safety-starvation verdict |
| Reliability and reload | Traffic continues while an endpoint is added/removed or a configuration reload is triggered | Drop count and continuity verdict during the event |
| System resource use | Samples attached gateway PIDs during every gateway-backed run | CPU, RSS, context switches, I/O; `--perf` additionally records cycles, instructions, IPC, cache references/misses, syscalls, task-clock, and elapsed time |

`perf` metrics are collected only when `--perf` is explicitly requested and the
host can attach `perf stat`; the runner fails rather than publishing a report
with blank requested hardware counters.

### Full feature suite coverage

The exact definitions live in [`configs/full_suite.json`](configs/full_suite.json).
The groups below make the scenario names and intent visible at a glance.

| Coverage | Scenarios |
| --- | --- |
| Loopback baselines | `baseline_tcp_loopback_1KB`, `baseline_tcp_loopback_64KB`, `baseline_udp_loopback_1400B` |
| TCP routing, topology, and optimization | `scg_routing_tcp_4KB`, `scg_routing_tcp_4KB_zerocopy`, `scg_routing_tcp_scgscg_4KB`, `scg_routing_tcp_256conn`, `scg_ktls13_tcp_4KB`, `scg_ktls13_tcp_4KB_zerocopy` |
| TLS and security profiles | `scg_tls12_tcp_4KB`, `scg_tls13_tcp_4KB`, `scg_tls13_tcp_scgscg_4KB`, `scg_mtls13_tcp_4KB`, `scg_integrity_tls12_tcp_4KB`, `scg_subset146_pki_tls12_tcp_4KB`, `scg_subset146_psk_tls12_tcp_4KB` |
| DTLS and UDP-over-TLS applications | `scg_dtls12_udp_1400B`, `scg_dtls12_mtls_udp_1400B`, `scg_ale_udp_over_tls13_1400B`, `scg_raw_udp_over_tls13_1400B` |
| Local interfaces | `scg_uds_routing_4KB`, `scg_uds_tls13_4KB`, `scg_shm_routing_4KB`, `scg_shm_routing_4KB_spinwait` |
| Transparent proxy | `scg_tproxy_tls13_4KB` (requires `CAP_NET_ADMIN`) |
| Payload and connection scaling | TLS 1.3 TCP at 64B, 256B, 1KB, 4KB, 16KB, and 64KB (`scg_tls13_tcp_*`); plus `scg_tls13_tcp_1024conn` and the routing 256-connection case above |
| Gateway RTT | `scg_tls13_pingpong_rtt_1KB`, `scg_routing_pingpong_rtt_1KB` |
| Scheduling and DSCP | `multistream_safety_bulk`, `multistream_dscp_preservation` |
| Hot reload | `hotreload_add_remove_endpoint`, `hotreload_invalid_config_rollback`, `hotreload_tls_profile_update` |
| Virtual topology and impairment | `scg_routing_veth_4KB`, `scg_tls13_netns_4KB`, `scg_routing_netem_50ms_4KB`, `scg_routing_netem_1pct_loss_4KB` (all require `CAP_NET_ADMIN`) |

Four entries are deliberately disabled, so they cannot be mistaken for tested
coverage: `scg_dtls12_udp_4conn` (the DTLS transport has one shared backend
flow), `scg_tls13_connrate` (gateway connection-rate mode is not implemented),
`wireguard_tcp_4KB`, and `ipsec_ikev2_tcp_4KB` (SCG provider stubs). A missing
gateway binary, `openssl`, or required privileges produces a recorded skip
rather than a fabricated result.

### Focused suites

| Suite | Scenarios and purpose |
| --- | --- |
| [`latency.json`](configs/latency.json) | `lat_tcp_loopback_1KB`, `lat_udp_loopback_1KB`, `lat_scg_routing_tcp_1KB`, `lat_scg_tls13_tcp_1KB`, `lat_scg_dtls12_udp_1KB`: paced one-way latency comparisons |
| [`saturation.json`](configs/saturation.json) | `sat_tcp_loopback_1KB`, `sat_udp_loopback_1KB`, `sat_scg_routing_tcp_1KB`, `sat_scg_dtls12_udp_1KB`: offered-load sweeps and loss-free ceilings |
| [`pingpong.json`](configs/pingpong.json) | `pp_tcp_loopback_64B`, `pp_tcp_loopback_1KB`, `pp_udp_loopback_64B`, `pp_udp_loopback_1KB`: loopback closed-loop RTT controls |
| [`connrate.json`](configs/connrate.json) | `conn_tcp_loopback_1thread`, `conn_tcp_loopback_4thread`: TCP connection/handshake rate controls |

---

## CLI reference

```
seshat [--log-level error|warn|info|debug|trace] [--quiet] <command>
```

| Command | Purpose | State |
| --- | --- | --- |
| `run` | Execute a full benchmark suite from a config | ✅ |
| `validate` | Parse + validate a config, report errors, do not run | ✅ |
| `list` | Expand and list every scenario with its parameters | ✅ |
| `calibrate` | Sweep the harness null-loopback throughput ceiling | ✅ |
| `sysinfo` | Dump host hardware/kernel info (`--format table\|json`) | ✅ |
| `sender` / `receiver` | Distributed (two-host) TCP mode | ✅ |
| `setup` / `teardown` | Create/remove a `veth`/`netns` topology | ✅ |
| `impair` | Apply `tc netem` latency/loss/jitter to an interface | ✅ |
| `report` | Re-generate CSV from an existing result directory | ✅ |

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
| `streams` | Multi-stream definition for scheduling scenarios | ✅ |
| `reload_event` | Hot-reload event (SIGHUP mid-measurement) | ✅ |
| `optimization_flags` | SCG perf toggles — zero-copy, spin-wait, … | ✅ |
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
  "type": "tls",            // none | tls | dtls | wireguard | ipsec
  "version": "1.3",         // 1.2 | 1.3
  "kernel": false,          // true → kTLS (kernel TLS)
  "mutual_auth": false,     // true → mTLS / mutual DTLS
  "protection_mode": "full",// full | integrity-only | routing-only
  "app_protocol": "none",   // none | ale | raw   (UDP-over-TLS framing)
  "cipher_suite": null
}
```

| `type` | Transport | Notes |
| --- | --- | --- |
| `none` | tcp | Plaintext / routing-only baseline through the SCG |
| `tls` | tcp | Userspace TLS 1.2/1.3; `kernel:true` → kTLS; `mutual_auth` → mTLS; `protection_mode:integrity-only` → NULL-cipher authenticated TLS |
| `dtls` | udp | DTLS 1.2, server-auth or `mutual_auth`; single logical flow |
| `wireguard` / `ipsec` | — | **Disabled** (SCG provides stubs only); kept for forward-compat |

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
| `cpu_pct_peak`, `cpu_pct_mean`, `gbps_per_core` | Gateway CPU utilisation (from `/proc`) and throughput efficiency |
| `perf_cycles`, `perf_instructions`, `perf_ipc`, `perf_cache_*`, `perf_context_switches`, `perf_task_clock_ms`, `perf_duration_s` | Scenario-wide `perf stat` hardware/software counters when the `perf` backend is enabled |
| `bottleneck` | Calibration verdict: `harness-io`, `scg`, … (who limited the result) |
| `rtt_us_mean/ci95/p50/p99` | Closed-loop round-trip time (populated only for `pingpong` scenarios) |
| `conns_per_sec`, `conns_per_sec_ci95`, `conn_handshake_p50_us`, `conn_handshake_p99_us` | Connection rate + handshake latency (populated only for `connrate` scenarios) |
| `conn_first_handshake_us`, `conn_resumed_handshake_us` | Session-resumption analysis: first (cold) vs subsequent (potentially resumed) TLS handshake latency |
| `perf_syscalls` | System calls during the scenario (from `raw_syscalls:sys_enter` tracepoint via `perf stat`) |

Each `runs.csv` adds the full latency percentile spread
(`p50/p90/p95/p99/p999/min/max`) and duplicate/reordered/outlier counts. For
`pingpong` rows the latency columns carry the RTT distribution; for `connrate`
rows they carry the per-connection handshake distribution.

---

## NFR-PERF — the harness must not be the bottleneck

The hard requirement is that SESHAT always saturates *after* the SCG, so every
number reflects the gateway's limit. This is enforced two ways:

1. **Engineering** — batched/vectored I/O, pre-allocated reusable buffers,
   immediate receive-side timestamping, statistics computed off the hot path,
   and harness threads pinnable to cores *separate* from the SCG.
2. **A calibration gate** — before trusting a gateway result, the harness
   measures its own loopback ceiling for that exact message shape. The console
   and CSV surface the `headroom` (ceiling ÷ measured) and flag any scenario
   `[HARNESS-LIMITED]` when the margin is insufficient, so questionable numbers
   are never reported silently. Run it standalone with `seshat calibrate`.

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
configs/                    example suites
benchmark_features.md       feature specification (F-01..F-20)
PLAN.md                     implementation plan + progress
run_all.sh                  full benchmark execution + result consolidation
```

---

## Relationship to other repos

- **System under test:** [`SCG`](../SCG) — the gateway binary and its
  `scg-client` / `scg-ipc` / `scg-proto` crates.
- **Legacy harness it replaces:**
  [`SCG-Interface-benchmarks`](../SCG-Interface-benchmarks).

---

## License

Apache-2.0 (see [LICENSE](LICENSE)).
