# SESHAT — measurement methodology, coverage, and limitations

This document is the scientific companion to the SESHAT benchmark harness. It
states, defensibly and with source references, **what SESHAT measures**, **how**,
**what it covers** against the feature spec (`benchmark_features.md`), and **where
the limits are**. It is written for thesis/examiner scrutiny: every metric is
either directly observed (cited below) or explicitly marked as not measured.

Terminology: *DUT* = the SCG gateway under test; *paced* = an open-loop sender
with a non-zero inter-message gap; *blast* = an unthrottled open-loop sender.

---

## 1. Spec → implementation matrix

| Capability (benchmark_features.md) | Status | Where |
|---|---|---|
| Transports: TCP, UDP, UDS, SHM ring, TPROXY | **Implemented** | `src/transport/{tcp,udp,uds,shm,tproxy,gateway}.rs` |
| Topologies: `scg-direct`, `scg-scg` | **Implemented** | `src/gateway/mod.rs` (`build_path`, `Topology`) |
| Protocols: TLS 1.2/1.3, kTLS, DTLS 1.0/1.2, ALE/raw UDP-in-TLS, integrity-only, subset-146 PKI/PSK, routing | **Implemented** | `src/gateway/config.rs`, `src/commands.rs` (`gateway_plan`) |
| mTLS (TLS, kTLS, DTLS, ALE, raw) | **Implemented** | `GwSecurity::Mtls`; ALE/raw mTLS scenarios added (`configs/full_suite.json`) |
| Modes: throughput, saturation sweep, paced latency, ping-pong RTT, connection-rate, multi-stream QoS, hot-reload | **Implemented** | `src/run/{engine,saturation}.rs`, `src/workload/streams.rs`, `src/gateway/reload.rs` |
| Parallel connections, payload sweep (64 B … 64 KB + 9 KB jumbo datagram) | **Implemented** | `src/run/engine.rs`; `configs/matrix_spec.json` |
| Metrics: throughput, latency mean/p50/p95/p99/p999, jitter, loss, CPU, RSS/PSS, **context switches (exact, process-wide)**, perf HW counters, handshake latency, DSCP preservation, encapsulation overhead | **Implemented** | `src/metrics/{app,stats,system}.rs`, `src/report/results.rs` |
| **Memory copies per message** | **Implemented (privileged)** | eBPF backend `src/metrics/system.rs` + `scripts/mem_copies.bt`; needs root + `bpftrace` |
| **Session-resumption ground truth** | **Implemented (userspace TLS + kTLS)** | SCG logs `resumed=` on both accept paths; `src/gateway/logscan.rs` counts → `resumed_fraction` |
| Coordinated-omission-corrected latency | **Implemented (paced)** | `src/run/engine.rs` (scheduled-send stamping) |
| Reproducibility capture: governor, **turbo**, SMT, isolcpus, **NUMA**, THP, **git hashes** + preflight warnings | **Implemented** | `src/sysinfo.rs` (`preflight_warnings`) |
| DTLS/UDP **multi-connection** per-connection metrics | **Not measured (scoped)** | gateway demuxes by peer but forwards to one backend; see §4 |
| Hot-reload **TLS-profile swap on active connection** | **Not effective (no-op)** | SCG diff is name-keyed; see §4 |
| WireGuard in the **unified `seshat run`** table | **Out of unified run** | script-orchestrated `scripts/wg_*.sh`; see §4 |
| IPSec/IKEv2 | **Not implemented (SCG stub)** | disabled scenarios |

---

## 2. Measurement methodology

**Clock.** All timing uses `CLOCK_MONOTONIC` via `clock_gettime`
(`src/time.rs`), which never steps backward and is unaffected by NTP. Latency is
the difference of two monotonic reads in one process (same clock domain).

**Throughput** (`src/metrics/app.rs::throughput_gbps`) = `wire_bytes·8 / 1e9 /
window_seconds`. Wire bytes include the 24-byte SESHAT header
(`src/proto/wire.rs`), which is *carved out* of the configured message size so
the SCG sees exactly the requested on-wire size. The window is bounded by the
main thread's `PHASE_MEASURE → PHASE_COOLDOWN` transition; warmup and cooldown
traffic is deterministically excluded by a per-message phase check
(`src/run/engine.rs`).

**Latency & percentiles.** Every received message yields one
`(seq, latency_ns)` sample — no histogram approximation. Percentiles are exact,
sorted, linearly interpolated (R-7 / numpy "type 7";
`src/metrics/stats.rs::percentile`): p50/p90/p95/p99/p999. Jitter is mean
absolute consecutive-sample difference (packet delay variation, order-preserving;
`src/metrics/app.rs::jitter`) — *not* standard deviation.

**Coordinated omission.** Open-loop latency is corrected for paced senders: each
message is stamped with its **scheduled** send time (`start + n·interval`), not
its actual send time, so when the pacer falls behind, the queueing it absorbed
stays visible in receiver-side latency (the wrk2/HdrHistogram approach;
`src/run/engine.rs::sender_loop` via `MessageBuilder::build_at`). The result
columns carry `co_corrected` (true for paced and for the inherently closed-loop
ping-pong/connrate modes; false only for blast, where there is no schedule) and
`send_lag_mean_us`/`send_lag_max_us` — the magnitude of the omission that naïve
actual-send stamping would have hidden. Latency-sensitive scenarios should use
ping-pong mode, which measures RTT closed-loop and is CO-immune by construction.

**Statistics across runs.** N independent runs, each with its own
warmup/measure/cooldown. Aggregation uses Bessel-corrected stddev, Student-*t*
95 % confidence intervals (honest at small N; `ci95_halfwidth`), optional
Tukey-1.5·IQR outlier removal (reported count), and coefficient of variation
(`src/metrics/stats.rs`). All statistics are native Rust and deterministic
(no third-party stats dependency → exact cross-platform reproducibility).

**System metrics** (`src/metrics/system.rs`). The gateway PID(s) are sampled
from `/proc/<pid>/{stat,status,io,smaps_rollup}` on a background thread (default
**50 Hz**, configurable) for the spike-sensitive timeseries (peak CPU, RSS/PSS).
Headline **totals are exact, not sampled**: CPU-seconds and context switches come
from first→last cumulative-counter deltas over the sampled span, so they are
independent of the sample rate. CPU ticks are process-wide (`/proc/pid/stat`);
context switches are summed across all threads (`/proc/pid/task/<tid>/status`,
not the thread-group leader alone, which would read ~0 for a worker-threaded
gateway). Surfaced columns include `cpu_pct_peak`, `cpu_pct_mean`,
`cpu_seconds_total`, `ctx_switches_total`, `ctx_switches_per_s`.
`perf stat` hardware counters (cycles, IPC, cache, context-switches, syscalls,
task-clock) are collected when the `perf` backend is selected and available.

**Memory copies per message** (eBPF backend, `scripts/mem_copies.bt`). When the
`ebpf` backend is selected and the host is privileged, a `bpftrace` probe counts
`_copy_to_user`/`_copy_from_user` and the payload-moving syscalls
(`sendmsg`/`recvmsg`/`splice`) attributed to the gateway PID(s) over the run. The
reported `mem_copies_per_msg` divides total user↔kernel copies by messages
delivered — directly demonstrating that the splice/kTLS zero-copy paths approach
~0 user copies per message while userspace TLS copies each payload in and out.
Degrades to empty (`[SKIPPED]`) when unprivileged or `bpftrace` is absent.

**Session resumption ground truth.** The SCG logs `resumed=<bool>` per TLS accept
(`SSL_session_reused`) on the decrypt side, for both the userspace-TLS and kTLS
paths (the kTLS handshake still runs through OpenSSL).
`src/gateway/logscan.rs` counts resumed vs full handshakes and reports
`resumed_fraction` — the ground-truth counterpart to the timing-based
first-vs-resumed handshake latency already collected by the connection-rate mode.
(End-to-end verified: a connrate run logs `resumed=false` per fresh handshake and
reports `resumed_fraction=0`; a resumption-enabled run reports a positive
fraction.)

**NFR-PERF (the harness is never the bottleneck).** Before trusting an SCG
throughput figure, the calibrator (`src/run/calibrate.rs`) measures the harness's
own loopback ceiling for the same message shape and computes headroom
(`ceiling / measured`). A result is flagged `harness_limited` when headroom is
below the threshold *unless* the gateway's pinned cores are saturated — in which
case the SCG genuinely is the bottleneck and the figure is trusted. `perf_gate.sh
--strict` refuses to publish `harness_limited=true` throughput rows.

---

## 3. Reproducibility

Each result directory captures a host fingerprint (`sysinfo.csv`): CPU model/
topology, **governor**, **turbo/boost state**, SMT, **isolated CPUs**, **NUMA node
count**, THP policy, kTLS usability, and the **SESHAT and SCG git commits**
(`src/sysinfo.rs`). At the start of a run, `preflight_warnings` emits `WARN` lines
when the host is not in a controlled state (governor ≠ `performance`, turbo on,
SMT active, multi-node NUMA without isolated CPUs) so a number is never silently
taken on a drifting box.

**Recommended controlled setup** (document alongside published numbers):

```
sudo cpupower frequency-set -g performance         # pin clocks
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo   # disable turbo
# boot with isolcpus=<gateway,sender,receiver cores>, then pin via the config's
# cpu_affinity_{gateway,sender,receiver}; keep all three on one NUMA node.
```

Determinism: no `Math.random`/wall-clock in measurement logic; workload patterns
are deterministic; CSV-only, per-run output enables independent re-analysis.

---

## 4. Limitations (state these when publishing)

1. **Open-loop blast latency is CO-uncorrected.** Paced scenarios are corrected
   (§2); an unthrottled blast has no schedule to correct against and its latency
   is queueing-dominated. Such rows carry `co_corrected=false`. Use ping-pong for
   latency claims.
2. **System-metric window includes warmup/cooldown.** The sampler spans the whole
   scenario (all runs). Totals are *exact* for that span but not measure-window-
   only; with the default 30 s measure vs 5 s+2 s warmup/cooldown per run this is
   a bounded ~19 % envelope. Measure-only alignment needs per-phase counter
   snapshots threaded from the run engine (future work).
3. **Memory copies require root + `bpftrace`** and a kernel exposing
   `_copy_to_user`/`_copy_from_user` (stable on x86_64); otherwise the columns are
   empty. The eBPF backend covers the standard throughput path (not multi-stream/
   hot-reload).
4. **DTLS/UDP per-connection metrics are not produced.** Verified: the SCG DTLS
   engine *does* demux clients by peer address (`dtls_engine.rs`,
   `HashMap<SocketAddr, session>`), so N source ports create N sessions. The
   blocker is harness-side attribution — the decrypt rule forwards every session
   to one shared backend socket, so N receiver threads steal datagrams from a
   single socket and each sees gap-riddled sequences (bogus per-connection loss).
   Correct per-connection metrics need either N independent ingress→backend rule
   pairs or an aggregate-only N-flow receiver. The 4-conn scenario is kept
   disabled rather than emit wrong numbers.
5. **Hot-reload TLS-profile / cert change is a no-op on the current SCG.** The
   gateway's config diff matches rules **by name only**
   (`GatewayConfig::diff`), so a same-name rule whose profile changed is
   classified `unchanged` and never re-applied. A zero-drop result therefore
   proves nothing (nothing happened); the harness flags this as
   `change_applied=false` and the scenario is disabled. Add/remove connection
   (gRPC) and invalid-config rollback *do* take effect and must stay zero-drop.
   True seamless profile reload needs an SCG enhancement (content-aware diff or a
   gRPC rule-update API).
6. **WireGuard is not in the unified `seshat run` table.** It is a kernel offload
   that needs a separate network namespace per gateway; the in-process spawn is
   not netns-aware and the distributed sender/receiver are TCP-only. WG is
   measured by the privileged script harness (`scripts/wg_*.sh`, `wg_probe.py`)
   and reported separately. Folding it in needs a netns-aware `GatewayProcess`
   and a UDP distributed engine (future work).
7. **Loopback dominance.** Most scenarios run on loopback; the physical-NIC and
   veth/netns topologies are supported but a loopback ceiling can mask real-NIC
   effects. Use the netem-impaired and veth topologies for path realism.
8. **`perf`/eBPF are optional.** When unavailable the corresponding columns are
   empty (graceful), so a result without them is incomplete, not wrong.
9. **Jitter is PDV, throughput is wire-bytes.** Both are valid but must be stated;
   readers expecting latency-stddev or payload-goodput should convert.

---

## 5. Provenance of this methodology

The harness changes underpinning §2–§3 (coordinated-omission correction, exact
metric totals, environment capture + preflight, the eBPF memory-copy backend,
resumption telemetry, honest hot-reload accounting, the optimization-knob A/B
surface, and the degradation-curve annotations) were added as a scientific-rigor
pass; see the per-area commits and the unit tests in
`src/{proto/wire,workload/sender,run/engine,metrics/system,sysinfo,gateway}.rs`.
