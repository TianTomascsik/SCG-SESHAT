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
| Hot-reload **TLS-profile swap on active connection** | **Gateway field-aware; harness no-op** | SCG `diff` now restarts changed same-name rules; SESHAT reload action doesn't yet rewrite the file. See §4 |
| WireGuard in the **unified `seshat run`** table | **Out of unified run (explicit blocked row)** | script-orchestrated `scripts/wg_*.sh`; every generated matrix tier carries a disabled `blocked_wireguard_script_orchestrated` row; see §4 |
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

**Fair cross-transport comparison & new modes (2026-07).** To let figures compare transports
and protocols like-for-like rather than apples-to-oranges, the matrix and suites gained:

- **Multi-connection stream IPC.** The UDS (`unix`) and SHM profiles in
  `configs/matrix_spec.json` no longer pin `connections: [1]`; they follow the tier like TCP
  (canonical `1`, nightly `[1,4,16,64]`). Each connection provisions its own endpoint
  (gRPC + `SCM_RIGHTS`), so this is a real concurrency sweep, letting concurrency-scaling and
  cross-transport figures cover more than TCP. UDP/DTLS stay single-connection by design (a
  datagram "connection" is a flow) and TPROXY stays `1` (no per-connection fan-out here).
  Regenerate the derived configs after editing the spec: `seshat matrix generate --spec
  configs/matrix_spec.json --out-dir configs`.
- **Paced latency-at-target.** `configs/latency.json` adds a `rate_limit_mbps` sweep
  (sustained, sub-saturation) per (transport, protocol) so latency is measured at a real
  offered load below saturation — `co_corrected=true`, not open-loop blast bufferbloat. This
  is the honest counterpart to the matrix's blast p99 (which is queue depth, ranking-only).
- **Cipher × size grid.** `append_cipher_scenarios` (`src/matrix.rs`) now sweeps each AEAD
  suite across a small stream-size grid in nightly (`1024/4096/16384 B`), not a single
  `4096 B` cell, so AES-128/256-GCM vs ChaCha20 cost is comparable across payloads.
- **Resumption / PSK / more handshake coverage.** `configs/connrate.json` adds TLS 1.3 session
  resumption (`resumption: true`, so `resumed_fraction > 0`), a subset146-PSK handshake, TLS 1.2
  and kTLS 1.3 variants, and an 8-thread point — so full-handshake vs resumed vs PSK vs
  cert(mTLS, already in the matrix) are comparable beyond the old routing-vs-TLS-1.3 / {1,4}-thread pair.
- **Perf pass (efficiency panels).** The cycles/byte, cache-miss, IPC and ctxsw figures need
  hardware counters: run a second pass with `seshat suite --tier nightly --metrics-backend perf`
  (or `scripts/collect_perf_data.sh`), keeping the default `procfs` pass for the headline
  throughput/latency numbers so perf sampling overhead never contaminates them.
- **Statistical rigor knobs.** Tighter CIs for comparison-critical or degenerate-CI rows come
  from existing overrides, e.g. `seshat suite --tier nightly --runs 5 --duration 10s`
  (optionally scoped with `--scenario-filter`); cost is linear in `runs × duration`.

**Figure-numbering note.** The visualization's resource-cost figure (F9) consolidates what were
once three separate figures (old F9 + F10 + F14); the gaps at F10/F14 are intentional, not
missing figures.

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
own null-loopback ceiling for the same message shape and computes headroom
(`ceiling / measured`), flagging `harness_limited` when headroom falls below 3×.
As of 2026-07 this gate was overhauled end to end:

- **The harness itself is batched.** Stream transports (TCP, and the gateway/
  TPROXY paths built on it) send whole batches with one vectored `writev`
  (size-adaptive, up to 1024 messages / 256 KiB per call) and carve every
  message one `read` yields out of a cursor-based reassembly buffer (one
  compaction memmove per buffer-full instead of one per message). The UDS
  client (`scg-client`) batches identically (one `writev` per ≤512 frames; a
  buffered `FrameDecoder` receive with no per-frame allocation). The
  deterministic payload fill/verify runs in 256-byte blocks against a static
  ramp table (memcpy/memcmp-class) instead of a per-byte function call, so the
  integrity check can never become the harness's own hot-path ceiling. Net
  effect on the single-connection TCP loopback ceiling: ~0.14 → ~9 Gbit/s at
  64 B (~62×), ~2 → ~41 Gbit/s at 1 KiB, ~13 → ~51 Gbit/s at 16 KiB — the
  harness ceiling is now transport-bound, not syscall- or validation-bound.
- **The probe runs under the scenario's own conditions.** The ceiling probe is
  pinned to the same sender/receiver core pools as the scenario, warmed for
  500 ms, measured for 1 s, and taken as the **best of 2** probes (probe noise
  is one-sided — it can only depress a probe — so max-of-N estimates the true
  ceiling from below and can never overstate the harness). The earlier probe
  (unpinned, unwarmed, 500 ms, single-shot) systematically under-measured,
  producing rows as absurd as `headroom = 0.32`; a measured value far above the
  ceiling (headroom < 0.85) now triggers a loud `suspect ceiling` warning.
  One caveat is expected and benign: a *near-transparent* gateway path
  (routing/passthrough) is a three-stage sender→gateway→receiver pipeline whose
  kernel work spreads over more cores than the two-thread null probe, so it can
  legitimately measure a few percent **above** the ceiling (headroom 0.9–1.0);
  such rows stay conservatively flagged `harness-io`.
- **Ceilings are interface-true.** The probe uses the scenario's *access*
  interface: UDP for DTLS **and ALE/RAW**, a Unix-stream pair (`uds-null`) for
  UDS, a shared-memory ring sized like the scenario's (`shm-null`) for SHM, and
  TCP otherwise (TPROXY's client side is plain TCP). Every row records its
  `ceiling_transport` (a failed null-transport probe falls back to TCP and says
  so). Ceilings are cached per (interface, size, connections, core pools).
- **The bottleneck classifier uses three CPU signals** (all p95 over the
  sampler's ticks — a single 200 ms burst cannot flip a label and cooldown
  ticks cannot dilute one): (1) gateway pool ≥ 85 % of its pinned cores →
  `scg-cpu` (trusted); (2) hottest single gateway thread ≥ 90 % of one core →
  `scg-cpu` (the per-connection data plane is serial, so a pegged relay thread
  is the gateway's limit even when its pool looks idle — this fixes the
  1-connection misclassification); (3) whole host ≥ 90 % busy →
  `host-saturated`: sender, receiver, and gateway together exhaust the machine,
  so no harness improvement could add headroom. `host-saturated` rows **keep**
  `harness_limited=true` — the figure is a trustworthy *lower bound*, not a
  demonstrated gateway limit — but the distinct label lets figures separate
  single-host physics from harness slowness. Only the residual (low headroom,
  no explaining CPU signal) is labeled `harness-io`.

**Reading the concurrency sweep (F15).** On a single loopback host, sweeping
SHM/UDS connection count does **not** raise aggregate throughput, and this is not
a harness or gateway defect. The engine opens N independent gateway endpoints per
connection (`run/engine.rs`, one gRPC/`SCM_RIGHTS` endpoint + sender/receiver
thread pair each) and the gateway spawns a dedicated relay thread per endpoint, so
the "add a thread per interface" fan-out is already in place. But the data plane
is *serial per connection* and loopback has no NIC for SHM/UDS to bypass, so the
box stays largely idle (`host_busy_frac_p95` ≈ 0.09–0.30) while one relay thread
pegs a core (`cpu_hot_thread_pct_p95` ≈ 85–100 %, hence `scg-cpu`). Routing already
sits at the single-stream loopback ceiling and encrypted paths even *decline* (per-
thread CPU falls as they stall on per-connection poll/futex wakeups). That is why
`unix`/`shm` are capped at the nightly `[1,4,16,64]` ladder rather than the
256/1024 scalability tier — past it the sweep only re-measures the serial ceiling —
and why F15 tags each point with its bottleneck class. The `shm_null.rs`/
`uds_null.rs` `connections:1` transports are the ceiling-calibration probes (no
gateway attached), not the benchmark path. The remedy for real scaling is a
bandwidth-bound / real-NIC tier (or a non-serial local-IPC relay), not more
connections.

`perf_gate.sh --strict` still refuses to publish `harness_limited=true`
throughput rows, including `host-saturated` ones (by design: a lower bound is
not a publishable gateway limit).

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
5. **Hot-reload TLS-profile / cert change: gateway now field-aware; harness
   scenario not yet exercising it.** *Historical note:* the gateway's
   `GatewayConfig::diff` used to match rules **by name only**, so a same-name
   rule whose profile changed was classified `unchanged` and never re-applied
   (a true no-op). That gateway limitation has since been fixed: `diff` now has a
   `changed` bucket driven by `RuleConfig::reload_differs`, which compares
   security-relevant fields (provider, upstream, protocol, profile, `verify`,
   cert/CA, classification, QoS) and restarts the affected listener. So a
   same-name field change **is** now applied by the gateway. SESHAT's
   `UpdateTlsProfile`/`RotateCert` actions, however, currently only send SIGHUP
   *without rewriting the config file*, so at the harness level they remain a
   no-op and are still reported `change_applied=false` — the limitation is now on
   the harness side, not the gateway. Exercising the new capability requires the
   reload action to write a modified same-name rule (future work). Add/remove
   connection (gRPC) and invalid-config rollback *do* take effect and stay
   zero-drop.
6. **WireGuard is not in the unified `seshat run` table.** It is a kernel offload
   that needs a separate network namespace per gateway; the in-process spawn is
   not netns-aware and the distributed sender/receiver are TCP-only. WG is
   measured by the privileged script harness (`scripts/wg_*.sh`, `wg_probe.py`)
   and reported separately. Folding it in needs a netns-aware `GatewayProcess`
   and a UDP distributed engine (future work). So that no unified run silently
   omits this, every generated matrix tier (`matrix_catalog.json`,
   `full_matrix.json`, `canonical_matrix.json`) carries an explicit disabled
   `blocked_wireguard_script_orchestrated` row whose `disabled_reason` points
   at the `scripts/wg_bench.sh` / `scripts/perf_gate.sh` orchestration; the
   runner never executes disabled rows, so the row is a pure coverage signal.
7. **Loopback dominance.** Most scenarios run on loopback; the physical-NIC and
   veth/netns topologies are supported but a loopback ceiling can mask real-NIC
   effects. Use the netem-impaired and veth topologies for path realism. A
   related single-host limit is surfaced explicitly since 2026-07: rows where
   the whole host is ≥90 % busy are labeled `bottleneck=host-saturated` (still
   `harness_limited=true`) — loopback co-saturation means the measurement is a
   lower bound that no harness improvement could raise. Note also that the SHM
   null ceiling measures the harness's ring push/pop ability (memcpy-bound) and
   is therefore generous; SHM rows lean on the CPU signals for honest
   classification. Per-thread CPU deltas only diff tids present in consecutive
   sampler ticks, so thread churn between 200 ms ticks cannot fabricate a
   hot-thread signal (it can only briefly under-report one).
8. **`perf`/eBPF are optional.** When unavailable the corresponding columns are
   empty (graceful), so a result without them is incomplete, not wrong.
9. **Jitter is PDV, throughput is wire-bytes.** Both are valid but must be stated;
   readers expecting latency-stddev or payload-goodput should convert.
10. **Blast rows measure capacity under an efficient (batched) load generator,
    not a naïve application.** Since the 2026-07 fast-path work, the blast
    sender coalesces up to 1024 messages per vectored syscall — standard load-
    generator practice (`iperf3`, `pktgen`) and required by NFR-PERF, and the
    wire contents are unchanged in kind (byte-identical stream framing on
    TCP/UDS; identical discrete datagrams on UDP/DTLS). The batched connection
    stands in for the *aggregate* of many clients. Two consequences must be
    stated: (a) the gateway's ingress sees fewer, larger reads than a legacy
    application issuing one `write()` per message, so per-wakeup gateway
    overheads are amortised — throughput ceilings are upper-bound capacity
    figures, and a single unbatched client would offer less; (b) application-
    representative behavior lives in the paced/periodic, ping-pong, and
    connection-rate modes, which intentionally remain one-message-per-event
    (`send_msg` per schedule tick, one in-flight round trip) so latency and
    ETCS-like low-rate results are unaffected by batching.

---

## 5. Provenance of this methodology

The harness changes underpinning §2–§3 (coordinated-omission correction, exact
metric totals, environment capture + preflight, the eBPF memory-copy backend,
resumption telemetry, honest hot-reload accounting, the optimization-knob A/B
surface, and the degradation-curve annotations) were added as a scientific-rigor
pass; see the per-area commits and the unit tests in
`src/{proto/wire,workload/sender,run/engine,metrics/system,sysinfo,gateway}.rs`.
