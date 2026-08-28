# SESHAT Implementation Plan

## Generated Matrix and Interface Comparison (implemented)

The benchmark matrix is now generated from `configs/matrix_spec.json` with
`seshat matrix generate`. The committed outputs are `canonical_matrix.json`,
`full_matrix.json`, `matrix_catalog.json`, and `interface_comparison.json`.
`run_all.sh` executes the canonical and interface suites by default; `--nightly`
selects the exhaustive generated matrix.

The interface suite compares direct TCP loopback, SCG TCP routing, TPROXY, UDS,
and SHM with matched routing-only traffic. It records absolute values and
direct-TCP/SCG-TCP deltas in `interface_comparison.csv`; latency rows pace at
50% of the lowest successfully measured throughput within their comparison
group. Capability-dependent paths are recorded in `skipped.csv` rather than
silently omitted.

Implemented supporting changes: DTLS 1.0 configuration validation, OpenSSL/
kTLS/DTLS/privilege/perf preflight, TLS-version-specific cipher setup, PSS
sampling, payload/boundary validation counters, gateway completed-path
connection-rate support, hot-reload artifacts, and per-stream scheduling CSVs.
True kTLS+mTLS, total physical copy counts, session-resumption classification,
and acknowledged same-rule TLS-profile reload remain SCG architectural work and
are explicitly catalogued/documented rather than misreported.

> **S**CG **E**valuation, **S**tress & **H**arness **A**nalysis **T**oolkit
>
> Build out `SCG-SESHAT` (currently a scaffold) into the full benchmark harness
> specified in [benchmark_features.md](benchmark_features.md) (features
> F-01..F-20). The harness drives the real `gateway` binary end-to-end; measures
> performance, protocol agility, scheduling, and hot-reload; and emits CSV. It
> reuses proven SCG crates (`scg-client`, `scg-ipc`, `scg-proto`,
> `ktls_pipe`/`tls_pipe`) via path deps. A small set of SCG gateway changes adds
> zero-copy + spin-wait config toggles so optimizations can be benchmarked
> against a baseline. WireGuard/IPSec are defined as disabled scenarios.

---

## Progress

- **Phase 0 — Foundation**: ✅ complete (WP0.1 CLI/skeleton, WP0.2 config + `validate`/`list`, WP0.3 `sysinfo`).
- **Phase 1 — Core measurement engine (loopback)**: ✅ complete — WP1.1 wire+clock, WP1.2 metrics+stats, WP1.3 workload, WP1.4 run engine, WP1.5 transport (tcp/udp), WP1.6 CSV+result-dir, WP1.7 calibration/NFR-PERF gate. `seshat run`/`calibrate` execute loopback suites end-to-end; gateway/crypto/stream scenarios skipped pending Phase 2. 68 tests green, clippy clean.
- **Phase 2 — Gateway integration**: ⏳ in progress.
  - **WP2.1 — Gateway lifecycle**: ✅ complete. `src/gateway/{config,process,mod}.rs` generate the gateway JSON (rules + allow-all policy + api block), spawn the real `gateway` binary, wait for readiness by socket-polling (not log-scraping), capture logs to the work dir, and shut down via `SIGTERM`→`SIGKILL` with a `Drop` guard. Both topologies (single-gateway, scg↔scg) build, stand up, proxy, and tear down. `src/pki.rs` mints EC certs via the `openssl` CLI (no Rust crypto dep). Validated end-to-end: routing TCP round-trip (both topologies) **and** TLS 1.3 round-trip (gateway does crypto internally; SESHAT speaks plaintext to ingress/backend). 79 tests green, clippy clean.
  - **Gateway-backed TCP transport + run wiring**: ✅ complete. `src/transport/gateway.rs` (`GatewayTcpTransport`) plugs the real SCG path into the run engine via the existing `Transport` trait — sender connects to the encrypt ingress, the gateway forwards plaintext out the decrypt upstream to a backend listener that becomes the receiver. Binds backend before gateway start and skips leftover readiness-probe connections via a liveness peek (the fix for the initial "0 messages" bug). `commands.rs` now resolves each scenario to loopback **or** gateway, probes a working gateway binary once, runs SCG scenarios through `engine::run_scenario`, and computes headroom with `Calibration::for_scg` (ceiling = loopback-TCP capacity for the shape) — surfacing a yellow `[HARNESS-LIMITED]` marker and `harness_limited`/`dut=scg` CSV columns. Verified `seshat run` end-to-end: routing (direct + scg↔scg), userspace TLS 1.3, and kTLS (graceful userspace fallback when the kernel `tls` module is absent), all 0-loss with archived per-scenario gateway configs/logs/certs.
  - **WP2.5 — Security & app-protocol matrix**: ⏳ partial. Implemented: routing (`type=none`/`protection-mode=routing-only`), userspace TLS + kTLS (`kernel=true`) at `tls1.2`/`tls1.3` server-auth, **mTLS** (`mutual_auth`, CA-signed client+server certs verified both ways), **integrity-only** (`protection-mode=integrity-only`, NULL-cipher authenticated TLS 1.2) over TCP, plus **DTLS over UDP** (`type=dtls`, server-auth + `mutual_auth`) via a new `GatewayUdpTransport`, all both topologies. Still pending: ALE/RAW (UDP-over-TLS framing), TLS-PSK/Subset-146.
  - **WP2.6 — System metrics**: ✅ complete (procfs). `src/metrics/system.rs` samples each live gateway PID's `/proc/{stat,status,io}` at `metrics_sample_rate_hz` on a background thread (CPU%, RSS, threads, ctx-switches, block I/O) and writes one `gateway_pid_<pid>.csv` timeseries per process under `scenarios/<name>/system_metrics/`. Honors `--no-system-metrics`/`backend=none`; `perf`/`ebpf` backends still TODO.
- **Benchmark-fidelity improvements (A–G)**: ✅ complete. Seven cross-cutting upgrades that make the numbers trustworthy: **(A)** core-pinning + auto-affinity + saturation-aware headroom verdict; **(B)** effective-protocol detection (logscan surfaces `tls/1.3 (ktls→userspace)` when kTLS falls back) → `effective_protocol` column; **(C)** gateway CPU% aggregation + `bottleneck`/`gbps_per_core` verdict; **(D)** per-scenario offered-load **saturation sweep** (`saturation_gbps`, `max_lossfree_gbps`) — fulfils the saturation half of WP3.1; **(E)** kTLS **auto-detect** via a real `TCP_ULP` probe + WSL2 awareness (`sysinfo` `ktls_usable`/`wsl`); **(F)** closed-loop **ping-pong RTT** mode (`mode:pingpong`, `rtt_us_*`); **(G)** **connection-establishment rate** mode (`mode:connrate`, `conns_per_sec` + handshake latency) — fulfils the connection-rate half of WP3.1. 108 tests green, clippy clean. New configs: `latency`, `saturation`, `pingpong`, `connrate`.
- Phases 3–6: WP3.1 (saturation + connection-establishment) largely landed via improvements D & G; multi-stream scheduling/QoS, topology/distributed, and SCG optimization toggles not started.

---

## Locked decisions

1. **WireGuard/IPSec** → defined as **disabled/skipped** scenarios (forward-compatible). No SCG crypto changes.
2. **Optimization toggles** → **YES**, add SCG gateway changes for `zero_copy` + `spin_wait`. These live in the **SCG gateway config files** (per-rule fields in the gateway JSON config that SESHAT generates), set per scenario (Phase 5).
3. **Reuse proven crates** via path deps (`scg-client`, `scg-ipc`, `scg-proto`, `ktls_pipe`, `tls_pipe`); SESHAT otherwise standalone. Latency statistics implemented **natively** (the legacy `bench_log` is only in `old/`, not the current SCG workspace).
4. **Gateway orchestration** → SESHAT **spawns/teardowns real gateways**; cover BOTH topologies (`client↔SCG↔SCG↔client` and `client↔SCG↔client`).
5. **Output** → **CSV only** (single format). Raw per-run samples + sysinfo still captured for reproducibility.
6. **Binary name** → **`seshat`** only (CLI = `run | sender | receiver | report | validate | list | sysinfo | setup | teardown | impair`).
7. **NFR-PERF (hard requirement)** → the harness must **NEVER** be the bottleneck — only the SCG. SESHAT's sender/receiver must generate + absorb traffic and resolve latency faster than the SCG under test, so every measurement reflects the SCG's limit. Enforced by engineering (batched/vectored I/O, pre-allocated buffers, multi-threaded senders/receivers pinned to cores **separate** from the SCG, immediate recv-timestamping, stats off the hot path) **and** by a mandatory headroom-calibration gate (WP1.7). If `scg-client`'s simple sync `send`/`recv` can't keep up, drop to `scg-ipc` rings/framing directly with batching.
8. **Proprietary vendor providers** → **EXCLUDED** (out of scope for the open harness; not benchmarked).

---

## Real SCG capabilities (verified against `SCG/gateway/src`)

- **Transports**: TCP, UDP, UDS, SHM — all real. UDS/SHM dynamically provisioned via the gRPC management API.
- **Crypto**: `tls` (userspace), `ktls` (kernel), `dtls` (1.0/1.2), `routing` (plaintext L4). Integrity-only = TLS NULL cipher profile. mTLS, TLS 1.2/1.3, PSK (subset146-psk), subset146-pki — all real.
- **App protocols**: `ale`, `raw` (UDP-over-TLS framing).
- **TPROXY** transparent mode: real (`interfaces/tproxy.rs`).
- **QoS**: DSCP set/preserve + `SO_PRIORITY` + safety-thread nice (`networking/socket_manager.rs`).
- **Hot-reload**: `SIGHUP` + file-watch (`--watch`). No gRPC reload RPC. New connections get new config; in-flight keep old.
- **gRPC mgmt API** (UDS, tonic): `CreateUdsEndpoint`, `CreateShmEndpoint`, `CloseEndpoint`, `Health`, `ListRules`.
- **Perf knobs today**: `sock_buf_size`, `buffer_slots`, `buffer_slot_size`, `shm_ring_capacity`, `simulated_delay_ms`. No zero-copy/spin-wait toggle yet (Phase 5 adds them).
- **WireGuard + IPSec/IKEv2**: STUB only (`security/stubs.rs`) — not usable.
- **Gateway launch**: `gateway --config FILE [--watch] [--log-level L]`.

### Key reusable assets

- `SCG/crates/scg-client` → `ScgClient::connect(Some(&mgmt_path), app_id, Transport::{Uds|Shm}, TrafficClass, Direction)` + `.send(traffic_id, &payload)` + `.recv_timeout(...)` + `.close()`. Handles gRPC provisioning + token HELLO + `SCM_RIGHTS` rings.
  - `scg_client::mgmt::{create_endpoint, close_endpoint, Created}` — low-level ops.
  - `scg_client::shm::ShmClient::connect(control_socket_path, token, role)`.
- Reference flow: `SCG/gateway/tests/local_interface_e2e.rs`.
- `SCG/crates/scg-ipc` → `frame::{encode_into, FrameDecoder}`, rings, token, handshake.
- `SCG/crates/scg-proto` → generated `management_api_client::ManagementApiClient`.
- `SCG/crates/{ktls_pipe,tls_pipe}` → client-side TLS/kTLS pipe abstractions.
- Gateway test fixtures: `dscp.rs`, `subset146_{pki,psk}.rs`, `integrity_only.rs`, `dtls.rs`, `ale_raw.rs`, `routing_smoke.rs`, `common/{pki,qos,dtls}.rs`.

---

## SCG feature-coverage gaps added to the harness

The raw spec under-covers several real SCG features; these are added to the plan:

- **A. kTLS as a first-class variant** distinct from userspace TLS → WP2.5 (`type=tls`, `kernel=true`).
- **B. UDS/SHM via real gRPC provisioning** (token + `SCM_RIGHTS`), not raw IPC → WP2.3 / WP2.4 via `scg-client`.
- **C. TPROXY transparent interface mode** → WP2.7.
- **D. ALE + RAW app-protocol variants** (UDP-over-TLS) → WP2.5.
- **E. TLS-PSK (subset146-psk) + Subset-146 PKI + integrity-only (NULL) + routing-only** → WP2.5.
- **F. gRPC mgmt API** for UDS/SHM provisioning AND runtime add/remove endpoint (hot-reload) → WP2.2 + WP3.4.
- **G. SCG perf knobs** in gateway config files (`sock_buf_size`, `buffer_slots`/`slot_size`, `shm_ring_capacity`, `simulated_delay_ms` + NEW `zero_copy`/`spin_wait`) → Phase 5.

Spec-but-not-in-SCG (mark disabled): **WireGuard**, **IPSec/IKEv2** → WP6.1.

Adaptation: hot-reload triggered via `SIGHUP`/file-watch (+ gRPC create/close), not a gRPC reload RPC (none exists). "Change TLS profile on active connection" affects only NEW connections in the current SCG — documented.

---

## NFR-PERF — Harness must not be the bottleneck (cross-cutting; gates Phases 1–3)

Every perf-path component is built so the SCG saturates first:

- **Sender**: batched/vectored I/O (`writev`; `sendmmsg` for UDP; large coalesced TCP writes; ring batch-fill for SHM amortizing `eventfd` wakeups), pre-allocated reusable buffers (zero per-message alloc), optional multiple sender threads, rate generated faster than the SCG can consume.
- **Receiver**: immediate `CLOCK_MONOTONIC` timestamp on recv; `recvmmsg` for UDP; minimal hot-path work; stats/aggregation deferred off the hot path (lock-free handoff / per-thread accumulators).
- **Placement**: sender/receiver threads pinned to cores **separate** from the SCG; avoid cross-core cache bouncing.
- **UDS/SHM**: prefer `scg-client` for correctness; if WP1.7 calibration shows it caps below SCG capacity, use `scg-ipc` rings/framing directly with batched frames.
- **Calibration gate (WP1.7)**: a null/loopback path measures the harness's own ceiling; console + CSV must show harness ceiling ≫ measured SCG throughput (≥3–5×). If the margin is insufficient, the run is flagged `HARNESS-LIMITED` and the scenario is not trusted.

---

## Module layout (crate `seshat`)

```
src/main.rs              dispatch
src/cli.rs               clap definitions (F-01, F-02)
src/logging.rs           level-based logger (F-16)
src/console.rs           banners / tables / progress
src/config/{mod,schema,scenario}.rs   config model + validation (F-03, F-04)
src/sysinfo.rs           hardware/kernel snapshot (F-19)
src/proto/wire.rs        SpikeHeader payload format (F-12)
src/workload/{sender,receiver,streams}.rs   traffic generators (F-07, F-10, F-12)
src/metrics/{app,system,stats}.rs   app + system metrics, statistics (F-13, F-14)
src/run/{mod,orchestrator}.rs       run execution model (F-15, F-20)
src/transport/{mod,tcp,udp,uds,shm,tproxy}.rs   transports (F-05)
src/gateway/{mod,grpc_client}.rs    spawn/teardown + config-gen + gRPC (F-11)
src/topology/{mod,impair}.rs        topology + impairment (F-08, F-09)
src/report/{csv,results}.rs         CSV output + result dir (F-17, F-18)
```

---

## Work packages

Each work package lists **Goal**, **Deliverables**, and **Fulfillment** (acceptance criteria).

### Phase 0 — Foundation (SESHAT skeleton)

**WP0.1 — CLI, flags, logging, console, crate layout** _(deps: none)_
- **Goal**: `seshat` binary with all subcommands (F-01) + global flags (F-02), level-based logging (F-16), console UI primitives.
- **Deliverables**: clap-based `cli.rs` (run/sender/receiver/report/validate/list/sysinfo/setup/teardown/impair); global flags; `logging.rs`; `console.rs` (banner, boxed tables, live progress); `Cargo.toml` deps.
- **Fulfillment**: `seshat --help` lists every subcommand; every global flag parses; `cargo build` + `cargo clippy` clean; unknown subcommand errors cleanly.

**WP0.2 — Config model + JSON schema + validate/list/dry-run** _(deps: WP0.1)_
- **Goal**: JSON config is the experiment spec (F-03); defaults (F-04); `validate`, `list`, `run --dry-run`.
- **Deliverables**: serde types for suite/defaults/scenarios; validation; `validate` (per-scenario report), `list` (table), `--dry-run` (plan + time estimate).
- **Fulfillment**: valid config validates with per-scenario report; invalid config → precise error + nonzero exit; `list` shows enabled/total; `--dry-run` prints matrix + est. time, executes nothing.

**WP0.3 — System info capture + `sysinfo`** _(deps: WP0.1)_
- **Goal**: auto-capture hardware/kernel snapshot (F-19).
- **Deliverables**: `sysinfo.rs` reading hostname, kernel, CPU model/cores/freq, RAM, NIC, kTLS/io_uring availability, governor, HT, isolcpus, THP; `sysinfo` subcommand (table/csv).
- **Fulfillment**: `seshat sysinfo` prints accurate values on the dev host; snapshot persisted into the result dir (WP1.6).

### Phase 1 — Core measurement engine (loopback, no gateway)

**WP1.1 — Wire payload format** _(deps: WP0.1)_
- **Goal**: self-describing 24 B `SpikeHeader` + deterministic fill (F-12).
- **Deliverables**: `proto/wire.rs` `repr(C, packed)` {magic `b"SPKE"`, seq u64, ts_ns u64, payload_len u32}; encode/decode; fill `(seq % 256)`; corruption/boundary checks.
- **Fulfillment**: round-trip encode/decode unit tests; tamper/short-frame/bad-magic detected; fill verified.

**WP1.2 — App metrics + statistics** _(deps: WP0.1)_
- **Goal**: throughput/latency/jitter/loss/dup/reorder (F-13a) + aggregation mean/median/stddev/min/max/p50/95/99/99.9/95%CI/CoV/IQR-outlier (F-14).
- **Deliverables**: `metrics/app.rs`, `metrics/stats.rs` (native percentile/CI/CoV/IQR); per-message latency from `SpikeHeader` ts; seq-gap loss, dup, reorder counters.
- **Fulfillment**: unit tests on known sample sets; throughput in Gbit/s (decimal); CI/IQR counts logged.

**WP1.3 — Workload generators** _(deps: WP1.1)_
- **Goal**: sustained/periodic/burst/ramp patterns (F-07).
- **Deliverables**: `workload/sender.rs` (rate limit, interval, burst, ramp) + `receiver.rs`.
- **Fulfillment**: each pattern produces expected inter-send timing within tolerance; ramp increases offered load; receiver reconstructs metrics.

**WP1.4 — Run execution model** _(deps: WP1.2, WP1.3)_
- **Goal**: connect → warmup(discard) → measure(record) → cooldown, N runs, aggregate (F-15, F-04).
- **Deliverables**: `run/mod.rs` lifecycle; warmup discarded; N-run loop; per-run + aggregated stats; live console; CPU-affinity pinning.
- **Fulfillment**: warmup excluded; N runs aggregated with CI; outliers removed per config; affinity verified via `/proc`.

**WP1.5 — TCP + UDP transports (loopback baseline)** _(deps: WP1.1, WP1.4)_
- **Goal**: direct TCP/UDP loopback transport (no gateway) = baseline path (F-05 tcp/udp).
- **Deliverables**: `transport/{tcp,udp}.rs` implementing a `Transport` trait; multi-connection support.
- **Fulfillment**: tcp + udp scenarios run end-to-end on loopback; integrity PASS; loss=0 on tcp; metrics produced; WP1.7 headroom check applies.

**WP1.6 — CSV reporting + result directory + suite summary** _(deps: WP1.2, WP1.4)_
- **Goal**: CSV output (F-17, CSV-only), self-contained result dir (F-18), final summary (F-20).
- **Deliverables**: `report/csv.rs` + `report/results.rs` (`results/<ts>/{meta,sysinfo,scenarios/<name>/{config,summary,runs,system_metrics}}`); suite-complete console summary.
- **Fulfillment**: a 2-scenario loopback suite writes a complete result dir; CSV opens in a spreadsheet; summary lists best/worst.

**WP1.7 — Harness performance & headroom calibration** _(deps: WP1.5; enforces NFR-PERF)_
- **Goal**: guarantee the harness out-runs the SCG so measurements reflect the SCG, not the harness.
- **Deliverables**: high-perf sender/receiver (batched/vectored I/O, pre-allocated buffers, multi-thread, recv-side immediate timestamp, stats off hot-path, core pinning); a `calibrate`/null-loopback path; per-scenario "harness headroom" check in CSV; `HARNESS-LIMITED` warning.
- **Fulfillment**: null-loopback ceiling recorded; harness sustains ≥3–5× the SCG's measured throughput; harness-limited scenarios flagged; instrumentation latency overhead quantified as negligible.

### Phase 2 — Gateway integration & full protocol/transport matrix

**WP2.1 — Gateway lifecycle manager** _(deps: WP1.5)_ — ✅ **DONE**
- **Goal**: generate gateway JSON config; spawn/teardown the real `gateway`; support both topologies.
- **Deliverables**: `gateway/mod.rs` — build `GatewayConfig` JSON from scenario; spawn child, wait for readiness, graceful shutdown; chain two gateways for scg-scg.
- **Fulfillment**: gateway proxies a TCP TLS round-trip; both topologies stand up + tear down cleanly; logs captured; sockets cleaned on teardown/panic.
- **Done**: `gateway/{config,process,mod}.rs` + `pki.rs`. Readiness = socket-poll. Policy must be allow-all (gateway defaults to deny). `--log-dir` set to work dir (avoids `/results` EPERM). **Key insight**: with the encrypt→decrypt rule pair, the gateway does TLS *internally*; SESHAT speaks **plaintext TCP** to ingress (sender) and backend (receiver), so no client-side TLS is needed for the standard path. Validated: routing round-trip (both topologies) + TLS 1.3 round-trip. Binary autodetected (`SCG_GATEWAY_BIN` or `SCG/target/{release,debug}/gateway`); note the cached **release** build is stale (lacks `routing`), tests pick a working binary by probing.

**WP2.2 — gRPC management client** _(deps: WP2.1)_
- **Goal**: provision/close UDS+SHM endpoints, ListRules, Health via gRPC.
- **Deliverables**: `gateway/grpc_client.rs` wrapping `scg_client::mgmt` + `ManagementApiClient`.
- **Fulfillment**: create+close UDS and SHM endpoints succeed; health ok; list_rules returns configured rules.

**WP2.3 — UDS transport (via scg-client)** _(deps: WP2.2; honors NFR-PERF)_ [add B]
- **Goal**: benchmark the real gRPC-provisioned UDS path (F-05 unix).
- **Deliverables**: `transport/uds.rs` wrapping `ScgClient::connect(Transport::Uds,...)`; batched send/recv + pre-allocated buffers; fast-path fallback to `scg-ipc` if needed (WP1.7).
- **Fulfillment**: UDS round-trips with integrity PASS; token handshake works; multiple endpoints supported; harness not the limit.

**WP2.4 — SHM transport (via scg-client)** _(deps: WP2.2; honors NFR-PERF)_ [add B]
- **Goal**: benchmark the real gRPC-provisioned SHM ring path (F-05 shm).
- **Deliverables**: `transport/shm.rs` wrapping `ScgClient::connect(Transport::Shm,...)`; ring batch-fill; fast-path direct `scg-ipc` if needed (WP1.7).
- **Fulfillment**: SHM round-trips with integrity PASS; rings map; comparison vs UDS/TCP captured; harness not the limit.

**WP2.5 — Security & app-protocol matrix** _(deps: WP2.1)_ [adds A,D,E] — ⏳ **PARTIAL**
- **Goal**: cover all real SCG crypto/protocol variants (F-06 + intro).
- **Deliverables**: protocol → gateway config mapping for tls/ktls/dtls/routing/integrity-only/mTLS/TLS 1.2&1.3/subset146-pki/subset146-psk; app_protocol `ale` + `raw`; client-side TLS via `tls_pipe`/`ktls_pipe`. Reuse gateway test fixtures.
- **Fulfillment**: each enabled variant completes a measured round-trip; mTLS rejects missing client cert; integrity-only reports NULL; kTLS engages kernel TLS; ale + raw round-trip.
- **Done so far** (`commands.rs::gateway_plan` + `run_gateway_scenario`): routing (`type=none` / `protection-mode=routing-only`), userspace **TLS** and **kTLS** (`kernel=true`) at `tls1.2`/`tls1.3` server-auth, **mTLS** (`mutual_auth=true`), and **integrity-only** (`protection-mode=integrity-only`) over TCP, plus **DTLS over UDP** (`type=dtls`, server-auth `dtls1.2` and `mutual_auth=true`), both topologies — all measured end-to-end (kTLS falls back to userspace cleanly when the kernel `tls` module is absent). mTLS/DTLS-mutual use `pki::generate_mtls_bundle` (a self-signed EC CA signing `serverAuth`/`clientAuth` leaves via the `openssl` CLI); the decrypt side runs `verify=mutual`+`ca_path` and the encrypt side presents the client identity and verifies the server (hostname `localhost`). Integrity-only is server-auth TLS 1.2 with `profile=integrity-only` (authenticated NULL cipher). The encrypt (client) and decrypt (server) `verify` values are set **per direction** (`apply_encrypt`/`apply_decrypt`), not shared. **DTLS** speaks UDP datagrams end-to-end via `transport::gateway::GatewayUdpTransport` (one datagram per message; single logical flow — `connections>1` is skipped); the two concrete transports are unified behind a `GatewayDut` enum (`as_transport`/`pids`/`shutdown`). Pure-UDP processes have no TCP listener, so `start_path` injects a management-API block (`ensure_readiness_api`) whose UDS appears at full init and serves as the readiness signal (also silences the gateway's `management API server error`). DTLS calibrates against the loopback-**UDP** ceiling. CSV `protocol` column distinguishes all (`tls/1.3+mtls`, `tls/1.2+integrity`, `dtls/1.2`, `dtls/1.2+mtls`). Unsupported variants return `None` from `gateway_plan` and are skipped with a notice. **Pending**: ALE + RAW (UDP-over-TLS framing — needs asymmetric per-direction listen/upstream protos), TLS-PSK + Subset-146 PKI/PSK. **Note**: client-side `tls_pipe`/`ktls_pipe` are **not** needed for the standard encrypt→decrypt path (gateway terminates TLS internally) — only for a hypothetical single decrypt-only rule.

**WP2.6 — System metrics collection** _(deps: WP2.1)_ — ✅ **DONE** (procfs backend)
- **Goal**: per-SCG-PID CPU%, ctx switches, RSS, threads (1 Hz), syscalls/cache-misses per run (F-13b).
- **Deliverables**: `metrics/system.rs` reading `/proc/<pid>/{stat,status,io}`; optional `perf stat`; auto-detect PID or `--scg-pid`; timeseries CSV. **PID source ready**: `RunningPath::pids()` / `GatewayTcpTransport::pids()` expose the live gateway PID(s).
- **Fulfillment**: CPU/ctx/RSS timeseries recorded; perf degrades gracefully when unavailable; values sane vs `top`.
- **Done**: `src/metrics/system.rs` — `SystemSampler::start(pids,hz)` spawns a background thread that reads `/proc/<pid>/{stat,status,io}` at `metrics_sample_rate_hz`, `stop()` returns the timeseries. Counters: RSS (VmRSS), thread count, utime/stime ticks (+ derived `cpu_pct` via `_SC_CLK_TCK`), voluntary/involuntary context switches, block-I/O read/write bytes. `commands.rs::run_gateway_scenario` starts it on the real gateway PID(s) for the run window and `ResultDir::record_system_metrics` writes one `gateway_pid_<pid>.csv` per process under `scenarios/<name>/system_metrics/`. Honors `--no-system-metrics` and `metrics_backend=none`. Robust `stat` parse (splits after the last `)` so a `comm` with spaces/parens is safe); missing `/proc` (process exit) just truncates the series; unreadable `io` defaults to 0. Verified on a scg↔scg run: both gateway PIDs sampled at 5 Hz, `cpu_pct` 0→~45% under load. **Not done**: `perf`/`ebpf` backends (syscalls/cache-misses) — `backend=procfs` only for now.

**WP2.7 — TPROXY transparent interface mode** _(deps: WP2.1)_ [add C]
- **Goal**: benchmark the transparent TPROXY path.
- **Deliverables**: `transport/tproxy.rs` + gateway `transparent=true`; iptables/ip-rule setup helper (privileged; skip+warn if no CAP_NET_ADMIN).
- **Fulfillment**: with privileges, a redirected connection is proxied transparently and measured; without, skips with a clear message.

### Phase 3 — Advanced scenarios

**WP3.1 — Parallel/multi-connection + saturation + connection establishment** _(deps: WP2.5)_
- **Goal**: scale 1↔1 … 256↔1024; saturation ramp; short-lived connection rate.
- **Deliverables**: multi-connection orchestration; ramp-to-saturation recording saturation point + degradation curve; connection-establishment benchmark.
- **Fulfillment**: focus-area scenarios run; saturation point + curve recorded; conns/sec + handshake latency reported.

**WP3.2 — Multi-stream scheduling & prioritization** _(deps: WP2.5, WP2.6)_ — F-10
- **Goal**: prove safety traffic not blocked by bulk; DSCP preserve/manipulate; fairness; CPU per class.
- **Deliverables**: `workload/streams.rs` concurrent streams each measured; DSCP read-back; per-class CPU; fairness ratio.
- **Fulfillment**: under bulk flood, safety p99 under target + 0 loss; DSCP preserved/rewritten; fairness + CPU-per-class reported.

**WP3.3 — Protocol agility validation** _(deps: WP2.5)_
- **Goal**: payload integrity, datagram semantics, encapsulation overhead, packet loss across protocols.
- **Deliverables**: per-protocol agility checks; encapsulation-overhead computation; datagram-boundary assertion for UDP/DTLS.
- **Fulfillment**: all payloads round-trip byte-identical; boundaries preserved; overhead bytes recorded; loss measured.

**WP3.4 — Hot-reload event injection** _(deps: WP2.1, WP2.2)_ — F-11
- **Goal**: apply config change mid-run without dropping active connections; measure impact + rollback.
- **Deliverables**: `reload.rs` — swap config file + SIGHUP/file-watch and/or gRPC create/close; before/during/after windows; invalid-config → rollback check.
- **Fulfillment**: reload applies; drops measured (target 0 for gRPC add/remove); dip + spike recorded; invalid config rejected; profile-change limitation documented.

### Phase 4 — Topology & distributed

**WP4.1 — Topology setup/teardown (loopback/veth/netns)** _(deps: WP0.2)_ — F-08
- **Goal**: virtual two-host topologies without hardware; `setup`/`teardown`.
- **Deliverables**: `topology/mod.rs` (loopback/veth/netns) via `ip`/nix; tag results per topology; loopback warning.
- **Fulfillment**: `seshat setup --topology veth` creates a working pair; traffic flows; `teardown` removes it; results tagged.

**WP4.2 — Network impairment (tc netem)** _(deps: WP4.1)_ — F-09
- **Goal**: inject latency/jitter/loss/bw/reorder/dup; `impair` subcommand.
- **Deliverables**: `topology/impair.rs` applying `tc netem`; record impairment state.
- **Fulfillment**: applied impairment observable in measured latency/loss; recorded; removed on teardown.

**WP4.3 — Distributed sender/receiver mode** _(deps: WP1.4, WP2.1)_ — F-01
- **Goal**: run sender/receiver on different machines.
- **Deliverables**: `seshat sender --target` / `receiver --bind`; control/sync handshake; partial-result merge in `report`.
- **Fulfillment**: split run across two processes/hosts produces a merged result equivalent to single-host.

### Phase 5 — SCG gateway optimization toggles (SCG repo changes)

**WP5.1 — `zero_copy` config toggle** _(SCG repo)_
- **Goal**: add a runtime toggle for a zero-copy relay path.
- **Deliverables**: extend `RuleConfig` (`SCG/gateway/src/management/config.rs`) with `zero_copy: bool`; `splice()`-based relay in `routing_provider.rs`; kTLS sendfile path; validation (reject where unsupported).
- **Fulfillment**: routing with `zero_copy=true` uses `splice` (verify via strace); disabled by default; gateway tests pass; example config added.

**WP5.2 — `spin_wait` ring busy-poll toggle** _(SCG repo)_
- **Goal**: add busy-poll-before-block knob to SHM/UDP rings.
- **Deliverables**: add `spin_wait_us: u64`; ring consumer loops busy-poll before `eventfd`/futex block; validation.
- **Fulfillment**: `spin_wait_us>0` reduces wakeup latency at higher CPU; default 0 preserves behavior; tests pass.

**WP5.3 — Optimization comparison scenarios** _(deps: WP5.1, WP5.2, WP2.4)_
- **Goal**: benchmark each optimization vs unoptimized baseline.
- **Deliverables**: SESHAT scenarios sweeping `optimization_flags`; paired baseline-vs-optimized CSV deltas.
- **Fulfillment**: report shows baseline vs each optimization with throughput/latency/CPU deltas + CI; each flag independently toggled.

### Phase 6 — Forward-compat & finalization

**WP6.1 — Disabled WireGuard/IPSec scenarios** _(deps: WP0.2)_
- **Goal**: forward-compatible placeholders that skip cleanly.
- **Deliverables**: scenario defs with `enabled=false` + reason; `list`/`validate` show SKIP.
- **Fulfillment**: present in suite as disabled; never executed; clearly labeled.

**WP6.2 — Full suite + `report` + docs + e2e validation** _(deps: all)_
- **Goal**: ship a complete example suite; offline report regen; docs.
- **Deliverables**: `configs/full_suite.json`; `report` subcommand (regen CSV); update README + benchmark_features.md (seshat naming, CSV-only, real-vs-disabled features).
- **Fulfillment**: `--dry-run` validates the whole matrix; a reduced real run completes green and emits CSV; `report` regenerates CSV; README accurate.

---

## Dependency / parallelism

- Phase 0 → 1 → 2 → 3 (sequential phase gates).
- P1: WP1.1 ∥ WP1.2 → WP1.3 → WP1.4 → WP1.5 → WP1.7 (calibration gate) ∥ WP1.6.
- P2: WP2.1 → {WP2.2, WP2.5, WP2.6, WP2.7}; WP2.2 → WP2.3 ∥ WP2.4.
- P3: WP3.1, WP3.3 ← WP2.5; WP3.2 ← WP2.5, WP2.6; WP3.4 ← WP2.1, WP2.2.
- Phase 4 infra can develop ∥ P2/P3 (needs only WP0.2).
- Phase 5 (SCG repo) ∥ SESHAT P1–P4; WP5.3 needs WP5.1, WP5.2 + WP2.4.
- Phase 6 last.

## Verification

1. `cargo build` + `cargo clippy` + `cargo test` green (unit tests: wire format, stats, config validation).
2. `seshat sysinfo`, `validate`, `list`, `run --dry-run` all behave.
3. Loopback smoke: 2-scenario TCP/UDP suite writes a complete result dir + CSV.
4. Gateway e2e smoke: spawn gateway, run TLS TCP; UDS + SHM via gRPC provisioning round-trip; integrity PASS.
5. Scheduling: safety-vs-bulk flood → safety p99 under target + 0 loss + DSCP preserved.
6. Hot-reload: gRPC add/remove endpoint mid-run → 0 drops; invalid config rollback.
7. Phase 5: gateway tests green; strace shows `splice()` when `zero_copy=true`; spin_wait reduces wakeup latency.
8. Optimization report shows baseline-vs-optimized deltas with CI.
9. **NFR-PERF**: WP1.7 null-loopback calibration proves harness ceiling ≫ SCG throughput (≥3–5×); harness-limited scenarios flagged; instrumentation overhead negligible.

## Risks

- `scg-client` is sync send/recv per `(traffic_id, payload)`. Per NFR-PERF, WP1.7 calibrates whether it sustains target throughput; if it caps below SCG capacity, use `scg-ipc` rings/framing directly with batched frames.
- `perf` may be unavailable (WSL/containers) → procfs-only fallback.
- TPROXY + veth/netns + tc netem need privileges → privileged scenarios skip+warn when capabilities absent.
- "Change TLS profile on active connection" can't affect in-flight connections in the current SCG → hot-reload WP measures gRPC add/remove for zero-drop and documents the limitation.
- Throughput unit: Gbit/s (decimal).
- Phase 5 zero-copy is meaningful mainly for routing (`splice`) + kTLS (`sendfile`); userspace TLS cannot be zero-copy (reject in validation).
