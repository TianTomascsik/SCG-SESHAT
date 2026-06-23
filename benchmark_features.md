# Benchmarks - SESHAT
- Should mesure general hardware requirements (CPU usage, Context switches, syscall count, ram usage, Memory copies...)
### Performance
-  Prove that local app ↔ SCG data plane communication can sustain high throughput with minimal copy overhead.
- For that use all accessible Interfaces
	- TCP / UDP Socket
	- TPROXY
	- Unix Domain Socket
	- Shared Memory ring buffer
- Use also all feasible package sizes to cover a brought range of use cases:
	- ...
- For that use all available protocol variations that are supported by the SCG
	- TLS and mTLS
	- kTLS and mTLS
	- UDP in TLS with ale
	- UDP in TLS normal wrapped
	- DTLS
	- Wire Guard
- Investigate also the performance with multiple parallel connections
	- Including multiple of the same type and the same package size
	- Same type different package Size
	- different types
	- These should all include different numbers of parallel connections form 1 to X
	- These should also be done for Incoming connections from 1 to X
- These Benchmarks should be done in the following configurations:
	- client <-> SCG <-> SCG <-> client
	- client <->SCG <-> client (That supports all the crypto protocol (cant be the bottle neck))
- Benchmark variants to compare:
	- Shared Memory (ring buffer) vs. Unix Domain Sockets vs. TCP loopback
	- With and without zero-copy
- There is also a need to look at all performance improvements we did
	-  For that meaningful test should also be part of this benchmark harness that compare each performance improvement to an unoptimized baseline
	- That includes zero-copy, spin waits in the ring buffer, buffer sizes, data plane optimizations...
	- Therefore the gateway probably needs to be changed so everything can be configured via a Config file that is used to define the performance characteristics of the gateway.
- Add a **saturation test** to each performance scenario:
	- Ramp load until throughput plateaus or latency explodes
	- Record the **saturation point** (Gbit/s or connections) and the **degradation curve**
- Connection establishment benchmak
	- Check for everything how the SCG behaves with many short lived connections
- Measurements:
	- Throughput in Gbit/s
	- Latency (mean) in µs
	- Latency (p50/p95/p99)
	- Jitter in µs
	- CPU utilization
	- memmory copies per message
	- Context switches per second
	- Messages size sweep
	- Cipher suite compatibility
	- Handshake Latency
	- connection establishment rate
	- session resumption latency (pks)
	- ...

### Protocol Agility
- Prove payload-agnostic DTLS encapsulation of UDP without altering application data.
- Various datagram sizes
- With and without mutual authentication (mTLS/DTLS)
- show that all payloads and protocols keep the original content and structure
- TLS and mTLS 1.2&1.3
- kTLS and mTLS 1.2&1.3
- UDP in TLS with ale
- UDP in TLS normal wrapped
- DTLS
- Wire Guard
- Measurements:
	- payload Integrity
	- Datagram Semantics preserved
	- Encapsulation overhead in bytes
	- packet loss rate
	- Handshake time
	- ...

### Runtime Configuration & Hot Reload
- Prove configuration changes via gRPC apply at runtime **without dropping active connections**.
- For that use all available protocol variations that are supported by the SCG
	- TLS and mTLS 1.2&1.3
	- kTLS and mTLS 1.2&1.3
	- UDP in TLS with ale
	- UDP in TLS normal wrapped
	- DTLS 1.0&1.2 
	- Wire Guard
	- Integrity Only (Auth and HMAC)
	- Routing Only
- Add/remove a connection definition while traffic is flowing
- Change TLS profile on an active connection
- Push invalid config → verify rollback
- Measure under load (saturated data plane)
- Measurements:
	- In-flight packet loss
		- connections dropped
		- connection count before and after
	- Throughput during Reload in Gbit/s
	- Latency Spike in µs
	- Rollback success
	- Config Validation time in µs
	- Concurrent active connections (1..X)

### Traffic Scheduling & Prioritization
- Prove safety-critical traffic is **never blocked** by bulk/low-priority traffic, even under heavy load.
- Flood bulk (low-priority) traffic → measure high-priority latency/throughput
- Mixed load: safety + monitoring + bulk simultaneously
- Gradually increase bulk load until saturation → observe high-priority degradation point
- For that use all available protocol variations that are supported by the SCG
	- TLS and mTLS 1.2&1.3
	- kTLS and mTLS 1.2&1.3
	- UDP in TLS with ale
	- UDP in TLS normal wrapped
	- DTLS
	- Wire Guard
- Measurements (for "normal" and "safety" traffic):
	- Latency (mean) in µs
	- Latency (p50/p95/p99)
	- Jitter in µs
	- Throughput in Gbit/s
	- Scheduling fairness ratio
	- DSCP Tag preservation
	- DSCP Tag manipulation
	- CPU per prio class
	- ...

### Specific Focus Areas:
Scenario	Incoming	Outgoing	Why
Sidecar baseline	1	1	ARC-001.1 — simplest case, best throughput per connection
Small interlocking	4	16	4 apps, 16 field elements#
Medium interlocking	8	64	Realistic mid-size station
Large appliance	16	128	Large station / data center gateway
Saturation test	64	256	Find where throughput/latency degrades
Stress test	128	512	Beyond expected use — find the ceiling
Extreme	256	1024	Pure stress — useful for finding resource leaks	  
### Complete Metrics Checklist (Consolidated)
`@dataclass
class BenchmarkMetrics:
    # === PERFORMANCE (all PoCs) ===
    throughput_gbps: float
    latency_mean_us: float
    latency_p50_us: float
    latency_p95_us: float
    latency_p99_us: float
    latency_max_us: float
    jitter_stddev_us: float

    # === RESOURCE (all PoCs) ===
    cpu_percent: float
    cpu_per_priority_class: dict      # {"safety": 12.3, "bulk": 45.6}
    ram_usage_mb: float
    context_switches_per_sec: int     # voluntary + involuntary
    syscalls_per_sec: int
    memory_copies_per_msg: int

    # === CONNECTION (Performance + Hot Reload) ===
    handshake_latency_ms: float       # <-- MISSING IN YOUR PLAN
    connections_per_sec: float        # <-- MISSING IN YOUR PLAN
    connections_dropped: int
    concurrent_connections: int
    saturation_point_gbps: float     # <-- MISSING IN YOUR PLAN

    # === PROTOCOL AGILITY ===
    payload_integrity: bool
    datagram_semantics_preserved: bool
    encapsulation_overhead_bytes: int
    packet_loss_rate_percent: float

    # === HOT RELOAD ===
    inflight_packet_loss: int
    throughput_during_reload_gbps: float
    latency_spike_during_reload_us: float
    reconfiguration_time_ms: float   
    rollback_success: bool
    config_validation_time_ms: float

    # === SCHEDULING ===
    scheduling_fairness_ratio: float  # high_prio_tput / low_prio_tput
    dscp_preserved: bool
    dscp_manipulated_correctly: bool
    high_prio_degradation_point_gbps: float  

    # === METADATA ===
    scenario_name: str
    interface_type: str        # tcp, udp, uds, shm, tproxy
    protocol: str              # tls13, dtls13, wireguard, ipsec, ...
    protection_mode: str       # full, integrity_only, routing_only 
    message_size_bytes: int
    num_parallel_connections: int
    optimization_flags: dict   # {"zero_copy": True, "spin_wait": False, ...}
    topology: str              # "scg-scg" or "scg-direct"
    tls_version: str           # "1.2" or "1.3"  
    
    
    
# SPIKE — Complete Feature Specification

```
    ███████╗██████╗ ██╗██╗  ██╗███████╗
    ██╔════╝██╔══██╗██║██║ ██╔╝██╔════╝
    ███████╗██████╔╝██║█████╔╝ █████╗
    ╚════██║██╔═══╝ ██║██╔═██╗ ██╔══╝
    ███████║██║     ██║██║  ██╗███████╗
    ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
    Systematic Performance Investigation & Key Evaluation
    v0.1.0 | SCG Benchmark Harness
```

---

## F-01 · Subcommands

> _Why: Clean separation of concerns. A benchmark tool must support distributed execution (sender/receiver on different machines), offline report regeneration, and dry-run validation — each is a distinct workflow._

|Subcommand|Arguments|Description|
|---|---|---|
|`spike run`|`--config <path>`|Run a full benchmark suite|
|`spike sender`|`--config <path> --scenario <name> --target <addr>`|Run only the sender side (distributed mode)|
|`spike receiver`|`--config <path> --scenario <name> --bind <addr>`|Run only the receiver side (distributed mode)|
|`spike report`|`--input <dir> --format <md\|csv\|latex\|json>`|Re-generate reports from existing result files|
|`spike validate`|`--config <path>`|Validate a config file without executing|
|`spike list`|`--config <path>`|List all scenarios with their parameters|
|`spike sysinfo`|`--format <json\|table>`|Dump system hardware/kernel info|
|`spike setup`|`--topology <veth\|netns> [topology flags]`|Auto-create virtual network topology|
|`spike teardown`|`--topology <veth\|netns> [topology flags]`|Remove virtual network topology|
|`spike impair`|`--interface <name> --latency <ms> --loss <%>`|Apply `tc netem` impairment to an interface|

### Console Look — `spike list`

```
 ── Suite: SCG Full Benchmark v1 ──────────────────────────────
  Scenarios: 47 enabled / 52 total

  #  Name                              Category       Interface  Protocol    Conns  MsgSize
  ─────────────────────────────────────────────────────────────────────────────────────────
  01 perf_tcp_tls13_128B_1conn         performance    tcp        tls/1.3     1      128 B
  02 perf_tcp_tls13_1400B_16conn       performance    tcp        tls/1.3     16     1.4 KB
  03 perf_shm_tls13_64KB_1conn         performance    shm        tls/1.3     1      64 KB
  04 sched_flood_safety_vs_bulk        scheduling     udp+tcp    tls/1.3     1+32   128 B+64 KB
  05 hotreload_cipher_swap             hot-reload     tcp        tls/1.3     64     1.4 KB
  ×  disabled_wireguard_test           protocol       udp        wireguard   4      1.4 KB
  ...
 ──────────────────────────────────────────────────────────────
```

---

## F-02 · Global CLI Flags

> _Why: Every scientific benchmark needs reproducibility controls. CPU pinning eliminates scheduling noise, warmup excludes JIT/slow-start artifacts, and tagging enables comparison across runs._

|Flag|Type|Default|Description|
|---|---|---|---|
|`--config`|`path`|**required**|Path to JSON config file|
|`--output-dir`|`path`|`./results/<timestamp>`|Result output directory|
|`--runs`|`u32`|from config / `5`|Override number of repetitions per scenario|
|`--duration`|`duration`|from config / `30s`|Override measurement phase length|
|`--warmup`|`duration`|from config / `5s`|Override warmup phase length|
|`--cooldown`|`duration`|from config / `2s`|Override pause between runs|
|`--scenario`|`string`|all|Run only one scenario by name|
|`--tag`|`string`|none|Custom label written into result metadata|
|`--log-level`|`enum`|`info`|`error\|warn\|info\|debug\|trace`|
|`--cpu-affinity`|`list<u32>`|none|Pin SPIKE threads to specific CPU cores|
|`--quiet`|`bool`|`false`|Suppress live console output|
|`--no-system-metrics`|`bool`|`false`|Skip `/proc`/`perf` collection|
|`--scg-pid`|`u32`|auto-detect|PID of SCG process for system metrics|
|`--dry-run`|`bool`|`false`|Parse + validate config, print plan, don't execute|

### Console Look — `spike run --dry-run`

```
    ███████╗██████╗ ██╗██╗  ██╗███████╗
    ██╔════╝██╔══██╗██║██║ ██╔╝██╔════╝
    ███████╗██████╔╝██║█████╔╝ █████╗
    ╚════██║██╔═══╝ ██║██╔═██╗ ██╔══╝
    ███████║██║     ██║██║  ██╗███████╗
    ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝
    v0.1.0 | SCG Benchmark Harness

 ── DRY RUN ───────────────────────────────────────────────────
  Config    : ./configs/full_suite.json              ✔ valid
  Scenarios : 47 enabled / 52 total
  Runs/scn  : 5
  Duration  : 30s measure + 5s warmup + 2s cooldown = 37s/run
  Est. time : 47 × 5 × 37s = 2h 25m 35s
  Output    : ./results/2026-06-16T084600Z/
  Tag       : baseline-v1
  CPU pin   : sender=[0,1]  receiver=[2,3]
  SCG PID   : 48291 (auto-detected: "scg")
 ──────────────────────────────────────────────────────────────
  ✔ All scenarios validated. Ready to execute.
  ✖ Not executing (--dry-run).
```

---

## F-03 · Configuration via JSON

> _Why: JSON is machine-parseable, human-readable, schema-validatable, and language-agnostic. Enables automated generation of scenario matrices and keeps the benchmark reproducible — the config file IS the experiment specification._

### Schema Structure

```json
{
  "$schema": "spike-config-v1",
  "suite": {
    "name": "string       — human-readable suite title",
    "description": "string — what this suite tests",
    "author": "string",
    "version": "string     — semver for the config itself"
  },
  "defaults": { "/* F-04 */" : "see Execution Defaults" },
  "scenarios": [ { "/* F-05..F-11 */" : "see per-scenario features" } ]
}
```

|Field|Required|Reason|
|---|---|---|
|`suite.name`|✅|Appears in every report header and result `meta.json` — traceability|
|`suite.version`|✅|Track config evolution across experiment iterations|
|`defaults`|✅|Avoid repeating warmup/runs/affinity in every scenario|
|`scenarios[]`|✅|The actual experiments to run|

### Console Look — `spike validate`

```
 ── Validating: ./configs/full_suite.json ─────────────────────
  Schema    : spike-config-v1                        ✔
  Suite     : "SCG Full Benchmark v1" (v1.0.0)       ✔
  Defaults  : 5 runs, 30s duration, 5s warmup        ✔
  Scenarios : 52 defined, 47 enabled                  ✔
  ├─ perf_tcp_tls13_128B_1conn                        ✔
  ├─ perf_tcp_tls13_1400B_16conn                      ✔
  ├─ sched_flood_safety_vs_bulk                       ✔
  │   └─ streams: 2 (safety + bulk)                   ✔
  ├─ hotreload_cipher_swap                            ✔
  │   └─ reload_event: grpc @ 127.0.0.1:50051        ✔
  ├─ ✖ disabled_wireguard_test                        SKIP (disabled)
  └─ ...
 ──────────────────────────────────────────────────────────────
  ✔ Config valid. 47 scenarios ready.
```

---

## F-04 · Execution Defaults

> _Why: Scientific benchmarking requires controlled timing. Warmup excludes TLS handshakes and TCP slow-start. Multiple runs enable statistical confidence. Cooldown prevents cross-contamination. Outlier removal (IQR) prevents a single OS scheduling hiccup from skewing the mean._

```json
{
  "defaults": {
    "runs": 5,
    "duration_secs": 30,
    "warmup_secs": 5,
    "cooldown_secs": 2,
    "cpu_affinity_sender": [0, 1],
    "cpu_affinity_receiver": [2, 3],
    "scg_process_name": "scg",
    "collect_system_metrics": true,
    "outlier_removal": "iqr",
    "confidence_level": 0.95
  }
}
```

|Parameter|Type|Default|Why|
|---|---|---|---|
|`runs`|`u32`|`5`|Min 3 for std-dev, 5 for decent 95% CI, >30 diminishing returns|
|`duration_secs`|`u32`|`30`|Enough samples for stable p99; catches periodic OS noise|
|`warmup_secs`|`u32`|`5`|TLS handshakes + TCP slow-start settle within 2–3s|
|`cooldown_secs`|`u32`|`2`|OS buffers drain, prevents inter-run contamination|
|`cpu_affinity_sender`|`[u32]`|none|Pin sender threads to cores → eliminates NUMA/migration noise|
|`cpu_affinity_receiver`|`[u32]`|none|Pin receiver threads to cores|
|`scg_process_name`|`string`|`"scg"`|Auto-detect SCG PID for system metric collection|
|`collect_system_metrics`|`bool`|`true`|Capture CPU, ctx switches, memory of the SCG process|
|`outlier_removal`|`enum`|`"iqr"`|`none`, `iqr`, `percentile` — remove statistical outliers across runs|
|`confidence_level`|`f64`|`0.95`|Confidence interval width for reported means|

---

## F-05 · Transport Interfaces

> _Why: The thesis defines four application-facing interfaces (INT-001, INT-002). The benchmark must test each independently to measure IPC overhead differences. Loopback TCP/UDP work everywhere; UDS and SHM are local-only — matching sidecar/native deployment (ARC-001.1)._

```json
{
  "sender": {
    "interface": "tcp | udp | unix | shm",
    "target_addr": "127.0.0.1:10000 | /tmp/scg.sock | shm:///scg_ring"
  }
}
```

|Interface|Address Format|NIC Required|Thesis Req|What It Tests|
|---|---|---|---|---|
|`tcp`|`<ip>:<port>`|No (loopback)|`INT-002.1`|Standard TCP path, most common|
|`udp`|`<ip>:<port>`|No (loopback)|`INT-002.2`|Datagram path, safety protocol simulation|
|`unix`|`/path/to/socket`|No|`INT-001.2`|Unix Domain Socket, lower overhead than TCP|
|`shm`|`shm:///<name>`|No|`INT-001.1, PER-002`|Shared memory ring buffer, zero-copy path|

---

## F-06 · Security Protocols

> _Why: The thesis requires protocol agility across TLS/DTLS/WireGuard (EXT-001). The benchmark must test each protocol independently and also `none` as a baseline to isolate crypto overhead._

```json
{
  "protocol": {
    "type": "tls | dtls | wireguard | none",
    "version": "1.2 | 1.3",
    "mutual_auth": true,
    "cipher_suite": null,
    "protection_mode": "full | integrity-only | routing-only"
  }
}
```

| Field             | Values                               | Why                                                                            |
| ----------------- | ------------------------------------ | ------------------------------------------------------------------------------ |
| `type`            | `tls, dtls, wireguard, none`         | Each protocol has different overhead — `none` = baseline                       |
| `version`         | `1.2, 1.3`                           | TLS 1.3 has fewer round-trips, different cipher negotiation                    |
| `mutual_auth`     | `bool`                               | mTLS adds certificate exchange cost — measurable                               |
| `cipher_suite`    | `string \| null`                     | Override to test specific ciphers (e.g., AES-GCM vs ChaCha20)                  |
| `protection_mode` | `full, integrity-only, routing-only` | Test crypto overhead at each layer: full encryption vs MAC-only vs tunnel-only |

---

## F-07 · Traffic Patterns

> _Why: Railway traffic is not uniform. Safety commands are small periodic datagrams (ETCS), diagnostics are bursty, bulk updates are sustained. The benchmark must simulate each pattern to measure how the SCG handles mixed workloads (PER-004, QOS-001)._

```json
{
  "sender": {
    "pattern": "sustained | periodic | burst | ramp",
    "rate_limit_mbps": null,
    "interval_us": 1000,
    "burst_count": 100,
    "burst_pause_us": 5000,
    "ramp_start_mbps": 100,
    "ramp_step_mbps": 100,
    "ramp_step_interval_secs": 5
  }
}
```

|Pattern|Behavior|Railway Use Case|
|---|---|---|
|`sustained`|Send as fast as possible, no rate limit|Throughput ceiling (diagnostics bulk, software updates)|
|`periodic`|One message every `interval_us`|Safety-critical signalling (ETCS, RaSTA) — deterministic|
|`burst`|`burst_count` messages, pause, repeat|Telemetry, periodic diagnostic dumps|
|`ramp`|Start at `ramp_start`, increase by `ramp_step` every interval|Saturation point discovery — find where latency spikes|

---

## F-08 · Network Topology Modes

> _Why: Not every developer or CI system has a physical NIC. The sidecar deployment (ARC-001.1) and native deployment (3.5.1) are localhost-native. `veth`/`netns` simulate real two-host SCG-to-SCG without hardware. Results are tagged per topology so they are never accidentally compared._

```json
{
  "topology": {
    "mode": "loopback | veth | netns | physical | remote",
    "auto_setup": true,
    "left_namespace": "scg_left",
    "right_namespace": "scg_right",
    "left_ip": "10.0.0.1",
    "right_ip": "10.0.0.2",
    "subnet_mask": 24,
    "mtu": 1500
  }
}
```

| Mode       | NIC Required | What It Simulates                   | When to Use                 |
| ---------- | ------------ | ----------------------------------- | --------------------------- |
| `loopback` | ❌            | Sidecar, same-host                  | Default, dev machine, CI    |
| `veth`     | ❌            | Two-host link over virtual pair     | SCG-to-SCG without hardware |
| `netns`    | ❌            | Full zone separation with routing   | VLAN, NAT, firewall testing |
| `physical` | ✅            | Real NIC, same machine or crossover | Production-grade throughput |
| `remote`   | ✅ + 2 hosts  | True end-to-end wire latency        | Final validation            |

### Console Look — Topology Warning

```
 ── Environment ───────────────────────────────────────────────
  Topology  : loopback (127.0.0.1)
  NIC       : lo (virtual, MTU=65536)
  ⚠ NOTICE  : Loopback mode — throughput/latency numbers are NOT
              comparable to physical NIC measurements. Use for
              relative comparison and regression testing only.
 ──────────────────────────────────────────────────────────────
```

---

## F-09 · Network Impairment

> _Why: Loopback is perfect (zero loss, zero latency). Real railway links have latency, jitter, and occasional loss. Injecting `tc netem` makes loopback results more realistic and tests SCG behavior under degraded conditions (AVR-001, AVR-005)._

```json
{
  "network_impairment": {
    "enabled": true,
    "apply_to": "veth-right",
    "latency_ms": 2.0,
    "jitter_ms": 0.5,
    "loss_percent": 0.01,
    "bandwidth_limit_mbps": 1000,
    "reorder_percent": 0.0,
    "duplicate_percent": 0.0
  }
}
```

|Parameter|Why|
|---|---|
|`latency_ms`|Simulates physical distance / switch hops|
|`jitter_ms`|Tests SCG sensitivity to timing variance — critical for safety traffic|
|`loss_percent`|Tests retransmission, timeout handling, and DTLS replay windows|
|`bandwidth_limit_mbps`|Simulates link capacity constraints (trackside links may be 100 Mbit)|
|`reorder_percent`|Tests sequence number handling (CRP-002)|

---

## F-10 · Multi-Stream Scenarios (Scheduling)

> _Why: The most critical PoC — safety traffic must never be blocked by bulk traffic (PER-004, QOS-001). Requires sending multiple concurrent streams with different priorities and measuring each independently._

```json
{
  "streams": [
    {
      "role": "safety",
      "interface": "udp",
      "target_addr": "127.0.0.1:10010",
      "connections": 1,
      "message_size_bytes": 128,
      "pattern": "periodic",
      "interval_us": 1000,
      "priority": {
        "dscp_tag": "EF",
        "traffic_class": "safety-critical"
      }
    },
    {
      "role": "bulk",
      "interface": "tcp",
      "target_addr": "127.0.0.1:10020",
      "connections": 32,
      "message_size_bytes": 65536,
      "pattern": "sustained",
      "priority": {
        "dscp_tag": "BE",
        "traffic_class": "non-safety"
      }
    }
  ]
}
```

|Field|Values|Why|
|---|---|---|
|`role`|`safety, bulk, monitoring`|Labels the stream in reports for clear comparison|
|`dscp_tag`|`EF, AF41, BE, CS0–CS7`|Matches QOS-001.1 / QOS-001.2 — preserved or rewritten by SCG|
|`traffic_class`|`safety-critical, safety-monitoring, non-safety`|Maps to thesis Table 4.1 traffic classes|

### Console Look — Scheduling Result

```
 [12/47] sched_flood_safety_vs_bulk                          ✔ DONE (3m 12s)
  ┌────────────────────────────────────────────────────────────────────────────┐
  │ Stream          Throughput       Lat p50      Lat p99      Lat p99.9      │
  │ ──────────────  ───────────────  ───────────  ───────────  ────────────   │
  │ ● safety        1.02 Mbit/s          41 µs        87 µs       143 µs     │
  │ ○ bulk          6.81 Gbit/s         312 µs     1,204 µs     4,201 µs     │
  │                                                                          │
  │ Safety p99 under flood : 87 µs (target: < 500 µs)            ✔ PASS     │
  │ Fairness ratio         : 14.7:1 (safety:bulk latency)                    │
  │ DSCP preserved         : ✔ (EF → EF)                                    │
  │ Safety packets lost    : 0 / 30,000                                      │
  └────────────────────────────────────────────────────────────────────────────┘
```

---

## F-11 · Hot-Reload Event Injection

> _Why: The thesis requires config changes without interrupting active connections (CFG-003, AVR-002). The benchmark must trigger a reload mid-run via gRPC and measure whether connections drop, latency spikes, or throughput dips. This is the ONLY feature that touches the SCG API — isolated to a single module._

```json
{
  "reload_event": {
    "trigger_at_secs": 15,
    "grpc_addr": "127.0.0.1:50051",
    "action": "update_tls_profile | add_connection | remove_connection | rotate_cert",
    "payload_file": "configs/new_tls_profile.json",
    "expect_zero_drops": true,
    "measure_window_before_secs": 5,
    "measure_window_after_secs": 10
  }
}
```

|Field|Why|
|---|---|
|`trigger_at_secs`|Fire the reload at a known point during measurement — creates a clean before/after split|
|`action`|Different reload types have different risk profiles|
|`expect_zero_drops`|Assertion: the reload must not drop active connections|
|`measure_window_*`|Isolate metrics around the reload event for precise impact analysis|

### Console Look — Hot-Reload Result

```
 [31/47] hotreload_cipher_swap                               ✔ DONE (3m 05s)
  ┌────────────────────────────────────────────────────────────────────────────┐
  │ Phase              Throughput     Lat p99     Connections   Drops          │
  │ ─────────────────  ─────────────  ──────────  ────────────  ─────          │
  │ Before reload      7.34 Gbit/s      148 µs   64 active     0              │
  │ During reload      7.12 Gbit/s      203 µs   64 active     0              │
  │ After reload       7.29 Gbit/s      151 µs   64 active     0              │
  │                                                                           │
  │ Reload latency     : 12.4 ms (time from gRPC call to config applied)      │
  │ Connection drops   : 0 / 64                                   ✔ PASS     │
  │ Throughput dip     : -3.0% (max observed during reload)       ✔ PASS     │
  │ Latency spike      : +37.2% at p99 (transient, recovered)    ⚠ WARN     │
  └────────────────────────────────────────────────────────────────────────────┘
```

---

## F-12 · Payload Wire Format

> _Why: SCG-agnostic integrity validation. Every message carries a self-describing header so the receiver can detect loss, reordering, corruption, and measure latency — without knowing anything about the SCG implementation._

```
┌──────────┬───────────┬──────────┬──────────┬─────────────────┐
│ magic    │ seq_num   │ ts_ns    │ payload_ │ payload         │
│ (4B)     │ (8B)      │ (8B)     │ len (4B) │ (variable)      │
│ "SPKE"   │ u64 LE    │ u64 LE   │ u32 LE   │ deterministic   │
└──────────┴───────────┴──────────┴──────────┴─────────────────┘
 Header: 24 bytes fixed
```

```rust
#[repr(C, packed)]
struct SpikeHeader {
    magic: [u8; 4],       // b"SPKE" — detect corruption
    sequence: u64,        // monotonic — detect loss, duplication, reorder
    timestamp_ns: u64,    // CLOCK_MONOTONIC — compute latency
    payload_len: u32,     // validate datagram boundaries
}
// Payload fill: (seq % 256) repeated — detect bit flips
```

|Check|What It Catches|Thesis Req|
|---|---|---|
|`magic == b"SPKE"`|Corruption, frame misalignment|Data integrity|
|`sequence` gaps|Packet loss|AVR-001|
|`sequence` duplicates|Replay / duplication|CRP-002|
|`sequence` out-of-order|Reordering|CRP-002.1|
|`timestamp_ns` delta|One-way latency|PER-004|
|`payload_len` vs actual|Datagram boundary preservation|EXT-003.1|
|Fill pattern|Bit-level corruption|Data integrity|

---

## F-13 · Metrics Collection

> _Why: Throughput alone is insufficient. The thesis requires evaluation of CPU overhead, context switches, and copy behavior (PER-001, PER-003.2). Collecting SCG process metrics externally keeps the harness SCG-agnostic._

### 13a · Application-Level Metrics (measured by SPIKE directly)

|Metric|Unit|How|
|---|---|---|
|Throughput|Gbit/s|`bytes_sent / elapsed_time`|
|Latency|µs|`receiver_ts - sender_ts` (per message)|
|Jitter|µs|`stddev(latency)`|
|Packets sent/received|count|Sequence number tracking|
|Packets lost|count|Sequence gaps at receiver|
|Packets duplicated|count|Duplicate sequence numbers|
|Packets reordered|count|Out-of-order sequence numbers|
|Connections established|count|Successful connect/accept|
|Connections dropped|count|Unexpected disconnects during measurement|
|DSCP preserved|bool|Compare sent vs received IP header|

### 13b · System-Level Metrics (read from `/proc` + `perf`)

|Metric|Source|Rate|Why|
|---|---|---|---|
|CPU % (user + sys)|`/proc/<pid>/stat`|1 Hz|Detect if SCG saturates cores|
|Voluntary ctx switches|`/proc/<pid>/status`|1 Hz|High = too much blocking I/O|
|Involuntary ctx switches|`/proc/<pid>/status`|1 Hz|High = OS preempting SCG|
|RSS memory|`/proc/<pid>/status`|1 Hz|Detect memory leaks|
|Thread count|`/proc/<pid>/status`|1 Hz|Verify threading model|
|Syscalls/sec|`perf stat`|per run|Quantify kernel transitions|
|Cache misses|`perf stat`|per run|Data path locality|

```json
{
  "defaults": {
    "collect_system_metrics": true,
    "metrics_backend": "procfs | perf | ebpf | none",
    "metrics_sample_rate_hz": 1,
    "scg_process_name": "scg"
  }
}
```

---

## F-14 · Statistical Aggregation

> _Why: A single run means nothing. Science requires: multiple repetitions, central tendency, dispersion, confidence intervals, and outlier handling. Without this, results are anecdotal, not evidence._

|Statistic|Reported|Why|
|---|---|---|
|Mean|✅|Central tendency|
|Median|✅|Robust against skew|
|Std-Dev (σ)|✅|Dispersion|
|Min / Max|✅|Range|
|p50 / p95 / p99 / p99.9|✅ (latency)|Tail latency is critical for safety traffic|
|95% Confidence Interval|✅|Statistical rigor — "is this difference real?"|
|Coefficient of Variation|✅|Relative consistency across scenarios|
|Outliers removed (IQR)|✅|Count + values logged for transparency|

### Console Look — Per-Scenario Summary

```
 [03/47] perf_tcp_tls13_1400B_16conn                         ✔ DONE (3m 02s)
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │ Throughput      7.34 ± 0.12 Gbit/s    (95% CI: [7.22, 7.46])              │
  │ Latency mean         89.2 µs          Jitter (σ):    4.1 µs               │
  │ Latency p50          86.0 µs          p95:         121.0 µs               │
  │ Latency p99         148.3 µs          p99.9:       312.7 µs               │
  │ CPU (SCG)           34.2 ± 1.1 %      Ctx-sw:    12,481/s                 │
  │ Payload integrity   PASS              Packets lost: 0                      │
  │ Outliers removed    1/5 runs (IQR)                                         │
  └──────────────────────────────────────────────────────────────────────────────┘
```

---

## F-15 · Run Execution Model

> _Why: The warmup → measure → cooldown cycle is the standard methodology in systems benchmarking. Data collected during warmup is discarded. This is non-negotiable for scientific validity._

```
  ┌─────────┐    ┌──────────┐    ┌────────────┐    ┌──────────┐
  │ Connect │───▶│ Warmup   │───▶│ Measure    │───▶│ Cooldown │
  │ + Setup │    │ (discard)│    │ (record)   │    │+Teardown │
  └─────────┘    └──────────┘    └────────────┘    └──────────┘
                  5s default      30s default       2s default

  × N runs per scenario
  Then: aggregate across runs → statistics → write results
```

### Console Look — Live Progress

```
 [03/47] perf_tcp_tls13_1400B_16conn
         cat=performance  topo=loopback  if=tcp  proto=tls/1.3  msg=1400B  conns=16
  ├─ Run 1/5 ··· [WARMUP 5s] ████████████████████ [MEASURE 30s] ████████░░░░  18s
  │            live: 7.21 Gbit/s  p99=142µs  cpu=34.2%
```

---

## F-16 · Logging Levels

> _Why: `stderr` for humans (colored, structured), result files for machines (JSON). Never mixed. Debug and trace levels enable root-cause analysis when results look wrong without polluting normal output._

|Level|Content|Audience|
|---|---|---|
|`error`|Fatal: can't bind socket, config parse failure, assertion violation|CI / alerting|
|`warn`|Anomalies: outlier runs detected, unexpected packet loss, connection resets|Investigator|
|`info`|Progress, per-scenario summaries, suite summary|Normal use|
|`debug`|Per-run stats, config resolution, connection lifecycle, topology setup|Debugging|
|`trace`|Per-packet send/recv timestamps, individual syscall timings|Deep analysis|

```
2026-06-16T08:35:12.483Z INFO  [spike::orchestrator] Starting scenario 3/47: perf_tcp_tls13_1400B_16conn
2026-06-16T08:35:12.484Z DEBUG [spike::sender] Opening 16 TCP connections to 127.0.0.1:10000
2026-06-16T08:35:12.491Z DEBUG [spike::sender] All 16 connections established in 7.2ms
2026-06-16T08:35:12.491Z INFO  [spike::orchestrator] Warmup phase: 5s (data discarded)
2026-06-16T08:35:17.491Z INFO  [spike::orchestrator] Measurement phase: 30s
2026-06-16T08:35:47.492Z INFO  [spike::run] Run 1/5 complete: 7.21 Gbit/s, p99=142µs
```

---

## F-17 · Output Formats

> _Why: Different consumers need different formats. Markdown for thesis drafts, LaTeX for final thesis tables, CSV for matplotlib/gnuplot, JSON for programmatic analysis and archiving._

|Format|Command|Use Case|
|---|---|---|
|**JSON** (structured)|automatic|Archival, programmatic re-analysis|
|**JSONL** (per-sample)|automatic|Raw per-message measurements, streaming writes|
|**Markdown**|`spike report --format md`|Quick human-readable report|
|**LaTeX**|`spike report --format latex`|Direct `\input{}` into thesis|
|**CSV**|`spike report --format csv`|matplotlib, gnuplot, R, Excel|
|**Console**|always (live)|Real-time progress and summaries|

### Console Look — `spike report --format latex` output

```latex
\begin{table}[h]
\centering
\caption{Throughput by interface (TLS 1.3, 1400B, 16 connections, loopback)}
\label{tab:throughput_interface}
\begin{tabular}{lrrrrr}
\toprule
Interface & Mean (Gbit/s) & $\sigma$ & CI$_{95\%}$ & p99 ($\mu$s) & CPU (\%) \\
\midrule
TCP       & 7.34 & 0.12 & [7.22, 7.46] & 148.3 & 34.2 \\
UDS       & 8.12 & 0.09 & [8.03, 8.21] &  98.1 & 28.7 \\
SHM       & 9.41 & 0.05 & [9.36, 9.46] &  31.2 & 18.4 \\
\bottomrule
\end{tabular}
\end{table}
```

---

## F-18 · Result Directory Structure

> _Why: Every run must be self-contained and reproducible. The config that produced the results, the system info, the raw samples, and the aggregated statistics all live together. Any result directory can be re-analyzed months later without the original environment._

```
results/
└── 2026-06-16T083500Z/
    ├── meta.json                            # F-19: suite metadata + system info
    ├── sysinfo.json                         # F-20: full hardware snapshot
    ├── report.md                            # generated report
    ├── report.csv                           # flat summary
    ├── scenarios/
    │   ├── perf_tcp_tls13_1400B_16conn/
    │   │   ├── config.json                  # exact config for this scenario
    │   │   ├── summary.json                 # F-14: aggregated statistics
    │   │   ├── latency_histogram.json       # HdrHistogram serialized
    │   │   ├── runs/
    │   │   │   ├── run_001.jsonl             # per-sample data
    │   │   │   ├── run_002.jsonl
    │   │   │   └── ...
    │   │   └── system_metrics/
    │   │       ├── cpu.csv                   # 1 Hz CPU timeseries
    │   │       ├── context_switches.csv
    │   │       └── memory.csv
    │   └── sched_flood_safety_vs_bulk/
    │       └── ...
    └── topology.json                        # recorded topology + impairment state
```

---

## F-19 · System Info Capture

> _Why: Results without hardware context are meaningless. "7.34 Gbit/s" means nothing unless you know the CPU, RAM speed, NIC, kernel version, and whether kTLS/io_uring were available. This is recorded automatically at the start of every suite._

```json
{
  "hostname": "rail-bench-01",
  "kernel": "6.8.0-45-generic",
  "cpu_model": "AMD EPYC 7763",
  "cpu_cores": 64,
  "cpu_freq_mhz": 2450,
  "ram_total_gb": 128,
  "ram_speed": "DDR4-3200",
  "nic": "lo (virtual)",
  "nic_speed": "N/A",
  "ktls_available": true,
  "io_uring_available": true,
  "cpu_governor": "performance",
  "hyperthreading": false,
  "isolcpus": "8-15",
  "kernel_tls_module": "loaded",
  "transparent_hugepages": "madvise"
}
```

### Console Look — System Info Header

```
 ── System ────────────────────────────────────────────────────
  Host      : rail-bench-01 (Linux 6.8.0-45-generic x86_64)
  CPU       : AMD EPYC 7763 @ 2.45GHz (64 cores, governor=performance)
  RAM       : 128 GB DDR4-3200
  NIC       : lo (virtual, MTU=65536)
  Kernel    : kTLS=yes  io_uring=yes  THP=madvise
  SCG PID   : 48291 (scg v2.1.0, 4 threads, RSS=42MB)
 ──────────────────────────────────────────────────────────────
```

---

## F-20 · Suite Summary

> _Why: After 2+ hours of benchmarking, the operator needs a fast overview: how many passed, what were the extremes, and where are the full results. This is the final console output._

```
 ── Suite Complete ─────────────────────────────────────────────
  Total time : 2h 11m 34s
  Scenarios  : 47 passed / 0 failed / 0 skipped
  Results    : ./results/2026-06-16T083500Z/
 ──────────────────────────────────────────────────────────────

  ── Performance Highlights ──
  Best throughput  : 9.41 Gbit/s  (perf_shm_tls13_64KB_1conn)
  Worst throughput : 0.82 Gbit/s  (perf_tcp_tls12_64B_256conn)
  Best latency p99 :      31 µs  (perf_shm_none_128B_1conn)
  Worst latency p99:   4,201 µs  (perf_tcp_tls12_64B_256conn)

  ── Scheduling Highlights ──
  Safety p99 under flood : 87 µs   (target: < 500 µs)    ✔
  Fairness ratio         : 14.7:1  (safety:bulk latency)

  ── Hot-Reload Highlights ──
  Connection drops       : 0 / 64                         ✔
  Max throughput dip     : -3.0%                           ✔
  Reload apply latency   : 12.4 ms

  Full report : ./results/2026-06-16T083500Z/report.md
  CSV export  : ./results/2026-06-16T083500Z/report.csv
  LaTeX tables: spike report --input ./results/2026-06-16T083500Z/ --format latex
```

---
