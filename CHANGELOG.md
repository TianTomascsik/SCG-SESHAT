# Changelog

## Harness fast-path engineering

Before this pass, half the nightly matrix was flagged `harness_limited`
because the harness itself was syscall- and validation-bound. What changed:

| Improvement | Before | After |
| --- | --- | --- |
| **Stream batch send** — TCP/UDS (and the gateway/TPROXY paths built on them) push whole batches with one size-adaptive `writev` (up to 1024 messages / 256 KiB per call); stream `send_batch` returns only at message boundaries so a short write can never desynchronise the stream | 1 `write()` syscall per message | 1 syscall per ≤1024 messages |
| **Cursor-based frame reassembly** — `FramedReader` keeps read/write cursors over one fixed buffer and compacts with a single memmove per buffer-full; `recv_batch` carves every complete message one `read` yielded | `Vec::drain` memmove **per message** (O(n²) per read burst), 1 message per `recv_batch` | 1 memmove per buffer-full, one syscall drained into up to 1024 messages |
| **Block-wise payload integrity** — the deterministic fill/verify pattern is cyclic with period 256, so both run as 256-byte block copies/compares against a static ramp table | per-byte function call on **every** payload byte | memcpy/memcmp-class |
| **UDS client batching** (`scg-client`) — vectored `writev` of ≤512 frames (header+payload iovec pairs) and a buffered `FrameDecoder` receive | 2 `write` syscalls + 1 heap allocation per frame | 1 syscall per ≤512 frames, allocation-free receive |

Measured effect on the harness's own single-connection loopback ceiling
(the NFR-PERF reference, on the original evaluation host): **64 B: 0.14 →
~9 Gbit/s (~62×) · 1 KiB: 2.0 → ~41 Gbit/s · 4 KiB: 12 → ~49 Gbit/s ·
16 KiB: 13 → ~51 Gbit/s.** Consequently, previously harness-throttled gateway
rows roughly doubled to sextupled (e.g. routing 4 KiB single-connection
6.5 → ~42 Gbit/s), and all TLS/kTLS/mTLS/integrity/cipher rows clear the 3×
headroom gate.

Whether a batched load generator is still representative — and for which
metrics — is treated in `docs/methodology.md` (limitations §4.10).
