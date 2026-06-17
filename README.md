# SESHAT

SESHAT is the next-generation benchmark harness for the **SCG** project. It is
a fresh, improved replacement for the legacy benchmark orchestration that
currently lives in the `SCG-Interface-benchmarks` repository (scripts, container
compose files, and visualization tooling).

## Status

Scaffold only. Implementation is pending and tracked separately.

## Scope (planned)

- Orchestrate the Secure Communication Gateway (SCG) and the interface
  benchmarks under reproducible conditions.
- Collect throughput/latency results across transports (TCP, UDP, UDS, SHM) and
  crypto modes (plain, TLS, kTLS, DTLS).
- Aggregate and report results (tables + figures).

## Relationship to other repos

- Benchmarks it drives: [`SCG-Interface-benchmarks`](../SCG-Interface-benchmarks)
- System under test: [`SCG`](../SCG)

## License

Apache-2.0
