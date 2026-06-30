#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DEPRECATED — run_all.sh has been folded into the `seshat` binary.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# A full evaluation now runs straight from the binary's `suite` subcommand,
# which iterates the tier's config files, consolidates results into one tree,
# and renders the performance overview (terminal + PERFORMANCE_OVERVIEW.txt).
#
#   cargo build --release            # build seshat (and ../SCG gateway)
#   ./target/release/seshat suite                 # canonical tier (was: ./run_all.sh)
#   ./target/release/seshat suite --tier nightly  # exhaustive (was: --nightly)
#   ./target/release/seshat suite --quick         # fast smoke (was: --quick)
#   ./target/release/seshat suite --scenario-filter tcp   # (was: --scenario-filter tcp)
#
# Verbosity:  --verbose (full detail) · --describe (per-test descriptions) ·
#             --quiet (warnings + final report only).
# Safety-isolation checks (was: --safety-tests) now run as plain `cargo test`.
set -euo pipefail

echo "run_all.sh is deprecated — use the seshat binary's 'suite' subcommand:" >&2
echo "    cargo build --release && ./target/release/seshat suite" >&2
echo "    (see README.md → 'Benchmark matrix and measurements')" >&2
exit 2
