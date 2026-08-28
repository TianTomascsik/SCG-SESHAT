#!/usr/bin/env bash
# Shared configuration + helpers for the SCG two-host ("wire") benchmark.
#
# The benchmark measures the SCG across a real Ethernet link instead of
# loopback, to close the one requirement the single-host campaign cannot
# discharge: that a DSCP mark survives a physical interface and that a real
# queueing discipline acts on it.
#
#   [probe] -> [SCG encrypt gw, host A] ==== cable ==== [SCG decrypt gw, host B] -> [sink/echo]
#
# Only the *mid hop* (the inter-gateway address) differs between the two modes:
#   --mode loopback   mid = 127.0.0.1   both gateways on host A
#   --mode wire       mid = $WIRE_PEER_IP, decrypt gateway on host B
# so a loopback cell and its wire twin differ in exactly one variable.
#
# Why a script and not the SESHAT runner: the runner binds every address on
# loopback (src/net.rs, src/gateway/mod.rs::build_path), and the decisive
# artefact here is a far-side packet capture, which no harness code produces.
# This mirrors how the WireGuard provider is benchmarked (wg_bench.sh) and is
# catalogued in configs/matrix_spec.json under `limitations[]`.

# ── Addressing ───────────────────────────────────────────────────────────────
# Point-to-point link between the two machines. Defaults assume a dedicated
# cable on a spare NIC, so the benchmark never contends with real LAN traffic.
WIRE_LOCAL_IP="${WIRE_LOCAL_IP:-10.9.0.1}"   # host A (the instrumented side)
WIRE_PEER_IP="${WIRE_PEER_IP:-10.9.0.2}"     # host B (terminates the tunnel)
WIRE_DEV="${WIRE_DEV:-}"                      # host A's egress NIC (tc/tcpdump); no default — pass --dev or set WIRE_DEV

# ── Ports ────────────────────────────────────────────────────────────────────
# ingress = plaintext into gateway A (always loopback on host A)
# mid     = the secured inter-gateway hop (this is what crosses the cable)
# sink    = plaintext out of gateway B (always loopback on host B)
WIRE_INGRESS_BULK="${WIRE_INGRESS_BULK:-21000}"
WIRE_INGRESS_SAFETY="${WIRE_INGRESS_SAFETY:-21001}"
WIRE_INGRESS_DGRAM="${WIRE_INGRESS_DGRAM:-21002}"
# The classification control: a probe path identical to the safety one in every
# respect except its traffic class, so a p99 difference between them is
# attributable to classification alone. It needs its own echo endpoint — routing
# the control probe at the bulk rule would reach a sink and never get a reply.
WIRE_INGRESS_NPROBE="${WIRE_INGRESS_NPROBE:-21003}"
WIRE_MID_BULK="${WIRE_MID_BULK:-21100}"
WIRE_MID_SAFETY="${WIRE_MID_SAFETY:-21101}"
WIRE_MID_DGRAM="${WIRE_MID_DGRAM:-21102}"
WIRE_MID_NPROBE="${WIRE_MID_NPROBE:-21103}"
WIRE_SINK_BULK="${WIRE_SINK_BULK:-21200}"
WIRE_SINK_SAFETY="${WIRE_SINK_SAFETY:-21201}"
WIRE_SINK_DGRAM="${WIRE_SINK_DGRAM:-21202}"
WIRE_SINK_NPROBE="${WIRE_SINK_NPROBE:-21203}"

# ── Traffic shape ────────────────────────────────────────────────────────────
# The safety stream deliberately mirrors the published loopback parameters
# (256 B every 200 us, EF) so the wire number is directly comparable.
WIRE_SAFETY_MSG="${WIRE_SAFETY_MSG:-256}"
WIRE_SAFETY_INTERVAL_US="${WIRE_SAFETY_INTERVAL_US:-200}"
WIRE_SAFETY_DSCP="${WIRE_SAFETY_DSCP:-46}"   # EF
WIRE_NORMAL_DSCP="${WIRE_NORMAL_DSCP:-0}"    # BE
WIRE_BULK_MSG="${WIRE_BULK_MSG:-65536}"
WIRE_BULK_CONNS="${WIRE_BULK_CONNS:-4}"
WIRE_DGRAM_MSG="${WIRE_DGRAM_MSG:-1400}"     # under a 1500 B MTU; DTLS cannot fragment
# Datagram offered rate, just under the link ceiling. Never blast the DTLS path:
# without flow control an unthrottled sender measures the relay's drop point,
# not the crypto.
WIRE_DTLS_RATE_MBPS="${WIRE_DTLS_RATE_MBPS:-900}"
# Kernel vs user-space TLS on the encrypt side. The single-host evaluation records
# their parity as a loopback artefact that "says nothing about offload gains behind
# a real NIC"; setting this to false and re-running the same cells turns that caveat
# into a measurement. Note these NICs have no TLS *hardware* offload, so this
# compares kernel-software kTLS against user-space TLS, not hardware offload.
WIRE_PREFER_KTLS="${WIRE_PREFER_KTLS:-true}"

# ── Timing ───────────────────────────────────────────────────────────────────
WIRE_WARMUP_S="${WIRE_WARMUP_S:-2}"
WIRE_MEASURE_S="${WIRE_MEASURE_S:-20}"
WIRE_RUNS="${WIRE_RUNS:-3}"
# Sweep grid, mirroring SweepPlan (src/run/saturation.rs): start/step/max in
# Mbit/s plus the loss budget that defines the lossless knee.
WIRE_SWEEP_START_MBPS="${WIRE_SWEEP_START_MBPS:-50}"
WIRE_SWEEP_STEP_MBPS="${WIRE_SWEEP_STEP_MBPS:-100}"
WIRE_SWEEP_MAX_MBPS="${WIRE_SWEEP_MAX_MBPS:-950}"
WIRE_SWEEP_MEASURE_S="${WIRE_SWEEP_MEASURE_S:-10}"
WIRE_LOSS_THRESHOLD_PCT="${WIRE_LOSS_THRESHOLD_PCT:-1}"

# 1 GbE TCP/IPv4 goodput ceiling at a 1500 B MTU: 1460 payload / 1538 on the
# wire (frame + preamble + inter-frame gap). This is the reference a wire cell
# is reported against, NOT the loopback null-transport ceiling that
# src/run/calibrate.rs uses for single-host runs.
WIRE_LINK_MBPS="${WIRE_LINK_MBPS:-1000}"
wire_goodput_ceiling_gbps() {
  awk -v l="$WIRE_LINK_MBPS" 'BEGIN{printf "%.4f", l*1460/1538/1000}'
}

wire_info() { printf '[wire] %s\n' "$*"; }
wire_err() { printf '[wire] ERROR: %s\n' "$*" >&2; }

# ── Gateway config emission ──────────────────────────────────────────────────
# One rule per traffic class per direction. The gateway
# (SCG/gateway/src/management/config.rs) makes `verify: mutual` mandatory the
# moment a decrypt listener is non-loopback, so the wire path is mutual-TLS by
# construction — never pass allow_unverified_transport to work around it.
#
# `upstream_addr` must be a literal IP:port on the TCP encrypt path:
# classify_and_check_policy_target() parses it as a SocketAddr and fails closed
# on a hostname, and --validate does not catch that.

# wire_rule <name> <direction> <listen> <listen_proto> <upstream> <upstream_proto>
#           <provider> <class> <dscp|-> <pki_dir> <role:client|server> <peer_name>
wire_rule() {
  local name="$1" dir="$2" listen="$3" lproto="$4" up="$5" uproto="$6"
  local provider="$7" class="$8" dscp="$9" pki="${10}" role="${11}" peer="${12}"
  local dscp_line=""
  [[ "$dscp" != "-" ]] && dscp_line="\"dscp_tag\": $dscp,"
  # The version namespace follows the provider: the validator rejects a
  # 'tls1.3' version on a dtls rule outright.
  local version="tls1.3"
  [[ "$provider" == "dtls" ]] && version="dtls1.2"
  local cert key sni_line=""
  if [[ "$role" == "server" ]]; then
    cert="$pki/server.crt"; key="$pki/server.key"
  else
    cert="$pki/client.crt"; key="$pki/client.key"
    # Dialling by IP literal, so the peer's leaf must carry a matching IP SAN
    # (see pki::generate_mtls_bundle_with_sans). Naming "localhost" here would
    # verify a hostname that is not on the wire.
    sni_line="\"server_name\": \"$peer\","
  fi
  cat <<JSON
{
  "name": "$name", "direction": "$dir", "priority": 0,
  "listen_addr": "$listen", "listen_proto": "$lproto",
  "upstream_addr": "$up", "upstream_proto": "$uproto",
  "security_provider": "$provider",
  "protocol_version": "$version",
  "traffic_class": "$class",
  $dscp_line
  "verify": "mutual",
  $sni_line
  "cert_path": "$cert",
  "key_path": "$key",
  "ca_path": "$pki/ca.crt"
}
JSON
}

# wire_config <pki_dir> <rules_json...>  -> a full gateway config document
#
# `sock_buf_size` is in BYTES (the gateway prints it as KiB). 16 MiB matches
# gateway.example.json; passing 16384 here would set a 16 KiB buffer and throttle
# the relay to roughly 1 Mbit/s, which looks exactly like a slow gateway.
wire_config() {
  local pki="$1"; shift
  local rules
  rules="$(printf '%s,\n' "$@" | sed '$ s/,$//')"
  cat <<JSON
{
  "sock_buf_size": 16777216,
  "prefer_ktls": $WIRE_PREFER_KTLS,
  "log_level": "info",
  "api": { "enabled": false },
  "policy": { "default_action": "allow", "whitelist": [] },
  "rules": [
$rules
  ]
}
JSON
}

# Wait until a TCP listener accepts, or fail after ~10 s. Used instead of a log
# grep for the peer gateway, which logs on the other machine.
wire_wait_tcp() { # host port
  local host="$1" port="$2"
  for _ in $(seq 1 50); do
    if timeout 1 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
      exec 3<&- 2>/dev/null || true
      return 0
    fi
    sleep 0.2
  done
  return 1
}

# Wait for a log line to appear in a local gateway's captured output.
wire_wait_log() { # file pattern
  local file="$1" pattern="$2"
  for _ in $(seq 1 50); do
    grep -q "$pattern" "$file" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}
