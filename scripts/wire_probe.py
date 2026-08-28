#!/usr/bin/env python3
"""Load/latency probe for the SCG two-host ("wire") benchmark.

SESHAT's own runner binds every address on loopback (`src/net.rs`), so it cannot
drive a path whose inter-gateway hop crosses a physical link. This standalone
probe does, for the small wire campaign only. It is deliberately
dependency-free (stdlib only), like `wg_probe.py`, so it runs on the peer laptop
without installing anything.

Roles
-----
  sink   receive-only endpoint: counts messages/bytes, derives loss from
         sequence gaps, and (UDP only) observes the DS field via IP_RECVTOS.
  echo   echoes every message back, so the sender can time a closed-loop RTT.
  point  one measurement point: an optional bulk load at a target offered rate
         plus an optional concurrent closed-loop RTT probe, both for the same
         window. This is the unit the sweep grid and the QoS cells are built from.

Clock discipline
----------------
The two hosts have unsynchronised `CLOCK_MONOTONIC` bases, so a one-way latency
(`recv_ts - send_ts`) computed across them is meaningless. Every latency number
this probe emits is therefore a **closed-loop RTT measured entirely on the
sender's clock**: t0 before send, t1 after the echo returns. Nothing here
subtracts a remote timestamp from a local one.

Throughput is likewise sender-side. For TCP that is within a socket buffer of
delivered goodput because the stream backpressures; for **paced UDP it is only
the offered rate**, so the delivered figure must come from the `sink` role on
the far side.
"""

import argparse
import json
import socket
import struct
import sys
import threading
import time

# Linux IP_RECVTOS; Python only exposes it as a constant on newer releases.
IP_RECVTOS = getattr(socket, "IP_RECVTOS", 13)

# Every message starts with a big-endian sequence number so the sink can derive
# loss from gaps and the RTT probe can match a reply to its request.
SEQ = struct.Struct(">Q")
MIN_MSG = SEQ.size


def parse_hostport(value):
    """Parse `HOST:PORT` into a `(host, port)` tuple."""
    host, _, port = value.rpartition(":")
    if not host or not port:
        raise argparse.ArgumentTypeError(f"expected HOST:PORT, got {value!r}")
    return host.strip("[]"), int(port)


def percentile(sorted_values, fraction):
    """Percentile of an already-sorted list (nearest-rank, clamped)."""
    if not sorted_values:
        return 0.0
    idx = min(len(sorted_values) - 1, int(len(sorted_values) * fraction))
    return sorted_values[idx]


def summarise_rtts(rtts_us):
    """Reduce RTT samples to the fields the CSV needs (all in microseconds)."""
    if not rtts_us:
        return {"rtt_n": 0}
    ordered = sorted(rtts_us)
    n = len(ordered)
    mean = sum(ordered) / n
    # 95% confidence half-width on the mean, normal approximation. With n in the
    # thousands this is the same estimator SESHAT reports for its own runs.
    if n > 1:
        var = sum((v - mean) ** 2 for v in ordered) / (n - 1)
        ci95 = 1.96 * (var**0.5) / (n**0.5)
    else:
        ci95 = 0.0
    return {
        "rtt_n": n,
        "rtt_us_mean": round(mean, 3),
        "rtt_us_ci95": round(ci95, 3),
        "rtt_us_p50": round(percentile(ordered, 0.50), 3),
        "rtt_us_p99": round(percentile(ordered, 0.99), 3),
    }


def apply_dscp(sock, dscp):
    """Stamp `IP_TOS` so this socket's packets carry `dscp` (0..63)."""
    if dscp is None:
        return
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, dscp << 2)


def make_payload(size):
    """A message body of `size` bytes; the first 8 are overwritten per send."""
    return bytearray(b"\0" * size)


def stamp_seq(buf, seq):
    """Write the sequence number into the message header, in place."""
    SEQ.pack_into(buf, 0, seq)
    return buf


# --------------------------------------------------------------------------
# sink
# --------------------------------------------------------------------------


class SinkTally:
    """Thread-safe receive tally shared across a TCP sink's connections."""

    def __init__(self, expect_dscp):
        self.lock = threading.Lock()
        self.count = 0
        self.bytes = 0
        # Each bulk connection numbers its own messages and carries its index in
        # the high bits, so the high-water mark is tracked per connection. A
        # single global maximum would read connection 3's sequence space as
        # billions of lost messages from connection 0.
        self.max_seq = {}
        self.expect_dscp = expect_dscp
        self.dscp_observed = 0
        self.dscp_matched = 0
        # Delivered rate is computed over the sink's *own* observation window.
        # An elapsed interval is the difference of two local clock reads, so it
        # stays valid across hosts whose CLOCK_MONOTONIC bases differ — unlike a
        # one-way latency, which subtracts a remote instant from a local one.
        self.first_ts = None
        self.last_ts = None

    def reset(self):
        """Zero the counters for the next burst, keeping the expected DSCP."""
        with self.lock:
            self.count = 0
            self.bytes = 0
            self.max_seq = {}
            self.dscp_observed = 0
            self.dscp_matched = 0
            self.first_ts = None
            self.last_ts = None

    def record(self, nbytes, seq, tos):
        conn = seq >> 48
        local = seq & ((1 << 48) - 1)
        now = time.perf_counter()
        with self.lock:
            self.count += 1
            self.bytes += nbytes
            if self.first_ts is None:
                self.first_ts = now
            self.last_ts = now
            if local > self.max_seq.get(conn, -1):
                self.max_seq[conn] = local
            if tos is not None and self.expect_dscp is not None:
                self.dscp_observed += 1
                if (tos >> 2) == self.expect_dscp:
                    self.dscp_matched += 1

    def report(self):
        with self.lock:
            # Loss from sequence gaps: per connection, the highest sequence seen
            # implies how many were sent, so anything missing below it was
            # dropped in transit.
            expected = sum(high + 1 for high in self.max_seq.values())
            lost = max(0, expected - self.count)
            loss_pct = (100.0 * lost / expected) if expected > 0 else 0.0
            observed_s = 0.0
            if self.first_ts is not None and self.last_ts is not None:
                observed_s = self.last_ts - self.first_ts
            out = {
                "count": self.count,
                "bytes": self.bytes,
                "lost": lost,
                "loss_pct": round(loss_pct, 4),
                "observed_s": round(observed_s, 4),
                "delivered_gbps": (
                    round(self.bytes * 8 / observed_s / 1e9, 6) if observed_s > 0 else 0.0
                ),
            }
            if self.expect_dscp is not None:
                out["dscp_observed"] = self.dscp_observed
                out["dscp_matched"] = self.dscp_matched
                # Honest verdict: unobserved stays unset rather than defaulting
                # to a pass or a fail (the TCP path can never observe the field).
                if self.dscp_observed > 0:
                    out["dscp_preserved"] = self.dscp_matched == self.dscp_observed
            return out


class BurstReporter:
    """Emit one record per traffic burst, so a long-lived peer-side sink can be
    attributed to individual cells without a control channel.

    Host A cannot tell the peer when a cell starts and stops (there is
    deliberately no remote-execution path), and its sinks therefore run for the
    whole session. But cells are separated by gaps in which no traffic flows, so
    an idle gap is an unambiguous cell boundary. Each burst is written as one
    JSON line, in cell order, and merged against host A's CSV afterwards by
    copying `peer-out/` back.
    """

    def __init__(self, path, idle_gap_s=1.5):
        self.path = path
        self.idle_gap_s = idle_gap_s
        self.records = 0

    def flush(self, tally):
        report = tally.report()
        if not report.get("count"):
            return
        report["burst"] = self.records
        self.records += 1
        if self.path:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(report, sort_keys=True) + "\n")
        print("BURST " + json.dumps(report, sort_keys=True), flush=True)
        tally.reset()

    def maybe_flush(self, tally, now):
        last = tally.last_ts
        if last is not None and (now - last) >= self.idle_gap_s:
            self.flush(tally)


def sink_udp(bind, msg_bytes, duration, tally, burst=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    sock.bind(bind)
    observe = tally.expect_dscp is not None
    if observe:
        try:
            sock.setsockopt(socket.IPPROTO_IP, IP_RECVTOS, 1)
        except OSError as exc:
            print(f"[wire-probe] IP_RECVTOS unavailable: {exc}", file=sys.stderr)
            observe = False
    sock.settimeout(0.5)
    print("ready", flush=True)
    deadline = time.monotonic() + duration if duration > 0 else None
    while deadline is None or time.monotonic() < deadline:
        try:
            if observe:
                data, ancdata, _flags, _addr = sock.recvmsg(65535, 256)
                tos = None
                for level, ctype, cdata in ancdata:
                    if level == socket.IPPROTO_IP and ctype == socket.IP_TOS and cdata:
                        tos = cdata[0]
                        break
            else:
                data = sock.recv(65535)
                tos = None
        except socket.timeout:
            if burst:
                burst.maybe_flush(tally, time.perf_counter())
            continue
        except OSError:
            continue
        if len(data) >= MIN_MSG:
            tally.record(len(data), SEQ.unpack_from(data, 0)[0], tos)
    if burst:
        burst.flush(tally)


def _sink_tcp_conn(conn, msg_bytes, tally):
    """Drain one TCP connection, reframing the stream into fixed-size messages."""
    conn.settimeout(1.0)
    buf = b""
    while True:
        try:
            chunk = conn.recv(1 << 16)
        except socket.timeout:
            continue
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= msg_bytes:
            msg, buf = buf[:msg_bytes], buf[msg_bytes:]
            tally.record(len(msg), SEQ.unpack_from(msg, 0)[0], None)
    conn.close()


def sink_tcp(bind, msg_bytes, duration, tally, conns, burst=None):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(bind)
    srv.listen(max(8, conns))
    srv.settimeout(0.5)
    print("ready", flush=True)
    deadline = time.monotonic() + duration if duration > 0 else None
    workers = []
    while deadline is None or time.monotonic() < deadline:
        try:
            conn, _peer = srv.accept()
        except socket.timeout:
            if burst:
                burst.maybe_flush(tally, time.perf_counter())
            continue
        except OSError:
            break
        worker = threading.Thread(
            target=_sink_tcp_conn, args=(conn, msg_bytes, tally), daemon=True
        )
        worker.start()
        workers.append(worker)
    srv.close()
    for worker in workers:
        worker.join(timeout=2.0)
    if burst:
        burst.flush(tally)


# --------------------------------------------------------------------------
# echo
# --------------------------------------------------------------------------


def echo_udp(bind, duration):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(bind)
    sock.settimeout(0.5)
    print("ready", flush=True)
    deadline = time.monotonic() + duration if duration > 0 else None
    while deadline is None or time.monotonic() < deadline:
        try:
            data, peer = sock.recvfrom(65535)
            sock.sendto(data, peer)
        except socket.timeout:
            continue
        except OSError:
            continue


def _echo_tcp_conn(conn, msg_bytes):
    """Reflect the byte stream back verbatim, as it arrives.

    Deliberately frame-agnostic. An earlier version reassembled `msg_bytes`
    blocks before echoing, which silently corrupted every RTT whose message size
    was not the echo's own: the client's requests were held until a full block
    accumulated, then returned together, so all but the last round trip appeared
    to complete in microseconds. TCP is a byte stream — echoing chunks
    unmodified preserves the client's framing whatever size it chose.
    """
    del msg_bytes  # intentionally unused; see above
    conn.settimeout(1.0)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    while True:
        try:
            chunk = conn.recv(1 << 16)
        except socket.timeout:
            continue
        except OSError:
            break
        if not chunk:
            break
        try:
            conn.sendall(chunk)
        except OSError:
            break
    conn.close()


def echo_tcp(bind, msg_bytes, duration):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(bind)
    srv.listen(8)
    srv.settimeout(0.5)
    print("ready", flush=True)
    deadline = time.monotonic() + duration if duration > 0 else None
    workers = []
    while deadline is None or time.monotonic() < deadline:
        try:
            conn, _peer = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        worker = threading.Thread(target=_echo_tcp_conn, args=(conn, msg_bytes), daemon=True)
        worker.start()
        workers.append(worker)
    srv.close()
    for worker in workers:
        worker.join(timeout=2.0)


# --------------------------------------------------------------------------
# point: bulk load + concurrent closed-loop RTT
# --------------------------------------------------------------------------


class BulkResult:
    def __init__(self):
        self.msgs = 0
        self.bytes = 0
        self.lag_sum_us = 0.0
        self.lag_max_us = 0.0
        self.lag_n = 0


def bulk_sender(args, stop, measuring, result, index):
    """One bulk connection: paced to `--bulk-rate-mbps`, or unthrottled at 0.

    Pacing uses a fixed 1 ms tick with catch-up, and accounts how late each tick
    woke. A large send lag means the pacer itself fell behind, which invalidates
    the point — the caller must discard it rather than report the offered rate as
    if it had been delivered.
    """
    proto = args.proto
    host, port = args.bulk_target
    if proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024 * 1024)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    apply_dscp(sock, args.bulk_dscp)
    sock.connect((host, port))

    payload = make_payload(args.bulk_msg)
    seq = index << 48  # disjoint sequence space per connection
    send = sock.send if proto == "udp" else sock.sendall

    per_conn_mbps = args.bulk_rate_mbps / max(1, args.bulk_conns)
    if per_conn_mbps <= 0:
        while not stop.is_set():
            try:
                send(stamp_seq(payload, seq))
            except OSError:
                break
            if measuring.is_set():
                result.msgs += 1
                result.bytes += args.bulk_msg
            seq += 1
    else:
        pps = per_conn_mbps * 1e6 / 8.0 / args.bulk_msg
        per_tick = max(1, int(pps / 1000.0))
        tick = 0.001 * per_tick / max(pps / 1000.0, 1e-9) if pps > 0 else 0.001
        next_tick = time.perf_counter()
        while not stop.is_set():
            woke = time.perf_counter()
            if measuring.is_set():
                lag_us = max(0.0, (woke - next_tick) * 1e6)
                result.lag_sum_us += lag_us
                result.lag_n += 1
                result.lag_max_us = max(result.lag_max_us, lag_us)
            for _ in range(per_tick):
                try:
                    send(stamp_seq(payload, seq))
                except OSError:
                    stop.set()
                    break
                if measuring.is_set():
                    result.msgs += 1
                    result.bytes += args.bulk_msg
                seq += 1
            next_tick += tick
            sleep_for = next_tick - time.perf_counter()
            if sleep_for > 0:
                time.sleep(sleep_for)
    try:
        sock.close()
    except OSError:
        pass


def _connect_rtt(args):
    """Open (or reopen) the RTT probe's connection to the echo endpoint."""
    host, port = args.rtt_target
    if args.proto == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    apply_dscp(sock, args.rtt_dscp)
    sock.connect((host, port))
    sock.settimeout(1.0)
    return sock


def rtt_prober(args, stop, measuring, samples, stats):
    """Closed-loop RTT against the echo endpoint, timed entirely on this host.

    Runs concurrently with the bulk load so the recorded p99 is latency *under*
    that offered load — the curve loopback cannot produce, because loopback has
    no queue to build.
    """
    sock = _connect_rtt(args)
    payload = make_payload(args.rtt_msg)
    interval = args.rtt_interval_us / 1e6 if args.rtt_interval_us > 0 else 0.0
    seq = 0
    next_send = time.perf_counter()
    while not stop.is_set():
        if interval > 0:
            sleep_for = next_send - time.perf_counter()
            if sleep_for > 0:
                time.sleep(sleep_for)
            next_send += interval
        t0 = time.perf_counter()
        try:
            if args.proto == "udp":
                sock.send(stamp_seq(payload, seq))
                reply = sock.recv(65535)
            else:
                sock.sendall(stamp_seq(payload, seq))
                remaining = args.rtt_msg
                parts = []
                while remaining > 0:
                    chunk = sock.recv(remaining)
                    if not chunk:
                        raise OSError("echo closed")
                    parts.append(chunk)
                    remaining -= len(chunk)
                reply = b"".join(parts)
            elapsed_us = (time.perf_counter() - t0) * 1e6
        except (OSError, socket.timeout):
            # A dropped or late reply leaves an unread response in the stream.
            # Continuing would pair every later request with the PREVIOUS
            # reply, so each "round trip" would then be read straight out of
            # the socket buffer and report a physically impossible RTT. Rebuild
            # the connection instead, and lose the samples rather than the truth.
            stats["resyncs"] += 1
            try:
                sock.close()
            except OSError:
                pass
            sock = _connect_rtt(args)
            seq = 0
            continue
        # Same guard against silent desynchronisation: the reply must be the
        # answer to *this* request, not an older one still in flight.
        if len(reply) >= MIN_MSG and SEQ.unpack_from(reply, 0)[0] != seq:
            stats["resyncs"] += 1
            try:
                sock.close()
            except OSError:
                pass
            sock = _connect_rtt(args)
            seq = 0
            continue
        if measuring.is_set():
            samples.append(elapsed_us)
        seq += 1
    try:
        sock.close()
    except OSError:
        pass


def run_point(args):
    stop = threading.Event()
    measuring = threading.Event()
    threads = []
    bulk_results = []
    rtt_samples = []
    rtt_stats = {"resyncs": 0}

    if args.bulk_target and args.bulk_conns > 0:
        for i in range(args.bulk_conns):
            res = BulkResult()
            bulk_results.append(res)
            thread = threading.Thread(
                target=bulk_sender, args=(args, stop, measuring, res, i), daemon=True
            )
            thread.start()
            threads.append(thread)

    if args.rtt_target:
        thread = threading.Thread(
            target=rtt_prober,
            args=(args, stop, measuring, rtt_samples, rtt_stats),
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    if not threads:
        sys.exit("point: nothing to do (give --bulk-target and/or --rtt-target)")

    time.sleep(args.warmup)
    measuring.set()
    started = time.perf_counter()
    time.sleep(args.duration)
    measured_s = time.perf_counter() - started
    stop.set()
    for thread in threads:
        thread.join(timeout=5.0)

    out = {
        "proto": args.proto,
        "measure_s": round(measured_s, 4),
        "measurement_side": "sender",
    }
    if bulk_results:
        msgs = sum(r.msgs for r in bulk_results)
        sent_bytes = sum(r.bytes for r in bulk_results)
        lag_n = sum(r.lag_n for r in bulk_results)
        out.update(
            {
                "bulk_conns": args.bulk_conns,
                "bulk_msg_bytes": args.bulk_msg,
                "offered_mbps": args.bulk_rate_mbps,
                "sent_msgs": msgs,
                "sent_bytes": sent_bytes,
                "sender_gbps": round(sent_bytes * 8 / measured_s / 1e9, 6),
                "send_lag_mean_us": round(
                    sum(r.lag_sum_us for r in bulk_results) / lag_n if lag_n else 0.0, 3
                ),
                "send_lag_max_us": round(max(r.lag_max_us for r in bulk_results), 3),
            }
        )
    if args.rtt_target:
        out.update(summarise_rtts(rtt_samples))
        # A resync means a reply went unmatched and the connection was rebuilt.
        # Non-zero is not fatal, but it bounds how much of the window the RTT
        # figure actually covers, so it must be visible rather than swallowed.
        out["rtt_resyncs"] = rtt_stats["resyncs"]
    return out


# --------------------------------------------------------------------------


def emit(result, path):
    line = json.dumps(result, sort_keys=True)
    print("RESULT " + line, flush=True)
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(line + "\n")


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--report-file", help="also write the RESULT JSON here")
    sub = parser.add_subparsers(dest="role", required=True)

    sink = sub.add_parser("sink", help="receive-only endpoint (far side)")
    sink.add_argument("--proto", choices=["tcp", "udp"], required=True)
    sink.add_argument("--bind", type=parse_hostport, required=True)
    sink.add_argument("--msg", type=int, default=1400, help="TCP reframing size")
    sink.add_argument("--duration", type=float, default=0.0)
    sink.add_argument("--conns", type=int, default=4)
    sink.add_argument(
        "--expect-dscp",
        type=int,
        help="observe the DS field (UDP only) and check it equals this value",
    )
    sink.add_argument(
        "--burst-report",
        help="append one JSON line per traffic burst here; an idle gap ends a "
        "burst, which is how a long-lived peer sink is attributed to cells",
    )
    sink.add_argument("--idle-gap", type=float, default=1.5, help="seconds of silence that end a burst")

    echo = sub.add_parser("echo", help="echo endpoint for closed-loop RTT (far side)")
    echo.add_argument("--proto", choices=["tcp", "udp"], required=True)
    echo.add_argument("--bind", type=parse_hostport, required=True)
    echo.add_argument("--msg", type=int, default=256)
    echo.add_argument("--duration", type=float, default=0.0)

    point = sub.add_parser("point", help="one measurement point (bulk and/or RTT)")
    point.add_argument("--proto", choices=["tcp", "udp"], required=True)
    point.add_argument("--duration", type=float, required=True)
    point.add_argument("--warmup", type=float, default=2.0)
    point.add_argument("--bulk-target", type=parse_hostport)
    point.add_argument("--bulk-conns", type=int, default=0)
    point.add_argument("--bulk-msg", type=int, default=65536)
    point.add_argument(
        "--bulk-rate-mbps",
        type=float,
        default=0.0,
        help="offered load across all bulk connections; 0 = unthrottled",
    )
    point.add_argument("--bulk-dscp", type=int)
    point.add_argument("--rtt-target", type=parse_hostport)
    point.add_argument("--rtt-msg", type=int, default=256)
    point.add_argument(
        "--rtt-interval-us",
        type=float,
        default=200.0,
        help="paced send interval; 0 = back-to-back",
    )
    point.add_argument("--rtt-dscp", type=int)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    for name in ("bulk_dscp", "rtt_dscp", "expect_dscp"):
        value = getattr(args, name, None)
        if value is not None and not 0 <= value <= 63:
            sys.exit(f"{name.replace('_', '-')} must be in 0..63, got {value}")

    if args.role == "sink":
        tally = SinkTally(args.expect_dscp)
        burst = BurstReporter(args.burst_report, args.idle_gap) if args.burst_report else None
        if args.proto == "udp":
            sink_udp(args.bind, args.msg, args.duration, tally, burst)
        else:
            if args.expect_dscp is not None:
                print(
                    "[wire-probe] TCP cannot observe the DS field from userspace; "
                    "the verdict will stay unset (use a packet capture)",
                    file=sys.stderr,
                )
            sink_tcp(args.bind, args.msg, args.duration, tally, args.conns, burst)
        # In burst mode the per-burst records are the result; a trailing
        # cumulative report would double-count what was already flushed.
        if not burst:
            emit(tally.report(), args.report_file)
    elif args.role == "echo":
        if args.proto == "udp":
            echo_udp(args.bind, args.duration)
        else:
            echo_tcp(args.bind, args.msg, args.duration)
    else:
        emit(run_point(args), args.report_file)


if __name__ == "__main__":
    main()
