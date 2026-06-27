#!/usr/bin/env python3
"""UDP load/latency probe for the SCG WireGuard benchmark.

SESHAT's own distributed sender/receiver are TCP-only, so they cannot drive a
UDP datagram path. This standalone probe measures the WireGuard scg->scg path
with plain UDP: one-way throughput (sink counts received bytes) and closed-loop
latency (echo + RTT). It is intentionally dependency-free (stdlib only).
"""
import signal
import socket
import sys
import time


def receiver(host, port, mode, duration=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    s.bind((host, port))
    state = {"count": 0, "bytes": 0}

    def report(*_):
        sys.stderr.write("RECV count=%d bytes=%d\n" % (state["count"], state["bytes"]))
        sys.stderr.flush()
        sys.exit(0)

    signal.signal(signal.SIGTERM, report)
    signal.signal(signal.SIGINT, report)
    if duration > 0:
        # Self-terminate after `duration` s so the caller never has to signal us.
        signal.signal(signal.SIGALRM, report)
        signal.alarm(duration)
    print("ready", flush=True)  # readiness handshake on stdout
    while True:
        try:
            data, peer = s.recvfrom(65535)
        except OSError:
            continue
        state["count"] += 1
        state["bytes"] += len(data)
        if mode == "echo":
            try:
                s.sendto(data, peer)
            except OSError:
                pass


def latency(host, port, msg, samples):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((host, port))
    s.settimeout(1.0)
    payload = b"L" + b"\x00" * (msg - 1)
    for _ in range(20):  # warm up + establish the WireGuard session
        try:
            s.send(payload)
            s.recv(65535)
        except OSError:
            pass
    rtts = []
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            s.send(payload)
            s.recv(65535)
            rtts.append((time.perf_counter() - t0) * 1e6)
        except OSError:
            pass
    if not rtts:
        print("LAT none", flush=True)
        return
    rtts.sort()
    p50 = rtts[len(rtts) // 2]
    p99 = rtts[min(len(rtts) - 1, int(len(rtts) * 0.99))]
    print("LAT p50=%.1f p99=%.1f n=%d" % (p50, p99, len(rtts)), flush=True)


def throughput(host, port, msg, duration, rate_mbps=0):
    """Send for `duration` s. rate_mbps<=0 blasts unthrottled; otherwise paces
    to the target offered rate so the path is not overwhelmed (UDP has no flow
    control, so an unthrottled blast just measures where the relay starts
    dropping). Prints the count actually sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((host, port))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024 * 1024)
    payload = b"T" + b"\x00" * (msg - 1)
    sent = 0
    end = time.perf_counter() + duration
    if rate_mbps <= 0:
        while time.perf_counter() < end:
            for _ in range(64):
                try:
                    s.send(payload)
                    sent += 1
                except OSError:
                    pass
    else:
        pps = rate_mbps * 1e6 / 8.0 / msg
        per_ms = max(1, int(pps / 1000.0))  # datagrams per 1 ms tick
        next_tick = time.perf_counter()
        while time.perf_counter() < end:
            for _ in range(per_ms):
                try:
                    s.send(payload)
                    sent += 1
                except OSError:
                    pass
            next_tick += 0.001
            dt = next_tick - time.perf_counter()
            if dt > 0:
                time.sleep(dt)
    print("SENT %d" % sent, flush=True)


if __name__ == "__main__":
    role = sys.argv[1]
    if role == "receiver":
        dur = int(sys.argv[5]) if len(sys.argv) > 5 else 0
        receiver(sys.argv[2], int(sys.argv[3]), sys.argv[4], dur)
    elif role == "latency":
        latency(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]))
    elif role == "throughput":
        rate = int(sys.argv[6]) if len(sys.argv) > 6 else 0
        throughput(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), rate)
    else:
        sys.exit("unknown role: %s" % role)
