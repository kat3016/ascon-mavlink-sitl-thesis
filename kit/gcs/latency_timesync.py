#!/usr/bin/env python3
"""Round-trip latency with MAVLink TIMESYNC probes.

Each probe is TIMESYNC(tc1=0, ts1=<PC monotonic ns>). ArduPilot answers every
request with TIMESYNC(tc1=<its clock>, ts1=<our ts1>), so the RTT is measured
with the PC clock only: RTT = now - ts1. No clock synchronisation is needed
(the previous thesis subtracted the drone's time_boot_ms from the PC clock,
which does not measure latency).

CSV: seq,t_send_ns,rtt_us,lost
"""
import argparse
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mavtools import DEFAULT_CONN, Link  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--conn", default=DEFAULT_CONN)
    ap.add_argument("--n", type=int, default=1000, help="number of probes")
    ap.add_argument("--rate", type=float, default=5.0, help="probes per second")
    ap.add_argument("--timeout", type=float, default=2.0, help="seconds before a probe is lost")
    ap.add_argument("--wait", type=float, default=60.0, help="max wait for the vehicle")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    link = Link(args.conn, component=191)
    if not link.wait_vehicle(args.wait):
        sys.exit("no vehicle heartbeat")
    m = link.m

    pending = {}  # ts1 -> seq
    sent_at = [0] * args.n
    rtt = [None] * args.n
    interval_ns = int(1e9 / args.rate)
    t0 = time.monotonic_ns()
    seq = 0
    deadline = None
    while True:
        now = time.monotonic_ns()
        if seq < args.n and now >= t0 + seq * interval_ns:
            ts1 = time.monotonic_ns()
            pending[ts1] = seq
            sent_at[seq] = ts1
            m.mav.timesync_send(0, ts1)
            seq += 1
            if seq == args.n:
                deadline = time.monotonic_ns() + int(args.timeout * 1e9)
        link.heartbeat_tick()
        if deadline is not None and (time.monotonic_ns() > deadline or not pending):
            break
        wait_s = 0.005
        if seq < args.n:
            wait_s = max(0.0, min(wait_s, (t0 + seq * interval_ns - time.monotonic_ns()) / 1e9))
        msg = m.recv_match(type="TIMESYNC", blocking=True, timeout=wait_s)
        while msg is not None:
            t_rx = time.monotonic_ns()
            if msg.tc1 != 0 and msg.ts1 in pending:
                s = pending.pop(msg.ts1)
                if t_rx - sent_at[s] <= args.timeout * 1e9:
                    rtt[s] = (t_rx - sent_at[s]) / 1000.0
            msg = m.recv_match(type="TIMESYNC", blocking=False)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        f.write("seq,t_send_ns,rtt_us,lost\n")
        for i in range(args.n):
            if rtt[i] is None:
                f.write(f"{i},{sent_at[i]},,1\n")
            else:
                f.write(f"{i},{sent_at[i]},{rtt[i]:.1f},0\n")
    got = [r for r in rtt if r is not None]
    loss = 100.0 * (args.n - len(got)) / args.n
    if got:
        q = sorted(got)
        print(f"latency: sent={args.n} received={len(got)} loss={loss:.2f}% "
              f"median={statistics.median(q) / 1000:.3f} ms "
              f"p95={q[int(0.95 * (len(q) - 1))] / 1000:.3f} ms -> {args.out}")
    else:
        print(f"latency: sent={args.n} received=0 loss=100% -> {args.out}")


if __name__ == "__main__":
    main()
