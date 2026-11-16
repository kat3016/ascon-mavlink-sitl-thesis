#!/usr/bin/env python3
"""Telemetry throughput: request MAV_DATA_STREAM_ALL at --hz and count what arrives.

CSV, one row per second:
    t_s,msgs,bytes,timesync_msgs,n_types,seq_gaps
msgs/bytes exclude TIMESYNC (latency probes running in parallel), counted
apart. bytes = clear MAVLink frame bytes (the on-air bytes are in the proxy
log). seq_gaps = frames missing according to the MAVLink sequence number of
the vehicle's link (one counter per link, not per message type).
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mavtools import DEFAULT_CONN, Link  # noqa: E402
from pymavlink import mavutil  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--conn", default=DEFAULT_CONN)
    ap.add_argument("--hz", type=int, default=1, help="stream rate (0 = do not request)")
    ap.add_argument("--duration", type=float, default=300.0, help="measured seconds")
    ap.add_argument("--warmup", type=float, default=3.0, help="seconds discarded after the request")
    ap.add_argument("--wait", type=float, default=60.0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--debug-gaps", action="store_true", help="print every sequence gap")
    args = ap.parse_args()

    link = Link(args.conn, component=192)
    if not link.wait_vehicle(args.wait):
        sys.exit("no vehicle heartbeat")
    m = link.m

    def request():
        if args.hz > 0:
            m.mav.request_data_stream_send(link.target_system, link.target_component,
                                           mavutil.mavlink.MAV_DATA_STREAM_ALL, args.hz, 1)

    request()
    next_req = time.monotonic() + 5.0
    t_meas = time.monotonic() + args.warmup
    t_end = t_meas + args.duration
    nsec = int(args.duration)
    rows = [[0, 0, 0, set(), 0] for _ in range(nsec)]
    last_seq = None
    while True:
        now = time.monotonic()
        if now >= t_end:
            break
        link.heartbeat_tick()
        if now >= next_req:  # re-send in case the request was lost
            request()
            next_req = now + 5.0
        msg = m.recv_match(blocking=True, timeout=0.05)
        if msg is None or msg.get_type() == "BAD_DATA":
            continue
        if msg.get_srcSystem() != link.target_system:
            continue
        # sequence gaps on the vehicle's main link (autopilot component)
        if msg.get_srcComponent() == link.target_component:
            s = msg.get_seq()
            gap = 0 if last_seq is None else (s - last_seq - 1) % 256
            if gap and args.debug_gaps:
                print(f"gap: seq {last_seq} -> {s} ({msg.get_type()})", file=sys.stderr)
            last_seq = s
        else:
            gap = 0
        t = time.monotonic()
        if t < t_meas:
            continue
        i = int(t - t_meas)
        if i >= nsec:
            break
        r = rows[i]
        if msg.get_type() == "TIMESYNC":
            r[2] += 1
        else:
            r[0] += 1
            r[1] += len(msg.get_msgbuf())
            r[3].add(msg.get_type())
        r[4] += gap

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        f.write("t_s,msgs,bytes,timesync_msgs,n_types,seq_gaps\n")
        for i, r in enumerate(rows):
            f.write(f"{i},{r[0]},{r[1]},{r[2]},{len(r[3])},{r[4]}\n")
    tot = sum(r[0] for r in rows)
    byt = sum(r[1] for r in rows)
    gaps = sum(r[4] for r in rows)
    print(f"throughput: {tot / nsec:.1f} msg/s, {byt / nsec:.0f} B/s, seq_gaps={gaps} "
          f"({nsec} s, request {args.hz} Hz) -> {args.out}")


if __name__ == "__main__":
    main()
