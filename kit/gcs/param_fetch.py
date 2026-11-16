#!/usr/bin/env python3
"""Uplink check: download the full parameter list through the proxy
(equivalent to 'param fetch' in MAVProxy). Exit code 0 if complete."""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mavtools import DEFAULT_CONN, Link  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--conn", default=DEFAULT_CONN)
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    link = Link(args.conn, component=193)
    if not link.wait_vehicle(30):
        sys.exit("no vehicle heartbeat")
    m = link.m
    m.mav.param_request_list_send(link.target_system, link.target_component)
    seen = set()
    total = None
    t_end = time.monotonic() + args.timeout
    last_rx = time.monotonic()
    while time.monotonic() < t_end:
        link.heartbeat_tick()
        msg = m.recv_match(type="PARAM_VALUE", blocking=True, timeout=0.5)
        if msg is None:
            # re-request missing indices after a pause, like a real GCS does
            if total is not None and time.monotonic() - last_rx > 2.0:
                for idx in range(total):
                    if idx not in seen:
                        m.mav.param_request_read_send(link.target_system,
                                                      link.target_component, b"", idx)
                last_rx = time.monotonic()
            continue
        last_rx = time.monotonic()
        total = msg.param_count
        seen.add(msg.param_index)
        if total and len(seen) >= total:
            break
    ok = total is not None and len(seen) >= total
    print(f"param fetch: {len(seen)}/{total} parameters {'OK' if ok else 'INCOMPLETE'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
