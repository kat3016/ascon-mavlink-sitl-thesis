#!/usr/bin/env python3
"""Validation criteria for one run (used by sitl_e2e.sh).

    python3 tests/check_run.py <data_dir> <scenario> <scheme> <run> [--tamper N]
"""
import argparse
import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(KIT, "gcs"))
import summarize  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data_dir")
    ap.add_argument("scenario")
    ap.add_argument("scheme")
    ap.add_argument("run")
    ap.add_argument("--tamper", type=int, default=0)
    args = ap.parse_args()
    p = os.path.join(args.data_dir, f"{args.scenario}_{args.scheme}_run{args.run}_")

    res = []

    def crit(name, ok, detail):
        res.append(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    lat = summarize.latency(p + "latency.csv")
    thr = summarize.throughput(p + "throughput.csv")
    prx = summarize.proxy(p + "proxy.csv")
    loss = lat["lat_loss_pct"]
    if args.tamper:
        exp = 100.0 / args.tamper
        crit("tampered uplink frames are dropped",
             exp * 0.4 <= loss <= exp * 1.8,
             f"probe loss {loss:.1f}% (expected about {exp:.0f}%)")
    else:
        # With 50 probes (S0) a single loss is already 2 %, and at N1's expected
        # ~0.2 % round-trip loss one lost probe happens in about one run in ten:
        # tolerate one lost probe when the sample is too small for a percentage
        # threshold to mean anything. With the 1000-2000 probes of S1-S4 this is
        # the plain < 1 % criterion.
        lost = lat["lat_sent"] - lat["lat_received"]
        # The gate must follow the emulated link: a probe crosses it twice, so the
        # expected round-trip loss is about twice the per-direction NetEm loss
        # (N0 0 %, N1 0.1 % -> 0.2 %, N2 1 % -> 2 %, N3 5 % -> 10 %). The bound is
        # a sanity gate (a broken run), not a measurement; the loss itself is data.
        prof = args.scenario.split("_")[-1] if "_" in args.scenario else "N1"
        bound = {"N0": 1.0, "N1": 1.0, "N2": 6.0, "N3": 25.0}.get(prof, 1.0)
        crit(f"probe loss < {bound:g}% for {prof} (or <= 1 probe of a small sample)",
             loss < bound or (lat["lat_sent"] < 100 and lost <= 1),
             f"{loss:.2f}% of {lat['lat_sent']} probes ({lost} lost)")
    if "rtt_median_ms" in lat:
        print(f"         RTT median {lat['rtt_median_ms']:.3f} ms, p95 {lat['rtt_p95_ms']:.3f} ms")
    crit("telemetry arrives", thr.get("thr_msgs_per_s", 0) > 0,
         f"{thr.get('thr_msgs_per_s', 0):.1f} msg/s, {thr.get('thr_bytes_per_s', 0):.0f} B/s")
    crit("downlink auth_fail = 0 and replay = 0",
         prx["auth_fail"] == 0 and prx["replay"] == 0,
         f"auth_fail={prx['auth_fail']} replay={prx['replay']}")
    crit("uplink works (frames sent to the drone)", prx.get("up_frames", 0) > 0,
         f"{prx.get('up_frames', 0)} frames")
    ovh = prx.get("down_overhead_bytes_per_frame")
    want = {"ascon": 32.0, "aesgcm": 28.0, "chacha": 28.0}.get(args.scheme.removesuffix("-hw"), 0.0)
    crit(f"overhead exactly {want:.0f} B per frame", ovh is not None and abs(ovh - want) < 1e-6,
         f"{prx.get('down_wire_bytes_per_frame', 0):.2f} B on air vs "
         f"{prx.get('down_plain_bytes_per_frame', 0):.2f} B clear per frame "
         f"({prx.get('down_frames', 0)} frames; {prx.get('down_bytes_unrecovered', 0)} B of "
         f"partial frames at start/end not counted)")
    if args.scheme.removesuffix("-hw") in ("ascon", "aesgcm", "chacha"):
        print(f"         PC decrypt {prx.get('down_crypto_ns_per_frame', 0):.0f} ns/frame "
              f"(incl. Python call), encrypt {prx.get('up_crypto_ns_per_frame', 0):.0f} ns/frame")
    if all(res):
        print("RUN PASSED")
        return 0
    print("RUN FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
