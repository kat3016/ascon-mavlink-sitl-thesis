#!/usr/bin/env python3
"""Summarise every run found in a data directory.

Reads <scenario>_<profile>_<scheme>_run<NN>_<metric>.csv or .csv.gz (metric =
latency, throughput, proxy, ram); <profile> (N0-N3) is optional (names
without a profile are also accepted). <scheme> may contain a hyphen
(aesgcm-hw, chacha-hw).
Writes, in the same directory:
    summary.csv            one row per run
    summary_by_scheme.csv  mean and standard deviation across runs,
                           per scenario, profile and scheme
Only the standard library is used. Raw CSVs are never modified.
"""
import argparse
import csv
import gzip
import math
import os
import re
import statistics
import sys
from collections import defaultdict

NAME = re.compile(r"^([A-Z]\d+)_(?:(N\d)_)?([a-z0-9]+(?:-[a-z0-9]+)?)_run(\d+)_"
                  r"(latency|throughput|proxy|ram_tunnel|ram)\.csv(\.gz)?$")
USER_HZ = 100  # /proc tick rate on Linux (PC)


def rows(path):
    if not os.path.exists(path) and os.path.exists(path + ".gz"):
        path += ".gz"
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", newline="") as f:
        return list(csv.DictReader(f))


def pct(sorted_vals, p):
    if not sorted_vals:
        return math.nan
    k = (len(sorted_vals) - 1) * p
    lo, hi = math.floor(k), math.ceil(k)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def latency(path):
    r = rows(path)
    rtt = sorted(float(x["rtt_us"]) / 1000.0 for x in r if x["lost"] == "0")
    n = len(r)
    out = {"lat_sent": n, "lat_received": len(rtt),
           "lat_loss_pct": 100.0 * (n - len(rtt)) / n if n else math.nan}
    if rtt:
        out.update({
            "rtt_mean_ms": statistics.fmean(rtt),
            "rtt_median_ms": statistics.median(rtt),
            "rtt_p95_ms": pct(rtt, 0.95),
            "rtt_p99_ms": pct(rtt, 0.99),
            "rtt_std_ms": statistics.stdev(rtt) if len(rtt) > 1 else 0.0,
            "rtt_min_ms": rtt[0],
            "rtt_max_ms": rtt[-1],
        })
    return out


def throughput(path):
    r = rows(path)
    n = len(r)
    if n == 0:
        return {}
    msgs = [int(x["msgs"]) for x in r]
    byts = [int(x["bytes"]) for x in r]
    gaps = sum(int(x["seq_gaps"]) for x in r)
    total = sum(msgs)
    return {
        "thr_seconds": n,
        "thr_msgs_per_s": total / n,
        "thr_bytes_per_s": sum(byts) / n,
        "thr_msgs_per_s_std": statistics.stdev(msgs) if n > 1 else 0.0,
        "thr_seq_gaps": gaps,
        "thr_gap_pct": 100.0 * gaps / (total + gaps) if total + gaps else math.nan,
    }


def proxy(path):
    r = rows(path)
    out = {}
    for d in ("down", "up"):
        sel = [x for x in r if x["dir"] == d]
        frames = sum(int(x["frames"]) for x in sel)
        wire = sum(int(x["wire_bytes"]) for x in sel)
        fbytes = sum(int(x.get("frame_bytes") or x["wire_bytes"]) for x in sel)
        plain = sum(int(x["plain_bytes"]) for x in sel)
        ns = sum(int(x["crypto_ns"]) for x in sel)
        out[f"{d}_datagrams"] = len(sel)
        out[f"{d}_frames"] = frames
        if frames:
            out[f"{d}_wire_bytes_per_frame"] = fbytes / frames
            out[f"{d}_plain_bytes_per_frame"] = plain / frames
            out[f"{d}_overhead_bytes_per_frame"] = (fbytes - plain) / frames
            out[f"{d}_bytes_on_air"] = wire
            out[f"{d}_bytes_unrecovered"] = wire - fbytes
            out[f"{d}_crypto_ns_per_frame"] = ns / frames
    last = r[-1] if r else {}
    out["auth_fail"] = int(last.get("auth_fail", 0) or 0)
    out["replay"] = int(last.get("replay", 0) or 0)
    return out


def ram(path, prefix=""):
    r = rows(path)
    if not r:
        return {}
    rss = [int(x["vmrss_kb"]) for x in r if x["vmrss_kb"]]
    hwm = max(int(x["vmhwm_kb"]) for x in r if x["vmhwm_kb"])
    first, last = r[0], r[-1]
    dt = int(last["t_s"]) - int(first["t_s"])
    ticks = (int(last["utime_ticks"]) + int(last["stime_ticks"])
             - int(first["utime_ticks"]) - int(first["stime_ticks"]))
    return {
        f"{prefix}ram_rss_mean_kb": statistics.fmean(rss),
        f"{prefix}ram_rss_max_kb": max(rss),
        f"{prefix}ram_hwm_kb": hwm,
        f"{prefix}cpu_pct": 100.0 * ticks / (USER_HZ * dt) if dt > 0 else math.nan,
    }


def ram_tunnel(path):
    """RSS/CPU of the UAV-side dtls_tunnel, with a tun_ prefix. It is part of
    the UAV's protection cost for the dtls treatment, so analysis adds it to
    the firmware's own ram_* / cpu_pct columns."""
    return ram(path, prefix="tun_")


PARSERS = {"latency": latency, "throughput": throughput, "proxy": proxy, "ram": ram,
           "ram_tunnel": ram_tunnel}
KEY_METRICS = ["rtt_median_ms", "rtt_p95_ms", "rtt_mean_ms", "lat_loss_pct",
               "thr_msgs_per_s", "thr_bytes_per_s", "thr_gap_pct",
               "down_wire_bytes_per_frame", "down_overhead_bytes_per_frame",
               "down_crypto_ns_per_frame", "up_crypto_ns_per_frame",
               "auth_fail", "ram_rss_mean_kb", "ram_hwm_kb", "cpu_pct"]


def fmt(v):
    if isinstance(v, float):
        return "" if math.isnan(v) else f"{v:.4f}"
    return str(v)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("data_dir")
    args = ap.parse_args()

    runs = defaultdict(dict)
    files = defaultdict(list)
    for name in sorted(os.listdir(args.data_dir)):
        mt = NAME.match(name)
        if not mt:
            continue
        sc, profile, scheme, run, metric, _ = mt.groups()
        profile = profile or ""  # names without a network profile
        key = (sc, profile, scheme, run)
        try:
            runs[key].update(PARSERS[metric](os.path.join(args.data_dir, name)))
            files[key].append(metric)
        except (ValueError, KeyError, ZeroDivisionError) as e:
            print(f"warning: {name}: {e}", file=sys.stderr)
    if not runs:
        sys.exit(f"no <scenario>_[profile_]<scheme>_runNN_<metric>.csv files in {args.data_dir}")

    cols = sorted({k for v in runs.values() for k in v})
    out1 = os.path.join(args.data_dir, "summary.csv")
    with open(out1, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "profile", "scheme", "run", "metrics"] + cols)
        for key in sorted(runs):
            w.writerow(list(key) + ["+".join(sorted(files[key]))]
                       + [fmt(runs[key].get(c, "")) for c in cols])

    groups = defaultdict(list)
    for (sc, profile, scheme, run), v in runs.items():
        groups[(sc, profile, scheme)].append(v)
    out2 = os.path.join(args.data_dir, "summary_by_scheme.csv")
    with open(out2, "w", newline="") as f:
        w = csv.writer(f)
        head = ["scenario", "profile", "scheme", "runs"]
        for c in KEY_METRICS:
            head += [f"{c}_mean", f"{c}_std"]
        w.writerow(head)
        for (sc, profile, scheme) in sorted(groups):
            g = groups[(sc, profile, scheme)]
            line = [sc, profile, scheme, len(g)]
            for c in KEY_METRICS:
                vals = [x[c] for x in g if c in x and not (isinstance(x[c], float) and math.isnan(x[c]))]
                line += [fmt(statistics.fmean(vals)) if vals else "",
                         fmt(statistics.stdev(vals)) if len(vals) > 1 else ""]
            w.writerow(line)

    print(f"{len(runs)} runs -> {out1}, {out2}")
    print(f"{'scenario':8} {'profile':7} {'scheme':9} {'runs':>4} {'rtt_med_ms':>10} {'loss_%':>7} "
          f"{'msg/s':>7} {'B/frame':>8} {'ovh_B':>6} {'dec_ns':>8} {'auth_fail':>9}")
    for (sc, profile, scheme) in sorted(groups):
        g = groups[(sc, profile, scheme)]

        def m(c):
            vals = [x[c] for x in g if c in x]
            return statistics.fmean(vals) if vals else math.nan
        print(f"{sc:8} {profile:7} {scheme:9} {len(g):>4} {m('rtt_median_ms'):>10.3f} "
              f"{m('lat_loss_pct'):>7.2f} "
              f"{m('thr_msgs_per_s'):>7.1f} {m('down_wire_bytes_per_frame'):>8.2f} "
              f"{m('down_overhead_bytes_per_frame'):>6.2f} {m('down_crypto_ns_per_frame'):>8.0f} "
              f"{m('auth_fail'):>9.0f}")


if __name__ == "__main__":
    main()
