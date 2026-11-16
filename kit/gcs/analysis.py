#!/usr/bin/env python3
"""Statistical analysis of the campaign, as specified in the thesis (Section
"Statistical Analysis"). Reads the raw per-run CSV files, not summary.csv, so
every number can be regenerated from the stored data.

    python3 analysis.py ../data/sitl --out ../data/analysis [--baseline plain]

Procedure, in the order the thesis states it:
  * warm-up: the first W0 = 30 s of every time series is discarded (latency
    probes by send time, throughput intervals and RAM/CPU samples by t_s);
    lost probes are excluded from the latency distribution but counted in the
    loss ratio;
  * descriptive statistics per scenario/profile/treatment: median, IQR, p95,
    p99, mean, standard deviation; 95 % percentile-bootstrap CI of the median
    with B = 10000, resampling whole RUNS (cluster bootstrap) because probes
    within a run are not independent;
  * Shapiro-Wilk on the pooled latency (reported, not used to choose tests);
  * inference on RUN-LEVEL medians: two-sided Mann-Whitney U against the
    baseline (and Ascon against each competitor), Kruskal-Wallis across all
    treatments of a scenario/profile with Dunn's post-hoc and Holm adjustment;
  * effect size: Vargha-Delaney A12 and difference of medians with its
    cluster-bootstrap CI.

With 5 runs per treatment the smallest two-sided exact Mann-Whitney p-value is
2/252 = 0.0079, so alpha = 0.05 is reachable but multiplicity is not free:
read Holm-adjusted columns where they exist.
"""
import argparse
import csv
import gzip
import itertools
import math
import os
import re
import sys
import warnings

import numpy as np
from scipy import stats

try:
    import scikit_posthocs as sp
except ImportError:  # Dunn is optional: everything else still runs
    sp = None

W0 = 30.0
B = 10000
RNG_SEED = 20261022
NAME = re.compile(r"^([A-Z]\d+)_(N\d)_([a-z0-9]+(?:-[a-z0-9]+)?)_run(\d+)_"
                  r"(latency|throughput|proxy|ram_tunnel|ram)\.csv(\.gz)?$")
USER_HZ = 100.0


def rows(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", newline="") as f:
        return list(csv.DictReader(f))


def kv(path):
    out = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    k, v = line.strip().split("=", 1)
                    out.setdefault(k, []).append(v)
    return out


def load_run(d, sc, pr, sch, run, files):
    """Return per-run metrics and the raw latency array (ms, after warm-up)."""
    base = f"{sc}_{pr}_{sch}_run{run}_"
    r = {"scenario": sc, "profile": pr, "scheme": sch, "run": run}
    # latency
    lat = rows(os.path.join(d, files["latency"]))
    t0 = float(lat[0]["t_send_ns"])
    keep = [x for x in lat if (float(x["t_send_ns"]) - t0) / 1e9 >= W0]
    ok = np.array([float(x["rtt_us"]) / 1000.0 for x in keep if x["lost"] == "0"])
    sent = len(keep)
    r["probes_after_warmup"] = sent
    r["loss_pct"] = 100.0 * (sent - len(ok)) / sent if sent else math.nan
    if len(ok):
        r["rtt_median_ms"] = float(np.median(ok))
        r["rtt_mean_ms"] = float(np.mean(ok))
        r["rtt_p95_ms"] = float(np.percentile(ok, 95))
        r["rtt_p99_ms"] = float(np.percentile(ok, 99))
    # throughput
    thr = [x for x in rows(os.path.join(d, files["throughput"])) if int(x["t_s"]) >= W0]
    msgs = sum(int(x["msgs"]) for x in thr)
    r["thr_msgs_s"] = msgs / len(thr) if thr else math.nan
    r["thr_bytes_s"] = sum(int(x["bytes"]) for x in thr) / len(thr) if thr else math.nan
    # memory and CPU of the UAV side (firmware + tunnel endpoint for dtls)
    cpu_ticks = 0.0
    rss = None
    hwm = 0.0
    for key in ("ram", "ram_tunnel"):
        if key not in files:
            continue
        ra = [x for x in rows(os.path.join(d, files[key])) if x["vmrss_kb"] and int(x["t_s"]) >= W0]
        if not ra:
            continue
        s = np.array([int(x["vmrss_kb"]) for x in ra], dtype=float)
        rss = np.median(s) if rss is None else rss + np.median(s)
        hwm += max(int(x["vmhwm_kb"]) for x in ra)
        t = [int(x["utime_ticks"]) + int(x["stime_ticks"]) for x in ra]
        cpu_ticks += t[-1] - t[0]
        if key == "ram":
            r["fw_rss_kb"] = float(np.median(s))
            r["fw_cpu_s"] = (t[-1] - t[0]) / USER_HZ
    if rss is not None:
        r["uav_rss_kb"] = float(rss)
        r["uav_hwm_kb"] = float(hwm)
        r["uav_cpu_s"] = cpu_ticks / USER_HZ
        r["uav_cpu_us_per_frame"] = 1e6 * (cpu_ticks / USER_HZ) / msgs if msgs else math.nan
    # proxy log: byte overhead and PC-side crypto time
    if "proxy" in files:
        px = rows(os.path.join(d, files["proxy"]))
        for dr in ("down", "up"):
            sel = [x for x in px if x["dir"] == dr]
            fr = sum(int(x["frames"]) for x in sel)
            if fr:
                fb = sum(int(x.get("frame_bytes") or x["wire_bytes"]) for x in sel)
                pl = sum(int(x["plain_bytes"]) for x in sel)
                r[f"{dr}_overhead_B"] = (fb - pl) / fr
                r[f"{dr}_plain_B"] = pl / fr
                r[f"{dr}_proxy_crypto_ns"] = sum(int(x["crypto_ns"]) for x in sel) / fr
        last = px[-1] if px else {}
        r["auth_fail"] = int(last.get("auth_fail", 0) or 0)
        r["replay"] = int(last.get("replay", 0) or 0)
    # DTLS tunnel report
    txt = kv(os.path.join(d, base + "dtls.txt"))
    if txt:
        hs = [float(v) for v in txt.get("handshake_ms", [])]
        if hs:
            r["dtls_handshake_ms_max"] = max(hs)
        for k in ("down_dtls_overhead_bytes_per_datagram", "up_dtls_overhead_bytes_per_datagram"):
            if k in txt:
                r[k.replace("_bytes_per_datagram", "_B")] = float(txt[k][0])
        r["dtls_read_errors"] = sum(int(v) for v in txt.get("read_errors", []))
        r["dtls_write_dropped"] = sum(int(v) for v in txt.get("write_dropped", []))
    return r, ok


def vd_a12(x, y):
    x, y = np.asarray(x, float), np.asarray(y, float)
    gt = sum((a > y).sum() + 0.5 * (a == y).sum() for a in x)
    return float(gt / (len(x) * len(y)))


def boot_ci(groups, stat, rng, b=B):
    """Percentile bootstrap, resampling whole runs. groups: list of arrays."""
    n = len(groups)
    vals = np.empty(b)
    for i in range(b):
        idx = rng.integers(0, n, n)
        vals[i] = stat([groups[j] for j in idx])
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))


def pooled_median(gs):
    return float(np.median(np.concatenate(gs))) if len(gs) else math.nan


def write_csv(path, rows_, cols=None):
    if not rows_:
        return
    cols = cols or sorted({k for r in rows_ for k in r})
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows_:
            w.writerow({k: ("" if (isinstance(r.get(k), float) and math.isnan(r[k])) else r.get(k, "")) for k in cols})


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("data_dir")
    ap.add_argument("--out", required=True)
    ap.add_argument("--baseline", default="plain")
    ap.add_argument("--boot", type=int, default=B)
    ap.add_argument("--margin", type=float, default=0.2,
                    help="equivalence margin for the RTT difference, ms (declared a priori)")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    rng = np.random.default_rng(RNG_SEED)

    # ---- collect runs (only complete ones) ---------------------------------
    inv = {}
    for name in sorted(os.listdir(args.data_dir)):
        m = NAME.match(name)
        if m:
            sc, pr, sch, run, metric, _ = m.groups()
            inv.setdefault((sc, pr, sch, run), {})[metric] = name
    runs, lat_by_run = [], {}
    skipped = []
    for (sc, pr, sch, run), files in sorted(inv.items()):
        if sc not in ("S1", "S2", "S3", "S4"):
            continue  # S0 and T0 are gates, not analysed data
        if not {"latency", "throughput", "proxy", "ram"} <= set(files):
            skipped.append((sc, pr, sch, run))
            continue
        r, ok = load_run(args.data_dir, sc, pr, sch, run, files)
        runs.append(r)
        lat_by_run[(sc, pr, sch, run)] = ok
    write_csv(os.path.join(args.out, "run_level.csv"), runs)
    print(f"{len(runs)} complete runs; skipped incomplete: {skipped}")

    cells = {}
    for r in runs:
        cells.setdefault((r["scenario"], r["profile"], r["scheme"]), []).append(r)

    # ---- descriptive statistics ---------------------------------------------
    desc, shapiro = [], []
    for (sc, pr, sch), rs in sorted(cells.items()):
        arrs = [lat_by_run[(sc, pr, sch, r["run"])] for r in rs]
        arrs = [a for a in arrs if len(a)]
        pooled = np.concatenate(arrs)
        lo, hi = boot_ci(arrs, pooled_median, rng, args.boot)
        q1, q3 = np.percentile(pooled, [25, 75])
        loss = [r["loss_pct"] for r in rs]
        d = {"scenario": sc, "profile": pr, "scheme": sch, "runs": len(rs), "probes": len(pooled),
             "rtt_median_ms": float(np.median(pooled)), "rtt_median_ci_lo": lo, "rtt_median_ci_hi": hi,
             "rtt_iqr_ms": float(q3 - q1), "rtt_p95_ms": float(np.percentile(pooled, 95)),
             "rtt_p99_ms": float(np.percentile(pooled, 99)), "rtt_mean_ms": float(pooled.mean()),
             "rtt_std_ms": float(pooled.std(ddof=1)), "loss_pct_mean": float(np.mean(loss))}
        for k in ("thr_msgs_s", "uav_rss_kb", "uav_hwm_kb", "uav_cpu_us_per_frame", "down_overhead_B",
                  "up_overhead_B", "down_dtls_overhead_B", "up_dtls_overhead_B", "dtls_handshake_ms_max",
                  "down_proxy_crypto_ns", "up_proxy_crypto_ns", "down_plain_B"):
            v = [r[k] for r in rs if k in r and not (isinstance(r[k], float) and math.isnan(r[k]))]
            if v:
                d[k + "_median"] = float(np.median(v))
        desc.append(d)
        sample = pooled if len(pooled) <= 5000 else rng.choice(pooled, 5000, replace=False)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            w, p = stats.shapiro(sample)
        shapiro.append({"scenario": sc, "profile": pr, "scheme": sch, "n": len(sample),
                        "W": float(w), "p": float(p)})
    write_csv(os.path.join(args.out, "descriptive.csv"), desc)
    write_csv(os.path.join(args.out, "shapiro.csv"), shapiro)

    # ---- pairwise comparisons -------------------------------------------------
    metrics = ["rtt_median_ms", "rtt_p95_ms", "loss_pct", "thr_msgs_s", "uav_rss_kb", "uav_cpu_us_per_frame"]
    pairs_for = lambda schemes: (
        [(s, args.baseline) for s in schemes if s != args.baseline]
        + [("ascon", s) for s in schemes if s not in ("ascon", args.baseline)]
        + [(a + "-hw", a) for a in ("aesgcm", "chacha") if a + "-hw" in schemes and a in schemes])
    comp = []
    for (sc, pr) in sorted({(k[0], k[1]) for k in cells}):
        schemes = sorted({k[2] for k in cells if k[0] == sc and k[1] == pr})
        for a, b in pairs_for(schemes):
            ra, rb = cells.get((sc, pr, a), []), cells.get((sc, pr, b), [])
            if len(ra) < 3 or len(rb) < 3:
                continue
            for mtr in metrics:
                xa = [r[mtr] for r in ra if mtr in r]
                xb = [r[mtr] for r in rb if mtr in r]
                if len(xa) < 3 or len(xb) < 3:
                    continue
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    try:
                        p = float(stats.mannwhitneyu(xa, xb, alternative="two-sided").pvalue)
                    except ValueError:
                        p = math.nan
                row = {"scenario": sc, "profile": pr, "scheme": a, "versus": b, "metric": mtr,
                       "n_a": len(xa), "n_b": len(xb), "median_a": float(np.median(xa)),
                       "median_b": float(np.median(xb)), "diff_of_medians": float(np.median(xa) - np.median(xb)),
                       "mannwhitney_p": p, "A12": vd_a12(xa, xb)}
                if mtr == "rtt_median_ms":  # pooled-probe difference, cluster bootstrap
                    ga = [lat_by_run[(sc, pr, a, r["run"])] for r in ra]
                    gb = [lat_by_run[(sc, pr, b, r["run"])] for r in rb]
                    ga = [g for g in ga if len(g)]
                    gb = [g for g in gb if len(g)]
                    nA, nB = len(ga), len(gb)
                    vals = np.empty(args.boot)
                    for i in range(args.boot):
                        ia, ib = rng.integers(0, nA, nA), rng.integers(0, nB, nB)
                        vals[i] = (pooled_median([ga[j] for j in ia]) - pooled_median([gb[j] for j in ib]))
                    row["latency_overhead_pooled_ms"] = pooled_median(ga) - pooled_median(gb)
                    row["latency_overhead_ci_lo"], row["latency_overhead_ci_hi"] = (
                        float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5)))
                comp.append(row)
    # Holm over the comparisons of each metric within a scenario/profile
    by = {}
    for r in comp:
        by.setdefault((r["scenario"], r["profile"], r["metric"]), []).append(r)
    for rs in by.values():
        ps = [(i, r["mannwhitney_p"]) for i, r in enumerate(rs) if not math.isnan(r["mannwhitney_p"])]
        ps.sort(key=lambda t: t[1])
        m = len(ps)
        run_max = 0.0
        for rank, (i, p) in enumerate(ps):
            run_max = max(run_max, min(1.0, (m - rank) * p))
            rs[i]["holm_p"] = run_max
    write_csv(os.path.join(args.out, "comparisons.csv"), comp)

    # ---- Kruskal-Wallis + Dunn per scenario/profile -----------------------------
    kw = []
    for (sc, pr) in sorted({(k[0], k[1]) for k in cells}):
        schemes = [s for s in sorted({k[2] for k in cells if k[0] == sc and k[1] == pr})
                   if not s.endswith("-hw") and len(cells[(sc, pr, s)]) >= 3]
        if len(schemes) < 3:
            continue
        groups = [[r["rtt_median_ms"] for r in cells[(sc, pr, s)]] for s in schemes]
        h, p = stats.kruskal(*groups)
        row = {"scenario": sc, "profile": pr, "schemes": " ".join(schemes), "H": float(h), "kruskal_p": float(p)}
        if sp is not None and p < 0.05:
            dunn = sp.posthoc_dunn(groups, p_adjust="holm")
            for i, j in itertools.combinations(range(len(schemes)), 2):
                row[f"dunn_holm_{schemes[i]}_vs_{schemes[j]}"] = float(dunn.iloc[i, j])
        kw.append(row)
    write_csv(os.path.join(args.out, "kruskal_dunn.csv"), kw)

    # ---- equivalence (TOST) against the baseline ---------------------------------
    # Claim tested: |difference of run-level median RTT| < margin. Two one-sided
    # Welch t-tests (TOST) on the run-level medians; the 90 % CI of the difference
    # (equivalent to the 5 % TOST) does not depend on the margin and is reported
    # so that a reader can apply a different margin. The margin is declared in the
    # thesis before the confirmatory runs and is not tuned to the data.
    eq = []
    for (sc, pr) in sorted({(k[0], k[1]) for k in cells}):
        base = [r["rtt_median_ms"] for r in cells.get((sc, pr, args.baseline), []) if "rtt_median_ms" in r]
        if len(base) < 3:
            continue
        for sch in sorted({k[2] for k in cells if k[0] == sc and k[1] == pr}):
            if sch == args.baseline:
                continue
            x = [r["rtt_median_ms"] for r in cells[(sc, pr, sch)] if "rtt_median_ms" in r]
            if len(x) < 3:
                continue
            xa, xb = np.asarray(x, float), np.asarray(base, float)
            va, vb = xa.var(ddof=1) / len(xa), xb.var(ddof=1) / len(xb)
            se = math.sqrt(va + vb)
            df = (va + vb) ** 2 / (va ** 2 / (len(xa) - 1) + vb ** 2 / (len(xb) - 1)) if se > 0 else len(xa) + len(xb) - 2
            diff = float(xa.mean() - xb.mean())
            m = args.margin
            p_lo = float(1 - stats.t.cdf((diff + m) / se, df))   # H0: diff <= -m
            p_hi = float(stats.t.cdf((diff - m) / se, df))       # H0: diff >= +m
            tcrit = float(stats.t.ppf(0.95, df))
            eq.append({"scenario": sc, "profile": pr, "scheme": sch, "versus": args.baseline,
                       "n_a": len(xa), "n_b": len(xb), "diff_of_means_ms": diff, "se_ms": se,
                       "ci90_lo": diff - tcrit * se, "ci90_hi": diff + tcrit * se,
                       "margin_ms": m, "tost_p": max(p_lo, p_hi),
                       "equivalent": bool(max(p_lo, p_hi) < 0.05)})
    write_csv(os.path.join(args.out, "equivalence.csv"), eq)
    print(f"descriptive: {len(desc)} cells; comparisons: {len(comp)}; Kruskal-Wallis: {len(kw)}; equivalence: {len(eq)}")


if __name__ == "__main__":
    main()
