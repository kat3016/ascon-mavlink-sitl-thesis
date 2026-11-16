#!/usr/bin/env python3
"""Figures of the IEEE-Access version of the thesis, generated only from the CSV
files in data/ (nothing is typed by hand).

    python figures/make_figures.py

Output: figures/figures/*.pdf  (column width 3.4 in, page width 7.1 in)
"""
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(HERE, "figures")
os.makedirs(OUT, exist_ok=True)
sys.path.insert(0, os.path.join(ROOT, "kit", "gcs"))
import analysis  # noqa: E402  (same parsing/warm-up rule as the statistics)

COL, PAGE = 3.4, 7.1
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 7.5, "axes.labelsize": 7.5, "axes.titlesize": 7.5, "legend.fontsize": 6.5,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "axes.linewidth": 0.6,
    "pdf.fonttype": 42, "ps.fonttype": 42, "axes.grid": True, "grid.alpha": 0.3,
    "grid.linewidth": 0.4, "lines.linewidth": 1.0, "lines.markersize": 4,
})

# Okabe-Ito palette, distinct markers so that the figures survive grayscale printing
COLOR = {"plain": "#6e6e6e", "ascon": "#0072B2", "aesgcm": "#D55E00", "chacha": "#009E73",
         "dtls": "#CC79A7", "aesgcm-hw": "#E69F00", "chacha-hw": "#56B4E9"}
MARK = {"plain": "o", "ascon": "s", "aesgcm": "^", "chacha": "D", "dtls": "v"}
SCHEMES = ["plain", "ascon", "aesgcm", "chacha", "dtls"]
SCEN = {"S1": "S1 (1 Hz)", "S2": "S2 (10 Hz)", "S3": "S3 (50 Hz)", "S4": "S4 (commands)"}
NICE = {"plain": "plain", "ascon": "Ascon", "aesgcm": "AES-GCM", "chacha": "ChaCha20", "dtls": "DTLS 1.3"}

desc = pd.read_csv(os.path.join(DATA, "analysis", "descriptive.csv"))


def save(fig, name):
    fig.savefig(os.path.join(OUT, name), bbox_inches="tight", pad_inches=0.02)
    if os.environ.get("PREVIEW_DIR"):
        fig.savefig(os.path.join(os.environ["PREVIEW_DIR"], name[:-4] + ".png"), dpi=130, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    print("wrote", name)


# 1. median RTT with 95% CI, N1, four scenarios -----------------------------------------------
def fig_latency():
    fig, axes = plt.subplots(1, 4, figsize=(PAGE, 2.1))
    for ax, sc in zip(axes, SCEN):
        sub = desc[(desc.scenario == sc) & (desc.profile == "N1")]
        for i, s in enumerate(SCHEMES):
            d = sub[sub.scheme == s].iloc[0]
            ax.errorbar(i, d.rtt_median_ms,
                        yerr=[[d.rtt_median_ms - d.rtt_median_ci_lo], [d.rtt_median_ci_hi - d.rtt_median_ms]],
                        fmt=MARK[s], color=COLOR[s], capsize=2.5, mfc=COLOR[s])
        ax.set_xticks(range(len(SCHEMES)))
        ax.set_xticklabels([NICE[s] for s in SCHEMES], rotation=50, ha="right")
        ax.set_title(SCEN[sc])
    axes[0].set_ylabel("Median RTT (ms), 95% CI")
    fig.tight_layout(w_pad=0.6)
    save(fig, "fig_latency_n1.pdf")


# 2. pooled RTT distribution, S1/N1 -----------------------------------------------------------
def pooled(sc, pr):
    groups = {}
    for name in sorted(os.listdir(os.path.join(DATA, "sitl"))):
        m = analysis.NAME.match(name)
        if not m:
            continue
        s_, p_, sch, run, metric, _ = m.groups()
        if s_ == sc and p_ == pr and metric == "latency" and sch in SCHEMES:
            lat = analysis.rows(os.path.join(DATA, "sitl", name))
            t0 = float(lat[0]["t_send_ns"])
            groups.setdefault(sch, []).extend(
                float(x["rtt_us"]) / 1000 for x in lat
                if x["lost"] == "0" and (float(x["t_send_ns"]) - t0) / 1e9 >= analysis.W0)
    return groups


def fig_box():
    g = pooled("S1", "N1")
    fig, ax = plt.subplots(figsize=(COL, 2.3))
    bp = ax.boxplot([g[s] for s in SCHEMES], showfliers=False, whis=(1, 99), patch_artist=True,
                    widths=0.6, medianprops={"color": "black", "linewidth": 1.0})
    for patch, s in zip(bp["boxes"], SCHEMES):
        patch.set_facecolor(COLOR[s]); patch.set_alpha(0.65); patch.set_linewidth(0.6)
    ax.set_xticklabels([NICE[s] for s in SCHEMES])
    ax.set_ylabel("RTT (ms)")
    save(fig, "fig_box_s1.pdf")


# 3. link sweep ------------------------------------------------------------------------------
def fig_sweep():
    profiles = ["N0", "N1", "N2", "N3"]
    fig, axes = plt.subplots(2, 2, figsize=(PAGE, 3.3), sharex=True)
    for col, sc in enumerate(("S1", "S4")):
        for s in SCHEMES:
            xs, ys, ls = [], [], []
            for i, p in enumerate(profiles):
                r = desc[(desc.scenario == sc) & (desc.profile == p) & (desc.scheme == s)]
                if len(r):
                    xs.append(i); ys.append(r.iloc[0].rtt_median_ms); ls.append(r.iloc[0].loss_pct_mean)
            kw = dict(color=COLOR[s], marker=MARK[s], label=NICE[s], mfc="none" if s == "plain" else COLOR[s])
            axes[0, col].plot(xs, ys, **kw)
            axes[1, col].plot(xs, ls, **kw)
        axes[0, col].set_title(SCEN[sc])
        axes[1, col].set_xticks(range(len(profiles)))
        axes[1, col].set_xticklabels(profiles)
        axes[1, col].set_xlabel("Link profile")
    axes[0, 0].set_ylabel("Median RTT (ms)")
    axes[1, 0].set_ylabel("Probe loss (%)")
    axes[0, 0].legend(ncol=1, loc="upper left")
    fig.tight_layout(h_pad=0.5, w_pad=0.8)
    save(fig, "fig_sweep.pdf")


# 4. resident memory -------------------------------------------------------------------------
def fig_rss():
    sub = desc[(desc.scenario == "S1") & (desc.profile == "N1")]
    base = sub[sub.scheme == "plain"].iloc[0].uav_rss_kb_median
    sch = SCHEMES[1:]
    vals = [(sub[sub.scheme == s].iloc[0].uav_rss_kb_median - base) / 1024 for s in sch]
    fig, ax = plt.subplots(figsize=(COL, 2.1))
    bars = ax.bar([NICE[s] for s in sch], vals, color=[COLOR[s] for s in sch], width=0.6)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.05, f"{v:.2f}", ha="center", fontsize=6.5)
    ax.set_ylabel(r"$\Delta$RSS vs. plain (MiB)")
    ax.set_ylim(0, max(vals) * 1.15)
    save(fig, "fig_rss.pdf")


# 5. instructions per frame vs payload (QEMU, Cortex-A9) --------------------------------------
def fig_qemu():
    q = pd.read_csv(os.path.join(DATA, "qemu_sweep.csv"))
    q = q[q.op == "seal"]
    style = {("ascon", "own code"): ("ascon", "-", "Ascon"),
             ("aesgcm", "NEON"): ("aesgcm", "-", "AES-GCM (NEON)"),
             ("aesgcm", "no NEON"): ("aesgcm", "--", "AES-GCM (no NEON)"),
             ("chacha", "NEON"): ("chacha", "-", "ChaCha20 (NEON)"),
             ("chacha", "no NEON"): ("chacha", "--", "ChaCha20 (no NEON)")}
    fig, ax = plt.subplots(figsize=(COL, 2.5))
    for (alg, cfg), (key, ls, lab) in style.items():
        d = q[(q.alg == alg) & (q.config == cfg)].sort_values("payload")
        ax.plot(d.payload, d.insns_per_frame / 1000, ls, color=COLOR[key], marker=MARK[key],
                markersize=3, label=lab)
    ax.axvspan(0, 56, color="grey", alpha=0.12, lw=0)
    ax.text(28, 29.5, "95% of\nS1 frames", ha="center", va="top", fontsize=6)
    ax.set_xlabel("Payload length (bytes)")
    ax.set_ylabel("Instructions per seal (thousands)")
    ax.set_xlim(0, 260)
    ax.legend(loc="upper left", bbox_to_anchor=(0.20, 1.0))
    save(fig, "fig_qemu.pdf")


# 6. host time per operation ----------------------------------------------------------------
def fig_micro():
    m = pd.read_csv(os.path.join(DATA, "microbench_host.csv"))
    m = m[m.op == "seal"]
    rows = [("ascon", "scalar (no OpenSSL)", "Ascon", COLOR["ascon"], None),
            ("aesgcm", "scalar mask", "AES-GCM scalar", COLOR["aesgcm"], None),
            ("aesgcm", "accelerated", "AES-GCM AES-NI", COLOR["aesgcm"], "//"),
            ("chacha", "scalar mask", "ChaCha20 scalar", COLOR["chacha"], None),
            ("chacha", "accelerated", "ChaCha20 vector", COLOR["chacha"], "//")]
    fig, ax = plt.subplots(figsize=(COL, 2.3))
    w = 0.16
    for j, (alg, cfg, lab, c, h) in enumerate(rows):
        vals = [m[(m.alg == alg) & (m.config == cfg) & (m.payload == L)].median_ns.iloc[0] for L in (36, 255)]
        ax.bar(np.arange(2) + (j - 2) * w, vals, w, color=c, hatch=h, edgecolor="white" if h else c,
               linewidth=0.3, label=lab)
    ax.set_yscale("log")
    ax.set_xticks(range(2)); ax.set_xticklabels(["36 B payload", "255 B payload"])
    ax.set_ylabel("Host time per seal (ns)")
    ax.legend(ncol=1, loc="upper left")
    ax.set_ylim(80, 4500)
    save(fig, "fig_micro.pdf")


# 7. analytical relative overhead -------------------------------------------------------------
def fig_overhead():
    L = np.arange(0, 256)
    fig, ax = plt.subplots(figsize=(COL, 2.2))
    for lab, delta, key, ls in (("Ascon-AEAD128 (32 B)", 32, "ascon", "-"),
                                ("AES-GCM, ChaCha20 (28 B)", 28, "aesgcm", "-"),
                                ("DTLS 1.3 record (22 B)", 22, "dtls", "-"),
                                ("MAVLink 2 signing (13 B)", 13, "plain", "--")):
        ax.plot(L, 100 * delta / (12 + L), ls, color=COLOR[key], label=lab)
    ax.axvline(22, color="k", lw=0.5, ls=":")
    ax.text(25, 205, "mean S1 frame\n(34 B)", fontsize=6, va="top")
    ax.set_yscale("log")
    ax.set_xlabel("MAVLink 2 payload length $L$ (bytes)")
    ax.set_ylabel("Relative overhead (%)")
    ax.set_xlim(0, 255); ax.set_ylim(4, 300)
    ax.legend(loc="lower left")
    save(fig, "fig_overhead.pdf")


# 8. normalised synthesis -------------------------------------------------------------------
def fig_synthesis():
    sub = desc[(desc.scenario == "S1") & (desc.profile == "N1")].set_index("scheme")
    plain = sub.loc["plain"]
    metrics = [("Median RTT", "rtt_median_ms"), ("p95 RTT", "rtt_p95_ms"), ("UAV RSS", "uav_rss_kb_median"),
               ("CPU / frame", "uav_cpu_us_per_frame_median"), ("Bytes / frame", None)]
    fig, ax = plt.subplots(figsize=(PAGE, 2.1))
    sch = SCHEMES[1:]
    w = 0.19
    for j, s in enumerate(sch):
        vals = [sub.loc[s][c] / plain[c] for _, c in metrics if c]
        ov = sub.loc[s].down_dtls_overhead_B_median if s == "dtls" else sub.loc[s].down_overhead_B_median
        vals.append(1 + ov / plain.down_plain_B_median)
        ax.bar(np.arange(len(metrics)) + (j - 1.5) * w, vals, w, color=COLOR[s], label=NICE[s])
    ax.axhline(1.0, color="k", lw=0.6)
    ax.set_xticks(range(len(metrics))); ax.set_xticklabels([n for n, _ in metrics])
    ax.set_ylabel("Ratio to plain (S1, N1)")
    ax.set_ylim(0.9, 2.25)
    ax.legend(ncol=4, loc="upper left")
    save(fig, "fig_synthesis.pdf")


if __name__ == "__main__":
    for fn in (fig_latency, fig_box, fig_sweep, fig_rss, fig_qemu, fig_micro, fig_overhead, fig_synthesis):
        fn()
