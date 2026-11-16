#!/usr/bin/env python3
"""LaTeX tables and PDF figures of the Results chapter, generated from the CSV
files of analysis.py (and from the raw latency files for the box plot), so
that nothing in the chapter is typed by hand.

    python3 make_results.py ../data/sitl ../data/analysis --tables ../tables --figures ../figures \
            [--microbench ../data/microbench_host.csv]
"""
import argparse
import math
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analysis  # noqa: E402

ORDER = ["plain", "ascon", "aesgcm", "chacha", "dtls", "aesgcm-hw", "chacha-hw"]
LABEL = {"plain": "plain", "ascon": "ascon", "aesgcm": "aesgcm", "chacha": "chacha", "dtls": "dtls",
         "aesgcm-hw": "aesgcm-hw", "chacha-hw": "chacha-hw"}
COLOR = {"plain": "#7f7f7f", "ascon": "#1f77b4", "aesgcm": "#d62728", "chacha": "#2ca02c",
         "dtls": "#9467bd", "aesgcm-hw": "#ff9896", "chacha-hw": "#98df8a"}
SCEN_NAME = {"S1": "S1 (1 Hz)", "S2": "S2 (10 Hz)", "S3": "S3 (50 Hz)", "S4": "S4 (commands)"}


def f(x, nd=2):
    return "--" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.{nd}f}"


def ptxt(p):
    if p is None or (isinstance(p, float) and math.isnan(p)):
        return "--"
    return "$<$0.001" if p < 0.001 else f"{p:.3f}"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def schemes_present(df, sc, pr):
    s = set(df[(df.scenario == sc) & (df.profile == pr)].scheme)
    return [x for x in ORDER if x in s]


def comp_row(comp, sc, pr, a, b, metric):
    r = comp[(comp.scenario == sc) & (comp.profile == pr) & (comp.scheme == a)
             & (comp.versus == b) & (comp.metric == metric)]
    return r.iloc[0] if len(r) else None


def table_latency(desc, comp, pr="N1"):
    lines = [r"\begin{tabular}{@{}llcrrrrrcc@{}}", r"\toprule",
             r"Scenario & Scheme & Median [95\% CI] (ms) & IQR & p95 & p99 & Loss (\%) & "
             r"$\Delta\ell$ vs.\ plain [95\% CI] (ms) & $\hat A_{12}$ & $p_{\mathrm{Holm}}$ \\", r"\midrule"]
    for sc in ("S1", "S2", "S3", "S4"):
        sub = desc[(desc.scenario == sc) & (desc.profile == pr)]
        if sub.empty:
            continue
        first = True
        for s in [x for x in ORDER if x in set(sub.scheme)]:
            d = sub[sub.scheme == s].iloc[0]
            c = comp_row(comp, sc, pr, s, "plain", "rtt_median_ms") if s != "plain" else None
            delta = a12 = ph = "--"
            if c is not None:
                delta = f"{c.latency_overhead_pooled_ms:+.2f} [{c.latency_overhead_ci_lo:+.2f}, {c.latency_overhead_ci_hi:+.2f}]"
                a12 = f(c.A12)
                ph = ptxt(c.get("holm_p"))
            lines.append(f"{SCEN_NAME[sc] if first else ''} & {LABEL[s]} & {f(d.rtt_median_ms)} "
                         f"[{f(d.rtt_median_ci_lo)}, {f(d.rtt_median_ci_hi)}] & {f(d.rtt_iqr_ms)} & {f(d.rtt_p95_ms)} & "
                         f"{f(d.rtt_p99_ms)} & {f(d.loss_pct_mean)} & {delta} & {a12} & {ph} \\\\")
            first = False
        lines.append(r"\addlinespace")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def table_sweep(desc):
    profiles = [p for p in ("N0", "N1", "N2", "N3") if p in set(desc.profile)]
    cols = "@{}ll" + "rr" * len(profiles) + "@{}"
    hdr = " & ".join(rf"\multicolumn{{2}}{{c}}{{{p}}}" for p in profiles)
    sub = " & ".join("Median & Loss" for _ in profiles)
    lines = [rf"\begin{{tabular}}{{{cols}}}", r"\toprule", f"Scenario & Scheme & {hdr} \\\\",
             "& & " + sub + r" \\", r"\midrule"]
    for sc in ("S1", "S4"):
        first = True
        for s in [x for x in ORDER if x in set(desc[desc.scenario == sc].scheme)]:
            cells = []
            for p in profiles:
                r = desc[(desc.scenario == sc) & (desc.profile == p) & (desc.scheme == s)]
                cells.append(f"{f(r.iloc[0].rtt_median_ms)} & {f(r.iloc[0].loss_pct_mean)}" if len(r) else "-- & --")
            lines.append(f"{SCEN_NAME[sc] if first else ''} & {LABEL[s]} & " + " & ".join(cells) + r" \\")
            first = False
        lines.append(r"\addlinespace")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def table_sweep_delta(desc, comp):
    profiles = [p for p in ("N0", "N1", "N2", "N3") if p in set(desc.profile)]
    cols = "@{}ll" + "r" * len(profiles) + "@{}"
    lines = [rf"\begin{{tabular}}{{{cols}}}", r"\toprule",
             "Scenario & Scheme & " + " & ".join(f"{p}" for p in profiles) + r" \\", r"\midrule"]
    for sc in ("S1", "S4"):
        first = True
        for s in ["ascon", "aesgcm", "chacha", "dtls"]:
            cells = []
            for p in profiles:
                c = comp_row(comp, sc, p, s, "plain", "rtt_median_ms")
                cells.append("--" if c is None else f"{c.latency_overhead_pooled_ms:+.2f}")
            lines.append(f"{SCEN_NAME[sc] if first else ''} & {LABEL[s]} & " + " & ".join(cells) + r" \\")
            first = False
        lines.append(r"\addlinespace")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def table_ram_cpu(desc, comp, pr="N1"):
    lines = [r"\begin{tabular}{@{}llrrrrr@{}}", r"\toprule",
             r"Scenario & Scheme & UAV RSS (KiB) & $\Delta$RSS vs.\ plain & Peak RSS (KiB) & "
             r"CPU ($\mu$s/frame) & $\Delta$CPU vs.\ plain \\", r"\midrule"]
    for sc in ("S1", "S3"):
        sub = desc[(desc.scenario == sc) & (desc.profile == pr)]
        first = True
        for s in [x for x in ORDER if x in set(sub.scheme)]:
            d = sub[sub.scheme == s].iloc[0]
            cr = comp_row(comp, sc, pr, s, "plain", "uav_rss_kb") if s != "plain" else None
            cc = comp_row(comp, sc, pr, s, "plain", "uav_cpu_us_per_frame") if s != "plain" else None
            lines.append(f"{SCEN_NAME[sc] if first else ''} & {LABEL[s]} & {f(d.uav_rss_kb_median, 0)} & "
                         f"{'--' if cr is None else f'{cr.diff_of_medians:+.0f}'} & {f(d.uav_hwm_kb_median, 0)} & "
                         f"{f(d.uav_cpu_us_per_frame_median, 1)} & "
                         f"{'--' if cc is None else f'{cc.diff_of_medians:+.1f}'} \\\\")
            first = False
        lines.append(r"\addlinespace")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def table_throughput(desc, pr="N1"):
    lines = [r"\begin{tabular}{@{}l" + "r" * 4 + "@{}}", r"\toprule",
             "Scheme & " + " & ".join(SCEN_NAME[s] for s in ("S1", "S2", "S3", "S4")) + r" \\", r"\midrule"]
    for s in [x for x in ORDER if x in set(desc.scheme)]:
        vals = []
        for sc in ("S1", "S2", "S3", "S4"):
            r = desc[(desc.scenario == sc) & (desc.profile == pr) & (desc.scheme == s)]
            vals.append(f(r.iloc[0].thr_msgs_s_median, 1) if len(r) else "--")
        lines.append(f"{LABEL[s]} & " + " & ".join(vals) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def table_overhead(desc, pr="N1"):
    ana = {"plain": 0, "ascon": 32, "aesgcm": 28, "chacha": 28, "dtls": None}
    lines = [r"\begin{tabular}{@{}lrrr@{}}", r"\toprule",
             r"Scheme & Analytical (B) & Measured, downlink (B) & Measured, uplink (B) \\", r"\midrule"]
    sub = desc[(desc.scenario == "S1") & (desc.profile == pr)]
    for s in ["plain", "ascon", "aesgcm", "chacha", "dtls"]:
        r = sub[sub.scheme == s]
        if r.empty:
            continue
        r = r.iloc[0]
        if s == "dtls":
            down, up, a = r.get("down_dtls_overhead_B_median"), r.get("up_dtls_overhead_B_median"), "19--22"
        else:
            down, up, a = r.get("down_overhead_B_median"), None, str(ana[s])
            if s != "plain":
                # uplink frames are protected too; the proxy logs their overhead
                up = r.get("up_overhead_B_median")
        lines.append(f"{LABEL[s]} & {a} & {f(down)} & {f(up)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def table_hw(desc, comp, pr="N1"):
    lines = [r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
             r"Scheme & Median RTT (ms) & $\Delta$ vs.\ scalar (ms) [95\% CI] & CPU ($\mu$s/frame) & PC crypto, down (ns/frame) \\",
             r"\midrule"]
    sub = desc[(desc.scenario == "S1") & (desc.profile == pr)]
    for s in ["aesgcm", "aesgcm-hw", "chacha", "chacha-hw"]:
        r = sub[sub.scheme == s]
        if r.empty:
            continue
        r = r.iloc[0]
        delta = "--"
        if s.endswith("-hw"):
            c = comp_row(comp, "S1", pr, s, s[:-3], "rtt_median_ms")
            if c is not None:
                delta = f"{c.latency_overhead_pooled_ms:+.2f} [{c.latency_overhead_ci_lo:+.2f}, {c.latency_overhead_ci_hi:+.2f}]"
        lines.append(f"{LABEL[s]} & {f(r.rtt_median_ms)} & {delta} & {f(r.uav_cpu_us_per_frame_median, 1)} & "
                     f"{f(r.get('down_proxy_crypto_ns_median'), 0)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def table_synthesis(desc, pr="N1", sc="S1"):
    sub = desc[(desc.scenario == sc) & (desc.profile == pr)].set_index("scheme")
    base = sub.loc["plain"]
    clear = base.down_plain_B_median  # mean clear MAVLink frame of the S1 mix, from the proxy log
    ovh = {"plain": 0.0, "ascon": sub.loc["ascon"].down_overhead_B_median,
           "aesgcm": sub.loc["aesgcm"].down_overhead_B_median, "chacha": sub.loc["chacha"].down_overhead_B_median,
           "dtls": sub.loc["dtls"].down_dtls_overhead_B_median}
    lines = [r"\begin{tabular}{@{}lrrrrr@{}}", r"\toprule",
             r"Scheme & Median RTT & p95 RTT & UAV RSS & CPU/frame & Bytes/frame \\", r"\midrule"]
    for s in ["plain", "ascon", "aesgcm", "chacha", "dtls"]:
        if s not in sub.index:
            continue
        r = sub.loc[s]
        lines.append(f"{LABEL[s]} & {f(r.rtt_median_ms / base.rtt_median_ms, 3)} & {f(r.rtt_p95_ms / base.rtt_p95_ms, 3)} & "
                     f"{f(r.uav_rss_kb_median / base.uav_rss_kb_median, 3)} & "
                     f"{f(r.uav_cpu_us_per_frame_median / base.uav_cpu_us_per_frame_median, 3)} & "
                     f"{f((clear + ovh[s]) / clear, 3)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def table_kw(kw):
    lines = [r"\begin{tabular}{@{}llrr@{}}", r"\toprule", r"Scenario & Profile & $H$ & $p$ \\", r"\midrule"]
    for _, r in kw.iterrows():
        lines.append(f"{SCEN_NAME[r.scenario]} & {r.profile} & {f(r.H)} & {ptxt(r.kruskal_p)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def table_equivalence(eq, pr="N1", lang="en"):
    """TOST equivalence of the run-level median RTT against plain."""
    # last column: smallest margin for which the 90 % CI would lie inside +-margin,
    # so that a reader can apply a margin other than the declared one
    hdr = {"en": (r"Scenario & Scheme & Diff.\ (ms) & 90\% CI (ms) & TOST $p$ & Equiv. & Min.\ margin (ms)", "Yes", "No"),
           "es": (r"Escenario & Esquema & Dif.\ (ms) & IC 90\% (ms) & $p$ TOST & Equiv. & Margen mín.\ (ms)", "S\\'i", "No")}[lang]
    lines = [r"\begin{tabular}{@{}llccccc@{}}", r"\toprule", hdr[0] + r" \\", r"\midrule"]
    sub = eq[eq.profile == pr]
    for sc in ("S1", "S2", "S3", "S4"):
        for s in ORDER:
            r = sub[(sub.scenario == sc) & (sub.scheme == s)]
            if not len(r) or s.endswith("-hw"):
                continue
            r = r.iloc[0]
            lines.append(f"{SCEN_NAME[sc]} & {LABEL[s]} & {r.diff_of_means_ms:+.2f} & "
                         f"[{r.ci90_lo:+.2f}, {r.ci90_hi:+.2f}] & {ptxt(r.tost_p)} & "
                         f"{hdr[1] if bool(r.equivalent) else hdr[2]} & "
                         f"{max(abs(r.ci90_lo), abs(r.ci90_hi)):.2f} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def table_micro(path):
    m = pd.read_csv(path)
    lines = [r"\begin{tabular}{@{}llrrrr@{}}", r"\toprule",
             r"Scheme & Config. & Seal 36\,B (ns) & Open 36\,B (ns) & Seal 255\,B (ns) & Open 255\,B (ns) \\", r"\midrule"]
    for (alg, cfg), g in m.groupby(["alg", "config"], sort=False):
        v = {(r.payload, r.op): r.median_ns for r in g.itertuples()}
        lines.append(f"{alg} & {cfg} & {f(v.get((36, 'seal')), 0)} & {f(v.get((36, 'open')), 0)} & "
                     f"{f(v.get((255, 'seal')), 0)} & {f(v.get((255, 'open')), 0)} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ figures
def fig_latency(desc, out, pr="N1"):
    fig, axes = plt.subplots(1, 4, figsize=(11, 3.1), sharey=False)
    for ax, sc in zip(axes, ("S1", "S2", "S3", "S4")):
        sub = desc[(desc.scenario == sc) & (desc.profile == pr)]
        sch = [s for s in ORDER if s in set(sub.scheme) and not s.endswith("-hw")]
        for i, s in enumerate(sch):
            d = sub[sub.scheme == s].iloc[0]
            ax.errorbar(i, d.rtt_median_ms, yerr=[[d.rtt_median_ms - d.rtt_median_ci_lo],
                                                  [d.rtt_median_ci_hi - d.rtt_median_ms]],
                        fmt="o", color=COLOR[s], capsize=3)
        ax.set_xticks(range(len(sch)))
        ax.set_xticklabels(sch, rotation=45, ha="right", fontsize=8)
        ax.set_title(SCEN_NAME[sc], fontsize=9)
        ax.grid(axis="y", alpha=0.3)
    axes[0].set_ylabel("median RTT (ms), 95% CI")
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)


def fig_box(data_dir, runs, out, sc="S1", pr="N1"):
    import re
    groups = {}
    for (s, p, sch, run), files in runs.items():
        if s == sc and p == pr and {"latency"} <= set(files):
            lat = analysis.rows(os.path.join(data_dir, files["latency"]))
            t0 = float(lat[0]["t_send_ns"])
            v = [float(x["rtt_us"]) / 1000 for x in lat
                 if x["lost"] == "0" and (float(x["t_send_ns"]) - t0) / 1e9 >= analysis.W0]
            groups.setdefault(sch, []).extend(v)
    sch = [s for s in ORDER if s in groups]
    fig, ax = plt.subplots(figsize=(7.5, 3.4))
    bp = ax.boxplot([groups[s] for s in sch], tick_labels=sch, showfliers=False, whis=(1, 99), patch_artist=True)
    for patch, s in zip(bp["boxes"], sch):
        patch.set_facecolor(COLOR[s]); patch.set_alpha(0.6)
    ax.set_ylabel("RTT (ms)")
    ax.set_title(f"{SCEN_NAME[sc]}, profile {pr}: pooled probes after warm-up (whiskers: p1-p99)", fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)


def fig_sweep(desc, out):
    profiles = [p for p in ("N0", "N1", "N2", "N3") if p in set(desc.profile)]
    fig, axes = plt.subplots(2, 2, figsize=(8, 5), sharex=True)
    for col, sc in enumerate(("S1", "S4")):
        for s in ["plain", "ascon", "aesgcm", "chacha", "dtls"]:
            ys, ls, xs = [], [], []
            for i, p in enumerate(profiles):
                r = desc[(desc.scenario == sc) & (desc.profile == p) & (desc.scheme == s)]
                if len(r):
                    xs.append(i); ys.append(r.iloc[0].rtt_median_ms); ls.append(r.iloc[0].loss_pct_mean)
            axes[0, col].plot(xs, ys, "o-", color=COLOR[s], label=s)
            axes[1, col].plot(xs, ls, "o-", color=COLOR[s])
        axes[0, col].set_title(SCEN_NAME[sc], fontsize=9)
        axes[1, col].set_xticks(range(len(profiles))); axes[1, col].set_xticklabels(profiles)
        axes[0, col].grid(alpha=0.3); axes[1, col].grid(alpha=0.3)
    axes[0, 0].set_ylabel("median RTT (ms)"); axes[1, 0].set_ylabel("probe loss (%)")
    axes[0, 0].legend(fontsize=7)
    fig.tight_layout(); fig.savefig(out, bbox_inches="tight"); plt.close(fig)


def fig_rss(desc, out, pr="N1", sc="S1"):
    sub = desc[(desc.scenario == sc) & (desc.profile == pr)]
    sch = [s for s in ORDER if s in set(sub.scheme)]
    base = sub[sub.scheme == "plain"].iloc[0].uav_rss_kb_median
    fig, ax = plt.subplots(figsize=(6.5, 3.2))
    vals = [(sub[sub.scheme == s].iloc[0].uav_rss_kb_median - base) / 1024 for s in sch]
    ax.bar(sch, vals, color=[COLOR[s] for s in sch])
    ax.set_ylabel(r"$\Delta$RSS vs. plain (MiB)")
    ax.set_title(f"UAV-side resident memory, {SCEN_NAME[sc]}, {pr} (dtls: firmware + tunnel)", fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right", fontsize=8)
    fig.tight_layout(); fig.savefig(out, bbox_inches="tight"); plt.close(fig)


def _sc(sc, lang):
    return SCEN_NAME[sc].replace("commands", "comandos") if lang == "es" else SCEN_NAME[sc]


def fig_equivalence(eq, out, pr="N1", scenarios=("S1", "S2", "S4"), lang="en"):
    """Forest plot: 90% CI of (scheme - plain) in run-level median RTT against the +-margin band."""
    sub = eq[eq.profile == pr]
    margin = float(sub.margin_ms.iloc[0])
    sch = [s for s in ORDER if s not in ("plain",) and not s.endswith("-hw")]
    fig, axes = plt.subplots(1, len(scenarios), figsize=(9.5, 2.9), sharey=True, sharex=True)
    for ax, sc in zip(axes, scenarios):
        ax.axvspan(-margin, margin, color="0.85", zorder=0)
        ax.axvline(0, color="0.4", lw=0.8)
        for i, s in enumerate(sch):
            r = sub[(sub.scenario == sc) & (sub.scheme == s)]
            if not len(r):
                continue
            r = r.iloc[0]
            ok = bool(r.equivalent)
            ax.errorbar(r.diff_of_means_ms, i, xerr=[[r.diff_of_means_ms - r.ci90_lo], [r.ci90_hi - r.diff_of_means_ms]],
                        fmt="o" if ok else "s", color=COLOR[s], mfc=COLOR[s] if ok else "white", capsize=3)
        ax.set_yticks(range(len(sch))); ax.set_yticklabels(sch, fontsize=8)
        ax.set_title(_sc(sc, lang), fontsize=9)
        ax.set_xlabel("diferencia vs. plain (ms)" if lang == "es" else "difference vs. plain (ms)", fontsize=8)
        ax.grid(axis="x", alpha=0.3)
    ax.set_xlim(-0.35, 0.45)
    if lang == "es":
        ttl = (f"IC 90% de la diferencia en el RTT mediano por ejecución; banda gris = margen de equivalencia $\\pm${margin:g} ms "
               "(lleno = equivalente, vacío = no demostrado)")
    else:
        ttl = (f"90% CI of the difference in run-level median RTT; grey band = equivalence margin $\\pm${margin:g} ms "
               "(filled = equivalent, open = not shown)")
    fig.suptitle(ttl, fontsize=8, y=1.02)
    fig.tight_layout(); fig.savefig(out, bbox_inches="tight"); plt.close(fig)


def fig_runs(runlevel, out, sc="S1", pr="N1", lang="en"):
    """Run-level median RTT of each run, exploratory (runs 1-5) vs confirmatory (runs 6-10)."""
    sub = runlevel[(runlevel.scenario == sc) & (runlevel.profile == pr)].copy()
    sub["run"] = sub["run"].astype(int)
    sch = [s for s in ORDER if s in set(sub.scheme) and not s.endswith("-hw")]
    fig, ax = plt.subplots(figsize=(6.5, 3.2))
    for i, s in enumerate(sch):
        g = sub[sub.scheme == s]
        for ph, mk, fc in ((g[g.run <= 5], "o", "none"), (g[g.run > 5], "o", COLOR[s])):
            ax.scatter(np.full(len(ph), i) + np.linspace(-0.12, 0.12, max(len(ph), 1))[:len(ph)],
                       ph.rtt_median_ms, marker=mk, facecolors=fc, edgecolors=COLOR[s], s=28)
    ax.set_xticks(range(len(sch))); ax.set_xticklabels(sch, fontsize=8)
    if lang == "es":
        ax.set_ylabel("RTT mediano por ejecución (ms)")
        ax.set_title(f"{_sc(sc, lang)}, {pr}: un punto por ejecución (vacío = ejecuciones 1-5, lleno = 6-10)", fontsize=9)
    else:
        ax.set_ylabel("run-level median RTT (ms)")
        ax.set_title(f"{SCEN_NAME[sc]}, {pr}: one point per run (open = runs 1-5, filled = runs 6-10)", fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(out, bbox_inches="tight"); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data_dir"); ap.add_argument("analysis_dir")
    ap.add_argument("--tables", required=True); ap.add_argument("--figures", required=True)
    ap.add_argument("--microbench")
    ap.add_argument("--tables-es", dest="tables_es", help="directory for the Spanish copy of the equivalence table")
    ap.add_argument("--figures-es", dest="figures_es", help="directory for the Spanish copy of the equivalence figures")
    a = ap.parse_args()
    desc = pd.read_csv(os.path.join(a.analysis_dir, "descriptive.csv"))
    comp = pd.read_csv(os.path.join(a.analysis_dir, "comparisons.csv"))
    kw = pd.read_csv(os.path.join(a.analysis_dir, "kruskal_dunn.csv"))
    T = lambda n, s: write(os.path.join(a.tables, n), s)
    T("tab_latency_n1.tex", table_latency(desc, comp))
    T("tab_sweep.tex", table_sweep(desc))
    T("tab_sweep_delta.tex", table_sweep_delta(desc, comp))
    T("tab_ram_cpu.tex", table_ram_cpu(desc, comp))
    T("tab_throughput.tex", table_throughput(desc))
    T("tab_overhead_measured.tex", table_overhead(desc))
    T("tab_hw.tex", table_hw(desc, comp))
    T("tab_synthesis.tex", table_synthesis(desc))
    T("tab_kruskal.tex", table_kw(kw))
    eqp = os.path.join(a.analysis_dir, "equivalence.csv")
    if os.path.exists(eqp):
        eq = pd.read_csv(eqp)
        T("tab_equivalence.tex", table_equivalence(eq, lang="en"))
        if a.tables_es:
            write(os.path.join(a.tables_es, "tab_equivalence.tex"), table_equivalence(eq, lang="es"))
    if a.microbench and os.path.exists(a.microbench):
        T("tab_microbench.tex", table_micro(a.microbench))
    os.makedirs(a.figures, exist_ok=True)
    fig_latency(desc, os.path.join(a.figures, "fig_latency_n1.pdf"))
    fig_sweep(desc, os.path.join(a.figures, "fig_sweep.pdf"))
    fig_rss(desc, os.path.join(a.figures, "fig_rss.pdf"))
    inv = {}
    import re
    for name in sorted(os.listdir(a.data_dir)):
        m = analysis.NAME.match(name)
        if m:
            sc, pr, sch, run, metric, _ = m.groups()
            inv.setdefault((sc, pr, sch, run), {})[metric] = name
    fig_box(a.data_dir, inv, os.path.join(a.figures, "fig_box_s1.pdf"))
    if os.path.exists(eqp):
        fig_equivalence(eq, os.path.join(a.figures, "fig_equivalence.pdf"))
        if a.figures_es:
            os.makedirs(a.figures_es, exist_ok=True)
            fig_equivalence(eq, os.path.join(a.figures_es, "fig_equivalence.pdf"), lang="es")
    rlp = os.path.join(a.analysis_dir, "run_level.csv")
    if os.path.exists(rlp):
        rl = pd.read_csv(rlp, dtype={"run": str})
        fig_runs(rl, os.path.join(a.figures, "fig_runs_s1.pdf"))
        if a.figures_es:
            fig_runs(rl, os.path.join(a.figures_es, "fig_runs_s1.pdf"), lang="es")
    print("tables:", sorted(os.listdir(a.tables)))
    print("figures:", sorted(os.listdir(a.figures)))


if __name__ == "__main__":
    main()
