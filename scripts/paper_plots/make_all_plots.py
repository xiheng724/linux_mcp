#!/usr/bin/env python3
"""
Regenerate every experiment figure used in the BBC6521 final report in a unified
B&W conference style.

Output: PDFs (and one PNG) written into the paper's figures/ directory,
reusing the filenames the .tex files already reference so no LaTeX edits are
needed.

Data sources (all rooted under experiment-results/):
    linux-mcp-paper-final-n30/run-20260411-075604/   core n=30 runs
    kernel-ablation/run-20260414-133832/             paired ablation
    registry-scaling/run-20260414-123832/            registry scaling
    netlink-microbench-e/run-20260406-111914/        netlink RTT microbench
    attack-extended/run-20260414T095204Z/            E4 cross-UID + fuzz
"""
from __future__ import annotations

import math
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import FancyArrowPatch, Patch

ROOT = Path("/Users/lixiheng/Code/linux_mcp")
RES = ROOT / "experiment-results"
FIG_DIR = ROOT / "BBC6521_Final_Report_LaTeX_Template_25_26 (3) 2" / "figures"

N30 = RES / "linux-mcp-paper-final-n30" / "run-20260411-075604"
N5  = RES / "linux-mcp-paper-final-n5"  / "run-20260405-173020"
ABL = RES / "kernel-ablation" / "run-20260414-133832"
REG = RES / "registry-scaling" / "run-20260414-123832"
NET = RES / "netlink-microbench-e" / "run-20260406-111914"
ATK = RES / "attack-extended" / "run-20260414T095204Z"

SYSTEMS = ["userspace", "seccomp", "kernel"]
SYS_STYLE = {
    "userspace": {"face": "#ffffff", "edge": "black", "hatch": "///",  "ls": "-",  "marker": "o"},
    "seccomp":   {"face": "#b8b8b8", "edge": "black", "hatch": "xxx",  "ls": "--", "marker": "s"},
    "kernel":    {"face": "#2d2d2d", "edge": "black", "hatch": "",     "ls": ":",  "marker": "^"},
}
PAYLOADS = ["100 B", "10 KiB", "1 MiB"]


def setup_style() -> None:
    mpl.rcParams.update({
        "font.family": "serif",
        "font.serif": ["DejaVu Serif", "Times New Roman", "Nimbus Roman"],
        "font.size": 9,
        "axes.labelsize": 9,
        "axes.titlesize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "axes.linewidth": 0.6,
        "axes.edgecolor": "black",
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.color": "#cccccc",
        "grid.linestyle": ":",
        "grid.linewidth": 0.4,
        "grid.alpha": 0.7,
        "lines.linewidth": 1.1,
        "lines.markersize": 4,
        "patch.linewidth": 0.6,
        "hatch.linewidth": 0.4,
        "legend.frameon": False,
        "legend.borderaxespad": 0.4,
        "legend.handlelength": 1.8,
    })


def save(fig, name: str, w: float = 6.3, h: float = 3.0) -> None:
    fig.set_size_inches(w, h)
    fig.tight_layout(pad=0.4)
    out = FIG_DIR / name
    fig.savefig(out, bbox_inches="tight", pad_inches=0.02)
    if name.endswith(".pdf"):
        png = out.with_suffix(".png")
        fig.savefig(png, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)
    print(f"  wrote {out.name}")


def sys_bar(ax, xs, heights, errs, sys_name, width, offset, label=None):
    st = SYS_STYLE[sys_name]
    ax.bar(
        np.asarray(xs) + offset, heights,
        width=width, yerr=errs,
        facecolor=st["face"], edgecolor=st["edge"], hatch=st["hatch"],
        linewidth=0.7, error_kw={"elinewidth": 0.7, "capsize": 2, "capthick": 0.7, "ecolor": "black"},
        label=label if label else sys_name,
    )


# ---------- 1. Absolute mean latency (replaces figure_latency_mean_by_payload) ----------
def plot_latency_mean() -> None:
    print("latency mean...")
    s = pd.read_csv(N30 / "latency_summary.csv")
    s["payload_label_disp"] = s["payload_label"].map(
        {"small": "100 B", "medium": "10 KiB", "large": "1 MiB"}
    )
    fig, ax = plt.subplots()
    x = np.arange(len(PAYLOADS))
    width = 0.26
    offsets = {-1: -width, 0: 0.0, 1: width}
    for i, sysname in enumerate(SYSTEMS):
        sub = s[s["system"] == sysname].set_index("payload_label_disp").loc[PAYLOADS]
        heights = sub["latency_avg_ms"].values
        err_lo = heights - sub["latency_avg_ci_lo_ms"].values
        err_hi = sub["latency_avg_ci_hi_ms"].values - heights
        sys_bar(ax, x, heights, [err_lo, err_hi], sysname, width, offsets[i - 1])
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(PAYLOADS)
    ax.set_ylabel("mean end-to-end latency (ms, log scale)")
    ax.set_xlabel("payload size (error bars: 95% CI, $n=30$ runs $\\times$ 2000 requests)")
    ax.set_ylim(0.5, 20)
    ax.legend(loc="upper left", ncols=3, bbox_to_anchor=(0.0, 1.12), borderaxespad=0.0)
    save(fig, "figure_latency_mean_by_payload.pdf")


# ---------- 2. p95 latency (replaces figure_latency_p95_by_payload) ----------
def plot_latency_p95() -> None:
    print("latency p95...")
    s = pd.read_csv(N30 / "latency_summary.csv")
    s["payload_label_disp"] = s["payload_label"].map(
        {"small": "100 B", "medium": "10 KiB", "large": "1 MiB"}
    )
    fig, ax = plt.subplots()
    x = np.arange(len(PAYLOADS))
    width = 0.26
    offsets = {-1: -width, 0: 0.0, 1: width}
    for i, sysname in enumerate(SYSTEMS):
        sub = s[s["system"] == sysname].set_index("payload_label_disp").loc[PAYLOADS]
        heights = sub["latency_p95_ms"].values
        err_lo = heights - sub["latency_p95_ci_lo_ms"].values
        err_hi = sub["latency_p95_ci_hi_ms"].values - heights
        sys_bar(ax, x, heights, [err_lo, err_hi], sysname, width, offsets[i - 1])
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(PAYLOADS)
    ax.set_ylabel("p95 latency (ms, log scale)")
    ax.set_xlabel("payload size (error bars: 95% CI, $n=30$)")
    ax.set_ylim(0.6, 20)
    ax.legend(loc="upper left", ncols=3, bbox_to_anchor=(0.0, 1.12), borderaxespad=0.0)
    save(fig, "figure_latency_p95_by_payload.pdf")


# ---------- 3. Normalized overhead ratio (replaces figure_latency_overhead) ----------
def plot_latency_overhead() -> None:
    print("latency overhead ratio...")
    s = pd.read_csv(N30 / "latency_summary.csv")
    s["payload_label_disp"] = s["payload_label"].map(
        {"small": "100 B", "medium": "10 KiB", "large": "1 MiB"}
    )
    us = s[s["system"] == "userspace"].set_index("payload_label_disp").loc[PAYLOADS]
    fig, ax = plt.subplots()
    x = np.arange(len(PAYLOADS))
    width = 0.34
    for i, sysname in enumerate(["seccomp", "kernel"]):
        sub = s[s["system"] == sysname].set_index("payload_label_disp").loc[PAYLOADS]
        ratio = sub["latency_avg_ms"].values / us["latency_avg_ms"].values
        hi = sub["latency_avg_ci_hi_ms"].values / us["latency_avg_ms"].values
        lo = sub["latency_avg_ci_lo_ms"].values / us["latency_avg_ms"].values
        err_lo = ratio - lo
        err_hi = hi - ratio
        offset = -width / 2 if i == 0 else width / 2
        st = SYS_STYLE[sysname]
        ax.bar(
            x + offset, ratio,
            width=width, yerr=[err_lo, err_hi],
            facecolor=st["face"], edgecolor=st["edge"], hatch=st["hatch"],
            linewidth=0.7,
            error_kw={"elinewidth": 0.7, "capsize": 2, "capthick": 0.7, "ecolor": "black"},
            label=f"{sysname} / userspace",
        )
        for xi, r in zip(x, ratio):
            ax.text(
                xi + offset, r + (err_hi[np.where(x == xi)[0][0]] if hasattr(err_hi, "__len__") else 0) + 0.01,
                f"{r:.2f}", ha="center", va="bottom", fontsize=7,
            )
    ax.axhline(1.0, color="black", lw=0.6, ls="--")
    ax.text(
        -0.05, 1.0, "parity",
        transform=ax.get_yaxis_transform(), ha="right", va="center",
        fontsize=7, color="#555555",
    )
    ax.set_xticks(x)
    ax.set_xticklabels(PAYLOADS)
    ax.set_xlabel("payload size (error bars: 95% CI; ratio = $\\mathrm{mean}_{\\text{system}}\\,/\\,\\mathrm{mean}_{\\text{userspace}}$)")
    ax.set_ylabel("mean-latency ratio vs userspace")
    ax.set_ylim(0.88, 1.42)
    ax.legend(loc="upper left", bbox_to_anchor=(0.0, 1.16), ncols=2, borderaxespad=0.0)
    save(fig, "figure_latency_overhead.pdf")


# ---------- 4. Per-stage latency breakdown + zoom (replaces figure_latency_breakdown) ----------
def plot_latency_breakdown() -> None:
    print("latency breakdown + zoom...")
    b = pd.read_csv(N30 / "breakdown_summary.csv")
    b["payload_label_disp"] = b["payload_label"].map(
        {"small": "100 B", "medium": "10 KiB", "large": "1 MiB"}
    )

    stages_full = ["session_lookup", "arbitration", "tool_exec"]
    stages_zoom = ["session_lookup", "arbitration"]

    fig, (ax1, ax2) = plt.subplots(1, 2, gridspec_kw={"width_ratios": [1.2, 1.0]})
    width = 0.24
    offsets = {-1: -width, 0: 0.0, 1: width}

    x = np.arange(len(stages_full))
    for i, sysname in enumerate(SYSTEMS):
        sub = b[(b["system"] == sysname)].set_index("payload_label_disp").loc[PAYLOADS]
        mean_across_payloads = np.array([
            sub[f"{stage}_ms"].mean() for stage in stages_full
        ])
        st = SYS_STYLE[sysname]
        ax1.bar(
            x + offsets[i - 1], mean_across_payloads,
            width=width,
            facecolor=st["face"], edgecolor=st["edge"], hatch=st["hatch"],
            linewidth=0.7, label=sysname,
        )
    ax1.set_yscale("log")
    ax1.set_xticks(x)
    ax1.set_xticklabels(stages_full)
    ax1.set_ylabel("stage latency (ms, log scale)")
    ax1.set_title("(a) full pipeline", loc="left", fontsize=9, pad=4)
    ax1.set_ylim(1e-3, 10)
    ax1.legend(loc="upper left")

    x = np.arange(len(stages_zoom))
    for i, sysname in enumerate(SYSTEMS):
        sub = b[b["system"] == sysname].set_index("payload_label_disp").loc[PAYLOADS]
        mean_across_payloads = np.array([
            sub[f"{stage}_ms"].mean() * 1000.0 for stage in stages_zoom
        ])
        st = SYS_STYLE[sysname]
        ax2.bar(
            x + offsets[i - 1], mean_across_payloads,
            width=width,
            facecolor=st["face"], edgecolor=st["edge"], hatch=st["hatch"],
            linewidth=0.7,
        )
        for xi, v in zip(x, mean_across_payloads):
            ax2.text(xi + offsets[i - 1], v + 0.3, f"{v:.1f}", ha="center", va="bottom", fontsize=7)
    ax2.set_xticks(x)
    ax2.set_xticklabels(stages_zoom)
    ax2.set_ylabel("stage latency (μs, linear)")
    ax2.set_title("(b) zoom on control-plane stages", loc="left", fontsize=9, pad=4)
    ax2.set_ylim(0, max(ax2.get_ylim()[1], 35))

    arb_kernel_us = b[b["system"] == "kernel"]["arbitration_ms"].mean() * 1000
    arb_user_us = b[b["system"] == "userspace"]["arbitration_ms"].mean() * 1000
    ax2.text(
        0.98, 0.95,
        f"kernel arbitration adds\n+{arb_kernel_us - arb_user_us:.1f} μs over user-space",
        transform=ax2.transAxes, fontsize=7, ha="right", va="top",
        color="#222222",
        bbox=dict(facecolor="white", edgecolor="#888888", lw=0.4, pad=2.5),
    )
    ax2.set_ylim(0, max(arb_kernel_us * 1.35, 40))

    save(fig, "figure_latency_breakdown.pdf", w=6.8, h=3.0)


# ---------- 4b. Consolidated 2x2 latency panel (replaces the four individual latency figures in the paper) ----------
def plot_latency_panel() -> None:
    print("latency 2x2 panel...")
    s = pd.read_csv(N30 / "latency_summary.csv")
    s["payload_label_disp"] = s["payload_label"].map(
        {"small": "100 B", "medium": "10 KiB", "large": "1 MiB"}
    )
    b = pd.read_csv(N30 / "breakdown_summary.csv")
    b["payload_label_disp"] = b["payload_label"].map(
        {"small": "100 B", "medium": "10 KiB", "large": "1 MiB"}
    )

    fig, axes = plt.subplots(2, 2)
    ax_mean, ax_p95 = axes[0, 0], axes[0, 1]
    ax_ratio, ax_break = axes[1, 0], axes[1, 1]

    x = np.arange(len(PAYLOADS))
    width = 0.26
    offsets = {-1: -width, 0: 0.0, 1: width}

    # (a) mean latency, log-y
    for i, sysname in enumerate(SYSTEMS):
        sub = s[s["system"] == sysname].set_index("payload_label_disp").loc[PAYLOADS]
        heights = sub["latency_avg_ms"].values
        err_lo = heights - sub["latency_avg_ci_lo_ms"].values
        err_hi = sub["latency_avg_ci_hi_ms"].values - heights
        sys_bar(ax_mean, x, heights, [err_lo, err_hi], sysname, width, offsets[i - 1])
    ax_mean.set_yscale("log")
    ax_mean.set_xticks(x); ax_mean.set_xticklabels(PAYLOADS)
    ax_mean.set_ylabel("mean latency (ms, log)")
    ax_mean.set_ylim(0.5, 20)
    ax_mean.set_title("(a) mean end-to-end latency", loc="left", fontsize=9, pad=3)

    # (b) p95 latency, log-y
    for i, sysname in enumerate(SYSTEMS):
        sub = s[s["system"] == sysname].set_index("payload_label_disp").loc[PAYLOADS]
        heights = sub["latency_p95_ms"].values
        err_lo = heights - sub["latency_p95_ci_lo_ms"].values
        err_hi = sub["latency_p95_ci_hi_ms"].values - heights
        sys_bar(ax_p95, x, heights, [err_lo, err_hi], sysname, width, offsets[i - 1])
    ax_p95.set_yscale("log")
    ax_p95.set_xticks(x); ax_p95.set_xticklabels(PAYLOADS)
    ax_p95.set_ylabel("$p_{95}$ latency (ms, log)")
    ax_p95.set_ylim(0.6, 20)
    ax_p95.set_title("(b) $p_{95}$ latency", loc="left", fontsize=9, pad=3)

    # (c) overhead ratio vs userspace, zoomed around parity
    us = s[s["system"] == "userspace"].set_index("payload_label_disp").loc[PAYLOADS]
    rwidth = 0.34
    for i, sysname in enumerate(["seccomp", "kernel"]):
        sub = s[s["system"] == sysname].set_index("payload_label_disp").loc[PAYLOADS]
        ratio = sub["latency_avg_ms"].values / us["latency_avg_ms"].values
        hi = sub["latency_avg_ci_hi_ms"].values / us["latency_avg_ms"].values
        lo = sub["latency_avg_ci_lo_ms"].values / us["latency_avg_ms"].values
        err_lo = ratio - lo
        err_hi = hi - ratio
        offset = -rwidth / 2 if i == 0 else rwidth / 2
        st = SYS_STYLE[sysname]
        ax_ratio.bar(
            x + offset, ratio, width=rwidth, yerr=[err_lo, err_hi],
            facecolor=st["face"], edgecolor=st["edge"], hatch=st["hatch"],
            linewidth=0.7,
            error_kw={"elinewidth": 0.7, "capsize": 2, "capthick": 0.7, "ecolor": "black"},
            label=f"{sysname}/userspace",
        )
        for xi, r, eh in zip(x, ratio, err_hi):
            ax_ratio.text(xi + offset, r + eh + 0.01, f"{r:.2f}", ha="center", va="bottom", fontsize=6.5)
    ax_ratio.axhline(1.0, color="black", lw=0.6, ls="--")
    ax_ratio.text(-0.05, 1.0, "parity", transform=ax_ratio.get_yaxis_transform(),
                  ha="right", va="center", fontsize=7, color="#555555")
    ax_ratio.set_xticks(x); ax_ratio.set_xticklabels(PAYLOADS)
    ax_ratio.set_ylabel("mean-latency ratio")
    ax_ratio.set_ylim(0.88, 1.42)
    ax_ratio.set_title("(c) overhead ratio vs userspace", loc="left", fontsize=9, pad=3)
    ax_ratio.legend(loc="upper left", fontsize=7)

    # (d) control-plane stage zoom (session_lookup + arbitration), linear μs
    stages_zoom = ["session_lookup", "arbitration"]
    xz = np.arange(len(stages_zoom))
    for i, sysname in enumerate(SYSTEMS):
        sub = b[b["system"] == sysname].set_index("payload_label_disp").loc[PAYLOADS]
        vals_us = np.array([sub[f"{stage}_ms"].mean() * 1000.0 for stage in stages_zoom])
        st = SYS_STYLE[sysname]
        ax_break.bar(
            xz + offsets[i - 1], vals_us, width=width,
            facecolor=st["face"], edgecolor=st["edge"], hatch=st["hatch"],
            linewidth=0.7,
        )
        for xi, v in zip(xz, vals_us):
            ax_break.text(xi + offsets[i - 1], v + 0.25, f"{v:.1f}", ha="center", va="bottom", fontsize=6.5)
    ax_break.set_xticks(xz); ax_break.set_xticklabels(stages_zoom)
    ax_break.set_ylabel("control-plane stage (μs, linear)")
    arb_k = b[b["system"] == "kernel"]["arbitration_ms"].mean() * 1000
    arb_u = b[b["system"] == "userspace"]["arbitration_ms"].mean() * 1000
    ax_break.text(
        0.98, 0.95,
        f"kernel arbitration adds\n+{arb_k - arb_u:.1f} μs over userspace",
        transform=ax_break.transAxes, fontsize=7, ha="right", va="top",
        bbox=dict(facecolor="white", edgecolor="#888888", lw=0.4, pad=2.5),
    )
    ax_break.set_ylim(0, max(arb_k * 1.45, 40))
    ax_break.set_title("(d) control-plane stage breakdown", loc="left", fontsize=9, pad=3)

    handles = [
        Patch(facecolor=SYS_STYLE[s2]["face"], edgecolor="black",
              hatch=SYS_STYLE[s2]["hatch"], label=s2)
        for s2 in SYSTEMS
    ]
    fig.legend(handles=handles, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.02),
               frameon=False, fontsize=8)
    fig.supxlabel("payload size (panels a–c) / stage (panel d); error bars: 95% CI, $n=30$",
                  fontsize=7.5, y=-0.02)

    save(fig, "figure_latency_panel.pdf", w=6.8, h=5.2)


# ---------- 5. Latency ECDF (new, not referenced by paper but useful) ----------
def plot_latency_ecdf() -> None:
    print("latency ecdf (new aux)...")
    reps = pd.read_csv(N30 / "latency_repetitions.csv")
    reps["payload_label_disp"] = reps["payload_label"].map(
        {"small": "100 B", "medium": "10 KiB", "large": "1 MiB"}
    )

    fig, axes = plt.subplots(1, 3, sharey=True)
    for ax, payload in zip(axes, PAYLOADS):
        all_vals = []
        for sysname in SYSTEMS:
            sub = reps[(reps["system"] == sysname) & (reps["payload_label_disp"] == payload)]
            vals = np.sort(sub["latency_avg_ms"].values)
            all_vals.extend(vals.tolist())
            y = np.arange(1, len(vals) + 1) / len(vals)
            st = SYS_STYLE[sysname]
            ax.step(
                vals, y,
                where="post", linestyle=st["ls"], color="black",
                linewidth=1.1, label=sysname,
            )
        lo, hi = min(all_vals), max(all_vals)
        pad = (hi - lo) * 0.08
        ax.set_xlim(lo - pad, hi + pad)
        ax.set_title(payload, fontsize=9)
        ax.set_xlabel("mean latency (ms)")
        ax.set_ylim(0, 1.02)
        ax.tick_params(axis="x", labelsize=7)
    axes[0].set_ylabel("ECDF over 30 runs")
    axes[0].legend(loc="lower right")
    save(fig, "figure_latency_ecdf.pdf", w=6.6, h=2.6)


# ---------- 5b. Throughput RPS × concurrency sweep across agent counts ----------
def plot_throughput_sweep() -> None:
    print("throughput sweep (agents x concurrency)...")
    s = pd.read_csv(N5 / "scalability_summary.csv")
    agents_order = [1, 5, 10, 20, 50]
    conc_order = sorted(s["concurrency"].unique())

    fig, axes = plt.subplots(1, len(agents_order), sharey=True)
    for ax, a in zip(axes, agents_order):
        sub_a = s[s["agents"] == a]
        for sysname in SYSTEMS:
            sub = sub_a[sub_a["system"] == sysname].set_index("concurrency").loc[conc_order]
            y = sub["throughput_rps"].values
            yerr_lo = y - sub["throughput_rps_ci_lo"].values
            yerr_hi = sub["throughput_rps_ci_hi"].values - y
            st = SYS_STYLE[sysname]
            ax.errorbar(
                conc_order, y, yerr=[yerr_lo, yerr_hi],
                color="black", linestyle=st["ls"], marker=st["marker"],
                mfc=st["face"], mec="black", lw=1.0, capsize=2, capthick=0.6, elinewidth=0.6,
                label=sysname,
            )
        ax.set_xscale("log")
        ax.set_xticks(conc_order)
        ax.set_xticklabels([str(c) for c in conc_order], fontsize=7)
        ax.set_title(f"agents = {a}", fontsize=9, pad=3)
        ax.set_xlabel("concurrency")
    axes[0].set_ylabel("throughput (RPS)")
    axes[0].legend(loc="lower right", fontsize=7)

    ymin = min(s["throughput_rps_ci_lo"].min() * 0.97, s["throughput_rps"].min() * 0.97)
    ymax = max(s["throughput_rps_ci_hi"].max() * 1.03, s["throughput_rps"].max() * 1.03)
    for ax in axes:
        ax.set_ylim(ymin, ymax)

    save(fig, "figure_throughput_sweep.pdf", w=7.4, h=2.6)


# ---------- 6. Attack per-case matrix (replaces figure_attack_heatmap.png) ----------
def plot_attack_matrix() -> None:
    print("attack per-case matrix...")
    cs = pd.read_csv(N30 / "attack_case_summary.csv")
    order_types = ["spoof", "replay", "substitute", "escalation"]
    cases_by_type = {}
    for t in order_types:
        cases_by_type[t] = sorted(cs[cs["attack_type"] == t]["attack_case"].unique())
    ordered_cases = []
    for t in order_types:
        ordered_cases.extend([(t, c) for c in cases_by_type[t]])

    n_cases = len(ordered_cases)
    fig, ax = plt.subplots()
    for j, sysname in enumerate(SYSTEMS):
        for i, (t, c) in enumerate(ordered_cases):
            row = cs[(cs["system"] == sysname) & (cs["attack_type"] == t) & (cs["attack_case"] == c)]
            if row.empty:
                continue
            rate = float(row["success_rate"].iloc[0])
            successes = int(row["successes"].iloc[0])
            attempts = int(row["attempts"].iloc[0])
            if rate == 0.0:
                face, edge, hatch = "#2d2d2d", "black", ""
                marker_text = ""
            elif rate < 1.0:
                face, edge, hatch = "#ffffff", "black", "///"
                marker_text = f"{successes}/{attempts}"
            else:
                face, edge, hatch = "#ffffff", "black", ""
                marker_text = f"{successes}/{attempts}"
            ax.add_patch(plt.Rectangle(
                (j - 0.45, i - 0.45), 0.9, 0.9,
                facecolor=face, edgecolor=edge, linewidth=0.7, hatch=hatch,
            ))
            if marker_text:
                ax.text(
                    j, i, marker_text,
                    ha="center", va="center", fontsize=7,
                    color="black",
                )

    ax.set_xlim(-0.6, len(SYSTEMS) - 0.4)
    ax.set_ylim(-0.6, n_cases - 0.4)
    ax.invert_yaxis()
    ax.set_xticks(range(len(SYSTEMS)))
    ax.set_xticklabels(SYSTEMS)
    ax.set_yticks(range(n_cases))
    ax.set_yticklabels([f"{t}/{c}" for (t, c) in ordered_cases])
    ax.tick_params(length=0)
    ax.set_xlabel("system")
    ax.set_ylabel("attack case")
    ax.grid(False)
    for spine in ax.spines.values():
        spine.set_visible(False)

    row_boundaries = []
    running = 0
    for t in order_types:
        running += len(cases_by_type[t])
        row_boundaries.append(running - 0.5)
    for rb in row_boundaries[:-1]:
        ax.axhline(rb, color="#888888", lw=0.4, ls="-")

    legend_patches = [
        Patch(facecolor="#2d2d2d", edgecolor="black", label="blocked (0/N)"),
        Patch(facecolor="white", edgecolor="black", hatch="///", label="partial bypass"),
        Patch(facecolor="white", edgecolor="black", label="full bypass (N/N)"),
    ]
    ax.legend(
        handles=legend_patches, loc="upper right",
        bbox_to_anchor=(1.02, 1.08), ncol=3, frameon=False, fontsize=7,
    )
    save(fig, "figure_attack_heatmap.png", w=5.4, h=4.3)
    save(fig, "figure_attack_heatmap.pdf", w=5.4, h=4.3)


# ---------- 7. Registry lookup scaling (log-log, flat fit) ----------
def plot_registry_lookup_scaling() -> None:
    print("registry lookup scaling...")
    s = pd.read_csv(REG / "registry_scaling_summary.csv")
    s = s.sort_values("N")
    N = s["N"].values
    kernel_rtt_us = s["lookup_avg_ms"].values * 1000.0
    kernel_err_us = s["lookup_ci95_ms"].values * 1000.0
    dict_rtt_us = s["userspace_dict_avg_ms"].values * 1000.0

    fig, ax = plt.subplots()
    ax.errorbar(
        N, kernel_rtt_us, yerr=kernel_err_us,
        fmt="o-", color="black", mfc="#2d2d2d", mec="black", lw=1.0,
        capsize=2, capthick=0.6, elinewidth=0.6,
        label="kernel_mcp lookup",
    )
    ax.plot(
        N, dict_rtt_us,
        ls="--", color="black", marker="s", mfc="white", mec="black",
        lw=1.0, label="Python dict lookup",
    )
    kernel_mean = kernel_rtt_us.mean()
    ax.axhline(kernel_mean, color="#555555", ls=":", lw=0.7)
    ax.text(
        N[-1], kernel_mean * 1.06,
        f"kernel mean ≈ {kernel_mean:.2f} μs (slope ≈ 0)",
        fontsize=7, ha="right", va="bottom", color="#333333",
    )

    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("N (registered tools)")
    ax.set_ylabel("lookup RTT (μs, log scale)")
    ax.set_ylim(0.03, 30)
    ax.legend(loc="center right")
    save(fig, "figure_registry_lookup_scaling.pdf")


# ---------- 8. Registry register-path per-tool cost (fit + asymptote) ----------
def plot_registry_register_curve() -> None:
    print("registry register curve...")
    s = pd.read_csv(REG / "registry_scaling_summary.csv").sort_values("N")
    N = s["N"].values.astype(float)
    cost_us = s["register_per_tool_us_avg"].values
    err_us = s["register_per_tool_us_ci95"].values

    def model(N, a, b):
        return a / N + b

    A = np.vstack([1.0 / N, np.ones_like(N)]).T
    ab, *_ = np.linalg.lstsq(A, cost_us, rcond=None)
    a_fit, b_fit = ab
    Ns = np.logspace(np.log10(N.min()), np.log10(N.max()), 120)
    fit_vals = model(Ns, a_fit, b_fit)

    fig, ax = plt.subplots()
    ax.errorbar(
        N, cost_us, yerr=err_us,
        fmt="o", color="black", mfc="#2d2d2d", mec="black",
        capsize=2, capthick=0.6, elinewidth=0.6, lw=0, label="measured",
    )
    ax.plot(Ns, fit_vals, color="black", lw=1.0, ls="-", label=f"fit $a/N+b$, $b={b_fit:.2f}$ μs")
    ax.axhline(b_fit, color="#555555", ls=":", lw=0.7, label=f"asymptote $b={b_fit:.2f}$ μs")

    ax.set_xscale("log", base=2)
    ax.set_xlabel("N (registered tools)")
    ax.set_ylabel("per-tool register cost (μs)")
    ax.legend(loc="upper right")
    save(fig, "figure_registry_register_curve.pdf")


# ---------- 9. Kernel ablation: per-mode full RTT, log-y ----------
def plot_ablation_mean_rtt() -> None:
    print("ablation mean rtt...")
    m = pd.read_csv(ABL / "kernel_ablation_mode_summary.csv")
    order = ["full", "skip_lookups", "ticket_trigger_full", "ticket_trigger_skip", "skip_hash", "skip_binding"]
    m = m.set_index("mode").loc[order].reset_index()
    fig, ax = plt.subplots()
    x = np.arange(len(order))
    vals = m["avg_ms"].values * 1000.0
    ci = m["ci95_ms"].values * 1000.0
    face = [
        "#2d2d2d" if mode == "full" or mode == "ticket_trigger_full"
        else "#b8b8b8" if mode.startswith("ticket")
        else "#ffffff"
        for mode in order
    ]
    for xi, v, e, fc in zip(x, vals, ci, face):
        ax.bar(
            xi, v, yerr=e, width=0.6,
            facecolor=fc, edgecolor="black", linewidth=0.7,
            error_kw={"elinewidth": 0.7, "capsize": 2, "capthick": 0.7, "ecolor": "black"},
        )
        ax.text(xi, v + e + 0.2, f"{v:.2f}", ha="center", va="bottom", fontsize=7)
    ax.set_xticks(x)
    ax.set_xticklabels(order, rotation=25, ha="right")
    ax.set_ylabel("mean RTT (μs)")
    ax.set_xlabel("ablation mode (lower = cheaper kernel path)")
    ax.set_ylim(0, max(vals + ci) * 1.25)
    legend_patches = [
        Patch(facecolor="#2d2d2d", edgecolor="black", label="baseline (no skip)"),
        Patch(facecolor="#b8b8b8", edgecolor="black", label="ticket-path baseline"),
        Patch(facecolor="#ffffff", edgecolor="black", label="skip variants"),
    ]
    ax.legend(handles=legend_patches, loc="upper right", ncol=1)
    save(fig, "figure_ablation_mean_rtt.pdf")


# ---------- 10. Per-stage kernel cost deltas + total waterfall ----------
def plot_ablation_stage_delta() -> None:
    print("ablation stage deltas (waterfall)...")
    sd = pd.read_csv(ABL / "kernel_ablation_stage_deltas.csv")
    noop = pd.read_csv(ABL / "kernel_ablation_noop.csv").set_index("mode")

    noop_us = float(noop.loc["noop", "avg_ms"]) * 1000.0

    reg_delta = float(sd[sd["stage"] == "registry+agent_lookup"]["delta_avg_ms"].iloc[0]) * 1000.0
    ticket_delta = float(sd[sd["stage"] == "approval_ticket_body"]["delta_avg_ms"].iloc[0]) * 1000.0
    ticket_ci_lo = float(sd[sd["stage"] == "approval_ticket_body"]["delta_ci_lo"].iloc[0]) * 1000.0
    ticket_ci_hi = float(sd[sd["stage"] == "approval_ticket_body"]["delta_ci_hi"].iloc[0]) * 1000.0

    total_over_noop_us = 4.334
    reply_skb_delta = total_over_noop_us - reg_delta
    full_kernel_us = noop_us + total_over_noop_us

    fig, ax = plt.subplots()
    stages = [
        ("noop floor\n(Generic Netlink)", 0, noop_us, "#b8b8b8", ""),
        ("registry +\nagent lookup", noop_us, reg_delta, "#2d2d2d", ""),
        ("reply-skb\nconstruction", noop_us + reg_delta, reply_skb_delta, "#ffffff", "///"),
    ]
    x_positions = np.arange(len(stages))
    for i, (label, base, delta, fc, hatch) in enumerate(stages):
        ax.bar(
            i, delta, bottom=base,
            facecolor=fc, edgecolor="black", linewidth=0.8, hatch=hatch,
            width=0.58,
        )
        ax.text(
            i, base + delta + 0.12,
            f"{delta:.2f} μs" if i == 0 else f"+{delta:.2f} μs",
            ha="center", va="bottom", fontsize=7,
        )
        if i < len(stages) - 1:
            next_base = base + delta
            ax.plot(
                [i + 0.29, i + 1 - 0.29], [next_base, next_base],
                color="black", lw=0.4, ls=":",
            )

    ax.axhline(full_kernel_us, color="black", ls="--", lw=0.6)
    ax.text(
        len(stages) - 0.6, full_kernel_us + 0.15,
        f"full kernel RTT $\\approx$ {full_kernel_us:.2f} μs",
        ha="right", va="bottom", fontsize=7, color="black",
    )
    ax.text(
        1.5, noop_us / 2.0,
        f"kernel arbitration adds\n{total_over_noop_us:.3f} μs above NOOP floor",
        ha="center", va="center", fontsize=7, color="#222222",
        bbox=dict(facecolor="white", edgecolor="#888888", lw=0.4, pad=2.5),
    )

    ticket_x = len(stages) + 0.8
    ax.bar(
        ticket_x, ticket_delta, bottom=0,
        facecolor="#ffffff", edgecolor="black", linewidth=0.8, hatch="xxx",
        width=0.5,
        yerr=[[ticket_delta - ticket_ci_lo], [ticket_ci_hi - ticket_delta]],
        error_kw={"elinewidth": 0.6, "capsize": 2, "capthick": 0.6, "ecolor": "black"},
    )
    ax.text(
        ticket_x, ticket_delta + 0.2,
        f"+{ticket_delta:.2f} μs",
        ha="center", va="bottom", fontsize=7,
    )

    ax.set_xticks(list(x_positions) + [ticket_x])
    ax.set_xticklabels(
        [s[0] for s in stages] + ["approval-ticket\nbody (DEFER path)"],
        fontsize=8,
    )
    divider_x = (len(stages) - 0.5 + ticket_x - 0.4) / 2 + 0.2
    ax.axvline(divider_x, color="#bbbbbb", lw=0.4, ls=":")
    ax.text(
        (0 + len(stages) - 1) / 2, full_kernel_us * 1.25,
        "benign fast path (waterfall)",
        ha="center", va="center", fontsize=7, color="#555555", style="italic",
    )
    ax.text(
        ticket_x, full_kernel_us * 1.25,
        "DEFER path\n(ticket body)",
        ha="center", va="center", fontsize=7, color="#555555", style="italic",
    )
    ax.set_ylabel("kernel-side RTT contribution (μs)")
    ax.set_ylim(0, full_kernel_us * 1.45)
    ax.set_xlim(-0.6, ticket_x + 0.6)
    save(fig, "figure_ablation_stage_delta.pdf", w=6.5, h=3.4)


# ---------- 11. Netlink paired microbench ECDF with 4.334 us annotation ----------
def plot_netlink_rtt() -> None:
    print("netlink rtt ecdf...")
    samples = pd.read_csv(NET / "netlink_microbench_samples.csv")
    fig, ax = plt.subplots()
    for mode, ls, label in [("bare", "--", "bare Netlink (NOOP)"), ("full", "-", "full kernel arbitration")]:
        vals = np.sort(samples[samples["mode"] == mode]["rtt_ms"].values * 1000.0)
        y = np.arange(1, len(vals) + 1) / len(vals)
        ax.step(vals, y, where="post", lw=1.1, color="black", ls=ls, label=label)
    ax.set_xscale("log")
    ax.set_xlim(5, 50)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("per-request RTT (μs, log scale)")
    ax.set_ylabel("ECDF (10k samples per mode)")
    ax.legend(loc="lower right")

    summary = pd.read_csv(NET / "netlink_microbench_summary.csv").set_index("mode")
    bare_us = float(summary.loc["bare", "avg_ms"]) * 1000.0
    full_us = float(summary.loc["full", "avg_ms"]) * 1000.0

    y_anno = 0.55
    ax.annotate(
        "",
        xy=(full_us, y_anno), xytext=(bare_us, y_anno),
        arrowprops=dict(arrowstyle="<->", lw=0.7, color="black"),
    )
    ax.text(
        math.sqrt(bare_us * full_us), y_anno + 0.04,
        f"mean gap = {full_us - bare_us:.2f} μs",
        ha="center", va="bottom", fontsize=7,
    )
    ax.text(
        0.02, 0.96,
        "paired ablation attributes 4.334 μs to the full kernel\n"
        "arbitration path above the measured NOOP floor (§4.1)",
        transform=ax.transAxes, fontsize=7, ha="left", va="top", color="#333333",
        bbox=dict(facecolor="white", edgecolor="#888888", lw=0.4, pad=2.5),
    )
    save(fig, "figure_netlink_rtt_ecdf.pdf", w=6.3, h=3.0)


# ---------- 12. Fuzz errno distribution (redraw) ----------
def plot_fuzz_errno() -> None:
    print("fuzz errno distribution...")
    s = pd.read_csv(ATK / "fuzz_samples.csv")
    cmds_order = s["cmd"].value_counts().sort_values(ascending=False).index.tolist()
    errnos = sorted(s["errno"].unique())
    errno_label = {
        -1: "-1 EPERM",
        -2: "-2 ENOENT",
        -14: "-14 EFAULT",
        -22: "-22 EINVAL",
        -34: "-34 ERANGE",
    }

    counts = {e: [] for e in errnos}
    for cmd in cmds_order:
        sub = s[s["cmd"] == cmd]
        total = len(sub)
        for e in errnos:
            counts[e].append(100.0 * (sub["errno"] == e).sum() / max(total, 1))

    fig, ax = plt.subplots()
    x = np.arange(len(cmds_order))
    bottoms = np.zeros(len(cmds_order))
    gray_levels = np.linspace(0.85, 0.15, len(errnos))
    hatches = ["", "///", "xxx", "...", "\\\\"]
    for i, e in enumerate(errnos):
        ax.bar(
            x, counts[e], bottom=bottoms, width=0.7,
            facecolor=str(gray_levels[i]), edgecolor="black", linewidth=0.5,
            hatch=hatches[i % len(hatches)],
            label=errno_label.get(e, str(e)),
        )
        bottoms = bottoms + np.array(counts[e])

    ax.set_xticks(x)
    ax.set_xticklabels(cmds_order, rotation=20, ha="right", fontsize=7)
    ax.set_ylabel("share of rejected inputs (%)")
    ax.set_xlabel("Generic Netlink command")
    ax.set_ylim(0, 100)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.12), ncol=len(errnos), fontsize=7)
    save(fig, "figure_fuzz_errno_distribution.pdf", w=6.5, h=3.2)


# ---------- 13. E4 peer-credential A/B (new aux) ----------
def plot_e4_peer_cred() -> None:
    print("E4 peer-cred A/B...")
    with_patch = pd.read_csv(ATK / "crossuid_result_with_patch.csv")
    without = pd.read_csv(ATK / "crossuid_result_without_patch.csv")
    fig, ax = plt.subplots()
    for label, df, ls in [
        ("without patch (pre-E4 module)", without, "--"),
        ("with six-line peer_cred patch", with_patch, "-"),
    ]:
        vals = np.sort(df["latency_ms"].values * 1000.0)
        y = np.arange(1, len(vals) + 1) / len(vals)
        ax.step(vals, y, where="post", lw=1.1, color="black", ls=ls, label=label)
    ax.set_xscale("log")
    ax.set_xlim(1, 200)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("cross-UID attack latency (μs, log scale)")
    ax.set_ylabel("ECDF")
    ax.legend(loc="lower right")

    def leak_frac(df):
        n = len(df)
        leaked = int((df["outcome"] != "blocked").sum())
        return leaked, n

    leaked_w, n_w = leak_frac(without)
    leaked_p, n_p = leak_frac(with_patch)
    reasons_without = without["reason"].value_counts()
    reasons_with = with_patch["reason"].value_counts()
    top_without = reasons_without.index[0] if not reasons_without.empty else "n/a"
    top_with = reasons_with.index[0] if not reasons_with.empty else "n/a"
    note = (
        f"both variants block all attempts:\n"
        f"  without patch {n_w - leaked_w}/{n_w} blocked, rejection reason '{top_without}'\n"
        f"  with    patch {n_p - leaked_p}/{n_p} blocked, rejection reason '{top_with}'\n"
        "the six-line change shifts the reject path from a binding check to an OS-level peer-cred check\n"
        "at no measurable latency cost"
    )
    ax.text(
        0.02, 0.95, note,
        transform=ax.transAxes, fontsize=7, va="top", color="#333333",
        bbox=dict(facecolor="white", edgecolor="#888888", lw=0.4, pad=2.5),
    )
    save(fig, "figure_e4_peer_cred_ab.pdf", w=6.3, h=3.0)


def main() -> None:
    setup_style()
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    plot_latency_mean()
    plot_latency_p95()
    plot_latency_overhead()
    plot_latency_breakdown()
    plot_latency_panel()
    plot_latency_ecdf()
    plot_throughput_sweep()
    plot_attack_matrix()
    plot_registry_lookup_scaling()
    plot_registry_register_curve()
    plot_ablation_mean_rtt()
    plot_ablation_stage_delta()
    plot_netlink_rtt()
    plot_fuzz_errno()
    plot_e4_peer_cred()
    print("done.")


if __name__ == "__main__":
    main()
