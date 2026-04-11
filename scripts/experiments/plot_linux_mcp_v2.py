#!/usr/bin/env python3
"""Plot linux_mcp v2 figures from evaluation outputs.

Separate from plot_linux_mcp_results.py: this script assumes one or two
run directories (one for the latency/attack/boundary data, optionally a
second for the scalability sweep). It emits both PNG and PDF for every
figure so the paper can ship vector plots.

Figures produced:
  * figure_latency_mean_by_payload.{png,pdf}      3 subplots, mean + 95% CI
  * figure_latency_p95_by_payload.{png,pdf}       same layout, p95
  * figure_latency_breakdown.{png,pdf}            grouped bars per stage, per payload
  * figure_latency_overhead.{png,pdf}             overhead ratios centred on 1.0
  * figure_latency_cdf.{png,pdf}                  log-x CDF with tail zoom
  * figure_attack_matrix.{png,pdf}                heatmap with absolute counts
  * figure_boundary_matrix.{png,pdf}              heatmap of group-F results
  * figure_scalability_throughput.{png,pdf}       optional, from scalability run
  * figure_scalability_p95.{png,pdf}              optional, from scalability run

The script never reads *_samples.csv (those are gitignored); all figures
are regenerated from the per-repetition CSVs and the aggregated summary
CSVs.
"""

from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

try:
    from scipy import stats as scipy_stats  # type: ignore
except Exception:  # noqa: BLE001
    scipy_stats = None


# ---------------------------------------------------------------------------
# Shared style / constants
# ---------------------------------------------------------------------------

SYSTEM_ORDER = ["userspace", "seccomp", "kernel"]
SYSTEM_LABELS = {
    "userspace": "userspace",
    "seccomp": "seccomp",
    "kernel": "kernel",
}
# Color-blind friendly qualitative palette; avoids the red-vs-green implicit
# valence of the v1 palette.
SYSTEM_COLORS = {
    "userspace": "#4C72B0",  # blue
    "seccomp": "#DD8452",    # orange
    "kernel": "#55A868",     # desaturated green
}
STAGE_LABELS = {
    "session_lookup_ms": "session_lookup",
    "arbitration_ms": "arbitration",
    "tool_exec_ms": "tool_exec",
}
STAGE_COLORS = {
    "session_lookup_ms": "#9FB3C8",
    "arbitration_ms": "#5C80BC",
    "tool_exec_ms": "#2D6A4F",
}
PAYLOAD_LABEL_ORDER = ["small", "medium", "large"]
PAYLOAD_DISPLAY = {
    "small": "100 B",
    "medium": "10 KiB",
    "large": "1 MiB",
}

FIGURE_DPI = 180


def _apply_rc_params() -> None:
    plt.rcParams.update(
        {
            "figure.dpi": 100,
            "savefig.dpi": FIGURE_DPI,
            "font.family": "DejaVu Sans",
            "font.size": 9.5,
            "axes.titlesize": 10.5,
            "axes.labelsize": 10,
            "axes.grid": True,
            "axes.grid.axis": "y",
            "grid.alpha": 0.25,
            "grid.linestyle": ":",
            "legend.frameon": False,
            "legend.fontsize": 9,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------

def load_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _float(row: Dict[str, str], key: str, default: float = 0.0) -> float:
    raw = row.get(key, "")
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _systems_present(rows: Sequence[Dict[str, str]], key: str = "system") -> List[str]:
    present = {row.get(key, "") for row in rows if row.get(key)}
    return [name for name in SYSTEM_ORDER if name in present]


def _save(fig: plt.Figure, out_dir: Path, basename: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    png_path = out_dir / f"{basename}.png"
    pdf_path = out_dir / f"{basename}.pdf"
    fig.savefig(png_path, dpi=FIGURE_DPI, bbox_inches="tight")
    fig.savefig(pdf_path, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Statistics helpers (reconstruct per-rep distributions from the CSVs so we
# can compute 95% CIs without reading the huge *_samples.csv files).
# ---------------------------------------------------------------------------

def _mean_std_ci(values: Sequence[float]) -> Tuple[float, float, float, float]:
    """Return (mean, std, ci_lo, ci_hi) using Student t if scipy is available."""
    values = [float(v) for v in values]
    if not values:
        return (0.0, 0.0, 0.0, 0.0)
    mean = statistics.fmean(values)
    if len(values) < 2:
        return (mean, 0.0, mean, mean)
    std = statistics.stdev(values)
    sem = std / math.sqrt(len(values))
    if scipy_stats is not None:
        ci_lo, ci_hi = scipy_stats.t.interval(0.95, len(values) - 1, loc=mean, scale=sem)
    else:
        margin = 1.96 * sem
        ci_lo, ci_hi = mean - margin, mean + margin
    return (mean, std, float(ci_lo), float(ci_hi))


def _welch_p(lhs: Sequence[float], rhs: Sequence[float]) -> float:
    if len(lhs) < 2 or len(rhs) < 2:
        return 1.0
    if scipy_stats is not None:
        result = scipy_stats.ttest_ind(list(lhs), list(rhs), equal_var=False)
        return float(result.pvalue) if result.pvalue is not None else 1.0
    mean_l = statistics.fmean(lhs)
    mean_r = statistics.fmean(rhs)
    var_l = statistics.variance(lhs)
    var_r = statistics.variance(rhs)
    denom = math.sqrt(var_l / len(lhs) + var_r / len(rhs))
    if denom <= 0:
        return 1.0
    z = abs(mean_l - mean_r) / denom
    return math.erfc(z / math.sqrt(2.0))


def _collect_per_rep(
    latency_reps: Sequence[Dict[str, str]], column: str
) -> Dict[Tuple[str, str], List[float]]:
    out: Dict[Tuple[str, str], List[float]] = defaultdict(list)
    for row in latency_reps:
        system = row.get("system", "")
        payload = row.get("payload_label", "")
        out[(system, payload)].append(_float(row, column))
    return out


# ---------------------------------------------------------------------------
# Figures 1a / 1b: latency mean and p95 by payload, with 95% CIs
# ---------------------------------------------------------------------------

def _plot_latency_by_payload_metric(
    latency_reps: Sequence[Dict[str, str]],
    out_dir: Path,
    metric_column: str,
    metric_label: str,
    basename: str,
) -> None:
    if not latency_reps:
        return
    systems = _systems_present(latency_reps)
    payloads = [p for p in PAYLOAD_LABEL_ORDER if any(
        row.get("system") == s and row.get("payload_label") == p
        for row in latency_reps for s in systems
    )]
    if not payloads:
        return
    per_rep = _collect_per_rep(latency_reps, metric_column)

    # One subplot per payload — each with an auto-ranged y axis.
    fig, axes = plt.subplots(
        1, len(payloads), figsize=(3.4 * len(payloads), 3.4), sharey=False
    )
    if len(payloads) == 1:
        axes = [axes]

    bar_width = 0.62
    x_positions = np.arange(len(systems))
    baseline_system = "userspace" if "userspace" in systems else systems[0]

    for ax, payload in zip(axes, payloads):
        means: List[float] = []
        err_los: List[float] = []
        err_his: List[float] = []
        for system in systems:
            values = per_rep.get((system, payload), [])
            mean, _, lo, hi = _mean_std_ci(values)
            means.append(mean)
            err_los.append(max(mean - lo, 0.0))
            err_his.append(max(hi - mean, 0.0))
        bar_colors = [SYSTEM_COLORS[s] for s in systems]
        ax.bar(
            x_positions,
            means,
            width=bar_width,
            color=bar_colors,
            yerr=np.array([err_los, err_his]),
            capsize=3,
            error_kw={"elinewidth": 1.0, "ecolor": "#333333"},
        )
        # Annotate each bar with its mean value, placed above the error bar.
        max_top = max((m + eh) for m, eh in zip(means, err_his)) if means else 0.0
        label_pad = max_top * 0.04 if max_top > 0 else 0.01
        for x, mean, eh in zip(x_positions, means, err_his):
            ax.text(
                x,
                mean + eh + label_pad,
                f"{mean:.3f}",
                ha="center",
                va="bottom",
                fontsize=8.5,
                color="#222222",
            )
        if max_top > 0:
            ax.set_ylim(0, max_top * 1.25)

        ax.set_xticks(x_positions)
        ax.set_xticklabels([SYSTEM_LABELS[s] for s in systems])
        ax.set_title(f"{PAYLOAD_DISPLAY.get(payload, payload)}")
        ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%g"))

    axes[0].set_ylabel(f"{metric_label} (ms)")
    fig.tight_layout()
    _save(fig, out_dir, basename)


def _p_value_marker(p: float) -> str:
    if p < 0.001:
        return "***"
    if p < 0.01:
        return "**"
    if p < 0.05:
        return "*"
    return "ns"


def plot_latency_mean(latency_reps, out_dir: Path) -> None:
    _plot_latency_by_payload_metric(
        latency_reps,
        out_dir,
        metric_column="latency_avg_ms",
        metric_label="mean latency",
        basename="figure_latency_mean_by_payload",
    )


def plot_latency_p95(latency_reps, out_dir: Path) -> None:
    _plot_latency_by_payload_metric(
        latency_reps,
        out_dir,
        metric_column="latency_p95_ms",
        metric_label="p95 latency",
        basename="figure_latency_p95_by_payload",
    )


# ---------------------------------------------------------------------------
# Figure 2: latency breakdown — grouped bars per stage, subplot per payload,
#           log y axis so session_lookup is visible alongside tool_exec.
# ---------------------------------------------------------------------------

def plot_latency_breakdown(
    breakdown_rows: Sequence[Dict[str, str]], out_dir: Path
) -> None:
    if not breakdown_rows:
        return
    systems = _systems_present(breakdown_rows)
    payloads = [p for p in PAYLOAD_LABEL_ORDER if any(
        r.get("payload_label") == p for r in breakdown_rows
    )]
    stages = list(STAGE_LABELS.keys())

    fig, axes = plt.subplots(
        1, len(payloads), figsize=(3.4 * len(payloads), 3.6), sharey=True
    )
    if len(payloads) == 1:
        axes = [axes]

    stage_positions = np.arange(len(stages))
    group_width = 0.78
    bar_width = group_width / len(systems)

    for ax, payload in zip(axes, payloads):
        stage_max_per_group: List[float] = []
        for stage_idx, stage in enumerate(stages):
            group_max = 0.0
            for idx, system in enumerate(systems):
                match = next(
                    (
                        r
                        for r in breakdown_rows
                        if r.get("system") == system and r.get("payload_label") == payload
                    ),
                    {},
                )
                values = [max(_float(match, s), 1e-5) for s in stages]
                offsets = stage_positions + (idx - (len(systems) - 1) / 2) * bar_width
                # Draw only the bar for this particular (system, stage) pair.
                ax.bar(
                    [offsets[stage_idx]],
                    [values[stage_idx]],
                    width=bar_width,
                    color=SYSTEM_COLORS[system],
                    label=SYSTEM_LABELS[system]
                    if (ax is axes[0] and stage_idx == 0)
                    else None,
                )
                group_max = max(group_max, values[stage_idx])
            stage_max_per_group.append(group_max)

        # Draw rotated labels above each bar, sized so adjacent labels don't
        # collide even when the values are close.
        for stage_idx, stage in enumerate(stages):
            for idx, system in enumerate(systems):
                match = next(
                    (
                        r
                        for r in breakdown_rows
                        if r.get("system") == system and r.get("payload_label") == payload
                    ),
                    {},
                )
                v = max(_float(match, stage), 1e-5)
                x = stage_positions[stage_idx] + (idx - (len(systems) - 1) / 2) * bar_width
                label = f"{v:.3g}"
                ax.text(
                    x,
                    v * 1.12,
                    label,
                    ha="center",
                    va="bottom",
                    fontsize=6.5,
                    rotation=90,
                    color="#222222",
                )

        ax.set_yscale("log")
        ax.set_xticks(stage_positions)
        ax.set_xticklabels(
            [STAGE_LABELS[s] for s in stages], rotation=15, ha="right"
        )
        ax.set_title(f"{PAYLOAD_DISPLAY.get(payload, payload)}")
        ax.yaxis.set_major_formatter(mticker.FormatStrFormatter("%g"))
        ax.grid(axis="y", which="both", alpha=0.25, linestyle=":")
        # Give headroom for the rotated numeric labels.
        top_value = max(stage_max_per_group) if stage_max_per_group else 1.0
        ax.set_ylim(1e-3, top_value * 6.0)

    axes[0].set_ylabel("mean stage latency (ms, log)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    fig.legend(
        handles,
        labels,
        loc="upper center",
        ncols=len(handles),
        frameon=False,
        bbox_to_anchor=(0.5, 0.99),
    )
    _save(fig, out_dir, "figure_latency_breakdown")


# ---------------------------------------------------------------------------
# Figure 3: latency overhead ratio relative to userspace, y axis zoomed on 1.0
# ---------------------------------------------------------------------------

def plot_latency_overhead(
    latency_reps: Sequence[Dict[str, str]], out_dir: Path
) -> None:
    if not latency_reps:
        return
    systems = _systems_present(latency_reps)
    if "userspace" not in systems:
        return
    payloads = [p for p in PAYLOAD_LABEL_ORDER if any(
        r.get("payload_label") == p for r in latency_reps
    )]
    per_rep_mean = _collect_per_rep(latency_reps, "latency_avg_ms")

    comparators = [s for s in systems if s != "userspace"]
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    x_positions = np.arange(len(payloads))
    group_width = 0.68
    bar_width = group_width / max(len(comparators), 1)

    all_values: List[float] = []
    for idx, system in enumerate(comparators):
        ratios: List[float] = []
        errs_lo: List[float] = []
        errs_hi: List[float] = []
        for payload in payloads:
            base = per_rep_mean.get(("userspace", payload), [])
            other = per_rep_mean.get((system, payload), [])
            if not base or not other:
                ratios.append(1.0)
                errs_lo.append(0.0)
                errs_hi.append(0.0)
                continue
            base_mean = statistics.fmean(base)
            other_mean = statistics.fmean(other)
            ratio = other_mean / base_mean if base_mean > 0 else 1.0
            # Propagate CI using the CI on (other_mean - base_mean) and
            # divide by base_mean as a linear approximation.
            _, _, lo_other, hi_other = _mean_std_ci(other)
            ratio_lo = (lo_other / base_mean) if base_mean > 0 else ratio
            ratio_hi = (hi_other / base_mean) if base_mean > 0 else ratio
            ratios.append(ratio)
            errs_lo.append(max(ratio - ratio_lo, 0.0))
            errs_hi.append(max(ratio_hi - ratio, 0.0))
            all_values.extend([ratio_lo, ratio_hi])
        offsets = x_positions + (idx - (len(comparators) - 1) / 2) * bar_width
        ax.bar(
            offsets,
            ratios,
            width=bar_width,
            color=SYSTEM_COLORS[system],
            label=f"{system} / userspace",
            yerr=np.array([errs_lo, errs_hi]),
            capsize=3,
            error_kw={"elinewidth": 1.0, "ecolor": "#333333"},
        )
        for x, ratio, eh in zip(offsets, ratios, errs_hi):
            ax.text(
                x,
                ratio + eh + 0.025,
                f"{ratio:.2f}",
                ha="center",
                va="bottom",
                fontsize=8,
                color="#222222",
            )

    ax.axhline(1.0, color="#444444", linestyle="--", linewidth=1.0)
    ax.set_xticks(x_positions)
    ax.set_xticklabels([PAYLOAD_DISPLAY.get(p, p) for p in payloads])
    ax.set_ylabel("mean-latency ratio (1.00 = parity)")
    low = min(all_values + [0.9]) if all_values else 0.9
    high = max(all_values + [1.1]) if all_values else 1.1
    pad = (high - low) * 0.35 if high > low else 0.1
    ax.set_ylim(max(0, low - pad * 0.5), high + pad)
    ax.legend(loc="upper left")
    fig.tight_layout()
    _save(fig, out_dir, "figure_latency_overhead")


# ---------------------------------------------------------------------------
# Figure 4: latency CDF — log x axis, one subplot per payload, with the
# reported p50/p95/p99 marks from latency_repetitions.csv overlaid as
# vertical reference lines (since we can't read the raw samples).
# ---------------------------------------------------------------------------

def plot_latency_cdf(
    latency_reps: Sequence[Dict[str, str]], out_dir: Path
) -> None:
    """Approximate CDF using the p50/p95/p99 percentiles recorded per rep.

    Because *_samples.csv files are gitignored and large, we don't have the
    raw per-request latencies on disk. Instead we interpolate an empirical
    CDF from the 30 (rep, p50), (rep, p95), (rep, p99) tuples per system,
    which still conveys the distributional story with much less noise than
    the v1 plot's hairy long-tail line.
    """
    if not latency_reps:
        return
    systems = _systems_present(latency_reps)
    payloads = [p for p in PAYLOAD_LABEL_ORDER if any(
        r.get("payload_label") == p for r in latency_reps
    )]

    fig, axes = plt.subplots(
        1, len(payloads), figsize=(3.6 * len(payloads), 3.6), sharey=True
    )
    if len(payloads) == 1:
        axes = [axes]

    percentiles = [
        ("latency_p50_ms", 0.50, "p50"),
        ("latency_p95_ms", 0.95, "p95"),
        ("latency_p99_ms", 0.99, "p99"),
    ]
    y_positions = [0.50, 0.95, 0.99]

    for ax, payload in zip(axes, payloads):
        x_range_min = float("inf")
        x_range_max = float("-inf")
        for system_idx, system in enumerate(systems):
            by_rep = [
                {key: _float(r, key) for key in ("latency_p50_ms", "latency_p95_ms", "latency_p99_ms")}
                for r in latency_reps
                if r.get("system") == system and r.get("payload_label") == payload
            ]
            if not by_rep:
                continue
            means: List[float] = []
            lows: List[float] = []
            highs: List[float] = []
            for column, _q, _label in percentiles:
                vals = [r[column] for r in by_rep if r[column] > 0]
                if not vals:
                    means.append(float("nan"))
                    lows.append(float("nan"))
                    highs.append(float("nan"))
                    continue
                mean, _, lo, hi = _mean_std_ci(vals)
                means.append(mean)
                lows.append(lo)
                highs.append(hi)
                x_range_min = min(x_range_min, lo)
                x_range_max = max(x_range_max, hi)
            x_err = np.array([
                [max(m - lo, 0.0) for m, lo in zip(means, lows)],
                [max(hi - m, 0.0) for m, hi in zip(means, highs)],
            ])
            ax.errorbar(
                means,
                y_positions,
                xerr=x_err,
                marker="o",
                linewidth=1.6,
                markersize=6,
                capsize=3,
                color=SYSTEM_COLORS[system],
                label=SYSTEM_LABELS[system] if ax is axes[0] else None,
            )
        ax.set_yticks(y_positions)
        ax.set_yticklabels(["p50", "p95", "p99"])
        ax.set_ylim(0.40, 1.05)
        ax.set_xlabel("latency (ms)")
        ax.set_title(f"{PAYLOAD_DISPLAY.get(payload, payload)}")
        ax.grid(axis="both", alpha=0.25, linestyle=":")
        # Tight but non-collapsed x limits.
        if math.isfinite(x_range_min) and math.isfinite(x_range_max) and x_range_max > x_range_min:
            pad = (x_range_max - x_range_min) * 0.15
            ax.set_xlim(max(0.0, x_range_min - pad), x_range_max + pad)
        ax.xaxis.set_major_formatter(mticker.FormatStrFormatter("%g"))

    axes[0].set_ylabel("quantile")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    fig.legend(
        handles,
        labels,
        loc="upper center",
        ncols=len(handles),
        frameon=False,
        bbox_to_anchor=(0.5, 0.99),
    )
    _save(fig, out_dir, "figure_latency_cdf")


# ---------------------------------------------------------------------------
# Figure 5: attack resistance matrix — colorblind-friendly, absolute counts
# ---------------------------------------------------------------------------

def plot_attack_matrix(
    attack_rows: Sequence[Dict[str, str]], out_dir: Path
) -> None:
    if not attack_rows:
        return
    systems = _systems_present(attack_rows)
    attack_types = ["spoof", "replay", "substitute", "escalation"]

    values: List[List[float]] = []
    cells: List[List[str]] = []
    for attack in attack_types:
        row_values: List[float] = []
        row_cells: List[str] = []
        for system in systems:
            match = next(
                (r for r in attack_rows if r.get("attack_type") == attack and r.get("system") == system),
                {},
            )
            success_rate = _float(match, "success_rate")
            successes = int(_float(match, "successes"))
            attempts = int(_float(match, "attempts"))
            row_values.append(success_rate)
            row_cells.append(f"{successes}/{attempts}")
        values.append(row_values)
        cells.append(row_cells)

    fig, ax = plt.subplots(figsize=(8.0, 4.8))
    image = ax.pcolormesh(
        np.arange(len(systems) + 1) - 0.5,
        np.arange(len(attack_types) + 1) - 0.5,
        np.array(values),
        cmap="RdYlGn_r",
        vmin=0.0,
        vmax=1.0,
        edgecolors="white",
        linewidth=1.0,
    )
    ax.set_xticks(range(len(systems)), [SYSTEM_LABELS[s] for s in systems])
    ax.set_yticks(range(len(attack_types)), attack_types)
    ax.set_xlim(-0.5, len(systems) - 0.5)
    ax.set_ylim(len(attack_types) - 0.5, -0.5)
    for r_idx, row_values in enumerate(values):
        for c_idx, val in enumerate(row_values):
            cell_text = cells[r_idx][c_idx]
            pct = f"{val * 100:.0f}%"
            ax.text(
                c_idx,
                r_idx,
                f"{cell_text}\n({pct})",
                ha="center",
                va="center",
                color="#111111",
                fontsize=11,
                fontweight="bold",
            )
    colorbar = fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    colorbar.set_label("bypass rate")
    fig.tight_layout()
    _save(fig, out_dir, "figure_attack_matrix")


# ---------------------------------------------------------------------------
# Figure 6: boundary supplement matrix — group F cases × systems
# ---------------------------------------------------------------------------

def plot_boundary_matrix(
    boundary_rows: Sequence[Dict[str, str]], out_dir: Path
) -> None:
    if not boundary_rows:
        return
    systems = _systems_present(boundary_rows)
    cases = sorted({row.get("attack_case", "") for row in boundary_rows if row.get("attack_case")})
    if not cases:
        return

    values: List[List[float]] = []
    cells: List[List[str]] = []
    for case in cases:
        row_values: List[float] = []
        row_cells: List[str] = []
        for system in systems:
            match = next(
                (r for r in boundary_rows if r.get("attack_case") == case and r.get("system") == system),
                {},
            )
            success_rate = _float(match, "success_rate")
            successes = int(_float(match, "successes"))
            attempts = int(_float(match, "attempts"))
            row_values.append(success_rate)
            row_cells.append(f"{successes}/{attempts}")
        values.append(row_values)
        cells.append(row_cells)

    fig, ax = plt.subplots(figsize=(8.0, max(4.0, 0.45 * len(cases) + 2.0)))
    image = ax.pcolormesh(
        np.arange(len(systems) + 1) - 0.5,
        np.arange(len(cases) + 1) - 0.5,
        np.array(values),
        cmap="RdYlGn_r",
        vmin=0.0,
        vmax=1.0,
        edgecolors="white",
        linewidth=1.0,
    )
    ax.set_xticks(range(len(systems)), [SYSTEM_LABELS[s] for s in systems])
    ax.set_yticks(range(len(cases)), cases)
    ax.set_xlim(-0.5, len(systems) - 0.5)
    ax.set_ylim(len(cases) - 0.5, -0.5)
    for r_idx, row_values in enumerate(values):
        for c_idx, val in enumerate(row_values):
            ax.text(
                c_idx,
                r_idx,
                cells[r_idx][c_idx],
                ha="center",
                va="center",
                color="#111111",
                fontsize=10,
                fontweight="bold",
            )
    colorbar = fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    colorbar.set_label("bypass rate")
    fig.tight_layout()
    _save(fig, out_dir, "figure_boundary_matrix")


# ---------------------------------------------------------------------------
# Figure 7 & 8: scalability — throughput and p95 under load. Two-dimensional
# data (agents × concurrency) plotted as faceted line charts.
# ---------------------------------------------------------------------------

def _scalability_grid(
    scalability_rows: Sequence[Dict[str, str]], metric_column: str
) -> Tuple[List[int], List[int], Dict[str, Dict[Tuple[int, int], Tuple[float, float]]]]:
    """Return (agent_values, concurrency_values, per_system -> (agents, conc) -> (mean, std_or_ci_half)).

    For throughput we already have throughput_rps_std; for latency we have
    latency_p95_ms_std. Both appear in scalability_summary.csv when
    --repetitions > 1.
    """
    agents = sorted({int(_float(r, "agents")) for r in scalability_rows})
    concs = sorted({int(_float(r, "concurrency")) for r in scalability_rows})
    per_system: Dict[str, Dict[Tuple[int, int], Tuple[float, float]]] = defaultdict(dict)
    std_col = (
        "throughput_rps_std"
        if metric_column == "throughput_rps"
        else f"{metric_column}_std"
    )
    for row in scalability_rows:
        system = row.get("system", "")
        key = (int(_float(row, "agents")), int(_float(row, "concurrency")))
        value = _float(row, metric_column)
        err = _float(row, std_col)
        per_system[system][key] = (value, err)
    return agents, concs, per_system


def plot_scalability_throughput(
    scalability_rows: Sequence[Dict[str, str]], out_dir: Path
) -> None:
    if not scalability_rows:
        return
    systems = _systems_present(scalability_rows)
    agents, concs, per_system = _scalability_grid(scalability_rows, "throughput_rps")
    if not agents or not concs:
        return

    fig, axes = plt.subplots(
        1, len(concs), figsize=(3.4 * len(concs), 3.4), sharey=True
    )
    if len(concs) == 1:
        axes = [axes]

    for ax, conc in zip(axes, concs):
        for system in systems:
            xs: List[int] = []
            ys: List[float] = []
            errs: List[float] = []
            for a in agents:
                if (a, conc) in per_system[system]:
                    mean, err = per_system[system][(a, conc)]
                    xs.append(a)
                    ys.append(mean)
                    errs.append(err)
            if not xs:
                continue
            ax.errorbar(
                xs,
                ys,
                yerr=errs,
                marker="o",
                linewidth=1.8,
                markersize=5,
                capsize=3,
                color=SYSTEM_COLORS[system],
                label=SYSTEM_LABELS[system] if ax is axes[0] else None,
            )
        ax.set_xscale("log")
        ax.set_xlabel("agents (log)")
        ax.set_title(f"concurrency = {conc}")
        ax.grid(which="both", alpha=0.25, linestyle=":")

    axes[0].set_ylabel("throughput (ops/sec)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    fig.legend(
        handles,
        labels,
        loc="upper center",
        ncols=len(handles),
        frameon=False,
        bbox_to_anchor=(0.5, 0.99),
    )
    _save(fig, out_dir, "figure_scalability_throughput")


def plot_scalability_p95(
    scalability_rows: Sequence[Dict[str, str]], out_dir: Path
) -> None:
    if not scalability_rows:
        return
    systems = _systems_present(scalability_rows)
    agents, concs, per_system = _scalability_grid(
        scalability_rows, "latency_p95_ms"
    )
    if not agents or not concs:
        return

    fig, axes = plt.subplots(
        1, len(concs), figsize=(3.4 * len(concs), 3.4), sharey=True
    )
    if len(concs) == 1:
        axes = [axes]

    for ax, conc in zip(axes, concs):
        for system in systems:
            xs: List[int] = []
            ys: List[float] = []
            errs: List[float] = []
            for a in agents:
                if (a, conc) in per_system[system]:
                    mean, err = per_system[system][(a, conc)]
                    xs.append(a)
                    ys.append(mean)
                    errs.append(err)
            if not xs:
                continue
            ax.errorbar(
                xs,
                ys,
                yerr=errs,
                marker="o",
                linewidth=1.8,
                markersize=5,
                capsize=3,
                color=SYSTEM_COLORS[system],
                label=SYSTEM_LABELS[system] if ax is axes[0] else None,
            )
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("agents (log)")
        ax.set_title(f"concurrency = {conc}")
        ax.grid(which="both", alpha=0.25, linestyle=":")

    axes[0].set_ylabel("p95 latency (ms, log)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    fig.legend(
        handles,
        labels,
        loc="upper center",
        ncols=len(handles),
        frameon=False,
        bbox_to_anchor=(0.5, 0.99),
    )
    _save(fig, out_dir, "figure_scalability_p95")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Plot linux_mcp v2 figures")
    parser.add_argument(
        "--latency-run-dir",
        type=str,
        required=True,
        help="run directory containing latency_repetitions.csv, breakdown_summary.csv, attack_matrix.csv, boundary_matrix.csv",
    )
    parser.add_argument(
        "--scalability-run-dir",
        type=str,
        default=None,
        help="optional run directory providing scalability_summary.csv (from a separate sweep)",
    )
    parser.add_argument(
        "--boundary-run-dir",
        type=str,
        default=None,
        help="optional run directory providing boundary_matrix.csv; defaults to --latency-run-dir if not set",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="output directory; defaults to <latency-run-dir>/plots_v2",
    )
    args = parser.parse_args()

    latency_run = Path(args.latency_run_dir)
    if not latency_run.is_dir():
        raise SystemExit(f"latency run dir not found: {latency_run}")

    out_dir = Path(args.output_dir) if args.output_dir else latency_run / "plots_v2"

    _apply_rc_params()

    latency_reps = load_csv(latency_run / "latency_repetitions.csv")
    breakdown_rows = load_csv(latency_run / "breakdown_summary.csv")
    attack_rows = load_csv(latency_run / "attack_matrix.csv")

    boundary_run = Path(args.boundary_run_dir) if args.boundary_run_dir else latency_run
    boundary_rows = load_csv(boundary_run / "boundary_matrix.csv")

    plot_latency_mean(latency_reps, out_dir)
    plot_latency_p95(latency_reps, out_dir)
    plot_latency_breakdown(breakdown_rows, out_dir)
    plot_latency_overhead(latency_reps, out_dir)
    plot_latency_cdf(latency_reps, out_dir)
    plot_attack_matrix(attack_rows, out_dir)
    plot_boundary_matrix(boundary_rows, out_dir)

    if args.scalability_run_dir:
        scalability_run = Path(args.scalability_run_dir)
        scalability_rows = load_csv(scalability_run / "scalability_summary.csv")
        plot_scalability_throughput(scalability_rows, out_dir)
        plot_scalability_p95(scalability_rows, out_dir)
    else:
        print("[info] no --scalability-run-dir given; skipping scalability figures")

    print(f"[done] plots_v2 dir={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
