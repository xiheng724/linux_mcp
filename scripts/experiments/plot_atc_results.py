#!/usr/bin/env python3
"""Plot single-run ATC evaluation outputs."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def f(value: str) -> float:
    return float(value or 0.0)


def i(value: str) -> int:
    return int(float(value or 0))


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def save(fig: plt.Figure, out_path: Path) -> None:
    fig.tight_layout()
    fig.savefig(out_path, dpi=220, bbox_inches="tight")
    plt.close(fig)


def plot_ablation(atc_dir: Path, out_dir: Path) -> None:
    rows = load_csv(atc_dir / "e2e_summaries.csv") + load_csv(atc_dir / "variant_summaries.csv")
    by_mode: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_mode.setdefault(row["mode"], []).append(row)
    ordered = ["direct", "mcpd", "forwarder_only", "userspace_semantic_plane"]
    for items in by_mode.values():
        items.sort(key=lambda row: i(row["concurrency"]))
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.2))
    colors = {
        "direct": "#355070",
        "mcpd": "#C1121F",
        "forwarder_only": "#588157",
        "userspace_semantic_plane": "#B08968",
    }
    for mode in ordered:
        items = by_mode.get(mode, [])
        if not items:
            continue
        xs = [i(row["concurrency"]) for row in items]
        thr = [f(row["throughput_rps"]) for row in items]
        p95 = [f(row["latency_p95_ms"]) for row in items]
        axes[0].plot(xs, thr, marker="o", linewidth=2.2, label=mode, color=colors.get(mode))
        axes[1].plot(xs, p95, marker="o", linewidth=2.2, label=mode, color=colors.get(mode))
    axes[0].set_title("End-to-End Throughput")
    axes[0].set_xlabel("Concurrency")
    axes[0].set_ylabel("Throughput (req/s)")
    axes[1].set_title("End-to-End p95 Latency")
    axes[1].set_xlabel("Concurrency")
    axes[1].set_ylabel("Latency (ms)")
    for ax in axes:
        ax.grid(alpha=0.25)
    axes[0].legend(frameon=False)
    save(fig, out_dir / "figure_atc_ablation.png")


def plot_path_breakdown(atc_dir: Path, out_dir: Path) -> None:
    rows = load_csv(atc_dir / "path_breakdown.csv")
    ordered_modes = ["mcpd", "userspace_semantic_plane"]
    ordered_paths = ["allow", "defer", "deny"]
    fig, axes = plt.subplots(1, 2, figsize=(12.0, 4.4))
    width = 0.35
    x = list(range(len(ordered_paths)))
    for idx, mode in enumerate(ordered_modes):
        mode_rows = {(row["path"]): row for row in rows if row["mode"] == mode}
        e2e = [f(mode_rows[path]["latency_p95_ms"]) if path in mode_rows else 0.0 for path in ordered_paths]
        arb = [f(mode_rows[path]["arbitration_p95_ms"]) if path in mode_rows else 0.0 for path in ordered_paths]
        axes[0].bar([v + (idx - 0.5) * width for v in x], e2e, width=width, label=mode)
        axes[1].bar([v + (idx - 0.5) * width for v in x], arb, width=width, label=mode)
    for ax, title, ylabel in (
        (axes[0], "Path-Level End-to-End p95", "p95 (ms)"),
        (axes[1], "Arbitration / Kernel Round-Trip p95", "p95 (ms)"),
    ):
        ax.set_xticks(x)
        ax.set_xticklabels(ordered_paths)
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.grid(axis="y", alpha=0.25)
    axes[0].legend(frameon=False)
    save(fig, out_dir / "figure_atc_path_breakdown.png")


def plot_path_cdf(atc_dir: Path, out_dir: Path) -> None:
    rows = load_csv(atc_dir / "path_breakdown_raw.csv")
    if not rows:
        return
    fig, axes = plt.subplots(1, 2, figsize=(12.0, 4.4))
    focus = [("mcpd", "e2e_ms"), ("mcpd", "arbitration_ms"), ("userspace_semantic_plane", "e2e_ms"), ("userspace_semantic_plane", "arbitration_ms")]
    colors = {
        ("mcpd", "e2e_ms"): "#C1121F",
        ("mcpd", "arbitration_ms"): "#F4A261",
        ("userspace_semantic_plane", "e2e_ms"): "#355070",
        ("userspace_semantic_plane", "arbitration_ms"): "#84A59D",
    }
    for ax, path_name in zip(axes, ("allow", "deny"), strict=True):
        for mode, metric in focus:
            vals = sorted(f(row[metric]) for row in rows if row["mode"] == mode and row["path"] == path_name)
            if not vals:
                continue
            ys = [(idx + 1) / len(vals) for idx in range(len(vals))]
            label = f"{mode} {metric.replace('_ms', '')}"
            ax.plot(vals, ys, linewidth=2.0, label=label, color=colors[(mode, metric)])
        ax.set_title(f"{path_name.capitalize()} Path CDF")
        ax.set_xlabel("Latency (ms)")
        ax.set_ylabel("CDF")
        ax.grid(alpha=0.25)
    axes[0].legend(frameon=False)
    save(fig, out_dir / "figure_atc_path_cdf.png")


def plot_recovery(atc_dir: Path, out_dir: Path) -> None:
    restart_rows = load_csv(atc_dir / "restart_recovery.csv")
    tool_rows = load_csv(atc_dir / "tool_service_recovery.csv")
    approval_rows = load_csv(atc_dir / "approval_path.csv")
    labels = ["restart outage", "restart p95", "tool outage", "tool restart p95", "approval defer p95", "approval deny p95"]
    values = [
        f(restart_rows[0]["outage_ms"]) if restart_rows else 0.0,
        f(restart_rows[0]["latency_p95_ms"]) if restart_rows else 0.0,
        f(tool_rows[0]["outage_ms"]) if tool_rows else 0.0,
        f(tool_rows[0]["latency_p95_ms"]) if tool_rows else 0.0,
        f(approval_rows[0]["defer_p95_ms"]) if approval_rows else 0.0,
        f(approval_rows[0]["deny_p95_ms"]) if approval_rows else 0.0,
    ]
    fig, ax = plt.subplots(figsize=(10.0, 4.2))
    ax.bar(labels, values, color=["#6D597A", "#6D597A", "#2A9D8F", "#2A9D8F", "#BC4749", "#BC4749"])
    ax.set_title("Recovery and Approval Costs")
    ax.set_ylabel("Latency / Outage (ms)")
    ax.tick_params(axis="x", rotation=22)
    ax.grid(axis="y", alpha=0.25)
    save(fig, out_dir / "figure_atc_recovery.png")


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot single-run ATC results")
    parser.add_argument("--atc-dir", type=str, required=True)
    parser.add_argument("--output-dir", type=str, default="")
    args = parser.parse_args()

    atc_dir = Path(args.atc_dir)
    output_dir = Path(args.output_dir) if args.output_dir else atc_dir / "plots"
    ensure_dir(output_dir)
    plot_ablation(atc_dir, output_dir)
    plot_path_breakdown(atc_dir, output_dir)
    plot_path_cdf(atc_dir, output_dir)
    plot_recovery(atc_dir, output_dir)
    print(f"[done] atc_plots_dir={output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
