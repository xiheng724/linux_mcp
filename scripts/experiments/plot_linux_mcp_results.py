#!/usr/bin/env python3
"""Plot linux_mcp evaluation outputs."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List

import matplotlib.pyplot as plt


def load_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _float(row: Dict[str, str], key: str) -> float:
    try:
        return float(row.get(key, "0") or 0.0)
    except ValueError:
        return 0.0


def _ordered_systems(rows: List[Dict[str, str]]) -> List[str]:
    preferred = ["userspace", "seccomp", "kernel"]
    present = {row.get("system", "") for row in rows}
    return [name for name in preferred if name in present]


def plot_latency_bars(summary_rows: List[Dict[str, str]], out_path: Path) -> None:
    ordered_systems = _ordered_systems(summary_rows)
    ordered_payloads = ["small", "medium", "large"]
    colors = {"userspace": "#C1666B", "seccomp": "#5C80BC", "kernel": "#2D6A4F"}
    x = list(range(len(ordered_payloads)))
    width = 0.22 if len(ordered_systems) >= 3 else 0.32
    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    for idx, system in enumerate(ordered_systems):
        system_rows = {row["payload_label"]: row for row in summary_rows if row.get("system") == system}
        ys = [_float(system_rows.get(payload, {}), "latency_p95_ms") for payload in ordered_payloads]
        offsets = [value + (idx - (len(ordered_systems) - 1) / 2) * width for value in x]
        ax.bar(offsets, ys, width=width, label=system, color=colors.get(system, "#666666"))
    ax.set_xticks(x, ordered_payloads)
    ax.set_ylabel("p95 latency (ms)")
    ax.set_title("Latency by Payload Size")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def plot_latency_overhead(summary_rows: List[Dict[str, str]], out_path: Path) -> None:
    ordered_payloads = ["small", "medium", "large"]
    baseline = {row["payload_label"]: row for row in summary_rows if row.get("system") == "userspace"}
    comparison_systems = [system for system in _ordered_systems(summary_rows) if system != "userspace"]
    colors = {"seccomp": "#5C80BC", "kernel": "#2D6A4F"}
    x = list(range(len(ordered_payloads)))
    width = 0.28 if len(comparison_systems) >= 2 else 0.42
    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    ax.axhline(1.0, color="#444444", linewidth=1.2, linestyle="--")
    for idx, system in enumerate(comparison_systems):
        system_rows = {row["payload_label"]: row for row in summary_rows if row.get("system") == system}
        ys = []
        for payload in ordered_payloads:
            base = _float(baseline.get(payload, {}), "latency_p95_ms")
            current = _float(system_rows.get(payload, {}), "latency_p95_ms")
            ys.append(current / base if base > 0 else 0.0)
        offsets = [value + (idx - (len(comparison_systems) - 1) / 2) * width for value in x]
        ax.bar(offsets, ys, width=width, label=f"{system} / userspace", color=colors.get(system, "#666666"))
    ax.set_xticks(x, ordered_payloads)
    ax.set_ylabel("relative p95 latency")
    ax.set_title("Latency Overhead Relative to Userspace Baseline")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def plot_scalability(summary_rows: List[Dict[str, str]], out_path: Path) -> None:
    ordered_systems = _ordered_systems(summary_rows)
    agent_values = sorted({int(row["agents"]) for row in summary_rows if row.get("concurrency") == "100"})
    colors = {"userspace": "#C1666B", "seccomp": "#5C80BC", "kernel": "#2D6A4F"}
    x = list(range(len(agent_values)))
    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    for system in ordered_systems:
        rows = {
            int(row["agents"]): row
            for row in summary_rows
            if row.get("system") == system and row.get("concurrency") == "100"
        }
        ys = [_float(rows.get(agent, {}), "throughput_rps") for agent in agent_values]
        ax.plot(x, ys, marker="o", linewidth=2.4, markersize=6, label=system, color=colors.get(system, "#666666"))
    ax.set_xticks(x, [str(agent) for agent in agent_values])
    ax.set_xlabel("agents")
    ax.set_ylabel("throughput (ops/sec)")
    ax.set_title("Throughput at High Concurrency (100)")
    ax.grid(alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def plot_attack_heatmap(rows: List[Dict[str, str]], out_path: Path) -> None:
    systems = _ordered_systems(rows)
    attack_types = ["spoof", "replay", "substitute", "escalation"]
    values: List[List[float]] = []
    labels: List[List[str]] = []
    for attack in attack_types:
        row_values: List[float] = []
        row_labels: List[str] = []
        for system in systems:
            match = next((item for item in rows if item.get("attack_type") == attack and item.get("system") == system), {})
            success_rate = _float(match, "success_rate")
            row_values.append(success_rate)
            row_labels.append("FAIL" if success_rate == 0.0 else f"{success_rate * 100:.0f}%")
        values.append(row_values)
        labels.append(row_labels)
    fig, ax = plt.subplots(figsize=(7.6, 4.6))
    image = ax.imshow(values, cmap="RdYlGn_r", vmin=0.0, vmax=1.0, aspect="auto")
    ax.set_xticks(range(len(systems)), systems)
    ax.set_yticks(range(len(attack_types)), attack_types)
    ax.set_title("Attack Success Rate")
    for row_idx, row_labels in enumerate(labels):
        for col_idx, label in enumerate(row_labels):
            ax.text(col_idx, row_idx, label, ha="center", va="center", color="#111111", fontsize=10, fontweight="bold")
    colorbar = fig.colorbar(image, ax=ax)
    colorbar.set_label("success rate")
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def plot_budget(rows: List[Dict[str, str]], out_path: Path) -> None:
    if not rows:
        return
    systems = _ordered_systems(rows)
    colors = {"userspace": "#C1666B", "seccomp": "#5C80BC", "kernel": "#2D6A4F"}
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.6))
    for system in systems:
        system_rows = [row for row in rows if row.get("system") == system]
        xs = [_float(row, "elapsed_ms") for row in system_rows]
        allows = [_float(row, "allowed_so_far") for row in system_rows]
        usage = [_float(row, "budget_usage_pct") for row in system_rows]
        axes[0].plot(xs, allows, linewidth=2.2, label=system, color=colors.get(system, "#666666"))
        axes[1].plot(xs, usage, linewidth=2.2, label=system, color=colors.get(system, "#666666"))
    axes[0].set_title("Calls vs Time")
    axes[0].set_xlabel("elapsed time (ms)")
    axes[0].set_ylabel("allowed calls")
    axes[0].grid(alpha=0.25)
    axes[1].set_title("Budget Usage")
    axes[1].set_xlabel("elapsed time (ms)")
    axes[1].set_ylabel("budget usage (%)")
    axes[1].axhline(100.0, color="#444444", linestyle="--", linewidth=1.2)
    axes[1].grid(alpha=0.25)
    axes[1].legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot linux_mcp evaluation outputs")
    parser.add_argument("--run-dir", type=str, required=True)
    parser.add_argument("--output-dir", type=str)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    output_dir = Path(args.output_dir) if args.output_dir else run_dir / "plots"
    output_dir.mkdir(parents=True, exist_ok=True)

    latency_rows = load_csv(run_dir / "latency_summary.csv")
    scalability_rows = load_csv(run_dir / "scalability_summary.csv")
    attack_rows = load_csv(run_dir / "attack_matrix.csv")
    budget_rows = load_csv(run_dir / "budget_samples.csv")

    plot_latency_bars(latency_rows, output_dir / "figure_latency_by_payload.png")
    plot_latency_overhead(latency_rows, output_dir / "figure_latency_overhead.png")
    plot_scalability(scalability_rows, output_dir / "figure_throughput_by_agents.png")
    plot_attack_heatmap(attack_rows, output_dir / "figure_attack_heatmap.png")
    plot_budget(budget_rows, output_dir / "figure_budget_usage.png")
    print(f"[done] plots_dir={output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
