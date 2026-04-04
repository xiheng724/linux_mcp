#!/usr/bin/env python3
"""Plot aggregated repeated security results."""

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


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def save(fig: plt.Figure, out_path: Path) -> None:
    fig.tight_layout()
    fig.savefig(out_path, dpi=220, bbox_inches="tight")
    plt.close(fig)


def plot_attack_and_semantic(agg_dir: Path, out_dir: Path) -> None:
    attack = load_csv(agg_dir / "security_attack_aggregate.csv")
    semantic = load_csv(agg_dir / "security_semantic_aggregate.csv")
    fig, axes = plt.subplots(1, 2, figsize=(12.2, 4.6))
    focus_modes = ["mcpd", "userspace_semantic_plane", "userspace_tamper_approval", "userspace_tamper_metadata", "userspace_tamper_session"]
    groups = ["A", "B", "C", "D", "E"]
    x = list(range(len(groups)))
    width = 0.16
    for idx, mode in enumerate(focus_modes):
        vals = []
        for group in groups:
            rows = [row for row in attack if row["mode"] == mode and row["scenario_group"] == group]
            vals.append(sum(f(row["bypass_success_rate_mean"]) for row in rows) / len(rows) * 100.0 if rows else 0.0)
        axes[0].bar([v + (idx - 2) * width for v in x], vals, width=width, label=mode)
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(groups)
    axes[0].set_title("Repeated Attack Success")
    axes[0].set_ylabel("Bypass Success Rate (%)")
    axes[0].grid(axis="y", alpha=0.25)
    axes[0].legend(frameon=False, fontsize=8)

    if semantic:
        item = semantic[0]
        labels = ["precision", "recall", "FPR", "FNR", "bypass"]
        vals = [
            f(item["precision_mean"]) * 100.0,
            f(item["recall_mean"]) * 100.0,
            f(item["false_positive_rate_mean"]) * 100.0,
            f(item["false_negative_rate_mean"]) * 100.0,
            f(item["bypass_success_rate_mean"]) * 100.0,
        ]
        axes[1].bar(labels, vals, color=["#355070", "#6D597A", "#E56B6F", "#E56B6F", "#BC4749"])
    axes[1].set_title("Repeated Semantic Detector Quality")
    axes[1].set_ylabel("Rate (%)")
    axes[1].grid(axis="y", alpha=0.25)
    save(fig, out_dir / "figure_repeated_security_attack_semantic.png")


def plot_daemon_and_mixed(agg_dir: Path, out_dir: Path) -> None:
    daemon = load_csv(agg_dir / "security_daemon_aggregate.csv")
    mixed = load_csv(agg_dir / "security_mixed_aggregate.csv")
    fig, axes = plt.subplots(1, 2, figsize=(12.2, 4.6))
    if daemon:
        labels = [row["mode"] for row in daemon]
        approval = [f(row["approval_state_preserved_mean"]) * 100.0 for row in daemon]
        visibility = [f(row["post_crash_agent_visible_mean"]) * 100.0 for row in daemon]
        x = list(range(len(labels)))
        axes[0].bar([v - 0.18 for v in x], approval, width=0.36, label="approval state preserved")
        axes[0].bar([v + 0.18 for v in x], visibility, width=0.36, label="post-crash visibility")
        axes[0].set_xticks(x)
        axes[0].set_xticklabels(labels)
        axes[0].set_title("Repeated Daemon Crash Recovery")
        axes[0].set_ylabel("Rate (%)")
        axes[0].grid(axis="y", alpha=0.25)
        axes[0].legend(frameon=False)

    focus_modes = ["mcpd", "userspace_semantic_plane", "userspace_compromised"]
    for mode in focus_modes:
        rows = sorted((row for row in mixed if row["mode"] == mode), key=lambda row: int(row["malicious_pct"]))
        xs = [int(row["malicious_pct"]) for row in rows]
        acceptance = [f(row["attack_acceptance_rate_mean"]) * 100.0 for row in rows]
        axes[1].plot(xs, acceptance, marker="o", linewidth=2.0, label=mode)
    axes[1].set_title("Repeated Mixed-Attack Acceptance")
    axes[1].set_xlabel("Malicious Requests (%)")
    axes[1].set_ylabel("Attack Acceptance Rate (%)")
    axes[1].grid(alpha=0.25)
    axes[1].legend(frameon=False)
    save(fig, out_dir / "figure_repeated_security_daemon_mixed.png")


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot repeated security aggregates")
    parser.add_argument("--aggregate-dir", required=True)
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    agg_dir = Path(args.aggregate_dir)
    out_dir = Path(args.output_dir) if args.output_dir else agg_dir / "plots"
    ensure_dir(out_dir)
    plot_attack_and_semantic(agg_dir, out_dir)
    plot_daemon_and_mixed(agg_dir, out_dir)
    print(f"[done] repeated_security_plots_dir={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
