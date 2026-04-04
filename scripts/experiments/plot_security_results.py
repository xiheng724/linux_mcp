#!/usr/bin/env python3
"""Plot security evaluation outputs."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def attack_success_plot(rows: list[dict[str, str]], out_path: Path) -> None:
    focus_modes = ["mcpd", "userspace_semantic_plane", "userspace_compromised"]
    focus_groups = ["A", "B", "C", "D"]
    series: dict[str, list[float]] = {mode: [] for mode in focus_modes}
    for group in focus_groups:
        group_rows = [row for row in rows if row["scenario_group"] == group]
        for mode in focus_modes:
            mode_rows = [row for row in group_rows if row["mode"] == mode]
            if mode_rows:
                value = sum(float(row["bypass_success_rate"]) for row in mode_rows) / len(mode_rows)
            else:
                value = 0.0
            series[mode].append(value * 100.0)
    x = list(range(len(focus_groups)))
    width = 0.25
    fig, ax = plt.subplots(figsize=(9, 4.5))
    for idx, mode in enumerate(focus_modes):
        ax.bar([v + (idx - 1) * width for v in x], series[mode], width=width, label=mode)
    ax.set_xticks(x)
    ax.set_xticklabels([f"Attack {group}" for group in focus_groups])
    ax.set_ylabel("Attack Success Rate (%)")
    ax.set_title("Security Attacks: Kernel-Backed vs Userspace Baselines")
    ax.legend()
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def detection_latency_plot(rows: list[dict[str, str]], out_path: Path) -> None:
    focus_modes = ["mcpd", "userspace_semantic_plane", "userspace_compromised"]
    focus_groups = ["A", "B", "C", "D"]
    x = list(range(len(focus_groups)))
    width = 0.25
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    for idx, mode in enumerate(focus_modes):
        detection_vals = []
        latency_vals = []
        for group in focus_groups:
            group_rows = [row for row in rows if row["scenario_group"] == group and row["mode"] == mode]
            if group_rows:
                detection_vals.append(sum(float(row["detection_rate"]) for row in group_rows) / len(group_rows) * 100.0)
                latency_vals.append(sum(float(row["reject_latency_p95_ms"]) for row in group_rows) / len(group_rows))
            else:
                detection_vals.append(0.0)
                latency_vals.append(0.0)
        axes[0].bar([v + (idx - 1) * width for v in x], detection_vals, width=width, label=mode)
        axes[1].bar([v + (idx - 1) * width for v in x], latency_vals, width=width, label=mode)
    for ax, title, ylabel in (
        (axes[0], "Detection Rate", "Detection Rate (%)"),
        (axes[1], "Reject Latency", "Reject p95 (ms)"),
    ):
        ax.set_xticks(x)
        ax.set_xticklabels([f"Attack {group}" for group in focus_groups])
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.grid(axis="y", alpha=0.25)
    axes[0].legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def mixed_attack_plot(rows: list[dict[str, str]], out_path: Path) -> None:
    focus_modes = ["mcpd", "userspace_semantic_plane", "userspace_compromised"]
    malicious_pcts = sorted({int(row["malicious_pct"]) for row in rows})
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.2))
    for mode in focus_modes:
        mode_rows = {int(row["malicious_pct"]): row for row in rows if row["mode"] == mode}
        xs = malicious_pcts
        throughput = [float(mode_rows[p]["legit_throughput_rps"]) if p in mode_rows else 0.0 for p in xs]
        p95 = [float(mode_rows[p]["legit_p95_ms"]) if p in mode_rows else 0.0 for p in xs]
        acceptance = [float(mode_rows[p]["attack_acceptance_rate"]) * 100.0 if p in mode_rows else 0.0 for p in xs]
        axes[0].plot(xs, throughput, marker="o", label=mode)
        axes[1].plot(xs, p95, marker="o", label=mode)
        axes[2].plot(xs, acceptance, marker="o", label=mode)
    axes[0].set_title("Legitimate Throughput")
    axes[0].set_ylabel("Throughput (rps)")
    axes[1].set_title("Legitimate Tail Latency")
    axes[1].set_ylabel("p95 (ms)")
    axes[2].set_title("Attack Acceptance")
    axes[2].set_ylabel("Acceptance Rate (%)")
    for ax in axes:
        ax.set_xlabel("Malicious Requests (%)")
        ax.grid(alpha=0.25)
    axes[0].legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def semantic_and_ablation_plot(
    semantic_rows: list[dict[str, str]],
    ablation_rows: list[dict[str, str]],
    out_path: Path,
) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.4))
    if semantic_rows:
        item = semantic_rows[0]
        labels = ["precision", "recall", "FPR", "FNR", "bypass"]
        values = [
            float(item.get("precision", 0.0)) * 100.0,
            float(item.get("recall", 0.0)) * 100.0,
            float(item.get("false_positive_rate", 0.0)) * 100.0,
            float(item.get("false_negative_rate", 0.0)) * 100.0,
            float(item.get("bypass_success_rate", 0.0)) * 100.0,
        ]
        axes[0].bar(labels, values, color=["#355070", "#6D597A", "#E56B6F", "#E56B6F", "#BC4749"])
        axes[0].set_title("Semantic Tampering Detector")
        axes[0].set_ylabel("Rate (%)")
        axes[0].grid(axis="y", alpha=0.25)
    if ablation_rows:
        labels = [row["mechanism"] for row in ablation_rows]
        deltas = [float(row.get("delta", 0.0)) * 100.0 for row in ablation_rows]
        axes[1].bar(labels, deltas, color="#588157")
        axes[1].set_title("Mechanism Contribution")
        axes[1].set_ylabel("Attack Success Delta (%)")
        axes[1].tick_params(axis="x", rotation=22)
        axes[1].grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def daemon_and_observability_plot(
    daemon_rows: list[dict[str, str]],
    observability_rows: list[dict[str, str]],
    out_path: Path,
) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.4))
    if daemon_rows:
        labels = [row["mode"] for row in daemon_rows]
        approval = [float(row.get("approval_state_preserved", 0.0)) * 100.0 for row in daemon_rows]
        visibility = [float(row.get("post_crash_agent_visible", 0.0)) * 100.0 for row in daemon_rows]
        x = list(range(len(labels)))
        axes[0].bar([v - 0.18 for v in x], approval, width=0.36, label="approval state preserved")
        axes[0].bar([v + 0.18 for v in x], visibility, width=0.36, label="post-crash visibility")
        axes[0].set_xticks(x)
        axes[0].set_xticklabels(labels)
        axes[0].set_title("Daemon Crash Recovery")
        axes[0].set_ylabel("Rate (%)")
        axes[0].grid(axis="y", alpha=0.25)
        axes[0].legend(frameon=False)
    if observability_rows:
        labels = [row["mode"] for row in observability_rows]
        audit = [float(row.get("independent_audit", 0.0)) * 100.0 for row in observability_rows]
        introspection = [float(row.get("state_introspection", 0.0)) * 100.0 for row in observability_rows]
        root_cause = [float(row.get("root_cause_success_rate", 0.0)) * 100.0 for row in observability_rows]
        x = list(range(len(labels)))
        axes[1].plot(x, audit, marker="o", linewidth=2.0, label="independent audit")
        axes[1].plot(x, introspection, marker="s", linewidth=2.0, label="state introspection")
        axes[1].plot(x, root_cause, marker="^", linewidth=2.0, label="root-cause success")
        axes[1].set_xticks(x)
        axes[1].set_xticklabels(labels)
        axes[1].set_title("Observability")
        axes[1].set_ylabel("Rate (%)")
        axes[1].grid(alpha=0.25)
        axes[1].legend(frameon=False)
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot security evaluation results")
    parser.add_argument("--security-dir", type=str, required=True)
    parser.add_argument("--output-dir", type=str, default="experiment-results/plots")
    args = parser.parse_args()

    security_dir = Path(args.security_dir)
    output_dir = Path(args.output_dir)
    ensure_dir(output_dir)
    attack_rows = load_csv(security_dir / "attack_summary.csv")
    mixed_rows = load_csv(security_dir / "mixed_attack.csv")
    semantic_rows = load_csv(security_dir / "semantic_summary.csv") if (security_dir / "semantic_summary.csv").exists() else []
    daemon_rows = load_csv(security_dir / "daemon_compromise.csv") if (security_dir / "daemon_compromise.csv").exists() else []
    observability_rows = load_csv(security_dir / "observability.csv") if (security_dir / "observability.csv").exists() else []
    ablation_rows = load_csv(security_dir / "mechanism_ablation.csv") if (security_dir / "mechanism_ablation.csv").exists() else []

    attack_success_plot(attack_rows, output_dir / "figure_security_attack_success.png")
    detection_latency_plot(attack_rows, output_dir / "figure_security_detection_latency.png")
    mixed_attack_plot(mixed_rows, output_dir / "figure_security_mixed_attack.png")
    semantic_and_ablation_plot(semantic_rows, ablation_rows, output_dir / "figure_security_semantic_ablation.png")
    daemon_and_observability_plot(daemon_rows, observability_rows, output_dir / "figure_security_recovery_observability.png")
    print(f"[done] security_plots_dir={output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
