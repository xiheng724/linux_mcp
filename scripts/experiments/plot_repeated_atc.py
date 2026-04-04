#!/usr/bin/env python3
"""Plot repeated ATC aggregate outputs."""

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


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot repeated ATC aggregates")
    parser.add_argument("--aggregate-dir", required=True)
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    agg_dir = Path(args.aggregate_dir)
    out_dir = Path(args.output_dir) if args.output_dir else agg_dir / "plots"
    ensure_dir(out_dir)

    e2e = load_csv(agg_dir / "atc_e2e_aggregate.csv")
    variants = load_csv(agg_dir / "atc_variant_aggregate.csv")
    by_mode: dict[str, list[dict[str, str]]] = {}
    for row in e2e:
        by_mode.setdefault(row["mode"], []).append(row)
    for row in variants:
        by_mode.setdefault(row["variant"], []).append(
            {
                "concurrency": row["concurrency"],
                "throughput_rps_mean": row["throughput_rps_mean"],
                "latency_p95_ms_mean": row["latency_p95_ms_mean"],
            }
        )
    for items in by_mode.values():
        items.sort(key=lambda row: i(row["concurrency"]))

    fig, axes = plt.subplots(1, 2, figsize=(12.0, 4.4))
    ordered = ["direct", "mcpd", "forwarder_only", "userspace_semantic_plane"]
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
        thr = [f(row["throughput_rps_mean"]) for row in items]
        p95 = [f(row["latency_p95_ms_mean"]) for row in items]
        axes[0].plot(xs, thr, marker="o", linewidth=2.2, label=mode, color=colors.get(mode))
        axes[1].plot(xs, p95, marker="o", linewidth=2.2, label=mode, color=colors.get(mode))
    axes[0].set_title("Repeated ATC Throughput")
    axes[0].set_xlabel("Concurrency")
    axes[0].set_ylabel("Mean Throughput (req/s)")
    axes[1].set_title("Repeated ATC p95 Latency")
    axes[1].set_xlabel("Concurrency")
    axes[1].set_ylabel("Mean p95 (ms)")
    for ax in axes:
        ax.grid(alpha=0.25)
    axes[0].legend(frameon=False)
    save(fig, out_dir / "figure_repeated_atc.png")
    print(f"[done] repeated_atc_plots_dir={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
