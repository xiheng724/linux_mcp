#!/usr/bin/env python3
"""Generate Phase 5 benchmark plots (matplotlib only)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def load_results(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="infile", required=True)
    parser.add_argument("--outdir", default="plots")
    args = parser.parse_args()

    in_path = Path(args.infile)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    data = load_results(in_path)
    agents: List[Dict[str, Any]] = data.get("agents", [])
    if not agents:
        print("no agent data found in results")
        return 1

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:  # noqa: BLE001
        print(f"matplotlib unavailable: {exc}")
        print("install hint: sudo apt-get install python3-matplotlib")
        return 0

    ids = [a["agent_id"] for a in agents]
    throughput = [float(a["throughput_ops_s"]) for a in agents]
    p95 = [float(a["latency_end_to_end_ms"]["p95"]) for a in agents]
    allow_counts = [int(a["sysfs"]["allow"]) for a in agents]
    fairness_cv = float(data.get("fairness", {}).get("allow_cv", 0.0))

    plt.figure(figsize=(10, 4))
    plt.bar(ids, throughput, color="#2a9d8f")
    plt.title("Per-Agent Throughput")
    plt.xlabel("Agent")
    plt.ylabel("Successful executions / sec")
    plt.tight_layout()
    throughput_path = outdir / "throughput.png"
    plt.savefig(throughput_path, dpi=120)
    plt.close()

    plt.figure(figsize=(10, 4))
    plt.bar(ids, p95, color="#e76f51")
    plt.title("Per-Agent End-to-End Latency p95")
    plt.xlabel("Agent")
    plt.ylabel("Latency (ms)")
    plt.tight_layout()
    latency_path = outdir / "latency_p95.png"
    plt.savefig(latency_path, dpi=120)
    plt.close()

    plt.figure(figsize=(10, 4))
    plt.bar(ids, allow_counts, color="#264653")
    plt.title(f"Fairness (ALLOW counts), CV={fairness_cv:.4f}")
    plt.xlabel("Agent")
    plt.ylabel("ALLOW count (sysfs)")
    plt.tight_layout()
    fairness_path = outdir / "fairness.png"
    plt.savefig(fairness_path, dpi=120)
    plt.close()

    print(f"generated: {throughput_path}")
    print(f"generated: {latency_path}")
    print(f"generated: {fairness_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

