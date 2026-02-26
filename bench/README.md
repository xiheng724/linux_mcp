# bench

Benchmark drivers and harness scripts.

## Quick Benchmark (Phase 5)

Prerequisites:
- Kernel module loaded
- `mcpd` running on `/tmp/mcpd.sock`
- Client binaries built (`make -C client`, outputs in `client/bin/`)

Run benchmark:

```bash
python3 bench/bench_runner.py --agents 10 --requests 50 --tool cpu_burn --burn-ms 50 --out results/phase5_run.json
```

Generate plots:

```bash
python3 bench/plot_results.py --in results/phase5_run.json --outdir plots
```

Generated artifacts:
- `results/phase5_run.json`: machine-readable per-request and per-agent metrics
- `plots/throughput.png`
- `plots/latency_p95.png`
- `plots/fairness.png`

Key metrics:
- Throughput: successful executions per second per agent
- Latency: end-to-end p50/p95/p99 (includes DEFER retries)
- Fairness: coefficient of variation (`std/mean`) of per-agent ALLOW counts
