# Experiment Suite

This directory contains a large-volume comparative experiment framework for linux-mcp.

## Files

- `benchmark_suite.py`: main benchmark runner
- `atc_eval.py`: ATC-oriented evaluation runner
- `render_report.py`: render `summary.json` to markdown
- `render_atc_report.py`: render `atc_summary.json` to markdown
- `aggregate_eval.py`: aggregate multiple benchmark runs into CSV tables and a detailed report
- `run_matrix.sh`: high-volume matrix runner
- `../run_experiment_suite.sh`: one-click run for a single benchmark campaign
- `../run_atc_evaluation.sh`: one-click run for an ATC-style evaluation campaign
- `../run_repeated_suite.sh`: repeated benchmark campaigns plus statistical aggregation

## What Is Compared

`benchmark_suite.py` runs multiple scenarios:

1. `direct_cX`: direct app endpoint RPC (baseline, bypass mcpd + kernel arbitration)
2. `mcpd_cX`: mcpd mediated execution path (includes session + kernel arbitration)
3. negative controls:
   - invalid session
   - invalid tool id
   - hash mismatch

The default concurrency sweep is `1,4,8,16,32`.

It answers three basic questions:

1. what is the fixed cost of mediated execution vs direct endpoint RPC
2. how throughput and tail latency evolve as concurrency increases
3. whether negative-control paths fail fast and deterministically

## ATC-Oriented Evaluation

`atc_eval.py` adds experiment groups that map more directly to a systems-paper evaluation:

1. end-to-end mediated overhead vs direct endpoint RPC
2. mcpd ablation runs:
   - `forwarder_only`: keep `mcpd` as a lookup/relay hop with minimal semantics
   - `userspace_semantic_plane`: preserve session/hash/approval semantics in `mcpd`, without kernel arbitration
3. fixed trace workloads:
   - mixed round-robin trace
   - hotspot trace
4. control-plane RPC latency for `list_apps`, `list_tools`, and `open_session`
5. safety/correctness controls, including approval-path behavior
6. policy-mix experiments as the high-risk request ratio increases
7. restart-recovery experiments under continuing request load
8. synthetic manifest-scale experiments for control-plane metadata growth
9. optional `reload_10x` stability check when run as root

The most important comparison group is now:

1. `direct`
2. `mcpd`
3. `forwarder_only`
4. `userspace_semantic_plane`

Interpretation:

- `direct` is the lower bound with no mediation
- `forwarder_only` measures the cost of keeping `mcpd` as a lookup + relay hop
- `userspace_semantic_plane` is the equivalent userspace baseline
- `mcpd` is the current full kernel-backed control plane path

Run it with:

```bash
bash scripts/run_atc_evaluation.sh
```

If services are already up, you can skip auto-start:

```bash
bash scripts/run_atc_evaluation.sh --skip-start
```

## Default Scale

Single campaign defaults:

- requests per scenario: 4000
- negative repeats: 500
- max validated tools: 20

Large matrix (`run_matrix.sh`) defaults:

- requests: 2000, 8000, 20000
- concurrency profiles: `1,4,8,16` / `1,8,16,32` / `1,16,32,64`
- negative repeats: 300, 800, 1500

Repeated suite (`run_repeated_suite.sh`) defaults:

- repeats: 5
- requests per scenario: 4000
- concurrency: `1,4,8,16,32`
- aggregate outputs: per-run raw summaries plus aggregate CSV/markdown tables

## Run Commands

Single campaign:

```bash
bash scripts/run_experiment_suite.sh
```

Single campaign with larger load:

```bash
bash scripts/run_experiment_suite.sh \
  --requests 12000 \
  --concurrency "1,8,16,32,64" \
  --negative-repeats 1200 \
  --max-tools 24
```

Large matrix campaign:

```bash
bash scripts/experiments/run_matrix.sh
```

Repeated benchmark campaign with aggregation:

```bash
bash scripts/run_repeated_suite.sh
```

ATC smoke run:

```bash
bash scripts/run_atc_evaluation.sh \
  --skip-start \
  --skip-reload-10x \
  --requests 200 \
  --trace-requests 50 \
  --policy-requests 50 \
  --restart-requests 50 \
  --restart-after 10 \
  --negative-repeats 20 \
  --approval-repeats 10 \
  --rpc-repeats 20 \
  --scale-repeats 2 \
  --concurrency "1,4" \
  --manifest-scales "1,2" \
  --max-tools 8
```

## Output Layout

Each run writes to:

- `experiment-results/run-<timestamp>/summary.json`
- `experiment-results/run-<timestamp>/report.md`
- `experiment-results/run-<timestamp>/<scenario>.csv`

For matrix runs:

- `experiment-results/matrix/run-<timestamp>/...`

For repeated runs:

- `experiment-results/repeated-suite/run-<timestamp>/raw/run-<timestamp>/...`
- `experiment-results/repeated-suite/run-<timestamp>/aggregate/detailed_report.md`
- `experiment-results/repeated-suite/run-<timestamp>/aggregate/*.csv`

For ATC runs:

- `experiment-results/atc/run-<timestamp>/atc_summary.json`
- `experiment-results/atc/run-<timestamp>/atc_report.md`
- `experiment-results/atc/run-<timestamp>/e2e_summaries.csv`
- `experiment-results/atc/run-<timestamp>/variant_summaries.csv`
- `experiment-results/atc/run-<timestamp>/trace_results.csv`
- `experiment-results/atc/run-<timestamp>/policy_mix.csv`
- `experiment-results/atc/run-<timestamp>/control_plane_rpcs.csv`
- `experiment-results/atc/run-<timestamp>/negative_controls.csv`
- `experiment-results/atc/run-<timestamp>/approval_path.csv`
- `experiment-results/atc/run-<timestamp>/restart_recovery.csv`
- `experiment-results/atc/run-<timestamp>/manifest_scale.csv`
- `experiment-results/atc/run-<timestamp>/derived_metrics.csv`
- `experiment-results/atc/run-<timestamp>/selected_tools.csv`

## Notes

- Start scripts are auto-invoked by `run_experiment_suite.sh` unless `--skip-start` is passed.
- Start scripts are auto-invoked by `run_atc_evaluation.sh` unless `--skip-start` is passed.
- By default, write/mutation tools are excluded. Add `--include-write-tools` to include them.
- Tool selection is preflight-validated through both direct and mcpd paths to keep comparisons fair.
- `reload_10x` requires root; otherwise ATC output will mark it as skipped.
