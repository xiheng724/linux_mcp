# Experiment Suite

`linux-mcp` 现在保留两条主实验线：

1. `security_eval.py`
   attack-driven 安全评估，重点比较 kernel-backed control plane、equivalent userspace semantic plane，以及被显式 tamper 的 userspace baseline。
2. `atc_eval.py`
   论文导向综合评估，覆盖性能、机制级对照、approval path、恢复、扩展性和路径级 latency 分解。

配套保留两个 repeated wrapper：

- `scripts/run_repeated_atc.sh`
- `scripts/run_repeated_security.sh`

旧的 benchmark-only 入口、matrix wrapper、全局 plot 汇总脚本和历史 smoke/debug 结果已经删除，避免和新的 ATC/security 口径重复、结论冲突。

## Files

- `benchmark_suite.py`
  共享实验库，提供 manifest 预检、direct/mcpd 请求驱动、基础 latency 汇总等通用能力。
- `atc_eval.py`
  综合评估 runner。
- `render_atc_report.py`
  将 `atc_summary.json` 渲染成 markdown。
- `plot_atc_results.py`
  为单次 ATC run 生成 figure，包括 ablation、path breakdown、CDF、recovery 图。
- `aggregate_atc_runs.py`
  聚合 repeated ATC runs。
- `security_eval.py`
  attack-driven 安全评估 runner。
- `plot_security_results.py`
  生成安全实验图，包括 attack success、detection latency、mixed attack、semantic+ablation、recovery+observability。

## Security Evaluation

入口：

```bash
bash scripts/run_security_evaluation.sh
```

如果服务已经启动：

```bash
bash scripts/run_security_evaluation.sh --skip-start
```

当前覆盖：

1. identity spoofing
   - fake session id
   - expired session
   - session token theft
2. approval replay / forgery
   - forged approval ticket
   - cross-agent replay
   - cross-tool replay
   - delayed replay
   - denied-ticket replay
3. semantic tampering
   - live metadata tampering
   - offline semantic fingerprint precision / recall
4. daemon compromise
   - compromised userspace baseline
   - daemon crash / approval-state preservation 对比
5. TOCTOU
   - approve 后 hash mismatch
   - approve 后 tool swap
6. mechanism ablation
   - agent binding
   - approval token
   - semantic hash
   - kernel state
7. observability
   - independent audit
   - state introspection
   - post-crash visibility

主要输出：

- `security_summary.json`
- `attack_rows.csv`
- `attack_summary.csv`
- `semantic_tampering.csv`
- `semantic_summary.csv`
- `daemon_compromise.csv`
- `mechanism_ablation.csv`
- `observability.csv`
- `mixed_attack.csv`
- `security_report.md`
- `plots/figure_security_*.png`

## ATC Evaluation

入口：

```bash
bash scripts/run_atc_evaluation.sh
```

如果服务已经启动：

```bash
bash scripts/run_atc_evaluation.sh --skip-start
```

当前覆盖：

1. end-to-end direct vs mediated comparison
2. `forwarder_only` / `userspace_semantic_plane` ablation
3. trace workloads
4. control-plane RPC latency
5. allow / defer / deny path breakdown
6. arbitration / kernel round-trip timing
7. approval path
8. policy mix
9. daemon restart recovery
10. tool-service restart recovery
11. manifest scale
12. optional `reload_10x`

主要输出：

- `atc_summary.json`
- `atc_report.md`
- `e2e_summaries.csv`
- `variant_summaries.csv`
- `trace_results.csv`
- `policy_mix.csv`
- `control_plane_rpcs.csv`
- `path_breakdown.csv`
- `path_breakdown_raw.csv`
- `negative_controls.csv`
- `approval_path.csv`
- `restart_recovery.csv`
- `tool_service_recovery.csv`
- `manifest_scale.csv`
- `derived_metrics.csv`
- `selected_tools.csv`
- `plots/figure_atc_*.png`

ATC smoke：

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

## Repeated ATC

入口：

```bash
bash scripts/run_repeated_atc.sh
```

输出：

- `experiment-results/atc-repeat/run-<timestamp>/raw/run-<timestamp>/...`
- `experiment-results/atc-repeat/run-<timestamp>/aggregate/atc_e2e_aggregate.csv`
- `experiment-results/atc-repeat/run-<timestamp>/aggregate/atc_variant_aggregate.csv`
- `experiment-results/atc-repeat/run-<timestamp>/aggregate/repeated_atc_report.md`

## Repeated Security

入口：

```bash
bash scripts/run_repeated_security.sh
```

输出：

- `experiment-results/security-repeat/run-<timestamp>/raw/run-<timestamp>/...`
- `experiment-results/security-repeat/run-<timestamp>/aggregate/security_attack_aggregate.csv`
- `experiment-results/security-repeat/run-<timestamp>/aggregate/security_semantic_aggregate.csv`
- `experiment-results/security-repeat/run-<timestamp>/aggregate/security_daemon_aggregate.csv`
- `experiment-results/security-repeat/run-<timestamp>/aggregate/security_mixed_aggregate.csv`
- `experiment-results/security-repeat/run-<timestamp>/aggregate/security_ablation_aggregate.csv`
- `experiment-results/security-repeat/run-<timestamp>/aggregate/repeated_security_report.md`

## Interpretation Boundaries

- 安全实验支持的强结论是 control-plane enforcement、spoofing/replay/tampering resistance、以及 kernel-held approval state 在 daemon crash 后仍可被重放验证。
- 它们不支持 “execution is protected” 或 “prevents all attacks” 之类的过强 claim。
- daemon crash 实验会明确展示一个 falsifiable 限制：
  kernel approval state 可保留，但 userspace session 仍会在 daemon restart 后丢失。
