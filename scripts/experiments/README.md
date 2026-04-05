# Experiment Suite

`linux-mcp` 当前保留两条实验线：

1. `linux_mcp_eval.py`
   面向执行版实验设计的主评估，比较三套系统：
   - A: `userspace` baseline
   - B: `userspace + seccomp/simple-sandbox + logging + stricter checks`
   - C: `kernel_mcp`
2. `security_eval.py`
   保留原有更细粒度的 attack-driven 安全分析，用于机制级拆解和 userspace tamper profile 研究。

## Main Entry Points

主实验：

```bash
bash scripts/run_linux_mcp_evaluation.sh
```

多轮重复：

```bash
bash scripts/run_repeated_linux_mcp.sh
```

安全细分实验：

```bash
bash scripts/run_security_evaluation.sh
```

## `linux_mcp_eval.py` 覆盖内容

1. latency
   - 1000 次调用
   - payload: `small=100B`, `medium=10KB`, `large=1MB`
   - 输出 `avg / p50 / p95 / p99`
2. scalability
   - `agents = [1,5,10,20,50]`
   - `concurrency = [1,10,50,100]`
   - 每个 agent 100 次调用
   - 输出 throughput、latency、error rate
3. baseline comparison
   - 同一 workload 下比较 A/B/C
4. attack matrix
   - spoof
   - replay
   - substitute
   - escalation
5. budget/accounting
   - `max_calls = 50`
   - 超预算后拒绝
   - 输出 `budget_samples.csv` 和 budget 图

## 主要输出

- `linux_mcp_summary.json`
- `linux_mcp_report.md`
- `latency_samples.csv`
- `latency_summary.csv`
- `scalability_samples.csv`
- `scalability_summary.csv`
- `attack_samples.csv`
- `attack_matrix.csv`
- `plots/figure_latency_by_payload.png`
- `plots/figure_throughput_by_agents.png`
- `plots/figure_latency_by_concurrency.png`

## 当前 B 组说明

B 组现在实现为 `userspace_semantic_plane + simple sandboxed tool services + mcpd strict checks + audit logging`，不是完整 seccomp profile。

目前 simple sandbox 提供：

- tool service 进程 `no_new_privs`
- `RLIMIT_FSIZE` 文件大小上限
- 阻断 demo tool 内的外部 subprocess 启动
- 阻断 repo 外 `write_host_text_file`

这保证 B 组是一个真实可运行、可复现的 userspace sandbox 变体，但不应被表述成完整容器隔离或完整 seccomp 沙箱。
