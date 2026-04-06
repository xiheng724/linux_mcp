# Experiment Suite

`linux-mcp` 当前保留四类实验入口：

1. `linux_mcp_eval.py`
   面向执行版实验设计的主评估，比较三套系统：
   - A: `userspace` baseline
   - B: `userspace + seccomp/simple-sandbox + logging + stricter checks`
   - C: `kernel_mcp`
2. `security_eval.py`
   保留原有更细粒度的 attack-driven 安全分析，用于机制级拆解和 userspace tamper profile 研究。
3. `netlink_microbench.py`
   面向 Generic Netlink 往返延迟的 microbenchmark，用来拆分纯通信开销和 registry lookup 开销。
4. `semantic_hash_prompt_injection_eval.py`
   面向 prompt injection 相关 runtime substitution 的补充实验，用来测受污染 prompt 下 planning 的实际选择，以及同一条执行链如何在 kernel 阶段被 semantic hash 检查截断。

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

Generic Netlink microbenchmark：

```bash
bash scripts/run_netlink_microbenchmark.sh
```

Semantic hash prompt injection：

```bash
bash scripts/run_semantic_hash_prompt_injection.sh
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

## `netlink_microbench.py` 覆盖内容

1. bare RTT
   - `TOOL_REQUEST` 走 benchmark fast path
   - 不做 tool/agent lookup
   - 输出 `netlink_rtt_bare_ms`
2. full RTT
   - `TOOL_REQUEST` 走正常 kernel 路径
   - 包含 xarray/hashtable lookup 和 binding 校验
   - 输出 `netlink_rtt_full_ms`
3. derived metrics
   - `lookup_overhead_ms = full - bare`

主要输出：

- `netlink_microbench_summary.json`
- `netlink_microbench_report.md`
- `netlink_microbench_summary.csv`
- `netlink_microbench_samples.csv`
- `netlink_lookup_overhead_samples.csv`
- `plots/figure_netlink_rtt_boxplot.png`
- `plots/figure_netlink_rtt_ordered.png`
- `plots/figure_lookup_overhead_hist.png`

## `semantic_hash_prompt_injection_eval.py` 覆盖内容

1. planning under injection
   - 对受污染 prompt 调用 `llm-app` 的 `build_execution_plan()`
   - 统计 planner 是否仍产出有效 plan，以及是否仍落在合法 `notes_app` 工具上
   - 这一步只提供上下文，不用于证明 LLM 本身有抗注入能力
2. kernel-stage runtime substitution cutoff
   - 先基于真实 catalog 生成合法 plan，并沿正常 `execute_plan()` 路径构造 `tool:exec`
   - 在真正发送请求前通过 `request_mutator` 强行替换 `tool_hash`
   - 使用结构化返回字段 `decision=DENY` 且 `reason=hash_mismatch` 统计 kernel 拦截率
   - 这一步测试的是同一条 planning -> execution 链在 runtime substitution 下是否会被 kernel 截断

主要输出：

- `semantic_hash_prompt_injection_summary.json`
- `semantic_hash_prompt_injection_report.md`
- `planning_rows.csv`
- `kernel_rows.csv`
- `case_summary.csv`
- `plots/figure_planning_latency_by_case.png`
- `plots/figure_kernel_block_rate_by_case.png`

注意：

- 当前实验不声称 kernel 能防止 prompt injection 本身
- 它当前只证明一条真实的 `llm-app -> mcpd -> kernel` 执行链在 runtime semantic-hash substitution 下会被截断
- `kernel_closed_chain_blocked` 统计的是“同一条 plan 被执行并被拦截”的完整链路结果
- 当前版本已移除 mock planner、planner-side catalog overlay 和 gateway 污染探针，以避免启发式构造
- 该实验需要 `DEEPSEEK_API_KEY`
- 展示版默认 `--repeats 10`，以便让 per-case 统计和图表更稳定；可按需覆盖

## `netlink_microbench.py` 的计时方式

- 该脚本按“发一个 `TOOL_REQUEST`，等待一个回复，再记录一次耗时”的方式计时
- `measure_mode()` 内部每轮都会同步调用 `KernelMcpNetlinkClient.tool_request()`
- `tool_request()` 又会在 `_request()` 中先 `sendto()`，再阻塞等待 `_recv_one()`
- 因此测得的是单次往返 RTT，而不是异步批量吞吐量

## 当前 B 组说明

B 组现在实现为 `userspace_semantic_plane + simple sandboxed tool services + mcpd strict checks + audit logging`，不是完整 seccomp profile。

目前 simple sandbox 提供：

- tool service 进程 `no_new_privs`
- `RLIMIT_FSIZE` 文件大小上限
- 阻断 demo tool 内的外部 subprocess 启动
- 阻断 repo 外 `write_host_text_file`

这保证 B 组是一个真实可运行、可复现的 userspace sandbox 变体，但不应被表述成完整容器隔离或完整 seccomp 沙箱。
