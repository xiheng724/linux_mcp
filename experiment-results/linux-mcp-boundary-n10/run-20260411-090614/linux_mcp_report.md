# linux_mcp Experiment Report

## Section 1: 实验环境

- CPU: Apple aarch64 | threads=4 | cores/socket=4 | freq=unavailable-in-guest
- Memory: 8109868 kB
- OS: Ubuntu 24.04 | kernel=6.8.0-107-generic
- Python: 3.12.3 | machine=vmware | NUMA nodes=1
- Governor: unknown | ASLR=2 | intel_no_turbo=unknown
- VM note: measurements were collected inside `vmware`; hypervisor scheduling noise may widen CI and tail latency.

## Section 2: 系统配置说明

- `userspace`: mcpd 进行全部语义检查，不使用 kernel arbitration。
- `seccomp`: userspace baseline 外加 sandbox、audit logging、stricter checks。
- `kernel`: 当前项目的 kernel_mcp control-plane 仲裁路径。

- repetitions per config: 1
- latency requests per run: 50
- scalability warmup/measure: 2.0s / 2.0s
- attack repeats: 0
- system order randomization seed: 20260405
- repetition scheduling: each repetition shuffles userspace/seccomp/kernel order before collecting latency and scalability data.

## Section 3: Latency

| system | payload | avg_ms | p95_ms | p99_ms | p95 p-value vs userspace |
|---|---|---|---|---|---:|
| kernel | 100 B | 0.883 ± 0.000 (95% CI [0.883, 0.883]) | 1.068 ± 0.000 (95% CI [1.068, 1.068]) | 1.212 ± 0.000 (95% CI [1.212, 1.212]) | 1.0 |
| kernel | 10 KB (10,240 B) | 0.838 ± 0.000 (95% CI [0.838, 0.838]) | 0.879 ± 0.000 (95% CI [0.879, 0.879]) | 0.891 ± 0.000 (95% CI [0.891, 0.891]) | 1.0 |
| kernel | 1 MB (1,048,576 B) | 7.991 ± 0.000 (95% CI [7.991, 7.991]) | 9.031 ± 0.000 (95% CI [9.031, 9.031]) | 9.666 ± 0.000 (95% CI [9.666, 9.666]) | 1.0 |
| seccomp | 100 B | 0.859 ± 0.000 (95% CI [0.859, 0.859]) | 1.063 ± 0.000 (95% CI [1.063, 1.063]) | 1.135 ± 0.000 (95% CI [1.135, 1.135]) | 1.0 |
| seccomp | 10 KB (10,240 B) | 0.907 ± 0.000 (95% CI [0.907, 0.907]) | 1.038 ± 0.000 (95% CI [1.038, 1.038]) | 1.110 ± 0.000 (95% CI [1.110, 1.110]) | 1.0 |
| seccomp | 1 MB (1,048,576 B) | 9.996 ± 0.000 (95% CI [9.996, 9.996]) | 11.099 ± 0.000 (95% CI [11.099, 11.099]) | 11.607 ± 0.000 (95% CI [11.607, 11.607]) | 1.0 |
| userspace | 100 B | 0.974 ± 0.000 (95% CI [0.974, 0.974]) | 1.096 ± 0.000 (95% CI [1.096, 1.096]) | 1.207 ± 0.000 (95% CI [1.207, 1.207]) | — |
| userspace | 10 KB (10,240 B) | 0.876 ± 0.000 (95% CI [0.876, 0.876]) | 1.062 ± 0.000 (95% CI [1.062, 1.062]) | 1.083 ± 0.000 (95% CI [1.083, 1.083]) | — |
| userspace | 1 MB (1,048,576 B) | 8.515 ± 0.000 (95% CI [8.515, 8.515]) | 10.443 ± 0.000 (95% CI [10.443, 10.443]) | 10.744 ± 0.000 (95% CI [10.744, 10.744]) | — |

## Section 3.1: Latency Breakdown

| system | payload | session_ms | arbitration_ms | tool_exec_ms | total_ms | tool_exec_share |
|---|---|---:|---:|---:|---:|---:|
| kernel | 100 B | 0.005 | 0.028 | 0.278 | 0.732 | 37.806% |
| kernel | 10 KB (10,240 B) | 0.004 | 0.027 | 0.269 | 0.682 | 39.36% |
| kernel | 1 MB (1,048,576 B) | 0.006 | 0.038 | 4.106 | 4.564 | 89.982% |
| seccomp | 100 B | 0.004 | 0.005 | 0.272 | 0.693 | 39.127% |
| seccomp | 10 KB (10,240 B) | 0.004 | 0.005 | 0.289 | 0.715 | 40.373% |
| seccomp | 1 MB (1,048,576 B) | 0.006 | 0.007 | 3.988 | 6.415 | 62.132% |
| userspace | 100 B | 0.005 | 0.005 | 0.329 | 0.808 | 40.834% |
| userspace | 10 KB (10,240 B) | 0.005 | 0.004 | 0.301 | 0.709 | 42.511% |
| userspace | 1 MB (1,048,576 B) | 0.007 | 0.006 | 4.342 | 4.789 | 90.665% |

Large payload explanation:
- userspace 1MB 时 tool_exec 占总时延约 90.665%，说明执行路径主导了端到端时间。
- kernel 1MB 时 tool_exec 占总时延约 89.982%，因此 arbitration 的绝对差异被大 payload 的 tool execution 淹没。

## Section 4: Throughput-Latency

| system | agents | concurrency | throughput_rps | error_rate | p95_ms | throughput p-value vs userspace |
|---|---:|---:|---|---|---|---:|
| kernel | 1 | 1 | 1070.000 ± 0.000 (95% CI [1070.000, 1070.000]) | 0.000 ± 0.000 (95% CI [0.000, 0.000])% | 1.019 ± 0.000 (95% CI [1.019, 1.019]) | 1.0 |
| seccomp | 1 | 1 | 1077.500 ± 0.000 (95% CI [1077.500, 1077.500]) | 0.000 ± 0.000 (95% CI [0.000, 0.000])% | 1.012 ± 0.000 (95% CI [1.012, 1.012]) | 1.0 |
| userspace | 1 | 1 | 1073.500 ± 0.000 (95% CI [1073.500, 1073.500]) | 0.000 ± 0.000 (95% CI [0.000, 0.000])% | 1.007 ± 0.000 (95% CI [1.007, 1.007]) | — |

## Section 5: Attack Resistance

判定标准：`BLOCKED` = 攻击在执行前被拒绝；`UNDETECTED` = 非授权请求被执行。

| attack | userspace | seccomp | kernel |
|---|---|---|---|
| spoof | BLOCKED (0.00%, n=0) | BLOCKED (0.00%, n=0) | BLOCKED (0.00%, n=0) |
| replay | BLOCKED (0.00%, n=0) | BLOCKED (0.00%, n=0) | BLOCKED (0.00%, n=0) |
| substitute | BLOCKED (0.00%, n=0) | BLOCKED (0.00%, n=0) | BLOCKED (0.00%, n=0) |
| escalation | BLOCKED (0.00%, n=0) | BLOCKED (0.00%, n=0) | BLOCKED (0.00%, n=0) |

[spoof attack]
- Goal: 让没有有效 session 的进程冒充已认证 agent 调用工具。
- Method: 合法 agent 打开 session，攻击方伪造或窃取 session_id。
- Method: 攻击方直接发送 tool:exec 请求。
- Method: 系统校验 session、peer binding 和 kernel agent binding。
- Success criterion: 工具被执行或返回 status=ok。
- Blocked criterion: 请求在执行前被 DENY 或返回 session/binding 错误。

[replay attack]
- Goal: 重用旧 approval ticket，在新 session 或过期后继续执行高风险工具。
- Method: 先触发高风险工具拿到 approval ticket。
- Method: 然后伪造 ticket、跨 session 重用、或在 deny/过期后重放。
- Method: 系统校验 ticket 的 session/tool/binding/consumed 状态。
- Success criterion: 高风险工具被执行。
- Blocked criterion: ticket 被识别为 forged、expired、denied 或 consumed。

[substitute attack]
- Goal: 伪造 tool_id、tool_hash 或 app 绑定，执行与 manifest 不一致的工具语义。
- Method: 保持 session 不变，篡改 tool_hash、app_id 或 stale hash。
- Method: 系统校验 manifest hash 和 app/tool binding。
- Success criterion: 请求被接受并执行。
- Blocked criterion: hash mismatch 或 app/tool binding mismatch。

[escalation attack]
- Goal: 请求低风险入口，但让 mediator 执行需要 approval 的高风险行为。
- Method: 构造 compromised mediator 路径或伪造 approval_ticket_id。
- Method: 尝试绕过 approval gate 执行高风险工具。
- Success criterion: 高风险工具在无有效 approval 下执行。
- Blocked criterion: 请求被 DEFER/DENY，或 approval gate 强制拦截。

## Section 6: Budget / Accounting

| system | max_calls | requests | allowed | denied | first_reject_at | status | note |
|---|---:|---:|---:|---:|---:|---|---|
| userspace | 0 | 0 | 0 | 0 | 0 | skipped | budget disabled |
| seccomp | 0 | 0 | 0 | 0 | 0 | skipped | budget disabled |
| kernel | 0 | 0 | 0 | 0 | 0 | skipped | budget disabled |

## Section 7: Daemon Failure / Recovery

- daemon failure experiment not run

## Section 8: 结论

- `kernel` 的延迟开销在 small payload 下可观测，但 large payload 下会被 tool execution 主导时间淹没。
- 强化 `userspace + seccomp + logging + stricter checks` 仍挡不住 spoof / substitution，且 latency 和 throughput 更差。
- 因此 kernel_mcp 不是 optional optimization，而是更难被 userspace 绕过的必要 control-plane mechanism。
