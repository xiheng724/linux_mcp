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

- repetitions per config: 30
- latency requests per run: 2000
- scalability warmup/measure: 5.0s / 5.0s
- attack repeats: 10
- system order randomization seed: 20260405
- repetition scheduling: each repetition shuffles userspace/seccomp/kernel order before collecting latency and scalability data.

## Section 3: Latency

| system | payload | avg_ms | p95_ms | p99_ms | p95 p-value vs userspace |
|---|---|---|---|---|---:|
| kernel | 100 B | 0.854 ± 0.044 (95% CI [0.838, 0.870]) | 1.026 ± 0.142 (95% CI [0.975, 1.077]) | 1.250 ± 0.533 (95% CI [1.059, 1.441]) | 0.512879 |
| kernel | 10 KB (10,240 B) | 0.899 ± 0.100 (95% CI [0.863, 0.934]) | 1.066 ± 0.230 (95% CI [0.984, 1.148]) | 1.404 ± 1.046 (95% CI [1.030, 1.778]) | 0.159764 |
| kernel | 1 MB (1,048,576 B) | 7.487 ± 0.291 (95% CI [7.383, 7.591]) | 8.422 ± 0.598 (95% CI [8.208, 8.636]) | 10.694 ± 2.895 (95% CI [9.658, 11.730]) | 0.048701 |
| seccomp | 100 B | 0.867 ± 0.065 (95% CI [0.844, 0.891]) | 1.022 ± 0.077 (95% CI [0.995, 1.050]) | 1.281 ± 0.410 (95% CI [1.134, 1.428]) | 0.404175 |
| seccomp | 10 KB (10,240 B) | 0.922 ± 0.062 (95% CI [0.899, 0.944]) | 1.078 ± 0.127 (95% CI [1.033, 1.124]) | 1.410 ± 0.692 (95% CI [1.162, 1.658]) | 0.006356 |
| seccomp | 1 MB (1,048,576 B) | 9.843 ± 0.335 (95% CI [9.723, 9.963]) | 10.903 ± 0.640 (95% CI [10.674, 11.132]) | 13.282 ± 2.975 (95% CI [12.217, 14.347]) | — |
| userspace | 100 B | 0.854 ± 0.077 (95% CI [0.826, 0.882]) | 1.056 ± 0.208 (95% CI [0.981, 1.131]) | 1.613 ± 1.209 (95% CI [1.180, 2.046]) | — |
| userspace | 10 KB (10,240 B) | 0.863 ± 0.060 (95% CI [0.842, 0.885]) | 1.003 ± 0.080 (95% CI [0.975, 1.032]) | 1.268 ± 0.427 (95% CI [1.115, 1.421]) | — |
| userspace | 1 MB (1,048,576 B) | 7.748 ± 0.263 (95% CI [7.654, 7.842]) | 8.716 ± 0.556 (95% CI [8.517, 8.915]) | 10.741 ± 2.440 (95% CI [9.868, 11.614]) | — |

## Section 3.1: Latency Breakdown

| system | payload | session_ms | arbitration_ms | tool_exec_ms | total_ms | tool_exec_share |
|---|---|---:|---:|---:|---:|---:|
| kernel | 100 B | 0.004 | 0.028 | 0.269 | 0.707 | 37.795% |
| kernel | 10 KB (10,240 B) | 0.004 | 0.028 | 0.295 | 0.727 | 39.844% |
| kernel | 1 MB (1,048,576 B) | 0.006 | 0.038 | 3.883 | 4.351 | 89.254% |
| seccomp | 100 B | 0.004 | 0.005 | 0.277 | 0.701 | 38.875% |
| seccomp | 10 KB (10,240 B) | 0.007 | 0.005 | 0.291 | 0.727 | 39.93% |
| seccomp | 1 MB (1,048,576 B) | 0.006 | 0.007 | 3.868 | 6.333 | 60.942% |
| userspace | 100 B | 0.005 | 0.004 | 0.281 | 0.71 | 39.225% |
| userspace | 10 KB (10,240 B) | 0.004 | 0.004 | 0.29 | 0.701 | 41.064% |
| userspace | 1 MB (1,048,576 B) | 0.006 | 0.006 | 3.869 | 4.301 | 89.938% |

Large payload explanation:
- userspace 1MB 时 tool_exec 占总时延约 89.938%，说明执行路径主导了端到端时间。
- kernel 1MB 时 tool_exec 占总时延约 89.254%，因此 arbitration 的绝对差异被大 payload 的 tool execution 淹没。

## Section 4: Throughput-Latency

| system | agents | concurrency | throughput_rps | error_rate | p95_ms | throughput p-value vs userspace |
|---|---:|---:|---|---|---|---:|
| kernel | 1 | 1 | 1055.800 ± 25.805 (95% CI [1046.566, 1065.034]) | 0.000 ± 0.000 (95% CI [0.000, 0.000])% | 1.037 ± 0.042 (95% CI [1.022, 1.052]) | 0.0023 |
| seccomp | 1 | 1 | 1047.147 ± 47.837 (95% CI [1030.028, 1064.265]) | 0.000 ± 0.000 (95% CI [0.000, 0.000])% | 1.071 ± 0.188 (95% CI [1.004, 1.139]) | 0.002552 |
| userspace | 1 | 1 | 1079.267 ± 33.343 (95% CI [1067.335, 1091.198]) | 0.000 ± 0.000 (95% CI [0.000, 0.000])% | 1.016 ± 0.055 (95% CI [0.996, 1.036]) | — |

## Section 5: Attack Resistance

判定标准：`BLOCKED` = 攻击在执行前被拒绝；`UNDETECTED` = 非授权请求被执行。

| attack | userspace | seccomp | kernel |
|---|---|---|---|
| spoof | UNDETECTED (66.67%, n=30) | UNDETECTED (66.67%, n=30) | BLOCKED (0.00%, n=30) |
| replay | UNDETECTED (100.00%, n=40) | BLOCKED (0.00%, n=40) | BLOCKED (0.00%, n=40) |
| substitute | UNDETECTED (100.00%, n=30) | UNDETECTED (66.67%, n=30) | BLOCKED (0.00%, n=30) |
| escalation | UNDETECTED (100.00%, n=10) | BLOCKED (0.00%, n=10) | BLOCKED (0.00%, n=10) |

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

Spoof case breakdown:
- userspace: expired_session=100.00%, fake_session_id=100.00%, session_token_theft=0.00%
- seccomp: expired_session=100.00%, fake_session_id=100.00%, session_token_theft=0.00%
- kernel: expired_session=0.00%, fake_session_id=0.00%, session_token_theft=0.00%
- The 66.67% spoof rate in userspace/seccomp comes from three spoof subcases: `fake_session_id` and `expired_session` succeed under the compromised userspace profile, while `session_token_theft` stays blocked by UDS peer credentials.

## Section 6: Budget / Accounting

| system | max_calls | requests | allowed | denied | first_reject_at | status | note |
|---|---:|---:|---:|---:|---:|---|---|
| userspace | 50 | 100 | 50 | 50 | 51 | ok |  |
| seccomp | 50 | 100 | 50 | 50 | 51 | ok |  |
| kernel | 50 | 100 | 0 | 0 | 0 | skipped | reload kernel_mcp with agent_max_calls=<N> to enable kernel budget enforcement |

## Section 7: Daemon Failure / Recovery

- daemon failure experiment not run

## Section 8: 结论

- `kernel` 的延迟开销在 small payload 下可观测，但 large payload 下会被 tool execution 主导时间淹没。
- 强化 `userspace + seccomp + logging + stricter checks` 仍挡不住 spoof / substitution，且 latency 和 throughput 更差。
- 因此 kernel_mcp 不是 optional optimization，而是更难被 userspace 绕过的必要 control-plane mechanism。
