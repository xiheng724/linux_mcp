# Generic Netlink Microbenchmark Report

## Setup

- warmup_requests: 500
- measure_requests: 10000
- agent_id: `bench-agent`
- tool_id: `9001`

## Summary

| mode | avg_ms | p95_ms | p99_ms | std_ms | 95% CI |
|---|---:|---:|---:|---:|---:|
| bare | 0.008196 | 0.010417 | 0.020959 | 0.002594 | +/- 0.000051 |
| full | 0.009315 | 0.009750 | 0.020167 | 0.130640 | +/- 0.002561 |

## Derived Metrics

- `netlink_rtt_bare_ms = 0.008196`
- `netlink_rtt_full_ms = 0.009315`
- `lookup_overhead_ms = 0.001119`
- `lookup_overhead_share_pct = 12.011%`

解释：`bare` 只测 Generic Netlink 往返和最小命令处理；`full` 走正常 `TOOL_REQUEST` 路径并包含 tool/agent 查找与绑定校验。
