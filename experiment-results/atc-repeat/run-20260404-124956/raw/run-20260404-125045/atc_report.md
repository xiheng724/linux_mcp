# linux-mcp ATC Evaluation Report

## Run Meta

- run_ts: 20260404-125045
- requests_per_scenario: 300
- concurrency: [1, 4, 8]
- selected_tools: 8

## E2E Overhead

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| direct_c1 | direct | 1 | 300 | 100.00% | 568.901 | 1.43 | 4.39 | 6.64 |
| direct_c4 | direct | 4 | 300 | 100.00% | 1145.221 | 1.84 | 10.63 | 27.75 |
| direct_c8 | direct | 8 | 300 | 100.00% | 1765.027 | 3.14 | 10.57 | 16.85 |
| mcpd_c1 | mcpd | 1 | 300 | 100.00% | 200.987 | 4.20 | 9.82 | 27.91 |
| mcpd_c4 | mcpd | 4 | 300 | 100.00% | 344.167 | 10.65 | 20.24 | 38.19 |
| mcpd_c8 | mcpd | 8 | 300 | 100.00% | 334.995 | 22.18 | 43.35 | 52.65 |

## Ablation

### forwarder_only

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| forwarder_only_c1 | forwarder_only | 1 | 300 | 100.00% | 201.062 | 3.82 | 11.27 | 23.55 |
| forwarder_only_c4 | forwarder_only | 4 | 300 | 100.00% | 346.654 | 9.22 | 23.84 | 45.63 |
| forwarder_only_c8 | forwarder_only | 8 | 300 | 100.00% | 483.3 | 12.58 | 39.22 | 55.54 |

### userspace_semantic_plane

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| userspace_semantic_plane_c1 | userspace_semantic_plane | 1 | 300 | 100.00% | 123.477 | 4.74 | 28.83 | 52.00 |
| userspace_semantic_plane_c4 | userspace_semantic_plane | 4 | 300 | 100.00% | 257.15 | 10.27 | 50.50 | 99.65 |
| userspace_semantic_plane_c8 | userspace_semantic_plane | 8 | 300 | 100.00% | 369.278 | 14.79 | 55.26 | 80.16 |

These variants are intended to separate pure forwarding cost from semantically equivalent userspace control-plane cost.

## Trace Workloads

| trace | mode | requests | success_rate | avg_ms | p95_ms | p99_ms |
|---|---|---:|---:|---:|---:|---:|
| mixed | direct | 80 | 100.00% | 2.01 | 7.49 | 11.34 |
| hotspot | direct | 80 | 100.00% | 3.31 | 11.31 | 31.80 |
| mixed | mcpd | 80 | 100.00% | 4.90 | 13.38 | 19.74 |
| mixed | forwarder_only | 80 | 100.00% | 13.08 | 42.20 | 58.63 |
| mixed | userspace_semantic_plane | 80 | 100.00% | 6.25 | 15.41 | 28.46 |
| hotspot | mcpd | 80 | 100.00% | 4.54 | 13.20 | 19.05 |
| hotspot | forwarder_only | 80 | 100.00% | 5.23 | 14.47 | 21.33 |
| hotspot | userspace_semantic_plane | 80 | 100.00% | 4.17 | 10.95 | 19.87 |

## Policy Mix

| risky_pct | requests | success_rate | defer_rate | deny_rate | avg_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0 | 80 | 100.00% | 0.00% | 0.00% | 5.81 | 13.85 | 25.11 |
| 25 | 80 | 75.00% | 25.00% | 0.00% | 4.05 | 12.04 | 18.82 |
| 50 | 80 | 50.00% | 50.00% | 0.00% | 7.73 | 42.23 | 57.47 |
| 75 | 80 | 25.00% | 75.00% | 0.00% | 4.76 | 18.20 | 35.59 |
| 100 | 80 | 0.00% | 100.00% | 0.00% | 4.95 | 16.56 | 78.33 |

## Restart Recovery

- status: ok
- requests: 80
- restart_after: 20
- success_rate: 100.00%
- error_rate: 0.00%
- post_restart_error_rate: 0.00%
- outage_ms: 478.35
- p95_ms: 70.99

## Tool-Service Recovery

- status: ok
- app_id: notes_app
- tool: note_list (2)
- requests: 80
- restart_after: 20
- success_rate: 100.00%
- error_rate: 0.00%
- post_restart_error_rate: 0.00%
- outage_ms: 987.75
- p95_ms: 26.65

## Control-Plane RPCs

| rpc | repeats | success_rate | avg_ms | p95_ms | sample_error |
|---|---:|---:|---:|---:|---|
| list_apps | 40 | 100.00% | 1.71 | 5.97 |  |
| list_tools | 40 | 100.00% | 4.28 | 7.34 |  |
| open_session | 40 | 100.00% | 0.64 | 1.73 |  |

## Path Breakdown

| mode | path | repeats | success_rate | throughput_rps | e2e_p95_ms | arbitration_p95_ms | total_p95_ms | sample_error |
|---|---|---:|---:|---:|---:|---:|---:|---|
| mcpd | allow | 40 | 100.00% | 129.723 | 19.33 | 0.58 | 13.37 |  |
| mcpd | deny | 40 | 100.00% | 352.317 | 8.41 | 0.18 | 3.63 |  |
| mcpd | defer | 40 | 100.00% | 269.7 | 9.45 | 0.34 | 5.88 |  |
| userspace_semantic_plane | allow | 40 | 100.00% | 38.509 | 93.70 | 0.42 | 65.41 |  |
| userspace_semantic_plane | deny | 40 | 100.00% | 833.783 | 2.37 | 0.01 | 1.63 |  |
| userspace_semantic_plane | defer | 40 | 100.00% | 504.989 | 5.24 | 0.02 | 2.09 |  |

## Safety Controls

| case | repeats | error_rate | deny_rate | defer_rate | avg_ms | p95_ms |
|---|---:|---:|---:|---:|---:|---:|
| invalid_session | 40 | 100.00% | 0.00% | 0.00% | 0.50 | 1.41 |
| invalid_tool_id | 40 | 100.00% | 0.00% | 0.00% | 2.78 | 11.72 |
| hash_mismatch | 40 | 100.00% | 100.00% | 0.00% | 2.07 | 4.87 |

## Approval Path

- tool: open_url (13)
- risk_tags: ['external_network', 'system_mutation']
- defer_success_rate: 100.00%
- deny_error_rate: 100.00%
- session_mismatch_error_rate: 100.00%
- defer_p95_ms: 4.02
- deny_p95_ms: 1.55

## Manifest Scale

| scale | apps | tools | catalog_bytes | load_manifests_p95_ms | load_tools_p95_ms | render_catalog_p95_ms |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 14 | 43 | 26713 | 3.73 | 1.62 | 0.04 |
| 2 | 28 | 86 | 53425 | 3.80 | 8.01 | 0.10 |
| 4 | 56 | 172 | 106849 | 12.49 | 12.04 | 0.34 |

## Reload Stability

- status: skipped
- reason: disabled by flag
