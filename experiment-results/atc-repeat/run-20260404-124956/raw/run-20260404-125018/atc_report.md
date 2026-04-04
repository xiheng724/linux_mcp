# linux-mcp ATC Evaluation Report

## Run Meta

- run_ts: 20260404-125018
- requests_per_scenario: 300
- concurrency: [1, 4, 8]
- selected_tools: 8

## E2E Overhead

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| direct_c1 | direct | 1 | 300 | 100.00% | 172.192 | 3.61 | 15.69 | 35.65 |
| direct_c4 | direct | 4 | 300 | 100.00% | 387.36 | 5.23 | 32.09 | 51.51 |
| direct_c8 | direct | 8 | 300 | 100.00% | 605.563 | 7.54 | 31.75 | 55.62 |
| mcpd_c1 | mcpd | 1 | 300 | 100.00% | 113.837 | 6.13 | 21.06 | 37.83 |
| mcpd_c4 | mcpd | 4 | 300 | 100.00% | 129.649 | 10.69 | 32.95 | 64.64 |
| mcpd_c8 | mcpd | 8 | 300 | 100.00% | 387.149 | 16.79 | 41.07 | 51.62 |

## Ablation

### forwarder_only

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| forwarder_only_c1 | forwarder_only | 1 | 300 | 100.00% | 133.094 | 5.33 | 17.64 | 36.84 |
| forwarder_only_c4 | forwarder_only | 4 | 300 | 100.00% | 336.997 | 8.46 | 23.18 | 52.15 |
| forwarder_only_c8 | forwarder_only | 8 | 300 | 100.00% | 390.923 | 15.53 | 47.39 | 68.33 |

### userspace_semantic_plane

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| userspace_semantic_plane_c1 | userspace_semantic_plane | 1 | 300 | 100.00% | 135.216 | 5.43 | 17.15 | 36.95 |
| userspace_semantic_plane_c4 | userspace_semantic_plane | 4 | 300 | 100.00% | 372.281 | 8.31 | 25.29 | 29.97 |
| userspace_semantic_plane_c8 | userspace_semantic_plane | 8 | 300 | 100.00% | 447.349 | 14.62 | 37.34 | 62.24 |

These variants are intended to separate pure forwarding cost from semantically equivalent userspace control-plane cost.

## Trace Workloads

| trace | mode | requests | success_rate | avg_ms | p95_ms | p99_ms |
|---|---|---:|---:|---:|---:|---:|
| mixed | direct | 80 | 100.00% | 4.89 | 15.43 | 21.87 |
| hotspot | direct | 80 | 100.00% | 2.65 | 9.93 | 18.67 |
| mixed | mcpd | 80 | 100.00% | 5.79 | 10.72 | 22.71 |
| mixed | forwarder_only | 80 | 100.00% | 3.15 | 6.79 | 7.66 |
| mixed | userspace_semantic_plane | 80 | 100.00% | 4.08 | 9.02 | 17.86 |
| hotspot | mcpd | 80 | 100.00% | 3.40 | 6.52 | 6.77 |
| hotspot | forwarder_only | 80 | 100.00% | 3.43 | 6.37 | 21.29 |
| hotspot | userspace_semantic_plane | 80 | 100.00% | 2.63 | 5.19 | 12.57 |

## Policy Mix

| risky_pct | requests | success_rate | defer_rate | deny_rate | avg_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0 | 80 | 100.00% | 0.00% | 0.00% | 3.77 | 6.90 | 13.86 |
| 25 | 80 | 75.00% | 25.00% | 0.00% | 2.98 | 5.78 | 7.10 |
| 50 | 80 | 50.00% | 50.00% | 0.00% | 3.57 | 8.13 | 14.59 |
| 75 | 80 | 25.00% | 75.00% | 0.00% | 2.37 | 4.64 | 5.40 |
| 100 | 80 | 0.00% | 100.00% | 0.00% | 2.17 | 4.46 | 11.47 |

## Restart Recovery

- status: ok
- requests: 80
- restart_after: 20
- success_rate: 100.00%
- error_rate: 0.00%
- post_restart_error_rate: 0.00%
- outage_ms: 104.86
- p95_ms: 6.97

## Tool-Service Recovery

- status: ok
- app_id: notes_app
- tool: note_list (2)
- requests: 80
- restart_after: 20
- success_rate: 100.00%
- error_rate: 0.00%
- post_restart_error_rate: 0.00%
- outage_ms: 619.71
- p95_ms: 7.34

## Control-Plane RPCs

| rpc | repeats | success_rate | avg_ms | p95_ms | sample_error |
|---|---:|---:|---:|---:|---|
| list_apps | 40 | 100.00% | 1.23 | 3.03 |  |
| list_tools | 40 | 100.00% | 2.10 | 4.78 |  |
| open_session | 40 | 100.00% | 0.26 | 0.57 |  |

## Path Breakdown

| mode | path | repeats | success_rate | throughput_rps | e2e_p95_ms | arbitration_p95_ms | total_p95_ms | sample_error |
|---|---|---:|---:|---:|---:|---:|---:|---|
| mcpd | allow | 40 | 100.00% | 464.491 | 3.99 | 0.07 | 2.82 |  |
| mcpd | deny | 40 | 100.00% | 534.007 | 3.38 | 0.27 | 2.62 |  |
| mcpd | defer | 40 | 100.00% | 686.103 | 3.92 | 0.26 | 1.44 |  |
| userspace_semantic_plane | allow | 40 | 100.00% | 348.065 | 4.33 | 0.02 | 3.56 |  |
| userspace_semantic_plane | deny | 40 | 100.00% | 773.969 | 2.59 | 0.03 | 1.60 |  |
| userspace_semantic_plane | defer | 40 | 100.00% | 775.798 | 2.34 | 0.07 | 1.77 |  |

## Safety Controls

| case | repeats | error_rate | deny_rate | defer_rate | avg_ms | p95_ms |
|---|---:|---:|---:|---:|---:|---:|
| invalid_session | 40 | 100.00% | 0.00% | 0.00% | 1.19 | 2.24 |
| invalid_tool_id | 40 | 100.00% | 0.00% | 0.00% | 2.04 | 4.22 |
| hash_mismatch | 40 | 100.00% | 100.00% | 0.00% | 1.72 | 3.09 |

## Approval Path

- tool: open_url (13)
- risk_tags: ['external_network', 'system_mutation']
- defer_success_rate: 100.00%
- deny_error_rate: 100.00%
- session_mismatch_error_rate: 100.00%
- defer_p95_ms: 3.82
- deny_p95_ms: 1.63

## Manifest Scale

| scale | apps | tools | catalog_bytes | load_manifests_p95_ms | load_tools_p95_ms | render_catalog_p95_ms |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 14 | 43 | 26713 | 2.45 | 5.59 | 0.15 |
| 2 | 28 | 86 | 53425 | 6.27 | 4.08 | 0.10 |
| 4 | 56 | 172 | 106849 | 7.85 | 6.95 | 0.55 |

## Reload Stability

- status: skipped
- reason: disabled by flag
