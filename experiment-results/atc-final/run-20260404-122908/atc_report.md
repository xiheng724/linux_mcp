# linux-mcp ATC Evaluation Report

## Run Meta

- run_ts: 20260404-122908
- requests_per_scenario: 400
- concurrency: [1, 4, 8]
- selected_tools: 10

## E2E Overhead

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| direct_c1 | direct | 1 | 400 | 100.00% | 637.326 | 0.62 | 5.86 | 9.73 |
| direct_c4 | direct | 4 | 400 | 100.00% | 1813.516 | 0.69 | 6.67 | 14.80 |
| direct_c8 | direct | 8 | 400 | 100.00% | 1539.527 | 1.10 | 22.22 | 57.78 |
| mcpd_c1 | mcpd | 1 | 400 | 100.00% | 318.314 | 2.10 | 8.61 | 12.19 |
| mcpd_c4 | mcpd | 4 | 400 | 100.00% | 358.454 | 7.26 | 23.39 | 69.25 |
| mcpd_c8 | mcpd | 8 | 400 | 100.00% | 123.13 | 21.59 | 190.33 | 403.26 |

## Ablation

### forwarder_only

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| forwarder_only_c1 | forwarder_only | 1 | 400 | 98.75% | 8.741 | 8.05 | 116.14 | 5082.53 |
| forwarder_only_c4 | forwarder_only | 4 | 400 | 100.00% | 298.025 | 6.49 | 31.76 | 95.76 |
| forwarder_only_c8 | forwarder_only | 8 | 400 | 100.00% | 440.475 | 9.43 | 38.70 | 61.98 |

### userspace_semantic_plane

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| userspace_semantic_plane_c1 | userspace_semantic_plane | 1 | 400 | 100.00% | 75.789 | 4.66 | 37.29 | 74.28 |
| userspace_semantic_plane_c4 | userspace_semantic_plane | 4 | 400 | 100.00% | 380.346 | 4.86 | 32.75 | 57.40 |
| userspace_semantic_plane_c8 | userspace_semantic_plane | 8 | 400 | 100.00% | 558.614 | 6.42 | 39.44 | 109.56 |

These variants are intended to separate pure forwarding cost from semantically equivalent userspace control-plane cost.

## Trace Workloads

| trace | mode | requests | success_rate | avg_ms | p95_ms | p99_ms |
|---|---|---:|---:|---:|---:|---:|
| mixed | direct | 100 | 100.00% | 5.99 | 25.26 | 58.40 |
| hotspot | direct | 100 | 100.00% | 1.43 | 4.06 | 13.66 |
| mixed | mcpd | 100 | 100.00% | 6.24 | 17.22 | 27.59 |
| mixed | forwarder_only | 100 | 100.00% | 7.76 | 26.66 | 44.75 |
| mixed | userspace_semantic_plane | 100 | 100.00% | 4.62 | 13.78 | 31.20 |
| hotspot | mcpd | 100 | 100.00% | 1.92 | 4.28 | 6.68 |
| hotspot | forwarder_only | 100 | 100.00% | 1.91 | 3.96 | 5.57 |
| hotspot | userspace_semantic_plane | 100 | 100.00% | 2.83 | 5.81 | 13.80 |

## Policy Mix

| risky_pct | requests | success_rate | defer_rate | deny_rate | avg_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0 | 100 | 100.00% | 0.00% | 0.00% | 2.32 | 4.69 | 7.01 |
| 25 | 100 | 75.00% | 25.00% | 0.00% | 1.85 | 3.68 | 5.04 |
| 50 | 100 | 50.00% | 50.00% | 0.00% | 1.30 | 2.23 | 2.85 |
| 75 | 100 | 25.00% | 75.00% | 0.00% | 1.40 | 3.91 | 4.57 |
| 100 | 100 | 0.00% | 100.00% | 0.00% | 1.14 | 2.80 | 3.51 |

## Restart Recovery

- status: ok
- requests: 100
- restart_after: 20
- success_rate: 100.00%
- error_rate: 0.00%
- post_restart_error_rate: 0.00%
- outage_ms: 105.21
- p95_ms: 4.96

## Tool-Service Recovery

- status: ok
- app_id: notes_app
- tool: note_list (2)
- requests: 100
- restart_after: 20
- success_rate: 100.00%
- error_rate: 0.00%
- post_restart_error_rate: 0.00%
- outage_ms: 611.36
- p95_ms: 5.29

## Control-Plane RPCs

| rpc | repeats | success_rate | avg_ms | p95_ms | sample_error |
|---|---:|---:|---:|---:|---|
| list_apps | 60 | 100.00% | 1.64 | 5.11 |  |
| list_tools | 60 | 100.00% | 2.46 | 5.26 |  |
| open_session | 60 | 100.00% | 0.67 | 2.25 |  |

## Path Breakdown

| mode | path | repeats | success_rate | throughput_rps | e2e_p95_ms | arbitration_p95_ms | total_p95_ms | sample_error |
|---|---|---:|---:|---:|---:|---:|---:|---|
| mcpd | allow | 60 | 100.00% | 366.803 | 4.69 | 0.20 | 3.35 |  |
| mcpd | deny | 60 | 100.00% | 826.449 | 2.26 | 0.09 | 1.20 |  |
| mcpd | defer | 60 | 100.00% | 862.781 | 2.89 | 0.10 | 0.87 |  |
| userspace_semantic_plane | allow | 60 | 100.00% | 453.702 | 4.29 | 0.01 | 3.38 |  |
| userspace_semantic_plane | deny | 60 | 100.00% | 1349.767 | 1.57 | 0.01 | 0.68 |  |
| userspace_semantic_plane | defer | 60 | 100.00% | 1052.101 | 2.65 | 0.02 | 0.76 |  |

## Safety Controls

| case | repeats | error_rate | deny_rate | defer_rate | avg_ms | p95_ms |
|---|---:|---:|---:|---:|---:|---:|
| invalid_session | 50 | 100.00% | 0.00% | 0.00% | 0.35 | 1.52 |
| invalid_tool_id | 50 | 100.00% | 0.00% | 0.00% | 1.73 | 3.76 |
| hash_mismatch | 50 | 100.00% | 100.00% | 0.00% | 1.48 | 3.65 |

## Approval Path

- tool: open_url (13)
- risk_tags: ['external_network', 'system_mutation']
- defer_success_rate: 100.00%
- deny_error_rate: 100.00%
- session_mismatch_error_rate: 100.00%
- defer_p95_ms: 4.04
- deny_p95_ms: 2.71

## Manifest Scale

| scale | apps | tools | catalog_bytes | load_manifests_p95_ms | load_tools_p95_ms | render_catalog_p95_ms |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 14 | 43 | 26713 | 1.95 | 1.06 | 0.05 |
| 2 | 28 | 86 | 53425 | 3.00 | 3.98 | 0.13 |
| 4 | 56 | 172 | 106849 | 5.47 | 5.28 | 0.27 |

## Reload Stability

- status: skipped
- reason: disabled by flag
