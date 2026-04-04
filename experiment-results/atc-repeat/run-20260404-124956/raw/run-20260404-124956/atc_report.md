# linux-mcp ATC Evaluation Report

## Run Meta

- run_ts: 20260404-124956
- requests_per_scenario: 300
- concurrency: [1, 4, 8]
- selected_tools: 8

## E2E Overhead

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| direct_c1 | direct | 1 | 300 | 100.00% | 1196.01 | 0.60 | 1.93 | 3.86 |
| direct_c4 | direct | 4 | 300 | 100.00% | 2417.192 | 0.70 | 4.69 | 19.27 |
| direct_c8 | direct | 8 | 300 | 100.00% | 3277.321 | 1.00 | 8.08 | 10.02 |
| mcpd_c1 | mcpd | 1 | 300 | 100.00% | 449.483 | 1.72 | 4.37 | 7.14 |
| mcpd_c4 | mcpd | 4 | 300 | 100.00% | 570.747 | 5.90 | 11.88 | 27.39 |
| mcpd_c8 | mcpd | 8 | 300 | 100.00% | 620.609 | 11.39 | 21.07 | 40.58 |

## Ablation

### forwarder_only

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| forwarder_only_c1 | forwarder_only | 1 | 300 | 100.00% | 352.254 | 2.06 | 6.30 | 10.46 |
| forwarder_only_c4 | forwarder_only | 4 | 300 | 100.00% | 607.853 | 6.00 | 10.79 | 12.78 |
| forwarder_only_c8 | forwarder_only | 8 | 300 | 100.00% | 614.8 | 10.73 | 32.59 | 41.76 |

### userspace_semantic_plane

| scenario | mode | concurrency | requests | success_rate | throughput_rps | p50_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| userspace_semantic_plane_c1 | userspace_semantic_plane | 1 | 300 | 100.00% | 354.0 | 2.02 | 5.96 | 10.48 |
| userspace_semantic_plane_c4 | userspace_semantic_plane | 4 | 300 | 100.00% | 477.979 | 7.14 | 16.63 | 36.71 |
| userspace_semantic_plane_c8 | userspace_semantic_plane | 8 | 300 | 100.00% | 459.485 | 15.00 | 35.17 | 61.98 |

These variants are intended to separate pure forwarding cost from semantically equivalent userspace control-plane cost.

## Trace Workloads

| trace | mode | requests | success_rate | avg_ms | p95_ms | p99_ms |
|---|---|---:|---:|---:|---:|---:|
| mixed | direct | 80 | 100.00% | 0.71 | 1.52 | 3.58 |
| hotspot | direct | 80 | 100.00% | 1.27 | 3.37 | 4.93 |
| mixed | mcpd | 80 | 100.00% | 3.35 | 6.82 | 9.70 |
| mixed | forwarder_only | 80 | 100.00% | 10.39 | 29.17 | 41.38 |
| mixed | userspace_semantic_plane | 80 | 100.00% | 12.52 | 37.68 | 54.33 |
| hotspot | mcpd | 80 | 100.00% | 6.24 | 14.67 | 43.32 |
| hotspot | forwarder_only | 80 | 100.00% | 6.59 | 25.91 | 35.74 |
| hotspot | userspace_semantic_plane | 80 | 100.00% | 9.21 | 40.95 | 60.77 |

## Policy Mix

| risky_pct | requests | success_rate | defer_rate | deny_rate | avg_ms | p95_ms | p99_ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0 | 80 | 100.00% | 0.00% | 0.00% | 4.96 | 9.29 | 17.23 |
| 25 | 80 | 75.00% | 25.00% | 0.00% | 3.74 | 6.49 | 8.71 |
| 50 | 80 | 50.00% | 50.00% | 0.00% | 3.32 | 7.95 | 11.27 |
| 75 | 80 | 25.00% | 75.00% | 0.00% | 2.92 | 7.84 | 8.74 |
| 100 | 80 | 0.00% | 100.00% | 0.00% | 11.21 | 32.13 | 50.35 |

## Restart Recovery

- status: ok
- requests: 80
- restart_after: 20
- success_rate: 100.00%
- error_rate: 0.00%
- post_restart_error_rate: 0.00%
- outage_ms: 211.75
- p95_ms: 18.65

## Tool-Service Recovery

- status: ok
- app_id: notes_app
- tool: note_list (2)
- requests: 80
- restart_after: 20
- success_rate: 100.00%
- error_rate: 0.00%
- post_restart_error_rate: 0.00%
- outage_ms: 226.26
- p95_ms: 24.91

## Control-Plane RPCs

| rpc | repeats | success_rate | avg_ms | p95_ms | sample_error |
|---|---:|---:|---:|---:|---|
| list_apps | 40 | 100.00% | 1.79 | 5.00 |  |
| list_tools | 40 | 100.00% | 2.78 | 5.98 |  |
| open_session | 40 | 100.00% | 1.68 | 5.46 |  |

## Path Breakdown

| mode | path | repeats | success_rate | throughput_rps | e2e_p95_ms | arbitration_p95_ms | total_p95_ms | sample_error |
|---|---|---:|---:|---:|---:|---:|---:|---|
| mcpd | allow | 40 | 100.00% | 101.156 | 17.39 | 0.36 | 15.84 |  |
| mcpd | deny | 40 | 100.00% | 216.458 | 14.17 | 1.02 | 6.03 |  |
| mcpd | defer | 40 | 100.00% | 291.047 | 7.42 | 0.70 | 5.05 |  |
| userspace_semantic_plane | allow | 40 | 100.00% | 118.378 | 21.13 | 0.02 | 20.32 |  |
| userspace_semantic_plane | deny | 40 | 100.00% | 486.499 | 4.18 | 0.02 | 3.14 |  |
| userspace_semantic_plane | defer | 40 | 100.00% | 324.697 | 6.67 | 0.04 | 3.90 |  |

## Safety Controls

| case | repeats | error_rate | deny_rate | defer_rate | avg_ms | p95_ms |
|---|---:|---:|---:|---:|---:|---:|
| invalid_session | 40 | 100.00% | 0.00% | 0.00% | 0.59 | 2.39 |
| invalid_tool_id | 40 | 100.00% | 0.00% | 0.00% | 3.06 | 6.08 |
| hash_mismatch | 40 | 100.00% | 100.00% | 0.00% | 4.22 | 9.56 |

## Approval Path

- tool: open_url (13)
- risk_tags: ['external_network', 'system_mutation']
- defer_success_rate: 100.00%
- deny_error_rate: 100.00%
- session_mismatch_error_rate: 100.00%
- defer_p95_ms: 4.67
- deny_p95_ms: 2.88

## Manifest Scale

| scale | apps | tools | catalog_bytes | load_manifests_p95_ms | load_tools_p95_ms | render_catalog_p95_ms |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 14 | 43 | 26713 | 2.83 | 3.09 | 0.25 |
| 2 | 28 | 86 | 53425 | 5.14 | 6.65 | 2.33 |
| 4 | 56 | 172 | 106849 | 11.36 | 9.28 | 1.06 |

## Reload Stability

- status: skipped
- reason: disabled by flag
