# Repeated Security Aggregate

## Attack Aggregate

| group | case | mode | runs | bypass_mean | detection_mean | reject_p95_mean_ms |
|---|---|---|---:|---:|---:|---:|
| A | expired_session | mcpd | 3 | 0.00% | 100.00% | 2.121 |
| A | expired_session | userspace_semantic_plane | 3 | 0.00% | 100.00% | 2.699 |
| A | expired_session | userspace_tamper_session | 3 | 100.00% | 0.00% | 9.570667 |
| A | fake_session_id | mcpd | 3 | 0.00% | 100.00% | 3.487 |
| A | fake_session_id | userspace_semantic_plane | 3 | 0.00% | 100.00% | 2.143333 |
| A | fake_session_id | userspace_tamper_session | 3 | 100.00% | 0.00% | 17.814667 |
| A | session_token_theft | mcpd | 3 | 0.00% | 100.00% | 3.898 |
| A | session_token_theft | userspace_semantic_plane | 3 | 0.00% | 100.00% | 1.998 |
| A | session_token_theft | userspace_tamper_session | 3 | 0.00% | 100.00% | 9.762 |
| B | cross_agent_ticket_reuse | mcpd | 3 | 0.00% | 100.00% | 5.458 |
| B | cross_agent_ticket_reuse | userspace_semantic_plane | 3 | 0.00% | 100.00% | 1.534667 |
| B | cross_agent_ticket_reuse | userspace_tamper_approval | 3 | 100.00% | 0.00% | 388.249333 |
| B | cross_tool_ticket_reuse | mcpd | 3 | 0.00% | 100.00% | 4.165333 |
| B | cross_tool_ticket_reuse | userspace_semantic_plane | 3 | 0.00% | 100.00% | 1.742333 |
| B | cross_tool_ticket_reuse | userspace_tamper_approval | 3 | 100.00% | 0.00% | 164.997333 |
| B | denied_ticket_reuse | mcpd | 3 | 0.00% | 100.00% | 2.308667 |
| B | denied_ticket_reuse | userspace_semantic_plane | 3 | 0.00% | 100.00% | 3.778667 |
| B | denied_ticket_reuse | userspace_tamper_approval | 3 | 100.00% | 0.00% | 238.663 |
| B | expired_ticket_replay | mcpd | 3 | 0.00% | 100.00% | 6.813667 |
| B | expired_ticket_replay | userspace_semantic_plane | 3 | 0.00% | 100.00% | 3.973333 |
| B | expired_ticket_replay | userspace_tamper_approval | 3 | 100.00% | 0.00% | 147.101333 |
| B | forged_approval_ticket | mcpd | 3 | 0.00% | 100.00% | 4.184 |
| B | forged_approval_ticket | userspace_semantic_plane | 3 | 0.00% | 100.00% | 3.258667 |
| B | forged_approval_ticket | userspace_tamper_approval | 3 | 100.00% | 0.00% | 101.453667 |
| C | hash_mismatch | mcpd | 3 | 0.00% | 100.00% | 3.577 |
| C | hash_mismatch | userspace_semantic_plane | 3 | 0.00% | 100.00% | 2.136667 |
| C | hash_mismatch | userspace_tamper_metadata | 3 | 100.00% | 0.00% | 468.939667 |
| C | stale_catalog_replay | mcpd | 3 | 0.00% | 100.00% | 6.135333 |
| C | stale_catalog_replay | userspace_semantic_plane | 3 | 0.00% | 100.00% | 2.579333 |
| C | stale_catalog_replay | userspace_tamper_metadata | 3 | 100.00% | 0.00% | 237.371 |
| C | wrong_app_binding | mcpd | 3 | 0.00% | 100.00% | 2.683333 |
| C | wrong_app_binding | userspace_semantic_plane | 3 | 0.00% | 100.00% | 2.012667 |
| C | wrong_app_binding | userspace_tamper_metadata | 3 | 100.00% | 0.00% | 223.161667 |
| D | approval_required_bypass | mcpd | 3 | 0.00% | 100.00% | 1.747 |
| D | approval_required_bypass | userspace_compromised | 3 | 100.00% | 0.00% | 41.817 |
| D | approval_required_bypass | userspace_semantic_plane | 3 | 0.00% | 100.00% | 0.707333 |
| D | invalid_session_hash_bypass | mcpd | 3 | 0.00% | 100.00% | 1.553667 |
| D | invalid_session_hash_bypass | userspace_compromised | 3 | 100.00% | 0.00% | 12.464 |
| D | invalid_session_hash_bypass | userspace_semantic_plane | 3 | 0.00% | 100.00% | 0.708667 |
| E | toctou_hash_mismatch_after_approval | mcpd | 3 | 0.00% | 100.00% | 2.148667 |
| E | toctou_hash_mismatch_after_approval | userspace_semantic_plane | 3 | 0.00% | 100.00% | 3.36 |
| E | toctou_hash_mismatch_after_approval | userspace_tamper_approval | 3 | 0.00% | 100.00% | 2.984667 |
| E | toctou_tool_swap_after_approval | mcpd | 3 | 0.00% | 100.00% | 3.497 |
| E | toctou_tool_swap_after_approval | userspace_semantic_plane | 3 | 0.00% | 100.00% | 1.783 |
| E | toctou_tool_swap_after_approval | userspace_tamper_approval | 3 | 100.00% | 0.00% | 65.525 |
| E1 | direct_risky_tool | direct | 3 | 100.00% | 0.00% | 119.888333 |
| E1 | direct_safe_tool | direct | 3 | 100.00% | 0.00% | 3.794333 |
| E1 | forwarder_fake_session | forwarder_only | 3 | 0.00% | 100.00% | 0.676333 |

## Semantic Aggregate

| runs | precision_mean | recall_mean | fnr_mean | bypass_mean |
|---:|---:|---:|---:|---:|
| 3 | 100.00% | 66.67% | 33.33% | 33.33% |

## Daemon Aggregate

| mode | runs | approval_state_preserved_mean | session_state_preserved_mean | post_crash_visibility_mean |
|---|---:|---:|---:|---:|
| kernel | 3 | 100.00% | 0.00% | 100.00% |
| userspace | 3 | 0.00% | 0.00% | 0.00% |

## Mechanism Ablation Aggregate

| mechanism | runs | delta_mean |
|---|---:|---:|
| agent_binding | 3 | 66.67% |
| approval_token | 3 | 100.00% |
| kernel_state | 3 | 100.00% |
| semantic_hash | 3 | 100.00% |
| toctou_binding | 3 | 50.00% |

## Mixed Attack Aggregate

| mode | malicious_pct | runs | legit_p95_mean_ms | attack_acceptance_mean |
|---|---:|---:|---:|---:|
| mcpd | 0 | 3 | 39.668 | 0.00% |
| mcpd | 5 | 3 | 33.061333 | 0.00% |
| mcpd | 10 | 3 | 35.291333 | 0.00% |
| mcpd | 20 | 3 | 33.990667 | 0.00% |
| userspace_compromised | 0 | 3 | 23.585 | 0.00% |
| userspace_compromised | 5 | 3 | 44.343667 | 100.00% |
| userspace_compromised | 10 | 3 | 22.759333 | 100.00% |
| userspace_compromised | 20 | 3 | 9041.958333 | 96.88% |
| userspace_semantic_plane | 0 | 3 | 29.685333 | 0.00% |
| userspace_semantic_plane | 5 | 3 | 32.099 | 0.00% |
| userspace_semantic_plane | 10 | 3 | 29.687333 | 0.00% |
| userspace_semantic_plane | 20 | 3 | 26.027333 | 0.00% |
