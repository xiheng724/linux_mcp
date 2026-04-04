# linux-mcp Security Evaluation Report

## Threat Model Scope

- Local userspace adversary can tamper with userspace semantic state, forge sessions, replay approval tickets, and send malformed RPCs.
- The kernel-backed mode keeps kernel arbitration state trusted; the userspace baseline exposes optional attack profiles to simulate mediator compromise.
- Direct endpoint bypass is reported separately because the current demo does not isolate tool endpoints behind kernel-only mediation.

## Attack Summary

| group | case | mode | attempts | bypass_success_rate | detection_rate | reject_p95_ms |
|---|---|---|---:|---:|---:|---:|
| A | expired_session | mcpd | 8 | 0.00% | 100.00% | 1.43 |
| A | expired_session | userspace_semantic_plane | 8 | 0.00% | 100.00% | 1.80 |
| A | expired_session | userspace_tamper_session | 8 | 100.00% | 0.00% | 4.27 |
| A | fake_session_id | mcpd | 8 | 0.00% | 100.00% | 0.89 |
| A | fake_session_id | userspace_semantic_plane | 8 | 0.00% | 100.00% | 0.83 |
| A | fake_session_id | userspace_tamper_session | 8 | 100.00% | 0.00% | 5.53 |
| A | session_token_theft | mcpd | 8 | 0.00% | 100.00% | 3.04 |
| A | session_token_theft | userspace_semantic_plane | 8 | 0.00% | 100.00% | 1.15 |
| A | session_token_theft | userspace_tamper_session | 8 | 0.00% | 100.00% | 7.84 |
| B | cross_agent_ticket_reuse | mcpd | 8 | 0.00% | 100.00% | 3.46 |
| B | cross_agent_ticket_reuse | userspace_semantic_plane | 8 | 0.00% | 100.00% | 1.14 |
| B | cross_agent_ticket_reuse | userspace_tamper_approval | 8 | 100.00% | 0.00% | 41.40 |
| B | cross_tool_ticket_reuse | mcpd | 8 | 0.00% | 100.00% | 1.55 |
| B | cross_tool_ticket_reuse | userspace_semantic_plane | 8 | 0.00% | 100.00% | 1.43 |
| B | cross_tool_ticket_reuse | userspace_tamper_approval | 8 | 100.00% | 0.00% | 59.81 |
| B | denied_ticket_reuse | mcpd | 8 | 0.00% | 100.00% | 1.63 |
| B | denied_ticket_reuse | userspace_semantic_plane | 8 | 0.00% | 100.00% | 2.98 |
| B | denied_ticket_reuse | userspace_tamper_approval | 8 | 100.00% | 0.00% | 57.10 |
| B | expired_ticket_replay | mcpd | 8 | 0.00% | 100.00% | 3.91 |
| B | expired_ticket_replay | userspace_semantic_plane | 8 | 0.00% | 100.00% | 3.40 |
| B | expired_ticket_replay | userspace_tamper_approval | 8 | 100.00% | 0.00% | 78.15 |
| B | forged_approval_ticket | mcpd | 8 | 0.00% | 100.00% | 2.02 |
| B | forged_approval_ticket | userspace_semantic_plane | 8 | 0.00% | 100.00% | 3.85 |
| B | forged_approval_ticket | userspace_tamper_approval | 8 | 100.00% | 0.00% | 40.62 |
| C | hash_mismatch | mcpd | 8 | 0.00% | 100.00% | 2.52 |
| C | hash_mismatch | userspace_semantic_plane | 8 | 0.00% | 100.00% | 2.05 |
| C | hash_mismatch | userspace_tamper_metadata | 8 | 100.00% | 0.00% | 7.07 |
| C | stale_catalog_replay | mcpd | 8 | 0.00% | 100.00% | 6.04 |
| C | stale_catalog_replay | userspace_semantic_plane | 8 | 0.00% | 100.00% | 0.80 |
| C | stale_catalog_replay | userspace_tamper_metadata | 8 | 100.00% | 0.00% | 6.69 |
| C | wrong_app_binding | mcpd | 8 | 0.00% | 100.00% | 1.74 |
| C | wrong_app_binding | userspace_semantic_plane | 8 | 0.00% | 100.00% | 2.55 |
| C | wrong_app_binding | userspace_tamper_metadata | 8 | 100.00% | 0.00% | 4.52 |
| D | approval_required_bypass | mcpd | 8 | 0.00% | 100.00% | 1.36 |
| D | approval_required_bypass | userspace_compromised | 8 | 100.00% | 0.00% | 9.27 |
| D | approval_required_bypass | userspace_semantic_plane | 8 | 0.00% | 100.00% | 0.47 |
| D | invalid_session_hash_bypass | mcpd | 8 | 0.00% | 100.00% | 1.15 |
| D | invalid_session_hash_bypass | userspace_compromised | 8 | 100.00% | 0.00% | 10.64 |
| D | invalid_session_hash_bypass | userspace_semantic_plane | 8 | 0.00% | 100.00% | 0.30 |
| E | toctou_hash_mismatch_after_approval | mcpd | 8 | 0.00% | 100.00% | 2.02 |
| E | toctou_hash_mismatch_after_approval | userspace_semantic_plane | 8 | 0.00% | 100.00% | 2.00 |
| E | toctou_hash_mismatch_after_approval | userspace_tamper_approval | 8 | 0.00% | 100.00% | 2.16 |
| E | toctou_tool_swap_after_approval | mcpd | 8 | 0.00% | 100.00% | 2.15 |
| E | toctou_tool_swap_after_approval | userspace_semantic_plane | 8 | 0.00% | 100.00% | 2.17 |
| E | toctou_tool_swap_after_approval | userspace_tamper_approval | 8 | 100.00% | 0.00% | 41.62 |
| E1 | direct_risky_tool | direct | 1 | 100.00% | 0.00% | 263.24 |
| E1 | direct_safe_tool | direct | 1 | 100.00% | 0.00% | 7.22 |
| E1 | forwarder_fake_session | forwarder_only | 1 | 0.00% | 100.00% | 0.36 |

## Semantic Tampering

| precision | recall | false_positive_rate | false_negative_rate | bypass_success_rate |
|---:|---:|---:|---:|---:|
| 100.00% | 66.67% | 0.00% | 33.33% | 33.33% |

## Invariant Summary

| mode | I1 | I2 | I3 | I4 | I5 | preserved_ratio |
|---|---|---|---|---|---|---:|
| direct | no | no | no | no | no | 0.000 |
| forwarder_only | no | no | no | no | no | 0.000 |
| mcpd | yes | yes | yes | yes | yes | 1.000 |
| userspace_compromised | no | yes | yes | yes | no | 0.600 |
| userspace_semantic_plane | yes | yes | yes | yes | yes | 1.000 |
| userspace_tamper_approval | no | no | yes | yes | no | 0.400 |
| userspace_tamper_metadata | no | yes | yes | no | yes | 0.600 |
| userspace_tamper_session | no | yes | no | yes | yes | 0.600 |

## Daemon Compromise

| mode | approval_state_preserved | session_state_preserved | post_crash_agent_visible | approval_error | replay_error |
|---|---:|---:|---:|---|---|
| kernel | 1 | 0 | 1 |  | session not found or expired |
| userspace | 0 | 0 | 0 | pending approval not found: 1 | session not found or expired |

## Mechanism Ablation

| mechanism | baseline_mode | ablated_mode | baseline_attack_success_rate | ablated_attack_success_rate | delta |
|---|---|---|---:|---:|---:|
| agent_binding | mcpd | userspace_tamper_session | 0.00% | 66.67% | 66.67% |
| approval_token | mcpd | userspace_tamper_approval | 0.00% | 100.00% | 100.00% |
| semantic_hash | mcpd | userspace_tamper_metadata | 0.00% | 100.00% | 100.00% |
| toctou_binding | mcpd | userspace_tamper_approval | 0.00% | 50.00% | 50.00% |
| kernel_state | kernel | userspace | 0.00% | 100.00% | 100.00% |

## Mixed Attack Under Load

| mode | malicious_pct | legit_throughput_rps | legit_p95_ms | attack_acceptance_rate |
|---|---:|---:|---:|---:|
| mcpd | 0 | 507.383 | 29.062 | 0.00% |
| mcpd | 5 | 474.47 | 37.21 | 0.00% |
| mcpd | 10 | 396.342 | 49.937 | 0.00% |
| mcpd | 20 | 342.999 | 47.375 | 0.00% |
| userspace_semantic_plane | 0 | 388.991 | 47.522 | 0.00% |
| userspace_semantic_plane | 5 | 252.69 | 49.818 | 0.00% |
| userspace_semantic_plane | 10 | 466.794 | 32.796 | 0.00% |
| userspace_semantic_plane | 20 | 461.129 | 28.531 | 0.00% |
| userspace_compromised | 0 | 524.548 | 25.362 | 0.00% |
| userspace_compromised | 5 | 181.462 | 97.875 | 100.00% |
| userspace_compromised | 10 | 406.859 | 25.881 | 100.00% |
| userspace_compromised | 20 | 5.348 | 10221.74 | 96.88% |

## Observability

| mode | independent_audit | state_introspection | post_crash_visibility | root_cause_success_rate |
|---|---:|---:|---:|---:|
| kernel | 1 | 1 | 1 | 100.00% |
| userspace | 0 | 0 | 0 | 100.00% |
