# linux-mcp Security Evaluation Report

## Threat Model Scope

- Local userspace adversary can tamper with userspace semantic state, forge sessions, replay approval tickets, and send malformed RPCs.
- The kernel-backed mode keeps kernel arbitration state trusted; the userspace baseline exposes optional attack profiles to simulate mediator compromise.
- Direct endpoint bypass is reported separately because the current demo does not isolate tool endpoints behind kernel-only mediation.

## Attack Summary

| group | case | mode | attempts | bypass_success_rate | detection_rate | reject_p95_ms |
|---|---|---|---:|---:|---:|---:|
| A | expired_session | mcpd | 8 | 0.00% | 100.00% | 0.48 |
| A | expired_session | userspace_semantic_plane | 8 | 0.00% | 100.00% | 0.27 |
| A | expired_session | userspace_tamper_session | 8 | 100.00% | 0.00% | 3.60 |
| A | fake_session_id | mcpd | 8 | 0.00% | 100.00% | 2.04 |
| A | fake_session_id | userspace_semantic_plane | 8 | 0.00% | 100.00% | 0.66 |
| A | fake_session_id | userspace_tamper_session | 8 | 100.00% | 0.00% | 3.56 |
| A | session_token_theft | mcpd | 8 | 0.00% | 100.00% | 0.94 |
| A | session_token_theft | userspace_semantic_plane | 8 | 0.00% | 100.00% | 0.61 |
| A | session_token_theft | userspace_tamper_session | 8 | 0.00% | 100.00% | 3.14 |
| B | cross_agent_ticket_reuse | mcpd | 8 | 0.00% | 100.00% | 2.13 |
| B | cross_agent_ticket_reuse | userspace_semantic_plane | 8 | 0.00% | 100.00% | 1.37 |
| B | cross_agent_ticket_reuse | userspace_tamper_approval | 8 | 100.00% | 0.00% | 75.78 |
| B | cross_tool_ticket_reuse | mcpd | 8 | 0.00% | 100.00% | 2.85 |
| B | cross_tool_ticket_reuse | userspace_semantic_plane | 8 | 0.00% | 100.00% | 1.29 |
| B | cross_tool_ticket_reuse | userspace_tamper_approval | 8 | 100.00% | 0.00% | 84.22 |
| B | denied_ticket_reuse | mcpd | 8 | 0.00% | 100.00% | 3.36 |
| B | denied_ticket_reuse | userspace_semantic_plane | 8 | 0.00% | 100.00% | 4.18 |
| B | denied_ticket_reuse | userspace_tamper_approval | 8 | 100.00% | 0.00% | 35.73 |
| B | expired_ticket_replay | mcpd | 8 | 0.00% | 100.00% | 3.19 |
| B | expired_ticket_replay | userspace_semantic_plane | 8 | 0.00% | 100.00% | 2.49 |
| B | expired_ticket_replay | userspace_tamper_approval | 8 | 100.00% | 0.00% | 53.86 |
| B | forged_approval_ticket | mcpd | 8 | 0.00% | 100.00% | 2.47 |
| B | forged_approval_ticket | userspace_semantic_plane | 8 | 0.00% | 100.00% | 2.37 |
| B | forged_approval_ticket | userspace_tamper_approval | 8 | 100.00% | 0.00% | 106.72 |
| C | hash_mismatch | mcpd | 8 | 0.00% | 100.00% | 2.65 |
| C | hash_mismatch | userspace_semantic_plane | 8 | 0.00% | 100.00% | 0.73 |
| C | hash_mismatch | userspace_tamper_metadata | 8 | 100.00% | 0.00% | 2.96 |
| C | stale_catalog_replay | mcpd | 8 | 0.00% | 100.00% | 1.75 |
| C | stale_catalog_replay | userspace_semantic_plane | 8 | 0.00% | 100.00% | 2.72 |
| C | stale_catalog_replay | userspace_tamper_metadata | 8 | 100.00% | 0.00% | 2.36 |
| C | wrong_app_binding | mcpd | 8 | 0.00% | 100.00% | 1.72 |
| C | wrong_app_binding | userspace_semantic_plane | 8 | 0.00% | 100.00% | 2.42 |
| C | wrong_app_binding | userspace_tamper_metadata | 8 | 100.00% | 0.00% | 3.31 |
| D | approval_required_bypass | mcpd | 8 | 0.00% | 100.00% | 0.46 |
| D | approval_required_bypass | userspace_compromised | 8 | 100.00% | 0.00% | 65.81 |
| D | approval_required_bypass | userspace_semantic_plane | 8 | 0.00% | 100.00% | 0.39 |
| D | invalid_session_hash_bypass | mcpd | 8 | 0.00% | 100.00% | 0.54 |
| D | invalid_session_hash_bypass | userspace_compromised | 8 | 100.00% | 0.00% | 2.37 |
| D | invalid_session_hash_bypass | userspace_semantic_plane | 8 | 0.00% | 100.00% | 0.55 |
| E | toctou_hash_mismatch_after_approval | mcpd | 8 | 0.00% | 100.00% | 0.94 |
| E | toctou_hash_mismatch_after_approval | userspace_semantic_plane | 8 | 0.00% | 100.00% | 1.46 |
| E | toctou_hash_mismatch_after_approval | userspace_tamper_approval | 8 | 0.00% | 100.00% | 1.57 |
| E | toctou_tool_swap_after_approval | mcpd | 8 | 0.00% | 100.00% | 1.55 |
| E | toctou_tool_swap_after_approval | userspace_semantic_plane | 8 | 0.00% | 100.00% | 1.06 |
| E | toctou_tool_swap_after_approval | userspace_tamper_approval | 8 | 100.00% | 0.00% | 41.96 |
| E1 | direct_risky_tool | direct | 1 | 100.00% | 0.00% | 78.65 |
| E1 | direct_safe_tool | direct | 1 | 100.00% | 0.00% | 0.81 |
| E1 | forwarder_fake_session | forwarder_only | 1 | 0.00% | 100.00% | 1.30 |

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
| mcpd | 0 | 536.782 | 22.342 | 0.00% |
| mcpd | 5 | 559.837 | 20.31 | 0.00% |
| mcpd | 10 | 609.227 | 19.728 | 0.00% |
| mcpd | 20 | 631.675 | 19.752 | 0.00% |
| userspace_semantic_plane | 0 | 691.79 | 18.919 | 0.00% |
| userspace_semantic_plane | 5 | 701.431 | 19.547 | 0.00% |
| userspace_semantic_plane | 10 | 634.459 | 19.666 | 0.00% |
| userspace_semantic_plane | 20 | 640.178 | 19.411 | 0.00% |
| userspace_compromised | 0 | 737.905 | 18.055 | 0.00% |
| userspace_compromised | 5 | 433.393 | 5.323 | 100.00% |
| userspace_compromised | 10 | 316.24 | 12.094 | 100.00% |
| userspace_compromised | 20 | 331.63 | 5.333 | 100.00% |

## Observability

| mode | independent_audit | state_introspection | post_crash_visibility | root_cause_success_rate |
|---|---:|---:|---:|---:|
| kernel | 1 | 1 | 1 | 100.00% |
| userspace | 0 | 0 | 0 | 100.00% |
