# linux-mcp Security Evaluation Report

## Threat Model Scope

- Local userspace adversary can tamper with userspace semantic state, forge sessions, replay approval tickets, and send malformed RPCs.
- The kernel-backed mode keeps kernel arbitration state trusted; the userspace baseline exposes optional attack profiles to simulate mediator compromise.
- Direct endpoint bypass is reported separately because the current demo does not isolate tool endpoints behind kernel-only mediation.

## Attack Summary

| group | case | mode | attempts | bypass_success_rate | detection_rate | reject_p95_ms |
|---|---|---|---:|---:|---:|---:|
| A | expired_session | mcpd | 10 | 0.00% | 100.00% | 1.84 |
| A | expired_session | userspace_semantic_plane | 10 | 0.00% | 100.00% | 0.75 |
| A | expired_session | userspace_tamper_session | 10 | 100.00% | 0.00% | 7.85 |
| A | fake_session_id | mcpd | 10 | 0.00% | 100.00% | 1.24 |
| A | fake_session_id | userspace_semantic_plane | 10 | 0.00% | 100.00% | 1.39 |
| A | fake_session_id | userspace_tamper_session | 10 | 100.00% | 0.00% | 13.43 |
| A | session_token_theft | mcpd | 10 | 0.00% | 100.00% | 0.57 |
| A | session_token_theft | userspace_semantic_plane | 10 | 0.00% | 100.00% | 2.26 |
| A | session_token_theft | userspace_tamper_session | 10 | 0.00% | 100.00% | 5.93 |
| B | cross_agent_ticket_reuse | mcpd | 10 | 0.00% | 100.00% | 1.69 |
| B | cross_agent_ticket_reuse | userspace_semantic_plane | 10 | 0.00% | 100.00% | 1.51 |
| B | cross_agent_ticket_reuse | userspace_tamper_approval | 10 | 100.00% | 0.00% | 26.30 |
| B | cross_tool_ticket_reuse | mcpd | 10 | 0.00% | 100.00% | 2.25 |
| B | cross_tool_ticket_reuse | userspace_semantic_plane | 10 | 0.00% | 100.00% | 2.45 |
| B | cross_tool_ticket_reuse | userspace_tamper_approval | 10 | 100.00% | 0.00% | 15.34 |
| B | denied_ticket_reuse | mcpd | 10 | 0.00% | 100.00% | 1.77 |
| B | denied_ticket_reuse | userspace_semantic_plane | 10 | 0.00% | 100.00% | 2.70 |
| B | denied_ticket_reuse | userspace_tamper_approval | 10 | 100.00% | 0.00% | 103.38 |
| B | expired_ticket_replay | mcpd | 10 | 0.00% | 100.00% | 3.78 |
| B | expired_ticket_replay | userspace_semantic_plane | 10 | 0.00% | 100.00% | 3.79 |
| B | expired_ticket_replay | userspace_tamper_approval | 10 | 100.00% | 0.00% | 280.42 |
| B | forged_approval_ticket | mcpd | 10 | 0.00% | 100.00% | 1.94 |
| B | forged_approval_ticket | userspace_semantic_plane | 10 | 0.00% | 100.00% | 2.65 |
| B | forged_approval_ticket | userspace_tamper_approval | 10 | 100.00% | 0.00% | 48.14 |
| C | hash_mismatch | mcpd | 10 | 0.00% | 100.00% | 1.02 |
| C | hash_mismatch | userspace_semantic_plane | 10 | 0.00% | 100.00% | 1.51 |
| C | hash_mismatch | userspace_tamper_metadata | 10 | 100.00% | 0.00% | 5.53 |
| C | stale_catalog_replay | mcpd | 10 | 0.00% | 100.00% | 2.60 |
| C | stale_catalog_replay | userspace_semantic_plane | 10 | 0.00% | 100.00% | 0.99 |
| C | stale_catalog_replay | userspace_tamper_metadata | 10 | 100.00% | 0.00% | 8.09 |
| C | wrong_app_binding | mcpd | 10 | 0.00% | 100.00% | 2.32 |
| C | wrong_app_binding | userspace_semantic_plane | 10 | 0.00% | 100.00% | 3.69 |
| C | wrong_app_binding | userspace_tamper_metadata | 10 | 100.00% | 0.00% | 5.00 |
| D | approval_required_bypass | mcpd | 10 | 0.00% | 100.00% | 0.65 |
| D | approval_required_bypass | userspace_compromised | 10 | 100.00% | 0.00% | 29.56 |
| D | approval_required_bypass | userspace_semantic_plane | 10 | 0.00% | 100.00% | 0.77 |
| D | invalid_session_hash_bypass | mcpd | 10 | 0.00% | 100.00% | 0.23 |
| D | invalid_session_hash_bypass | userspace_compromised | 10 | 100.00% | 0.00% | 8.09 |
| D | invalid_session_hash_bypass | userspace_semantic_plane | 10 | 0.00% | 100.00% | 1.15 |
| E | toctou_hash_mismatch_after_approval | mcpd | 10 | 0.00% | 100.00% | 2.18 |
| E | toctou_hash_mismatch_after_approval | userspace_semantic_plane | 10 | 0.00% | 100.00% | 1.46 |
| E | toctou_hash_mismatch_after_approval | userspace_tamper_approval | 10 | 0.00% | 100.00% | 4.28 |
| E | toctou_tool_swap_after_approval | mcpd | 10 | 0.00% | 100.00% | 2.72 |
| E | toctou_tool_swap_after_approval | userspace_semantic_plane | 10 | 0.00% | 100.00% | 2.89 |
| E | toctou_tool_swap_after_approval | userspace_tamper_approval | 10 | 100.00% | 0.00% | 97.25 |
| E1 | direct_risky_tool | direct | 1 | 100.00% | 0.00% | 63.14 |
| E1 | direct_safe_tool | direct | 1 | 100.00% | 0.00% | 0.95 |
| E1 | forwarder_fake_session | forwarder_only | 1 | 0.00% | 100.00% | 1.15 |

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
| mcpd | 0 | 432.882 | 31.356 | 0.00% |
| mcpd | 5 | 358.053 | 52.076 | 0.00% |
| mcpd | 10 | 486.647 | 27.018 | 0.00% |
| mcpd | 20 | 516.801 | 22.383 | 0.00% |
| userspace_semantic_plane | 0 | 441.967 | 32.873 | 0.00% |
| userspace_semantic_plane | 5 | 467.329 | 29.191 | 0.00% |
| userspace_semantic_plane | 10 | 524.283 | 22.474 | 0.00% |
| userspace_semantic_plane | 20 | 361.474 | 48.578 | 0.00% |
| userspace_compromised | 0 | 260.298 | 69.903 | 0.00% |
| userspace_compromised | 5 | 5.018 | 10489.195 | 68.75% |
| userspace_compromised | 10 | 272.991 | 51.308 | 100.00% |
| userspace_compromised | 20 | 189.507 | 25.252 | 100.00% |

## Observability

| mode | independent_audit | state_introspection | post_crash_visibility | root_cause_success_rate |
|---|---:|---:|---:|---:|
| kernel | 1 | 1 | 1 | 100.00% |
| userspace | 0 | 0 | 0 | 100.00% |
