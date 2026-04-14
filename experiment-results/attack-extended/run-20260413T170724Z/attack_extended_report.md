# E4 — Extended Attack Surface

Runner: `scripts/experiments/attack_extended.py`

## Phase 1 — TOCTOU on the approval window

- iterations: 10000, breach (ALLOW) count: 0
- blocked rate 95% CI: [0.999631, 1.000000]
- deny_hash_mismatch: 9984, deny_binding_mismatch: 0, defer: 16
- reason histogram:
  - approval_ticket_unknown: 16
  - hash_mismatch: 9984

## Phase 2 — Cross-uid session hijack

- attempts: 500, blocked: 326, passed: 174
- blocked rate 95% CI: [0.608444, 0.693746]
- sub-case pass counts — blind: 0, guessed: 0, leaked: 174
- **finding**: missing peer-cred enforcement → follow-up patch recommended: kernel_mcp_cmd_tool_request does not compare NETLINK_CB(skb) credentials against registered agent->uid

## Phase 3 — Generic Netlink dumb fuzzer

- total inputs sent: 876768
- socket errors: 0
- dmesg oops: 0, warn: 0, bug: 0, kmemleak: 0, gpf: 0
- see `fuzz_report.md` for per-CMD errno tables.
