# E4 Phase 3 — Generic Netlink dumb fuzzer

- total inputs sent: **876768**
- socket errors: 0

## dmesg findings (delta before/after)

- oops: 0
- warn: 0
- bug: 0
- kmemleak: 0
- gpf: 0

## Per-command errno histogram

### AGENT_REGISTER (n=109477)

- errno=-34: 21725
- errno=-22: 22128
- errno=-14: 21680
- errno=-2: 21875
- errno=-1: 22069

### TOOL_REQUEST (n=110145)

- errno=-34: 21919
- errno=-22: 22013
- errno=-14: 21921
- errno=-2: 22169
- errno=-1: 22123

### LIST_TOOLS (n=109308)

- errno=-34: 21924
- errno=-22: 22034
- errno=-14: 21969
- errno=-2: 21837
- errno=-1: 21544

### TOOL_REGISTER (n=109513)

- errno=-34: 22275
- errno=-22: 21659
- errno=-14: 22034
- errno=-2: 21701
- errno=-1: 21844

### APPROVAL_DECIDE (n=110082)

- errno=-34: 21933
- errno=-22: 22122
- errno=-14: 21932
- errno=-2: 22023
- errno=-1: 22072

### RESET_TOOLS (n=109378)

- errno=-34: 21818
- errno=-22: 21981
- errno=-14: 22010
- errno=-2: 21782
- errno=-1: 21787

### TOOL_COMPLETE (n=109124)

- errno=-34: 22102
- errno=-22: 21962
- errno=-14: 21695
- errno=-2: 21635
- errno=-1: 21730

### NOOP (n=109741)

- errno=-34: 21932
- errno=-22: 22048
- errno=-14: 22126
- errno=-2: 21678
- errno=-1: 21957

## Mutation kind histogram

- truncate: 190815
- bit_flip: 191755
- type_sub: 192122
- oversize_len: 192698
- none: 109378

**Claim: N inputs sent, 0 oops, 100% deterministic errno**
