# E4 Phase 3 — Generic Netlink dumb fuzzer

- total inputs sent: **880640**
- socket errors: 0

## dmesg findings (delta before/after)

- oops: 0
- warn: 0
- bug: 0
- kmemleak: 0
- gpf: 0

## Per-command errno histogram

### TOOL_REQUEST (n=110626)

- errno=-34: 22018
- errno=-22: 22102
- errno=-14: 22001
- errno=-2: 22280
- errno=-1: 22225

### TOOL_COMPLETE (n=109609)

- errno=-34: 22222
- errno=-22: 22055
- errno=-14: 21772
- errno=-2: 21723
- errno=-1: 21837

### TOOL_REGISTER (n=110016)

- errno=-34: 22374
- errno=-22: 21769
- errno=-14: 22140
- errno=-2: 21802
- errno=-1: 21931

### RESET_TOOLS (n=109846)

- errno=-34: 21917
- errno=-22: 22063
- errno=-14: 22122
- errno=-2: 21885
- errno=-1: 21859

### NOOP (n=110211)

- errno=-34: 22019
- errno=-22: 22120
- errno=-14: 22229
- errno=-2: 21776
- errno=-1: 22067

### AGENT_REGISTER (n=109968)

- errno=-34: 21818
- errno=-22: 22217
- errno=-14: 21778
- errno=-2: 21987
- errno=-1: 22168

### LIST_TOOLS (n=109782)

- errno=-34: 22017
- errno=-22: 22112
- errno=-14: 22061
- errno=-2: 21947
- errno=-1: 21645

### APPROVAL_DECIDE (n=110582)

- errno=-34: 22044
- errno=-22: 22226
- errno=-14: 22020
- errno=-2: 22131
- errno=-1: 22161

## Mutation kind histogram

- bit_flip: 192581
- oversize_len: 193514
- truncate: 191699
- none: 109846
- type_sub: 193000

**Claim: N inputs sent, 0 oops, 100% deterministic errno**
