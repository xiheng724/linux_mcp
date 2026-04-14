# Statistical Rehash Report (E5)

Source snapshot: `/Users/lixiheng/Code/linux_mcp/experiment-results/linux-mcp-paper-final-n5/run-20260405-173020`

This report post-processes existing `linux_mcp_eval.py` snapshots
without re-running any workload. It closes three gaps in the original
statistical treatment:

1. all pairwise comparisons (not only vs userspace)
2. Benjamini-Hochberg correction across the full pairwise set
3. Cliff's delta effect size alongside each t-test

Where an ablation run is supplied via `--ablation-run`, the measured
KERNEL_MCP_CMD_NOOP RTT is used as a noise floor anchor for μs-level
overhead claims.

## Noise floor (measured)

| metric | value (ms) |
|---|---:|
| avg  | 0.003150 |
| p50  | 0.003083 |
| p95  | 0.003292 |
| p99  | 0.004542 |

Any μs-level claim from the ablation or microbench suites should
be read as `floor + Δ`. The floor captures everything that
Generic Netlink + the minimum `KMCP_CMD_NOOP` handler contribute
before any registry, hash, binding, or ticket work is done.

## Latency pairwise tests (Welch t, BH-corrected, Cliff's delta)

| payload | system_a | system_b | n_a | n_b | mean_a | mean_b | t | p_raw | p_bh | δ |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| large | kernel | seccomp | 5 | 5 | 6.908 | 9.3302 | -11.7935 | 0.0000 | 0.0000 | 1.000 |
| large | kernel | userspace | 5 | 5 | 6.908 | 7.2256 | -1.9909 | 0.0465 | 0.0465 | 0.920 |
| large | seccomp | userspace | 5 | 5 | 9.3302 | 7.2256 | 8.1986 | 0.0000 | 0.0000 | -1.000 |
| medium | kernel | seccomp | 5 | 5 | 0.828 | 0.8392 | -3.5704 | 0.0004 | 0.0005 | 1.000 |
| medium | kernel | userspace | 5 | 5 | 0.828 | 0.8006 | 9.9653 | 0.0000 | 0.0000 | -1.000 |
| medium | seccomp | userspace | 5 | 5 | 0.8392 | 0.8006 | 13.3183 | 0.0000 | 0.0000 | -1.000 |
| small | kernel | seccomp | 5 | 5 | 0.7868 | 0.7778 | 2.3024 | 0.0213 | 0.0274 | -0.760 |
| small | kernel | userspace | 5 | 5 | 0.7868 | 0.7638 | 4.0172 | 0.0001 | 0.0001 | -1.000 |
| small | seccomp | userspace | 5 | 5 | 0.7778 | 0.7638 | 2.1355 | 0.0327 | 0.0368 | -0.640 |

## Latency cell bootstrap CIs

| system | payload | n | mean_avg_ms | [CI] | mean_p99_ms | [CI] |
|---|---|---:|---:|---|---:|---|
| kernel | large | 5 | 6.9080 | [6.8628, 6.9624] | 8.6518 | [8.5452, 8.7456] |
| kernel | medium | 5 | 0.8280 | [0.8244, 0.8316] | 1.0296 | [0.9918, 1.0662] |
| kernel | small | 5 | 0.7868 | [0.7840, 0.7896] | 1.0736 | [1.0482, 1.1022] |
| seccomp | large | 5 | 9.3302 | [9.1076, 9.7448] | 12.0726 | [10.9152, 14.1260] |
| seccomp | medium | 5 | 0.8392 | [0.8360, 0.8436] | 1.0320 | [0.9894, 1.0723] |
| seccomp | small | 5 | 0.7778 | [0.7720, 0.7846] | 1.0094 | [0.9568, 1.0576] |
| userspace | large | 5 | 7.2256 | [7.0112, 7.5498] | 9.8074 | [8.6864, 11.9036] |
| userspace | medium | 5 | 0.8006 | [0.7972, 0.8034] | 1.0152 | [0.9758, 1.0394] |
| userspace | small | 5 | 0.7638 | [0.7544, 0.7732] | 1.1444 | [1.0250, 1.3064] |

## Scalability pairwise tests

| agents | conc | system_a | system_b | mean_a | mean_b | p_raw | p_bh | δ |
|---|---|---|---|---:|---:|---:|---:|---:|
| 1 | 1 | kernel | seccomp | 1071.147 | 1088.54 | 0.0000 | 0.0000 | 1.000 |
| 1 | 1 | kernel | userspace | 1071.147 | 1117.534 | 0.0000 | 0.0000 | 1.000 |
| 1 | 1 | seccomp | userspace | 1088.54 | 1117.534 | 0.0000 | 0.0000 | 1.000 |
| 1 | 10 | kernel | seccomp | 1009.413 | 1036.947 | 0.0000 | 0.0000 | 1.000 |
| 1 | 10 | kernel | userspace | 1009.413 | 1145.953 | 0.0000 | 0.0000 | 1.000 |
| 1 | 10 | seccomp | userspace | 1036.947 | 1145.953 | 0.0000 | 0.0000 | 1.000 |
| 1 | 100 | kernel | seccomp | 1103.733 | 1072.52 | 0.5957 | 0.6619 | 0.600 |
| 1 | 100 | kernel | userspace | 1103.733 | 1213.36 | 0.0000 | 0.0000 | 1.000 |
| 1 | 100 | seccomp | userspace | 1072.52 | 1213.36 | 0.0169 | 0.0211 | 1.000 |
| 1 | 50 | kernel | seccomp | 1096.227 | 1123.547 | 0.0000 | 0.0000 | 1.000 |
| 1 | 50 | kernel | userspace | 1096.227 | 1215.647 | 0.0000 | 0.0000 | 1.000 |
| 1 | 50 | seccomp | userspace | 1123.547 | 1215.647 | 0.0000 | 0.0000 | 1.000 |
| 10 | 1 | kernel | seccomp | 1080.353 | 1079.2 | 0.9564 | 0.9564 | 0.600 |
| 10 | 1 | kernel | userspace | 1080.353 | 1112.753 | 0.1245 | 0.1524 | 0.600 |
| 10 | 1 | seccomp | userspace | 1079.2 | 1112.753 | 0.0000 | 0.0000 | 1.000 |
| 10 | 10 | kernel | seccomp | 1028.307 | 1047.18 | 0.2865 | 0.3306 | 0.360 |
| 10 | 10 | kernel | userspace | 1028.307 | 1140.274 | 0.0000 | 0.0000 | 1.000 |
| 10 | 10 | seccomp | userspace | 1047.18 | 1140.274 | 0.0000 | 0.0000 | 1.000 |
| 10 | 100 | kernel | seccomp | 1136.787 | 1125.787 | 0.6755 | 0.7237 | 0.200 |
| 10 | 100 | kernel | userspace | 1136.787 | 1217.333 | 0.0024 | 0.0032 | 0.840 |
| 10 | 100 | seccomp | userspace | 1125.787 | 1217.333 | 0.0000 | 0.0000 | 1.000 |
| 10 | 50 | kernel | seccomp | 1124.107 | 1113.0 | 0.6531 | 0.7125 | 0.040 |
| 10 | 50 | kernel | userspace | 1124.107 | 1215.747 | 0.0001 | 0.0001 | 0.920 |
| 10 | 50 | seccomp | userspace | 1113.0 | 1215.747 | 0.0000 | 0.0000 | 1.000 |
| 20 | 1 | kernel | seccomp | 1060.673 | 1100.947 | 0.0011 | 0.0016 | 1.000 |
| 20 | 1 | kernel | userspace | 1060.673 | 1104.84 | 0.0000 | 0.0000 | 1.000 |
| 20 | 1 | seccomp | userspace | 1100.947 | 1104.84 | 0.7555 | 0.7818 | -0.200 |
| 20 | 10 | kernel | seccomp | 1003.173 | 1054.38 | 0.0002 | 0.0004 | 1.000 |
| 20 | 10 | kernel | userspace | 1003.173 | 1130.48 | 0.0000 | 0.0000 | 1.000 |
| 20 | 10 | seccomp | userspace | 1054.38 | 1130.48 | 0.0000 | 0.0000 | 1.000 |
| 20 | 100 | kernel | seccomp | 1093.467 | 1200.393 | 0.0029 | 0.0038 | 1.000 |
| 20 | 100 | kernel | userspace | 1093.467 | 1211.573 | 0.0000 | 0.0000 | 1.000 |
| 20 | 100 | seccomp | userspace | 1200.393 | 1211.573 | 0.7557 | 0.7818 | -0.200 |
| 20 | 50 | kernel | seccomp | 1092.147 | 1175.9 | 0.0026 | 0.0034 | 1.000 |
| 20 | 50 | kernel | userspace | 1092.147 | 1207.507 | 0.0000 | 0.0000 | 1.000 |
| 20 | 50 | seccomp | userspace | 1175.9 | 1207.507 | 0.2547 | 0.2997 | 0.120 |
| 5 | 1 | kernel | seccomp | 1066.193 | 1069.353 | 0.8293 | 0.8434 | 0.600 |
| 5 | 1 | kernel | userspace | 1066.193 | 1109.0 | 0.0000 | 0.0000 | 1.000 |
| 5 | 1 | seccomp | userspace | 1069.353 | 1109.0 | 0.0076 | 0.0097 | 1.000 |
| 5 | 10 | kernel | seccomp | 1025.207 | 1037.64 | 0.2940 | 0.3328 | 0.600 |
| 5 | 10 | kernel | userspace | 1025.207 | 1138.613 | 0.0000 | 0.0000 | 1.000 |
| 5 | 10 | seccomp | userspace | 1037.64 | 1138.613 | 0.0000 | 0.0000 | 1.000 |
| 5 | 100 | kernel | seccomp | 1097.06 | 1152.68 | 0.0021 | 0.0029 | 1.000 |
| 5 | 100 | kernel | userspace | 1097.06 | 1218.773 | 0.0000 | 0.0000 | 1.000 |
| 5 | 100 | seccomp | userspace | 1152.68 | 1218.773 | 0.0002 | 0.0003 | 1.000 |
| 5 | 50 | kernel | seccomp | 1112.48 | 1134.24 | 0.2497 | 0.2997 | 0.600 |
| 5 | 50 | kernel | userspace | 1112.48 | 1215.94 | 0.0000 | 0.0000 | 1.000 |
| 5 | 50 | seccomp | userspace | 1134.24 | 1215.94 | 0.0000 | 0.0000 | 1.000 |
| 50 | 1 | kernel | seccomp | 1048.047 | 1067.353 | 0.0000 | 0.0000 | 1.000 |
| 50 | 1 | kernel | userspace | 1048.047 | 1090.16 | 0.0000 | 0.0000 | 1.000 |
| 50 | 1 | seccomp | userspace | 1067.353 | 1090.16 | 0.0000 | 0.0000 | 0.920 |
| 50 | 10 | kernel | seccomp | 1003.053 | 1020.16 | 0.0002 | 0.0003 | 0.920 |
| 50 | 10 | kernel | userspace | 1003.053 | 1126.92 | 0.0000 | 0.0000 | 1.000 |
| 50 | 10 | seccomp | userspace | 1020.16 | 1126.92 | 0.0000 | 0.0000 | 1.000 |
| 50 | 100 | kernel | seccomp | 1085.047 | 1112.453 | 0.0000 | 0.0000 | 1.000 |
| 50 | 100 | kernel | userspace | 1085.047 | 1207.193 | 0.0000 | 0.0000 | 1.000 |
| 50 | 100 | seccomp | userspace | 1112.453 | 1207.193 | 0.0000 | 0.0000 | 1.000 |
| 50 | 50 | kernel | seccomp | 1086.207 | 1102.12 | 0.0013 | 0.0018 | 0.920 |
| 50 | 50 | kernel | userspace | 1086.207 | 1201.747 | 0.0000 | 0.0000 | 1.000 |
| 50 | 50 | seccomp | userspace | 1102.12 | 1201.747 | 0.0000 | 0.0000 | 1.000 |

## Caveats

- Latency tests use per-repetition means (n=5 in paper-final-n5).
  Low-n Welch t-tests should be read alongside Cliff's delta — the
  non-parametric effect size is more informative when n is small.
- p-values use a normal-distribution approximation to the t tail. At
  df ≥ ~30 this is within 1% of the exact t CDF; at the n=5 per-cell
  size the approximation may under-report p slightly. Values near
  the decision boundary should be treated with care.
- BH correction is applied across each metric family (latency,
  scalability) separately, not globally.
