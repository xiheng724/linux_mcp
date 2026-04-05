# linux_mcp Experiment Report

## Latency

| system | payload | avg_ms | p50_ms | p95_ms | p99_ms |
|---|---|---:|---:|---:|---:|
| userspace | small | 2.468 | 1.879 | 4.7 | 8.83 |
| userspace | medium | 2.363 | 1.88 | 4.428 | 6.438 |
| userspace | large | 16.238 | 14.847 | 21.636 | 53.996 |
| seccomp | small | 2.926 | 2.453 | 5.645 | 7.365 |
| seccomp | medium | 3.061 | 2.573 | 5.279 | 8.618 |
| seccomp | large | 21.389 | 19.76 | 28.071 | 61.711 |

## Scalability

| system | agents | concurrency | throughput_rps | error_rate | p95_ms |
|---|---:|---:|---:|---:|---:|
| userspace | 1 | 1 | 394.195 | 0.00% | 4.45 |
| userspace | 1 | 10 | 521.783 | 0.00% | 26.643 |
| userspace | 1 | 100 | 530.583 | 0.00% | 68.009 |
| userspace | 10 | 1 | 425.816 | 0.00% | 4.449 |
| userspace | 10 | 10 | 492.066 | 0.00% | 33.878 |
| userspace | 10 | 100 | 499.846 | 0.00% | 327.225 |
| userspace | 50 | 1 | 428.94 | 0.00% | 4.561 |
| userspace | 50 | 10 | 476.124 | 0.00% | 38.203 |
| userspace | 50 | 100 | 495.393 | 0.00% | 397.467 |
| seccomp | 1 | 1 | 236.931 | 0.00% | 5.98 |
| seccomp | 1 | 10 | 305.615 | 0.00% | 44.108 |
| seccomp | 1 | 100 | 327.437 | 0.00% | 133.022 |
| seccomp | 10 | 1 | 351.946 | 0.00% | 5.341 |
| seccomp | 10 | 10 | 409.642 | 0.00% | 40.267 |
| seccomp | 10 | 100 | 399.663 | 0.00% | 414.301 |
| seccomp | 50 | 1 | 356.192 | 0.00% | 5.416 |
| seccomp | 50 | 10 | 382.996 | 0.00% | 45.129 |
| seccomp | 50 | 100 | 391.309 | 0.00% | 485.644 |

## Attack Matrix

| attack_type | userspace | seccomp | kernel |
|---|---|---|---|
| spoof | success | success |  |
| replay | success | fail |  |
| substitute | success | success |  |
| escalation | success | fail |  |
