# E3 Sustained Overload Report

- run_ts: `run-20260414-071246`
- dry_run: `False` | smoke: `False`
- duration per cell: 180.0s (warmup 30.0s), reps=3
- systems: userspace, seccomp, kernel
- concurrency levels: [50, 100, 200, 400, 800]

## p99 knee by system

| system | knee_c |
|---|---:|
| kernel | 100.0 |
| seccomp | 100.0 |
| userspace | 100.0 |

## Cell summary

| system | concurrency | rep | rps | p50 | p95 | p99 | error_rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| seccomp | 50 | 1 | 4.011 | 4675.8099 | 19111.9238 | 19871.8697 | 0.501385 |
| seccomp | 400 | 1 | 1453.739 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 100 | 1 | 1696.456 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 800 | 1 | 326099.15 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 400 | 1 | 333768.5 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 800 | 1 | 1061527.639 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 200 | 1 | 2060.333 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 50 | 1 | 2018.056 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 800 | 1 | 1773.894 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 50 | 1 | 2202.072 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 200 | 1 | 1776.261 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 200 | 1 | 2146.478 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 100 | 1 | 2094.989 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 100 | 1 | 2137.189 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 400 | 1 | 1892.728 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 200 | 2 | 1817.506 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 400 | 2 | 1979.211 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 50 | 2 | 2027.672 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 400 | 2 | 2020.961 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 800 | 2 | 289042.211 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 50 | 2 | 1767.083 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 50 | 2 | 2317.578 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 800 | 2 | 377604.239 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 100 | 2 | 1755.85 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 200 | 2 | 1744.422 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 800 | 2 | 375295.667 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 100 | 2 | 2131.661 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 400 | 2 | 1863.289 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 100 | 2 | 2210.233 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 200 | 2 | 2034.206 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 200 | 3 | 2041.261 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 400 | 3 | 1824.467 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 100 | 3 | 1825.089 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 400 | 3 | 1988.567 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 100 | 3 | 2188.517 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 50 | 3 | 2194.217 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 800 | 3 | 369244.878 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 50 | 3 | 2296.206 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 50 | 3 | 2182.344 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 400 | 3 | 1944.272 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 200 | 3 | 2127.372 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 800 | 3 | 402701.344 | 0.0 | 0.0 | 0.0 | 1.0 |
| userspace | 100 | 3 | 1716.844 | 0.0 | 0.0 | 0.0 | 1.0 |
| seccomp | 200 | 3 | 2095.45 | 0.0 | 0.0 | 0.0 | 1.0 |
| kernel | 800 | 3 | 372870.133 | 0.0 | 0.0 | 0.0 | 1.0 |

## p99 block-bootstrap CI (pooled reps)

| system | concurrency | p99 | CI lo | CI hi | n_samples |
|---|---:|---:|---:|---:|---:|
| seccomp | 50 | 19871.8697 | 9425.062 | 19898.5121 | 360 |

## Pairwise Mood's median test (by concurrency)

| concurrency | system_a | system_b | median_test_p |
|---:|---|---|---:|
| 50 | kernel | seccomp | 1.0 |
| 50 | kernel | userspace | 1.0 |
| 50 | seccomp | userspace | 1.0 |
| 100 | kernel | seccomp | 1.0 |
| 100 | kernel | userspace | 1.0 |
| 100 | seccomp | userspace | 1.0 |
| 200 | kernel | seccomp | 1.0 |
| 200 | kernel | userspace | 1.0 |
| 200 | seccomp | userspace | 1.0 |
| 400 | kernel | seccomp | 1.0 |
| 400 | kernel | userspace | 1.0 |
| 400 | seccomp | userspace | 1.0 |
| 800 | kernel | seccomp | 1.0 |
| 800 | kernel | userspace | 1.0 |
| 800 | seccomp | userspace | 1.0 |

## Notes

- Block-bootstrap uses a fixed block size of 10 consecutive latency samples to approximate autocorrelation; this is a pragmatic approximation, not a Politis-Romano optimal rule. Treat CI widths as indicative.
- Mood's median test is approximated with a chi-square(1) survival function (erfc). Use it for regime detection, not absolute p-values.