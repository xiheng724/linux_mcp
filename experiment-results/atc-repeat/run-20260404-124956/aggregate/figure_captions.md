## Figure Captions

### `figure_repeated_atc.png`

Repeated ATC results aggregated over three full runs. Left: end-to-end throughput and tail latency for `direct` and `mcpd` across concurrency levels 1, 4, and 8; bars show the run mean and error bars show one standard deviation. Right: variant comparison for `forwarder_only` and `userspace_semantic_plane`, showing that most overhead comes from the userspace mediation path while the additional kernel-backed semantic checks introduce a smaller incremental cost than the full direct-to-mcpd gap.
