## Figure Captions

### `figure_repeated_security_attack_semantic.png`

Repeated security results aggregated over three full runs. The attack panel shows that `mcpd` consistently blocks all tested spoofing, replay, tampering, and TOCTOU cases, while the corresponding userspace-only ablations fail exactly where their mechanism is removed. The semantic panel shows perfect precision but incomplete recall, which means the current semantic hash policy avoids false positives on benign edits but still misses one adversarial class.

### `figure_repeated_security_daemon_mixed.png`

Repeated daemon and mixed-traffic results aggregated over three full runs. The daemon panel shows that kernel-backed approval state remains visible and enforceable after a daemon crash even though session state does not survive, while the userspace baseline loses both state and post-crash visibility. The mixed-traffic panel shows that `mcpd` keeps attack acceptance at zero as malicious traffic increases, whereas a compromised userspace control plane accepts nearly all attacks and experiences severe tail-latency collapse at high malicious rates.
