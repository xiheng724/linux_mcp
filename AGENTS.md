# linux-mcp Project Rules

This repository implements a clean-room Kernel MCP governance system.

## Architecture
- kernel-mcp/: Linux kernel module
- mcpd/: daemon
- client/: agent library
- bench/: benchmarking
- scripts/: build/run automation
- results/: generated CSV
- plots/: generated graphs

## Core Principles
1) Kernel = control plane only (Generic Netlink).
2) No JSON parsing in kernel.
3) Large tool outputs use unix socket, not netlink.
4) Every phase must be runnable and testable.
5) Always apply changes using patch.
6) Always run verification commands and paste output.

## Coding Standards
Kernel:
- Defensive error handling
- No blocking in netlink handlers
- Clear sysfs attribute definitions

Python:
- Type hints
- Structured logging
- No hidden global state

## Phases
Phase 0: skeleton + scripts
Phase 1: netlink ping/pong
Phase 2: tool register + sysfs
Phase 3: arbitration + audit
Phase 4: daemon + client
Phase 5: benchmark
Phase 6: cgroup (optional)

## Kernel danger zones (must comply)
- sysfs/kobject lifecycle: every created kobject must be released; module exit must remove sysfs tree cleanly; repeated insmod/rmmod must not leak or crash.
- Concurrency: token accounting must be atomic or protected by spinlock; never update shared counters without protection.
- Rate limiting: DO NOT use timers or kernel threads. Use lazy refill based on jiffies delta on each request.


以后每次开发/运行 GUI：

cd ~/Code/linux-mcp
source .venv/bin/activate
python llm-app/gui_app.py