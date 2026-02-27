# linux-mcp

Kernel MCP clean-room governance prototype.

## Directory Layout

- `kernel-mcp/`: kernel module (Generic Netlink control plane)
- `mcpd/`: Unix Domain Socket data-plane daemon
- `mcpd/tools.d/`: tool semantic manifests (single source in user-space)
- `tool-app/`: standalone tool applications executed by mcpd
- `client/`: raw netlink tools and demo client
- `bench/`: benchmark runner and plot generator
- `llm-app/`: semantic tool-selection demo client
- `scripts/`: build/load/acceptance automation
- `results/`: benchmark outputs
- `plots/`: generated figures

## Clean State

The repository should keep source and scripts only.
Build/cache artifacts to clean:

```bash
make -C client clean
make -C kernel-mcp clean
python3 - <<'PY'
import pathlib, shutil
for p in pathlib.Path('.').rglob('__pycache__'):
    if p.is_dir():
        shutil.rmtree(p)
PY
```

## Core Contract

- Kernel stays control-plane only (Generic Netlink).
- Kernel does not parse JSON.
- JSON and large payload stay in user-space UDS (`mcpd`).
- llm-app talks to `mcpd` only; `mcpd` is the system gateway to kernel arbitration + tool execution.
- `mcpd` startup is fail-fast:
  - load `mcpd/tools.d/*.json`
  - reconcile `tool_id/name/perm/cost` with kernel registry
  - refuse start on any mismatch.
- gateway closed-loop for each execution:
  - llm-app -> `{"kind":"tool:exec",...}` -> mcpd
  - mcpd -> kernel arbitration (`genl_tool_request`)
  - ALLOW only then run tool-app
  - mcpd -> kernel completion (`genl_tool_complete`)

Tool natural-language semantics are registered in `mcpd/tools.d/*.json` using:
- `description`
- `input_schema`
- `examples`
- `app_path` (points to executable tool app under `tool-app/`)

## Command Guide

1. Build userspace clients:

```bash
make -C client clean
make -C client
```

2. Build/load kernel module:

```bash
sudo bash scripts/load_module.sh
```

3. Start gateway daemon (includes reconcile):

```bash
bash scripts/run_mcpd.sh
```

4. Activate venv for app development (recommended):

```bash
source .venv/bin/activate
```

5. Run llm-app single request:

```bash
python3 llm-app/cli.py --once "hello"
```

6. Run llm-app REPL:

```bash
python3 llm-app/cli.py --repl
```

7. Run llm-app GUI:

```bash
python3 llm-app/gui_app.py
```

8. Optional DeepSeek selector:

```bash
export DEEPSEEK_API_KEY="your_key"
python3 llm-app/cli.py --selector deepseek --repl
```

9. Stop and unload:

```bash
bash scripts/stop_mcpd.sh
sudo bash scripts/unload_module.sh
```

## How llm-app Connects to tool-app

`llm-app` never executes tool-app directly.

Execution path:
1. `llm-app -> mcpd` via UDS `{"sys":"list_tools"}` to get tool semantics.
2. `llm-app` chooses a tool by heuristic or DeepSeek.
3. `llm-app -> mcpd` via UDS `{"kind":"tool:exec",...}`.
4. `mcpd` performs kernel arbitration (`genl_tool_request`).
5. If ALLOW, `mcpd` runs the mapped `tool-app/*.py`.
6. `mcpd` reports completion to kernel (`genl_tool_complete`).
7. `mcpd -> llm-app` returns JSON result.

This makes `mcpd` the only gateway for controlled tool execution.

## Kernel Scope (Important)

- Kernel module path: `kernel-mcp/src/kernel_mcp_main.c`
- Kernel responsibilities:
  - Generic Netlink control-plane commands
  - tool/agent registry and sysfs state export
  - arbitration decisions (ALLOW/DENY/DEFER)
  - token bucket governance (lazy jiffies refill, concurrency-safe)
  - execution completion accounting from userspace reports
- Kernel explicitly does **not**:
  - parse JSON
  - carry large payload/results

Runtime sysfs:
- `/sys/kernel/mcp/tools/*`
- `/sys/kernel/mcp/agents/*`

## Manual Netlink Operations

```bash
./client/bin/genl_register_agent --id a1
./client/bin/genl_tool_request --agent a1 --tool 2 --n 10
```

Manual tool registration example (hash from manifest):

```bash
HASH="$(python3 - <<'PY'
import json,hashlib
raw=json.load(open('mcpd/tools.d/3_text_stats.json','r',encoding='utf-8'))
print(hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()[:8])
PY
)"
./client/bin/genl_register_tool --id 3 --name text_stats --perm 1 --cost 1 --hash "$HASH"
```

List kernel tool registry:

```bash
./client/bin/genl_list_tools
ls -l /sys/kernel/mcp/tools
```

## Add New Tool-App

1. Add app script under `tool-app/` (supports `--stdin-json`, prints JSON result).
2. Add manifest under `mcpd/tools.d/` with:
   - `tool_id/name/perm/cost`
   - natural-language fields `description/input_schema/examples`
   - `app_path` pointing to your script (e.g. `tool-app/my_tool.py`)
3. Start daemon:

```bash
bash scripts/run_mcpd.sh
```

`run_mcpd.sh` will reconcile manifest with kernel registry and fail fast on mismatch.

## Permission Strategy

- Demo mode (default):
  - keep current developer ownership, easiest to iterate.
- Harden mode (optional):
  - run `bash scripts/harden_toolapp_perms.sh`
  - script only applies restrictive ownership/perms when it will not break `run_mcpd.sh` for current user; otherwise it prints WARN and exits safely.

## Full Demo Acceptance

```bash
sudo bash scripts/demo_acceptance.sh
```

## Runtime Files

- UDS socket: `/tmp/mcpd.sock`
- PID file: `/tmp/mcpd-<uid>.pid`
- Log file: `/tmp/mcpd-<uid>.log`
