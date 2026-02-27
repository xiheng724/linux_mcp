# mcpd

Userspace daemon for policy, arbitration, and data-plane bridge (Unix Domain Socket).

## Data Plane

- Socket path: `/tmp/mcpd.sock`
- Framing: `4-byte big-endian length + UTF-8 JSON`
- Built-in tools:
  - `tool_id=1` echo
  - `tool_id=2` cpu_burn (`{"ms": 200}`)
  - `tool_id=3` text_stats (`{"text": "..."}`)
  - `tool_id=4` sys_info (`{"path": "."}`)
  - `tool_id=5` calc (`{"expression": "(21+7)*3"}`)
  - `tool_id=6` file_preview (`{"path": "README.md", "max_lines": 30}`)
  - `tool_id=7` hash_text (`{"text": "hello", "algorithm": "sha256"}`)
  - `tool_id=8` time_now (`{"timezone": "local"}`)
- Tool code location:
  - `tool-app/*.py`

## Tool Semantic Registry

- Manifest directory: `mcpd/tools.d/*.json`
- Natural-language semantics are registered in manifest fields:
  - `description`
  - `input_schema`
  - `examples`
- Runtime binding field:
  - `app_path` (must point to `tool-app/...`)
- Startup behavior:
  - load manifests
  - compute per-tool manifest hash
  - expose discovery API via UDS:
    - request: `{"sys":"list_tools"}`
    - response: `{"status":"ok","tools":[...]}` (semantic fields only; hides `app_path`)
- Kernel mapping sync:
  - `scripts/run_mcpd.sh` runs `python3 mcpd/reconcile_kernel.py` before start
  - daemon start fails fast if manifest and kernel tool registry mismatch
  - strict 1:1 mapping on `tool_id/name/perm/cost`
  - also verifies `hash` when hash-aware clients are used
  - mcpd dispatches to tool app by `app_path`

## Gateway Enforcement

- Client execution request:
  - `{"kind":"tool:exec","req_id":...,"agent_id":"a1","tool_id":...,"tool_hash":"8hex","payload":{...}}`
- `mcpd` enforces closed-loop control:
  1. `genl_register_agent` (lazy, once per agent)
  2. `genl_tool_request` arbitration (DENY/DEFER/ALLOW; DEFER retry loop)
  3. execute tool app from manifest `app_path`
  4. `genl_tool_complete` report

## Run

Prerequisites:
- `kernel_mcp` module loaded
- client binaries built (`make -C client clean && make -C client`)

Start:

```bash
bash scripts/run_mcpd.sh
```

Stop:

```bash
bash scripts/stop_mcpd.sh
```

Runtime files:
- PID: `/tmp/mcpd-<uid>.pid`
- Log: `/tmp/mcpd-<uid>.log`
