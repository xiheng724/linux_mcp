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
  - `tool_id=9` volume_control (`{"action":"set","level":40}`)
  - `tool_id=10` file_create (`{"path":"tmp/demo.txt","content":"hello"}`)
  - `tool_id=11` file_list (`{"path":"tool-app","max_entries":50}`)
  - `tool_id=12` file_delete (`{"path":"tmp/demo.txt"}`)
  - `tool_id=13` file_copy (`{"src_path":"README.md","dst_path":"tmp/README.copy.md"}`)
  - `tool_id=14` file_rename (`{"src_path":"tmp/a.txt","dst_path":"tmp/a_renamed.txt"}`)
- Tool code location:
  - `tool-app/apps/*.py` (one module per app)

## Tool Service Protocol (Resident Service)

- Transport: Unix Domain Socket per app endpoint (from manifest `endpoint`).
- Framing: `4-byte big-endian length prefix + UTF-8 JSON`.
- Request object:
  - `{"req_id":int,"agent_id":str,"tool_id":int,"payload":object}`
- Response object:
  - `{"req_id":int,"status":"ok"|"error","result":object,"error":str,"t_ms":int}`

## Tool Semantic Registry

- Manifest directory: `tool-app/manifests/*.json`
- Natural-language semantics are registered in manifest fields:
  - `tools[].description`
  - `tools[].input_schema`
  - `tools[].examples`
- Runtime binding field:
  - `app_impl` (app module path)
  - `service_path` (app service entry)
  - `mode` (`uds_service`)
  - `endpoint` (app resident socket)
  - `tools[].handler` (handler key in app module `HANDLERS`)
- Startup behavior:
  - start with empty runtime registry
  - accept `{"sys":"register_manifest","manifest":{...}}` from `tool-app`
  - validate and expand tool registry in memory
  - sync `tool_id/name/perm/cost/hash` to kernel
  - compute per-tool semantic hash from canonical subset:
    - `tool_id/name/app_id/app_name/perm/cost/description/input_schema/examples`
  - expose app discovery API via UDS:
    - request: `{"sys":"list_apps"}`
    - response: `{"status":"ok","apps":[...]}`
  - expose discovery API via UDS:
    - request: `{"sys":"list_tools"}`
    - request (filtered): `{"sys":"list_tools","app_id":"settings_app"}`
    - response: `{"status":"ok","tools":[...]}` (semantic fields only; hides runtime fields)
- Kernel mapping sync:
  - `scripts/run_mcpd.sh` waits for tool manifests to register, then runs `python3 mcpd/reconcile_kernel.py`
  - daemon start fails fast if manifest and kernel tool registry mismatch
  - strict 1:1 mapping on `tool_id/name/perm/cost`
  - also verifies `hash` when hash-aware clients are used
  - mcpd dispatches to app resident service by `endpoint` + `tool_id`

## Gateway Enforcement

- Client execution request:
  - `{"kind":"tool:exec","req_id":...,"agent_id":"a1","app_id":"settings_app","tool_id":...,"tool_hash":"8hex","payload":{...}}`
- `mcpd` enforces closed-loop control:
  1. `genl_register_agent` (lazy, once per agent)
  2. `genl_tool_request` arbitration (DENY/DEFER/ALLOW; DEFER retry loop)
  3. call app resident service via manifest `endpoint` + `tool_id`
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
