# mcpd

Userspace gateway for kernel arbitration, manifest registry, and tool execution.

## Runtime Model

- `mcpd` auto-loads `tool-app/manifests/*.json` at startup.
- Manifest semantics are the source of truth for tool discovery.
- `mcpd` syncs `tool_id/name/perm/cost/hash` into the kernel registry.
- Tool execution happens through the app's declared interface, not by importing Python handlers.

## Supported Tool Transport

- `uds_rpc`
  - endpoint from manifest `endpoint`
  - request:
    - `{"req_id":int,"agent_id":str,"tool_id":int,"operation":str,"payload":object}`
  - response:
    - `{"req_id":int,"status":"ok"|"error","result":object,"error":str,"t_ms":int}`

## Public RPC

- `{"sys":"list_apps"}`
- `{"sys":"list_tools"}`
- `{"sys":"list_tools","app_id":"settings_app"}`
- `{"kind":"tool:exec","req_id":...,"agent_id":"a1","app_id":"settings_app","tool_id":2,"tool_hash":"8hex","payload":{...}}`

Only semantic fields are exposed to `llm-app`:
- `tool_id`
- `name`
- `app_id`
- `app_name`
- `description`
- `input_schema`
- `examples`
- `perm`
- `cost`
- `hash`

## Startup

1. load manifests from disk
2. register tools with kernel netlink interface
3. expose `list_apps` / `list_tools`
4. accept `tool:exec`
5. arbitrate through kernel
6. invoke app endpoint via `transport + endpoint + operation`
7. report completion back to kernel
