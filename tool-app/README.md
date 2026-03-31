# tool-app

Demo tool providers and manifest definitions.

## Structure

- `tool-app/manifests/*.json`
  - declarative app/tool metadata
  - runtime fields describe interface transport and endpoint
  - demo-only field `demo_entrypoint` is used by `scripts/run_tool_services.sh`
- `tool-app/demo_apps/*.py`
  - standalone demo services that expose app capabilities over UDS RPC
- `tool-app/demo_rpc.py`
  - shared framed-JSON helper used by demo services

`mcpd` no longer imports app Python modules. It loads manifests directly, publishes tool semantics to the rest of the system, and invokes each app through its declared interface (`transport=uds_rpc`, `endpoint`, `tools[].operation`).

## Manifest Shape

App-level fields:
- `app_id`
- `app_name`
- `transport`
- `endpoint`
- optional `demo_entrypoint`

Tool-level fields:
- `tool_id`
- `name`
- `perm`
- `cost`
- `operation`
- optional `timeout_ms`
- `description`
- `input_schema`
- `examples`

## Current Demo Apps

- `demo_apps/settings_app.py`
- `demo_apps/file_manager_app.py`
- `demo_apps/calculator_app.py`
- `demo_apps/utility_app.py`
