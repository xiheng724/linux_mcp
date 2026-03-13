# mcpd

`mcpd` is the userspace broker/orchestration daemon for `linux-mcp`.

Canonical model:
- kernel-facing objects are `capabilities` and `participants`
- planner requests `capability:exec`
- `mcpd` chooses broker/provider/action/executor
- kernel issues a single-use lease
- `mcpd` dispatches the approved action and reports completion

## Socket API

- Socket path: `/tmp/mcpd.sock`
- Framing: `4-byte big-endian length + UTF-8 JSON`

System queries:
- `{"sys":"list_providers"}`
- `{"sys":"list_actions"}`
- `{"sys":"list_capabilities"}`
- `{"sys":"list_brokers"}`
- `{"sys":"register_manifest","manifest":{...}}`

Execution request:

```json
{
  "kind": "capability:exec",
  "req_id": 1,
  "participant_id": "planner-main",
  "capability_domain": "file.read",
  "capability_id": 104,
  "capability_hash": "1234abcd",
  "user_text": "preview README.md"
}
```

## Runtime role

`mcpd` is responsible for:
- loading provider manifests from `tool-app/manifests/*.json`
- building provider/action/capability/broker catalogs
- registering capabilities with the kernel control plane
- validating action payloads and executor descriptors
- requesting kernel approval and lease issuance
- dispatching exactly one approved action to a provider service
- reporting completion and emitting userspace audit events

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
