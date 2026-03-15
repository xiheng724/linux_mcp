# mcpd

`mcpd` is the manifest-driven broker.

Responsibilities:

- autoload provider manifests from `provider-app/manifests/`
- build provider, capability, and broker catalogs
- validate planner capability requests
- resolve provider and action from capability intent
- build schema-driven structured payloads
- bind short-lived executors
- dispatch provider calls
- request and complete kernel leases

## Socket API

Socket:

- `/tmp/mcpd.sock`

System queries:

- `{"sys":"list_providers"}`
- `{"sys":"list_actions"}`
- `{"sys":"list_capabilities"}`
- `{"sys":"list_brokers"}`

Canonical execution request:

```json
{
  "kind": "capability:exec",
  "req_id": 1,
  "participant_id": "planner-main",
  "capability_domain": "file.read",
  "intent_text": "preview README.md",
  "hints": {
    "selector_source": "catalog",
    "selector_reason": "catalog_score=42"
  }
}
```

Rejected on the canonical path:

- top-level `payload`
- `planner_hints`
- top-level `preferred_provider_id`
- `user_text`
- `hints.payload_slots`

## Run

```bash
bash scripts/run_mcpd.sh
bash scripts/stop_mcpd.sh
```
