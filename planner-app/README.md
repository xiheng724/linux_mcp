# planner-app

`planner-app/` is the planner/UI layer.

Responsibilities:

- fetch capability catalog from `mcpd`
- select one capability domain from catalog metadata or DeepSeek-constrained catalog choice
- emit canonical capability intents

Canonical planner request body:

```json
{
  "kind": "capability:exec",
  "req_id": 1,
  "participant_id": "planner-main",
  "capability_domain": "info.lookup",
  "intent_text": "what time is it in utc",
  "hints": {
    "selector_source": "catalog",
    "selector_reason": "catalog_score=..."
  }
}
```

The planner does not build final provider payloads.

## Run

```bash
python3 planner-app/cli.py --once "what time is it in utc"
python3 planner-app/cli.py --repl
python3 planner-app/gui_app.py
```

Selector modes:

- `auto`
- `catalog`
- `deepseek`
