# llm-app

Simple CLI demo that:

1. fetches tool semantics via `{"sys":"list_tools"}` from `mcpd`
2. chooses a tool by prompt semantics (DeepSeek or local heuristic)
3. sends `{"kind":"tool:exec", ...}` to `mcpd` only
4. `mcpd` performs kernel arbitration + tool execution + completion report

Tool semantics source:
- `mcpd/tools.d/*.json` (`description`, `input_schema`, `examples`)
- llm-app only sees semantic fields and hash (no `app_path`)

Prerequisites:
- `kernel_mcp` loaded
- `mcpd` running (`bash scripts/run_mcpd.sh`)
- client binaries built (`make -C client clean && make -C client`)

Run:

```bash
python3 llm-app/cli.py --once "hello"
python3 llm-app/cli.py --once "burn cpu for 200ms"
python3 llm-app/cli.py --once "count words in this sentence"
```

REPL mode:

```bash
python3 llm-app/cli.py --repl
```

REPL commands:
- `/help` show commands
- `/tools` refresh and print tool list
- `/exit` quit
- `Ctrl-D` quit

REPL options:
- `--agent-id a1` (default: `a1`)
- `--sock /tmp/mcpd.sock` (default: `/tmp/mcpd.sock`)
- `--show-tools` print full tool list every turn (default only print on first/changes; otherwise prints `tools unchanged`)

DeepSeek selection:

```bash
export DEEPSEEK_API_KEY="your_key"
python3 llm-app/cli.py --selector deepseek --once "please burn cpu for 100ms"
```

Example REPL output:

```text
[llm-app] REPL mode started
[llm-app] commands:
[llm-app]   /help  show help
[llm-app]   /tools force refresh and print tools
[llm-app]   /exit  quit
user> hello
[llm-app] tools unchanged
[llm-app] selected tool=echo id=1 hash=...
[llm-app] req_id=... status=ok t_ms=...
[llm-app] result={"message":"hello"}
```

Selector modes:
- `--selector auto` (default): use DeepSeek when key exists, otherwise heuristic.
- `--selector heuristic`: local keyword routing only.
- `--selector deepseek`: require DeepSeek and fail if unavailable.
