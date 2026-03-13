# llm-app

CLI planner for the current capability-domain flow:

1. fetch capability domains from `mcpd` via `{"sys":"list_capabilities"}`
2. choose one capability domain with DeepSeek or local heuristic
3. send `{"kind":"capability:exec", ...}` to `mcpd`
4. `mcpd` performs broker selection, kernel arbitration, provider dispatch, and completion report

`llm-app` now uses only the canonical inspection calls `list_providers`, `list_actions`, and `list_capabilities`.

Prerequisites:
- `kernel_mcp` loaded
- `mcpd` running (`bash scripts/run_mcpd.sh`)
- client binaries built (`make -C client clean && make -C client`)

Run:

```bash
python3 llm-app/cli.py --once "hello"
python3 llm-app/cli.py --once "burn cpu for 200ms"
python3 llm-app/cli.py --once "count words in this sentence"
python3 llm-app/cli.py --once "show system info"
python3 llm-app/cli.py --once "calculate (21+7)*3"
python3 llm-app/cli.py --once "preview README.md 20 lines"
python3 llm-app/cli.py --once "hash text hello with sha256"
python3 llm-app/cli.py --once "what time is it now"
python3 llm-app/cli.py --once "set volume to 30"
python3 llm-app/cli.py --once "create file tmp/demo.txt with content 'hello'"
python3 llm-app/cli.py --once "list files in tool-app"
python3 llm-app/cli.py --once "delete file tmp/demo.txt"
python3 llm-app/cli.py --once "copy file README.md to tmp/README.copy.md"
python3 llm-app/cli.py --once "rename file tmp/README.copy.md to tmp/README.renamed.md"
```

REPL mode:

```bash
python3 llm-app/cli.py --repl
```

REPL commands:
- `/help` show commands
- `/providers` refresh and print provider list
- `/actions` refresh and print provider action list
- `/caps` refresh and print capability domains
- `/exit` quit
- `Ctrl-D` quit

REPL options:
- `--participant-id planner-main` (default: `planner-main`)
- `--sock /tmp/mcpd.sock` (default: `/tmp/mcpd.sock`)
- `--show-actions` print full action list every turn

GUI mode (PySide6):

```bash
python3 llm-app/gui_app.py
```

Current GUI behavior:
- shows capability domains, providers, and provider actions side by side
- executes only through `capability:exec`
- supports manual capability override, provider preference, `interactive`, and `explicit_approval`
- displays selected capability, broker/provider/action result, and raw response JSON

If missing dependency:

```bash
sudo apt-get install python3-pyside6
# or
pip install PySide6
```

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
[llm-app]   /actions force refresh and print provider actions
[llm-app]   /exit  quit
user> hello
[llm-app] capabilities unchanged
[llm-app] selected capability=info.lookup id=1 hash=...
[llm-app] req_id=... status=ok t_ms=...
[llm-app] result={"message":"hello"}
```

Selector modes:
- `--selector deepseek` (default): require DeepSeek and fail if unavailable.
- `--selector auto`: use DeepSeek when key exists, otherwise heuristic.
- `--selector heuristic`: local keyword routing only.
