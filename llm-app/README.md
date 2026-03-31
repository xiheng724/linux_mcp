# llm-app

Simple CLI demo that:

1. fetches app catalog via `{"sys":"list_apps"}` from `mcpd`
2. chooses an app first with DeepSeek
3. fetches app-scoped tools via `{"sys":"list_tools","app_id":"..."}` and chooses one tool
4. sends `{"kind":"tool:exec","app_id":"...", ...}` to `mcpd` only
5. `mcpd` performs kernel arbitration + tool execution + completion report

Tool semantics source:
- `tool-app/manifests/*.json` (`tools[].description`, `tools[].input_schema`, `tools[].examples`)
- manifests are auto-loaded by `mcpd` at startup
- llm-app only sees semantic fields and hash (no runtime endpoint/operation fields)

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
- `/apps` refresh and print app list
- `/tools` refresh and print tool list
- `/exit` quit
- `Ctrl-D` quit

REPL options:
- `--agent-id a1` (default: `a1`)
- `--sock /tmp/mcpd.sock` (default: `/tmp/mcpd.sock`)
- `--show-tools` print full tool list every turn (default only print on first/changes; otherwise prints `tools unchanged`)

GUI mode (PySide6):

```bash
python3 llm-app/gui_app.py
```

GUI uses the same tool-selection logic as CLI (shared code):
- `--deepseek-model ...`
- `--deepseek-url ...`
- `--deepseek-timeout-sec ...`

Recommended dev workflow (venv):

```bash
cd ~/Code/linux-mcp
source .venv/bin/activate
python llm-app/gui_app.py
```

If missing dependency:

```bash
sudo apt-get install python3-pyside6
# or
pip install PySide6
```

DeepSeek selection:

```bash
export DEEPSEEK_API_KEY="your_key"
python3 llm-app/cli.py --once "please burn cpu for 100ms"
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

## Recommended Demo Flow (GUI)

1. Optional baseline:
   - `sudo bash scripts/demo_acceptance.sh`
2. Start gateway:
   - `bash scripts/run_mcpd.sh`
3. Start GUI:
   - `python3 llm-app/gui_app.py`
4. Try inputs:
   - `hello`
   - `burn cpu for a bit`
   - `统计这段文字：linux mcp demo`
   - `show system info`
   - `calculate 123 * (45 + 6)`
   - `preview llm-app/cli.py 20 lines`
   - `hash "linux-mcp" with md5`
   - `what time is it now`
5. Stop gateway:
   - `bash scripts/stop_mcpd.sh`

If `DEEPSEEK_API_KEY` is not set, CLI/GUI routing will fail fast.
