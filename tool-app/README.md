# tool-app

Independent tool applications executed by `mcpd`.

## Contract

Each tool app is a standalone script under `tool-app/` and should support:

- `--stdin-json`: read tool payload JSON from stdin.
- write JSON result to stdout.
- return non-zero on error and print JSON error message (best effort).

`mcpd` dispatches tools by `app_path` declared in `mcpd/tools.d/*.json`.

## Current Apps

- `echo_app.py`
- `cpu_burn_app.py`
- `text_stats_app.py`
- `sys_info_app.py`
- `calc_app.py`
- `file_preview_app.py`
- `hash_text_app.py`
- `time_now_app.py`
