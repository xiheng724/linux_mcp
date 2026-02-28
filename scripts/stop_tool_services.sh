#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

for pidfile in /tmp/linux-mcp-app-*.pid; do
  [[ -f "$pidfile" ]] || continue
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do
      if ! kill -0 "$pid" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pidfile"
done

for pidfile in /tmp/linux-mcp-tool-*.pid; do
  [[ -f "$pidfile" ]] || continue
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do
      if ! kill -0 "$pid" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pidfile"
done

while IFS= read -r endpoint; do
  [[ -n "$endpoint" ]] || continue
  rm -f "$endpoint"
done < <(
  "$PYTHON_BIN" - <<'PY'
import glob,json
for p in sorted(glob.glob("mcpd/apps.d/*.json")):
    raw=json.load(open(p,encoding="utf-8"))
    ep=raw.get("endpoint","")
    if isinstance(ep,str) and ep:
        print(ep)
PY
)

rm -f /tmp/linux-mcp-tools/*.sock 2>/dev/null || true

echo "app services stopped"
