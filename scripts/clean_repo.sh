#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[clean] stop runtime services (best effort)"
bash scripts/stop_mcpd.sh >/dev/null 2>&1 || true
bash scripts/stop_tool_services.sh >/dev/null 2>&1 || true

echo "[clean] remove build artifacts"
make -C client clean >/dev/null
make -C kernel-mcp clean >/dev/null

echo "[clean] remove python caches"
python3 - <<'PY'
import pathlib, shutil
for p in pathlib.Path('.').rglob('__pycache__'):
    if p.is_dir():
        shutil.rmtree(p)
print("python caches removed")
PY

echo "[clean] remove local temp logs"
rm -f ./*.log

echo "[clean] done"
