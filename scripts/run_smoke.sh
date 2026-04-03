#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export PYTHONDONTWRITEBYTECODE=1

REQUIRED_DIRS=(
  kernel-mcp
  mcpd
  tool-app
  tool-app/demo_apps
  tool-app/manifests
  llm-app
  client
  scripts
)

REQUIRED_SCRIPTS=(
  scripts/build_kernel.sh
  scripts/load_module.sh
  scripts/unload_module.sh
  scripts/reload_10x.sh
  scripts/run_mcpd.sh
  scripts/run_smoke.sh
  scripts/run_tool_services.sh
  scripts/stop_mcpd.sh
  scripts/stop_tool_services.sh
)

echo "[smoke] verify directory layout"
for d in "${REQUIRED_DIRS[@]}"; do
  [[ -d "$d" ]] || { echo "missing directory: $d"; exit 1; }
  echo "ok core dir: $d"
done

echo "[smoke] verify scripts exist"
for f in "${REQUIRED_SCRIPTS[@]}"; do
  [[ -f "$f" ]] || { echo "missing script: $f"; exit 1; }
  echo "ok script: $f"
done

echo "[smoke] shell syntax check"
for f in "${REQUIRED_SCRIPTS[@]}"; do
  bash -n "$f"
done
echo "ok shell syntax"

echo "[smoke] python imports"
python3 - <<'PY'
from client.kernel_mcp import ATTR, CMD, FAMILY_NAME, FAMILY_VERSION
print(f"client import ok: family={FAMILY_NAME} version={FAMILY_VERSION}")
print(f"cmd_count={len(CMD)} attr_count={len(ATTR)}")
PY

echo "[smoke] schema sync"
python3 scripts/verify_schema_sync.py

echo "[smoke] PASS"
