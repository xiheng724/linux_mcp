#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export PYTHONDONTWRITEBYTECODE=1
VENV_DIR="${LINUX_MCP_VENV_DIR:-/tmp/linux-mcp-venv}"

REQUIRED_DIRS=(
  kernel-mcp
  mcpd
  mcpd/apps.d
  tool-app
  tool-app/apps
  llm-app
  client
  scripts
)

OPTIONAL_DIRS=(
  bench
  results
  plots
)

REQUIRED_SCRIPTS=(
  scripts/bootstrap.sh
  scripts/build_kernel.sh
  scripts/clean_repo.sh
  scripts/load_module.sh
  scripts/unload_module.sh
  scripts/reload_10x.sh
  scripts/run_smoke.sh
)

echo "[smoke] verify directory layout"
for d in "${REQUIRED_DIRS[@]}"; do
  [[ -d "$d" ]] || { echo "missing directory: $d"; exit 1; }
  echo "ok core dir: $d"
done

for d in "${OPTIONAL_DIRS[@]}"; do
  if [[ -d "$d" ]]; then
    echo "ok optional dir: $d"
  else
    echo "skip optional dir: $d"
  fi
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

echo "[smoke] pyroute2 import check"
set +e
if [[ -x "$VENV_DIR/bin/python" ]]; then
  "$VENV_DIR/bin/python" -c "import pyroute2"
  py_rc=$?
else
  python3 -c "import pyroute2"
  py_rc=$?
fi
set -e

if [[ $py_rc -eq 0 ]]; then
  echo "ok pyroute2 import"
else
  if [[ "${REQUIRE_PYROUTE2:-0}" == "1" ]]; then
    echo "pyroute2 import failed and REQUIRE_PYROUTE2=1"
    exit 1
  fi
  echo "WARN: pyroute2 import failed (set REQUIRE_PYROUTE2=1 to make this fatal)"
fi

echo "[smoke] PASS"
