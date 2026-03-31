#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
VENV_DIR="${LINUX_MCP_VENV_DIR:-/tmp/linux-mcp-venv}"

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

OPTIONAL_DIRS=(
  results
  plots
)

echo "[bootstrap] ensure directory layout"
for d in "${REQUIRED_DIRS[@]}"; do
  mkdir -p "$d"
  echo "ok core dir: $d"
done

for d in "${OPTIONAL_DIRS[@]}"; do
  if [[ -d "$d" ]]; then
    echo "ok optional dir (exists): $d"
  else
    echo "skip optional dir: $d"
  fi
done

echo "[bootstrap] check build tools"
for cmd in bash make gcc python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 1
  fi
  echo "ok cmd: $cmd"
done

echo "[bootstrap] check kernel headers"
KERNEL_BUILD_DIR="/lib/modules/$(uname -r)/build"
if [[ ! -e "$KERNEL_BUILD_DIR" ]]; then
  echo "missing kernel headers: $KERNEL_BUILD_DIR"
  exit 1
fi
echo "ok headers: $KERNEL_BUILD_DIR"

echo "[bootstrap] create python venv"
if [[ ! -d "$VENV_DIR" ]]; then
  if python3 -m venv "$VENV_DIR" >/tmp/linux_mcp_venv.log 2>&1; then
    echo "created venv with ensurepip: $VENV_DIR"
  else
    cat /tmp/linux_mcp_venv.log
    echo "retry with --without-pip"
    python3 -m venv --without-pip "$VENV_DIR"
    echo "created venv without pip: $VENV_DIR"
  fi
else
  echo "venv already exists: $VENV_DIR"
fi

echo "[bootstrap] check pyroute2"
if "$VENV_DIR/bin/python" -c "import pyroute2" >/dev/null 2>&1; then
  echo "ok pyroute2: already in venv"
elif python3 -c "import pyroute2" >/dev/null 2>&1; then
  echo "ok pyroute2: available in system python"
else
  if [[ -x "$VENV_DIR/bin/pip" ]]; then
    set +e
    "$VENV_DIR/bin/pip" install pyroute2
    rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
      echo "installed pyroute2 into venv: $VENV_DIR"
    else
      echo "WARN: failed to install pyroute2 from pip (network/proxy restricted?)"
      echo "WARN: run on a networked host or install system package python3-pyroute2"
    fi
  else
    echo "WARN: venv has no pip (python3-venv/ensurepip not fully available)"
    echo "WARN: install python3-pyroute2 via apt on host, or recreate venv with pip support"
  fi
fi

echo "[bootstrap] done"
