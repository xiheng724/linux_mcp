#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "load_module requires root privileges"
  exit 1
fi

if [[ ! -f kernel-mcp/kernel_mcp.ko ]]; then
  bash scripts/build_kernel.sh
fi

if lsmod | awk '{print $1}' | grep -qx kernel_mcp; then
  echo "module kernel_mcp already loaded"
  exit 0
fi

AGENT_MAX_CALLS="${KERNEL_MCP_AGENT_MAX_CALLS:-0}"
insmod kernel-mcp/kernel_mcp.ko "agent_max_calls=${AGENT_MAX_CALLS}"
echo "module kernel_mcp loaded"
