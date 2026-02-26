#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "unload_module requires root privileges"
  exit 1
fi

if lsmod | awk '{print $1}' | grep -qx kernel_mcp; then
  rmmod kernel_mcp
  echo "module kernel_mcp unloaded"
else
  echo "module kernel_mcp is not loaded"
fi

