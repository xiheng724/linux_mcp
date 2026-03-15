#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[build_kernel] build kernel-mcp module"
make -C kernel-mcp clean
make -C kernel-mcp

if [[ ! -f kernel-mcp/out/kernel_mcp.ko ]]; then
  echo "build failed: kernel-mcp/out/kernel_mcp.ko not found"
  exit 1
fi

echo "[build_kernel] ok: kernel-mcp/out/kernel_mcp.ko"
