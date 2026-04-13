#!/usr/bin/env bash
# E5 — post-process an existing linux_mcp_eval snapshot with pairwise stats
# and (optionally) anchor against a kernel_ablation noise floor.
#
# Usage:
#   bash scripts/run_stats_rehash.sh <source-run-dir> [--ablation-run <dir>] [--output-dir <dir>]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <source-run-dir> [--ablation-run <dir>] [--output-dir <dir>]" >&2
  exit 2
fi

"$PYTHON_BIN" scripts/experiments/stats_rehash.py "$@"
