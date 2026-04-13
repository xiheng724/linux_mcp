#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

OUTPUT_DIR="experiment-results/kernel-ablation"
ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="$2"; shift 2 ;;
    *)
      ARGS+=("$1")
      shift ;;
  esac
done

"$PYTHON_BIN" scripts/experiments/kernel_ablation.py --output-dir "$OUTPUT_DIR" "${ARGS[@]}"
