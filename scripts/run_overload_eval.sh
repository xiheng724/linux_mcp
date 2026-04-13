#!/usr/bin/env bash
# E3 — sustained overload runner. Use taskset when available to pin the
# runner off the mcpd / kernel-worker CPUs. Falls back silently if taskset
# is missing (e.g. on macOS smoke runs).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

OUTPUT_DIR="experiment-results/overload"
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

"$PYTHON_BIN" scripts/experiments/overload_eval.py --output-dir "$OUTPUT_DIR" "${ARGS[@]}"
