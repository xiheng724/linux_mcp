#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

OUTPUT_DIR="experiment-results/linux-mcp"
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

"$PYTHON_BIN" scripts/experiments/linux_mcp_eval.py --output-dir "$OUTPUT_DIR" "${ARGS[@]}"

LATEST_RUN="$(ls -1dt "$OUTPUT_DIR"/run-* 2>/dev/null | head -n1 || true)"
if [[ -z "$LATEST_RUN" ]]; then
  echo "[linux_mcp] failed: no run directory found under $OUTPUT_DIR"
  exit 1
fi

"$PYTHON_BIN" scripts/experiments/render_linux_mcp_report.py \
  "$LATEST_RUN/linux_mcp_summary.json" \
  --output "$LATEST_RUN/linux_mcp_report.md"

"$PYTHON_BIN" scripts/experiments/plot_linux_mcp_results.py \
  --run-dir "$LATEST_RUN" \
  --output-dir "$LATEST_RUN/plots"

echo "[linux_mcp] done"
echo "[linux_mcp] result dir: $LATEST_RUN"
echo "[linux_mcp] summary:    $LATEST_RUN/linux_mcp_summary.json"
echo "[linux_mcp] report:     $LATEST_RUN/linux_mcp_report.md"
