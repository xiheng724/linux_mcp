#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

REQUESTS="4000"
CONCURRENCY="1,4,8,16,32"
NEGATIVE_REPEATS="500"
MAX_TOOLS="20"
OUTPUT_DIR="experiment-results"
TIMEOUT_S="10"
INCLUDE_WRITE=0
SKIP_DIRECT=0
SKIP_START=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --requests)
      REQUESTS="$2"; shift 2 ;;
    --concurrency)
      CONCURRENCY="$2"; shift 2 ;;
    --negative-repeats)
      NEGATIVE_REPEATS="$2"; shift 2 ;;
    --max-tools)
      MAX_TOOLS="$2"; shift 2 ;;
    --output-dir)
      OUTPUT_DIR="$2"; shift 2 ;;
    --timeout-s)
      TIMEOUT_S="$2"; shift 2 ;;
    --include-write-tools)
      INCLUDE_WRITE=1; shift ;;
    --skip-direct)
      SKIP_DIRECT=1; shift ;;
    --skip-start)
      SKIP_START=1; shift ;;
    *)
      echo "unknown option: $1"
      exit 1 ;;
  esac
done

if [[ "$SKIP_START" -eq 0 ]]; then
  echo "[suite] starting tool services"
  bash scripts/run_tool_services.sh
  echo "[suite] starting mcpd"
  bash scripts/run_mcpd.sh
fi

ARGS=(
  --mcpd-sock /tmp/mcpd.sock
  --timeout-s "$TIMEOUT_S"
  --output-dir "$OUTPUT_DIR"
  --requests "$REQUESTS"
  --concurrency "$CONCURRENCY"
  --negative-repeats "$NEGATIVE_REPEATS"
  --max-tools "$MAX_TOOLS"
)

if [[ "$INCLUDE_WRITE" -eq 1 ]]; then
  ARGS+=(--include-write-tools)
fi
if [[ "$SKIP_DIRECT" -eq 1 ]]; then
  ARGS+=(--skip-direct)
fi

echo "[suite] running benchmark suite"
"$PYTHON_BIN" scripts/experiments/benchmark_suite.py "${ARGS[@]}"

LATEST_RUN="$(ls -1dt "$OUTPUT_DIR"/run-* 2>/dev/null | head -n1 || true)"
if [[ -z "$LATEST_RUN" ]]; then
  echo "[suite] failed: no run directory found under $OUTPUT_DIR"
  exit 1
fi

echo "[suite] rendering markdown report"
"$PYTHON_BIN" scripts/experiments/render_report.py "$LATEST_RUN/summary.json" --output "$LATEST_RUN/report.md"

echo "[suite] done"
echo "[suite] result dir: $LATEST_RUN"
echo "[suite] summary: $LATEST_RUN/summary.json"
echo "[suite] report:  $LATEST_RUN/report.md"
