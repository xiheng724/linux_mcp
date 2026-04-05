#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REPEATS="3"
OUTPUT_DIR="experiment-results/linux-mcp-repeat"
SLEEP_S="1"
EVAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repeats)
      REPEATS="$2"; shift 2 ;;
    --output-dir)
      OUTPUT_DIR="$2"; shift 2 ;;
    --sleep-s)
      SLEEP_S="$2"; shift 2 ;;
    *)
      EVAL_ARGS+=("$1")
      shift ;;
  esac
done

RUN_TS="$(date -u +%Y%m%d-%H%M%S)"
RUN_DIR="$OUTPUT_DIR/run-$RUN_TS"
RAW_DIR="$RUN_DIR/raw"
mkdir -p "$RAW_DIR"

for ((i=1; i<=REPEATS; i++)); do
  echo "[repeat-linux_mcp] run $i/$REPEATS"
  bash scripts/run_linux_mcp_evaluation.sh --output-dir "$RAW_DIR" "${EVAL_ARGS[@]}"
  if [[ "$i" -lt "$REPEATS" ]]; then
    sleep "$SLEEP_S"
  fi
done

echo "[repeat-linux_mcp] done"
echo "[repeat-linux_mcp] run dir: $RUN_DIR"
echo "[repeat-linux_mcp] raw dir: $RAW_DIR"
