#!/usr/bin/env bash
# Wrapper around scripts/experiments/attack_extended.py (E4).
#
# Mirrors run_security_evaluation.sh: starts the tool services + mcpd stack
# (unless --skip-start), then invokes the Python runner, then renders the
# fuzz errno plot alongside the produced snapshot.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PHASE="all"
OUTPUT_DIR="experiment-results/attack-extended"
DURATION_S=""
TOCTOU_ITERS=""
CROSSUID_ATTEMPTS=""
RATE_LIMIT=""
DRY_RUN=0
SMOKE=0
SKIP_START=0

usage() {
  cat <<'USAGE'
Usage: scripts/run_attack_extended.sh [--phase toctou,crossuid,fuzz,all]
                                      [--output-dir DIR]
                                      [--duration-s SEC]
                                      [--toctou-iterations N]
                                      [--crossuid-attempts N]
                                      [--rate-limit-per-s N]
                                      [--dry-run] [--smoke]
                                      [--skip-start]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase) PHASE="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --duration-s) DURATION_S="$2"; shift 2 ;;
    --toctou-iterations) TOCTOU_ITERS="$2"; shift 2 ;;
    --crossuid-attempts) CROSSUID_ATTEMPTS="$2"; shift 2 ;;
    --rate-limit-per-s) RATE_LIMIT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --smoke) SMOKE=1; shift ;;
    --skip-start) SKIP_START=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ "$SKIP_START" -eq 0 && "$DRY_RUN" -eq 0 ]]; then
  bash scripts/run_tool_services.sh
  bash scripts/run_mcpd.sh
fi

CMD=(python3 scripts/experiments/attack_extended.py
     --phase "$PHASE"
     --output-dir "$OUTPUT_DIR")
[[ -n "$DURATION_S" ]] && CMD+=(--duration-s "$DURATION_S")
[[ -n "$TOCTOU_ITERS" ]] && CMD+=(--toctou-iterations "$TOCTOU_ITERS")
[[ -n "$CROSSUID_ATTEMPTS" ]] && CMD+=(--crossuid-attempts "$CROSSUID_ATTEMPTS")
[[ -n "$RATE_LIMIT" ]] && CMD+=(--rate-limit-per-s "$RATE_LIMIT")
[[ "$DRY_RUN" -eq 1 ]] && CMD+=(--dry-run)
[[ "$SMOKE" -eq 1 ]] && CMD+=(--smoke)

echo "[attack-extended] running: ${CMD[*]}"
"${CMD[@]}"
