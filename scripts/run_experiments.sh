#!/usr/bin/env bash
# Unified experiment driver for the 4 new linux-mcp experiments (E1-E5).
#
# Usage:
#   sudo bash scripts/run_experiments.sh           # everything, full duration
#   sudo bash scripts/run_experiments.sh --smoke   # quick shake-out (~10 min)
#   sudo bash scripts/run_experiments.sh e1 e2     # a subset
#
# Phase names: e1 (kernel ablation), e2 (registry scaling),
#              e3 (sustained overload), e4 (extended attacks),
#              e5 (statistical rehash). `all` is the default.
#
# Prerequisites (handled below):
#   - Linux VM with kernel headers installed under /lib/modules/$(uname -r)/build
#   - Python 3 with matplotlib in /Users/.../linux_mcp/.venv (optional but
#     recommended; the runners degrade gracefully if it is missing)
#   - Root privileges (kernel module load + /sys/module writes)
#
# What this script does:
#   1. (Re)builds and (re)loads the kernel_mcp module so the new experiment
#      flags (SKIP_HASH / SKIP_BINDING / SKIP_TICKET / KMCP_CMD_NOOP) AND the
#      E4 peer-cred knob are live.
#   2. Runs each selected experiment, writing into experiment-results/<suite>/
#      run-<ts>/ exactly as the per-runner scripts do.
#   3. For E4, runs the cross-uid phase twice — once with
#      require_peer_cred=0 (without-patch baseline) and once with =1 (with
#      the follow-up patch enabled) — producing the A/B comparison.
#   4. After all runs land, calls stats_rehash.py to anchor the
#      paper-final-n5 snapshot against the fresh E1 NOOP noise floor.
#   5. Renders the top-level experiment-results/INDEX.md.
#
# Everything is idempotent: rerunning the script starts a new UTC-stamped
# sub-directory under each suite. Old runs are never touched.

set -euo pipefail

# --- argument parsing ------------------------------------------------------

SMOKE=0
PHASES=()
for arg in "$@"; do
  case "$arg" in
    --smoke)   SMOKE=1 ;;
    e1|e2|e3|e4|e5|all) PHASES+=("$arg") ;;
    -h|--help)
      sed -n '1,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "run_experiments.sh: unknown argument '$arg'" >&2
      exit 2
      ;;
  esac
done
if [[ ${#PHASES[@]} -eq 0 ]]; then
  PHASES=("all")
fi
if [[ " ${PHASES[*]} " == *" all "* ]]; then
  PHASES=(e1 e2 e3 e4 e5)
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

RUN_LOG="$ROOT_DIR/experiment-results/run_experiments_$(date -u +%Y%m%dT%H%M%SZ).log"
mkdir -p "$ROOT_DIR/experiment-results"
echo "[driver] logging to $RUN_LOG"

log() {
  local msg="[driver $(date -u +%H:%M:%SZ)] $*"
  echo "$msg" | tee -a "$RUN_LOG"
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    log "ERROR: this step needs root. Rerun: sudo bash scripts/run_experiments.sh ${PHASES[*]}"
    exit 1
  fi
}

# --- phase 0: (re)build and (re)load the kernel module --------------------

build_and_load_kernel() {
  require_root
  log "phase 0: building + reloading kernel_mcp (picks up new flags + peer-cred knob)"
  bash scripts/build_kernel.sh     >> "$RUN_LOG" 2>&1
  bash scripts/unload_module.sh    >> "$RUN_LOG" 2>&1 || true
  bash scripts/load_module.sh      >> "$RUN_LOG" 2>&1
  # Sanity: every new UAPI/param we added must show up.
  local missing=0
  for sym in require_peer_cred agent_max_calls; do
    if [[ ! -e "/sys/module/kernel_mcp/parameters/$sym" ]]; then
      log "ERROR: /sys/module/kernel_mcp/parameters/$sym missing — is this the new build?"
      missing=1
    fi
  done
  if [[ $missing -ne 0 ]]; then
    log "abort: kernel module build does not expose the expected parameters"
    exit 1
  fi
  # Default peer-cred=0 so E1/E2/E3 do not get unexpectedly gated.
  echo 0 > /sys/module/kernel_mcp/parameters/require_peer_cred
  log "phase 0: kernel module loaded, require_peer_cred=0 (default)"
}

# --- per-phase runners -----------------------------------------------------

run_e1() {
  log "phase E1: kernel path stage ablation"
  local args=()
  if [[ $SMOKE -eq 1 ]]; then
    args+=(--smoke)
  else
    args+=(--reps 10 --requests 10000)
  fi
  "$PYTHON_BIN" scripts/experiments/kernel_ablation.py "${args[@]}" 2>&1 | tee -a "$RUN_LOG"
  E1_RUN_DIR="$(ls -td experiment-results/kernel-ablation/run-* | head -1)"
  log "phase E1 done → $E1_RUN_DIR"
}

run_e2() {
  log "phase E2: registry scaling"
  local args=()
  if [[ $SMOKE -eq 1 ]]; then
    args+=(--smoke)
  else
    args+=(--reps 5)
  fi
  "$PYTHON_BIN" scripts/experiments/registry_scaling.py "${args[@]}" 2>&1 | tee -a "$RUN_LOG"
  E2_RUN_DIR="$(ls -td experiment-results/registry-scaling/run-* | head -1)"
  log "phase E2 done → $E2_RUN_DIR"
}

run_e3() {
  log "phase E3: sustained overload (connection-pooled, errors excluded from latency)"
  # Raise SOMAXCONN so even the fixed connection-pool path has headroom.
  # Effect is process-wide, non-persistent, reverted on reboot.
  if [[ $EUID -eq 0 ]]; then
    sysctl -q -w net.core.somaxconn=4096 || true
    sysctl -q -w net.ipv4.tcp_max_syn_backlog=4096 || true
  fi
  local args=()
  if [[ $SMOKE -eq 1 ]]; then
    args+=(--smoke)
  else
    # 180s × 5 concurrency levels × 3 reps × 3 systems ≈ 2.5h wall clock.
    args+=(--duration-s 180 --reps 3 --warmup-s 30)
  fi
  "$PYTHON_BIN" scripts/experiments/overload_eval.py "${args[@]}" 2>&1 | tee -a "$RUN_LOG"
  E3_RUN_DIR="$(ls -td experiment-results/overload/run-* 2>/dev/null | head -1 || true)"
  if [[ -z "$E3_RUN_DIR" ]]; then
    # User may have invoked with --output-dir; fall back to the flat dir.
    E3_RUN_DIR="experiment-results/overload"
  fi
  log "phase E3 done → $E3_RUN_DIR"
}

run_e4() {
  require_root  # needed to write /sys/module/.../require_peer_cred
  log "phase E4: extended attack surface (crossuid A/B + TOCTOU + fuzzer)"
  local args=(--phase all --crossuid-both-modes)
  if [[ $SMOKE -eq 1 ]]; then
    args+=(--smoke)
  else
    # Default toctou=10k, crossuid=500 per mode, fuzz=1800s.
    :
  fi
  "$PYTHON_BIN" scripts/experiments/attack_extended.py "${args[@]}" 2>&1 | tee -a "$RUN_LOG"
  # Leave the knob in its restored default (=0) so the next unrelated run
  # does not inherit a surprising policy.
  if [[ -w /sys/module/kernel_mcp/parameters/require_peer_cred ]]; then
    echo 0 > /sys/module/kernel_mcp/parameters/require_peer_cred
  fi
  E4_RUN_DIR="$(ls -td experiment-results/attack-extended/run-* | head -1)"
  log "phase E4 done → $E4_RUN_DIR"
}

run_e5() {
  log "phase E5: statistical rehash of paper-final-n5 anchored on fresh noise floor"
  # Find the freshest E1 ablation run for the noise-floor anchor.
  local e1_dir
  e1_dir="$(ls -td experiment-results/kernel-ablation/run-* 2>/dev/null | head -1 || true)"
  local n5_dir="experiment-results/linux-mcp-paper-final-n5/run-20260405-173020"
  if [[ ! -d "$n5_dir" ]]; then
    log "skip E5: $n5_dir not present"
    return 0
  fi
  local ablation_arg=()
  if [[ -n "$e1_dir" ]]; then
    ablation_arg+=(--ablation-run "$e1_dir")
    log "E5 using noise floor from $e1_dir"
  else
    log "E5 running without ablation anchor (no kernel-ablation run found)"
  fi
  "$PYTHON_BIN" scripts/experiments/stats_rehash.py "$n5_dir" \
    "${ablation_arg[@]}" \
    --output-dir "$n5_dir/stats_rehash" \
    2>&1 | tee -a "$RUN_LOG"
  log "phase E5 done → $n5_dir/stats_rehash"
}

render_index() {
  log "rendering experiment-results/INDEX.md"
  "$PYTHON_BIN" scripts/experiments/render_experiment_index.py \
    --output experiment-results/INDEX.md 2>&1 | tee -a "$RUN_LOG"
}

# --- main ------------------------------------------------------------------

log "phases: ${PHASES[*]} (smoke=$SMOKE)"

# Anything that depends on the kernel module being up needs phase 0.
if [[ " ${PHASES[*]} " == *" e1 "* || \
      " ${PHASES[*]} " == *" e2 "* || \
      " ${PHASES[*]} " == *" e3 "* || \
      " ${PHASES[*]} " == *" e4 "* ]]; then
  build_and_load_kernel
fi

for phase in "${PHASES[@]}"; do
  case "$phase" in
    e1) run_e1 ;;
    e2) run_e2 ;;
    e3) run_e3 ;;
    e4) run_e4 ;;
    e5) run_e5 ;;
  esac
done

render_index
log "all requested phases complete."
echo
echo "Summary:"
echo "  log file:        $RUN_LOG"
echo "  index:           experiment-results/INDEX.md"
if [[ -n "${E1_RUN_DIR:-}" ]]; then echo "  E1 run dir:      $E1_RUN_DIR"; fi
if [[ -n "${E2_RUN_DIR:-}" ]]; then echo "  E2 run dir:      $E2_RUN_DIR"; fi
if [[ -n "${E3_RUN_DIR:-}" ]]; then echo "  E3 run dir:      $E3_RUN_DIR"; fi
if [[ -n "${E4_RUN_DIR:-}" ]]; then echo "  E4 run dir:      $E4_RUN_DIR"; fi
