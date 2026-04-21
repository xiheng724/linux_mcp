#!/usr/bin/env bash
# Acceptance: dynamic manifest re-registration obeys catalog_epoch semantics.
#
# Proves three things the project relies on:
#   - add: dropping a new manifest bumps catalog_epoch; any pre-existing
#          session's next tool:exec is denied with
#          catalog_stale_rebind_required, then succeeds after rebind.
#   - remove: deleting a manifest makes the removed tool_id fail at mcpd
#             userspace (unknown tool_id), never entering the kernel.
#   - change: flipping risk_flags to require approval forces an old
#             session to rebind first; after rebind, the call goes
#             through the approval path rather than the "low-risk allow"
#             cached from the prior registration.
#
# All scenarios are driven by a Python harness so the RPC state machine
# stays readable.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="python3"
fi

if [[ ! -S /tmp/mcpd.sock ]]; then
  echo "FAIL: mcpd socket missing; bring the stack up first"
  exit 1
fi

exec "$PYTHON_BIN" "$ROOT_DIR/scripts/acceptance_dynamic_reregister.py" "$@"
