#!/usr/bin/env python3
"""Current time tool app."""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict


def run(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("time_now payload must be object")

    now_local = datetime.now().astimezone()
    now_utc = datetime.now(timezone.utc)

    timezone_hint = payload.get("timezone", "local")
    if not isinstance(timezone_hint, str):
        raise ValueError("time_now payload.timezone must be string")
    timezone_hint = timezone_hint.lower().strip()
    if timezone_hint not in {"local", "utc"}:
        raise ValueError("timezone must be one of: local, utc")

    selected = now_local if timezone_hint == "local" else now_utc
    return {
        "requested_timezone": timezone_hint,
        "now_iso": selected.isoformat(),
        "local_iso": now_local.isoformat(),
        "utc_iso": now_utc.isoformat(),
        "weekday": selected.strftime("%A"),
        "epoch_ms": int(time.time() * 1000),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdin-json", action="store_true")
    args = parser.parse_args()

    try:
        if args.stdin_json:
            payload = json.loads(sys.stdin.read())
        else:
            payload = {}
        print(json.dumps(run(payload), ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
