#!/usr/bin/env python3
"""CPU burn tool app."""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, Dict


def _cpu_burn(ms: int) -> Dict[str, Any]:
    if ms < 0:
        ms = 0
    if ms > 10_000:
        ms = 10_000
    start = time.perf_counter()
    target = start + (ms / 1000.0)
    x = 0
    while time.perf_counter() < target:
        x = (x * 1664525 + 1013904223) & 0xFFFFFFFF
    _ = x
    return {"burned_ms": ms}


def run(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("cpu_burn payload must be object")
    ms_raw = payload.get("ms", 0)
    if isinstance(ms_raw, bool) or not isinstance(ms_raw, int):
        raise ValueError("cpu_burn payload.ms must be integer")
    return _cpu_burn(ms_raw)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdin-json", action="store_true")
    args = parser.parse_args()

    try:
        if args.stdin_json:
            payload = json.loads(sys.stdin.read())
        else:
            payload = {"ms": 0}
        print(json.dumps(run(payload), ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

