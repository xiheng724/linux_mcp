#!/usr/bin/env python3
"""Echo tool app."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def run(payload: Any) -> Any:
    return payload


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

