#!/usr/bin/env python3
"""Text hash tool app."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any, Dict

SUPPORTED_ALGOS = {"sha256", "sha1", "md5"}


def run(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("hash_text payload must be object")

    algorithm = payload.get("algorithm", "sha256")
    if not isinstance(algorithm, str):
        raise ValueError("hash_text payload.algorithm must be string")
    algorithm = algorithm.lower().strip()
    if algorithm not in SUPPORTED_ALGOS:
        raise ValueError(f"unsupported algorithm: {algorithm}")

    text = payload.get("text", "")
    if not isinstance(text, str):
        raise ValueError("hash_text payload.text must be string")
    if not text and isinstance(payload.get("message"), str):
        text = payload["message"]

    digest = hashlib.new(algorithm, text.encode("utf-8")).hexdigest()
    return {
        "algorithm": algorithm,
        "length": len(text),
        "digest": digest,
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
