#!/usr/bin/env python3
"""Text statistics tool app."""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict

WORD_RE = re.compile(r"\b\w+\b", re.UNICODE)


def run(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("text_stats payload must be object")

    text = payload.get("text", "")
    if not isinstance(text, str):
        raise ValueError("text_stats payload.text must be string")

    words = WORD_RE.findall(text)
    lines = text.splitlines()
    non_empty_lines = [line for line in lines if line.strip()]

    return {
        "chars": len(text),
        "words": len(words),
        "unique_words": len({word.lower() for word in words}),
        "lines": len(lines) if text else 0,
        "non_empty_lines": len(non_empty_lines),
        "preview": text[:80],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdin-json", action="store_true")
    args = parser.parse_args()

    try:
        if args.stdin_json:
            payload = json.loads(sys.stdin.read())
        else:
            payload = {"text": ""}
        print(json.dumps(run(payload), ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

