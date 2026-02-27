#!/usr/bin/env python3
"""Arithmetic calculator tool app."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from typing import Any, Dict, Union

Number = Union[int, float]


def _to_number(value: Any) -> Number:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("expression contains non-numeric constant")
    return value


def _eval_node(node: ast.AST) -> Number:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)
    if isinstance(node, ast.Constant):
        return _to_number(node.value)
    if isinstance(node, ast.UnaryOp):
        val = _eval_node(node.operand)
        if isinstance(node.op, ast.UAdd):
            return +val
        if isinstance(node.op, ast.USub):
            return -val
        raise ValueError("unsupported unary operator")
    if isinstance(node, ast.BinOp):
        left = _eval_node(node.left)
        right = _eval_node(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            return left / right
        if isinstance(node.op, ast.FloorDiv):
            return left // right
        if isinstance(node.op, ast.Mod):
            return left % right
        if isinstance(node.op, ast.Pow):
            return left**right
        raise ValueError("unsupported binary operator")
    raise ValueError("unsupported expression element")


def _extract_expression(payload: Dict[str, Any]) -> str:
    for key in ("expression", "message"):
        raw = payload.get(key, "")
        if isinstance(raw, str) and raw.strip():
            text = raw.strip()
            break
    else:
        raise ValueError("calc payload requires non-empty expression/message")

    m = re.search(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'", text)
    if m:
        for idx in (1, 2, 3):
            part = m.group(idx)
            if part:
                return part.strip()

    candidates = re.findall(r"[0-9\.\+\-\*\/%\(\)\s]{3,}", text)
    for cand in sorted(candidates, key=len, reverse=True):
        expr = " ".join(cand.split())
        if any(ch.isdigit() for ch in expr) and any(ch in expr for ch in "+-*/%"):
            return expr
    return text


def run(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("calc payload must be object")

    expr = _extract_expression(payload)
    if len(expr) > 200:
        raise ValueError("expression too long (max 200 chars)")

    tree = ast.parse(expr, mode="eval")
    result = _eval_node(tree)
    return {"expression": expr, "result": result}


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
