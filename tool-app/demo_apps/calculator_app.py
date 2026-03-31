#!/usr/bin/env python3
"""Demo Calculator App exposed over UDS RPC."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Any, Dict, Union

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve

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
    quoted = re.search(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'", text)
    if quoted:
        for idx in (1, 2, 3):
            part = quoted.group(idx)
            if part:
                return part.strip()
    candidates = re.findall(r"[0-9\.\+\-\*\/\(\)\s]{3,}", text)
    for cand in sorted(candidates, key=len, reverse=True):
        expr = " ".join(cand.split())
        if any(ch.isdigit() for ch in expr) and any(ch in expr for ch in "+-*/"):
            return expr
    return text


def calc(payload: Dict[str, Any]) -> Dict[str, Any]:
    expr = _extract_expression(payload)
    if len(expr) > 200:
        raise ValueError("expression too long (max 200 chars)")
    tree = ast.parse(expr, mode="eval")
    return {"expression": expr, "result": _eval_node(tree)}


def main() -> int:
    args = parse_args()
    return serve(args.manifest, {"calc": calc})


if __name__ == "__main__":
    raise SystemExit(main())
