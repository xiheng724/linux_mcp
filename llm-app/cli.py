#!/usr/bin/env python3
"""Simple LLM-app CLI with optional DeepSeek-based tool selection and REPL."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

SOCK_PATH = "/tmp/mcpd.sock"
DEFAULT_DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"
DEFAULT_UDS_TIMEOUT_SEC = 5.0


class CliError(Exception):
    """User-facing CLI error."""


class RpcError(CliError):
    """UDS RPC layer error."""


@dataclasses.dataclass(frozen=True)
class SelectorConfig:
    mode: str
    deepseek_url: str
    deepseek_model: str
    deepseek_timeout_sec: int


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def _send_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(struct.pack(">I", len(payload)))
    conn.sendall(payload)


def _recv_frame(conn: socket.socket) -> bytes:
    header = _recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    if length <= 0:
        raise ValueError(f"invalid frame length: {length}")
    return _recv_exact(conn, length)


def _tools_signature(tools: List[Dict[str, Any]]) -> str:
    encoded = json.dumps(tools, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()[:12]


def _uds_request(
    req: Dict[str, Any], sock_path: str, timeout_sec: float = DEFAULT_UDS_TIMEOUT_SEC
) -> Dict[str, Any]:
    if not os.path.exists(sock_path):
        raise RpcError(f"cannot connect to mcpd: socket not found: {sock_path}")

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout_sec)
            conn.connect(sock_path)
            _send_frame(conn, json.dumps(req, ensure_ascii=True).encode("utf-8"))
            raw = _recv_frame(conn)
    except socket.timeout as exc:
        raise RpcError(f"mcpd request timeout after {timeout_sec:.1f}s ({sock_path})") from exc
    except (FileNotFoundError, ConnectionRefusedError) as exc:
        raise RpcError(f"cannot connect to mcpd socket: {sock_path}") from exc
    except OSError as exc:
        raise RpcError(f"mcpd socket error at {sock_path}: {exc}") from exc

    try:
        resp = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise RpcError("invalid JSON response from mcpd") from exc
    if not isinstance(resp, dict):
        raise RpcError("invalid mcpd response type")
    return resp


def _list_tools(sock_path: str) -> List[Dict[str, Any]]:
    resp = _uds_request({"sys": "list_tools"}, sock_path)
    if resp.get("status") != "ok":
        raise RuntimeError(f"list_tools failed: {resp}")
    tools = resp.get("tools", [])
    if not isinstance(tools, list):
        raise RuntimeError("list_tools response missing tools list")
    typed_tools: List[Dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        typed_tools.append(tool)
    return typed_tools


def _print_tools(tools: List[Dict[str, Any]]) -> None:
    print(f"[llm-app] tools ({len(tools)}):", flush=True)
    for tool in tools:
        print(
            (
                f"[llm-app]   - id={tool.get('tool_id')} "
                f"name={tool.get('name')} hash={tool.get('hash', '-')}"
            ),
            flush=True,
        )
        print(f"[llm-app]     desc={tool.get('description')}", flush=True)


def _index_tools(tools: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    by_id: Dict[int, Dict[str, Any]] = {}
    for tool in tools:
        tool_id = tool.get("tool_id")
        if isinstance(tool_id, int):
            by_id[tool_id] = tool
    return by_id


def _heuristic_tool_id(user_text: str) -> Tuple[int, str]:
    lower = user_text.lower()
    if "burn" in lower or "cpu" in lower:
        return 2, "keyword(cpu/burn)"
    if "count" in lower or "stat" in lower or "word" in lower or "line" in lower:
        return 3, "keyword(text-stats)"
    return 1, "default(echo)"


def _extract_json_object(text: str) -> Dict[str, Any]:
    decoder = json.JSONDecoder()
    for idx, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _end = decoder.raw_decode(text[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError(f"no JSON object found in model output: {text!r}")


def _call_deepseek_selector(
    user_text: str,
    tools: List[Dict[str, Any]],
    api_key: str,
    cfg: SelectorConfig,
) -> Tuple[int, str]:
    tool_brief: List[Dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool.get("tool_id"), int):
            continue
        tool_brief.append(
            {
                "tool_id": tool["tool_id"],
                "name": tool.get("name", ""),
                "description": tool.get("description", ""),
                "input_schema": tool.get("input_schema", {}),
            }
        )

    prompt = {
        "user_input": user_text,
        "tools": tool_brief,
        "output_format": {"tool_id": "int", "reason": "string"},
        "rule": "Return one JSON object only. No markdown.",
    }
    req_obj = {
        "model": cfg.deepseek_model,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a tool router. Select exactly one tool_id from the provided tools. "
                    "Respond with strict JSON only: {\"tool_id\":<int>,\"reason\":\"...\"}."
                ),
            },
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=True)},
        ],
    }

    payload = json.dumps(req_obj, ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(
        cfg.deepseek_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.deepseek_timeout_sec) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"DeepSeek HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"DeepSeek request failed: {exc}") from exc

    data = json.loads(raw.decode("utf-8"))
    choices = data.get("choices", [])
    if not isinstance(choices, list) or not choices:
        raise RuntimeError(f"invalid DeepSeek response, missing choices: {data}")
    msg = choices[0].get("message", {})
    content = msg.get("content", "")
    if not isinstance(content, str) or not content:
        raise RuntimeError(f"invalid DeepSeek response content: {data}")

    obj = _extract_json_object(content)
    tool_id = obj.get("tool_id")
    if isinstance(tool_id, bool) or not isinstance(tool_id, int):
        raise RuntimeError(f"DeepSeek returned invalid tool_id: {obj}")
    reason = obj.get("reason", "")
    if not isinstance(reason, str):
        reason = str(reason)
    return tool_id, reason


def _select_tool(
    user_text: str,
    tools: List[Dict[str, Any]],
    cfg: SelectorConfig,
) -> Tuple[Dict[str, Any], str, str]:
    by_id = _index_tools(tools)
    if not by_id:
        raise RuntimeError("no valid tools discovered from mcpd")

    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    if cfg.mode in ("auto", "deepseek"):
        if api_key:
            try:
                selected_id, reason = _call_deepseek_selector(user_text, tools, api_key, cfg)
                selected = by_id.get(selected_id)
                if selected is None:
                    raise RuntimeError(
                        f"DeepSeek selected unavailable tool_id={selected_id}; "
                        f"available={sorted(by_id.keys())}"
                    )
                return selected, "deepseek", reason or "model-selected"
            except Exception as exc:  # noqa: BLE001
                if cfg.mode == "deepseek":
                    raise RuntimeError(f"DeepSeek selection failed: {exc}") from exc
                print(
                    f"[llm-app] WARN: DeepSeek unavailable ({exc}), fallback to heuristic",
                    flush=True,
                )
        elif cfg.mode == "deepseek":
            raise RuntimeError("DEEPSEEK_API_KEY not set, cannot use --selector deepseek")

    selected_id, reason = _heuristic_tool_id(user_text)
    selected = by_id.get(selected_id)
    if selected is None:
        fallback_id = sorted(by_id.keys())[0]
        selected = by_id[fallback_id]
        reason = f"{reason}; fallback_first_available={fallback_id}"
    return selected, "heuristic", reason


def _extract_burn_ms(user_text: str) -> int:
    found = re.search(r"(\d+)", user_text)
    if not found:
        return 200
    ms = int(found.group(1))
    if ms < 1:
        return 1
    if ms > 10_000:
        return 10_000
    return ms


def _build_payload(tool_name: str, user_text: str) -> Dict[str, Any]:
    if tool_name == "cpu_burn":
        return {"ms": _extract_burn_ms(user_text)}
    if tool_name == "text_stats":
        return {"text": user_text}
    return {"message": user_text}


def _execute_once_with_tools(
    user_text: str, agent_id: str, sock_path: str, cfg: SelectorConfig, tools: List[Dict[str, Any]]
) -> int:
    if not tools:
        raise CliError("no tools returned by mcpd")

    selected, selector_source, selector_reason = _select_tool(user_text, tools, cfg)
    tool_id = int(selected["tool_id"])
    tool_name = str(selected.get("name", "unknown"))
    tool_hash_raw = selected.get("hash")
    tool_hash = tool_hash_raw if isinstance(tool_hash_raw, str) and tool_hash_raw else ""
    payload = _build_payload(tool_name, user_text)
    print(
        f"[llm-app] selected tool={tool_name} id={tool_id} hash={tool_hash or '-'}",
        flush=True,
    )
    print(f"[llm-app] selector={selector_source} reason={selector_reason}", flush=True)

    req_id = int(time.time_ns() & 0xFFFFFFFFFFFF)
    resp = _uds_request(
        {
            "kind": "tool:exec",
            "req_id": req_id,
            "agent_id": agent_id,
            "tool_id": tool_id,
            "tool_hash": tool_hash,
            "payload": payload,
        },
        sock_path,
    )
    print(f"[llm-app] req_id={req_id} status={resp.get('status')} t_ms={resp.get('t_ms')}", flush=True)
    if resp.get("status") == "ok":
        print(f"[llm-app] result={json.dumps(resp.get('result', {}), ensure_ascii=True)}", flush=True)
        print("[llm-app] done", flush=True)
        return 0
    print(f"[llm-app] error={resp.get('error', 'unknown error')}", flush=True)
    print("[llm-app] tool execution failed", flush=True)
    return 3


def _run_once(user_text: str, agent_id: str, sock_path: str, cfg: SelectorConfig) -> int:
    tools = _list_tools(sock_path)
    _print_tools(tools)
    return _execute_once_with_tools(user_text, agent_id, sock_path, cfg, tools)


def _print_help() -> None:
    print("[llm-app] commands:", flush=True)
    print("[llm-app]   /help  show help", flush=True)
    print("[llm-app]   /tools force refresh and print tools", flush=True)
    print("[llm-app]   /exit  quit", flush=True)


def _repl_loop(
    agent_id: str,
    sock_path: str,
    cfg: SelectorConfig,
    show_tools: bool,
) -> int:
    try:
        tools = _list_tools(sock_path)
    except RpcError as exc:
        raise CliError(f"{exc}. start mcpd with: bash scripts/run_mcpd.sh") from exc

    if not tools:
        raise CliError("no tools returned by mcpd")

    last_sig = ""
    print("[llm-app] REPL mode started", flush=True)
    _print_help()
    _print_tools(tools)
    last_sig = _tools_signature(tools)

    while True:
        try:
            line = input("user> ")
        except EOFError:
            print("\n[llm-app] bye", flush=True)
            return 0
        user_text = line.strip()
        if not user_text:
            continue
        if user_text == "/exit":
            return 0
        if user_text == "/help":
            _print_help()
            continue
        if user_text == "/tools":
            tools = _list_tools(sock_path)
            _print_tools(tools)
            last_sig = _tools_signature(tools)
            continue

        tools = _list_tools(sock_path)
        sig = _tools_signature(tools)
        if show_tools:
            _print_tools(tools)
        elif sig != last_sig:
            print("[llm-app] tools changed", flush=True)
            _print_tools(tools)
        else:
            print("[llm-app] tools unchanged", flush=True)
        last_sig = sig

        rc = _execute_once_with_tools(user_text, agent_id, sock_path, cfg, tools)
        if rc != 0:
            print(f"[llm-app] request failed rc={rc}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", help="single prompt to run")
    parser.add_argument("--repl", action="store_true", help="interactive loop mode")
    parser.add_argument(
        "--selector",
        choices=["auto", "heuristic", "deepseek"],
        default="auto",
        help="tool selection strategy",
    )
    parser.add_argument("--deepseek-model", default=DEFAULT_DEEPSEEK_MODEL)
    parser.add_argument(
        "--deepseek-url",
        default=os.getenv("DEEPSEEK_API_URL", DEFAULT_DEEPSEEK_URL),
    )
    parser.add_argument("--deepseek-timeout-sec", type=int, default=20)
    parser.add_argument("--agent-id", default="a1", help="agent id for tool execution")
    parser.add_argument("--sock", default=SOCK_PATH, help="mcpd unix socket path")
    parser.add_argument("--show-tools", action="store_true", help="always print full tool list in REPL")
    parser.add_argument("--agent", dest="agent_legacy", help=argparse.SUPPRESS)
    parser.add_argument("--socket", dest="socket_legacy", help=argparse.SUPPRESS)
    args = parser.parse_args()

    agent_id = args.agent_legacy or args.agent_id
    sock_path = args.socket_legacy or args.sock

    cfg = SelectorConfig(
        mode=args.selector,
        deepseek_url=args.deepseek_url,
        deepseek_model=args.deepseek_model,
        deepseek_timeout_sec=args.deepseek_timeout_sec,
    )

    try:
        if args.once and args.repl:
            raise CliError("use either --once or --repl, not both")
        if args.once:
            return _run_once(args.once, agent_id, sock_path, cfg)
        if args.repl:
            return _repl_loop(agent_id, sock_path, cfg, args.show_tools)
        if not sys.stdin.isatty():
            raise CliError("no --once/--repl provided and stdin is not interactive")
        return _repl_loop(agent_id, sock_path, cfg, args.show_tools)
    except CliError as exc:
        print(f"[llm-app] ERROR: {exc}", flush=True)
        return 1
    except RpcError as exc:
        print(f"[llm-app] ERROR: {exc}", flush=True)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[llm-app] ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
