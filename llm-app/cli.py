#!/usr/bin/env python3
"""LLM-app CLI with shared selection logic (same as GUI)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from typing import Any, Dict, List

from app_logic import (
    DEFAULT_DEEPSEEK_MODEL,
    DEFAULT_DEEPSEEK_URL,
    SelectorConfig,
    build_payload_for_tool,
    select_route_for_request,
)
from rpc import mcpd_call

SOCK_PATH = "/tmp/mcpd.sock"


class CliError(Exception):
    """User-facing CLI error."""


def _tools_signature(tools: List[Dict[str, Any]]) -> str:
    encoded = json.dumps(tools, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()[:12]


def _apps_signature(apps: List[Dict[str, Any]]) -> str:
    encoded = json.dumps(apps, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()[:12]


def _list_apps(sock_path: str) -> List[Dict[str, Any]]:
    resp = mcpd_call({"sys": "list_apps"}, sock_path=sock_path, timeout_s=5)
    if resp.get("status") != "ok":
        raise CliError(resp.get("error", "list_apps failed"))
    apps = resp.get("apps", [])
    if not isinstance(apps, list):
        raise CliError("list_apps response missing apps list")
    typed_apps: List[Dict[str, Any]] = []
    for app in apps:
        if isinstance(app, dict):
            typed_apps.append(app)
    return typed_apps


def _list_tools(sock_path: str, app_id: str = "") -> List[Dict[str, Any]]:
    req: Dict[str, Any] = {"sys": "list_tools"}
    if app_id:
        req["app_id"] = app_id
    resp = mcpd_call(req, sock_path=sock_path, timeout_s=5)
    if resp.get("status") != "ok":
        raise CliError(resp.get("error", "list_tools failed"))
    tools = resp.get("tools", [])
    if not isinstance(tools, list):
        raise CliError("list_tools response missing tools list")
    typed_tools: List[Dict[str, Any]] = []
    for tool in tools:
        if isinstance(tool, dict):
            typed_tools.append(tool)
    return typed_tools


def _print_apps(apps: List[Dict[str, Any]]) -> None:
    print(f"[llm-app] apps ({len(apps)}):", flush=True)
    for app in apps:
        print(
            (
                f"[llm-app]   - id={app.get('app_id')} "
                f"name={app.get('app_name')} tools={app.get('tool_count')}"
            ),
            flush=True,
        )
        tool_names = app.get("tool_names", [])
        if isinstance(tool_names, list) and tool_names:
            print(f"[llm-app]     tool_names={','.join(str(x) for x in tool_names)}", flush=True)


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


def _execute_once_with_apps(
    user_text: str,
    agent_id: str,
    sock_path: str,
    cfg: SelectorConfig,
    apps: List[Dict[str, Any]],
) -> int:
    if not apps:
        raise CliError("no apps returned by mcpd")

    (
        selected_app,
        selected_tool,
        app_selector_source,
        app_selector_reason,
        tool_selector_source,
        tool_selector_reason,
        _apps_catalog,
        tools,
    ) = select_route_for_request(
        user_text,
        sock_path,
        cfg,
    )

    tool_id = int(selected_tool["tool_id"])
    tool_name = str(selected_tool.get("name", "unknown"))
    tool_hash_raw = selected_tool.get("hash")
    tool_hash = tool_hash_raw if isinstance(tool_hash_raw, str) and tool_hash_raw else ""
    app_id = str(selected_app.get("app_id", ""))
    app_name = str(selected_app.get("app_name", app_id))
    if not app_id:
        raise CliError("selected app missing app_id")
    payload = build_payload_for_tool(selected_tool, user_text, cfg)

    print(f"[llm-app] selected app={app_name} id={app_id}", flush=True)
    print(f"[llm-app] selected tool={tool_name} id={tool_id} hash={tool_hash or '-'}", flush=True)
    print(f"[llm-app] app_selector={app_selector_source} reason={app_selector_reason}", flush=True)
    print(f"[llm-app] tool_selector={tool_selector_source} reason={tool_selector_reason}", flush=True)

    req_id = int(time.time_ns() & 0xFFFFFFFFFFFF)
    resp = mcpd_call(
        {
            "kind": "tool:exec",
            "req_id": req_id,
            "agent_id": agent_id,
            "app_id": app_id,
            "tool_id": tool_id,
            "tool_hash": tool_hash,
            "payload": payload,
        },
        sock_path=sock_path,
        timeout_s=20,
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
    apps = _list_apps(sock_path)
    tools = _list_tools(sock_path)
    _print_apps(apps)
    _print_tools(tools)
    return _execute_once_with_apps(user_text, agent_id, sock_path, cfg, apps)


def _print_help() -> None:
    print("[llm-app] commands:", flush=True)
    print("[llm-app]   /help  show help", flush=True)
    print("[llm-app]   /apps  force refresh and print apps", flush=True)
    print("[llm-app]   /tools force refresh and print tools", flush=True)
    print("[llm-app]   /exit  quit", flush=True)


def _repl_loop(agent_id: str, sock_path: str, cfg: SelectorConfig, show_tools: bool) -> int:
    apps = _list_apps(sock_path)
    tools = _list_tools(sock_path)
    if not apps:
        raise CliError("no apps returned by mcpd")

    print("[llm-app] REPL mode started", flush=True)
    _print_help()
    _print_apps(apps)
    _print_tools(tools)
    last_apps_sig = _apps_signature(apps)
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
        if user_text == "/apps":
            apps = _list_apps(sock_path)
            _print_apps(apps)
            last_apps_sig = _apps_signature(apps)
            continue
        if user_text == "/tools":
            tools = _list_tools(sock_path)
            _print_tools(tools)
            last_sig = _tools_signature(tools)
            continue

        apps = _list_apps(sock_path)
        app_sig = _apps_signature(apps)
        if app_sig != last_apps_sig:
            print("[llm-app] apps changed", flush=True)
            _print_apps(apps)
        else:
            print("[llm-app] apps unchanged", flush=True)
        last_apps_sig = app_sig

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

        rc = _execute_once_with_apps(user_text, agent_id, sock_path, cfg, apps)
        if rc != 0:
            print(f"[llm-app] request failed rc={rc}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", help="single prompt to run")
    parser.add_argument("--repl", action="store_true", help="interactive loop mode")
    parser.add_argument(
        "--selector",
        choices=["deepseek"],
        default="deepseek",
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
    except Exception as exc:  # noqa: BLE001
        print(f"[llm-app] ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
