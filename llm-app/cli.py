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
    ApprovalRequest,
    DEFAULT_DEEPSEEK_MODEL,
    DEFAULT_DEEPSEEK_URL,
    SelectorConfig,
    execute_plan,
    load_catalog,
    render_execution_debug_lines,
)
from rpc import mcpd_call

SOCK_PATH = "/tmp/mcpd.sock"
SHOW_PAYLOAD_ENV = "LLM_APP_SHOW_PAYLOAD"


class CliError(Exception):
    """User-facing CLI error."""


def _env_flag(name: str) -> bool:
    raw = os.getenv(name, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


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


def _print_repl_banner(apps: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> None:
    print("[llm-app] REPL ready", flush=True)
    print(f"[llm-app] catalog: apps={len(apps)} tools={len(tools)}", flush=True)
    print("[llm-app] tip: /apps and /tools show full catalogs", flush=True)


def _execute_once_with_apps(
    user_text: str,
    agent_id: str,
    sock_path: str,
    cfg: SelectorConfig,
    apps: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    show_reasons: bool = False,
    show_payload: bool = False,
) -> int:
    if not apps:
        raise CliError("no apps returned by mcpd")
    def _approval_prompt(request: ApprovalRequest) -> bool:
        print(
            (
                f"[llm-app] approval required: step={request.step_id} "
                f"tool={request.tool_name} ticket_id={request.ticket_id} reason={request.reason}"
            ),
            flush=True,
        )
        print(
            f"[llm-app] approval payload: {json.dumps(request.payload, ensure_ascii=True, sort_keys=True)}",
            flush=True,
        )
        if not sys.stdin.isatty():
            return False
        answer = input("[llm-app] approve? [y/N] ").strip().lower()
        return answer in {"y", "yes"}

    execution = execute_plan(
        user_text,
        agent_id,
        sock_path,
        cfg,
        apps=apps,
        tools=tools,
        approval_handler=_approval_prompt,
    )
    for line in render_execution_debug_lines(
        execution,
        prefix="[llm-app]",
        show_payload=show_payload,
    ):
        print(line, flush=True)
    if show_reasons:
        print(f"[llm-app] plan_source: model", flush=True)
    resp = execution.get("response", {})
    if not isinstance(resp, dict):
        resp = {}
    if execution.get("status") == "ok":
        return 0
    print(f"[llm-app] error: {resp.get('error', execution.get('error', 'unknown error'))}", flush=True)
    return 3


def _run_once(
    user_text: str,
    agent_id: str,
    sock_path: str,
    cfg: SelectorConfig,
    show_reasons: bool,
    show_payload: bool,
) -> int:
    apps, tools = load_catalog(sock_path)
    print(f"[llm-app] catalog: apps={len(apps)} tools={len(tools)}", flush=True)
    return _execute_once_with_apps(
        user_text,
        agent_id,
        sock_path,
        cfg,
        apps,
        tools,
        show_reasons=show_reasons,
        show_payload=show_payload,
    )


def _print_help() -> None:
    print("[llm-app] commands:", flush=True)
    print("[llm-app]   /help  show help", flush=True)
    print("[llm-app]   /apps  force refresh and print apps", flush=True)
    print("[llm-app]   /tools force refresh and print tools", flush=True)
    print("[llm-app]   /exit  quit", flush=True)


def _repl_loop(
    agent_id: str,
    sock_path: str,
    cfg: SelectorConfig,
    show_tools: bool,
    show_reasons: bool,
    show_payload: bool,
) -> int:
    apps = _list_apps(sock_path)
    tools = _list_tools(sock_path)
    if not apps:
        raise CliError("no apps returned by mcpd")

    _print_repl_banner(apps, tools)
    _print_help()
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
            print(f"[llm-app] catalog updated: apps={len(apps)}", flush=True)
            _print_apps(apps)
        last_apps_sig = app_sig

        tools = _list_tools(sock_path)
        sig = _tools_signature(tools)
        if show_tools:
            _print_tools(tools)
        elif sig != last_sig:
            print(f"[llm-app] catalog updated: tools={len(tools)}", flush=True)
            _print_tools(tools)
        last_sig = sig

        rc = _execute_once_with_apps(
            user_text,
            agent_id,
            sock_path,
            cfg,
            apps,
            tools,
            show_reasons=show_reasons,
            show_payload=show_payload,
        )
        if rc != 0:
            print(f"[llm-app] request failed rc={rc}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", help="single prompt to run")
    parser.add_argument("--repl", action="store_true", help="interactive loop mode")
    parser.add_argument("--deepseek-model", default=DEFAULT_DEEPSEEK_MODEL)
    parser.add_argument(
        "--deepseek-url",
        default=os.getenv("DEEPSEEK_API_URL", DEFAULT_DEEPSEEK_URL),
    )
    parser.add_argument("--deepseek-timeout-sec", type=int, default=20)
    parser.add_argument("--agent-id", default="a1", help="agent id for tool execution")
    parser.add_argument("--sock", default=SOCK_PATH, help="mcpd unix socket path")
    parser.add_argument("--show-tools", action="store_true", help="always print full tool list in REPL")
    parser.add_argument(
        "--show-reasons",
        action="store_true",
        help="print planner metadata for each request",
    )
    parser.add_argument(
        "--show-payload",
        action="store_true",
        help=f"print model-generated payload before tool execution (or set {SHOW_PAYLOAD_ENV}=1)",
    )
    parser.add_argument("--agent", dest="agent_legacy", help=argparse.SUPPRESS)
    parser.add_argument("--socket", dest="socket_legacy", help=argparse.SUPPRESS)
    args = parser.parse_args()

    agent_id = args.agent_legacy or args.agent_id
    sock_path = args.socket_legacy or args.sock
    cfg = SelectorConfig(
        deepseek_url=args.deepseek_url,
        deepseek_model=args.deepseek_model,
        deepseek_timeout_sec=args.deepseek_timeout_sec,
    )
    show_payload = args.show_payload or _env_flag(SHOW_PAYLOAD_ENV)

    try:
        if args.once and args.repl:
            raise CliError("use either --once or --repl, not both")
        if args.once:
            return _run_once(args.once, agent_id, sock_path, cfg, args.show_reasons, show_payload)
        if args.repl:
            return _repl_loop(
                agent_id,
                sock_path,
                cfg,
                args.show_tools,
                args.show_reasons,
                show_payload,
            )
        if not sys.stdin.isatty():
            raise CliError("no --once/--repl provided and stdin is not interactive")
        return _repl_loop(
            agent_id,
            sock_path,
            cfg,
            args.show_tools,
            args.show_reasons,
            show_payload,
        )
    except CliError as exc:
        print(f"[llm-app] ERROR: {exc}", flush=True)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[llm-app] ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
