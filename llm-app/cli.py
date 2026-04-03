#!/usr/bin/env python3
"""LLM-app CLI with shared selection logic (same as GUI)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from typing import Any, Callable, Dict, List, Literal, TypeVar

from app_logic import (
    ApprovalRequest,
    execute_plan,
    load_catalog,
    load_apps,
    load_tools,
)
from debug_render import render_execution_debug_lines
from model_client import (
    DEFAULT_DEEPSEEK_MODEL,
    DEFAULT_DEEPSEEK_URL,
    SelectorConfig,
    SessionInfo,
    open_session,
)
from presentation import render_app_lines, render_execution_user_lines, render_tool_lines

SOCK_PATH = "/tmp/mcpd.sock"
SHOW_PAYLOAD_ENV = "LLM_APP_SHOW_PAYLOAD"
DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000
DisplayMode = Literal["user", "dev"]
T = TypeVar("T")


class CliError(Exception):
    """User-facing CLI error."""


def _env_flag(name: str) -> bool:
    raw = os.getenv(name, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _json_signature(data: Any) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()[:12]


def _tools_signature(tools: List[Dict[str, Any]]) -> str:
    return _json_signature(tools)


def _apps_signature(apps: List[Dict[str, Any]]) -> str:
    return _json_signature(apps)


def _with_cli_error(call: Callable[[], T]) -> T:
    try:
        return call()
    except RuntimeError as exc:
        raise CliError(str(exc)) from exc


def _list_apps(sock_path: str) -> List[Dict[str, Any]]:
    return _with_cli_error(lambda: load_apps(sock_path))


def _list_tools(sock_path: str, app_id: str = "") -> List[Dict[str, Any]]:
    return _with_cli_error(lambda: load_tools(sock_path, app_id))


def _print_lines(lines: List[str], *, prefix: str = "[llm-app]") -> None:
    for line in lines:
        print(f"{prefix} {line}" if line else "", flush=True)


def _print_apps(apps: List[Dict[str, Any]], mode: DisplayMode) -> None:
    _print_lines(render_app_lines(apps, detailed=(mode == "dev")))


def _print_tools(tools: List[Dict[str, Any]], mode: DisplayMode) -> None:
    _print_lines(render_tool_lines(tools, detailed=(mode == "dev")))


def _print_repl_banner(apps: List[Dict[str, Any]], tools: List[Dict[str, Any]], mode: DisplayMode) -> None:
    print("[llm-app] REPL ready", flush=True)
    print(f"[llm-app] mode: {mode}", flush=True)
    print(f"[llm-app] catalog: apps={len(apps)} tools={len(tools)}", flush=True)
    if mode == "user":
        print("[llm-app] tip: concise replies enabled; use /mode dev for full traces", flush=True)
    else:
        print("[llm-app] tip: dev mode shows planning and execution traces", flush=True)


def _ensure_session(sock_path: str, client_name: str, session: SessionInfo | None) -> SessionInfo:
    now_ms = int(time.time() * 1000)
    if session is not None and session.expires_at_ms > (now_ms + 5_000):
        return session
    return open_session(sock_path, client_name, DEFAULT_SESSION_TTL_MS)


def _execute_once_with_apps(
    user_text: str,
    session: SessionInfo,
    sock_path: str,
    cfg: SelectorConfig,
    apps: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    mode: DisplayMode,
    show_reasons: bool = False,
    show_payload: bool = False,
) -> int:
    if not apps:
        raise CliError("no apps returned by mcpd")
    def _approval_prompt(request: ApprovalRequest) -> bool:
        ticket_text = f" ticket_id={request.ticket_id}" if request.ticket_id > 0 else ""
        print(
            (
                f"[llm-app] approval required: step={request.step_id} "
                f"tool={request.tool_name}{ticket_text} reason={request.reason}"
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
        session,
        sock_path,
        cfg,
        apps=apps,
        tools=tools,
        approval_handler=_approval_prompt,
    )
    if mode == "dev":
        for line in render_execution_debug_lines(
            execution,
            prefix="[llm-app]",
            show_payload=show_payload,
        ):
            print(line, flush=True)
    else:
        for line in render_execution_user_lines(execution):
            print(f"assistant> {line}", flush=True)
    if show_reasons and mode == "dev":
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
    client_name: str,
    sock_path: str,
    cfg: SelectorConfig,
    mode: DisplayMode,
    show_reasons: bool,
    show_payload: bool,
) -> int:
    apps, tools = _with_cli_error(lambda: load_catalog(sock_path))
    session = _ensure_session(sock_path, client_name, None)
    print(f"[llm-app] catalog: apps={len(apps)} tools={len(tools)}", flush=True)
    return _execute_once_with_apps(
        user_text,
        session,
        sock_path,
        cfg,
        apps,
        tools,
        mode,
        show_reasons=show_reasons,
        show_payload=show_payload,
    )


def _print_help(mode: DisplayMode) -> None:
    print("[llm-app] commands:", flush=True)
    print("[llm-app]   /help  show help", flush=True)
    print("[llm-app]   /apps  force refresh and print apps", flush=True)
    print("[llm-app]   /tools force refresh and print tools", flush=True)
    print("[llm-app]   /mode  show current mode", flush=True)
    print("[llm-app]   /mode user | /mode dev  switch verbosity", flush=True)
    print("[llm-app]   /exit  quit", flush=True)
    if mode == "user":
        print("[llm-app] current output: concise user-facing summaries", flush=True)
    else:
        print("[llm-app] current output: full planning/debug traces", flush=True)


def _repl_loop(
    client_name: str,
    sock_path: str,
    cfg: SelectorConfig,
    show_tools: bool,
    show_reasons: bool,
    show_payload: bool,
    mode: DisplayMode,
) -> int:
    apps = _list_apps(sock_path)
    tools = _list_tools(sock_path)
    session = _ensure_session(sock_path, client_name, None)
    if not apps:
        raise CliError("no apps returned by mcpd")

    _print_repl_banner(apps, tools, mode)
    _print_help(mode)
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
            _print_help(mode)
            continue
        if user_text == "/mode":
            print(f"[llm-app] mode: {mode}", flush=True)
            continue
        if user_text in {"/mode user", "/mode dev"}:
            mode = "dev" if user_text.endswith("dev") else "user"
            print(f"[llm-app] switched to {mode} mode", flush=True)
            continue
        if user_text == "/apps":
            apps = _list_apps(sock_path)
            _print_apps(apps, mode)
            last_apps_sig = _apps_signature(apps)
            continue
        if user_text == "/tools":
            tools = _list_tools(sock_path)
            _print_tools(tools, mode)
            last_sig = _tools_signature(tools)
            continue

        apps = _list_apps(sock_path)
        app_sig = _apps_signature(apps)
        if app_sig != last_apps_sig:
            print(f"[llm-app] catalog updated: apps={len(apps)}", flush=True)
            if mode == "dev":
                _print_apps(apps, mode)
        last_apps_sig = app_sig

        tools = _list_tools(sock_path)
        sig = _tools_signature(tools)
        if show_tools:
            _print_tools(tools, mode)
        elif sig != last_sig:
            print(f"[llm-app] catalog updated: tools={len(tools)}", flush=True)
            if mode == "dev":
                _print_tools(tools, mode)
        last_sig = sig

        session = _ensure_session(sock_path, client_name, session)
        rc = _execute_once_with_apps(
            user_text,
            session,
            sock_path,
            cfg,
            apps,
            tools,
            mode,
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
    parser.add_argument("--agent-id", default="a1", help="client name hint for session opening")
    parser.add_argument("--sock", default=SOCK_PATH, help="mcpd unix socket path")
    parser.add_argument("--show-tools", action="store_true", help="always print full tool list in REPL")
    parser.add_argument(
        "--mode",
        choices=("user", "dev"),
        default="user",
        help="user mode shows concise results; dev mode shows detailed traces",
    )
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
    args = parser.parse_args()

    client_name = args.agent_id
    sock_path = args.sock
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
            return _run_once(
                args.once,
                client_name,
                sock_path,
                cfg,
                args.mode,
                args.show_reasons,
                show_payload,
            )
        if args.repl:
            return _repl_loop(
                client_name,
                sock_path,
                cfg,
                args.show_tools,
                args.show_reasons,
                show_payload,
                args.mode,
            )
        if not sys.stdin.isatty():
            raise CliError("no --once/--repl provided and stdin is not interactive")
        return _repl_loop(
            client_name,
            sock_path,
            cfg,
            args.show_tools,
            args.show_reasons,
            show_payload,
            args.mode,
        )
    except CliError as exc:
        print(f"[llm-app] ERROR: {exc}", flush=True)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[llm-app] ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
