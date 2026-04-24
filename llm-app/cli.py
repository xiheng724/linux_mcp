#!/usr/bin/env python3
"""LLM-app CLI with shared selection logic (same as GUI)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from typing import Any, Dict, List, Literal

from app_logic import ApprovalRequest, execute_plan, load_catalog
from debug_render import render_execution_debug_lines
from model_client import (
    DEFAULT_MODEL_NAME,
    DEFAULT_MODEL_URL,
    SelectorConfig,
    SessionInfo,
    open_session,
)
from presentation import render_app_lines, render_execution_user_lines, render_tool_lines
from rpc import mcpd_call

try:
    from rich import box as rich_box
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.spinner import Spinner
    from rich.table import Table
    from rich.text import Text

    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.formatted_text import HTML as PromptHtml
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.styles import Style as PromptStyle

    HAVE_PROMPT_TOOLKIT = True
except ImportError:
    HAVE_PROMPT_TOOLKIT = False

SOCK_PATH = "/tmp/mcpd.sock"
SHOW_PAYLOAD_ENV = "LLM_APP_SHOW_PAYLOAD"
DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000
DisplayMode = Literal["user", "dev"]
REPL_COMMANDS = [
    "/help",
    "/apps",
    "/tools",
    "/mode",
    "/mode user",
    "/mode dev",
    "/clear",
    "/exit",
]

console = Console(highlight=False) if HAVE_RICH else None


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


def _sysline(msg: str) -> None:
    if HAVE_RICH:
        text = Text()
        text.append("[llm-app] ", style="dim")
        text.append(msg)
        console.print(text)
        return
    print(f"[llm-app] {msg}", flush=True)


def _okline(msg: str) -> None:
    if HAVE_RICH:
        text = Text()
        text.append("[llm-app] ", style="dim")
        text.append("OK ", style="bold green")
        text.append(msg, style="green")
        console.print(text)
        return
    print(f"[llm-app] OK {msg}", flush=True)


def _warnline(msg: str) -> None:
    if HAVE_RICH:
        text = Text()
        text.append("[llm-app] ", style="dim")
        text.append("WARN ", style="bold yellow")
        text.append(msg, style="yellow")
        console.print(text)
        return
    print(f"[llm-app] WARN {msg}", flush=True)


def _errline(msg: str) -> None:
    if HAVE_RICH:
        text = Text()
        text.append("[llm-app] ", style="dim")
        text.append("ERROR ", style="bold red")
        text.append(msg, style="red")
        console.print(text)
        return
    print(f"[llm-app] ERROR: {msg}", flush=True)


def _separator() -> None:
    if HAVE_RICH:
        console.rule(style="dim")
        return
    print("-" * 60, flush=True)


def _spinner_context(message: str):
    if HAVE_RICH:
        return Live(
            Spinner("dots", text=f"[yellow]{message}[/yellow]"),
            console=console,
            refresh_per_second=12,
        )

    class _NoopSpinner:
        def __enter__(self) -> "_NoopSpinner":
            print(f"[llm-app] {message}...", flush=True)
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

    return _NoopSpinner()


def _list_apps(sock_path: str) -> List[Dict[str, Any]]:
    resp = mcpd_call({"sys": "list_apps"}, sock_path=sock_path, timeout_s=5)
    if resp.get("status") != "ok":
        raise CliError(resp.get("error", "list_apps failed"))
    apps = resp.get("apps", [])
    if not isinstance(apps, list):
        raise CliError("list_apps response missing apps list")
    return [app for app in apps if isinstance(app, dict)]


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
    return [tool for tool in tools if isinstance(tool, dict)]


def _print_lines(lines: List[str], *, prefix: str = "[llm-app]") -> None:
    for line in lines:
        print(f"{prefix} {line}" if line else "", flush=True)


def _print_apps(apps: List[Dict[str, Any]], mode: DisplayMode) -> None:
    if HAVE_RICH:
        table = Table(
            box=rich_box.SIMPLE,
            show_header=True,
            header_style="bold cyan",
            title=f"Apps ({len(apps)})",
        )
        table.add_column("App", style="white")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Tools", style="green", justify="right")
        if mode == "dev":
            table.add_column("Names", style="dim")
        for app in apps:
            app_name = str(app.get("app_name", app.get("app_id", "app")))
            app_id = str(app.get("app_id", ""))
            tool_count = str(app.get("tool_count", 0))
            row = [app_name, app_id, tool_count]
            if mode == "dev":
                names = app.get("tool_names", [])
                tool_text = ", ".join(str(name) for name in names[:8]) if isinstance(names, list) else ""
                row.append(tool_text)
            table.add_row(*row)
        console.print(table)
        return
    _print_lines(render_app_lines(apps, detailed=(mode == "dev")))


def _print_tools(tools: List[Dict[str, Any]], mode: DisplayMode) -> None:
    if HAVE_RICH:
        table = Table(
            box=rich_box.SIMPLE,
            show_header=True,
            header_style="bold blue",
            title=f"Tools ({len(tools)})",
        )
        table.add_column("Tool", style="white")
        table.add_column("App", style="cyan")
        if mode == "dev":
            table.add_column("ID", style="green", justify="right")
            table.add_column("Description", style="dim")
        for tool in tools:
            name = str(tool.get("name", "tool"))
            app_name = str(tool.get("app_name", tool.get("app_id", "app")))
            row = [name, app_name]
            if mode == "dev":
                row.append(str(tool.get("tool_id", "?")))
                row.append(str(tool.get("description", "")))
            table.add_row(*row)
        console.print(table)
        return
    _print_lines(render_tool_lines(tools, detailed=(mode == "dev")))


def _print_repl_banner(apps: List[Dict[str, Any]], tools: List[Dict[str, Any]], mode: DisplayMode) -> None:
    if HAVE_RICH:
        tip = (
            "concise replies enabled; use /mode dev for full traces"
            if mode == "user"
            else "dev mode shows planning and execution traces"
        )
        panel = Panel(
            f"mode: [bold]{mode}[/bold]\napps: [green]{len(apps)}[/green]   tools: [blue]{len(tools)}[/blue]\n[dim]{tip}[/dim]",
            title="llm-app REPL",
            border_style="dim",
            padding=(0, 1),
        )
        console.print(panel)
        return
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


def _approval_prompt(request: ApprovalRequest) -> bool:
    ticket_text = f" ticket_id={request.ticket_id}" if request.ticket_id > 0 else ""
    if HAVE_RICH:
        panel = Panel(
            (
                f"[bold yellow]step[/bold yellow] {request.step_id}\n"
                f"[bold yellow]tool[/bold yellow] {request.tool_name}{ticket_text}\n"
                f"[bold yellow]reason[/bold yellow] {request.reason}\n"
                f"[dim]{json.dumps(request.payload, ensure_ascii=True, sort_keys=True)}[/dim]"
            ),
            title="Approval Required",
            border_style="yellow",
            padding=(0, 1),
        )
        console.print(panel)
    else:
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
        _warnline("stdin is not a tty; auto-denying approval")
        return False
    try:
        if HAVE_RICH:
            answer = console.input("[bold green]approve?[/bold green] [dim][y/N][/dim] ").strip().lower()
        else:
            answer = input("[llm-app] approve? [y/N] ").strip().lower()
        return answer in {"y", "yes"}
    except (EOFError, KeyboardInterrupt):
        return False


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

    with _spinner_context("planning and executing"):
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
            if HAVE_RICH:
                console.print(line, highlight=False)
            else:
                print(line, flush=True)
    else:
        for line in render_execution_user_lines(execution):
            if HAVE_RICH:
                text = Text()
                text.append("assistant> ", style="bold magenta")
                text.append(line)
                console.print(text)
            else:
                print(f"assistant> {line}", flush=True)
    if show_reasons and mode == "dev":
        _sysline("plan_source: model")
    resp = execution.get("response", {})
    if not isinstance(resp, dict):
        resp = {}
    if execution.get("status") == "ok":
        return 0
    _errline(resp.get("error", execution.get("error", "unknown error")))
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
    apps, tools = load_catalog(sock_path)
    session = _ensure_session(sock_path, client_name, None)
    _sysline(f"catalog: apps={len(apps)} tools={len(tools)}")
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
    if HAVE_RICH:
        table = Table(box=rich_box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="dim")
        rows = [
            ("/help", "show help"),
            ("/apps", "force refresh and print apps"),
            ("/tools", "force refresh and print tools"),
            ("/mode", "show current mode"),
            ("/mode user", "switch to concise user-facing summaries"),
            ("/mode dev", "switch to planning/debug traces"),
            ("/clear", "clear terminal output"),
            ("/exit", "quit"),
        ]
        for command, description in rows:
            table.add_row(command, description)
        console.print(table)
        _sysline(
            "current output: concise user-facing summaries"
            if mode == "user"
            else "current output: full planning/debug traces"
        )
        return
    print("[llm-app] commands:", flush=True)
    print("[llm-app]   /help  show help", flush=True)
    print("[llm-app]   /apps  force refresh and print apps", flush=True)
    print("[llm-app]   /tools force refresh and print tools", flush=True)
    print("[llm-app]   /mode  show current mode", flush=True)
    print("[llm-app]   /mode user | /mode dev  switch verbosity", flush=True)
    print("[llm-app]   /clear clear terminal output", flush=True)
    print("[llm-app]   /exit  quit", flush=True)
    if mode == "user":
        print("[llm-app] current output: concise user-facing summaries", flush=True)
    else:
        print("[llm-app] current output: full planning/debug traces", flush=True)


def _build_prompt_session() -> PromptSession | None:
    if not HAVE_PROMPT_TOOLKIT:
        return None
    prompt_style = PromptStyle.from_dict(
        {
            "": "#e6edf3",
            "prompt": "bold #58a6ff",
        }
    )
    return PromptSession(
        history=InMemoryHistory(),
        auto_suggest=AutoSuggestFromHistory(),
        completer=WordCompleter(REPL_COMMANDS, sentence=True),
        style=prompt_style,
        complete_while_typing=False,
    )


def _read_line(prompt_session: PromptSession | None, mode: DisplayMode) -> str:
    if prompt_session is not None:
        color = "#d2a8ff" if mode == "dev" else "#58a6ff"
        return prompt_session.prompt(PromptHtml(f'<prompt><b><style fg="{color}">{mode}&gt; </style></b></prompt>'))
    label = f"[{mode}]" if mode == "dev" else "user"
    return input(f"{label}> ")


def _clear_terminal() -> None:
    if HAVE_RICH:
        console.clear()
        return
    print("\033[2J\033[H", end="", flush=True)


def _repl_loop(
    client_name: str,
    sock_path: str,
    cfg: SelectorConfig,
    show_tools: bool,
    show_reasons: bool,
    show_payload: bool,
    mode: DisplayMode,
) -> int:
    with _spinner_context("connecting to mcpd"):
        apps = _list_apps(sock_path)
        tools = _list_tools(sock_path)
        session = _ensure_session(sock_path, client_name, None)
    if not apps:
        raise CliError("no apps returned by mcpd")

    _print_repl_banner(apps, tools, mode)
    _print_help(mode)
    _separator()
    last_apps_sig = _apps_signature(apps)
    last_sig = _tools_signature(tools)
    prompt_session = _build_prompt_session()

    while True:
        try:
            line = _read_line(prompt_session, mode)
        except EOFError:
            _sysline("bye")
            return 0
        except KeyboardInterrupt:
            print("", flush=True)
            continue

        user_text = line.strip()
        if not user_text:
            continue
        if user_text == "/exit":
            _sysline("session ended")
            return 0
        if user_text == "/help":
            _print_help(mode)
            continue
        if user_text == "/clear":
            _clear_terminal()
            continue
        if user_text == "/mode":
            _sysline(f"mode: {mode}")
            continue
        if user_text in {"/mode user", "/mode dev"}:
            mode = "dev" if user_text.endswith("dev") else "user"
            _okline(f"switched to {mode} mode")
            continue
        if user_text == "/apps":
            with _spinner_context("refreshing apps"):
                apps = _list_apps(sock_path)
            _print_apps(apps, mode)
            last_apps_sig = _apps_signature(apps)
            continue
        if user_text == "/tools":
            with _spinner_context("refreshing tools"):
                tools = _list_tools(sock_path)
            _print_tools(tools, mode)
            last_sig = _tools_signature(tools)
            continue
        if user_text.startswith("/"):
            _warnline(f"unknown command: {user_text!r}; type /help")
            continue

        apps = _list_apps(sock_path)
        app_sig = _apps_signature(apps)
        if app_sig != last_apps_sig:
            _sysline(f"catalog updated: apps={len(apps)}")
            if mode == "dev":
                _print_apps(apps, mode)
        last_apps_sig = app_sig

        tools = _list_tools(sock_path)
        sig = _tools_signature(tools)
        if show_tools:
            _print_tools(tools, mode)
        elif sig != last_sig:
            _sysline(f"catalog updated: tools={len(tools)}")
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
            _warnline(f"request failed rc={rc}")
        _separator()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="LLM-app CLI with REPL and single-shot mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s --repl\n"
            "  %(prog)s --once \"open github on firefox\"\n"
            "  %(prog)s --repl --mode dev --show-payload"
        ),
    )
    parser.add_argument("--once", help="single prompt to run")
    parser.add_argument("--repl", action="store_true", help="interactive loop mode")
    # Primary model flags (provider-neutral). Defaults target any OpenAI-compatible
    # endpoint; the legacy --deepseek-* aliases below are retained so existing
    # scripts continue to work.
    parser.add_argument(
        "--model-name",
        "--deepseek-model",
        dest="model_name",
        default=DEFAULT_MODEL_NAME,
        help="model id to pass in the request body (e.g. gpt-4o-mini, llama3.1, deepseek-chat)",
    )
    parser.add_argument(
        "--model-url",
        "--deepseek-url",
        dest="model_url",
        default=DEFAULT_MODEL_URL,
        help="OpenAI-compatible /chat/completions URL (overrides LLM_MODEL_URL / DEEPSEEK_API_URL)",
    )
    parser.add_argument(
        "--model-timeout-sec",
        "--deepseek-timeout-sec",
        dest="model_timeout_sec",
        type=int,
        default=20,
    )
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
        model_url=args.model_url,
        model_name=args.model_name,
        model_timeout_sec=args.model_timeout_sec,
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
        if not HAVE_RICH or not HAVE_PROMPT_TOOLKIT:
            _sysline("tip: install rich and prompt_toolkit for an enhanced CLI UI")
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
        _errline(str(exc))
        return 1
    except Exception as exc:  # noqa: BLE001
        _errline(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
