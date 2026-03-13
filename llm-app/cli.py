#!/usr/bin/env python3
"""LLM-app CLI for capability-domain selection and execution."""

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
    select_capability_for_input,
)
from rpc import mcpd_call

SOCK_PATH = "/tmp/mcpd.sock"


class CliError(Exception):
    """User-facing CLI error."""


def _actions_signature(actions: List[Dict[str, Any]]) -> str:
    encoded = json.dumps(actions, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()[:12]


def _providers_signature(providers: List[Dict[str, Any]]) -> str:
    encoded = json.dumps(providers, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()[:12]


def _list_providers(sock_path: str) -> List[Dict[str, Any]]:
    resp = mcpd_call({"sys": "list_providers"}, sock_path=sock_path, timeout_s=5)
    if resp.get("status") != "ok":
        raise CliError(resp.get("error", "list_providers failed"))
    providers = resp.get("providers", [])
    if not isinstance(providers, list):
        raise CliError("list_providers response missing providers list")
    typed_providers: List[Dict[str, Any]] = []
    for provider in providers:
        if isinstance(provider, dict):
            typed_providers.append(provider)
    return typed_providers


def _list_actions(sock_path: str, provider_id: str = "") -> List[Dict[str, Any]]:
    req: Dict[str, Any] = {"sys": "list_actions"}
    if provider_id:
        req["provider_id"] = provider_id
    resp = mcpd_call(req, sock_path=sock_path, timeout_s=5)
    if resp.get("status") != "ok":
        raise CliError(resp.get("error", "list_actions failed"))
    actions = resp.get("actions", [])
    if not isinstance(actions, list):
        raise CliError("list_actions response missing actions list")
    typed_actions: List[Dict[str, Any]] = []
    for action in actions:
        if isinstance(action, dict):
            typed_actions.append(action)
    return typed_actions


def _list_capabilities(sock_path: str) -> List[Dict[str, Any]]:
    resp = mcpd_call({"sys": "list_capabilities"}, sock_path=sock_path, timeout_s=5)
    if resp.get("status") != "ok":
        raise CliError(resp.get("error", "list_capabilities failed"))
    capabilities = resp.get("capabilities", [])
    if not isinstance(capabilities, list):
        raise CliError("list_capabilities response missing capabilities list")
    typed_capabilities: List[Dict[str, Any]] = []
    for capability in capabilities:
        if isinstance(capability, dict):
            typed_capabilities.append(capability)
    return typed_capabilities


def _print_providers(providers: List[Dict[str, Any]]) -> None:
    print(f"[llm-app] providers ({len(providers)}):", flush=True)
    for provider in providers:
        print(
            (
                f"[llm-app]   - id={provider.get('provider_id')} "
                f"name={provider.get('app_name')} actions={provider.get('action_count')}"
            ),
            flush=True,
        )
        capability_domains = provider.get("capability_domains", [])
        if isinstance(capability_domains, list) and capability_domains:
            print(
                f"[llm-app]     capability_domains={','.join(str(x) for x in capability_domains)}",
                flush=True,
            )


def _print_actions(actions: List[Dict[str, Any]]) -> None:
    print(f"[llm-app] provider actions ({len(actions)}):", flush=True)
    for action in actions:
        print(
            (
                f"[llm-app]   - id={action.get('action_id')} "
                f"name={action.get('name')} capability={action.get('capability_domain', '-')}"
            ),
            flush=True,
        )
        print(f"[llm-app]     desc={action.get('description')}", flush=True)


def _print_capabilities(capabilities: List[Dict[str, Any]]) -> None:
    print(f"[llm-app] capabilities ({len(capabilities)}):", flush=True)
    for capability in capabilities:
        print(
            (
                f"[llm-app]   - id={capability.get('capability_id')} "
                f"domain={capability.get('capability_domain')} broker={capability.get('broker_id')}"
            ),
            flush=True,
        )
        print(
            f"[llm-app]     risk={capability.get('risk_level')} providers={capability.get('provider_ids', [])}",
            flush=True,
        )


def _execute_once_with_capabilities(
    user_text: str,
    participant_id: str,
    sock_path: str,
    cfg: SelectorConfig,
    capabilities: List[Dict[str, Any]],
) -> int:
    if not capabilities:
        raise CliError("no capabilities returned by mcpd")

    warnings: List[str] = []
    selected_capability, selector_source, selector_reason = select_capability_for_input(
        user_text,
        capabilities,
        cfg,
        warn_cb=lambda msg: warnings.append(msg),
    )
    for msg in warnings:
        print(f"[llm-app] WARN: {msg}", flush=True)

    capability_domain = str(selected_capability.get("capability_domain", ""))
    capability_id = int(selected_capability.get("capability_id", 0))
    capability_hash_raw = selected_capability.get("hash")
    capability_hash = (
        capability_hash_raw if isinstance(capability_hash_raw, str) and capability_hash_raw else ""
    )

    print(
        f"[llm-app] selected capability={capability_domain} id={capability_id} hash={capability_hash or '-'}",
        flush=True,
    )
    print(
        f"[llm-app] capability_selector={selector_source} reason={selector_reason}",
        flush=True,
    )

    req_id = int(time.time_ns() & 0xFFFFFFFFFFFF)
    resp = mcpd_call(
        {
            "kind": "capability:exec",
            "req_id": req_id,
            "participant_id": participant_id,
            "capability_domain": capability_domain,
            "capability_id": capability_id,
            "capability_hash": capability_hash,
            "user_text": user_text,
        },
        sock_path=sock_path,
        timeout_s=20,
    )
    print(f"[llm-app] req_id={req_id} status={resp.get('status')} t_ms={resp.get('t_ms')}", flush=True)
    if resp.get("status") == "ok":
        print(
            "[llm-app] broker={} provider={} action={} executor={}".format(
                resp.get("broker_id"),
                resp.get("provider_id"),
                resp.get("action_name"),
                resp.get("executor_id"),
            ),
            flush=True,
        )
        print(f"[llm-app] result={json.dumps(resp.get('result', {}), ensure_ascii=True)}", flush=True)
        print("[llm-app] done", flush=True)
        return 0
    print(f"[llm-app] error={resp.get('error', 'unknown error')}", flush=True)
    print("[llm-app] capability execution failed", flush=True)
    return 3


def _run_once(user_text: str, participant_id: str, sock_path: str, cfg: SelectorConfig) -> int:
    providers = _list_providers(sock_path)
    actions = _list_actions(sock_path)
    capabilities = _list_capabilities(sock_path)
    _print_providers(providers)
    _print_actions(actions)
    _print_capabilities(capabilities)
    return _execute_once_with_capabilities(user_text, participant_id, sock_path, cfg, capabilities)


def _print_help() -> None:
    print("[llm-app] commands:", flush=True)
    print("[llm-app]   /help  show help", flush=True)
    print("[llm-app]   /providers  force refresh and print providers", flush=True)
    print("[llm-app]   /actions force refresh and print provider actions", flush=True)
    print("[llm-app]   /caps  force refresh and print capability domains", flush=True)
    print("[llm-app]   /exit  quit", flush=True)


def _repl_loop(participant_id: str, sock_path: str, cfg: SelectorConfig, show_actions: bool) -> int:
    providers = _list_providers(sock_path)
    actions = _list_actions(sock_path)
    capabilities = _list_capabilities(sock_path)
    if not providers:
        raise CliError("no providers returned by mcpd")

    print("[llm-app] REPL mode started", flush=True)
    _print_help()
    _print_providers(providers)
    _print_actions(actions)
    _print_capabilities(capabilities)
    last_providers_sig = _providers_signature(providers)
    last_sig = _actions_signature(actions)

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
        if user_text == "/providers":
            providers = _list_providers(sock_path)
            _print_providers(providers)
            last_providers_sig = _providers_signature(providers)
            continue
        if user_text == "/actions":
            actions = _list_actions(sock_path)
            _print_actions(actions)
            last_sig = _actions_signature(actions)
            continue
        if user_text == "/caps":
            capabilities = _list_capabilities(sock_path)
            _print_capabilities(capabilities)
            continue

        providers = _list_providers(sock_path)
        providers_sig = _providers_signature(providers)
        if providers_sig != last_providers_sig:
            print("[llm-app] providers changed", flush=True)
            _print_providers(providers)
        else:
            print("[llm-app] providers unchanged", flush=True)
        last_providers_sig = providers_sig

        actions = _list_actions(sock_path)
        sig = _actions_signature(actions)
        if show_actions:
            _print_actions(actions)
        elif sig != last_sig:
            print("[llm-app] provider actions changed", flush=True)
            _print_actions(actions)
        else:
            print("[llm-app] provider actions unchanged", flush=True)
        last_sig = sig

        capabilities = _list_capabilities(sock_path)
        rc = _execute_once_with_capabilities(user_text, participant_id, sock_path, cfg, capabilities)
        if rc != 0:
            print(f"[llm-app] request failed rc={rc}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", help="single prompt to run")
    parser.add_argument("--repl", action="store_true", help="interactive loop mode")
    parser.add_argument(
        "--selector",
        choices=["auto", "heuristic", "deepseek"],
        default="deepseek",
        help="capability selection strategy",
    )
    parser.add_argument("--deepseek-model", default=DEFAULT_DEEPSEEK_MODEL)
    parser.add_argument(
        "--deepseek-url",
        default=os.getenv("DEEPSEEK_API_URL", DEFAULT_DEEPSEEK_URL),
    )
    parser.add_argument("--deepseek-timeout-sec", type=int, default=20)
    parser.add_argument("--participant-id", default="planner-main", help="planner participant id")
    parser.add_argument("--sock", default=SOCK_PATH, help="mcpd unix socket path")
    parser.add_argument("--show-actions", action="store_true", help="always print full action list in REPL")
    parser.add_argument("--socket", dest="socket_legacy", help=argparse.SUPPRESS)
    args = parser.parse_args()

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
            return _run_once(args.once, args.participant_id, sock_path, cfg)
        if args.repl:
            return _repl_loop(args.participant_id, sock_path, cfg, args.show_actions)
        if not sys.stdin.isatty():
            raise CliError("no --once/--repl provided and stdin is not interactive")
        return _repl_loop(args.participant_id, sock_path, cfg, args.show_actions)
    except CliError as exc:
        print(f"[llm-app] ERROR: {exc}", flush=True)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[llm-app] ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
