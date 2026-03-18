#!/usr/bin/env python3
"""Planner app CLI for capability-domain selection and execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from typing import Any, Dict, List

from app_logic import (
    DEFAULT_DEEPSEEK_MODEL,
    DEFAULT_DEEPSEEK_URL,
    CapabilityIntent,
    SelectorConfig,
    plan_capability_intent,
)
from rpc import mcpd_call

SOCK_PATH = "/tmp/mcpd.sock"


class CliError(Exception):
    """User-facing CLI error."""


_ENTITY_RE = re.compile(r"(?:\.\.?/)?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")


def _collect_entities(value: Any, out: List[str]) -> None:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return
        if "/" in text or "." in text:
            out.append(text)
        for match in _ENTITY_RE.findall(text):
            if "/" in match or "." in match:
                out.append(match)
        return
    if isinstance(value, dict):
        for item in value.values():
            _collect_entities(item, out)
        return
    if isinstance(value, list):
        for item in value:
            _collect_entities(item, out)


def _update_context_state(context: Dict[str, Any], user_text: str, resp: Dict[str, Any]) -> None:
    dialog_window = context.setdefault("dialog_window", [])
    if isinstance(dialog_window, list):
        dialog_window.append(user_text)
        context["dialog_window"] = dialog_window[-3:]
    if resp.get("status") != "ok":
        return
    entities: List[str] = []
    _collect_entities(resp.get("result", {}), entities)
    unique_entities: List[str] = []
    seen: set[str] = set()
    for item in entities:
        if item not in seen:
            unique_entities.append(item)
            seen.add(item)
    if unique_entities:
        context["recent_entities"] = unique_entities[-8:]
        context["last_result_refs"] = unique_entities[-4:]


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
    print(f"[planner-app] providers ({len(providers)}):", flush=True)
    for provider in providers:
        print(
            (
                f"[planner-app]   - id={provider.get('provider_id')} "
                f"name={provider.get('display_name')} actions={provider.get('action_count')}"
            ),
            flush=True,
        )
        capability_domains = provider.get("capability_domains", [])
        if isinstance(capability_domains, list) and capability_domains:
            print(
                f"[planner-app]     capability_domains={','.join(str(x) for x in capability_domains)}",
                flush=True,
            )


def _print_actions(actions: List[Dict[str, Any]]) -> None:
    print(f"[planner-app] provider actions ({len(actions)}):", flush=True)
    for action in actions:
        print(
            (
                f"[planner-app]   - id={action.get('action_id')} "
                f"name={action.get('name')} capability={action.get('capability_domain', '-')}"
            ),
            flush=True,
        )
        print(f"[planner-app]     desc={action.get('description')}", flush=True)


def _print_capabilities(capabilities: List[Dict[str, Any]]) -> None:
    print(f"[planner-app] capabilities ({len(capabilities)}):", flush=True)
    for capability in capabilities:
        print(
            (
                f"[planner-app]   - id={capability.get('capability_id')} "
                f"domain={capability.get('capability_domain')} broker={capability.get('broker_id')}"
            ),
            flush=True,
        )
        print(
            f"[planner-app]     risk={capability.get('risk_level')} providers={capability.get('provider_ids', [])}",
            flush=True,
        )


def _execute_once_with_capabilities(
    user_text: str,
    participant_id: str,
    sock_path: str,
    cfg: SelectorConfig,
    capabilities: List[Dict[str, Any]],
    *,
    context: Dict[str, Any] | None = None,
    allow_followup: bool = False,
) -> int:
    if not capabilities:
        raise CliError("no capabilities returned by mcpd")

    warnings: List[str] = []
    intent: CapabilityIntent = plan_capability_intent(
        user_text,
        capabilities,
        cfg,
        warn_cb=lambda msg: warnings.append(msg),
    )
    for msg in warnings:
        print(f"[planner-app] WARN: {msg}", flush=True)

    print(
        f"[planner-app] selected capability={intent.capability_domain} id={intent.capability_id} hash={intent.capability_hash or '-'}",
        flush=True,
    )
    print(
        f"[planner-app] capability_selector={intent.selector_source} reason={intent.selector_reason}",
        flush=True,
    )

    req_id = int(time.time_ns() & 0xFFFFFFFFFFFF)
    request: Dict[str, Any] = {
        "kind": "capability:exec",
        "req_id": req_id,
        "participant_id": participant_id,
        "capability_domain": intent.capability_domain,
        "intent_text": intent.intent_text,
    }
    hints = dict(intent.hints)
    hints["selector_source"] = intent.selector_source
    hints["selector_reason"] = intent.selector_reason
    if intent.preferred_provider_id:
        hints.setdefault("preferred_provider_id", intent.preferred_provider_id)
    if hints:
        request["hints"] = hints
    if isinstance(context, dict) and context:
        request["context"] = {
            "dialog_window": list(context.get("dialog_window", []))[-3:],
            "recent_entities": list(context.get("recent_entities", []))[-8:],
            "last_result_refs": list(context.get("last_result_refs", []))[-4:],
        }

    resp = mcpd_call(request, sock_path=sock_path, timeout_s=20)
    if isinstance(context, dict):
        _update_context_state(context, user_text, resp)
    print(f"[planner-app] req_id={req_id} status={resp.get('status')} t_ms={resp.get('t_ms')}", flush=True)
    if resp.get("status") == "ok":
        print(
            "[planner-app] broker={} provider={} action={} executor={}".format(
                resp.get("broker_id"),
                resp.get("provider_id"),
                resp.get("action_name"),
                resp.get("executor_id"),
            ),
            flush=True,
        )
        print(f"[planner-app] result={json.dumps(resp.get('result', {}), ensure_ascii=True)}", flush=True)
        print("[planner-app] done", flush=True)
        return 0
    error_code = str(resp.get("error_code", "execution_error"))
    missing_fields = resp.get("missing_fields", [])
    repairable = bool(resp.get("repairable", False))
    print(f"[planner-app] error={resp.get('error', 'unknown error')}", flush=True)
    print(
        f"[planner-app] error_code={error_code} repairable={repairable} missing_fields={missing_fields}",
        flush=True,
    )
    if allow_followup and repairable and isinstance(missing_fields, list) and missing_fields:
        missing_text = ", ".join(str(item) for item in missing_fields if str(item).strip())
        clarify_prompt = (
            "[planner-app] provide a natural-language clarification"
            + (f" (missing: {missing_text})" if missing_text else "")
            + ": "
        )
        clarification = input(clarify_prompt).strip()
        if clarification:
            followup_text = f"{user_text}\nclarification: {clarification}"
            print(f"[planner-app] retry with follow-up intent: {followup_text}", flush=True)
            return _execute_once_with_capabilities(
                followup_text,
                participant_id,
                sock_path,
                cfg,
                capabilities,
                context=context,
                allow_followup=False,
            )
    print("[planner-app] capability execution failed", flush=True)
    return 3


def _run_once(user_text: str, participant_id: str, sock_path: str, cfg: SelectorConfig) -> int:
    providers = _list_providers(sock_path)
    actions = _list_actions(sock_path)
    capabilities = _list_capabilities(sock_path)
    _print_providers(providers)
    _print_actions(actions)
    _print_capabilities(capabilities)
    return _execute_once_with_capabilities(
        user_text,
        participant_id,
        sock_path,
        cfg,
        capabilities,
        context={},
        allow_followup=False,
    )


def _print_help() -> None:
    print("[planner-app] commands:", flush=True)
    print("[planner-app]   /help  show help", flush=True)
    print("[planner-app]   /providers  force refresh and print providers", flush=True)
    print("[planner-app]   /actions force refresh and print provider actions", flush=True)
    print("[planner-app]   /caps  force refresh and print capability domains", flush=True)
    print("[planner-app]   /exit  quit", flush=True)


def _repl_loop(participant_id: str, sock_path: str, cfg: SelectorConfig, show_actions: bool) -> int:
    providers = _list_providers(sock_path)
    actions = _list_actions(sock_path)
    capabilities = _list_capabilities(sock_path)
    if not providers:
        raise CliError("no providers returned by mcpd")

    print("[planner-app] REPL mode started", flush=True)
    _print_help()
    _print_providers(providers)
    _print_actions(actions)
    _print_capabilities(capabilities)
    last_providers_sig = _providers_signature(providers)
    last_sig = _actions_signature(actions)
    context_state: Dict[str, Any] = {
        "dialog_window": [],
        "recent_entities": [],
        "last_result_refs": [],
    }

    while True:
        try:
            line = input("user> ")
        except EOFError:
            print("\n[planner-app] bye", flush=True)
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
            print("[planner-app] providers changed", flush=True)
            _print_providers(providers)
        else:
            print("[planner-app] providers unchanged", flush=True)
        last_providers_sig = providers_sig

        actions = _list_actions(sock_path)
        sig = _actions_signature(actions)
        if show_actions:
            _print_actions(actions)
        elif sig != last_sig:
            print("[planner-app] provider actions changed", flush=True)
            _print_actions(actions)
        else:
            print("[planner-app] provider actions unchanged", flush=True)
        last_sig = sig

        capabilities = _list_capabilities(sock_path)
        rc = _execute_once_with_capabilities(
            user_text,
            participant_id,
            sock_path,
            cfg,
            capabilities,
            context=context_state,
            allow_followup=True,
        )
        if rc != 0:
            print(f"[planner-app] request failed rc={rc}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", help="single prompt to run")
    parser.add_argument("--repl", action="store_true", help="interactive loop mode")
    parser.add_argument(
        "--selector",
        choices=["auto", "catalog", "deepseek"],
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
    args = parser.parse_args()

    sock_path = args.sock
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
        print(f"[planner-app] ERROR: {exc}", flush=True)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[planner-app] ERROR: {exc}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
