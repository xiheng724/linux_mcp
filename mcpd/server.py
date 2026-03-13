#!/usr/bin/env python3
"""Kernel MCP userspace daemon with capability-domain broker dispatch."""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from architecture import (
    HIGH_RISK_LEVEL,
    APPROVAL_STATE_APPROVED,
    APPROVAL_STATE_AUTO_APPROVED,
    APPROVAL_STATE_PENDING,
    CAPABILITY_REQUIRED_CAPS,
    BrokerDispatchPlan,
    BrokerDef,
    CapabilityDomain,
    ProviderAction,
    ProviderDef,
    build_executor_binding,
    build_broker_catalog,
    build_capability_catalog,
    load_provider_manifest,
    plan_capability_execution,
)
from netlink_client import KernelMcpNetlinkClient

ROOT_DIR = Path(__file__).resolve().parent.parent
LLM_APP_DIR = ROOT_DIR / "llm-app"
if str(LLM_APP_DIR) not in sys.path:
    sys.path.insert(0, str(LLM_APP_DIR))

from app_logic import build_payload_for_tool

SOCK_PATH = "/tmp/mcpd.sock"
MAX_MSG_SIZE = 16 * 1024 * 1024
MAX_DEFER_RETRIES = 50
LOGGER = logging.getLogger("mcpd")
HASH_RE = re.compile(r"^[0-9a-fA-F]{8}$")

REQUEST_FLAG_INTERACTIVE_SESSION = 1 << 0
REQUEST_FLAG_EXPLICIT_APPROVED = 1 << 1
REQUEST_FLAG_LEGACY_PATH = 1 << 2

_stop_event = threading.Event()
_agents_lock = threading.Lock()
_registry_lock = threading.RLock()
_registered_agents: set[str] = set()
_provider_registry: Dict[str, ProviderDef] = {}
_capability_registry: Dict[str, CapabilityDomain] = {}
_broker_registry: Dict[str, BrokerDef] = {}
_action_index: Dict[int, Tuple[str, ProviderAction]] = {}
_kernel_client: KernelMcpNetlinkClient | None = None

PLANNER_CAPS = 0
for _caps in CAPABILITY_REQUIRED_CAPS.values():
    PLANNER_CAPS |= _caps
PLANNER_TRUST_LEVEL = 8
PLANNER_FLAGS = 0
BROKER_TRUST_LEVEL = 8
BROKER_FLAGS = 0


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def _recv_frame(conn: socket.socket) -> bytes:
    header = _recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_MSG_SIZE:
        raise ValueError(f"invalid frame length: {length}")
    return _recv_exact(conn, length)


def _send_frame(conn: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_MSG_SIZE:
        raise ValueError("payload too large")
    conn.sendall(struct.pack(">I", len(payload)))
    conn.sendall(payload)


def _ensure_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be int")
    return value


def _ensure_non_empty_str(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty string")
    return value


def _matches_primitive(expected: str, value: Any) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "null":
        return value is None
    return True


def _validate_payload(input_schema: Dict[str, Any], payload: Any) -> None:
    schema_type = input_schema.get("type")
    if isinstance(schema_type, str) and not _matches_primitive(schema_type, payload):
        raise ValueError(f"payload type mismatch: expected {schema_type}")

    if schema_type != "object":
        return
    if not isinstance(payload, dict):
        raise ValueError("payload must be object")

    required = input_schema.get("required", [])
    if isinstance(required, list):
        for field in required:
            if isinstance(field, str) and field not in payload:
                raise ValueError(f"payload missing required field: {field}")

    properties = input_schema.get("properties", {})
    if not isinstance(properties, dict):
        return

    additional_properties = input_schema.get("additionalProperties", True)
    for key, value in payload.items():
        prop_schema = properties.get(key)
        if prop_schema is None:
            if additional_properties is False:
                raise ValueError(f"payload has unknown field: {key}")
            continue
        if not isinstance(prop_schema, dict):
            continue
        expected_type = prop_schema.get("type")
        if isinstance(expected_type, str) and not _matches_primitive(expected_type, value):
            raise ValueError(f"field '{key}' type mismatch: expected {expected_type}")


def _get_kernel_client() -> KernelMcpNetlinkClient:
    if _kernel_client is None:
        raise RuntimeError("kernel netlink client is not initialized")
    return _kernel_client


def _now_ms() -> int:
    return int(time.time() * 1000)


def _emit_audit_event(event_type: str, **fields: Any) -> None:
    entry = {"event_type": event_type, "ts_ms": _now_ms()}
    entry.update(fields)
    LOGGER.info(json.dumps(entry, sort_keys=True, ensure_ascii=True))


def _ensure_registered_agent(agent_id: str, *, caps: int, trust_level: int, flags: int = 0) -> None:
    with _agents_lock:
        if agent_id in _registered_agents:
            return

    client = _get_kernel_client()
    uid = os.getuid() if hasattr(os, "getuid") else 0
    client.register_agent(
        agent_id,
        pid=os.getpid(),
        uid=uid,
        caps=caps,
        trust_level=trust_level,
        flags=flags,
    )
    LOGGER.info(
        "agent registered via netlink: id=%s caps=%d trust=%d flags=%d",
        agent_id,
        caps,
        trust_level,
        flags,
    )

    with _agents_lock:
        _registered_agents.add(agent_id)


def _sync_capability_domains(capabilities: List[CapabilityDomain]) -> None:
    client = _get_kernel_client()
    for capability in sorted(capabilities, key=lambda item: item.capability_id):
        rate_limit = capability.rate_limit
        client.register_tool(
            tool_id=capability.capability_id,
            name=capability.name,
            perm=capability.perm,
            cost=capability.cost,
            tool_hash=capability.manifest_hash,
            required_caps=capability.required_caps,
            risk_level=capability.risk_level,
            approval_mode=capability.approval_mode,
            audit_mode=capability.audit_mode,
            max_inflight_per_agent=capability.max_inflight_per_agent,
            rl_enabled=bool(rate_limit.get("enabled", False)),
            rl_burst=int(rate_limit.get("burst", 0)),
            rl_refill_tokens=int(rate_limit.get("refill_tokens", 0)),
            rl_refill_jiffies=int(rate_limit.get("refill_jiffies", 0)),
            rl_default_cost=int(rate_limit.get("default_cost", 0)),
            rl_max_inflight_per_agent=int(rate_limit.get("max_inflight_per_agent", 0)),
            rl_defer_wait_ms=int(rate_limit.get("defer_wait_ms", 0)),
        )
        LOGGER.info(
            "kernel capability registered id=%d domain=%s broker=%s providers=%s",
            capability.capability_id,
            capability.name,
            capability.broker_id,
            ",".join(capability.provider_ids),
        )


def _rebuild_catalogs_locked() -> None:
    global _capability_registry
    global _broker_registry
    global _action_index

    action_index: Dict[int, Tuple[str, ProviderAction]] = {}
    for provider in _provider_registry.values():
        for action_id, action in provider.actions.items():
            if action_id in action_index:
                other_provider_id, _other_action = action_index[action_id]
                raise ValueError(
                    f"duplicate action/tool_id={action_id} providers={other_provider_id},{provider.provider_id}"
                )
            action_index[action_id] = (provider.provider_id, action)

    _capability_registry = build_capability_catalog(_provider_registry.values())
    _broker_registry = build_broker_catalog(_provider_registry.values(), _capability_registry)
    _action_index = action_index


def _register_manifest(raw: Any, source: str) -> Dict[str, Any]:
    provider = load_provider_manifest(source, raw)
    with _registry_lock:
        _provider_registry[provider.provider_id] = provider
        _rebuild_catalogs_locked()
        capabilities = list(_capability_registry.values())
        provider_capabilities = sorted(
            {
                action.capability_domain
                for action in provider.actions.values()
            }
        )

    _sync_capability_domains(capabilities)
    LOGGER.info(
        "registered provider source=%s provider_id=%s actions=%s capabilities=%s",
        source,
        provider.provider_id,
        sorted(provider.actions.keys()),
        provider_capabilities,
    )
    return {
        "status": "ok",
        "provider_id": provider.provider_id,
        "app_id": provider.provider_id,
        "app_name": provider.app_name,
        "tool_count": len(provider.actions),
        "tool_ids": sorted(provider.actions.keys()),
        "capability_count": len(provider_capabilities),
        "capability_domains": provider_capabilities,
    }


def _flatten_actions_locked() -> Dict[int, Tuple[ProviderDef, ProviderAction]]:
    out: Dict[int, Tuple[ProviderDef, ProviderAction]] = {}
    for provider in _provider_registry.values():
        for action_id, action in provider.actions.items():
            out[action_id] = (provider, action)
    return out


def _provider_to_public(provider: ProviderDef) -> Dict[str, Any]:
    actions = sorted(provider.actions.values(), key=lambda item: item.action_id)
    capability_domains = sorted({action.capability_domain for action in actions})
    return {
        "app_id": provider.provider_id,
        "app_name": provider.app_name,
        "provider_id": provider.provider_id,
        "provider_instance_id": provider.instance_id,
        "provider_type": provider.provider_type,
        "trust_class": provider.trust_class,
        "auth_mode": provider.auth_mode,
        "broker_domain": provider.broker_domain,
        "tool_count": len(actions),
        "tool_ids": [action.action_id for action in actions],
        "tool_names": [action.name for action in actions],
        "capability_domains": capability_domains,
    }


def _action_to_public(provider: ProviderDef, action: ProviderAction) -> Dict[str, Any]:
    return {
        "tool_id": action.action_id,
        "name": action.name,
        "app_id": provider.provider_id,
        "app_name": provider.app_name,
        "provider_id": provider.provider_id,
        "provider_type": provider.provider_type,
        "capability_domain": action.capability_domain,
        "risk_level": action.risk_level,
        "side_effect": action.side_effect,
        "auth_required": action.auth_required,
        "data_sensitivity": action.data_sensitivity,
        "executor_type": action.executor_type,
        "validation_policy": action.validation_policy,
        "parameter_schema_id": action.parameter_schema_id,
        "description": action.description,
        "input_schema": action.input_schema,
        "examples": action.examples,
        "perm": action.perm,
        "cost": action.cost,
        "handler": action.handler,
        "action_name": action.action_name,
    }


def _capability_to_public(capability: CapabilityDomain) -> Dict[str, Any]:
    return {
        "tool_id": capability.capability_id,
        "capability_id": capability.capability_id,
        "capability_domain": capability.name,
        "name": capability.name,
        "broker_id": capability.broker_id,
        "perm": capability.perm,
        "cost": capability.cost,
        "required_caps": capability.required_caps,
        "risk_level": capability.risk_level,
        "approval_mode": capability.approval_mode,
        "audit_mode": capability.audit_mode,
        "max_inflight_per_agent": capability.max_inflight_per_agent,
        "allows_side_effect": capability.allows_side_effect,
        "auth_mode": capability.auth_mode,
        "capability_class": capability.capability_class,
        "rate_limit": dict(capability.rate_limit),
        "hash": capability.manifest_hash,
        "provider_ids": list(capability.provider_ids),
        "action_ids": list(capability.action_ids),
        "description": f"Capability domain {capability.name} mediated by {capability.broker_id}.",
    }


def _broker_to_public(broker: BrokerDef) -> Dict[str, Any]:
    return {
        "broker_id": broker.broker_id,
        "capability_domains": list(broker.capability_domains),
        "provider_ids": list(broker.provider_ids),
        "policy_controlled": broker.policy_controlled,
        "runtime_identity_mode": broker.runtime_identity_mode,
    }


def _list_providers_public() -> List[Dict[str, Any]]:
    with _registry_lock:
        providers = sorted(_provider_registry.values(), key=lambda item: item.provider_id)
        return [_provider_to_public(provider) for provider in providers]


def _list_tools_public(provider_id: str = "") -> List[Dict[str, Any]]:
    with _registry_lock:
        tools: List[Dict[str, Any]] = []
        for provider in sorted(_provider_registry.values(), key=lambda item: item.provider_id):
            if provider_id and provider.provider_id != provider_id:
                continue
            for action in sorted(provider.actions.values(), key=lambda item: item.action_id):
                tools.append(_action_to_public(provider, action))
        return tools


def _list_capabilities_public() -> List[Dict[str, Any]]:
    with _registry_lock:
        capabilities = sorted(_capability_registry.values(), key=lambda item: item.capability_id)
        return [_capability_to_public(capability) for capability in capabilities]


def _list_brokers_public() -> List[Dict[str, Any]]:
    with _registry_lock:
        brokers = sorted(_broker_registry.values(), key=lambda item: item.broker_id)
        return [_broker_to_public(broker) for broker in brokers]


def _resolve_requested_hash(req: Dict[str, Any], default_hash: str) -> str:
    raw = req.get("tool_hash", req.get("capability_hash", ""))
    if raw in (None, ""):
        return default_hash
    if not isinstance(raw, str) or not HASH_RE.fullmatch(raw):
        raise ValueError("capability/tool hash must be 8 hex chars")
    return raw.lower()


def _approval_state_name(approval_state: int) -> str:
    if approval_state == APPROVAL_STATE_AUTO_APPROVED:
        return "AUTO_APPROVED"
    if approval_state == APPROVAL_STATE_APPROVED:
        return "APPROVED"
    if approval_state == APPROVAL_STATE_PENDING:
        return "PENDING"
    return "REJECTED"


def _build_request_flags(req: Dict[str, Any], request_mode: str) -> int:
    flags = 0
    if bool(req.get("interactive", False)):
        flags |= REQUEST_FLAG_INTERACTIVE_SESSION
    if bool(req.get("explicit_approval", False)):
        flags |= REQUEST_FLAG_EXPLICIT_APPROVED
    if request_mode == "tool:exec":
        flags |= REQUEST_FLAG_LEGACY_PATH
    return flags


def _make_executor_instance_id(plan: BrokerDispatchPlan, req_id: int) -> str:
    return f"{plan.executor.executor_id}:{req_id}:{time.time_ns()}"


def _ensure_executor_workdir(path: str) -> None:
    workdir = Path(path)
    workdir.mkdir(parents=True, exist_ok=True)


def _validate_executor_contract(plan: BrokerDispatchPlan, payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise ValueError("executor payload must be structured object")
    if not plan.executor.structured_payload_only:
        raise ValueError("executor must require structured payloads")
    if plan.executor.executor_type == "sandboxed-process":
        for forbidden_key in ("command", "cmd", "shell", "shell_command"):
            if forbidden_key in payload:
                raise ValueError(
                    f"free-form shell field '{forbidden_key}' is not allowed for executor payload"
                )


def _kernel_arbitrate(
    req_id: int,
    agent_id: str,
    capability: CapabilityDomain,
    broker_id: str,
    provider_id: str,
    provider_instance_id: str,
    executor_id: str,
    executor_instance_id: str,
    requested_hash: str,
    request_flags: int,
    approval_token: str,
) -> Tuple[str, int, int, str, int, int, int, int]:
    client = _get_kernel_client()
    for attempt in range(1, MAX_DEFER_RETRIES + 1):
        decision_reply = client.tool_request(
            req_id=req_id,
            agent_id=agent_id,
            tool_id=capability.capability_id,
            tool_hash=requested_hash,
            broker_id=broker_id,
            provider_id=provider_id,
            executor_id=executor_id,
            provider_instance_id=provider_instance_id,
            executor_instance_id=executor_instance_id,
            request_flags=request_flags,
            approval_token=approval_token,
        )
        decision = decision_reply.decision
        wait_ms = decision_reply.wait_ms
        tokens_left = decision_reply.tokens_left
        reason = decision_reply.reason
        lease_id = decision_reply.lease_id
        lease_expires_ms = decision_reply.lease_expires_ms
        approval_state = decision_reply.approval_state
        LOGGER.info(
            "arb req_id=%d planner=%s capability=%s broker=%s provider=%s executor=%s executor_instance=%s attempt=%d decision=%s wait_ms=%d tokens_left=%d reason=%s approval_state=%s",
            req_id,
            agent_id,
            capability.name,
            broker_id,
            provider_id,
            executor_id,
            executor_instance_id,
            attempt,
            decision,
            wait_ms,
            tokens_left,
            reason,
            _approval_state_name(approval_state),
        )

        if decision == "ALLOW" or decision == "DENY":
            return (
                decision,
                wait_ms,
                tokens_left,
                reason,
                attempt,
                lease_id,
                lease_expires_ms,
                approval_state,
            )
        if decision != "DEFER":
            raise RuntimeError(f"unknown arbitration decision: {decision}")
        time.sleep(wait_ms / 1000.0)

    raise RuntimeError(f"defer retries exceeded max={MAX_DEFER_RETRIES}")


def _kernel_report_complete(
    agent_id: str,
    capability: CapabilityDomain,
    req_id: int,
    status_code: int,
    exec_ms: int,
    broker_id: str,
    provider_id: str,
    provider_instance_id: str,
    executor_id: str,
    executor_instance_id: str,
    lease_id: int,
    approval_state: int,
) -> None:
    client = _get_kernel_client()
    client.tool_complete(
        req_id=req_id,
        agent_id=agent_id,
        tool_id=capability.capability_id,
        status_code=status_code,
        exec_ms=exec_ms,
        broker_id=broker_id,
        provider_id=provider_id,
        provider_instance_id=provider_instance_id,
        executor_id=executor_id,
        executor_instance_id=executor_instance_id,
        lease_id=lease_id,
        approval_state=approval_state,
    )


def _executor_binding_to_public(plan: BrokerDispatchPlan) -> Dict[str, Any]:
    return {
        "executor_id": plan.executor.executor_id,
        "executor_type": plan.executor.executor_type,
        "parameter_schema_id": plan.executor.parameter_schema_id,
        "sandbox_profile": plan.executor.sandbox_profile,
        "working_directory": plan.executor.working_directory,
        "network_policy": plan.executor.network_policy,
        "resource_limits": dict(plan.executor.resource_limits),
        "inherited_env_keys": list(plan.executor.inherited_env_keys),
        "command_schema_id": plan.executor.command_schema_id,
        "structured_payload_only": plan.executor.structured_payload_only,
        "sandbox_ready": plan.executor.sandbox_ready,
        "runtime_identity_mode": plan.executor.runtime_identity_mode,
        "short_lived": plan.executor.short_lived,
    }


def _call_provider_executor(
    plan: BrokerDispatchPlan,
    req_id: int,
    agent_id: str,
    payload: Dict[str, Any],
    lease_id: int,
    approval_state: int,
    provider_instance_id: str,
    executor_instance_id: str,
) -> Dict[str, Any]:
    _ensure_executor_workdir(plan.executor.working_directory)
    req = {
        "req_id": req_id,
        "agent_id": agent_id,
        "tool_id": plan.action.action_id,
        "provider_id": plan.provider.provider_id,
        "provider_instance_id": provider_instance_id,
        "capability_domain": plan.capability.name,
        "broker_id": plan.broker.broker_id,
        "executor_id": plan.executor.executor_id,
        "executor_instance_id": executor_instance_id,
        "lease_id": lease_id,
        "approval_state": approval_state,
        "action": {
            "action_id": plan.action.action_id,
            "action_name": plan.action.action_name,
            "handler": plan.action.handler,
            "capability_domain": plan.action.capability_domain,
            "validation_policy": plan.action.validation_policy,
            "parameter_schema_id": plan.action.parameter_schema_id,
            "side_effect": plan.action.side_effect,
            "auth_required": plan.action.auth_required,
            "data_sensitivity": plan.action.data_sensitivity,
        },
        "executor": _executor_binding_to_public(plan),
        "payload": payload,
    }
    encoded = json.dumps(req, ensure_ascii=True).encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(30)
            conn.connect(plan.provider.endpoint)
            _send_frame(conn, encoded)
            raw = _recv_frame(conn)
    except (FileNotFoundError, ConnectionRefusedError, TimeoutError, OSError) as exc:
        raise ValueError(f"provider offline: {plan.provider.endpoint}") from exc

    try:
        resp = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"provider returned invalid JSON ({plan.provider.provider_id})") from exc
    if not isinstance(resp, dict):
        raise ValueError(f"provider returned non-object response ({plan.provider.provider_id})")
    status = resp.get("status", "")
    if status not in ("ok", "error"):
        raise ValueError(f"provider returned invalid status ({plan.provider.provider_id})")
    return resp


def _build_action_payload(action: ProviderAction, req: Dict[str, Any]) -> Dict[str, Any]:
    payload = req.get("payload")
    if payload is None:
        user_text = str(req.get("user_text", ""))
        payload = build_payload_for_tool(action.name, user_text)
    if not isinstance(payload, dict):
        raise ValueError("payload must be object")
    return payload


def _execute_plan(
    req: Dict[str, Any],
    agent_id: str,
    plan: BrokerDispatchPlan,
    *,
    request_mode: str,
    audit_markers: List[str] | None = None,
) -> Dict[str, Any]:
    req_id = _ensure_int("req_id", req.get("req_id", 0))
    requested_hash = _resolve_requested_hash(req, plan.capability.manifest_hash)
    markers = list(audit_markers or [])
    request_flags = _build_request_flags(req, request_mode)
    approval_token = str(req.get("approval_token", ""))
    provider_instance_id = plan.provider.instance_id
    executor_instance_id = _make_executor_instance_id(plan, req_id)

    _ensure_registered_agent(
        agent_id,
        caps=PLANNER_CAPS,
        trust_level=PLANNER_TRUST_LEVEL,
        flags=PLANNER_FLAGS,
    )
    _ensure_registered_agent(
        plan.broker.broker_id,
        caps=plan.capability.required_caps,
        trust_level=BROKER_TRUST_LEVEL,
        flags=BROKER_FLAGS,
    )

    payload = _build_action_payload(plan.action, req)
    _validate_payload(plan.action.input_schema, payload)
    _validate_executor_contract(plan, payload)
    _emit_audit_event(
        "capability_request",
        req_id=req_id,
        capability_domain=plan.capability.name,
        planner_agent_id=agent_id,
        broker_id=plan.broker.broker_id,
        broker_pid=os.getpid(),
        provider_id=plan.provider.provider_id,
        provider_instance_id=provider_instance_id,
        executor_id=plan.executor.executor_id,
        executor_instance_id=executor_instance_id,
        lease_id=0,
        approval_mode=plan.capability.approval_mode,
        approval_state=_approval_state_name(APPROVAL_STATE_PENDING),
        decision_reason="pending",
        expiry_time=0,
        legacy_path_flag=bool(request_flags & REQUEST_FLAG_LEGACY_PATH),
        audit_markers=markers,
        request_mode=request_mode,
    )

    (
        decision,
        wait_ms,
        tokens_left,
        reason,
        arb_attempts,
        lease_id,
        lease_expires_ms,
        approval_state,
    ) = _kernel_arbitrate(
        req_id=req_id,
        agent_id=agent_id,
        capability=plan.capability,
        broker_id=plan.broker.broker_id,
        provider_id=plan.provider.provider_id,
        provider_instance_id=provider_instance_id,
        executor_id=plan.executor.executor_id,
        executor_instance_id=executor_instance_id,
        requested_hash=requested_hash,
        request_flags=request_flags,
        approval_token=approval_token,
    )
    expiry_time = _now_ms() + lease_expires_ms if lease_expires_ms else 0
    if decision == "DENY":
        _emit_audit_event(
            "request_denied",
            req_id=req_id,
            capability_domain=plan.capability.name,
            planner_agent_id=agent_id,
            broker_id=plan.broker.broker_id,
            broker_pid=os.getpid(),
            provider_id=plan.provider.provider_id,
            provider_instance_id=provider_instance_id,
            executor_id=plan.executor.executor_id,
            executor_instance_id=executor_instance_id,
            lease_id=lease_id,
            approval_mode=plan.capability.approval_mode,
            approval_state=_approval_state_name(approval_state),
            decision_reason=reason,
            expiry_time=expiry_time,
            legacy_path_flag=bool(request_flags & REQUEST_FLAG_LEGACY_PATH),
            audit_markers=markers,
            request_mode=request_mode,
        )
        return {
            "req_id": req_id,
            "status": "error",
            "result": {},
            "error": f"kernel arbitration denied: {reason}",
            "t_ms": 0,
            "decision": decision,
            "wait_ms": wait_ms,
            "tokens_left": tokens_left,
            "reason": reason,
            "approval_state": _approval_state_name(approval_state),
            "arb_attempts": arb_attempts,
            "audit_markers": markers,
            "capability_domain": plan.capability.name,
            "capability_id": plan.capability.capability_id,
            "broker_id": plan.broker.broker_id,
            "provider_id": plan.provider.provider_id,
            "provider_instance_id": provider_instance_id,
            "action_name": plan.action.action_name,
            "executor_id": plan.executor.executor_id,
            "executor_instance_id": executor_instance_id,
            "request_mode": request_mode,
        }

    exec_start = time.perf_counter()
    status_code = 1
    try:
        _emit_audit_event(
            "lease_issued",
            req_id=req_id,
            capability_domain=plan.capability.name,
            planner_agent_id=agent_id,
            broker_id=plan.broker.broker_id,
            broker_pid=os.getpid(),
            provider_id=plan.provider.provider_id,
            provider_instance_id=provider_instance_id,
            executor_id=plan.executor.executor_id,
            executor_instance_id=executor_instance_id,
            lease_id=lease_id,
            approval_mode=plan.capability.approval_mode,
            approval_state=_approval_state_name(approval_state),
            decision_reason=reason,
            expiry_time=expiry_time,
            legacy_path_flag=bool(request_flags & REQUEST_FLAG_LEGACY_PATH),
            audit_markers=markers,
            request_mode=request_mode,
        )
        executor_resp = _call_provider_executor(
            plan,
            req_id=req_id,
            agent_id=agent_id,
            payload=payload,
            lease_id=lease_id,
            approval_state=approval_state,
            provider_instance_id=provider_instance_id,
            executor_instance_id=executor_instance_id,
        )
        status = executor_resp.get("status")
        result = executor_resp.get("result", {})
        err = executor_resp.get("error", "")
        exec_t_ms = executor_resp.get("t_ms")
        if not isinstance(result, dict):
            result = {"value": result}
        if not isinstance(err, str):
            err = str(err)
        if not isinstance(exec_t_ms, int) or isinstance(exec_t_ms, bool) or exec_t_ms < 0:
            exec_t_ms = int((time.perf_counter() - exec_start) * 1000)
        if status == "ok":
            status_code = 0
        return {
            "req_id": req_id,
            "status": status,
            "result": result if status == "ok" else {},
            "error": "" if status == "ok" else err,
            "t_ms": exec_t_ms,
            "decision": decision,
            "wait_ms": wait_ms,
            "tokens_left": tokens_left,
            "reason": reason,
            "approval_state": _approval_state_name(approval_state),
            "arb_attempts": arb_attempts,
            "lease_id": lease_id,
            "lease_expires_ms": lease_expires_ms,
            "audit_markers": markers,
            "capability_domain": plan.capability.name,
            "capability_id": plan.capability.capability_id,
            "broker_id": plan.broker.broker_id,
            "provider_id": plan.provider.provider_id,
            "provider_instance_id": provider_instance_id,
            "provider_type": plan.provider.provider_type,
            "action_name": plan.action.action_name,
            "tool_name": plan.action.name,
            "executor_id": plan.executor.executor_id,
            "executor_instance_id": executor_instance_id,
            "executor_type": plan.executor.executor_type,
            "sandbox_profile": plan.executor.sandbox_profile,
            "working_directory": plan.executor.working_directory,
            "network_policy": plan.executor.network_policy,
            "resource_limits": dict(plan.executor.resource_limits),
            "parameter_schema_id": plan.executor.parameter_schema_id,
            "runtime_identity_mode": plan.executor.runtime_identity_mode,
            "request_mode": request_mode,
        }
    finally:
        exec_ms = int((time.perf_counter() - exec_start) * 1000)
        try:
            _kernel_report_complete(
                agent_id=agent_id,
                capability=plan.capability,
                req_id=req_id,
                status_code=status_code,
                exec_ms=exec_ms,
                broker_id=plan.broker.broker_id,
                provider_id=plan.provider.provider_id,
                provider_instance_id=provider_instance_id,
                executor_id=plan.executor.executor_id,
                executor_instance_id=executor_instance_id,
                lease_id=lease_id,
                approval_state=approval_state,
            )
            _emit_audit_event(
                "execution_completed",
                req_id=req_id,
                capability_domain=plan.capability.name,
                planner_agent_id=agent_id,
                broker_id=plan.broker.broker_id,
                broker_pid=os.getpid(),
                provider_id=plan.provider.provider_id,
                provider_instance_id=provider_instance_id,
                executor_id=plan.executor.executor_id,
                executor_instance_id=executor_instance_id,
                lease_id=lease_id,
                approval_mode=plan.capability.approval_mode,
                approval_state=_approval_state_name(approval_state),
                decision_reason="ok" if status_code == 0 else "error",
                expiry_time=expiry_time,
                legacy_path_flag=bool(request_flags & REQUEST_FLAG_LEGACY_PATH),
                audit_markers=markers,
                request_mode=request_mode,
            )
        except Exception as exc:  # noqa: BLE001
            event_type = "lease_expired" if "Timer expired" in str(exc) else "duplicate_completion_attempt"
            _emit_audit_event(
                event_type,
                req_id=req_id,
                capability_domain=plan.capability.name,
                planner_agent_id=agent_id,
                broker_id=plan.broker.broker_id,
                broker_pid=os.getpid(),
                provider_id=plan.provider.provider_id,
                provider_instance_id=provider_instance_id,
                executor_id=plan.executor.executor_id,
                executor_instance_id=executor_instance_id,
                lease_id=lease_id,
                approval_mode=plan.capability.approval_mode,
                approval_state=_approval_state_name(approval_state),
                decision_reason=str(exc),
                expiry_time=expiry_time,
                legacy_path_flag=bool(request_flags & REQUEST_FLAG_LEGACY_PATH),
                audit_markers=markers,
                request_mode=request_mode,
            )
            LOGGER.error(
                "tool_complete report failed req_id=%d planner=%s capability=%s err=%s",
                req_id,
                agent_id,
                plan.capability.name,
                exc,
            )


def _handle_capability_exec(req: Dict[str, Any]) -> Dict[str, Any]:
    req_id = _ensure_int("req_id", req.get("req_id", 0))
    agent_id = _ensure_non_empty_str("agent_id", req.get("agent_id", ""))
    user_text = _ensure_non_empty_str("user_text", req.get("user_text", ""))
    preferred_provider_id = str(req.get("preferred_provider_id", req.get("provider_id", "")))
    audit_markers: List[str] = []
    if preferred_provider_id and "preferred_provider_id" not in req and "provider_id" in req:
        audit_markers.append("deprecated_provider_id_alias")

    capability_name = req.get("capability_domain")
    if capability_name in ("", None):
        capability_id = _ensure_int("capability_id", req.get("capability_id", 0))
        with _registry_lock:
            matched = None
            for capability in _capability_registry.values():
                if capability.capability_id == capability_id:
                    matched = capability.name
                    break
        if matched is None:
            raise ValueError(f"unknown capability_id: {capability_id}")
        capability_name = matched
    capability_name = _ensure_non_empty_str("capability_domain", capability_name)

    with _registry_lock:
        capability = _capability_registry.get(capability_name)
        if capability is None:
            raise ValueError(f"unsupported capability_domain: {capability_name}")
        allow_preferred_provider = capability.risk_level < HIGH_RISK_LEVEL
        if preferred_provider_id and not allow_preferred_provider:
            audit_markers.append("provider_preference_ignored_high_risk")
            preferred_provider_id = ""
        plan = plan_capability_execution(
            capability_name,
            providers=_provider_registry,
            capabilities=_capability_registry,
            brokers=_broker_registry,
            user_text=user_text,
            preferred_provider_id=preferred_provider_id,
            allow_preferred_provider=allow_preferred_provider,
        )
    return _execute_plan(
        req,
        agent_id,
        plan,
        request_mode="capability:exec",
        audit_markers=audit_markers,
    )


def _handle_legacy_tool_exec(req: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = _ensure_non_empty_str("agent_id", req.get("agent_id", ""))
    provider_id = _ensure_non_empty_str("app_id", req.get("app_id", ""))
    tool_id = _ensure_int("tool_id", req.get("tool_id", 0))
    audit_markers = ["compat_tool_exec", "deprecated_legacy_path"]
    _emit_audit_event(
        "compatibility_path_usage",
        req_id=int(req.get("req_id", 0)),
        capability_domain="",
        planner_agent_id=agent_id,
        broker_id="",
        broker_pid=os.getpid(),
        provider_id=provider_id,
        executor_instance_id="",
        lease_id=0,
        approval_mode=0,
        approval_state="PENDING",
        decision_reason="legacy_path",
        expiry_time=0,
        legacy_path_flag=True,
        audit_markers=audit_markers,
        request_mode="tool:exec",
    )
    LOGGER.warning(
        "legacy tool:exec request agent=%s app_id=%s tool_id=%d",
        agent_id,
        provider_id,
        tool_id,
    )
    with _registry_lock:
        provider = _provider_registry.get(provider_id)
        if provider is None:
            raise ValueError(f"unknown provider/app_id: {provider_id}")
        action = provider.actions.get(tool_id)
        if action is None:
            raise ValueError(f"tool_id={tool_id} does not belong to app_id={provider_id}")
        capability = _capability_registry.get(action.capability_domain)
        if capability is None:
            raise ValueError(f"missing capability_domain mapping: {action.capability_domain}")
        broker = _broker_registry.get(capability.broker_id)
        if broker is None:
            raise ValueError(f"missing broker mapping: {capability.broker_id}")
        if capability.risk_level >= HIGH_RISK_LEVEL and not bool(
            req.get("allow_legacy_high_risk", False)
        ):
            raise ValueError(
                f"legacy tool:exec blocked for high-risk capability_domain={capability.name}"
            )
        if capability.risk_level >= HIGH_RISK_LEVEL:
            audit_markers.append("legacy_high_risk_override")
        plan = BrokerDispatchPlan(
            capability=capability,
            broker=broker,
            provider=provider,
            action=action,
            executor=build_executor_binding(provider, action),
        )
    return _execute_plan(
        req,
        agent_id,
        plan,
        request_mode="tool:exec",
        audit_markers=audit_markers,
    )


def _build_error(req_id: int, err: str, t_ms: int) -> Dict[str, Any]:
    return {
        "req_id": req_id,
        "status": "error",
        "result": {},
        "error": err,
        "t_ms": t_ms,
    }


def _handle_connection(conn: socket.socket) -> None:
    with conn:
        while True:
            req_id = 0
            agent_id = "unknown"
            req_kind = "capability:exec"
            try:
                t0 = time.perf_counter()
                raw = _recv_frame(conn)
                req = json.loads(raw.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("request must be JSON object")

                if req.get("sys") == "list_apps" or req.get("sys") == "list_providers":
                    req_kind = "sys:list_providers"
                    resp = {"status": "ok", "apps": _list_providers_public(), "providers": _list_providers_public()}
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                    continue

                if req.get("sys") == "list_tools":
                    req_kind = "sys:list_tools"
                    app_id_req = req.get("app_id", "")
                    if app_id_req not in ("", None) and not isinstance(app_id_req, str):
                        raise ValueError("app_id must be string when provided")
                    provider_id = "" if app_id_req in ("", None) else app_id_req
                    with _registry_lock:
                        if provider_id and provider_id not in _provider_registry:
                            raise ValueError(f"unknown app_id/provider_id: {provider_id}")
                    resp = {
                        "status": "ok",
                        "app_id": provider_id,
                        "tools": _list_tools_public(provider_id=provider_id),
                    }
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                    continue

                if req.get("sys") == "list_capabilities":
                    req_kind = "sys:list_capabilities"
                    resp = {"status": "ok", "capabilities": _list_capabilities_public()}
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                    continue

                if req.get("sys") == "list_brokers":
                    req_kind = "sys:list_brokers"
                    resp = {"status": "ok", "brokers": _list_brokers_public()}
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                    continue

                if req.get("sys") == "register_manifest":
                    req_kind = "sys:register_manifest"
                    resp = _register_manifest(req.get("manifest"), "rpc:register_manifest")
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                    continue

                req_id = _ensure_int("req_id", req.get("req_id", 0))
                agent_id = _ensure_non_empty_str("agent_id", req.get("agent_id", ""))
                req_kind = str(req.get("kind", "capability:exec"))
                if req_kind == "capability:exec":
                    resp = _handle_capability_exec(req)
                elif req_kind == "tool:exec":
                    resp = _handle_legacy_tool_exec(req)
                else:
                    raise ValueError(f"unsupported request kind: {req_kind}")

                _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                t_ms = int((time.perf_counter() - t0) * 1000)
                LOGGER.info(
                    "req_id=%d agent=%s kind=%s status=%s capability=%s provider=%s broker=%s t_ms=%d",
                    req_id,
                    agent_id,
                    req_kind,
                    resp.get("status"),
                    resp.get("capability_domain", "-"),
                    resp.get("provider_id", "-"),
                    resp.get("broker_id", "-"),
                    t_ms,
                )
            except ConnectionError:
                return
            except Exception as exc:  # noqa: BLE001
                t_ms = 0
                if "t0" in locals():
                    t_ms = int((time.perf_counter() - t0) * 1000)
                if req_kind.startswith("sys:"):
                    resp = {"status": "error", "error": str(exc)}
                else:
                    resp = _build_error(req_id=req_id, err=str(exc), t_ms=t_ms)
                try:
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                except Exception:  # noqa: BLE001
                    return
                LOGGER.error(
                    "req_id=%d agent=%s kind=%s status=error err=%s",
                    req_id,
                    agent_id,
                    req_kind,
                    exc,
                )


def _accept_loop(server: socket.socket) -> None:
    while not _stop_event.is_set():
        try:
            conn, _addr = server.accept()
        except OSError:
            if _stop_event.is_set():
                return
            continue
        th = threading.Thread(target=_handle_connection, args=(conn,), daemon=True)
        th.start()


def _cleanup_socket(path: str) -> None:
    p = Path(path)
    if p.exists():
        p.unlink()


def _signal_handler(_sig: int, _frame: Any) -> None:
    _stop_event.set()


def main() -> int:
    global _kernel_client

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        _kernel_client = KernelMcpNetlinkClient()
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("failed to initialize kernel netlink client: %s", exc)
        return 1

    LOGGER.info("mcpd capability registry ready; waiting for provider manifest registration")
    _cleanup_socket(SOCK_PATH)

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(SOCK_PATH)
            os.chmod(SOCK_PATH, 0o666)
            server.listen(128)
            server.settimeout(0.5)
            LOGGER.info("mcpd listening on %s", SOCK_PATH)

            accept_thread = threading.Thread(target=_accept_loop, args=(server,), daemon=True)
            accept_thread.start()

            while not _stop_event.is_set():
                time.sleep(0.2)
        return 0
    finally:
        _cleanup_socket(SOCK_PATH)
        if _kernel_client is not None:
            _kernel_client.close()
            _kernel_client = None
        LOGGER.info("mcpd stopped")


if __name__ == "__main__":
    raise SystemExit(main())
