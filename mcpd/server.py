#!/usr/bin/env python3
"""Kernel MCP userspace daemon with capability-domain broker dispatch."""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import socket
import subprocess
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from payload_inference import build_execution_payload_with_explain

from architecture import (
    APPROVAL_STATE_APPROVED,
    APPROVAL_STATE_AUTO_APPROVED,
    APPROVAL_STATE_PENDING,
    get_runtime,
    HIGH_RISK_LEVEL,
    BrokerDispatchPlan,
    BrokerDef,
    CapabilityDomain,
    ProviderAction,
    ProviderDef,
    fill_action_payload,
    build_executor_binding,
    build_broker_catalog,
    build_capability_catalog,
    explain_capability_request,
    load_provider_manifest,
    plan_capability_execution,
    validate_capability_request,
    validate_action_payload,
    validate_executor_binding_for_capability,
)
from config_loader import load_server_defaults_config
from explain import (
    build_capability_selection_explain,
    build_dispatch_explain,
    build_payload_construction_explain,
)
from netlink_client import KernelMcpNetlinkClient

ROOT_DIR = Path(__file__).resolve().parent.parent
MANIFEST_DIRS_ENV = "MCPD_MANIFEST_DIRS"
MAX_MSG_SIZE = 16 * 1024 * 1024
MAX_DEFER_RETRIES = 50
EXECUTOR_RUNTIME_TIMEOUT_S = 30.0
LOGGER = logging.getLogger("mcpd")
HASH_RE = re.compile(r"^[0-9a-fA-F]{8}$")
MISSING_FIELD_RE = re.compile(r"missing required payload field '([^']+)'")

REQUEST_FLAG_INTERACTIVE_SESSION = 1 << 0
REQUEST_FLAG_EXPLICIT_APPROVED = 1 << 1
PARTICIPANT_TYPE_PLANNER = 1
PARTICIPANT_TYPE_BROKER = 2

_stop_event = threading.Event()
_participants_lock = threading.Lock()
_registry_lock = threading.RLock()
_registered_participants: set[str] = set()
_provider_registry: Dict[str, ProviderDef] = {}
_capability_registry: Dict[str, CapabilityDomain] = {}
_broker_registry: Dict[str, BrokerDef] = {}
_kernel_client: KernelMcpNetlinkClient | None = None

_SERVER_DEFAULT_FALLBACKS: Dict[str, Any] = {
    "manifest_dirs": (ROOT_DIR / "provider-app" / "manifests",),
    "planner_trust_level": 8,
    "broker_trust_level": 8,
    "executor_workdir_root": "/tmp/linux-mcp-executors",
    "default_socket_paths": {"mcpd": "/tmp/mcpd.sock"},
}
_SERVER_DEFAULTS = load_server_defaults_config()


def _server_default_str(env_name: str, config_value: Any, fallback_value: str) -> str:
    env_value = os.getenv(env_name, "").strip()
    if env_value:
        return env_value
    if isinstance(config_value, str) and config_value.strip():
        return config_value.strip()
    return fallback_value


def _server_default_int(env_name: str, config_value: Any, fallback_value: int) -> int:
    env_value = os.getenv(env_name, "").strip()
    if env_value:
        try:
            return int(env_value)
        except ValueError as exc:
            raise ValueError(f"{env_name} must be an integer") from exc
    if isinstance(config_value, int) and not isinstance(config_value, bool):
        return config_value
    return fallback_value


DEFAULT_MANIFEST_DIRS = tuple(
    ROOT_DIR / entry
    if not Path(entry).expanduser().is_absolute()
    else Path(entry).expanduser()
    for entry in (
        _SERVER_DEFAULTS.get("manifest_dirs")
        or _SERVER_DEFAULT_FALLBACKS["manifest_dirs"]
    )
)
SOCK_PATH = _server_default_str(
    "MCPD_SOCKET_PATH",
    _SERVER_DEFAULTS.get("default_socket_paths", {}).get("mcpd"),
    _SERVER_DEFAULT_FALLBACKS["default_socket_paths"]["mcpd"],
)
EXECUTOR_WORKDIR_ROOT = _server_default_str(
    "MCPD_EXECUTOR_WORKDIR_ROOT",
    _SERVER_DEFAULTS.get("executor_workdir_root"),
    _SERVER_DEFAULT_FALLBACKS["executor_workdir_root"],
)

PLANNER_CAPS = 0
for _caps in get_runtime().CAPABILITY_REQUIRED_CAPS.values():
    PLANNER_CAPS |= _caps
PLANNER_TRUST_LEVEL = _server_default_int(
    "MCPD_PLANNER_TRUST_LEVEL",
    _SERVER_DEFAULTS.get("planner_trust_level"),
    _SERVER_DEFAULT_FALLBACKS["planner_trust_level"],
)
PLANNER_FLAGS = 0
BROKER_TRUST_LEVEL = _server_default_int(
    "MCPD_BROKER_TRUST_LEVEL",
    _SERVER_DEFAULTS.get("broker_trust_level"),
    _SERVER_DEFAULT_FALLBACKS["broker_trust_level"],
)
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


def _emit_structured_log(event_type: str, **fields: Any) -> None:
    entry = {"event_type": event_type, "ts_ms": _now_ms()}
    entry.update(fields)
    LOGGER.info(json.dumps(entry, sort_keys=True, ensure_ascii=True))


def _ensure_registered_participant(
    participant_id: str,
    *,
    caps: int,
    trust_level: int,
    flags: int = 0,
    participant_type: int,
) -> None:
    with _participants_lock:
        if participant_id in _registered_participants:
            return

    client = _get_kernel_client()
    uid = os.getuid() if hasattr(os, "getuid") else 0
    client.register_participant(
        participant_id,
        pid=os.getpid(),
        uid=uid,
        caps=caps,
        trust_level=trust_level,
        flags=flags,
        participant_type=participant_type,
    )
    LOGGER.info(
        "participant registered via netlink: id=%s type=%d caps=%d trust=%d flags=%d",
        participant_id,
        participant_type,
        caps,
        trust_level,
        flags,
    )

    with _participants_lock:
        _registered_participants.add(participant_id)


def _sync_capability_domains(capabilities: List[CapabilityDomain]) -> None:
    client = _get_kernel_client()
    for capability in sorted(capabilities, key=lambda item: item.capability_id):
        rate_limit = capability.rate_limit
        client.register_capability(
            capability_id=capability.capability_id,
            name=capability.name,
            perm=capability.perm,
            cost=capability.cost,
            capability_hash=capability.manifest_hash,
            required_caps=capability.required_caps,
            risk_level=capability.risk_level,
            approval_mode=capability.approval_mode,
            audit_mode=capability.audit_mode,
            max_inflight_per_participant=capability.max_inflight_per_participant,
            rl_enabled=bool(rate_limit.get("enabled", False)),
            rl_burst=int(rate_limit.get("burst", 0)),
            rl_refill_tokens=int(rate_limit.get("refill_tokens", 0)),
            rl_refill_jiffies=int(rate_limit.get("refill_jiffies", 0)),
            rl_default_cost=int(rate_limit.get("default_cost", 0)),
            rl_max_inflight_per_participant=int(
                rate_limit.get("max_inflight_per_participant", 0)
            ),
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

    action_index: Dict[int, Tuple[str, ProviderAction]] = {}
    for provider in _provider_registry.values():
        for action_id, action in provider.actions.items():
            if action_id in action_index:
                other_provider_id, _other_action = action_index[action_id]
                raise ValueError(
                    f"duplicate action_id={action_id} providers={other_provider_id},{provider.provider_id}"
                )
            action_index[action_id] = (provider.provider_id, action)

    _capability_registry = build_capability_catalog(_provider_registry.values())
    _broker_registry = build_broker_catalog(_provider_registry.values(), _capability_registry)


def _configured_manifest_dirs() -> Tuple[Path, ...]:
    raw = os.getenv(MANIFEST_DIRS_ENV, "")
    dirs: List[Path] = []
    if raw.strip():
        for entry in raw.split(os.pathsep):
            entry = entry.strip()
            if not entry:
                continue
            dirs.append(Path(entry).expanduser())
    else:
        dirs.extend(DEFAULT_MANIFEST_DIRS)

    resolved: List[Path] = []
    seen: set[Path] = set()
    for path in dirs:
        try:
            resolved_path = path.resolve()
        except OSError:
            resolved_path = path
        if resolved_path in seen:
            continue
        seen.add(resolved_path)
        resolved.append(resolved_path)
    return tuple(resolved)


def _autoload_manifests_on_startup() -> None:
    manifest_paths: List[Path] = []
    for manifest_dir in _configured_manifest_dirs():
        if manifest_dir.is_file():
            manifest_paths.append(manifest_dir)
            continue
        if not manifest_dir.exists():
            LOGGER.info("manifest dir missing at startup: %s", manifest_dir)
            continue
        manifest_paths.extend(sorted(manifest_dir.glob("*.json")))

    if not manifest_paths:
        LOGGER.warning("no provider manifests discovered at startup")
        return

    loaded_providers: Dict[str, ProviderDef] = {}
    for manifest_path in manifest_paths:
        source = str(manifest_path)
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            provider = load_provider_manifest(source, raw)
        except Exception as exc:  # noqa: BLE001
            _emit_structured_log("manifest_validation_error", source=source, error=str(exc))
            raise
        if provider.provider_id in loaded_providers:
            raise ValueError(
                f"duplicate provider_id during startup autoload: {provider.provider_id}"
            )
        loaded_providers[provider.provider_id] = provider
        _emit_structured_log(
            "manifest_registered",
            source=source,
            provider_id=provider.provider_id,
            capability_domains=sorted({action.capability_domain for action in provider.actions.values()}),
            registration_mode="startup_autoload",
        )

    with _registry_lock:
        _provider_registry.clear()
        _provider_registry.update(loaded_providers)
        _rebuild_catalogs_locked()
        capabilities = list(_capability_registry.values())

    _sync_capability_domains(capabilities)
    LOGGER.info(
        "startup manifest autoload complete providers=%d capabilities=%d brokers=%d",
        len(_provider_registry),
        len(_capability_registry),
        len(_broker_registry),
    )


def _provider_to_public(provider: ProviderDef) -> Dict[str, Any]:
    actions = sorted(provider.actions.values(), key=lambda item: item.action_id)
    capability_domains = sorted({action.capability_domain for action in actions})
    return {
        "display_name": provider.display_name,
        "provider_id": provider.provider_id,
        "provider_instance_id": provider.instance_id,
        "provider_type": provider.provider_type,
        "trust_class": provider.trust_class,
        "auth_mode": provider.auth_mode,
        "broker_domain": provider.broker_domain,
        "action_count": len(actions),
        "action_ids": [action.action_id for action in actions],
        "action_names": [action.action_name for action in actions],
        "action_display_names": [action.name for action in actions],
        "capability_domains": capability_domains,
    }


def _action_to_public(provider: ProviderDef, action: ProviderAction) -> Dict[str, Any]:
    return {
        "action_id": action.action_id,
        "name": action.name,
        "display_name": provider.display_name,
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
        "intent_tags": list(action.intent_tags),
        "examples": action.examples,
        "arg_hints": dict(action.arg_hints),
        "selection_priority": action.selection_priority,
        "perm": action.perm,
        "cost": action.cost,
        "action_name": action.action_name,
    }


def _capability_to_public(capability: CapabilityDomain) -> Dict[str, Any]:
    return {
        "capability_id": capability.capability_id,
        "capability_domain": capability.name,
        "name": capability.name,
        "description": capability.description,
        "intent_tags": list(capability.intent_tags),
        "examples": capability.examples,
        "broker_id": capability.broker_id,
        "perm": capability.perm,
        "cost": capability.cost,
        "required_caps": capability.required_caps,
        "risk_level": capability.risk_level,
        "approval_mode": capability.approval_mode,
        "audit_mode": capability.audit_mode,
        "max_inflight_per_agent": capability.max_inflight_per_agent,
        "max_inflight_per_participant": capability.max_inflight_per_participant,
        "executor_policy": dict(capability.executor_policy),
        "sandbox_profile": capability.sandbox_profile,
        "allows_side_effect": capability.allows_side_effect,
        "auth_mode": capability.auth_mode,
        "capability_class": capability.capability_class,
        "rate_limit": dict(capability.rate_limit),
        "hash": capability.manifest_hash,
        "provider_ids": list(capability.provider_ids),
        "action_ids": list(capability.action_ids),
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


def _list_actions_public(provider_id: str = "") -> List[Dict[str, Any]]:
    with _registry_lock:
        actions: List[Dict[str, Any]] = []
        for provider in sorted(_provider_registry.values(), key=lambda item: item.provider_id):
            if provider_id and provider.provider_id != provider_id:
                continue
            for action in sorted(provider.actions.values(), key=lambda item: item.action_id):
                actions.append(_action_to_public(provider, action))
        return actions


def _list_capabilities_public() -> List[Dict[str, Any]]:
    with _registry_lock:
        capabilities = sorted(_capability_registry.values(), key=lambda item: item.capability_id)
        return [_capability_to_public(capability) for capability in capabilities]


def _list_brokers_public() -> List[Dict[str, Any]]:
    with _registry_lock:
        brokers = sorted(_broker_registry.values(), key=lambda item: item.broker_id)
        return [_broker_to_public(broker) for broker in brokers]


def _resolve_requested_hash(req: Dict[str, Any], default_hash: str) -> str:
    raw = req.get("capability_hash", "")
    if raw in (None, ""):
        return default_hash
    if not isinstance(raw, str) or not HASH_RE.fullmatch(raw):
        raise ValueError("capability_hash must be 8 hex chars")
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
    return flags


def _make_executor_instance_id(plan: BrokerDispatchPlan, req_id: int) -> str:
    return f"{plan.executor.executor_id}:{req_id}:{time.time_ns()}"


def _ensure_executor_workdir(path: str) -> None:
    workdir = Path(path)
    root = Path(EXECUTOR_WORKDIR_ROOT).resolve()
    resolved = workdir.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"executor working_directory must stay under {EXECUTOR_WORKDIR_ROOT}: {resolved}"
        ) from exc
    workdir.mkdir(parents=True, exist_ok=True)


def _validate_executor_contract(plan: BrokerDispatchPlan, payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise ValueError("executor payload must be structured object")
    if not plan.executor.structured_payload_only:
        raise ValueError("executor must require structured payloads")
    if plan.executor.forbidden_payload_keys:
        for forbidden_key in plan.executor.forbidden_payload_keys:
            if forbidden_key in payload:
                raise ValueError(
                    f"free-form shell field '{forbidden_key}' is not allowed for executor payload"
                )
    validate_executor_binding_for_capability(
        plan.capability,
        plan.provider,
        plan.action,
        plan.executor,
    )


def _kernel_arbitrate(
    req_id: int,
    planner_participant_id: str,
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
        decision_reply = client.capability_request(
            req_id=req_id,
            participant_id=planner_participant_id,
            capability_id=capability.capability_id,
            capability_hash=requested_hash,
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
            planner_participant_id,
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
    planner_participant_id: str,
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
    client.capability_complete(
        req_id=req_id,
        participant_id=planner_participant_id,
        capability_id=capability.capability_id,
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
        "required_hooks": list(plan.executor.required_hooks),
        "deny_on_unenforced": plan.executor.deny_on_unenforced,
        "enforce_no_new_privs": plan.executor.enforce_no_new_privs,
    }


def _call_provider_executor(
    plan: BrokerDispatchPlan,
    req_id: int,
    participant_id: str,
    payload: Dict[str, Any],
    payload_fill_mode: str,
    lease_id: int,
    approval_state: int,
    provider_instance_id: str,
    executor_instance_id: str,
) -> Dict[str, Any]:
    _ensure_executor_workdir(plan.executor.working_directory)
    req = {
        "req_id": req_id,
        "participant_id": participant_id,
        "action_id": plan.action.action_id,
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
    runtime_job = {
        "request": req,
        "provider_endpoint": plan.provider.endpoint,
        "provider_timeout_s": EXECUTOR_RUNTIME_TIMEOUT_S,
        "allowed_workdir_root": EXECUTOR_WORKDIR_ROOT,
        "executor": _executor_binding_to_public(plan),
    }
    runtime_env = {
        key: os.environ[key]
        for key in plan.executor.inherited_env_keys
        if key in os.environ
    }
    runtime_env.setdefault("PATH", os.environ.get("PATH", "/usr/bin:/bin"))
    runtime_env["PYTHONUNBUFFERED"] = "1"
    runtime_script = ROOT_DIR / "mcpd" / "executor_runtime.py"
    exec_start = time.perf_counter()
    try:
        proc = subprocess.run(
            [sys.executable, str(runtime_script)],
            input=json.dumps(runtime_job, ensure_ascii=True).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=plan.executor.working_directory,
            env=runtime_env,
            timeout=EXECUTOR_RUNTIME_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"executor timeout for provider={plan.provider.provider_id}") from exc
    except OSError as exc:
        raise ValueError(f"executor launch failed for provider={plan.provider.provider_id}") from exc

    executor_runtime_ms = int((time.perf_counter() - exec_start) * 1000)
    try:
        resp = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(
            f"executor returned invalid JSON for provider={plan.provider.provider_id}: {stderr or '<empty>'}"
        ) from exc
    if not isinstance(resp, dict):
        raise ValueError(f"executor returned non-object response ({plan.provider.provider_id})")
    status = resp.get("status", "")
    if status not in ("ok", "error"):
        raise ValueError(f"executor returned invalid status ({plan.provider.provider_id})")
    executor_timing = resp.get("executor_timing")
    if not isinstance(executor_timing, dict):
        executor_timing = {}
        resp["executor_timing"] = executor_timing
    executor_timing.setdefault("broker_spawn_wall_ms", executor_runtime_ms)
    _emit_structured_log(
        "executor_runtime",
        req_id=req_id,
        participant_id=participant_id,
        capability_domain=plan.capability.name,
        provider_id=plan.provider.provider_id,
        action_name=plan.action.action_name,
        executor_type=plan.executor.executor_type,
        sandbox_profile=plan.executor.sandbox_profile,
        lease_id=lease_id,
        executor_instance_id=executor_instance_id,
        payload_fill_mode=payload_fill_mode,
        runtime_status=status,
        runtime_timings=dict(executor_timing),
        sandbox=resp.get("sandbox", {}),
    )
    return resp


def _build_execution_payload(
    action: ProviderAction,
    intent_text: str,
    req: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    hints = req.get("hints")
    if hints is not None and not isinstance(hints, dict):
        raise ValueError("hints must be object")
    context = req.get("context")
    if context is not None and not isinstance(context, dict):
        raise ValueError("context must be object")
    return build_execution_payload_with_explain(
        action,
        intent_text,
        hints=hints if isinstance(hints, dict) else None,
        context=context if isinstance(context, dict) else None,
    )


def _execute_plan(
    req: Dict[str, Any],
    participant_id: str,
    plan: BrokerDispatchPlan,
    *,
    request_mode: str,
    audit_markers: List[str] | None = None,
    planning_timings: Dict[str, int] | None = None,
    request_explanation: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    req_id = _ensure_int("req_id", req.get("req_id", 0))
    request_start = time.perf_counter()
    requested_hash = _resolve_requested_hash(req, plan.capability.manifest_hash)
    markers = list(audit_markers or [])
    request_flags = _build_request_flags(req, request_mode)
    approval_token = str(req.get("approval_token", ""))
    provider_instance_id = plan.provider.instance_id
    executor_instance_id = _make_executor_instance_id(plan, req_id)
    timings: Dict[str, int] = dict(planning_timings or {})

    _ensure_registered_participant(
        participant_id,
        caps=PLANNER_CAPS,
        trust_level=PLANNER_TRUST_LEVEL,
        flags=PLANNER_FLAGS,
        participant_type=PARTICIPANT_TYPE_PLANNER,
    )
    _ensure_registered_participant(
        plan.broker.broker_id,
        caps=plan.capability.required_caps,
        trust_level=BROKER_TRUST_LEVEL,
        flags=BROKER_FLAGS,
        participant_type=PARTICIPANT_TYPE_BROKER,
    )

    intent_text = _ensure_non_empty_str("intent_text", req.get("intent_text", ""))
    markers.extend(plan.audit_markers)
    payload_build_start = time.perf_counter()
    payload, payload_inference_explain = _build_execution_payload(plan.action, intent_text, req)
    payload = validate_action_payload(plan.action, payload)
    _validate_executor_contract(plan, payload)
    timings["payload_construction_ms"] = int((time.perf_counter() - payload_build_start) * 1000)
    payload_construction_explain = build_payload_construction_explain(
        fill_mode=str(payload_inference_explain.get("fill_mode", "schema_arg_hints")),
        schema=plan.action.input_schema,
        arg_hints=plan.action.arg_hints,
        payload=payload,
    )
    payload_construction_explain["inference"] = dict(payload_inference_explain)
    explain_payload = build_dispatch_explain(
        capability_request=dict((request_explanation or {}).get("capability_request", {})),
        capability_selection=dict((request_explanation or {}).get("capability_selection", {})),
        action_resolution=dict(plan.explanation.get("action_resolution", {})),
        executor_binding=dict(plan.explanation.get("executor_binding", {})),
        payload_construction=payload_construction_explain,
        compatibility_path=False,
    )
    _emit_audit_event(
        "capability_request",
        req_id=req_id,
        capability_domain=plan.capability.name,
        planner_participant_id=participant_id,
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
        audit_markers=markers,
        request_mode=request_mode,
    )

    arbitration_start = time.perf_counter()
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
        planner_participant_id=participant_id,
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
    timings["kernel_arbitration_ms"] = int((time.perf_counter() - arbitration_start) * 1000)
    expiry_time = _now_ms() + lease_expires_ms if lease_expires_ms else 0
    if decision == "DENY":
        _emit_audit_event(
            "request_denied",
            req_id=req_id,
            capability_domain=plan.capability.name,
            planner_participant_id=participant_id,
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
            "explain": explain_payload,
        }

    exec_start = time.perf_counter()
    status_code = 1
    try:
        _emit_audit_event(
            "lease_issued",
            req_id=req_id,
            capability_domain=plan.capability.name,
            planner_participant_id=participant_id,
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
            audit_markers=markers,
            request_mode=request_mode,
        )
        executor_resp = _call_provider_executor(
            plan,
            req_id=req_id,
            participant_id=participant_id,
            payload=payload,
            payload_fill_mode=str(payload_inference_explain.get("fill_mode", "schema_arg_hints")),
            lease_id=lease_id,
            approval_state=approval_state,
            provider_instance_id=provider_instance_id,
            executor_instance_id=executor_instance_id,
        )
        executor_timing = executor_resp.get("executor_timing", {})
        if isinstance(executor_timing, dict):
            if "executor_startup_ms" in executor_timing:
                timings["executor_startup_ms"] = int(executor_timing["executor_startup_ms"])
            if "provider_roundtrip_ms" in executor_timing:
                timings["provider_roundtrip_ms"] = int(executor_timing["provider_roundtrip_ms"])
            if "sandbox_setup_ms" in executor_timing:
                timings["sandbox_setup_ms"] = int(executor_timing["sandbox_setup_ms"])
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
        timings["request_total_ms"] = int((time.perf_counter() - request_start) * 1000)
        if status == "ok":
            status_code = 0
        _emit_structured_log(
            "request_timing",
            req_id=req_id,
            participant_id=participant_id,
            capability_domain=plan.capability.name,
            provider_id=plan.provider.provider_id,
            action_name=plan.action.action_name,
            executor_type=plan.executor.executor_type,
            sandbox_profile=plan.executor.sandbox_profile,
            lease_id=lease_id,
            request_mode=request_mode,
            timing_metrics=dict(timings),
        )
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
            "participant_id": participant_id,
            "capability_domain": plan.capability.name,
            "capability_id": plan.capability.capability_id,
            "broker_id": plan.broker.broker_id,
            "provider_id": plan.provider.provider_id,
            "provider_instance_id": provider_instance_id,
            "provider_type": plan.provider.provider_type,
            "action_id": plan.action.action_id,
            "action_name": plan.action.action_name,
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
            "timing_metrics": dict(timings),
            "sandbox": executor_resp.get("sandbox", {}),
            "explain": explain_payload,
        }
    finally:
        exec_ms = int((time.perf_counter() - exec_start) * 1000)
        try:
            _kernel_report_complete(
                planner_participant_id=participant_id,
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
                planner_participant_id=participant_id,
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
                audit_markers=markers,
                request_mode=request_mode,
            )
        except Exception as exc:  # noqa: BLE001
            event_type = "lease_expired" if "Timer expired" in str(exc) else "duplicate_completion_attempt"
            _emit_audit_event(
                event_type,
                req_id=req_id,
                capability_domain=plan.capability.name,
                planner_participant_id=participant_id,
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
                audit_markers=markers,
                request_mode=request_mode,
            )
            LOGGER.error(
                "capability_complete report failed req_id=%d planner_participant=%s capability=%s err=%s",
                req_id,
                participant_id,
                plan.capability.name,
                exc,
            )


def _execute_capability_request(
    req: Dict[str, Any],
    *,
    participant_id: str,
    capability_name: str,
    intent_text: str,
    hints: Dict[str, Any],
    preferred_provider_id: str,
    request_mode: str,
    audit_markers: List[str] | None = None,
) -> Dict[str, Any]:
    audit_markers = list(audit_markers or [])
    planning_timings: Dict[str, int] = {}
    with _registry_lock:
        capability = _capability_registry.get(capability_name)
        if capability is None:
            raise ValueError(f"unsupported capability_domain: {capability_name}")
        capability_request_explain = explain_capability_request(
            {
                "participant_id": participant_id,
                "caps": PLANNER_CAPS,
                "trust_level": PLANNER_TRUST_LEVEL,
                "flags": PLANNER_FLAGS,
            },
            capability,
            {
                "intent_text": intent_text,
                "interactive": bool(req.get("interactive", False)),
                "explicit_approval": bool(req.get("explicit_approval", False)),
                "approval_token": str(req.get("approval_token", "") or ""),
            },
        )
        if not capability_request_explain.get("allowed", False):
            _emit_structured_log(
                "capability_policy_result",
                participant_id=participant_id,
                capability_domain=capability.name,
                required_caps=capability.required_caps,
                risk_level=capability.risk_level,
                approval_mode=capability.approval_mode,
                audit_mode=capability.audit_mode,
                max_inflight_per_agent=capability.max_inflight_per_agent,
                capability_policy_result="deny",
                reason_codes=list(capability_request_explain.get("reason_codes", [])),
                policy_explain=capability_request_explain,
                error=str(capability_request_explain.get("deny_reason", "capability policy denied")),
            )
            return {
                "req_id": _ensure_int("req_id", req.get("req_id", 0)),
                "status": "error",
                "result": {},
                "error": str(capability_request_explain.get("deny_reason", "capability policy denied")),
                "error_code": "capability_policy_denied",
                "missing_fields": [],
                "repairable": False,
                "t_ms": 0,
                "participant_id": participant_id,
                "capability_domain": capability.name,
                "capability_id": capability.capability_id,
                "broker_id": capability.broker_id,
                "request_mode": request_mode,
                "audit_markers": list(capability_request_explain.get("audit_markers", [])),
                "explain": build_dispatch_explain(
                    capability_request=capability_request_explain,
                    capability_selection=build_capability_selection_explain(
                        capability_name,
                        selector_source=str(hints.get("selector_source", "unknown")),
                        selector_reason=str(hints.get("selector_reason", "")),
                        preferred_provider_id=preferred_provider_id,
                        compatibility_path=False,
                    ),
                    action_resolution={},
                    executor_binding={},
                    payload_construction={},
                    compatibility_path=False,
                ),
            }
        try:
            gating_start = time.perf_counter()
            policy_markers = validate_capability_request(
                {
                    "participant_id": participant_id,
                    "caps": PLANNER_CAPS,
                    "trust_level": PLANNER_TRUST_LEVEL,
                    "flags": PLANNER_FLAGS,
                },
                capability,
                {
                    "intent_text": intent_text,
                    "interactive": bool(req.get("interactive", False)),
                    "explicit_approval": bool(req.get("explicit_approval", False)),
                    "approval_token": str(req.get("approval_token", "") or ""),
                },
            )
            planning_timings["capability_gating_ms"] = int((time.perf_counter() - gating_start) * 1000)
        except Exception as exc:  # noqa: BLE001
            _emit_structured_log(
                "capability_policy_result",
                participant_id=participant_id,
                capability_domain=capability.name,
                required_caps=capability.required_caps,
                risk_level=capability.risk_level,
                approval_mode=capability.approval_mode,
                audit_mode=capability.audit_mode,
                max_inflight_per_agent=capability.max_inflight_per_agent,
                capability_policy_result="deny",
                reason_codes=list(capability_request_explain.get("reason_codes", [])),
                policy_explain=capability_request_explain,
                error=str(exc),
            )
            raise
        audit_markers.extend(policy_markers)
        _emit_structured_log(
            "capability_policy_result",
            participant_id=participant_id,
            capability_domain=capability.name,
            required_caps=capability.required_caps,
            risk_level=capability.risk_level,
            approval_mode=capability.approval_mode,
            audit_mode=capability.audit_mode,
            max_inflight_per_agent=capability.max_inflight_per_agent,
            capability_policy_result="allow",
            policy_markers=list(policy_markers),
            reason_codes=list(capability_request_explain.get("reason_codes", [])),
            policy_explain=capability_request_explain,
        )
        _emit_structured_log(
            "capability_resolver",
            participant_id=participant_id,
            selector_source=str(hints.get("selector_source", "unknown")),
            selector_reason=str(hints.get("selector_reason", "")),
            capability_domain=capability.name,
        )
        allow_preferred_provider = capability.risk_level < HIGH_RISK_LEVEL
        if preferred_provider_id and not allow_preferred_provider:
            audit_markers.append("provider_preference_ignored_high_risk")
            preferred_provider_id = ""
        resolution_start = time.perf_counter()
        plan = plan_capability_execution(
            capability_name,
            providers=_provider_registry,
            capabilities=_capability_registry,
            brokers=_broker_registry,
            intent_text=intent_text,
            preferred_provider_id=preferred_provider_id,
            allow_preferred_provider=allow_preferred_provider,
        )
        planning_timings["action_resolution_ms"] = int((time.perf_counter() - resolution_start) * 1000)
        _emit_structured_log(
            "action_resolver",
            participant_id=participant_id,
            capability_domain=capability.name,
            provider_id=plan.provider.provider_id,
            provider_trust_class=plan.provider.trust_class,
            action_name=plan.action.action_name,
            risk_level=plan.action.risk_level,
            selection_priority=plan.action.selection_priority,
            resolver_markers=list(plan.audit_markers),
            resolution_explain=plan.explanation.get("action_resolution", {}),
        )
    request_explanation = {
        "capability_request": capability_request_explain,
        "capability_selection": build_capability_selection_explain(
            capability_name,
            selector_source=str(hints.get("selector_source", "unknown")),
            selector_reason=str(hints.get("selector_reason", "")),
            preferred_provider_id=preferred_provider_id,
            compatibility_path=False,
        ),
        "action_resolution": dict(plan.explanation.get("action_resolution", {})),
        "executor_binding": dict(plan.explanation.get("executor_binding", {})),
    }
    return _execute_plan(
        req,
        participant_id,
        plan,
        request_mode=request_mode,
        audit_markers=audit_markers,
        planning_timings=planning_timings,
        request_explanation=request_explanation,
    )


def _handle_capability_exec(req: Dict[str, Any]) -> Dict[str, Any]:
    participant_id = _ensure_non_empty_str("participant_id", req.get("participant_id", ""))
    if "payload" in req:
        raise ValueError("canonical capability:exec does not accept payload")
    if "planner_hints" in req or "preferred_provider_id" in req or "user_text" in req:
        raise ValueError("canonical capability:exec accepts only capability_domain, intent_text, hints")

    capability_name = _ensure_non_empty_str("capability_domain", req.get("capability_domain", ""))
    intent_text = _ensure_non_empty_str("intent_text", req.get("intent_text", ""))
    hints = req.get("hints", {})
    if hints is not None and not isinstance(hints, dict):
        raise ValueError("hints must be object")
    canonical_hints = dict(hints or {})
    if "payload_slots" in canonical_hints:
        raise ValueError("canonical capability:exec does not accept hints.payload_slots")
    preferred_provider_id = str(canonical_hints.get("preferred_provider_id", "") or "")
    return _execute_capability_request(
        req,
        participant_id=participant_id,
        capability_name=capability_name,
        intent_text=intent_text,
        hints=canonical_hints,
        preferred_provider_id=preferred_provider_id,
        request_mode="capability:exec",
    )


def _classify_error(err: str) -> Dict[str, Any]:
    missing_fields = MISSING_FIELD_RE.findall(err)
    if missing_fields:
        return {
            "error_code": "missing_required_field",
            "missing_fields": sorted(list(set(missing_fields))),
            "repairable": True,
        }
    if "payload type mismatch" in err or "payload field" in err:
        return {
            "error_code": "schema_validation_failed",
            "missing_fields": [],
            "repairable": False,
        }
    return {
        "error_code": "execution_error",
        "missing_fields": [],
        "repairable": False,
    }


def _build_error(req_id: int, err: str, t_ms: int) -> Dict[str, Any]:
    payload = {
        "req_id": req_id,
        "status": "error",
        "result": {},
        "error": err,
        "t_ms": t_ms,
    }
    payload.update(_classify_error(err))
    return payload


def _handle_connection(conn: socket.socket) -> None:
    with conn:
        while True:
            req_id = 0
            participant_id = "unknown"
            req_kind = "capability:exec"
            try:
                t0 = time.perf_counter()
                raw = _recv_frame(conn)
                req = json.loads(raw.decode("utf-8"))
                if not isinstance(req, dict):
                    raise ValueError("request must be JSON object")

                if req.get("sys") == "list_providers":
                    req_kind = "sys:list_providers"
                    resp = {"status": "ok", "providers": _list_providers_public()}
                    _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                    continue

                if req.get("sys") == "list_actions":
                    req_kind = "sys:list_actions"
                    provider_id_req = req.get("provider_id", "")
                    if provider_id_req not in ("", None) and not isinstance(provider_id_req, str):
                        raise ValueError("provider_id must be string when provided")
                    provider_id = "" if provider_id_req in ("", None) else provider_id_req
                    with _registry_lock:
                        if provider_id and provider_id not in _provider_registry:
                            raise ValueError(f"unknown provider_id: {provider_id}")
                    resp = {
                        "status": "ok",
                        "provider_id": provider_id,
                        "actions": _list_actions_public(provider_id=provider_id),
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

                req_id = _ensure_int("req_id", req.get("req_id", 0))
                participant_id = _ensure_non_empty_str("participant_id", req.get("participant_id", ""))
                req_kind = str(req.get("kind", "capability:exec"))
                if req_kind != "capability:exec":
                    raise ValueError(f"unsupported request kind: {req_kind}")
                resp = _handle_capability_exec(req)

                _send_frame(conn, json.dumps(resp, ensure_ascii=True).encode("utf-8"))
                t_ms = int((time.perf_counter() - t0) * 1000)
                LOGGER.info(
                    "req_id=%d participant=%s kind=%s status=%s capability=%s provider=%s broker=%s t_ms=%d",
                    req_id,
                    participant_id,
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
                    "req_id=%d participant=%s kind=%s status=error err=%s",
                    req_id,
                    participant_id,
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

    try:
        _autoload_manifests_on_startup()
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("failed to autoload provider manifests: %s", exc)
        return 1

    LOGGER.info("mcpd capability registry ready; provider manifest autoload complete")
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
