#!/usr/bin/env python3
"""Capability-domain broker/provider architecture for userspace MCP."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent

CAPABILITY_DOMAIN_IDS: Dict[str, int] = {
    "info.lookup": 101,
    "message.read": 102,
    "message.send": 103,
    "file.read": 104,
    "file.write": 105,
    "network.fetch.readonly": 106,
    "browser.automation": 107,
    "external.write": 108,
    "exec.run": 109,
}

CAPABILITY_REQUIRED_CAPS: Dict[str, int] = {
    "info.lookup": 1 << 0,
    "message.read": 1 << 1,
    "message.send": 1 << 2,
    "file.read": 1 << 3,
    "file.write": 1 << 4,
    "network.fetch.readonly": 1 << 5,
    "browser.automation": 1 << 6,
    "external.write": 1 << 7,
    "exec.run": 1 << 8,
}

HIGH_RISK_DOMAINS = {
    "message.send",
    "file.write",
    "browser.automation",
    "external.write",
    "exec.run",
}

HIGH_RISK_LEVEL = 7

APPROVAL_MODE_AUTO = 0
APPROVAL_MODE_TRUSTED = 1
APPROVAL_MODE_ROOT_ONLY = 2
APPROVAL_MODE_INTERACTIVE = 3
APPROVAL_MODE_EXPLICIT = 4

APPROVAL_STATE_PENDING = 0
APPROVAL_STATE_AUTO_APPROVED = 1
APPROVAL_STATE_APPROVED = 2
APPROVAL_STATE_REJECTED = 3

AUDIT_MODE_BASIC = 0
AUDIT_MODE_DETAILED = 1
AUDIT_MODE_STRICT = 2

DEFAULT_BROKERS: Dict[str, str] = {
    "info.lookup": "info-broker",
    "message.read": "message-broker",
    "message.send": "message-broker",
    "file.read": "file-broker",
    "file.write": "file-broker",
    "network.fetch.readonly": "info-broker",
    "browser.automation": "browser-broker",
    "external.write": "external-router-broker",
    "exec.run": "exec-broker",
}

BROKER_CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    "info-broker": ("info.lookup", "network.fetch.readonly"),
    "message-broker": ("message.read", "message.send"),
    "file-broker": ("file.read", "file.write"),
    "browser-broker": ("browser.automation",),
    "exec-broker": ("exec.run",),
    "external-router-broker": ("external.write",),
}

CAPABILITY_CLASSES: Dict[str, str] = {
    "info.lookup": "read",
    "message.read": "read",
    "message.send": "write",
    "file.read": "read",
    "file.write": "write",
    "network.fetch.readonly": "network-read",
    "browser.automation": "automation",
    "external.write": "external-write",
    "exec.run": "execution",
}

CAPABILITY_AUTH_MODES: Dict[str, str] = {
    "info.lookup": "local-readonly",
    "message.read": "session-auth",
    "message.send": "session-auth",
    "file.read": "local-readonly",
    "file.write": "trusted-write",
    "network.fetch.readonly": "network-readonly",
    "browser.automation": "interactive-broker",
    "external.write": "provider-auth",
    "exec.run": "trusted-exec",
}

CAPABILITY_SIDE_EFFECTS: Dict[str, bool] = {
    "info.lookup": False,
    "message.read": False,
    "message.send": True,
    "file.read": False,
    "file.write": True,
    "network.fetch.readonly": False,
    "browser.automation": True,
    "external.write": True,
    "exec.run": True,
}


@dataclass(frozen=True)
class ProviderAction:
    action_id: int
    action_name: str
    name: str
    capability_domain: str
    risk_level: int
    side_effect: bool
    auth_required: bool
    data_sensitivity: str
    executor_type: str
    validation_policy: str
    parameter_schema_id: str
    handler: str
    perm: int
    cost: int
    description: str
    input_schema: Dict[str, Any]
    examples: List[Any]


@dataclass(frozen=True)
class ProviderDef:
    provider_id: str
    instance_id: str
    provider_type: str
    trust_class: str
    auth_mode: str
    broker_domain: str
    app_name: str
    endpoint: str
    mode: str
    actions: Dict[int, ProviderAction]


@dataclass(frozen=True)
class CapabilityDomain:
    capability_id: int
    name: str
    broker_id: str
    perm: int
    cost: int
    required_caps: int
    risk_level: int
    approval_mode: int
    audit_mode: int
    max_inflight_per_agent: int
    allows_side_effect: bool
    auth_mode: str
    capability_class: str
    rate_limit: Dict[str, int | bool]
    manifest_hash: str
    provider_ids: Tuple[str, ...]
    action_ids: Tuple[int, ...]


@dataclass(frozen=True)
class BrokerDef:
    broker_id: str
    capability_domains: Tuple[str, ...]
    provider_ids: Tuple[str, ...]
    policy_controlled: bool
    runtime_identity_mode: str


@dataclass(frozen=True)
class ExecutorBinding:
    executor_id: str
    executor_type: str
    parameter_schema_id: str
    short_lived: bool
    sandbox_profile: str
    working_directory: str
    network_policy: str
    resource_limits: Dict[str, int]
    inherited_env_keys: Tuple[str, ...]
    command_schema_id: str
    structured_payload_only: bool
    sandbox_ready: bool
    runtime_identity_mode: str


@dataclass(frozen=True)
class BrokerDispatchPlan:
    capability: CapabilityDomain
    broker: BrokerDef
    provider: ProviderDef
    action: ProviderAction
    executor: ExecutorBinding


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _short_hash(obj: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(obj)).hexdigest()[:8]


def _ensure_non_empty_str(name: str, value: Any, source: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{source}: {name} must be non-empty string")
    return value


def _ensure_int(name: str, value: Any, source: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{source}: {name} must be int")
    return value


def _ensure_tool_path(name: str, value: Any, source: str) -> str:
    text = _ensure_non_empty_str(name, value, source)
    if text.startswith("/"):
        raise ValueError(f"{source}: {name} must be relative to repo root")
    if not text.startswith("tool-app/"):
        raise ValueError(f"{source}: {name} must be under tool-app/")
    return text


def _domain_risk_level(capability_domain: str) -> int:
    if capability_domain in HIGH_RISK_DOMAINS:
        return 8
    if capability_domain in {"file.read", "network.fetch.readonly"}:
        return 4
    return 2


def infer_capability_domain(action_name: str) -> str:
    if action_name in {"calc", "text_stats", "sys_info", "time_now", "hash_text", "echo"}:
        return "info.lookup"
    if action_name in {"file_preview", "file_list"}:
        return "file.read"
    if action_name in {"file_create", "file_delete", "file_copy", "file_rename"}:
        return "file.write"
    if action_name in {"cpu_burn"}:
        return "exec.run"
    if action_name in {"volume_control"}:
        return "external.write"
    return "info.lookup"


def infer_broker_id(capability_domain: str) -> str:
    return DEFAULT_BROKERS.get(capability_domain, "external-router-broker")


def infer_executor_type(capability_domain: str) -> str:
    if capability_domain == "exec.run":
        return "sandboxed-process"
    if capability_domain in {"browser.automation", "external.write"}:
        return "broker-isolated-uds"
    return "broker-uds"


def infer_validation_policy(capability_domain: str) -> str:
    if capability_domain in HIGH_RISK_DOMAINS:
        return "json_schema_strict_v1"
    return "json_schema_v1"


def infer_parameter_schema_id(action_name: str, capability_domain: str) -> str:
    return f"{capability_domain}:{action_name}:v1"


def infer_side_effect(capability_domain: str, action_name: str) -> bool:
    if capability_domain in CAPABILITY_SIDE_EFFECTS:
        return CAPABILITY_SIDE_EFFECTS[capability_domain]
    return any(
        token in action_name
        for token in ("send", "write", "delete", "create", "update", "run", "burn")
    )


def infer_auth_required(capability_domain: str) -> bool:
    return capability_domain in HIGH_RISK_DOMAINS or capability_domain in {"message.read"}


def infer_data_sensitivity(capability_domain: str) -> str:
    if capability_domain in {"message.read", "message.send"}:
        return "message-content"
    if capability_domain in {"file.read", "file.write"}:
        return "filesystem"
    if capability_domain in {"external.write", "browser.automation"}:
        return "external-account"
    if capability_domain == "exec.run":
        return "host-execution"
    return "low"


def capability_approval_mode(capability_domain: str, risk_level: int) -> int:
    if capability_domain == "exec.run":
        return APPROVAL_MODE_ROOT_ONLY
    if capability_domain in {"message.send", "external.write", "file.write"}:
        return APPROVAL_MODE_EXPLICIT
    if capability_domain == "browser.automation":
        return APPROVAL_MODE_INTERACTIVE
    if capability_domain in HIGH_RISK_DOMAINS or risk_level >= HIGH_RISK_LEVEL:
        return APPROVAL_MODE_TRUSTED
    return APPROVAL_MODE_AUTO


def capability_audit_mode(capability_domain: str, risk_level: int) -> int:
    if capability_domain == "exec.run":
        return AUDIT_MODE_STRICT
    if capability_domain in HIGH_RISK_DOMAINS or risk_level >= HIGH_RISK_LEVEL:
        return AUDIT_MODE_DETAILED
    return AUDIT_MODE_BASIC


def capability_max_inflight_per_agent(capability_domain: str, risk_level: int) -> int:
    if capability_domain == "exec.run":
        return 1
    if capability_domain in HIGH_RISK_DOMAINS or risk_level >= HIGH_RISK_LEVEL:
        return 2
    return 4


def capability_rate_limit(capability_domain: str, risk_level: int) -> Dict[str, int | bool]:
    if capability_domain == "exec.run":
        return {
            "enabled": True,
            "burst": 1,
            "refill_tokens": 1,
            "refill_jiffies": 10,
            "default_cost": 1,
            "max_inflight_per_agent": 1,
            "defer_wait_ms": 1000,
        }
    if capability_domain in HIGH_RISK_DOMAINS or risk_level >= HIGH_RISK_LEVEL:
        return {
            "enabled": True,
            "burst": 2,
            "refill_tokens": 1,
            "refill_jiffies": 5,
            "default_cost": 1,
            "max_inflight_per_agent": 2,
            "defer_wait_ms": 500,
        }
    return {
        "enabled": False,
        "burst": 0,
        "refill_tokens": 0,
        "refill_jiffies": 0,
        "default_cost": 0,
        "max_inflight_per_agent": 0,
        "defer_wait_ms": 0,
    }


def infer_provider_type(provider_id: str) -> str:
    if provider_id.endswith("-provider"):
        return provider_id[:-9]
    return "local-service"


def build_executor_binding(provider: ProviderDef, action: ProviderAction) -> ExecutorBinding:
    sandbox_profile = "local-readonly"
    network_policy = "inherit"
    resource_limits = {"cpu_ms": 1000, "memory_kb": 131072, "nofile": 64}
    if action.capability_domain in HIGH_RISK_DOMAINS:
        sandbox_profile = "sandbox-high-risk"
        network_policy = "broker-mediated"
        resource_limits = {"cpu_ms": 5000, "memory_kb": 262144, "nofile": 64}
    return ExecutorBinding(
        executor_id=f"{provider.provider_id}:{action.action_name}:exec",
        executor_type=action.executor_type,
        parameter_schema_id=action.parameter_schema_id,
        short_lived=True,
        sandbox_profile=sandbox_profile,
        working_directory=f"/tmp/linux-mcp-executors/{provider.provider_id}",
        network_policy=network_policy,
        resource_limits=resource_limits,
        inherited_env_keys=("LANG", "LC_ALL", "PATH"),
        command_schema_id=action.parameter_schema_id,
        structured_payload_only=True,
        sandbox_ready=True,
        runtime_identity_mode="broker-bound",
    )


def _looks_like_write_or_exec(*values: str) -> bool:
    text = " ".join(values).lower()
    return any(
        token in text
        for token in (
            "send",
            "write",
            "delete",
            "remove",
            "create",
            "update",
            "rename",
            "copy",
            "move",
            "issue",
            "exec",
            "run",
            "burn",
        )
    )


def validate_provider_action(provider: ProviderDef, action: ProviderAction, source: str) -> None:
    capability_class = CAPABILITY_CLASSES[action.capability_domain]
    capability_auth_mode = CAPABILITY_AUTH_MODES[action.capability_domain]
    allows_side_effect = CAPABILITY_SIDE_EFFECTS[action.capability_domain]

    if action.side_effect and not allows_side_effect:
        raise ValueError(
            f"{source}: action {action.action_name} side_effect cannot map to {action.capability_domain}"
        )
    if action.risk_level >= HIGH_RISK_LEVEL and capability_class in {"read", "network-read"}:
        raise ValueError(
            f"{source}: high-risk action {action.action_name} cannot map to read-only capability {action.capability_domain}"
        )
    if action.auth_required and capability_auth_mode in {"local-readonly", "anonymous"}:
        raise ValueError(
            f"{source}: auth-required action {action.action_name} cannot map to low-trust capability {action.capability_domain}"
        )
    if action.capability_domain == "info.lookup" and _looks_like_write_or_exec(
        action.action_name, action.handler, action.name
    ):
        raise ValueError(
            f"{source}: write/exec-like action {action.action_name} cannot map to info.lookup"
        )
    if capability_class in {"read", "network-read"} and _looks_like_write_or_exec(
        action.action_name, action.handler, action.name
    ):
        raise ValueError(
            f"{source}: write/exec-like action {action.action_name} cannot map to read-only capability {action.capability_domain}"
        )
    if provider.auth_mode in {"anonymous", "none"} and action.auth_required:
        raise ValueError(
            f"{source}: provider {provider.provider_id} auth_mode incompatible with auth-required action {action.action_name}"
        )


def load_provider_manifest(source: str, raw: Any) -> ProviderDef:
    if not isinstance(raw, dict):
        raise ValueError(f"{source}: manifest must be JSON object")

    for field in ("app_id", "app_name", "mode", "endpoint", "app_impl", "service_path", "tools"):
        if field not in raw:
            raise ValueError(f"{source}: missing field '{field}'")

    app_id = _ensure_non_empty_str("app_id", raw["app_id"], source)
    app_name = _ensure_non_empty_str("app_name", raw["app_name"], source)
    mode = _ensure_non_empty_str("mode", raw["mode"], source)
    endpoint = _ensure_non_empty_str("endpoint", raw["endpoint"], source)
    _ensure_tool_path("app_impl", raw["app_impl"], source)
    _ensure_tool_path("service_path", raw["service_path"], source)
    if mode != "uds_service":
        raise ValueError(f"{source}: mode must be 'uds_service'")
    if not endpoint.startswith("/tmp/linux-mcp-apps/"):
        raise ValueError(f"{source}: endpoint must start with /tmp/linux-mcp-apps/")

    provider_id = str(raw.get("provider_id") or app_id.replace("_app", "-provider"))
    provider_instance_id = str(
        raw.get("provider_instance_id")
        or f"{provider_id}:{_short_hash({'endpoint': endpoint, 'mode': mode})}"
    )
    provider_type = str(raw.get("provider_type") or infer_provider_type(provider_id))
    trust_class = str(raw.get("trust_class") or "local")
    auth_mode = str(raw.get("auth_mode") or "local-process")
    broker_domain = str(raw.get("broker_domain") or "mixed")

    tools = raw["tools"]
    if not isinstance(tools, list) or not tools:
        raise ValueError(f"{source}: tools must be non-empty list")

    actions: Dict[int, ProviderAction] = {}
    for tool in tools:
        if not isinstance(tool, dict):
            raise ValueError(f"{source}: each tool must be object")
        for field in (
            "tool_id",
            "name",
            "perm",
            "cost",
            "handler",
            "description",
            "input_schema",
            "examples",
        ):
            if field not in tool:
                raise ValueError(f"{source}: tool missing field '{field}'")

        action_id = _ensure_int("tool_id", tool["tool_id"], source)
        action_name = str(tool.get("action_name") or tool["handler"])
        name = _ensure_non_empty_str("name", tool["name"], source)
        capability_domain = str(tool.get("capability_domain") or infer_capability_domain(name))
        if capability_domain not in CAPABILITY_DOMAIN_IDS:
            raise ValueError(f"{source}: unknown capability_domain {capability_domain!r}")

        perm = _ensure_int("perm", tool["perm"], source)
        cost = _ensure_int("cost", tool["cost"], source)
        handler = _ensure_non_empty_str("handler", tool["handler"], source)
        description = _ensure_non_empty_str("description", tool["description"], source)
        input_schema = tool["input_schema"]
        examples = tool["examples"]
        if not isinstance(input_schema, dict):
            raise ValueError(f"{source}: input_schema must be object")
        if not isinstance(examples, list):
            raise ValueError(f"{source}: examples must be list")

        risk_level = int(tool.get("risk_level") or _domain_risk_level(capability_domain))
        side_effect = bool(
            tool.get("side_effect")
            if "side_effect" in tool
            else infer_side_effect(capability_domain, action_name)
        )
        auth_required = bool(
            tool.get("auth_required")
            if "auth_required" in tool
            else infer_auth_required(capability_domain)
        )
        data_sensitivity = str(
            tool.get("data_sensitivity") or infer_data_sensitivity(capability_domain)
        )
        executor_type = str(tool.get("executor_type") or infer_executor_type(capability_domain))
        validation_policy = str(
            tool.get("validation_policy") or infer_validation_policy(capability_domain)
        )
        parameter_schema_id = str(
            tool.get("parameter_schema_id")
            or infer_parameter_schema_id(action_name, capability_domain)
        )

        if action_id in actions:
            raise ValueError(f"{source}: duplicate tool_id={action_id}")
        actions[action_id] = ProviderAction(
            action_id=action_id,
            action_name=action_name,
            name=name,
            capability_domain=capability_domain,
            risk_level=risk_level,
            side_effect=side_effect,
            auth_required=auth_required,
            data_sensitivity=data_sensitivity,
            executor_type=executor_type,
            validation_policy=validation_policy,
            parameter_schema_id=parameter_schema_id,
            handler=handler,
            perm=perm,
            cost=cost,
            description=description,
            input_schema=input_schema,
            examples=examples,
        )

    provider = ProviderDef(
        provider_id=provider_id,
        instance_id=provider_instance_id,
        provider_type=provider_type,
        trust_class=trust_class,
        auth_mode=auth_mode,
        broker_domain=broker_domain,
        app_name=app_name,
        endpoint=endpoint,
        mode=mode,
        actions=actions,
    )
    for action in provider.actions.values():
        validate_provider_action(provider, action, source)
    return provider


def build_capability_catalog(providers: Iterable[ProviderDef]) -> Dict[str, CapabilityDomain]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for provider in providers:
        for action in provider.actions.values():
            entry = grouped.setdefault(
                action.capability_domain,
                {
                    "provider_ids": set(),
                    "action_ids": set(),
                    "perm": 0,
                    "cost": 0,
                    "risk_level": 0,
                },
            )
            entry["provider_ids"].add(provider.provider_id)
            entry["action_ids"].add(action.action_id)
            entry["perm"] = max(entry["perm"], action.perm)
            entry["cost"] = max(entry["cost"], action.cost)
            entry["risk_level"] = max(entry["risk_level"], action.risk_level)

    out: Dict[str, CapabilityDomain] = {}
    for capability_domain, entry in grouped.items():
        approval_mode = capability_approval_mode(capability_domain, int(entry["risk_level"]))
        audit_mode = capability_audit_mode(capability_domain, int(entry["risk_level"]))
        max_inflight_per_agent = capability_max_inflight_per_agent(
            capability_domain, int(entry["risk_level"])
        )
        rate_limit = capability_rate_limit(capability_domain, int(entry["risk_level"]))
        capability_hash = _short_hash(
            {
                "capability_domain": capability_domain,
                "provider_ids": sorted(entry["provider_ids"]),
                "action_ids": sorted(entry["action_ids"]),
                "risk_level": entry["risk_level"],
                "required_caps": CAPABILITY_REQUIRED_CAPS[capability_domain],
                "approval_mode": approval_mode,
                "audit_mode": audit_mode,
                "max_inflight_per_agent": max_inflight_per_agent,
                "rate_limit": rate_limit,
            }
        )
        out[capability_domain] = CapabilityDomain(
            capability_id=CAPABILITY_DOMAIN_IDS[capability_domain],
            name=capability_domain,
            broker_id=infer_broker_id(capability_domain),
            perm=int(entry["perm"]),
            cost=max(int(entry["cost"]), 1),
            required_caps=CAPABILITY_REQUIRED_CAPS[capability_domain],
            risk_level=max(int(entry["risk_level"]), _domain_risk_level(capability_domain)),
            approval_mode=approval_mode,
            audit_mode=audit_mode,
            max_inflight_per_agent=max_inflight_per_agent,
            allows_side_effect=CAPABILITY_SIDE_EFFECTS[capability_domain],
            auth_mode=CAPABILITY_AUTH_MODES[capability_domain],
            capability_class=CAPABILITY_CLASSES[capability_domain],
            rate_limit=rate_limit,
            manifest_hash=capability_hash,
            provider_ids=tuple(sorted(entry["provider_ids"])),
            action_ids=tuple(sorted(entry["action_ids"])),
        )
    return out


def build_broker_catalog(
    providers: Iterable[ProviderDef], capabilities: Dict[str, CapabilityDomain]
) -> Dict[str, BrokerDef]:
    provider_ids_by_broker: Dict[str, set[str]] = {broker_id: set() for broker_id in BROKER_CAPABILITIES}
    for provider in providers:
        for action in provider.actions.values():
            broker_id = capabilities[action.capability_domain].broker_id
            provider_ids_by_broker.setdefault(broker_id, set()).add(provider.provider_id)

    out: Dict[str, BrokerDef] = {}
    for broker_id, capability_domains in BROKER_CAPABILITIES.items():
        out[broker_id] = BrokerDef(
            broker_id=broker_id,
            capability_domains=capability_domains,
            provider_ids=tuple(sorted(provider_ids_by_broker.get(broker_id, set()))),
            policy_controlled=True,
            runtime_identity_mode="registered-agent",
        )
    return out


def score_action_for_input(action: ProviderAction, user_text: str) -> int:
    lower = user_text.lower()
    score = 0
    keywords = {
        "calc": ("calc", "calculate", "compute", "math", "算", "计算"),
        "sys_info": ("system", "memory", "disk", "uptime", "sys", "系统"),
        "time_now": ("time", "date", "clock", "几点", "时间", "日期"),
        "hash_text": ("hash", "sha", "md5", "digest", "哈希", "摘要"),
        "text_stats": ("count", "stats", "word", "line", "text", "统计"),
        "file_preview": ("preview", "read", "show", "open", "查看", "读取"),
        "file_list": ("list", "dir", "ls", "目录", "列出"),
        "file_create": ("create", "new", "write", "touch", "创建", "写入"),
        "file_delete": ("delete", "remove", "unlink", "删除"),
        "file_copy": ("copy", "duplicate", "复制", "拷贝"),
        "file_rename": ("rename", "move", "重命名", "移动"),
        "volume_control": ("volume", "mute", "unmute", "音量", "静音"),
        "cpu_burn": ("burn", "stress", "run", "execute", "压力", "执行"),
    }.get(action.name, ())
    for word in keywords:
        if word in lower:
            score += 10
    if action.capability_domain == "info.lookup":
        score += 1
    return score


def plan_capability_execution(
    capability_domain: str,
    providers: Dict[str, ProviderDef],
    capabilities: Dict[str, CapabilityDomain],
    brokers: Dict[str, BrokerDef],
    user_text: str,
    preferred_provider_id: str = "",
    allow_preferred_provider: bool = True,
) -> BrokerDispatchPlan:
    capability = capabilities.get(capability_domain)
    if capability is None:
        raise ValueError(f"unsupported capability_domain: {capability_domain}")

    broker = brokers.get(capability.broker_id)
    if broker is None:
        raise ValueError(f"missing broker for capability_domain: {capability_domain}")

    candidate_providers: List[ProviderDef] = []
    for provider_id in capability.provider_ids:
        provider = providers.get(provider_id)
        if provider is not None:
            candidate_providers.append(provider)
    if preferred_provider_id and allow_preferred_provider:
        candidate_providers = [p for p in candidate_providers if p.provider_id == preferred_provider_id]
        if not candidate_providers:
            raise ValueError(
                f"preferred provider not available for capability_domain={capability_domain}: {preferred_provider_id}"
            )
    if not candidate_providers:
        raise ValueError(f"no providers available for capability_domain: {capability_domain}")

    best: Tuple[int, ProviderDef, ProviderAction] | None = None
    for provider in candidate_providers:
        for action in provider.actions.values():
            if action.capability_domain != capability_domain:
                continue
            score = score_action_for_input(action, user_text)
            if best is None or score > best[0]:
                best = (score, provider, action)
    if best is None:
        raise ValueError(f"no provider action mapped to capability_domain: {capability_domain}")

    _score, provider, action = best
    return BrokerDispatchPlan(
        capability=capability,
        broker=broker,
        provider=provider,
        action=action,
        executor=build_executor_binding(provider, action),
    )
