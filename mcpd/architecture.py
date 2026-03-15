#!/usr/bin/env python3
"""Canonical manifest-driven broker architecture for userspace MCP."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
LOGGER = logging.getLogger(__name__)

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

READ_ONLY_CAPABILITY_CLASSES = {"read", "network-read"}
LOW_TRUST_CAPABILITY_AUTH_MODES = {"anonymous", "local-readonly", "network-readonly"}
LOW_TRUST_PROVIDER_AUTH_MODES = {"anonymous", "none"}
STRUCTURED_EXECUTOR_TYPES = {"broker-uds", "broker-isolated-uds", "sandboxed-process"}
HIGH_RISK_EXECUTOR_TYPES = {"broker-isolated-uds", "sandboxed-process"}
TRUST_CLASS_RANKS: Dict[str, int] = {
    "anonymous": 0,
    "remote": 1,
    "provider": 1,
    "local": 2,
    "trusted": 3,
    "system": 4,
}


def _log_structured(level: int, event_type: str, **fields: Any) -> None:
    payload = {"event_type": event_type}
    payload.update(fields)
    LOGGER.log(level, json.dumps(payload, sort_keys=True, ensure_ascii=True))


# ---------------------------------------------------------------------------
# capability domain registry metadata

CAPABILITY_DOMAIN_REGISTRY: Dict[str, Dict[str, Any]] = {
    "info.lookup": {
        "capability_id": 101,
        "required_caps": 1 << 0,
        "broker_id": "info-broker",
        "capability_class": "read",
        "auth_mode": "local-readonly",
        "allows_side_effect": False,
        "baseline_risk_level": 1,
        "approval_mode": APPROVAL_MODE_AUTO,
        "audit_mode": AUDIT_MODE_BASIC,
        "max_inflight_per_participant": 8,
        "rate_limit": {
            "enabled": False,
            "burst": 0,
            "refill_tokens": 0,
            "refill_jiffies": 0,
            "default_cost": 0,
            "max_inflight_per_participant": 0,
            "defer_wait_ms": 0,
        },
    },
    "message.read": {
        "capability_id": 102,
        "required_caps": 1 << 1,
        "broker_id": "message-broker",
        "capability_class": "read",
        "auth_mode": "session-auth",
        "allows_side_effect": False,
        "baseline_risk_level": 3,
        "approval_mode": APPROVAL_MODE_AUTO,
        "audit_mode": AUDIT_MODE_BASIC,
        "max_inflight_per_participant": 4,
        "rate_limit": {
            "enabled": True,
            "burst": 8,
            "refill_tokens": 4,
            "refill_jiffies": 5,
            "default_cost": 1,
            "max_inflight_per_participant": 4,
            "defer_wait_ms": 250,
        },
    },
    "message.send": {
        "capability_id": 103,
        "required_caps": 1 << 2,
        "broker_id": "message-broker",
        "capability_class": "write",
        "auth_mode": "session-auth",
        "allows_side_effect": True,
        "baseline_risk_level": 8,
        "approval_mode": APPROVAL_MODE_EXPLICIT,
        "audit_mode": AUDIT_MODE_DETAILED,
        "max_inflight_per_participant": 2,
        "rate_limit": {
            "enabled": True,
            "burst": 2,
            "refill_tokens": 1,
            "refill_jiffies": 5,
            "default_cost": 1,
            "max_inflight_per_participant": 2,
            "defer_wait_ms": 500,
        },
    },
    "file.read": {
        "capability_id": 104,
        "required_caps": 1 << 3,
        "broker_id": "file-broker",
        "capability_class": "read",
        "auth_mode": "local-readonly",
        "allows_side_effect": False,
        "baseline_risk_level": 3,
        "approval_mode": APPROVAL_MODE_AUTO,
        "audit_mode": AUDIT_MODE_BASIC,
        "max_inflight_per_participant": 4,
        "rate_limit": {
            "enabled": True,
            "burst": 8,
            "refill_tokens": 4,
            "refill_jiffies": 5,
            "default_cost": 1,
            "max_inflight_per_participant": 4,
            "defer_wait_ms": 250,
        },
    },
    "file.write": {
        "capability_id": 105,
        "required_caps": 1 << 4,
        "broker_id": "file-broker",
        "capability_class": "write",
        "auth_mode": "trusted-write",
        "allows_side_effect": True,
        "baseline_risk_level": 8,
        "approval_mode": APPROVAL_MODE_EXPLICIT,
        "audit_mode": AUDIT_MODE_DETAILED,
        "max_inflight_per_participant": 2,
        "rate_limit": {
            "enabled": True,
            "burst": 2,
            "refill_tokens": 1,
            "refill_jiffies": 5,
            "default_cost": 1,
            "max_inflight_per_participant": 2,
            "defer_wait_ms": 500,
        },
    },
    "network.fetch.readonly": {
        "capability_id": 106,
        "required_caps": 1 << 5,
        "broker_id": "info-broker",
        "capability_class": "network-read",
        "auth_mode": "network-readonly",
        "allows_side_effect": False,
        "baseline_risk_level": 4,
        "approval_mode": APPROVAL_MODE_AUTO,
        "audit_mode": AUDIT_MODE_BASIC,
        "max_inflight_per_participant": 4,
        "rate_limit": {
            "enabled": True,
            "burst": 4,
            "refill_tokens": 2,
            "refill_jiffies": 5,
            "default_cost": 1,
            "max_inflight_per_participant": 4,
            "defer_wait_ms": 250,
        },
    },
    "browser.automation": {
        "capability_id": 107,
        "required_caps": 1 << 6,
        "broker_id": "browser-broker",
        "capability_class": "automation",
        "auth_mode": "interactive-broker",
        "allows_side_effect": True,
        "baseline_risk_level": 8,
        "approval_mode": APPROVAL_MODE_INTERACTIVE,
        "audit_mode": AUDIT_MODE_DETAILED,
        "max_inflight_per_participant": 2,
        "rate_limit": {
            "enabled": True,
            "burst": 2,
            "refill_tokens": 1,
            "refill_jiffies": 5,
            "default_cost": 1,
            "max_inflight_per_participant": 2,
            "defer_wait_ms": 500,
        },
    },
    "external.write": {
        "capability_id": 108,
        "required_caps": 1 << 7,
        "broker_id": "external-router-broker",
        "capability_class": "external-write",
        "auth_mode": "provider-auth",
        "allows_side_effect": True,
        "baseline_risk_level": 8,
        "approval_mode": APPROVAL_MODE_EXPLICIT,
        "audit_mode": AUDIT_MODE_DETAILED,
        "max_inflight_per_participant": 2,
        "rate_limit": {
            "enabled": True,
            "burst": 2,
            "refill_tokens": 1,
            "refill_jiffies": 5,
            "default_cost": 1,
            "max_inflight_per_participant": 2,
            "defer_wait_ms": 500,
        },
    },
    "exec.run": {
        "capability_id": 109,
        "required_caps": 1 << 8,
        "broker_id": "exec-broker",
        "capability_class": "execution",
        "auth_mode": "trusted-exec",
        "allows_side_effect": True,
        "baseline_risk_level": 8,
        "approval_mode": APPROVAL_MODE_ROOT_ONLY,
        "audit_mode": AUDIT_MODE_STRICT,
        "max_inflight_per_participant": 1,
        "rate_limit": {
            "enabled": True,
            "burst": 1,
            "refill_tokens": 1,
            "refill_jiffies": 10,
            "default_cost": 1,
            "max_inflight_per_participant": 1,
            "defer_wait_ms": 1000,
        },
    },
}

CAPABILITY_DOMAIN_IDS: Dict[str, int] = {
    name: int(meta["capability_id"]) for name, meta in CAPABILITY_DOMAIN_REGISTRY.items()
}
CAPABILITY_REQUIRED_CAPS: Dict[str, int] = {
    name: int(meta["required_caps"]) for name, meta in CAPABILITY_DOMAIN_REGISTRY.items()
}
DEFAULT_BROKERS: Dict[str, str] = {
    name: str(meta["broker_id"]) for name, meta in CAPABILITY_DOMAIN_REGISTRY.items()
}
CAPABILITY_CLASSES: Dict[str, str] = {
    name: str(meta["capability_class"]) for name, meta in CAPABILITY_DOMAIN_REGISTRY.items()
}
CAPABILITY_AUTH_MODES: Dict[str, str] = {
    name: str(meta["auth_mode"]) for name, meta in CAPABILITY_DOMAIN_REGISTRY.items()
}
CAPABILITY_SIDE_EFFECTS: Dict[str, bool] = {
    name: bool(meta["allows_side_effect"]) for name, meta in CAPABILITY_DOMAIN_REGISTRY.items()
}
HIGH_RISK_DOMAINS = frozenset(
    name
    for name, meta in CAPABILITY_DOMAIN_REGISTRY.items()
    if int(meta["baseline_risk_level"]) >= HIGH_RISK_LEVEL
)


def _capability_executor_policy(capability_domain: str, meta: Mapping[str, Any]) -> Dict[str, Any]:
    capability_class = str(meta["capability_class"])
    risk_level = int(meta["baseline_risk_level"])
    if capability_domain == "exec.run":
        return {
            "allowed_executor_types": ("sandboxed-process",),
            "network_policy": "broker-mediated",
            "require_short_lived": True,
            "min_planner_trust_level": 8,
            "min_provider_trust_class": "local",
        }
    if capability_class in READ_ONLY_CAPABILITY_CLASSES:
        return {
            "allowed_executor_types": ("broker-uds",),
            "network_policy": "inherit",
            "require_short_lived": True,
            "min_planner_trust_level": 0,
            "min_provider_trust_class": "local",
        }
    return {
        "allowed_executor_types": ("broker-isolated-uds", "sandboxed-process")
        if risk_level >= HIGH_RISK_LEVEL
        else ("broker-isolated-uds", "broker-uds"),
        "network_policy": "broker-mediated" if risk_level >= HIGH_RISK_LEVEL else "inherit",
        "require_short_lived": True,
        "min_planner_trust_level": 4 if risk_level >= HIGH_RISK_LEVEL else 0,
        "min_provider_trust_class": "local",
    }


def _capability_sandbox_profile(capability_domain: str, meta: Mapping[str, Any]) -> str:
    capability_class = str(meta["capability_class"])
    risk_level = int(meta["baseline_risk_level"])
    if capability_domain == "exec.run":
        return "sandbox-high-risk"
    if capability_class in READ_ONLY_CAPABILITY_CLASSES:
        return "local-readonly"
    if risk_level >= HIGH_RISK_LEVEL:
        return "sandbox-broker-isolated"
    return "local-readonly"


for _capability_name, _capability_meta in CAPABILITY_DOMAIN_REGISTRY.items():
    _capability_meta.setdefault(
        "max_inflight_per_agent",
        int(_capability_meta["max_inflight_per_participant"]),
    )
    _capability_meta.setdefault(
        "sandbox_profile",
        _capability_sandbox_profile(_capability_name, _capability_meta),
    )
    _capability_meta.setdefault(
        "executor_policy",
        _capability_executor_policy(_capability_name, _capability_meta),
    )


# ---------------------------------------------------------------------------
# broker registry metadata

BROKER_REGISTRY: Dict[str, Dict[str, Any]] = {
    "info-broker": {
        "capability_domains": ("info.lookup", "network.fetch.readonly"),
        "policy_controlled": True,
        "runtime_identity_mode": "registered-agent",
        "selection_policy": {
            "require_provider_availability": True,
            "prefer_manifest_priority": True,
            "prefer_example_matches": True,
            "prefer_lower_risk_on_tie": True,
            "allow_preferred_provider_high_risk": False,
        },
    },
    "message-broker": {
        "capability_domains": ("message.read", "message.send"),
        "policy_controlled": True,
        "runtime_identity_mode": "registered-agent",
        "selection_policy": {
            "require_provider_availability": True,
            "prefer_manifest_priority": True,
            "prefer_example_matches": True,
            "prefer_lower_risk_on_tie": True,
            "allow_preferred_provider_high_risk": False,
        },
    },
    "file-broker": {
        "capability_domains": ("file.read", "file.write"),
        "policy_controlled": True,
        "runtime_identity_mode": "registered-agent",
        "selection_policy": {
            "require_provider_availability": True,
            "prefer_manifest_priority": True,
            "prefer_example_matches": True,
            "prefer_lower_risk_on_tie": True,
            "allow_preferred_provider_high_risk": False,
        },
    },
    "browser-broker": {
        "capability_domains": ("browser.automation",),
        "policy_controlled": True,
        "runtime_identity_mode": "registered-agent",
        "selection_policy": {
            "require_provider_availability": True,
            "prefer_manifest_priority": True,
            "prefer_example_matches": True,
            "prefer_lower_risk_on_tie": True,
            "allow_preferred_provider_high_risk": False,
        },
    },
    "exec-broker": {
        "capability_domains": ("exec.run",),
        "policy_controlled": True,
        "runtime_identity_mode": "registered-agent",
        "selection_policy": {
            "require_provider_availability": True,
            "prefer_manifest_priority": True,
            "prefer_example_matches": True,
            "prefer_lower_risk_on_tie": True,
            "allow_preferred_provider_high_risk": False,
        },
    },
    "external-router-broker": {
        "capability_domains": ("external.write",),
        "policy_controlled": True,
        "runtime_identity_mode": "registered-agent",
        "selection_policy": {
            "require_provider_availability": True,
            "prefer_manifest_priority": True,
            "prefer_example_matches": True,
            "prefer_lower_risk_on_tie": True,
            "allow_preferred_provider_high_risk": False,
        },
    },
}

BROKER_CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    broker_id: tuple(meta["capability_domains"]) for broker_id, meta in BROKER_REGISTRY.items()
}


# ---------------------------------------------------------------------------
# provider/action dataclasses

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
    intent_tags: Tuple[str, ...] = ()
    examples: List[Any] = field(default_factory=list)
    arg_hints: Dict[str, Any] = field(default_factory=dict)
    selection_priority: int = 100
    manifest_source: str = ""


@dataclass(frozen=True)
class ProviderDef:
    provider_id: str
    instance_id: str
    provider_type: str
    trust_class: str
    auth_mode: str
    broker_domain: str
    display_name: str
    endpoint: str
    mode: str
    actions: Dict[int, ProviderAction]
    manifest_source: str = ""


@dataclass(frozen=True)
class CapabilityDomain:
    capability_id: int
    name: str
    description: str
    intent_tags: Tuple[str, ...]
    examples: List[Any]
    broker_id: str
    perm: int
    cost: int
    required_caps: int
    risk_level: int
    approval_mode: int
    audit_mode: int
    max_inflight_per_agent: int
    max_inflight_per_participant: int
    executor_policy: Dict[str, Any]
    sandbox_profile: str
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
    selection_policy: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# executor binding model

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
    audit_markers: Tuple[str, ...] = ()


def build_executor_binding(provider: ProviderDef, action: ProviderAction) -> ExecutorBinding:
    profile = {
        "sandbox_profile": "local-readonly",
        "network_policy": "inherit",
        "resource_limits": {"cpu_ms": 1000, "memory_kb": 131072, "nofile": 64},
    }
    if action.executor_type == "broker-isolated-uds":
        profile = {
            "sandbox_profile": "sandbox-broker-isolated",
            "network_policy": "broker-mediated",
            "resource_limits": {"cpu_ms": 3000, "memory_kb": 262144, "nofile": 64},
        }
    elif action.executor_type == "sandboxed-process":
        profile = {
            "sandbox_profile": "sandbox-high-risk",
            "network_policy": "broker-mediated",
            "resource_limits": {"cpu_ms": 5000, "memory_kb": 262144, "nofile": 64},
        }
    return ExecutorBinding(
        executor_id=f"{provider.provider_id}:{action.action_name}:exec",
        executor_type=action.executor_type,
        parameter_schema_id=action.parameter_schema_id,
        short_lived=True,
        sandbox_profile=str(profile["sandbox_profile"]),
        working_directory=f"/tmp/linux-mcp-executors/{provider.provider_id}",
        network_policy=str(profile["network_policy"]),
        resource_limits=dict(profile["resource_limits"]),
        inherited_env_keys=("LANG", "LC_ALL", "PATH"),
        command_schema_id=action.parameter_schema_id,
        structured_payload_only=action.executor_type in STRUCTURED_EXECUTOR_TYPES,
        sandbox_ready=True,
        runtime_identity_mode="broker-bound",
    )


def _trust_class_rank(trust_class: str) -> int:
    return TRUST_CLASS_RANKS.get(trust_class, 0)


def validate_executor_binding_for_capability(
    capability: CapabilityDomain,
    provider: ProviderDef,
    action: ProviderAction,
    executor: ExecutorBinding,
) -> None:
    executor_policy = dict(capability.executor_policy)
    allowed_executor_types = tuple(executor_policy.get("allowed_executor_types", ()))
    if allowed_executor_types and executor.executor_type not in allowed_executor_types:
        raise ValueError(
            f"executor_type {executor.executor_type!r} violates capability policy for {capability.name}"
        )
    required_network_policy = str(executor_policy.get("network_policy", executor.network_policy))
    if required_network_policy and executor.network_policy != required_network_policy:
        raise ValueError(
            f"executor network_policy {executor.network_policy!r} violates capability policy for {capability.name}"
        )
    if bool(executor_policy.get("require_short_lived", False)) and not executor.short_lived:
        raise ValueError(f"executor for capability {capability.name} must be short-lived")
    if capability.sandbox_profile and executor.sandbox_profile != capability.sandbox_profile:
        raise ValueError(
            f"executor sandbox_profile {executor.sandbox_profile!r} violates capability policy for {capability.name}"
        )
    min_provider_trust = str(executor_policy.get("min_provider_trust_class", "anonymous"))
    if _trust_class_rank(provider.trust_class) < _trust_class_rank(min_provider_trust):
        raise ValueError(
            f"provider trust_class {provider.trust_class!r} violates capability policy for {capability.name}"
        )
    if action.executor_type != executor.executor_type:
        raise ValueError("executor binding must use action executor_type")


def validate_capability_request(
    planner: Mapping[str, Any],
    capability: CapabilityDomain,
    intent: Mapping[str, Any],
) -> Tuple[str, ...]:
    participant_id = str(planner.get("participant_id", "unknown"))
    caps = int(planner.get("caps", 0) or 0)
    trust_level = int(planner.get("trust_level", 0) or 0)
    interactive = bool(intent.get("interactive", False))
    explicit_approval = bool(intent.get("explicit_approval", False))
    approval_token = str(intent.get("approval_token", "") or "")
    markers: List[str] = []

    if (caps & capability.required_caps) != capability.required_caps:
        raise ValueError(
            f"participant {participant_id} missing required capability bits for {capability.name}"
        )

    min_planner_trust = int(capability.executor_policy.get("min_planner_trust_level", 0))
    if trust_level < min_planner_trust:
        raise ValueError(
            f"participant {participant_id} trust_level={trust_level} below policy minimum for {capability.name}"
        )

    if capability.approval_mode == APPROVAL_MODE_INTERACTIVE and not interactive:
        raise ValueError(f"capability {capability.name} requires interactive approval context")
    if capability.approval_mode == APPROVAL_MODE_EXPLICIT:
        if explicit_approval or approval_token:
            markers.append("approval_mode_explicit_signaled")
        else:
            markers.append("approval_mode_explicit_kernel_pending")
    if capability.approval_mode == APPROVAL_MODE_TRUSTED and trust_level < HIGH_RISK_LEVEL:
        raise ValueError(f"capability {capability.name} requires trusted planner context")
    if capability.approval_mode == APPROVAL_MODE_ROOT_ONLY and not (explicit_approval or approval_token):
        markers.append("approval_mode_root_only_kernel_enforced")

    if capability.risk_level >= HIGH_RISK_LEVEL:
        markers.append("high_risk_capability")
    return tuple(markers)


def fill_action_payload(
    action: ProviderAction,
    payload: Mapping[str, Any] | None,
    *,
    defaults: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    merged: Dict[str, Any] = dict(defaults or {})
    if payload is not None:
        if not isinstance(payload, Mapping):
            raise ValueError(f"{action.action_name}: payload must be object")
        merged.update(dict(payload))
    return merged


def build_action_payload_from_intent(
    action: ProviderAction,
    intent_text: str,
    *,
    builder: Callable[[ProviderAction, str], Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    if builder is None:
        raise NotImplementedError(
            "planner-specific payload extraction does not belong in mcpd.architecture; "
            "pass a broker-side builder explicitly"
        )
    payload = dict(builder(action, intent_text))
    return fill_action_payload(action, payload)


def validate_action_payload(action: ProviderAction, payload: Mapping[str, Any]) -> Dict[str, Any]:
    merged = fill_action_payload(action, payload)
    _validate_payload_against_schema(action.input_schema, merged, source=action.action_name)
    return merged


_PATH_TOKEN_RE = re.compile(
    r"(?:\.\.?/)?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*|[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+"
)
_INTEGER_RE = re.compile(r"(?<![A-Za-z0-9])(-?\d+)(?![A-Za-z0-9])")
_FLOAT_RE = re.compile(r"(?<![A-Za-z0-9])(-?\d+(?:\.\d+)?)(?![A-Za-z0-9])")
_QUOTED_RE = re.compile(r"['\"]([^'\"]+)['\"]")
_MATH_RE = re.compile(r"([0-9(][0-9\s+\-*/().%]+)")


def _collect_quoted_values(text: str) -> List[str]:
    return [value.strip() for value in _QUOTED_RE.findall(text) if value.strip()]


def _extract_after_keywords(
    text: str,
    keywords: Sequence[str],
    *,
    quoted_only: bool = False,
) -> List[str]:
    matches: List[str] = []
    for keyword in keywords:
        pattern = re.compile(
            rf"\b{re.escape(keyword.lower())}\b\s+(?:['\"]([^'\"]+)['\"]|([^\s,;]+))",
            flags=re.IGNORECASE,
        )
        for match in pattern.finditer(text):
            quoted = match.group(1)
            raw = quoted if quoted is not None else ("" if quoted_only else match.group(2) or "")
            raw = raw.strip()
            if raw:
                matches.append(raw)
    return matches


def _extract_paths(text: str) -> List[str]:
    values: List[str] = []
    for raw in _collect_quoted_values(text):
        if "/" in raw or "." in raw:
            values.append(raw)
    for raw in _PATH_TOKEN_RE.findall(text):
        cleaned = raw.strip().rstrip(".,)")
        if cleaned and ("/" in cleaned or "." in cleaned):
            values.append(cleaned)
    seen: set[str] = set()
    out: List[str] = []
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out


def _extract_integers(text: str) -> List[int]:
    out: List[int] = []
    for match in _INTEGER_RE.findall(text):
        try:
            out.append(int(match))
        except ValueError:
            continue
    return out


def _extract_numbers(text: str) -> List[float]:
    out: List[float] = []
    for match in _FLOAT_RE.findall(text):
        try:
            out.append(float(match))
        except ValueError:
            continue
    return out


def _extract_enum_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    lower = text.lower()
    aliases_by_choice = field_hints.get("aliases_by_choice", {})
    if isinstance(aliases_by_choice, Mapping):
        for choice, aliases in aliases_by_choice.items():
            if isinstance(choice, str) and isinstance(aliases, Sequence):
                for alias in aliases:
                    if isinstance(alias, str) and alias.lower() in lower:
                        return choice
    choices = field_hints.get("choices", [])
    if isinstance(choices, Sequence):
        for choice in choices:
            if isinstance(choice, str) and choice.lower() in lower:
                return choice
    default = field_hints.get("default")
    return default


def _extract_boolean_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    lower = text.lower()
    false_tokens = field_hints.get("false_tokens", [])
    if isinstance(false_tokens, Sequence):
        for token in false_tokens:
            if isinstance(token, str) and token.lower() in lower:
                return False
    true_tokens = field_hints.get("true_tokens", [])
    if isinstance(true_tokens, Sequence):
        for token in true_tokens:
            if isinstance(token, str) and token.lower() in lower:
                return True
    return field_hints.get("default")


def _extract_integer_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    lower = text.lower()
    units = field_hints.get("units", [])
    matched_context = False
    if isinstance(units, Sequence):
        for unit in units:
            if not isinstance(unit, str):
                continue
            pattern = re.compile(rf"(-?\d+)\s*{re.escape(unit.lower())}\b")
            match = pattern.search(lower)
            if match:
                matched_context = True
                return int(match.group(1))
    after = field_hints.get("after", [])
    values = _extract_after_keywords(lower, [item for item in after if isinstance(item, str)])
    for value in values:
        numbers = _extract_integers(value)
        if numbers:
            matched_context = True
            return numbers[0]
    if (after or units) and not matched_context and not bool(field_hints.get("allow_global_search", False)):
        return field_hints.get("default")
    numbers = _extract_integers(lower)
    if numbers:
        position = field_hints.get("position")
        if isinstance(position, int) and 0 <= position < len(numbers):
            return numbers[position]
        return numbers[0]
    return field_hints.get("default")


def _extract_number_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    lower = text.lower()
    after = field_hints.get("after", [])
    values = _extract_after_keywords(lower, [item for item in after if isinstance(item, str)])
    for value in values:
        numbers = _extract_numbers(value)
        if numbers:
            return numbers[0]
    numbers = _extract_numbers(lower)
    if numbers:
        return numbers[0]
    return field_hints.get("default")


def _extract_path_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    after = [item for item in field_hints.get("after", []) if isinstance(item, str)]
    values = _extract_after_keywords(text, after)
    for value in values:
        return value
    paths = _extract_paths(text)
    position = field_hints.get("position")
    if isinstance(position, int) and 0 <= position < len(paths):
        return paths[position]
    if paths:
        return paths[0]
    return field_hints.get("default")


def _extract_list_value(
    text: str,
    field_hints: Mapping[str, Any],
    item_schema: Mapping[str, Any],
) -> List[Any] | None:
    after = [item for item in field_hints.get("after", []) if isinstance(item, str)]
    raw_value = ""
    if after:
        values = _extract_after_keywords(text, after)
        if values:
            raw_value = values[0]
    if not raw_value:
        quoted = _collect_quoted_values(text)
        if quoted:
            raw_value = quoted[0]
    if not raw_value:
        raw_value = field_hints.get("default", "")
    if raw_value in ("", None):
        return None

    item_type = str(item_schema.get("type", "string"))
    if isinstance(raw_value, list):
        raw_items = raw_value
    else:
        raw_items = [item.strip() for item in re.split(r"[,|]", str(raw_value)) if item.strip()]
        if len(raw_items) == 1 and " and " in str(raw_value):
            raw_items = [item.strip() for item in str(raw_value).split(" and ") if item.strip()]

    out: List[Any] = []
    for raw_item in raw_items:
        try:
            out.append(_coerce_schema_value(raw_item, {"type": item_type}, "list_item", "build_execution_payload"))
        except Exception:
            continue
    return out or None


def _extract_expression_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    quoted = _collect_quoted_values(text)
    for value in quoted:
        if any(ch in value for ch in "+-*/()%"):
            return value
    match = _MATH_RE.search(text)
    if match:
        candidate = match.group(1).strip()
        if any(ch in candidate for ch in "+-*/()%"):
            return candidate
    return field_hints.get("default")


def _strip_known_prefixes(text: str, prefixes: Sequence[str]) -> str:
    out = text.strip()
    for prefix in prefixes:
        if isinstance(prefix, str) and out.lower().startswith(prefix.lower() + " "):
            out = out[len(prefix) + 1 :].strip()
    return out


def _extract_tail_text_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    quoted = _collect_quoted_values(text)
    if quoted:
        position = field_hints.get("position")
        if isinstance(position, int) and 0 <= position < len(quoted):
            return quoted[position]
        return quoted[0]
    after = [item for item in field_hints.get("after", []) if isinstance(item, str)]
    for keyword in after:
        match = re.search(rf"\b{re.escape(keyword)}\b\s+(.+)$", text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    stripped = _strip_known_prefixes(text, field_hints.get("strip_prefixes", []))
    return stripped or field_hints.get("default")


def _extract_string_value(
    field_name: str,
    text: str,
    field_hints: Mapping[str, Any],
) -> Any:
    kind = str(field_hints.get("kind", "string"))
    if kind == "enum":
        return _extract_enum_value(text, field_hints)
    if kind == "path":
        return _extract_path_value(text, field_hints)
    if kind == "expression":
        return _extract_expression_value(text, field_hints)
    if kind == "quoted_string":
        quoted = _collect_quoted_values(text)
        if quoted:
            position = field_hints.get("position")
            if isinstance(position, int) and 0 <= position < len(quoted):
                return quoted[position]
            return quoted[0]
        return field_hints.get("default")
    if kind in {"quoted_or_tail", "tail_text"}:
        after = [item for item in field_hints.get("after", []) if isinstance(item, str)]
        if after:
            values = _extract_after_keywords(text, after)
            if values:
                position = field_hints.get("position")
                if isinstance(position, int) and 0 <= position < len(values):
                    return values[position]
                return values[0]
        return _extract_tail_text_value(text, field_hints)

    after = [item for item in field_hints.get("after", []) if isinstance(item, str)]
    if after:
        values = _extract_after_keywords(text, after)
        if values:
            position = field_hints.get("position")
            if isinstance(position, int) and 0 <= position < len(values):
                return values[position]
            return values[0]

    aliases = [item for item in field_hints.get("aliases", []) if isinstance(item, str)]
    if aliases:
        values = _extract_after_keywords(text, aliases)
        if values:
            return values[0]

    if field_name in {"message", "text", "content"}:
        return _extract_tail_text_value(text, field_hints)
    return field_hints.get("default")


def _coerce_schema_value(value: Any, schema: Mapping[str, Any], field_name: str, source: str) -> Any:
    expected_type = schema.get("type")
    if not isinstance(expected_type, str):
        return value
    if expected_type == "string":
        if isinstance(value, str):
            return value
        return str(value)
    if expected_type == "integer":
        if isinstance(value, bool):
            raise ValueError(f"{source}: field {field_name!r} must be integer")
        if isinstance(value, int):
            return value
        return int(value)
    if expected_type == "number":
        if isinstance(value, bool):
            raise ValueError(f"{source}: field {field_name!r} must be number")
        if isinstance(value, (int, float)):
            return value
        return float(value)
    if expected_type == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lower = value.lower().strip()
            if lower in {"true", "yes", "1", "on"}:
                return True
            if lower in {"false", "no", "0", "off"}:
                return False
        raise ValueError(f"{source}: field {field_name!r} must be boolean")
    return value


def _infer_field_value_from_intent(
    field_name: str,
    field_schema: Mapping[str, Any],
    field_hints: Mapping[str, Any],
    intent_text: str,
) -> Any:
    expected_type = str(field_schema.get("type", "string"))
    if expected_type == "boolean":
        value = _extract_boolean_value(intent_text, field_hints)
    elif expected_type == "integer":
        value = _extract_integer_value(intent_text, field_hints)
    elif expected_type == "number":
        value = _extract_number_value(intent_text, field_hints)
    elif expected_type == "array":
        item_schema = field_schema.get("items", {})
        if not isinstance(item_schema, Mapping):
            item_schema = {}
        value = _extract_list_value(intent_text, field_hints, item_schema)
    elif expected_type == "string":
        value = _extract_string_value(field_name, intent_text, field_hints)
    else:
        value = field_hints.get("default")
    if value is None:
        return None
    return _coerce_schema_value(value, field_schema, field_name, "build_execution_payload")


def _infer_payload_from_schema(
    action: ProviderAction,
    intent_text: str,
    *,
    hints: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    properties = action.input_schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return payload

    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, Mapping):
            continue
        field_hints = action.arg_hints.get(field_name, {})
        if not isinstance(field_hints, Mapping):
            field_hints = {}
        value = _infer_field_value_from_intent(field_name, field_schema, field_hints, intent_text)
        if value is not None:
            payload[field_name] = value
    return payload


def build_execution_payload(
    action: ProviderAction,
    intent_text: str,
    *,
    provided_payload: Mapping[str, Any] | None = None,
    hints: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    defaults = _infer_payload_from_schema(action, intent_text, hints=hints)
    payload = fill_action_payload(action, provided_payload, defaults=defaults)
    validated = validate_action_payload(action, payload)
    _log_structured(
        logging.INFO,
        "payload_fill_mode",
        action_name=action.action_name,
        capability_domain=action.capability_domain,
        fill_mode="schema_arg_hints",
        inferred_fields=sorted(defaults.keys()),
        provided_fields=sorted(list(provided_payload.keys())) if isinstance(provided_payload, Mapping) else [],
        used_planner_payload_slots=False,
    )
    return validated


# ---------------------------------------------------------------------------
# manifest loading + validation

CANONICAL_MANIFEST_ACTION_FIELDS = (
    "action_id",
    "action_name",
    "capability_domain",
    "risk_level",
    "side_effect",
    "auth_required",
    "executor_type",
    "validation_policy",
    "parameter_schema_id",
    "input_schema",
    "intent_tags",
    "examples",
    "arg_hints",
    "selection_priority",
)

CANONICAL_MANIFEST_PROVIDER_FIELDS = (
    "provider_id",
    "provider_type",
    "trust_class",
    "auth_mode",
    "broker_domain",
    "endpoint",
    "mode",
    "actions",
)
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


def _ensure_bool(name: str, value: Any, source: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{source}: {name} must be bool")
    return value


def _ensure_provider_repo_path(name: str, value: Any, source: str) -> str:
    text = _ensure_non_empty_str(name, value, source)
    if text.startswith("/"):
        raise ValueError(f"{source}: {name} must be relative to repo root")
    if not text.startswith("provider-app/"):
        raise ValueError(f"{source}: {name} must be under provider-app/")
    return text


def _resolve_repo_relative_json(source: str, rel_path: Any, field_name: str) -> Dict[str, Any]:
    path_text = _ensure_provider_repo_path(field_name, rel_path, source)
    path = ROOT_DIR / path_text
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{source}: unable to read {field_name} at {path_text}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source}: invalid JSON in {field_name} at {path_text}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{source}: {field_name} at {path_text} must contain a JSON object")
    return raw


def _validate_json_schema_object(schema: Any, source: str) -> Dict[str, Any]:
    if not isinstance(schema, dict):
        raise ValueError(f"{source}: input_schema must be object")
    schema_type = schema.get("type")
    if schema_type is None:
        raise ValueError(f"{source}: input_schema.type is required")
    if not isinstance(schema_type, str):
        raise ValueError(f"{source}: input_schema.type must be string")
    return dict(schema)


def _normalize_examples(examples: Any, source: str) -> List[Any]:
    if not isinstance(examples, list):
        raise ValueError(f"{source}: examples must be list")
    return list(examples)


def _normalize_intent_tags(intent_tags: Any, source: str) -> Tuple[str, ...]:
    if not isinstance(intent_tags, list):
        raise ValueError(f"{source}: intent_tags must be list")
    out: List[str] = []
    for idx, value in enumerate(intent_tags):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{source}: intent_tags[{idx}] must be non-empty string")
        out.append(value.strip().lower())
    return tuple(dict.fromkeys(out))


def _normalize_arg_hints(arg_hints: Any, source: str) -> Dict[str, Any]:
    if not isinstance(arg_hints, dict):
        raise ValueError(f"{source}: arg_hints must be object")
    return dict(arg_hints)


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


def _validate_executor_type(capability_domain: str, risk_level: int, executor_type: str, source: str) -> None:
    if executor_type not in STRUCTURED_EXECUTOR_TYPES:
        raise ValueError(f"{source}: unsupported executor_type {executor_type!r}")
    if risk_level >= HIGH_RISK_LEVEL and executor_type not in HIGH_RISK_EXECUTOR_TYPES:
        raise ValueError(
            f"{source}: executor_type {executor_type!r} incompatible with high-risk capability {capability_domain}"
        )


def _validate_action_schema_contract(
    action: ProviderAction,
    capability_meta: Mapping[str, Any],
    provider: ProviderDef,
    source: str,
) -> None:
    capability_class = str(capability_meta["capability_class"])
    capability_auth_mode = str(capability_meta["auth_mode"])
    allows_side_effect = bool(capability_meta["allows_side_effect"])

    if action.side_effect and not allows_side_effect:
        raise ValueError(
            f"{source}: action {action.action_name} side_effect cannot map to {action.capability_domain}"
        )
    if action.auth_required and capability_auth_mode in LOW_TRUST_CAPABILITY_AUTH_MODES:
        raise ValueError(
            f"{source}: auth-required action {action.action_name} cannot map to low-trust capability {action.capability_domain}"
        )
    if capability_class in READ_ONLY_CAPABILITY_CLASSES and action.side_effect:
        raise ValueError(
            f"{source}: side-effect action {action.action_name} cannot map to read-only capability {action.capability_domain}"
        )
    if capability_class in READ_ONLY_CAPABILITY_CLASSES and _looks_like_write_or_exec(
        action.action_name, action.handler, action.name, action.description
    ):
        raise ValueError(
            f"{source}: write/exec-like action {action.action_name} cannot map to read-only capability {action.capability_domain}"
        )
    if action.capability_domain == "info.lookup" and _looks_like_write_or_exec(
        action.action_name, action.handler, action.name, action.description
    ):
        raise ValueError(
            f"{source}: write/exec-like action {action.action_name} cannot map to info.lookup"
        )
    if provider.auth_mode in LOW_TRUST_PROVIDER_AUTH_MODES and action.auth_required:
        raise ValueError(
            f"{source}: provider {provider.provider_id} auth_mode incompatible with auth-required action {action.action_name}"
        )
    if action.executor_type in STRUCTURED_EXECUTOR_TYPES and not action.parameter_schema_id:
        raise ValueError(
            f"{source}: structured execution requires parameter_schema_id for {action.action_name}"
        )
    properties = action.input_schema.get("properties", {})
    required = action.input_schema.get("required", [])
    is_non_trivial_action = bool(
        action.side_effect
        or action.risk_level >= 2
        or (isinstance(properties, Mapping) and len(properties) > 1)
        or (isinstance(required, list) and len(required) > 0)
    )
    if is_non_trivial_action and not action.intent_tags:
        raise ValueError(f"{source}: non-trivial action {action.action_name} requires intent_tags")
    if is_non_trivial_action and not action.examples:
        raise ValueError(f"{source}: non-trivial action {action.action_name} requires examples")
    _validate_executor_type(action.capability_domain, action.risk_level, action.executor_type, source)


def load_provider_manifest(source: str, raw: Any) -> ProviderDef:
    if not isinstance(raw, dict):
        raise ValueError(f"{source}: manifest must be JSON object")

    for field in CANONICAL_MANIFEST_PROVIDER_FIELDS:
        if field not in raw:
            raise ValueError(f"{source}: missing field '{field}'")

    provider_id = _ensure_non_empty_str("provider_id", raw["provider_id"], source)
    provider_type = _ensure_non_empty_str("provider_type", raw["provider_type"], source)
    trust_class = _ensure_non_empty_str("trust_class", raw["trust_class"], source)
    auth_mode = _ensure_non_empty_str("auth_mode", raw["auth_mode"], source)
    broker_domain = _ensure_non_empty_str("broker_domain", raw["broker_domain"], source)
    mode = _ensure_non_empty_str("mode", raw["mode"], source)
    endpoint = _ensure_non_empty_str("endpoint", raw["endpoint"], source)
    display_name = _ensure_non_empty_str("display_name", raw.get("display_name", provider_id), source)
    if mode != "uds_service":
        raise ValueError(f"{source}: mode must be 'uds_service'")
    if not endpoint.startswith("/tmp/linux-mcp-providers/"):
        raise ValueError(f"{source}: endpoint must start with /tmp/linux-mcp-providers/")

    provider_instance_id = str(
        raw.get("provider_instance_id")
        or f"{provider_id}:{_short_hash({'endpoint': endpoint, 'mode': mode})}"
    )
    manifest_actions = raw["actions"]
    if not isinstance(manifest_actions, list) or not manifest_actions:
        raise ValueError(f"{source}: actions must be non-empty list")

    actions: Dict[int, ProviderAction] = {}
    for action_raw in manifest_actions:
        if not isinstance(action_raw, dict):
            raise ValueError(f"{source}: each action must be object")
        for field in (
            "action_id",
            "action_name",
            "capability_domain",
            "description",
            "risk_level",
            "side_effect",
            "auth_required",
            "data_sensitivity",
            "executor_type",
            "validation_policy",
            "parameter_schema_id",
            "intent_tags",
            "examples",
            "arg_hints",
            "selection_priority",
            "handler",
        ):
            if field not in action_raw:
                raise ValueError(f"{source}: action missing field '{field}'")
        if "input_schema" not in action_raw and "input_schema_path" not in action_raw:
            raise ValueError(f"{source}: action missing field 'input_schema' or 'input_schema_path'")

        action_id = _ensure_int("action_id", action_raw["action_id"], source)
        if action_id in actions:
            raise ValueError(f"{source}: duplicate action_id={action_id}")

        handler = _ensure_non_empty_str("handler", action_raw["handler"], source)
        action_name = _ensure_non_empty_str("action_name", action_raw["action_name"], source)
        name = _ensure_non_empty_str("name", action_raw.get("name", action_name), source)
        description = _ensure_non_empty_str("description", action_raw["description"], source)
        perm = _ensure_int("perm", action_raw.get("perm", 1), source)
        cost = _ensure_int("cost", action_raw.get("cost", 1), source)
        action_source = f"{source}:action[{action_id}]"
        capability_domain = _ensure_non_empty_str("capability_domain", action_raw["capability_domain"], action_source)
        if capability_domain not in CAPABILITY_DOMAIN_REGISTRY:
            raise ValueError(f"{action_source}: unknown capability_domain {capability_domain!r}")
        capability_meta = CAPABILITY_DOMAIN_REGISTRY[capability_domain]
        risk_level = _ensure_int("risk_level", action_raw["risk_level"], action_source)
        side_effect = _ensure_bool("side_effect", action_raw["side_effect"], action_source)
        auth_required = _ensure_bool("auth_required", action_raw["auth_required"], action_source)
        executor_type = _ensure_non_empty_str("executor_type", action_raw["executor_type"], action_source)
        validation_policy = _ensure_non_empty_str("validation_policy", action_raw["validation_policy"], action_source)
        raw_input_schema = action_raw.get("input_schema")
        if raw_input_schema is None:
            raw_input_schema = _resolve_repo_relative_json(
                action_source,
                action_raw.get("input_schema_path"),
                "input_schema_path",
            )
        input_schema = _validate_json_schema_object(raw_input_schema, action_source)
        if executor_type in STRUCTURED_EXECUTOR_TYPES and not input_schema:
            raise ValueError(
                f"{action_source}: parameter schema is required for structured execution"
            )

        intent_tags = _normalize_intent_tags(action_raw["intent_tags"], action_source)
        examples = _normalize_examples(action_raw["examples"], action_source)
        arg_hints = _normalize_arg_hints(action_raw["arg_hints"], action_source)
        selection_priority = _ensure_int("selection_priority", action_raw["selection_priority"], action_source)
        parameter_schema_id = _ensure_non_empty_str("parameter_schema_id", action_raw["parameter_schema_id"], action_source)
        data_sensitivity = _ensure_non_empty_str("data_sensitivity", action_raw["data_sensitivity"], action_source)

        action = ProviderAction(
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
            intent_tags=intent_tags,
            examples=examples,
            arg_hints=arg_hints,
            selection_priority=selection_priority,
            manifest_source=source,
        )
        actions[action_id] = action

    provider = ProviderDef(
        provider_id=provider_id,
        instance_id=provider_instance_id,
        provider_type=provider_type,
        trust_class=trust_class,
        auth_mode=auth_mode,
        broker_domain=broker_domain,
        display_name=display_name,
        endpoint=endpoint,
        mode=mode,
        actions=actions,
        manifest_source=source,
    )
    for action in provider.actions.values():
        _validate_action_schema_contract(action, CAPABILITY_DOMAIN_REGISTRY[action.capability_domain], provider, source)
    return provider


# ---------------------------------------------------------------------------
# capability catalog construction

CAPABILITY_DESCRIPTIONS: Dict[str, str] = {
    "info.lookup": "Read-only information lookup, diagnostics, calculation, and text utility operations.",
    "message.read": "Read-only access to inboxes, message history, or other message content.",
    "message.send": "Outbound messaging and notification delivery with observable side effects.",
    "file.read": "Read-only file preview, listing, and inspection operations.",
    "file.write": "Filesystem mutation operations such as create, delete, copy, and rename.",
    "network.fetch.readonly": "Read-only network fetch and external information retrieval.",
    "browser.automation": "Interactive browser automation and remote UI manipulation.",
    "external.write": "Mutating external systems through provider-authenticated actions.",
    "exec.run": "Host or sandboxed process execution.",
}

def build_capability_catalog(providers: Iterable[ProviderDef]) -> Dict[str, CapabilityDomain]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for provider in providers:
        for action in provider.actions.values():
            capability_domain = action.capability_domain
            if capability_domain not in CAPABILITY_DOMAIN_REGISTRY:
                raise ValueError(f"unknown capability_domain in provider catalog: {capability_domain}")
            entry = grouped.setdefault(
                capability_domain,
                {
                    "provider_ids": set(),
                    "action_ids": set(),
                    "perm": 0,
                    "cost": 0,
                    "risk_level": int(CAPABILITY_DOMAIN_REGISTRY[capability_domain]["baseline_risk_level"]),
                    "actions": [],
                    "intent_tags": set(),
                    "examples": [],
                },
            )
            entry["provider_ids"].add(provider.provider_id)
            entry["action_ids"].add(action.action_id)
            entry["perm"] = max(int(entry["perm"]), action.perm)
            entry["cost"] = max(int(entry["cost"]), action.cost)
            entry["risk_level"] = max(int(entry["risk_level"]), action.risk_level)
            entry["actions"].append(action)
            entry["intent_tags"].update(action.intent_tags)
            entry["examples"].extend(action.examples)

    out: Dict[str, CapabilityDomain] = {}
    for capability_domain, entry in grouped.items():
        meta = CAPABILITY_DOMAIN_REGISTRY[capability_domain]
        capability_description = CAPABILITY_DESCRIPTIONS.get(
            capability_domain,
            f"Capability domain {capability_domain} mediated by {meta['broker_id']}.",
        )
        capability_intent_tags = tuple(
            sorted(str(tag) for tag in entry["intent_tags"] if isinstance(tag, str))
        )
        capability_examples = list(entry["examples"])[:8]
        manifest_hash = _short_hash(
            {
                "capability_domain": capability_domain,
                "provider_ids": sorted(entry["provider_ids"]),
                "action_ids": sorted(entry["action_ids"]),
                "description": capability_description,
                "intent_tags": list(capability_intent_tags),
                "examples": capability_examples,
                "action_metadata": [
                    {
                        "action_id": action.action_id,
                        "risk_level": action.risk_level,
                        "side_effect": action.side_effect,
                        "auth_required": action.auth_required,
                        "executor_type": action.executor_type,
                        "validation_policy": action.validation_policy,
                        "selection_priority": action.selection_priority,
                        "intent_tags": list(action.intent_tags),
                    }
                    for action in sorted(entry["actions"], key=lambda item: item.action_id)
                ],
                "required_caps": meta["required_caps"],
                "approval_mode": meta["approval_mode"],
                "audit_mode": meta["audit_mode"],
                "max_inflight_per_agent": meta["max_inflight_per_agent"],
                "max_inflight_per_participant": meta["max_inflight_per_participant"],
                "executor_policy": meta["executor_policy"],
                "sandbox_profile": meta["sandbox_profile"],
                "rate_limit": meta["rate_limit"],
            }
        )
        out[capability_domain] = CapabilityDomain(
            capability_id=int(meta["capability_id"]),
            name=capability_domain,
            description=capability_description,
            intent_tags=capability_intent_tags,
            examples=capability_examples,
            broker_id=str(meta["broker_id"]),
            perm=max(int(entry["perm"]), 1),
            cost=max(int(entry["cost"]), 1),
            required_caps=int(meta["required_caps"]),
            risk_level=max(int(entry["risk_level"]), int(meta["baseline_risk_level"])),
            approval_mode=int(meta["approval_mode"]),
            audit_mode=int(meta["audit_mode"]),
            max_inflight_per_agent=int(meta["max_inflight_per_agent"]),
            max_inflight_per_participant=int(meta["max_inflight_per_participant"]),
            executor_policy=dict(meta["executor_policy"]),
            sandbox_profile=str(meta["sandbox_profile"]),
            allows_side_effect=bool(meta["allows_side_effect"]),
            auth_mode=str(meta["auth_mode"]),
            capability_class=str(meta["capability_class"]),
            rate_limit=dict(meta["rate_limit"]),
            manifest_hash=manifest_hash,
            provider_ids=tuple(sorted(entry["provider_ids"])),
            action_ids=tuple(sorted(entry["action_ids"])),
        )
    return out


# ---------------------------------------------------------------------------
# broker catalog construction

def build_broker_catalog(
    providers: Iterable[ProviderDef], capabilities: Mapping[str, CapabilityDomain]
) -> Dict[str, BrokerDef]:
    provider_ids_by_broker: Dict[str, set[str]] = {
        broker_id: set() for broker_id in BROKER_REGISTRY
    }
    for provider in providers:
        for action in provider.actions.values():
            capability = capabilities.get(action.capability_domain)
            if capability is None:
                raise ValueError(f"missing capability catalog entry for {action.capability_domain}")
            provider_ids_by_broker.setdefault(capability.broker_id, set()).add(provider.provider_id)

    out: Dict[str, BrokerDef] = {}
    for broker_id, broker_meta in BROKER_REGISTRY.items():
        capability_domains = tuple(
            domain
            for domain in broker_meta["capability_domains"]
            if domain in capabilities
        )
        out[broker_id] = BrokerDef(
            broker_id=broker_id,
            capability_domains=capability_domains,
            provider_ids=tuple(sorted(provider_ids_by_broker.get(broker_id, set()))),
            policy_controlled=bool(broker_meta["policy_controlled"]),
            runtime_identity_mode=str(broker_meta["runtime_identity_mode"]),
            selection_policy=dict(broker_meta["selection_policy"]),
        )
    return out


# ---------------------------------------------------------------------------
# action resolution / dispatch planning

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize_text(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(_TOKEN_RE.findall(value.lower()))
    if isinstance(value, Mapping):
        tokens: List[str] = []
        for key, item in value.items():
            tokens.extend(_tokenize_text(key))
            tokens.extend(_tokenize_text(item))
        return tuple(tokens)
    if isinstance(value, (list, tuple, set)):
        tokens = []
        for item in value:
            tokens.extend(_tokenize_text(item))
        return tuple(tokens)
    return tuple(_TOKEN_RE.findall(str(value).lower()))


def _normalize_tokens(tokens: Sequence[str]) -> Tuple[str, ...]:
    normalized: List[str] = []
    for token in tokens:
        if not token:
            continue
        normalized.append(token)
        if len(token) > 5 and token.endswith("e"):
            normalized.append(token[:-1])
        for suffix in ("ations", "ation", "ions", "ion", "ing", "ed", "es", "s"):
            if len(token) > len(suffix) + 2 and token.endswith(suffix):
                normalized.append(token[: -len(suffix)])
    return tuple(dict.fromkeys(normalized))


def _soft_token_matches(intent_tokens: set[str], metadata_tokens: set[str]) -> int:
    matches = 0
    for intent_token in intent_tokens:
        for metadata_token in metadata_tokens:
            if intent_token == metadata_token:
                continue
            if min(len(intent_token), len(metadata_token)) < 5:
                continue
            if intent_token.startswith(metadata_token) or metadata_token.startswith(intent_token):
                matches += 1
                break
    return matches


def _score_manifest_match(action: ProviderAction, intent_tokens: Sequence[str]) -> int:
    if not intent_tokens:
        return action.selection_priority * 10

    token_set = set(_normalize_tokens(intent_tokens))
    tag_tokens = set(_normalize_tokens(_tokenize_text(action.intent_tags)))
    name_tokens = set(
        _normalize_tokens(_tokenize_text((action.name, action.action_name, action.description)))
    )
    arg_tokens = set(_normalize_tokens(_tokenize_text(action.arg_hints)))
    example_tokens = set(_normalize_tokens(_tokenize_text(action.examples)))
    schema_tokens = set(
        _normalize_tokens(_tokenize_text(action.input_schema.get("properties", {})))
    )

    score = action.selection_priority * 10
    score += 18 * len(token_set & tag_tokens)
    score += 8 * _soft_token_matches(token_set, tag_tokens)
    score += 10 * len(token_set & example_tokens)
    score += 4 * _soft_token_matches(token_set, example_tokens)
    score += 8 * len(token_set & schema_tokens)
    score += 3 * _soft_token_matches(token_set, schema_tokens)
    score += 5 * len(token_set & arg_tokens)
    score += 2 * _soft_token_matches(token_set, arg_tokens)
    score += 3 * len(token_set & name_tokens)
    score += 2 * _soft_token_matches(token_set, name_tokens)
    if action.examples:
        score += 2
    if action.intent_tags:
        score += 2
    return score


def _score_capability_match(capability: CapabilityDomain, intent_tokens: Sequence[str]) -> int:
    if not intent_tokens:
        return 0
    token_set = set(_normalize_tokens(intent_tokens))
    tag_tokens = set(_normalize_tokens(_tokenize_text(capability.intent_tags)))
    desc_tokens = set(_normalize_tokens(_tokenize_text(capability.description)))
    example_tokens = set(_normalize_tokens(_tokenize_text(capability.examples)))
    provider_tokens = set(_normalize_tokens(_tokenize_text(capability.provider_ids)))
    domain_tokens = set(_normalize_tokens(_tokenize_text(capability.name)))

    score = 0
    score += 22 * len(token_set & tag_tokens)
    score += 10 * _soft_token_matches(token_set, tag_tokens)
    score += 12 * len(token_set & example_tokens)
    score += 5 * _soft_token_matches(token_set, example_tokens)
    score += 6 * len(token_set & desc_tokens)
    score += 3 * _soft_token_matches(token_set, desc_tokens)
    score += 4 * len(token_set & domain_tokens)
    score += 2 * _soft_token_matches(token_set, domain_tokens)
    score += 2 * len(token_set & provider_tokens)
    if capability.examples:
        score += 2
    if capability.intent_tags:
        score += 2
    return score


def select_capability_from_catalog(
    user_text: str,
    capability_catalog: Iterable[CapabilityDomain],
) -> Tuple[CapabilityDomain, str]:
    intent_tokens = _tokenize_text(user_text)
    capabilities = list(capability_catalog)
    if not capabilities:
        raise ValueError("capability catalog is empty")
    best: Tuple[int, int, str] | None = None
    selected: CapabilityDomain | None = None
    for capability in capabilities:
        score = _score_capability_match(capability, intent_tokens)
        rank = (score, -capability.risk_level, capability.name)
        if best is None or rank > best:
            best = rank
            selected = capability
    if selected is None or best is None:
        raise ValueError("no capability selected from catalog")
    _log_structured(
        logging.INFO,
        "capability_resolver",
        selector_source="catalog",
        capability_domain=selected.name,
        selector_reason=f"catalog_score={best[0]}",
    )
    return selected, f"catalog_score={best[0]}"


def resolve_action_for_capability(
    intent_text: str,
    candidate_actions: Iterable[Tuple[ProviderDef, ProviderAction]],
    *,
    capability: CapabilityDomain | None = None,
    provider_availability: Mapping[str, bool] | None = None,
    broker_policy: Mapping[str, Any] | None = None,
    preferred_provider_id: str = "",
    allow_preferred_provider: bool = True,
) -> Tuple[ProviderDef, ProviderAction, Tuple[str, ...]]:
    policy = dict(broker_policy or {})
    availability = provider_availability or {}
    require_provider_availability = bool(policy.get("require_provider_availability", True))
    prefer_lower_risk_on_tie = bool(policy.get("prefer_lower_risk_on_tie", True))
    allow_preferred_high_risk = bool(policy.get("allow_preferred_provider_high_risk", False))

    intent_tokens = _tokenize_text(intent_text)
    available_candidates: List[Tuple[ProviderDef, ProviderAction]] = []
    markers: List[str] = []
    for provider, action in candidate_actions:
        is_available = availability.get(provider.provider_id, True)
        if require_provider_availability and not is_available:
            continue
        if capability is not None:
            try:
                validate_executor_binding_for_capability(
                    capability,
                    provider,
                    action,
                    build_executor_binding(provider, action),
                )
            except ValueError:
                continue
        available_candidates.append((provider, action))
    if not available_candidates:
        raise ValueError("no available provider actions for capability")

    preferred_candidates = available_candidates
    if preferred_provider_id and allow_preferred_provider:
        preferred_candidates = [
            (provider, action)
            for provider, action in available_candidates
            if provider.provider_id == preferred_provider_id
        ]
        if preferred_candidates:
            markers.append("preferred_provider_applied")
        else:
            raise ValueError(f"preferred provider not available: {preferred_provider_id}")
    elif preferred_provider_id and not allow_preferred_provider and not allow_preferred_high_risk:
        markers.append("preferred_provider_ignored_by_broker_policy")

    ranked = preferred_candidates or available_candidates
    best: Tuple[int, int, int, str, int] | None = None
    selected_provider: ProviderDef | None = None
    selected_action: ProviderAction | None = None
    for provider, action in ranked:
        score = _score_manifest_match(action, intent_tokens)
        tie_risk = -action.risk_level if prefer_lower_risk_on_tie else 0
        provider_trust = _trust_class_rank(provider.trust_class)
        rank = (score, tie_risk, provider_trust, provider.provider_id, -action.action_id)
        if best is None or rank > best:
            best = rank
            selected_provider = provider
            selected_action = action
    if best is None or selected_provider is None or selected_action is None:
        raise ValueError("no provider action selected for capability")

    _log_structured(
        logging.INFO,
        "action_resolver",
        capability_domain=selected_action.capability_domain,
        provider_id=selected_provider.provider_id,
        action_name=selected_action.action_name,
        provider_trust_class=selected_provider.trust_class,
        risk_level=selected_action.risk_level,
        selection_priority=selected_action.selection_priority,
        resolver_markers=list(markers),
    )
    return selected_provider, selected_action, tuple(markers)


def plan_capability_execution(
    capability_domain: str,
    providers: Mapping[str, ProviderDef],
    capabilities: Mapping[str, CapabilityDomain],
    brokers: Mapping[str, BrokerDef],
    intent_text: str,
    preferred_provider_id: str = "",
    allow_preferred_provider: bool = True,
    provider_availability: Mapping[str, bool] | None = None,
) -> BrokerDispatchPlan:
    capability = capabilities.get(capability_domain)
    if capability is None:
        raise ValueError(f"unsupported capability_domain: {capability_domain}")

    broker = brokers.get(capability.broker_id)
    if broker is None:
        raise ValueError(f"missing broker for capability_domain: {capability_domain}")

    candidate_actions: List[Tuple[ProviderDef, ProviderAction]] = []
    for provider_id in capability.provider_ids:
        provider = providers.get(provider_id)
        if provider is None:
            continue
        for action in provider.actions.values():
            if action.capability_domain == capability_domain:
                candidate_actions.append((provider, action))
    if not candidate_actions:
        raise ValueError(f"no provider action mapped to capability_domain: {capability_domain}")

    provider, action, markers = resolve_action_for_capability(
        intent_text,
        candidate_actions,
        capability=capability,
        provider_availability=provider_availability,
        broker_policy=broker.selection_policy,
        preferred_provider_id=preferred_provider_id,
        allow_preferred_provider=allow_preferred_provider,
    )
    executor = build_executor_binding(provider, action)
    validate_executor_binding_for_capability(capability, provider, action, executor)
    return BrokerDispatchPlan(
        capability=capability,
        broker=broker,
        provider=provider,
        action=action,
        executor=executor,
        audit_markers=markers,
    )


def _matches_primitive(expected_type: str, value: Any) -> bool:
    mapping = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "object": dict,
        "array": list,
    }
    expected = mapping.get(expected_type)
    if expected is None:
        return True
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return (isinstance(value, (int, float))) and not isinstance(value, bool)
    return isinstance(value, expected)


def _validate_payload_against_schema(
    schema: Mapping[str, Any],
    payload: Any,
    *,
    source: str,
) -> None:
    schema_type = schema.get("type")
    if isinstance(schema_type, str) and schema_type != "object":
        if not _matches_primitive(schema_type, payload):
            raise ValueError(f"{source}: payload type mismatch, expected {schema_type}")
        return

    if not isinstance(payload, dict):
        raise ValueError(f"{source}: payload must be object")

    required = schema.get("required", [])
    if not isinstance(required, list):
        raise ValueError(f"{source}: input_schema.required must be list")
    for key in required:
        if key not in payload:
            raise ValueError(f"{source}: missing required payload field {key!r}")

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ValueError(f"{source}: input_schema.properties must be object")
    additional_properties = schema.get("additionalProperties", True)
    if not isinstance(additional_properties, bool):
        raise ValueError(f"{source}: input_schema.additionalProperties must be bool")

    for key, value in payload.items():
        prop_schema = properties.get(key)
        if prop_schema is None:
            if not additional_properties:
                raise ValueError(f"{source}: unexpected payload field {key!r}")
            continue
        if not isinstance(prop_schema, Mapping):
            raise ValueError(f"{source}: property schema for {key!r} must be object")
        expected_type = prop_schema.get("type")
        if isinstance(expected_type, str) and not _matches_primitive(expected_type, value):
            raise ValueError(f"{source}: payload field {key!r} must be {expected_type}")
