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

from config_loader import (
    load_controlplane_artifact_store,
    load_runtime_config_bundle,
    load_server_defaults_config,
    load_platform_capabilities_config,
)
from policy_engine import evaluate_capability_request, evaluate_executor_binding

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

APPROVAL_MODE_NAMES: Dict[str, int] = {
    "auto": APPROVAL_MODE_AUTO,
    "trusted": APPROVAL_MODE_TRUSTED,
    "root-only": APPROVAL_MODE_ROOT_ONLY,
    "interactive": APPROVAL_MODE_INTERACTIVE,
    "explicit": APPROVAL_MODE_EXPLICIT,
}
AUDIT_MODE_NAMES: Dict[str, int] = {
    "basic": AUDIT_MODE_BASIC,
    "detailed": AUDIT_MODE_DETAILED,
    "strict": AUDIT_MODE_STRICT,
}
DEFAULT_METADATA_SCORE_POLICY: Dict[str, Any] = {
    "require_provider_availability": True,
    "prefer_manifest_priority": True,
    "prefer_example_matches": True,
    "prefer_lower_risk_on_tie": True,
    "allow_preferred_provider_high_risk": False,
}
_RUNTIME_CONFIG_BUNDLE = load_runtime_config_bundle()
ARTIFACT_STORE = load_controlplane_artifact_store()


def _capability_registry_config() -> Dict[str, Any]:
    return dict(_RUNTIME_CONFIG_BUNDLE["capability_registry"])


def _broker_registry_config() -> Dict[str, Any]:
    return dict(_RUNTIME_CONFIG_BUNDLE["broker_registry"])


def _executor_profiles_config() -> Dict[str, Any]:
    return dict(_RUNTIME_CONFIG_BUNDLE["executor_profiles"])


def _log_structured(level: int, event_type: str, **fields: Any) -> None:
    payload = {"event_type": event_type}
    payload.update(fields)
    LOGGER.log(level, json.dumps(payload, sort_keys=True, ensure_ascii=True))


# ---------------------------------------------------------------------------
def _normalize_required_caps(value: Any, source: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return int(value)
    if not isinstance(value, list):
        raise ValueError(f"{source}: required_caps must be int or list")
    
    platform_caps = load_platform_capabilities_config()
    
    bitmask = 0
    for idx, cap_name in enumerate(value):
        if not isinstance(cap_name, str) or not cap_name.strip():
            raise ValueError(f"{source}: required_caps[{idx}] must be non-empty string")
        
        cap_val = cap_name.strip()
        cap_def = platform_caps.get(cap_val)
        
        if cap_def is None:
            raise ValueError(f"{source}: unknown required_caps entry {cap_val!r} (not declared in platform capabilities)")
        
        bitmask |= cap_def["bit"]
    return bitmask


def _normalize_mode_name(
    field_name: str,
    value: Any,
    mapping: Mapping[str, int],
    source: str,
) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        if value not in mapping.values():
            raise ValueError(f"{source}: unsupported {field_name} value {value}")
        return int(value)
    if not isinstance(value, str):
        raise ValueError(f"{source}: {field_name} must be string or int")
    normalized = value.strip().lower()
    if normalized not in mapping:
        raise ValueError(f"{source}: unsupported {field_name} value {value!r}")
    return int(mapping[normalized])


def _normalize_rate_limit(value: Any, source: str) -> Dict[str, int | bool]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{source}: rate_limit must be object")
    normalized: Dict[str, int | bool] = {}
    bool_keys = ("enabled",)
    int_keys = (
        "burst",
        "refill_tokens",
        "refill_jiffies",
        "default_cost",
        "max_inflight_per_participant",
        "defer_wait_ms",
    )
    for key in bool_keys:
        raw = value.get(key)
        if not isinstance(raw, bool):
            raise ValueError(f"{source}: rate_limit.{key} must be bool")
        normalized[key] = raw
    for key in int_keys:
        raw = value.get(key)
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ValueError(f"{source}: rate_limit.{key} must be int")
        normalized[key] = int(raw)
    return normalized


def _normalize_executor_policy(value: Any, source: str) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{source}: executor_policy must be object")
    allowed_executor_types = value.get("allowed_executor_types")
    if not isinstance(allowed_executor_types, list) or not allowed_executor_types:
        raise ValueError(f"{source}: executor_policy.allowed_executor_types must be non-empty list")
    normalized_types: List[str] = []
    for idx, executor_type in enumerate(allowed_executor_types):
        if not isinstance(executor_type, str) or executor_type not in get_runtime().STRUCTURED_EXECUTOR_TYPES:
            raise ValueError(
                f"{source}: executor_policy.allowed_executor_types[{idx}] is invalid"
            )
        normalized_types.append(executor_type)
    network_policy = value.get("network_policy")
    if not isinstance(network_policy, str) or not network_policy:
        raise ValueError(f"{source}: executor_policy.network_policy must be string")
    require_short_lived = value.get("require_short_lived")
    if not isinstance(require_short_lived, bool):
        raise ValueError(f"{source}: executor_policy.require_short_lived must be bool")
    min_planner_trust_level = value.get("min_planner_trust_level", 0)
    if isinstance(min_planner_trust_level, bool) or not isinstance(min_planner_trust_level, int):
        raise ValueError(f"{source}: executor_policy.min_planner_trust_level must be int")
    min_provider_trust_class = value.get("min_provider_trust_class", "anonymous")
    if not isinstance(min_provider_trust_class, str) or not min_provider_trust_class:
        raise ValueError(f"{source}: executor_policy.min_provider_trust_class must be string")
    deny_on_unenforced = value.get("deny_on_unenforced", False)
    if not isinstance(deny_on_unenforced, bool):
        raise ValueError(f"{source}: executor_policy.deny_on_unenforced must be bool")
    return {
        "allowed_executor_types": tuple(normalized_types),
        "network_policy": network_policy,
        "require_short_lived": require_short_lived,
        "min_planner_trust_level": int(min_planner_trust_level),
        "min_provider_trust_class": min_provider_trust_class,
        "deny_on_unenforced": deny_on_unenforced,
    }


def _load_capability_domain_registry() -> Dict[str, Dict[str, Any]]:
    raw = _capability_registry_config()
    registry: Dict[str, Dict[str, Any]] = {}
    for entry in raw["capabilities"]:
        capability_domain = str(entry["capability_domain"])
        source = f"capability_registry:{capability_domain}"
        risk_level = int(entry["risk_level"])
        sandbox_profile = str(entry["sandbox_profile"])
        executor_policy = _normalize_executor_policy(entry["executor_policy"], source)
        registry[capability_domain] = {
            "capability_id": int(entry["capability_id"]),
            "description": str(entry["description"]),
            "required_caps": _normalize_required_caps(entry["required_caps"], source),
            "broker_id": str(entry["broker_id"]),
            "capability_class": str(entry["capability_class"]),
            "auth_mode": str(entry["auth_mode"]),
            "allows_side_effect": bool(entry["allows_side_effect"]),
            "baseline_risk_level": risk_level,
            "approval_mode": _normalize_mode_name(
                "approval_mode",
                entry["approval_mode"],
                APPROVAL_MODE_NAMES,
                source,
            ),
            "audit_mode": _normalize_mode_name(
                "audit_mode",
                entry["audit_mode"],
                AUDIT_MODE_NAMES,
                source,
            ),
            "max_inflight_per_participant": int(entry["max_inflight_per_participant"]),
            "max_inflight_per_agent": int(entry["max_inflight_per_agent"]),
            "sandbox_profile": sandbox_profile,
            "executor_policy": executor_policy,
            "rate_limit": _normalize_rate_limit(entry["rate_limit"], source),
        }
        if risk_level >= HIGH_RISK_LEVEL and sandbox_profile != "sandbox-high-risk" and executor_policy.get("requires_isolation"):
            raise ValueError(f"{source}: capability requires high-risk sandbox isolation")
    return registry


def _normalize_selection_policy(value: Any, source: str) -> Dict[str, Any]:
    if isinstance(value, str):
        if value != "metadata-score":
            raise ValueError(f"{source}: unsupported selection_policy {value!r}")
        return dict(DEFAULT_METADATA_SCORE_POLICY)
    if not isinstance(value, Mapping):
        raise ValueError(f"{source}: selection_policy must be object or 'metadata-score'")
    merged = dict(DEFAULT_METADATA_SCORE_POLICY)
    for key, raw in value.items():
        if key not in merged:
            raise ValueError(f"{source}: unsupported selection_policy key {key!r}")
        if not isinstance(raw, bool):
            raise ValueError(f"{source}: selection_policy.{key} must be bool")
        merged[key] = raw
    return merged


def _load_broker_registry(capability_registry: Mapping[str, Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    raw = _broker_registry_config()
    registry: Dict[str, Dict[str, Any]] = {}
    for entry in raw["brokers"]:
        broker_id = str(entry["broker_id"])
        source = f"broker_registry:{broker_id}"
        capability_domains = tuple(str(value) for value in entry["capability_domains"])
        for capability_domain in capability_domains:
            if capability_domain not in capability_registry:
                raise ValueError(
                    f"{source}: unknown capability domain {capability_domain!r} in broker registry"
                )
        registry[broker_id] = {
            "capability_domains": capability_domains,
            "policy_controlled": bool(entry["policy_controlled"]),
            "runtime_identity_mode": str(entry["runtime_identity_mode"]),
            "selection_policy": _normalize_selection_policy(entry["selection_policy"], source),
        }
    for capability_domain, capability_meta in capability_registry.items():
        broker_id = str(capability_meta["broker_id"])
        broker_meta = registry.get(broker_id)
        if broker_meta is None:
            raise ValueError(
                f"capability_registry:{capability_domain}: broker_id {broker_id!r} missing from broker registry"
            )
        if capability_domain not in broker_meta["capability_domains"]:
            raise ValueError(
                f"broker_registry:{broker_id}: missing capability_domain {capability_domain!r}"
            )
    return registry


def _load_executor_profiles() -> Dict[Tuple[str, str], Dict[str, Any]]:
    raw = _executor_profiles_config()
    profiles: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for entry in raw["profiles"]:
        key = (str(entry["executor_type"]), str(entry["sandbox_profile"]))
        command_schema_mode = str(entry["command_schema_mode"])
        if command_schema_mode != "parameter_schema_id":
            raise ValueError(
                f"executor_profiles:{key[0]}/{key[1]}: unsupported command_schema_mode {command_schema_mode!r}"
            )
        profiles[key] = {
            "network_policy": str(entry["network_policy"]),
            "resource_limits": dict(entry["resource_limits"]),
            "short_lived": bool(entry["short_lived"]),
            "inherited_env_keys": tuple(entry["inherited_env_keys"]),
            "command_schema_mode": command_schema_mode,
            "structured_payload_only": bool(entry["structured_payload_only"]),
            "risk_tier": str(entry.get("risk_tier", "low")),
            "forbidden_payload_keys": tuple(entry.get("forbidden_payload_keys", ())),
            "sandbox_ready": bool(entry["sandbox_ready"]),
            "runtime_identity_mode": str(entry["runtime_identity_mode"]),
            "required_hooks": tuple(entry.get("required_hooks", ())),
            "deny_on_unenforced": bool(entry.get("deny_on_unenforced", False)),
            "enforce_no_new_privs": bool(entry.get("enforce_no_new_privs", True)),
        }
    return profiles


class ArchitectureRuntime:
    def __init__(self):
        self.CAPABILITY_DOMAIN_REGISTRY = _load_capability_domain_registry()
        self.EXECUTOR_PROFILE_REGISTRY = _load_executor_profiles()
        self.BROKER_REGISTRY = _load_broker_registry(self.CAPABILITY_DOMAIN_REGISTRY)

        self.CAPABILITY_DOMAIN_IDS = {
            name: int(meta["capability_id"]) for name, meta in self.CAPABILITY_DOMAIN_REGISTRY.items()
        }
        self.CAPABILITY_REQUIRED_CAPS = {
            name: int(meta["required_caps"]) for name, meta in self.CAPABILITY_DOMAIN_REGISTRY.items()
        }
        self.DEFAULT_BROKERS = {
            name: str(meta["broker_id"]) for name, meta in self.CAPABILITY_DOMAIN_REGISTRY.items()
        }
        self.CAPABILITY_CLASSES = {
            name: str(meta["capability_class"]) for name, meta in self.CAPABILITY_DOMAIN_REGISTRY.items()
        }
        self.CAPABILITY_AUTH_MODES = {
            name: str(meta["auth_mode"]) for name, meta in self.CAPABILITY_DOMAIN_REGISTRY.items()
        }
        self.CAPABILITY_SIDE_EFFECTS = {
            name: bool(meta["allows_side_effect"]) for name, meta in self.CAPABILITY_DOMAIN_REGISTRY.items()
        }
        self.HIGH_RISK_DOMAINS = frozenset(
            name
            for name, meta in self.CAPABILITY_DOMAIN_REGISTRY.items()
            if int(meta["baseline_risk_level"]) >= HIGH_RISK_LEVEL
        )
        
        auth_modes = load_server_defaults_config().get("auth_modes", [])
        self.AUTH_MODE_TRUST_LEVELS = {
            m["name"]: int(m["trust_level"]) for m in auth_modes
        }
        self.LOW_TRUST_AUTH_MODES = {
            m["name"] for m in auth_modes if m["trust_level"] < 2
        }
        self.STRUCTURED_EXECUTOR_TYPES = {
            profile["executor_type"] for profile in self.EXECUTOR_PROFILE_REGISTRY.values() if profile.get("structured_payload_only")
        }
        self.HIGH_RISK_EXECUTOR_TYPES = {
            profile["executor_type"] for profile in self.EXECUTOR_PROFILE_REGISTRY.values() if profile.get("risk_tier") == "high"
        }
        
        self.BROKER_CAPABILITIES = {
            broker_id: tuple(meta["capability_domains"]) for broker_id, meta in self.BROKER_REGISTRY.items()
        }
        # Assuming ALLOWABLE_RISK_THRESHOLDS existed or is calculated if used
        self.ALLOWABLE_RISK_THRESHOLDS = {
            name: int(meta.get("risk_threshold", 0)) for name, meta in self.BROKER_REGISTRY.items()
        }

_RUNTIME_INSTANCE = None

def init_architecture_runtime():
    global _RUNTIME_INSTANCE
    if _RUNTIME_INSTANCE is None:
        _RUNTIME_INSTANCE = ArchitectureRuntime()
    return _RUNTIME_INSTANCE

def get_runtime():
    if _RUNTIME_INSTANCE is None:
        init_architecture_runtime()  # Lazy initialization!
    return _RUNTIME_INSTANCE

def __getattr__(name):
    if name in ["AUTH_MODE_TRUST_LEVELS", "LOW_TRUST_AUTH_MODES", "STRUCTURED_EXECUTOR_TYPES", "HIGH_RISK_EXECUTOR_TYPES", "CAPABILITY_DOMAIN_REGISTRY", "EXECUTOR_PROFILE_REGISTRY", "BROKER_REGISTRY", 
                "CAPABILITY_DOMAIN_IDS", "CAPABILITY_REQUIRED_CAPS", "DEFAULT_BROKERS", 
                "CAPABILITY_CLASSES", "CAPABILITY_AUTH_MODES", "CAPABILITY_SIDE_EFFECTS", 
                "HIGH_RISK_DOMAINS", "BROKER_CAPABILITIES", "ALLOWABLE_RISK_THRESHOLDS"]:
        return getattr(get_runtime(), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")



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
    risk_tier: str
    forbidden_payload_keys: Tuple[str, ...]
    sandbox_ready: bool
    runtime_identity_mode: str
    required_hooks: Tuple[str, ...]
    deny_on_unenforced: bool
    enforce_no_new_privs: bool


@dataclass(frozen=True)
class BrokerDispatchPlan:
    capability: CapabilityDomain
    broker: BrokerDef
    provider: ProviderDef
    action: ProviderAction
    executor: ExecutorBinding
    audit_markers: Tuple[str, ...] = ()
    explanation: Dict[str, Any] = field(default_factory=dict)


def build_executor_binding(provider: ProviderDef, action: ProviderAction) -> ExecutorBinding:
    capability_meta = get_runtime().CAPABILITY_DOMAIN_REGISTRY.get(action.capability_domain)
    if capability_meta is None:
        raise ValueError(f"unknown capability domain for executor binding: {action.capability_domain}")
    sandbox_profile = str(capability_meta["sandbox_profile"])
    executor_policy = dict(capability_meta["executor_policy"])
    allowed_executor_types = tuple(executor_policy.get("allowed_executor_types", ()))
    if allowed_executor_types and action.executor_type not in allowed_executor_types:
        raise ValueError(
            f"executor_type {action.executor_type!r} violates configured capability policy for {action.capability_domain}"
        )
    profile = get_runtime().EXECUTOR_PROFILE_REGISTRY.get((action.executor_type, sandbox_profile))
    if profile is None:
        raise ValueError(
            "missing executor profile for "
            f"executor_type={action.executor_type!r} sandbox_profile={sandbox_profile!r}"
        )
    server_defaults = load_server_defaults_config()
    workdir_root = str(server_defaults["executor_workdir_root"]).rstrip("/")
    if not workdir_root:
        raise ValueError("server_defaults executor_workdir_root must be non-empty")
    return ExecutorBinding(
        executor_id=f"{provider.provider_id}:{action.action_name}:exec",
        executor_type=action.executor_type,
        parameter_schema_id=action.parameter_schema_id,
        short_lived=bool(profile["short_lived"]),
        sandbox_profile=sandbox_profile,
        working_directory=f"{workdir_root}/{provider.provider_id}",
        network_policy=str(profile["network_policy"]),
        resource_limits=dict(profile["resource_limits"]),
        inherited_env_keys=tuple(profile["inherited_env_keys"]),
        command_schema_id=action.parameter_schema_id,
        structured_payload_only=bool(profile["structured_payload_only"]),
        risk_tier=str(profile.get("risk_tier", "low")),
        forbidden_payload_keys=tuple(profile.get("forbidden_payload_keys", ())),
        sandbox_ready=bool(profile["sandbox_ready"]),
        runtime_identity_mode=str(profile["runtime_identity_mode"]),
        required_hooks=tuple(profile.get("required_hooks", ())),
        deny_on_unenforced=bool(profile.get("deny_on_unenforced", False)),
        enforce_no_new_privs=bool(profile.get("enforce_no_new_privs", True)),
    )


def _trust_class_rank(trust_class: str) -> int:
    return get_runtime().AUTH_MODE_TRUST_LEVELS.get(trust_class, 0)


def explain_executor_binding_for_capability(
    capability: CapabilityDomain,
    provider: ProviderDef,
    action: ProviderAction,
    executor: ExecutorBinding,
) -> Dict[str, Any]:
    return evaluate_executor_binding(
        capability,
        provider,
        action,
        executor,
        trust_class_ranks=get_runtime().AUTH_MODE_TRUST_LEVELS,
    ).as_dict()


def validate_executor_binding_for_capability(
    capability: CapabilityDomain,
    provider: ProviderDef,
    action: ProviderAction,
    executor: ExecutorBinding,
) -> None:
    explanation = explain_executor_binding_for_capability(capability, provider, action, executor)
    if not explanation["allowed"]:
        reason_codes = explanation.get("reason_codes", [])
        details = explanation.get("details", {})
        raise ValueError(
            f"executor binding rejected for {capability.name}: "
            f"{','.join(reason_codes) or 'policy_violation'} details={details}"
        )


def explain_capability_request(
    planner: Mapping[str, Any],
    capability: CapabilityDomain,
    intent: Mapping[str, Any],
) -> Dict[str, Any]:
    return evaluate_capability_request(
        planner,
        capability,
        intent,
        high_risk_level=HIGH_RISK_LEVEL,
        approval_mode_trusted=APPROVAL_MODE_TRUSTED,
        approval_mode_root_only=APPROVAL_MODE_ROOT_ONLY,
        approval_mode_interactive=APPROVAL_MODE_INTERACTIVE,
        approval_mode_explicit=APPROVAL_MODE_EXPLICIT,
    ).as_dict()


def validate_capability_request(
    planner: Mapping[str, Any],
    capability: CapabilityDomain,
    intent: Mapping[str, Any],
) -> Tuple[str, ...]:
    explanation = explain_capability_request(planner, capability, intent)
    if not explanation["allowed"]:
        reason_codes = explanation.get("reason_codes", [])
        details = explanation.get("details", {})
        raise ValueError(
            f"capability request rejected for {capability.name}: "
            f"{','.join(reason_codes) or 'policy_violation'} details={details}"
        )
    return tuple(str(marker) for marker in explanation.get("audit_markers", []))


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
    if executor_type not in get_runtime().STRUCTURED_EXECUTOR_TYPES:
        raise ValueError(f"{source}: unsupported executor_type {executor_type!r}")
    if risk_level >= HIGH_RISK_LEVEL and executor_type not in get_runtime().HIGH_RISK_EXECUTOR_TYPES:
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
    if action.auth_required and capability_auth_mode in get_runtime().LOW_TRUST_AUTH_MODES:
        raise ValueError(
            f"{source}: auth-required action {action.action_name} cannot map to low-trust capability {action.capability_domain}"
        )
    if not allows_side_effect and action.side_effect:
        raise ValueError(
            f"{source}: side-effect action {action.action_name} cannot map to read-only capability {action.capability_domain}"
        )
    if not allows_side_effect and _looks_like_write_or_exec(
        action.action_name, action.handler, action.name, action.description
    ):
        raise ValueError(
            f"{source}: write/exec-like action {action.action_name} mapped to read-only capability {action.capability_domain}"
        )

    # Note: info.lookup specific hardcoded check has been removed as per user request
    if provider.auth_mode in get_runtime().LOW_TRUST_AUTH_MODES and action.auth_required:
        raise ValueError(
            f"{source}: provider {provider.provider_id} auth_mode incompatible with auth-required action {action.action_name}"
        )
    if action.executor_type in get_runtime().STRUCTURED_EXECUTOR_TYPES and not action.parameter_schema_id:
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
        if capability_domain not in get_runtime().CAPABILITY_DOMAIN_REGISTRY:
            raise ValueError(f"{action_source}: unknown capability_domain {capability_domain!r}")
        capability_meta = get_runtime().CAPABILITY_DOMAIN_REGISTRY[capability_domain]
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
        if executor_type in get_runtime().STRUCTURED_EXECUTOR_TYPES and not input_schema:
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
        _validate_action_schema_contract(action, get_runtime().CAPABILITY_DOMAIN_REGISTRY[action.capability_domain], provider, source)
    return provider


# ---------------------------------------------------------------------------
# capability catalog construction

def build_capability_catalog(providers: Iterable[ProviderDef]) -> Dict[str, CapabilityDomain]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for provider in providers:
        for action in provider.actions.values():
            capability_domain = action.capability_domain
            if capability_domain not in get_runtime().CAPABILITY_DOMAIN_REGISTRY:
                raise ValueError(f"unknown capability_domain in provider catalog: {capability_domain}")
            entry = grouped.setdefault(
                capability_domain,
                {
                    "provider_ids": set(),
                    "action_ids": set(),
                    "perm": 0,
                    "cost": 0,
                    "risk_level": int(get_runtime().CAPABILITY_DOMAIN_REGISTRY[capability_domain]["baseline_risk_level"]),
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
        meta = get_runtime().CAPABILITY_DOMAIN_REGISTRY[capability_domain]
        capability_description = str(
            meta.get(
                "description",
                f"Capability domain {capability_domain} mediated by {meta['broker_id']}.",
            )
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
        broker_id: set() for broker_id in get_runtime().BROKER_REGISTRY
    }
    for provider in providers:
        for action in provider.actions.values():
            capability = capabilities.get(action.capability_domain)
            if capability is None:
                raise ValueError(f"missing capability catalog entry for {action.capability_domain}")
            provider_ids_by_broker.setdefault(capability.broker_id, set()).add(provider.provider_id)

    out: Dict[str, BrokerDef] = {}
    for broker_id, broker_meta in get_runtime().BROKER_REGISTRY.items():
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
) -> Tuple[ProviderDef, ProviderAction, Tuple[str, ...], Dict[str, Any]]:
    candidate_pairs = list(candidate_actions)
    policy = dict(broker_policy or {})
    availability = provider_availability or {}
    require_provider_availability = bool(policy.get("require_provider_availability", True))
    prefer_lower_risk_on_tie = bool(policy.get("prefer_lower_risk_on_tie", True))
    allow_preferred_high_risk = bool(policy.get("allow_preferred_provider_high_risk", False))

    intent_tokens = _tokenize_text(intent_text)
    available_candidates: List[Tuple[ProviderDef, ProviderAction]] = []
    markers: List[str] = []
    explanation_candidates: List[Dict[str, Any]] = []
    for provider, action in candidate_pairs:
        is_available = availability.get(provider.provider_id, True)
        if require_provider_availability and not is_available:
            explanation_candidates.append(
                {
                    "provider_id": provider.provider_id,
                    "action_id": action.action_id,
                    "action_name": action.action_name,
                    "available": False,
                    "eligible": False,
                    "eligibility_reason": "provider_unavailable",
                    "provider_trust_class": provider.trust_class,
                    "risk_level": action.risk_level,
                    "selection_priority": action.selection_priority,
                }
            )
            continue
        if capability is not None:
            try:
                validate_executor_binding_for_capability(
                    capability,
                    provider,
                    action,
                    build_executor_binding(provider, action),
                )
            except ValueError as exc:
                explanation_candidates.append(
                    {
                        "provider_id": provider.provider_id,
                        "action_id": action.action_id,
                        "action_name": action.action_name,
                        "available": is_available,
                        "eligible": False,
                        "eligibility_reason": "capability_policy_violation",
                        "policy_error": str(exc),
                        "provider_trust_class": provider.trust_class,
                        "risk_level": action.risk_level,
                        "selection_priority": action.selection_priority,
                    }
                )
                continue
        available_candidates.append((provider, action))
        explanation_candidates.append(
            {
                "provider_id": provider.provider_id,
                "action_id": action.action_id,
                "action_name": action.action_name,
                "available": is_available,
                "eligible": True,
                "eligibility_reason": "eligible",
                "provider_trust_class": provider.trust_class,
                "risk_level": action.risk_level,
                "selection_priority": action.selection_priority,
            }
        )
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
        for candidate in explanation_candidates:
            if (
                candidate.get("provider_id") == provider.provider_id
                and candidate.get("action_id") == action.action_id
            ):
                candidate["score"] = score
                candidate["tie_risk_rank"] = tie_risk
                candidate["provider_trust_rank"] = provider_trust
                candidate["rank_tuple"] = list(rank)
                break
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
    explanation: Dict[str, Any] = {
        "intent_text": intent_text,
        "intent_tokens": list(intent_tokens),
        "broker_policy": dict(policy),
        "preferred_provider_id": preferred_provider_id,
        "allow_preferred_provider": allow_preferred_provider,
        "candidate_count": len(candidate_pairs),
        "eligible_count": len(available_candidates),
        "resolver_markers": list(markers),
        "candidates": explanation_candidates,
        "selected": {
            "provider_id": selected_provider.provider_id,
            "action_id": selected_action.action_id,
            "action_name": selected_action.action_name,
            "provider_trust_class": selected_provider.trust_class,
            "risk_level": selected_action.risk_level,
            "selection_priority": selected_action.selection_priority,
            "score": best[0],
        },
    }
    for candidate in explanation_candidates:
        candidate["selected"] = (
            candidate.get("provider_id") == selected_provider.provider_id
            and candidate.get("action_id") == selected_action.action_id
        )
    return selected_provider, selected_action, tuple(markers), explanation


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

    provider, action, markers, action_resolution = resolve_action_for_capability(
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
    executor_binding = explain_executor_binding_for_capability(capability, provider, action, executor)
    return BrokerDispatchPlan(
        capability=capability,
        broker=broker,
        provider=provider,
        action=action,
        executor=executor,
        audit_markers=markers,
        explanation={
            "action_resolution": action_resolution,
            "executor_binding": executor_binding,
        },
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
