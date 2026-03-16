#!/usr/bin/env python3
"""Policy evaluation helpers for broker-side capability gating and executor safety."""

from __future__ import annotations

from typing import Any, Mapping

from policy_types import PolicyDecision


def _read_attr(obj: Any, name: str, default: Any = None) -> Any:
    if hasattr(obj, name):
        return getattr(obj, name)
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return default


def _int_attr(obj: Any, name: str, default: int = 0) -> int:
    value = _read_attr(obj, name, default)
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _str_attr(obj: Any, name: str, default: str = "") -> str:
    value = _read_attr(obj, name, default)
    if value is None:
        return default
    return str(value)


def _bool_attr(obj: Any, name: str, default: bool = False) -> bool:
    value = _read_attr(obj, name, default)
    return bool(value)


def evaluate_capability_request(
    planner: Mapping[str, Any],
    capability: Any,
    intent: Mapping[str, Any],
    *,
    high_risk_level: int,
    approval_mode_trusted: int,
    approval_mode_root_only: int,
    approval_mode_interactive: int,
    approval_mode_explicit: int,
) -> PolicyDecision:
    participant_id = _str_attr(planner, "participant_id", "unknown")
    caps = _int_attr(planner, "caps", 0)
    trust_level = _int_attr(planner, "trust_level", 0)
    required_caps = _int_attr(capability, "required_caps", 0)
    capability_name = _str_attr(capability, "name", "unknown")
    approval_mode = _int_attr(capability, "approval_mode", 0)
    risk_level = _int_attr(capability, "risk_level", 0)
    executor_policy = dict(_read_attr(capability, "executor_policy", {}) or {})
    min_planner_trust = int(executor_policy.get("min_planner_trust_level", 0) or 0)
    interactive = bool(intent.get("interactive", False))
    explicit_approval = bool(intent.get("explicit_approval", False))
    approval_token = str(intent.get("approval_token", "") or "")

    reason_codes = []
    audit_markers = []
    require_approval = approval_mode in {
        approval_mode_trusted,
        approval_mode_root_only,
        approval_mode_interactive,
        approval_mode_explicit,
    }
    required_executor_constraints = {
        "min_planner_trust_level": min_planner_trust,
        "allowed_executor_types": list(executor_policy.get("allowed_executor_types", ())),
        "network_policy": executor_policy.get("network_policy", ""),
        "sandbox_profile": _str_attr(capability, "sandbox_profile", ""),
    }

    if (caps & required_caps) != required_caps:
        return PolicyDecision(
            allowed=False,
            require_approval=require_approval,
            decision="deny",
            deny_reason="participant missing required capability bits",
            reason_codes=("missing_required_caps",),
            required_executor_constraints=required_executor_constraints,
            details={
                "participant_id": participant_id,
                "capability_domain": capability_name,
                "required_caps": required_caps,
                "participant_caps": caps,
            },
        )

    if trust_level < min_planner_trust:
        return PolicyDecision(
            allowed=False,
            require_approval=require_approval,
            decision="deny",
            deny_reason="planner trust level below capability minimum",
            reason_codes=("planner_trust_below_minimum",),
            required_executor_constraints=required_executor_constraints,
            details={
                "participant_id": participant_id,
                "capability_domain": capability_name,
                "trust_level": trust_level,
                "min_planner_trust_level": min_planner_trust,
            },
        )

    if approval_mode == approval_mode_interactive and not interactive:
        return PolicyDecision(
            allowed=False,
            require_approval=True,
            decision="deny",
            deny_reason="interactive approval context required",
            reason_codes=("interactive_approval_required",),
            required_executor_constraints=required_executor_constraints,
            details={
                "participant_id": participant_id,
                "capability_domain": capability_name,
                "approval_mode": approval_mode,
            },
        )

    if approval_mode == approval_mode_explicit:
        reason_codes.append("explicit_approval_policy")
        if explicit_approval or approval_token:
            audit_markers.append("approval_mode_explicit_signaled")
        else:
            audit_markers.append("approval_mode_explicit_kernel_pending")

    if approval_mode == approval_mode_trusted and trust_level < high_risk_level:
        return PolicyDecision(
            allowed=False,
            require_approval=True,
            decision="deny",
            deny_reason="trusted planner context required",
            reason_codes=("trusted_context_required",),
            required_executor_constraints=required_executor_constraints,
            details={
                "participant_id": participant_id,
                "capability_domain": capability_name,
                "approval_mode": approval_mode,
                "trust_level": trust_level,
                "required_trust_level": high_risk_level,
            },
        )

    if approval_mode == approval_mode_root_only and not (explicit_approval or approval_token):
        reason_codes.append("root_only_kernel_enforced")
        audit_markers.append("approval_mode_root_only_kernel_enforced")

    if risk_level >= high_risk_level:
        reason_codes.append("high_risk_capability")
        audit_markers.append("high_risk_capability")

    return PolicyDecision(
        allowed=True,
        require_approval=require_approval,
        decision="allow",
        reason_codes=tuple(reason_codes),
        audit_markers=tuple(audit_markers),
        required_executor_constraints=required_executor_constraints,
        details={
            "participant_id": participant_id,
            "capability_domain": capability_name,
            "required_caps": required_caps,
            "participant_caps": caps,
            "trust_level": trust_level,
            "min_planner_trust_level": min_planner_trust,
            "approval_mode": approval_mode,
            "risk_level": risk_level,
            "interactive": interactive,
            "explicit_approval": explicit_approval,
            "approval_token_present": bool(approval_token),
        },
    )


def evaluate_executor_binding(
    capability: Any,
    provider: Any,
    action: Any,
    executor: Any,
    *,
    trust_class_ranks: Mapping[str, int],
) -> PolicyDecision:
    capability_name = _str_attr(capability, "name", "unknown")
    capability_policy = dict(_read_attr(capability, "executor_policy", {}) or {})
    allowed_executor_types = tuple(capability_policy.get("allowed_executor_types", ()))
    executor_type = _str_attr(executor, "executor_type")
    network_policy = _str_attr(executor, "network_policy")
    sandbox_profile = _str_attr(executor, "sandbox_profile")
    short_lived = _bool_attr(executor, "short_lived", False)
    provider_trust = _str_attr(provider, "trust_class", "anonymous")
    min_provider_trust = str(capability_policy.get("min_provider_trust_class", "anonymous"))

    def rank(value: str) -> int:
        return int(trust_class_ranks.get(value, 0))

    if allowed_executor_types and executor_type not in allowed_executor_types:
        return PolicyDecision(
            allowed=False,
            require_approval=False,
            decision="deny",
            deny_reason="executor type is not allowed by capability policy",
            reason_codes=("executor_type_not_allowed",),
            required_executor_constraints={
                "allowed_executor_types": list(allowed_executor_types),
                "required_network_policy": capability_policy.get("network_policy", ""),
                "required_sandbox_profile": _str_attr(capability, "sandbox_profile"),
            },
            details={
                "capability_domain": capability_name,
                "executor_type": executor_type,
                "allowed_executor_types": list(allowed_executor_types),
            },
        )

    required_network_policy = str(capability_policy.get("network_policy", network_policy))
    if required_network_policy and network_policy != required_network_policy:
        return PolicyDecision(
            allowed=False,
            require_approval=False,
            decision="deny",
            deny_reason="executor network policy does not satisfy capability policy",
            reason_codes=("executor_network_policy_mismatch",),
            required_executor_constraints={
                "allowed_executor_types": list(allowed_executor_types),
                "required_network_policy": required_network_policy,
                "required_sandbox_profile": _str_attr(capability, "sandbox_profile"),
            },
            details={
                "capability_domain": capability_name,
                "executor_network_policy": network_policy,
                "required_network_policy": required_network_policy,
            },
        )

    if bool(capability_policy.get("require_short_lived", False)) and not short_lived:
        return PolicyDecision(
            allowed=False,
            require_approval=False,
            decision="deny",
            deny_reason="executor must be short-lived",
            reason_codes=("executor_must_be_short_lived",),
            required_executor_constraints={
                "require_short_lived": True,
                "required_sandbox_profile": _str_attr(capability, "sandbox_profile"),
            },
            details={
                "capability_domain": capability_name,
                "executor_type": executor_type,
            },
        )

    if bool(capability_policy.get("deny_on_unenforced", False)) and not _bool_attr(
        executor,
        "deny_on_unenforced",
        False,
    ):
        return PolicyDecision(
            allowed=False,
            require_approval=False,
            decision="deny",
            deny_reason="executor must deny on unenforced isolation requirements",
            reason_codes=("executor_deny_on_unenforced_required",),
            required_executor_constraints={
                "deny_on_unenforced": True,
                "required_sandbox_profile": _str_attr(capability, "sandbox_profile"),
            },
            details={
                "capability_domain": capability_name,
                "executor_type": executor_type,
                "sandbox_profile": sandbox_profile,
            },
        )

    capability_sandbox = _str_attr(capability, "sandbox_profile")
    if capability_sandbox and sandbox_profile != capability_sandbox:
        return PolicyDecision(
            allowed=False,
            require_approval=False,
            decision="deny",
            deny_reason="executor sandbox profile does not match capability policy",
            reason_codes=("sandbox_profile_mismatch",),
            required_executor_constraints={
                "required_sandbox_profile": capability_sandbox,
                "allowed_executor_types": list(allowed_executor_types),
            },
            details={
                "capability_domain": capability_name,
                "executor_sandbox_profile": sandbox_profile,
                "required_sandbox_profile": capability_sandbox,
            },
        )

    if rank(provider_trust) < rank(min_provider_trust):
        return PolicyDecision(
            allowed=False,
            require_approval=False,
            decision="deny",
            deny_reason="provider trust class below capability minimum",
            reason_codes=("provider_trust_below_minimum",),
            required_executor_constraints={
                "min_provider_trust_class": min_provider_trust,
            },
            details={
                "capability_domain": capability_name,
                "provider_trust_class": provider_trust,
                "min_provider_trust_class": min_provider_trust,
            },
        )

    action_executor_type = _str_attr(action, "executor_type")
    if action_executor_type != executor_type:
        return PolicyDecision(
            allowed=False,
            require_approval=False,
            decision="deny",
            deny_reason="executor binding does not match action executor type",
            reason_codes=("action_executor_type_mismatch",),
            required_executor_constraints={
                "action_executor_type": action_executor_type,
            },
            details={
                "capability_domain": capability_name,
                "action_executor_type": action_executor_type,
                "binding_executor_type": executor_type,
            },
        )

    return PolicyDecision(
        allowed=True,
        require_approval=False,
        decision="allow",
        reason_codes=("executor_binding_allowed",),
        required_executor_constraints={
            "allowed_executor_types": list(allowed_executor_types),
            "required_network_policy": capability_policy.get("network_policy", ""),
            "required_sandbox_profile": _str_attr(capability, "sandbox_profile"),
            "min_provider_trust_class": min_provider_trust,
        },
        details={
            "capability_domain": capability_name,
            "executor_type": executor_type,
            "network_policy": network_policy,
            "sandbox_profile": sandbox_profile,
            "provider_trust_class": provider_trust,
            "min_provider_trust_class": min_provider_trust,
            "short_lived": short_lived,
        },
    )
