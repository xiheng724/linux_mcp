#!/usr/bin/env python3
"""Package/definition control plane loader for mcpd."""

from __future__ import annotations

import json
import warnings
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Mapping

import yaml

ROOT_DIR = Path(__file__).resolve().parents[2]
CONTROLPLANE_DIR = ROOT_DIR / "mcpd" / "controlplane"
SCHEMA_DIR = CONTROLPLANE_DIR / "_schema"
API_VERSION = "mcpd/v1"
MCPD_RUNTIME_VERSION = "1.0.0"
HIGH_RISK_LEVEL = 7

KIND_SUBDIRS = {
    "CapabilityPackage": "packages",
    "BrokerDefinition": "definitions/brokers",
    "ExecutorDefinition": "definitions/executors",
    "PolicyDefinition": "definitions/policies",
    "ServerConfig": "platform",
}
KIND_SCHEMAS = {
    "CapabilityPackage": "package.schema.json",
    "BrokerDefinition": "broker.schema.json",
    "ExecutorDefinition": "executor.schema.json",
    "PolicyDefinition": "policy.schema.json",
    "ServerConfig": "server.schema.json",
}


@dataclass(frozen=True)
class ArtifactMetadata:
    name: str
    version: str
    labels: Dict[str, str]
    annotations: Dict[str, str]
    deprecated: bool
    replaced_by: str | None
    introduced_in: str
    requires_mcpd_version: str


@dataclass(frozen=True)
class Artifact:
    api_version: str
    kind: str
    metadata: ArtifactMetadata
    spec: Dict[str, Any]
    source: str


@dataclass(frozen=True)
class ArtifactStore:
    base_dir: Path
    packages: Dict[str, Artifact]
    brokers: Dict[str, Artifact]
    executors: Dict[str, Artifact]
    policies: Dict[str, Artifact]
    platform: Dict[str, Artifact]

    @property
    def server_config(self) -> Artifact:
        if not self.platform:
            raise ValueError("controlplane: missing ServerConfig artifact")
        if len(self.platform) != 1:
            raise ValueError("controlplane: exactly one ServerConfig artifact is required")
        return next(iter(self.platform.values()))


def _schema_dir(base_dir: Path) -> Path:
    return base_dir / "_schema"


def _ensure_object(name: str, value: Any, source: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{source}: {name} must be object")
    return dict(value)


def _ensure_str(name: str, value: Any, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{source}: {name} must be non-empty string")
    return value.strip()


def _ensure_bool(name: str, value: Any, source: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{source}: {name} must be bool")
    return value


def _ensure_int(name: str, value: Any, source: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{source}: {name} must be int")
    return int(value)


def _ensure_list(name: str, value: Any, source: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{source}: {name} must be list")
    return list(value)


def _ensure_string_list(name: str, value: Any, source: str) -> list[str]:
    return [_ensure_str(f"{name}[{idx}]", item, source) for idx, item in enumerate(_ensure_list(name, value, source))]


def _ensure_string_dict(name: str, value: Any, source: str) -> Dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{source}: {name} must be object")
    out: Dict[str, str] = {}
    for key, item in value.items():
        out[_ensure_str(f"{name}.key", key, source)] = _ensure_str(f"{name}[{key!r}]", item, source)
    return out


def _version_satisfies(requirement: str, current_version: str = MCPD_RUNTIME_VERSION) -> bool:
    requirement = requirement.strip()
    if not requirement or requirement == "*":
        return True
    if requirement.startswith(">="):
        return current_version >= requirement[2:].strip()
    if requirement.startswith("=="):
        return current_version == requirement[2:].strip()
    return current_version == requirement


@lru_cache(maxsize=None)
def _load_schema(base_dir: Path, schema_name: str) -> Dict[str, Any]:
    schema_path = _schema_dir(base_dir) / schema_name
    if not schema_path.is_file():
        raise ValueError(f"controlplane: missing schema {schema_path}")
    try:
        return json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{schema_path}: unable to read schema: {exc}") from exc


def _load_yaml(path: Path) -> Dict[str, Any]:
    source = str(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{source}: unable to read artifact: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"{source}: invalid YAML: {exc}") from exc
    return _ensure_object("artifact", raw, source)


def _validate_metadata(raw: Any, source: str) -> ArtifactMetadata:
    metadata = _ensure_object("metadata", raw, source)
    artifact = ArtifactMetadata(
        name=_ensure_str("metadata.name", metadata.get("name"), source),
        version=_ensure_str("metadata.version", metadata.get("version", "1.0.0"), source),
        labels=_ensure_string_dict("metadata.labels", metadata.get("labels", {}), source),
        annotations=_ensure_string_dict("metadata.annotations", metadata.get("annotations", {}), source),
        deprecated=_ensure_bool("metadata.deprecated", metadata.get("deprecated", False), source),
        replaced_by=str(metadata.get("replaced_by") or "") or None,
        introduced_in=_ensure_str("metadata.introduced_in", metadata.get("introduced_in", "1.0.0"), source),
        requires_mcpd_version=_ensure_str(
            "metadata.requires_mcpd_version",
            metadata.get("requires_mcpd_version", ">=1.0.0"),
            source,
        ),
    )
    if not _version_satisfies(artifact.requires_mcpd_version):
        raise ValueError(
            f"{source}: requires_mcpd_version {artifact.requires_mcpd_version!r} "
            f"is incompatible with runtime {MCPD_RUNTIME_VERSION}"
        )
    if artifact.deprecated:
        replacement = f" replaced_by={artifact.replaced_by}" if artifact.replaced_by else ""
        warnings.warn(f"{source}: deprecated artifact in use.{replacement}", RuntimeWarning)
    return artifact


def _validate_against_schema(document: Mapping[str, Any], kind: str, base_dir: Path, source: str) -> None:
    schema = _load_schema(base_dir, KIND_SCHEMAS[kind])
    required = schema.get("required", [])
    if isinstance(required, list):
        for field in required:
            if field not in document:
                raise ValueError(f"{source}: schema validation failed: missing required field {field!r}")
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return
    for field_name, field_schema in properties.items():
        if field_name not in document or not isinstance(field_schema, Mapping):
            continue
        expected_const = field_schema.get("const")
        if expected_const is not None and document.get(field_name) != expected_const:
            raise ValueError(
                f"{source}: schema validation failed at {field_name}: expected {expected_const!r}"
            )
        expected_type = field_schema.get("type")
        value = document.get(field_name)
        if expected_type == "object" and not isinstance(value, dict):
            raise ValueError(
                f"{source}: schema validation failed at {field_name}: expected object"
            )
        if expected_type == "array" and not isinstance(value, list):
            raise ValueError(
                f"{source}: schema validation failed at {field_name}: expected array"
            )
        if expected_type == "string" and not isinstance(value, str):
            raise ValueError(
                f"{source}: schema validation failed at {field_name}: expected string"
            )


def _validate_package_spec(spec: Any, source: str) -> Dict[str, Any]:
    data = _ensure_object("spec", spec, source)
    capability = _ensure_object("spec.capability", data.get("capability"), source)
    out = {
        "capability": {
            "capability_id": capability.get("capability_id"),
            "required_caps": _ensure_string_list("spec.capability.required_caps", capability.get("required_caps"), source),
            "capability_class": _ensure_str(
                "spec.capability.capability_class",
                capability.get("capability_class"),
                source,
            ),
            "risk_level": capability.get("risk_level"),
            "allows_side_effect": _ensure_bool(
                "spec.capability.allows_side_effect",
                capability.get("allows_side_effect"),
                source,
            ),
            "auth_mode": _ensure_str("spec.capability.auth_mode", capability.get("auth_mode"), source),
        },
        "broker_ref": _ensure_str("spec.broker_ref", data.get("broker_ref"), source),
        "policy_ref": _ensure_str("spec.policy_ref", data.get("policy_ref"), source),
        "executor_ref": _ensure_str("spec.executor_ref", data.get("executor_ref"), source),
        "provider_requirements": {
            "manifests": _ensure_string_list(
                "spec.provider_requirements.manifests",
                _ensure_object(
                    "spec.provider_requirements",
                    data.get("provider_requirements", {"manifests": []}),
                    source,
                ).get("manifests", []),
                source,
            ),
        },
        "description": _ensure_str("spec.description", data.get("description"), source),
    }
    capability_id = out["capability"]["capability_id"]
    if capability_id is not None:
        out["capability"]["capability_id"] = _ensure_int(
            "spec.capability.capability_id",
            capability_id,
            source,
        )
    risk_level = out["capability"]["risk_level"]
    if risk_level is not None:
        out["capability"]["risk_level"] = _ensure_int("spec.capability.risk_level", risk_level, source)
    return out


def _validate_broker_spec(spec: Any, source: str) -> Dict[str, Any]:
    data = _ensure_object("spec", spec, source)
    selection = _ensure_object("spec.selection_policy", data.get("selection_policy"), source)
    selection_policy = {
        key: _ensure_bool(f"spec.selection_policy.{key}", selection.get(key), source)
        for key in (
            "require_provider_availability",
            "prefer_manifest_priority",
            "prefer_example_matches",
            "prefer_lower_risk_on_tie",
            "allow_preferred_provider_high_risk",
        )
    }
    return {
        "selection_policy": selection_policy,
        "runtime_identity_mode": _ensure_str(
            "spec.runtime_identity_mode",
            data.get("runtime_identity_mode"),
            source,
        ),
        "policy_controlled": _ensure_bool("spec.policy_controlled", data.get("policy_controlled"), source),
    }


def _validate_executor_spec(spec: Any, source: str) -> Dict[str, Any]:
    data = _ensure_object("spec", spec, source)
    profiles: list[Dict[str, Any]] = []
    for idx, raw_profile in enumerate(_ensure_list("spec.profiles", data.get("profiles"), source)):
        item = _ensure_object(f"spec.profiles[{idx}]", raw_profile, source)
        env_policy = _ensure_object(f"spec.profiles[{idx}].environment_policy", item.get("environment_policy"), source)
        enforcement = _ensure_object(
            f"spec.profiles[{idx}].enforcement_requirements",
            item.get("enforcement_requirements"),
            source,
        )
        resource_limits = _ensure_object(f"spec.profiles[{idx}].resource_limits", item.get("resource_limits"), source)
        profiles.append(
            {
                "executor_type": _ensure_str(
                    f"spec.profiles[{idx}].executor_type",
                    item.get("executor_type"),
                    source,
                ),
                "sandbox_profile": _ensure_str(
                    f"spec.profiles[{idx}].sandbox_profile",
                    item.get("sandbox_profile"),
                    source,
                ),
                "network_policy": _ensure_str(
                    f"spec.profiles[{idx}].network_policy",
                    item.get("network_policy"),
                    source,
                ),
                "resource_limits": {
                    "cpu_ms": _ensure_int(
                        f"spec.profiles[{idx}].resource_limits.cpu_ms",
                        resource_limits.get("cpu_ms"),
                        source,
                    ),
                    "memory_kb": _ensure_int(
                        f"spec.profiles[{idx}].resource_limits.memory_kb",
                        resource_limits.get("memory_kb"),
                        source,
                    ),
                    "nofile": _ensure_int(
                        f"spec.profiles[{idx}].resource_limits.nofile",
                        resource_limits.get("nofile"),
                        source,
                    ),
                },
                "environment_policy": {
                    "inherited_env_keys": _ensure_string_list(
                        f"spec.profiles[{idx}].environment_policy.inherited_env_keys",
                        env_policy.get("inherited_env_keys"),
                        source,
                    ),
                    "structured_payload_only": _ensure_bool(
                        f"spec.profiles[{idx}].environment_policy.structured_payload_only",
                        env_policy.get("structured_payload_only"),
                        source,
                    ),
                    "command_schema_mode": _ensure_str(
                        f"spec.profiles[{idx}].environment_policy.command_schema_mode",
                        env_policy.get("command_schema_mode"),
                        source,
                    ),
                },
                "enforcement_requirements": {
                    "short_lived": _ensure_bool(
                        f"spec.profiles[{idx}].enforcement_requirements.short_lived",
                        enforcement.get("short_lived"),
                        source,
                    ),
                    "sandbox_ready": _ensure_bool(
                        f"spec.profiles[{idx}].enforcement_requirements.sandbox_ready",
                        enforcement.get("sandbox_ready"),
                        source,
                    ),
                    "runtime_identity_mode": _ensure_str(
                        f"spec.profiles[{idx}].enforcement_requirements.runtime_identity_mode",
                        enforcement.get("runtime_identity_mode"),
                        source,
                    ),
                    "required_hooks": _ensure_string_list(
                        f"spec.profiles[{idx}].enforcement_requirements.required_hooks",
                        enforcement.get("required_hooks", []),
                        source,
                    ),
                    "deny_on_unenforced": _ensure_bool(
                        f"spec.profiles[{idx}].enforcement_requirements.deny_on_unenforced",
                        enforcement.get("deny_on_unenforced"),
                        source,
                    ),
                    "enforce_no_new_privs": _ensure_bool(
                        f"spec.profiles[{idx}].enforcement_requirements.enforce_no_new_privs",
                        enforcement.get("enforce_no_new_privs"),
                        source,
                    ),
                },
            }
        )
    if not profiles:
        raise ValueError(f"{source}: spec.profiles must be non-empty")
    return {"profiles": profiles}


def _validate_policy_spec(spec: Any, source: str) -> Dict[str, Any]:
    data = _ensure_object("spec", spec, source)
    rate_limit = _ensure_object("spec.rate_limit", data.get("rate_limit"), source)
    executor_policy = _ensure_object("spec.executor_policy", data.get("executor_policy"), source)
    return {
        "risk_level": _ensure_int("spec.risk_level", data.get("risk_level"), source),
        "approval_mode": _ensure_str("spec.approval_mode", data.get("approval_mode"), source),
        "audit_mode": _ensure_str("spec.audit_mode", data.get("audit_mode"), source),
        "rate_limit": {
            "enabled": _ensure_bool("spec.rate_limit.enabled", rate_limit.get("enabled"), source),
            "burst": _ensure_int("spec.rate_limit.burst", rate_limit.get("burst"), source),
            "refill_tokens": _ensure_int(
                "spec.rate_limit.refill_tokens",
                rate_limit.get("refill_tokens"),
                source,
            ),
            "refill_jiffies": _ensure_int(
                "spec.rate_limit.refill_jiffies",
                rate_limit.get("refill_jiffies"),
                source,
            ),
            "default_cost": _ensure_int(
                "spec.rate_limit.default_cost",
                rate_limit.get("default_cost"),
                source,
            ),
            "max_inflight_per_participant": _ensure_int(
                "spec.rate_limit.max_inflight_per_participant",
                rate_limit.get("max_inflight_per_participant"),
                source,
            ),
            "defer_wait_ms": _ensure_int(
                "spec.rate_limit.defer_wait_ms",
                rate_limit.get("defer_wait_ms"),
                source,
            ),
        },
        "max_inflight_per_participant": _ensure_int(
            "spec.max_inflight_per_participant",
            data.get("max_inflight_per_participant"),
            source,
        ),
        "max_inflight_per_agent": _ensure_int(
            "spec.max_inflight_per_agent",
            data.get("max_inflight_per_agent"),
            source,
        ),
        "executor_policy": {
            "network_policy": _ensure_str(
                "spec.executor_policy.network_policy",
                executor_policy.get("network_policy"),
                source,
            ),
            "require_short_lived": _ensure_bool(
                "spec.executor_policy.require_short_lived",
                executor_policy.get("require_short_lived"),
                source,
            ),
            "min_planner_trust_level": _ensure_int(
                "spec.executor_policy.min_planner_trust_level",
                executor_policy.get("min_planner_trust_level"),
                source,
            ),
            "min_provider_trust_class": _ensure_str(
                "spec.executor_policy.min_provider_trust_class",
                executor_policy.get("min_provider_trust_class"),
                source,
            ),
            "deny_on_unenforced": _ensure_bool(
                "spec.executor_policy.deny_on_unenforced",
                executor_policy.get("deny_on_unenforced"),
                source,
            ),
        },
    }


def _validate_server_spec(spec: Any, source: str) -> Dict[str, Any]:
    data = _ensure_object("spec", spec, source)
    return {
        "manifest_dirs": _ensure_string_list("spec.manifest_dirs", data.get("manifest_dirs"), source),
        "socket_path": _ensure_str("spec.socket_path", data.get("socket_path"), source),
        "planner_trust_level": _ensure_int("spec.planner_trust_level", data.get("planner_trust_level"), source),
        "broker_trust_level": _ensure_int("spec.broker_trust_level", data.get("broker_trust_level"), source),
        "executor_workdir": _ensure_str("spec.executor_workdir", data.get("executor_workdir"), source),
    }


def _validate_artifact(document: Mapping[str, Any], base_dir: Path, source: str) -> Artifact:
    api_version = _ensure_str("apiVersion", document.get("apiVersion"), source)
    if api_version != API_VERSION:
        raise ValueError(f"{source}: unsupported apiVersion {api_version!r}")
    kind = _ensure_str("kind", document.get("kind"), source)
    if kind not in KIND_SUBDIRS:
        raise ValueError(f"{source}: unsupported kind {kind!r}")
    _validate_against_schema(document, kind, base_dir, source)
    metadata = _validate_metadata(document.get("metadata"), source)
    raw_spec = document.get("spec")
    if kind == "CapabilityPackage":
        spec = _validate_package_spec(raw_spec, source)
    elif kind == "BrokerDefinition":
        spec = _validate_broker_spec(raw_spec, source)
    elif kind == "ExecutorDefinition":
        spec = _validate_executor_spec(raw_spec, source)
    elif kind == "PolicyDefinition":
        spec = _validate_policy_spec(raw_spec, source)
    else:
        spec = _validate_server_spec(raw_spec, source)
    return Artifact(
        api_version=api_version,
        kind=kind,
        metadata=metadata,
        spec=spec,
        source=source,
    )


def _load_kind_dir(base_dir: Path, kind: str) -> Dict[str, Artifact]:
    artifact_dir = base_dir / KIND_SUBDIRS[kind]
    if not artifact_dir.is_dir():
        raise ValueError(f"controlplane: missing directory for kind={kind}: {artifact_dir}")
    artifacts: Dict[str, Artifact] = {}
    for path in sorted(artifact_dir.glob("*.yaml")):
        artifact = _validate_artifact(_load_yaml(path), base_dir, str(path))
        if artifact.kind != kind:
            raise ValueError(f"{path}: expected kind {kind!r}, found {artifact.kind!r}")
        if artifact.metadata.name in artifacts:
            raise ValueError(f"{path}: duplicate artifact name {artifact.metadata.name!r}")
        artifacts[artifact.metadata.name] = artifact
    return artifacts


def load_artifact_store(base_dir: Path = CONTROLPLANE_DIR) -> ArtifactStore:
    base_dir = Path(base_dir)
    packages = _load_kind_dir(base_dir, "CapabilityPackage")
    brokers = _load_kind_dir(base_dir, "BrokerDefinition")
    executors = _load_kind_dir(base_dir, "ExecutorDefinition")
    policies = _load_kind_dir(base_dir, "PolicyDefinition")
    platform = _load_kind_dir(base_dir, "ServerConfig")
    return ArtifactStore(
        base_dir=base_dir,
        packages=packages,
        brokers=brokers,
        executors=executors,
        policies=policies,
        platform=platform,
    )
