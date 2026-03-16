#!/usr/bin/env python3
"""Compile package + definitions control plane artifacts into runtime registry."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

from controlplane.loader import (
    API_VERSION,
    CONTROLPLANE_DIR,
    HIGH_RISK_LEVEL,
    MCPD_RUNTIME_VERSION,
    Artifact,
    ArtifactStore,
    load_artifact_store,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
GENERATED_DIR = ROOT_DIR / "mcpd" / "generated"
RUNTIME_REGISTRY_PATH = GENERATED_DIR / "runtime_registry.json"


def _version_satisfies(requirement: str, current_version: str = MCPD_RUNTIME_VERSION) -> bool:
    requirement = requirement.strip()
    if not requirement or requirement == "*":
        return True
    if requirement.startswith(">="):
        return current_version >= requirement[2:].strip()
    if requirement.startswith("=="):
        return current_version == requirement[2:].strip()
    return current_version == requirement


def _derive_capability_id(name: str) -> int:
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    return 1000 + int.from_bytes(digest[:4], "big") % 1000000


def _short_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:8]


def _governance_entry(artifact: Artifact) -> Dict[str, Any]:
    return {
        "deprecated": artifact.metadata.deprecated,
        "replaced_by": artifact.metadata.replaced_by or "",
        "introduced_in": artifact.metadata.introduced_in,
        "requires_mcpd_version": artifact.metadata.requires_mcpd_version,
        "compatibility_mode": "canonical",
        "version": artifact.metadata.version,
    }


def _resolve_manifest_paths(server_config: Mapping[str, Any]) -> tuple[Path, ...]:
    out: list[Path] = []
    seen: set[Path] = set()
    for entry in server_config.get("manifest_dirs", []):
        path = Path(str(entry)).expanduser()
        if not path.is_absolute():
            path = ROOT_DIR / path
        resolved = path.resolve() if path.exists() else path
        if resolved in seen:
            continue
        seen.add(resolved)
        out.append(resolved)
    return tuple(out)


def _load_provider_manifests(server_config: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    manifests: Dict[str, Dict[str, Any]] = {}
    for manifest_dir in _resolve_manifest_paths(server_config):
        if manifest_dir.is_file():
            manifest_paths = [manifest_dir]
        elif manifest_dir.exists():
            manifest_paths = sorted(manifest_dir.glob("*.json"))
        else:
            manifest_paths = []
        for manifest_path in manifest_paths:
            try:
                raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f"{manifest_path}: unable to read provider manifest: {exc}") from exc
            provider_id = str(raw.get("provider_id") or "").strip()
            if not provider_id:
                raise ValueError(f"{manifest_path}: provider_id must be non-empty string")
            raw["manifest_source"] = str(manifest_path)
            if provider_id in manifests:
                raise ValueError(f"{manifest_path}: duplicate provider_id {provider_id!r}")
            manifests[provider_id] = raw
    return manifests


def validate_provider_manifest_capability_refs(
    capability_registry: Mapping[str, Mapping[str, Any]],
    provider_manifests: Iterable[Mapping[str, Any]],
) -> None:
    for manifest in provider_manifests:
        source = str(manifest.get("manifest_source") or manifest.get("source") or "<provider-manifest>")
        actions = manifest.get("actions", [])
        if not isinstance(actions, list):
            raise ValueError(f"{source}: actions must be list")
        for idx, action in enumerate(actions):
            if not isinstance(action, Mapping):
                raise ValueError(f"{source}: actions[{idx}] must be object")
            capability_domain = str(action.get("capability_domain") or "")
            if capability_domain not in capability_registry:
                raise ValueError(
                    f"{source}: action capability_domain {capability_domain!r} does not exist"
                )


def compile_runtime_registry(
    store: ArtifactStore,
    *,
    provider_manifests: Mapping[str, Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    server_artifact = store.server_config
    server_defaults = {
        "governance": _governance_entry(server_artifact),
        "manifest_dirs": list(server_artifact.spec["manifest_dirs"]),
        "planner_trust_level": int(server_artifact.spec["planner_trust_level"]),
        "broker_trust_level": int(server_artifact.spec["broker_trust_level"]),
        "executor_workdir_root": str(server_artifact.spec["executor_workdir"]),
        "default_socket_paths": {"mcpd": str(server_artifact.spec["socket_path"])},
        "socket_path": str(server_artifact.spec["socket_path"]),
    }
    if provider_manifests is None:
        provider_manifests = _load_provider_manifests(server_defaults)

    compiled_brokers: Dict[str, Dict[str, Any]] = {}
    for broker_id, artifact in store.brokers.items():
        compiled_brokers[broker_id] = {
            "governance": _governance_entry(artifact),
            "broker_id": broker_id,
            "capability_domains": [],
            "selection_policy": dict(artifact.spec["selection_policy"]),
            "runtime_identity_mode": str(artifact.spec["runtime_identity_mode"]),
            "policy_controlled": bool(artifact.spec["policy_controlled"]),
        }

    compiled_executor_profiles: Dict[tuple[str, str], Dict[str, Any]] = {}
    compiled_executor_defs: Dict[str, Dict[str, Any]] = {}
    for executor_ref, artifact in store.executors.items():
        allowed_executor_types: list[str] = []
        sandbox_profiles: set[str] = set()
        network_policies: set[str] = set()
        profile_refs: list[Dict[str, str]] = []
        for profile in artifact.spec["profiles"]:
            key = (str(profile["executor_type"]), str(profile["sandbox_profile"]))
            if key in compiled_executor_profiles:
                raise ValueError(
                    f"{artifact.source}: duplicate executor profile {key[0]}/{key[1]}"
                )
            env_policy = profile["environment_policy"]
            enforcement = profile["enforcement_requirements"]
            compiled_executor_profiles[key] = {
                "definition_ref": executor_ref,
                "governance": _governance_entry(artifact),
                "executor_type": key[0],
                "sandbox_profile": key[1],
                "network_policy": str(profile["network_policy"]),
                "resource_limits": dict(profile["resource_limits"]),
                "inherited_env_keys": list(env_policy["inherited_env_keys"]),
                "command_schema_mode": str(env_policy["command_schema_mode"]),
                "structured_payload_only": bool(env_policy["structured_payload_only"]),
                "short_lived": bool(enforcement["short_lived"]),
                "sandbox_ready": bool(enforcement["sandbox_ready"]),
                "runtime_identity_mode": str(enforcement["runtime_identity_mode"]),
                "required_hooks": list(enforcement["required_hooks"]),
                "deny_on_unenforced": bool(enforcement["deny_on_unenforced"]),
                "enforce_no_new_privs": bool(enforcement["enforce_no_new_privs"]),
            }
            allowed_executor_types.append(key[0])
            sandbox_profiles.add(key[1])
            network_policies.add(str(profile["network_policy"]))
            profile_refs.append({"executor_type": key[0], "sandbox_profile": key[1]})
        if len(sandbox_profiles) != 1:
            raise ValueError(f"{artifact.source}: executor definition must resolve to exactly one sandbox_profile")
        compiled_executor_defs[executor_ref] = {
            "governance": _governance_entry(artifact),
            "executor_ref": executor_ref,
            "allowed_executor_types": sorted(set(allowed_executor_types)),
            "sandbox_profile": next(iter(sandbox_profiles)),
            "network_policies": sorted(network_policies),
            "profiles": profile_refs,
        }

    compiled_policies: Dict[str, Dict[str, Any]] = {}
    for policy_ref, artifact in store.policies.items():
        compiled_policies[policy_ref] = {
            "governance": _governance_entry(artifact),
            "policy_ref": policy_ref,
            "risk_level": int(artifact.spec["risk_level"]),
            "approval_mode": str(artifact.spec["approval_mode"]),
            "audit_mode": str(artifact.spec["audit_mode"]),
            "rate_limit": dict(artifact.spec["rate_limit"]),
            "max_inflight_per_participant": int(artifact.spec["max_inflight_per_participant"]),
            "max_inflight_per_agent": int(artifact.spec["max_inflight_per_agent"]),
            "executor_policy": dict(artifact.spec["executor_policy"]),
        }

    packages: Dict[str, Dict[str, Any]] = {}
    capability_registry: Dict[str, Dict[str, Any]] = {}
    for capability_domain, artifact in store.packages.items():
        spec = artifact.spec
        broker_ref = str(spec["broker_ref"])
        policy_ref = str(spec["policy_ref"])
        executor_ref = str(spec["executor_ref"])
        if broker_ref not in compiled_brokers:
            raise ValueError(f"{artifact.source}: broker_ref {broker_ref!r} does not exist")
        if policy_ref not in compiled_policies:
            raise ValueError(f"{artifact.source}: policy_ref {policy_ref!r} does not exist")
        if executor_ref not in compiled_executor_defs:
            raise ValueError(f"{artifact.source}: executor_ref {executor_ref!r} does not exist")
        capability_spec = dict(spec["capability"])
        policy = compiled_policies[policy_ref]
        executor_def = compiled_executor_defs[executor_ref]
        risk_level = int(capability_spec.get("risk_level") or policy["risk_level"])
        approval_mode = str(policy["approval_mode"])
        audit_mode = str(policy["audit_mode"])
        if risk_level >= HIGH_RISK_LEVEL:
            if approval_mode.lower() in {"", "auto", "0", "none"}:
                raise ValueError(f"{artifact.source}: high-risk package missing approval baseline")
            if audit_mode.lower() in {"", "basic", "0", "none"}:
                raise ValueError(f"{artifact.source}: high-risk package missing audit baseline")
        required_network_policy = str(policy["executor_policy"]["network_policy"])
        for profile in executor_def["profiles"]:
            profile_entry = compiled_executor_profiles[(profile["executor_type"], profile["sandbox_profile"])]
            if str(profile_entry["network_policy"]) != required_network_policy:
                raise ValueError(
                    f"{artifact.source}: executor profile {profile_entry['executor_type']}/{profile_entry['sandbox_profile']} "
                    f"conflicts with network policy {required_network_policy!r}"
                )
            if bool(policy["executor_policy"]["require_short_lived"]) and not bool(profile_entry["short_lived"]):
                raise ValueError(
                    f"{artifact.source}: executor profile {profile_entry['executor_type']}/{profile_entry['sandbox_profile']} "
                    f"does not satisfy short-lived enforcement"
                )
            if bool(policy["executor_policy"]["deny_on_unenforced"]) and not bool(profile_entry["deny_on_unenforced"]):
                raise ValueError(
                    f"{artifact.source}: executor profile {profile_entry['executor_type']}/{profile_entry['sandbox_profile']} "
                    f"does not satisfy deny_on_unenforced baseline"
                )
        provider_requirements = dict(spec["provider_requirements"])
        required_manifests = list(provider_requirements.get("manifests", []))
        for provider_id in required_manifests:
            if provider_id not in provider_manifests:
                raise ValueError(f"{artifact.source}: required provider manifest {provider_id!r} not found")
        capability_id = capability_spec.get("capability_id")
        if capability_id is None:
            capability_id = _derive_capability_id(capability_domain)
        packages[capability_domain] = {
            "governance": _governance_entry(artifact),
            "capability_domain": capability_domain,
            "description": str(spec["description"]),
            "broker_ref": broker_ref,
            "policy_ref": policy_ref,
            "executor_ref": executor_ref,
            "provider_requirements": {"manifests": required_manifests},
        }
        capability_registry[capability_domain] = {
            "governance": _governance_entry(artifact),
            "capability_id": int(capability_id),
            "capability_domain": capability_domain,
            "description": str(spec["description"]),
            "required_caps": list(capability_spec["required_caps"]),
            "broker_id": broker_ref,
            "capability_class": str(capability_spec["capability_class"]),
            "auth_mode": str(capability_spec["auth_mode"]),
            "allows_side_effect": bool(capability_spec["allows_side_effect"]),
            "risk_level": risk_level,
            "approval_mode": approval_mode,
            "audit_mode": audit_mode,
            "rate_limit": dict(policy["rate_limit"]),
            "max_inflight_per_participant": int(policy["max_inflight_per_participant"]),
            "max_inflight_per_agent": int(policy["max_inflight_per_agent"]),
            "sandbox_profile": str(executor_def["sandbox_profile"]),
            "executor_policy": {
                "allowed_executor_types": list(executor_def["allowed_executor_types"]),
                "network_policy": required_network_policy,
                "require_short_lived": bool(policy["executor_policy"]["require_short_lived"]),
                "min_planner_trust_level": int(policy["executor_policy"]["min_planner_trust_level"]),
                "min_provider_trust_class": str(policy["executor_policy"]["min_provider_trust_class"]),
                "deny_on_unenforced": bool(policy["executor_policy"]["deny_on_unenforced"]),
            },
            "provider_requirements": {"manifests": required_manifests},
            "policy_ref": policy_ref,
            "executor_ref": executor_ref,
        }
        compiled_brokers[broker_ref]["capability_domains"].append(capability_domain)

    for broker in compiled_brokers.values():
        broker["capability_domains"] = sorted(broker["capability_domains"])

    validate_provider_manifest_capability_refs(capability_registry, provider_manifests.values())
    for provider_id, manifest in provider_manifests.items():
        for action in manifest.get("actions", []):
            capability_domain = str(action.get("capability_domain") or "")
            if capability_domain in capability_registry:
                required = capability_registry[capability_domain].get("provider_requirements", {}).get("manifests", [])
                if required and provider_id not in required:
                    continue

    registry = {
        "apiVersion": API_VERSION,
        "kind": "RuntimeRegistry",
        "metadata": {
            "version": "1.0.0",
            "requires_mcpd_version": f">={MCPD_RUNTIME_VERSION}",
            "controlplane_layout": "package-definitions-generated",
        },
        "packages": {
            "version": 1,
            "items": [packages[name] for name in sorted(packages)],
        },
        "definitions": {
            "version": 1,
            "brokers": [compiled_brokers[name] for name in sorted(compiled_brokers)],
            "executors": [compiled_executor_defs[name] for name in sorted(compiled_executor_defs)],
            "policies": [compiled_policies[name] for name in sorted(compiled_policies)],
        },
        "capability_registry": {
            "version": 1,
            "capabilities": [capability_registry[name] for name in sorted(capability_registry)],
        },
        "broker_registry": {
            "version": 1,
            "brokers": [compiled_brokers[name] for name in sorted(compiled_brokers)],
        },
        "executor_profiles": {
            "version": 1,
            "profiles": [
                compiled_executor_profiles[key]
                for key in sorted(compiled_executor_profiles)
            ],
        },
        "policy_registry": {
            "version": 1,
            "policies": [compiled_policies[name] for name in sorted(compiled_policies)],
        },
        "server_defaults": server_defaults,
        "provider_manifest_index": {
            "version": 1,
            "providers": [
                {
                    "provider_id": provider_id,
                    "manifest_source": str(manifest.get("manifest_source", "")),
                    "capability_domains": sorted(
                        {
                            str(action.get("capability_domain") or "")
                            for action in manifest.get("actions", [])
                            if isinstance(action, Mapping)
                        }
                    ),
                }
                for provider_id, manifest in sorted(provider_manifests.items())
            ],
        },
    }
    registry["metadata"]["registry_hash"] = _short_hash(registry["capability_registry"])
    return registry


def render_controlplane_index(runtime_registry: Mapping[str, Any]) -> str:
    lines = [
        "# Control Plane Index",
        "",
        "| Capability Package | Broker Ref | Policy Ref | Executor Ref | Provider Requirements |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in runtime_registry.get("packages", {}).get("items", []):
        providers = ", ".join(item.get("provider_requirements", {}).get("manifests", [])) or "-"
        lines.append(
            f"| {item['capability_domain']} | {item['broker_ref']} | {item['policy_ref']} | {item['executor_ref']} | {providers} |"
        )
    return "\n".join(lines) + "\n"


def write_runtime_registry(runtime_registry: Mapping[str, Any], path: Path = RUNTIME_REGISTRY_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(runtime_registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_controlplane_index(runtime_registry: Mapping[str, Any], base_dir: Path = CONTROLPLANE_DIR) -> Path:
    index_path = Path(base_dir) / "INDEX.md"
    index_path.write_text(render_controlplane_index(runtime_registry), encoding="utf-8")
    return index_path


def compile_controlplane(
    base_dir: Path = CONTROLPLANE_DIR,
    *,
    write_generated: bool = True,
) -> Dict[str, Any]:
    store = load_artifact_store(base_dir)
    runtime_registry = compile_runtime_registry(store)
    if write_generated:
        write_runtime_registry(runtime_registry)
        write_controlplane_index(runtime_registry, base_dir)
    return runtime_registry
