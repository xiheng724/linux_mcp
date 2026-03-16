#!/usr/bin/env python3
"""Control plane reconciliation for package/definitions/generated layout."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping

from package_compiler import (
    compile_runtime_registry,
    validate_provider_manifest_capability_refs,
)
from ..loader import ArtifactStore


@dataclass(frozen=True)
class ReconciledControlPlane:
    artifact_store: ArtifactStore
    runtime_registry: Dict[str, Any]
    package_registry: Dict[str, Dict[str, Any]]
    capability_registry: Dict[str, Dict[str, Any]]
    broker_registry: Dict[str, Dict[str, Any]]
    executor_profiles: Dict[tuple[str, str], Dict[str, Any]]
    policy_registry: Dict[str, Dict[str, Any]]
    server_config: Dict[str, Any]


def reconcile_artifact_store(
    store: ArtifactStore,
    *,
    provider_manifests: Mapping[str, Mapping[str, Any]] | None = None,
) -> ReconciledControlPlane:
    runtime_registry = compile_runtime_registry(store, provider_manifests=provider_manifests)
    package_registry = {
        str(item["capability_domain"]): dict(item)
        for item in runtime_registry["packages"]["items"]
    }
    capability_registry = {
        str(item["capability_domain"]): dict(item)
        for item in runtime_registry["capability_registry"]["capabilities"]
    }
    broker_registry = {
        str(item["broker_id"]): dict(item)
        for item in runtime_registry["broker_registry"]["brokers"]
    }
    executor_profiles = {
        (str(item["executor_type"]), str(item["sandbox_profile"])): dict(item)
        for item in runtime_registry["executor_profiles"]["profiles"]
    }
    policy_registry = {
        str(item["policy_ref"]): dict(item)
        for item in runtime_registry["policy_registry"]["policies"]
    }
    return ReconciledControlPlane(
        artifact_store=store,
        runtime_registry=runtime_registry,
        package_registry=package_registry,
        capability_registry=capability_registry,
        broker_registry=broker_registry,
        executor_profiles=executor_profiles,
        policy_registry=policy_registry,
        server_config=dict(runtime_registry["server_defaults"]),
    )


__all__ = [
    "ReconciledControlPlane",
    "reconcile_artifact_store",
    "validate_provider_manifest_capability_refs",
]
