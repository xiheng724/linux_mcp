#!/usr/bin/env python3
"""Load compiled control plane runtime registry and compatibility views."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Dict, Mapping, Tuple

from controlplane.controllers import reconcile_artifact_store
from controlplane.loader import ArtifactStore, load_artifact_store
from package_compiler import RUNTIME_REGISTRY_PATH, compile_controlplane


@lru_cache(maxsize=1)
def load_controlplane_artifact_store() -> ArtifactStore:
    return load_artifact_store()


@lru_cache(maxsize=1)
def load_runtime_registry() -> Dict[str, Any]:
    compile_controlplane(write_generated=True)
    return json.loads(RUNTIME_REGISTRY_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_runtime_config_bundle() -> Dict[str, Any]:
    runtime_registry = load_runtime_registry()
    artifact_store = load_controlplane_artifact_store()
    reconciled = reconcile_artifact_store(artifact_store)
    return {
        "artifact_store": artifact_store,
        "runtime_registry": runtime_registry,
        "packages": dict(runtime_registry["packages"]),
        "definitions": dict(runtime_registry["definitions"]),
        "capability_registry": dict(runtime_registry["capability_registry"]),
        "broker_registry": dict(runtime_registry["broker_registry"]),
        "executor_profiles": dict(runtime_registry["executor_profiles"]),
        "policy_registry": dict(runtime_registry["policy_registry"]),
        "server_defaults": dict(runtime_registry["server_defaults"]),
        "reconciled": reconciled,
    }


def load_capability_registry_config() -> Dict[str, Any]:
    return dict(load_runtime_config_bundle()["capability_registry"])


def load_broker_registry_config() -> Dict[str, Any]:
    return dict(load_runtime_config_bundle()["broker_registry"])


def load_executor_profiles_config() -> Dict[str, Any]:
    return dict(load_runtime_config_bundle()["executor_profiles"])


def load_policy_registry_config() -> Dict[str, Any]:
    return dict(load_runtime_config_bundle()["policy_registry"])


def load_server_defaults_config() -> Dict[str, Any]:
    return dict(load_runtime_config_bundle()["server_defaults"])


def cross_validate_runtime_configs(
    capability_config: Mapping[str, Any],
    broker_config: Mapping[str, Any],
    executor_profiles_config: Mapping[str, Any],
) -> None:
    brokers_by_id = {str(entry["broker_id"]): dict(entry) for entry in broker_config.get("brokers", [])}
    capabilities_by_domain = {
        str(entry["capability_domain"]): dict(entry)
        for entry in capability_config.get("capabilities", [])
    }
    profiles_by_key = {
        (str(entry["executor_type"]), str(entry["sandbox_profile"])): dict(entry)
        for entry in executor_profiles_config.get("profiles", [])
    }
    for capability_domain, capability in capabilities_by_domain.items():
        source = f"CapabilityPackage/{capability_domain}"
        broker_id = str(capability["broker_id"])
        if broker_id not in brokers_by_id:
            raise ValueError(f"{source}: broker_id {broker_id!r} does not exist")
        executor_policy = dict(capability.get("executor_policy", {}))
        sandbox_profile = str(capability["sandbox_profile"])
        required_network_policy = str(executor_policy.get("network_policy", ""))
        for executor_type in executor_policy.get("allowed_executor_types", []):
            key: Tuple[str, str] = (str(executor_type), sandbox_profile)
            profile = profiles_by_key.get(key)
            if profile is None:
                raise ValueError(f"{source}: missing executor profile for {key[0]}/{key[1]}")
            if required_network_policy and str(profile["network_policy"]) != required_network_policy:
                raise ValueError(
                    f"{source}: executor profile {key[0]}/{key[1]} "
                    f"conflicts with network policy {required_network_policy!r}"
                )
            if bool(executor_policy.get("deny_on_unenforced", False)) and not bool(profile.get("deny_on_unenforced", False)):
                raise ValueError(
                    f"{source}: executor profile {key[0]}/{key[1]} does not satisfy deny_on_unenforced baseline"
                )
    for broker_id, broker in brokers_by_id.items():
        source = f"BrokerDefinition/{broker_id}"
        for capability_domain in broker.get("capability_domains", []):
            if capability_domain not in capabilities_by_domain:
                raise ValueError(f"{source}: capability_domain {capability_domain!r} does not exist")
