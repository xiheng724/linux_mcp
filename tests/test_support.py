from __future__ import annotations

import glob
import json
import sys
import tempfile
from shutil import copytree
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
MCPD_DIR = ROOT_DIR / "mcpd"
if str(MCPD_DIR) not in sys.path:
    sys.path.insert(0, str(MCPD_DIR))

from architecture import build_broker_catalog, build_capability_catalog, load_provider_manifest
from controlplane.loader import CONTROLPLANE_DIR, load_artifact_store
from controlplane.controllers import reconcile_artifact_store
from package_compiler import compile_controlplane


def load_real_catalogs():
    providers = {}
    manifest_paths = sorted(glob.glob(str(ROOT_DIR / "provider-app" / "manifests" / "*.json")))
    for path in manifest_paths:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        provider = load_provider_manifest(path, raw)
        providers[provider.provider_id] = provider
    capabilities = build_capability_catalog(providers.values())
    brokers = build_broker_catalog(providers.values(), capabilities)
    return providers, capabilities, brokers


def load_real_artifact_store():
    return load_artifact_store()


def load_reconciled_controlplane():
    return reconcile_artifact_store(load_real_artifact_store())


def load_runtime_registry():
    return compile_controlplane()


def copy_controlplane_tree() -> tempfile.TemporaryDirectory[str]:
    tempdir = tempfile.TemporaryDirectory()
    copytree(CONTROLPLANE_DIR, Path(tempdir.name) / "controlplane", dirs_exist_ok=True)
    return tempdir
