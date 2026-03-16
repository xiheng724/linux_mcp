from __future__ import annotations

import glob
import json
import unittest
from pathlib import Path

from test_support import load_real_catalogs, load_reconciled_controlplane


class CapabilityIntegrationTests(unittest.TestCase):
    def test_provider_manifests_reference_declared_capabilities(self) -> None:
        reconciled = load_reconciled_controlplane()
        capability_domains = set(reconciled.capability_registry)
        manifest_paths = sorted(glob.glob(str(Path(__file__).resolve().parent.parent / "provider-app" / "manifests" / "*.json")))
        self.assertGreaterEqual(len(manifest_paths), 1)
        for manifest_path in manifest_paths:
            raw = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
            for action in raw.get("actions", []):
                self.assertIn(action.get("capability_domain"), capability_domains)

    def test_capability_catalog_generation_still_works(self) -> None:
        _providers, capabilities, brokers = load_real_catalogs()
        self.assertIn("info.lookup", capabilities)
        self.assertIn("file-broker", brokers)
        self.assertEqual("info-broker", capabilities["info.lookup"].broker_id)
