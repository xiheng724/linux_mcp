from __future__ import annotations

import unittest

from test_support import load_runtime_registry


class RuntimeRegistryCompilationTests(unittest.TestCase):
    def test_runtime_registry_contains_expected_sections(self) -> None:
        registry = load_runtime_registry()
        self.assertEqual("RuntimeRegistry", registry["kind"])
        self.assertIn("capability_registry", registry)
        self.assertIn("broker_registry", registry)
        self.assertIn("executor_profiles", registry)
        self.assertIn("policy_registry", registry)
        self.assertIn("server_defaults", registry)

    def test_runtime_registry_compiles_provider_manifest_index(self) -> None:
        registry = load_runtime_registry()
        providers = {
            item["provider_id"]: item
            for item in registry["provider_manifest_index"]["providers"]
        }
        self.assertIn("file-manager-provider", providers)
        self.assertIn("info.lookup", providers["file-manager-provider"]["capability_domains"])
