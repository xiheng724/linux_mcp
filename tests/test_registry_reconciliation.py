from __future__ import annotations

import unittest

from test_support import load_real_artifact_store, load_reconciled_controlplane


class RegistryReconciliationTests(unittest.TestCase):
    def test_reconciled_registries_cover_all_capabilities(self) -> None:
        store = load_real_artifact_store()
        reconciled = load_reconciled_controlplane()
        self.assertEqual(set(store.packages), set(reconciled.capability_registry))
        self.assertEqual(set(store.brokers), set(reconciled.broker_registry))

    def test_every_capability_has_matching_executor_profiles(self) -> None:
        reconciled = load_reconciled_controlplane()
        profiles = reconciled.executor_profiles
        for capability_domain, capability in reconciled.capability_registry.items():
            sandbox_profile = capability["sandbox_profile"]
            executor_policy = capability["executor_policy"]
            for executor_type in executor_policy["allowed_executor_types"]:
                self.assertIn((executor_type, sandbox_profile), profiles, capability_domain)
