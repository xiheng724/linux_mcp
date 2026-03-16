from __future__ import annotations

import unittest

from test_support import load_real_artifact_store, load_reconciled_controlplane


class RegistryConsistencyTests(unittest.TestCase):
    def test_every_capability_has_a_broker(self) -> None:
        reconciled = load_reconciled_controlplane()
        broker_ids = set(reconciled.broker_registry)
        for capability in reconciled.capability_registry.values():
            self.assertIn(capability["broker_id"], broker_ids)

    def test_every_broker_capability_exists(self) -> None:
        reconciled = load_reconciled_controlplane()
        capability_ids = set(reconciled.capability_registry)
        for broker in reconciled.broker_registry.values():
            for capability_domain in broker["capability_domains"]:
                self.assertIn(capability_domain, capability_ids)

    def test_server_config_is_present(self) -> None:
        store = load_real_artifact_store()
        self.assertEqual("server", store.server_config.metadata.name)
