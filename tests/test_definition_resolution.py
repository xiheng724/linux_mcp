from __future__ import annotations

import unittest

from test_support import load_reconciled_controlplane


class DefinitionResolutionTests(unittest.TestCase):
    def test_package_resolves_broker_policy_and_executor_refs(self) -> None:
        reconciled = load_reconciled_controlplane()
        capability = reconciled.capability_registry["file.write"]
        self.assertEqual("file-broker", capability["broker_id"])
        self.assertEqual("write-mediumrisk", capability["policy_ref"])
        self.assertEqual("sandbox-broker-isolated", capability["executor_ref"])
        self.assertEqual(["broker-isolated-uds", "sandboxed-process"], capability["executor_policy"]["allowed_executor_types"])
