from __future__ import annotations

import unittest
from dataclasses import replace

from test_support import load_real_catalogs

import architecture
from architecture import build_executor_binding, validate_executor_binding_for_capability


class ExecutorBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.providers, cls.capabilities, cls.brokers = load_real_catalogs()

    def test_high_risk_profile_missing_fails(self) -> None:
        provider = self.providers["settings-provider"]
        action = next(
            item for item in provider.actions.values() if item.capability_domain == "exec.run"
        )
        original = dict(architecture.EXECUTOR_PROFILE_REGISTRY)
        try:
            architecture.EXECUTOR_PROFILE_REGISTRY.pop(("sandboxed-process", "sandbox-high-risk"), None)
            with self.assertRaises(ValueError):
                build_executor_binding(provider, action)
        finally:
            architecture.EXECUTOR_PROFILE_REGISTRY.clear()
            architecture.EXECUTOR_PROFILE_REGISTRY.update(original)

    def test_policy_mismatch_fails(self) -> None:
        provider = self.providers["file-manager-provider"]
        action = next(
            item for item in provider.actions.values() if item.capability_domain == "file.write"
        )
        capability = self.capabilities["file.write"]
        executor = build_executor_binding(provider, action)
        broken_executor = replace(executor, network_policy="inherit")
        with self.assertRaises(ValueError):
            validate_executor_binding_for_capability(capability, provider, action, broken_executor)

    def test_valid_binding_is_generated(self) -> None:
        provider = self.providers["calculator-provider"]
        action = next(
            item for item in provider.actions.values() if item.capability_domain == "info.lookup"
        )
        capability = self.capabilities["info.lookup"]
        executor = build_executor_binding(provider, action)
        validate_executor_binding_for_capability(capability, provider, action, executor)
        self.assertEqual("broker-uds", executor.executor_type)
        self.assertEqual("local-readonly", executor.sandbox_profile)
