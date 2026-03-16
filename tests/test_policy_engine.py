from __future__ import annotations

import unittest

from test_support import load_real_catalogs

from architecture import explain_capability_request


class PolicyEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.providers, cls.capabilities, cls.brokers = load_real_catalogs()

    def test_missing_required_caps_is_denied(self) -> None:
        capability = self.capabilities["file.write"]
        explain = explain_capability_request(
            {"participant_id": "planner-main", "caps": 0, "trust_level": 8},
            capability,
            {"intent_text": "create file /tmp/demo.txt"},
        )
        self.assertFalse(explain["allowed"])
        self.assertEqual("deny", explain["decision"])
        self.assertEqual("participant missing required capability bits", explain["deny_reason"])
        self.assertIn("missing_required_caps", explain["reason_codes"])

    def test_high_risk_capability_triggers_approval_metadata(self) -> None:
        capability = self.capabilities["file.write"]
        explain = explain_capability_request(
            {
                "participant_id": "planner-main",
                "caps": capability.required_caps,
                "trust_level": 8,
            },
            capability,
            {"intent_text": "create file /tmp/demo.txt"},
        )
        self.assertTrue(explain["allowed"])
        self.assertTrue(explain["require_approval"])
        self.assertIn("explicit_approval_policy", explain["reason_codes"])
        self.assertIn("approval_mode_explicit_kernel_pending", explain["audit_markers"])

    def test_trust_level_below_policy_is_denied(self) -> None:
        capability = self.capabilities["file.write"]
        explain = explain_capability_request(
            {
                "participant_id": "planner-main",
                "caps": capability.required_caps,
                "trust_level": 0,
            },
            capability,
            {"intent_text": "create file /tmp/demo.txt"},
        )
        self.assertFalse(explain["allowed"])
        self.assertEqual("planner trust level below capability minimum", explain["deny_reason"])
        self.assertIn("planner_trust_below_minimum", explain["reason_codes"])
