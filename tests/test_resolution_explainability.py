from __future__ import annotations

import unittest

from test_support import load_real_catalogs

from architecture import explain_capability_request, plan_capability_execution


class ResolutionExplainabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.providers, cls.capabilities, cls.brokers = load_real_catalogs()

    def test_action_resolution_explain_contains_candidates_and_selection(self) -> None:
        plan = plan_capability_execution(
            "info.lookup",
            self.providers,
            self.capabilities,
            self.brokers,
            "what time is it in utc",
        )
        explain = plan.explanation["action_resolution"]
        self.assertIn("candidates", explain)
        self.assertIn("selected", explain)
        self.assertGreaterEqual(explain["candidate_count"], 1)
        self.assertTrue(any(candidate.get("selected") for candidate in explain["candidates"]))

    def test_deny_explain_contains_reason_codes(self) -> None:
        capability = self.capabilities["file.write"]
        explain = explain_capability_request(
            {"participant_id": "planner-main", "caps": 0, "trust_level": 8},
            capability,
            {"intent_text": "create file /tmp/demo.txt"},
        )
        self.assertFalse(explain["allowed"])
        self.assertIsNotNone(explain["deny_reason"])
        self.assertTrue(explain["reason_codes"])

    def test_approval_explain_contains_trigger_reason(self) -> None:
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
        self.assertTrue(explain["require_approval"])
        self.assertIn("explicit_approval_policy", explain["reason_codes"])
