from __future__ import annotations

import unittest

from mcpd.manifest_loader import load_all_manifests


class ManifestLoaderTest(unittest.TestCase):
    def test_loads_all_manifests(self) -> None:
        apps = load_all_manifests()
        self.assertEqual(4, len(apps))
        tool_ids = sorted(tool.tool_id for app in apps for tool in app.tools)
        self.assertEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14], tool_ids)

    def test_transport_and_operation_present(self) -> None:
        apps = load_all_manifests()
        for app in apps:
            self.assertEqual("uds_rpc", app.transport)
            self.assertTrue(app.endpoint.startswith("/tmp/linux-mcp-apps/"))
            for tool in app.tools:
                self.assertTrue(tool.operation)
                self.assertGreater(tool.timeout_ms, 0)


if __name__ == "__main__":
    unittest.main()
