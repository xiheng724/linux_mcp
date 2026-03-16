from __future__ import annotations

import unittest
from pathlib import Path

from test_support import load_runtime_registry

from package_compiler import write_controlplane_index


class ControlPlaneIndexGenerationTests(unittest.TestCase):
    def test_index_contains_package_refs(self) -> None:
        registry = load_runtime_registry()
        index_path = write_controlplane_index(registry)
        content = Path(index_path).read_text(encoding="utf-8")
        self.assertIn("| file.write | file-broker | write-mediumrisk | sandbox-broker-isolated | file-manager-provider |", content)
