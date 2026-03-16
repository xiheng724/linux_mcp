from __future__ import annotations

import unittest
from pathlib import Path
import yaml

from test_support import copy_controlplane_tree, load_real_artifact_store

from controlplane.loader import load_artifact_store


class ArtifactLoaderTests(unittest.TestCase):
    def test_default_loader_scans_expected_artifacts(self) -> None:
        store = load_real_artifact_store()
        self.assertIn("file.read", store.packages)
        self.assertIn("file-broker", store.brokers)
        self.assertIn("sandbox-high-risk", store.executors)
        self.assertIn("write-mediumrisk", store.policies)
        self.assertEqual("server", store.server_config.metadata.name)

    def test_invalid_artifact_envelope_fails_fast(self) -> None:
        with copy_controlplane_tree() as tempdir:
            artifact_path = Path(tempdir) / "controlplane" / "packages" / "file.read.yaml"
            raw = yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
            raw["kind"] = "BrokerDefinition"
            artifact_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_artifact_store(Path(tempdir) / "controlplane")
