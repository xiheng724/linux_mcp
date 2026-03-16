from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from test_support import copy_controlplane_tree

from controlplane.loader import load_artifact_store


class PackageSchemaValidationTests(unittest.TestCase):
    def test_missing_executor_ref_fails_schema_validation(self) -> None:
        with copy_controlplane_tree() as tempdir:
            artifact_path = Path(tempdir) / "controlplane" / "packages" / "file.read.yaml"
            raw = yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
            del raw["spec"]["executor_ref"]
            artifact_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_artifact_store(Path(tempdir) / "controlplane")
