from __future__ import annotations

import warnings
import unittest
from pathlib import Path
import yaml

from test_support import copy_controlplane_tree, load_real_artifact_store

from controlplane.controllers import reconcile_artifact_store
from controlplane.loader import load_artifact_store


class ControlPlaneValidationTests(unittest.TestCase):
    def test_cross_artifact_validation_rejects_missing_broker(self) -> None:
        with copy_controlplane_tree() as tempdir:
            artifact_path = Path(tempdir) / "controlplane" / "packages" / "file.write.yaml"
            raw = yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
            raw["spec"]["broker_ref"] = "missing-broker"
            artifact_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
            store = load_artifact_store(Path(tempdir) / "controlplane")
            with self.assertRaises(ValueError):
                reconcile_artifact_store(store)

    def test_high_risk_capability_requires_baseline(self) -> None:
        with copy_controlplane_tree() as tempdir:
            artifact_path = Path(tempdir) / "controlplane" / "definitions" / "policies" / "exec-rootonly.yaml"
            raw = yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
            raw["spec"]["approval_mode"] = "auto"
            artifact_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
            with self.assertRaises(ValueError):
                reconcile_artifact_store(load_artifact_store(Path(tempdir) / "controlplane"))

    def test_deprecated_artifact_emits_warning(self) -> None:
        with copy_controlplane_tree() as tempdir:
            artifact_path = Path(tempdir) / "controlplane" / "definitions" / "brokers" / "info-broker.yaml"
            raw = yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
            raw["metadata"]["deprecated"] = True
            raw["metadata"]["replaced_by"] = "new-info-broker"
            artifact_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                load_artifact_store(Path(tempdir) / "controlplane")
            self.assertTrue(caught)
            self.assertIn("deprecated artifact", str(caught[0].message))

    def test_real_controlplane_reconciles(self) -> None:
        reconciled = reconcile_artifact_store(load_real_artifact_store())
        self.assertIn("info.lookup", reconciled.capability_registry)
