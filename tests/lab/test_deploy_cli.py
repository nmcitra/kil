"""The lab deployer selects a portable kubectl executable."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lab import deploy_campaign


class StopBeforeClusterAccess(Exception):
    pass


class DeployCLISelectionTest(unittest.TestCase):
    def first_command(self, configured):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "kind": "List", "items": [
                    {"metadata": {"namespace": "ktp-campaign-review"}}
                ]
            }))
            calls = []

            def stop_at_first_command(argv, **_kwargs):
                calls.append(argv)
                raise StopBeforeClusterAccess

            with patch.dict(os.environ, {"KIL_LAB_KUBECTL": configured}), \
                    patch.object(deploy_campaign, "run", side_effect=stop_at_first_command):
                with self.assertRaises(StopBeforeClusterAccess):
                    deploy_campaign.deploy("ktp-campaign-review", manifest,
                                           root / "identity", root / "kubeconfig",
                                           root / "run")
            self.assertEqual(len(calls), 1)
            return calls[0][0]

    def test_uses_declared_lab_kubectl_executable(self):
        self.assertEqual(self.first_command("/opt/lab/kubectl"),
                         "/opt/lab/kubectl")

    def test_falls_back_to_kubectl_on_path(self):
        self.assertEqual(self.first_command(""), "kubectl")


if __name__ == "__main__":
    unittest.main()
