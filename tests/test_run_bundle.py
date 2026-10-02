from dataclasses import replace
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from kil.domain import ReductionProfile
from kil.replay import replay
from kil.run_bundle import write_run_bundle
from kil.scenario import load_scenario


FIXTURE = Path(__file__).parent / "fixtures/scenario-minimal-v1.json"
PROFILE = ReductionProfile(Decimal("0.25"), Decimal("25"), 3)
EXPECTED_FILES = {
    "manifest.json",
    "scenario.json",
    "states.jsonl",
    "decisions.jsonl",
    "metrics.json",
    "summary.md",
    "SHA256SUMS",
}


class RunBundleTest(unittest.TestCase):
    def test_same_inputs_produce_same_run_id_and_artifacts(self):
        scenario = load_scenario(FIXTURE)
        report = replay(scenario, PROFILE)
        with TemporaryDirectory() as first, TemporaryDirectory() as second:
            one = write_run_bundle(
                report, scenario, Path(first), "test-commit", "profile-v0"
            )
            two = write_run_bundle(
                report, scenario, Path(second), "test-commit", "profile-v0"
            )
            self.assertEqual(one.name, two.name)
            for name in EXPECTED_FILES:
                self.assertEqual((one / name).read_bytes(), (two / name).read_bytes())

    def test_bundle_never_labels_historical_report_validated(self):
        scenario = load_scenario(FIXTURE)
        report = replay(scenario, PROFILE)
        with TemporaryDirectory() as directory:
            bundle = write_run_bundle(
                report, scenario, Path(directory), "test-commit", "profile-v0"
            )
            manifest = (bundle / "manifest.json").read_text(encoding="utf-8")
            self.assertIn('"evidence_class":"modeled"', manifest)
            self.assertNotIn('"evidence_class":"validated"', manifest)

    def test_bundle_contains_the_complete_publication_contract(self):
        scenario = load_scenario(FIXTURE)
        report = replay(scenario, PROFILE)
        with TemporaryDirectory() as directory:
            bundle = write_run_bundle(
                report, scenario, Path(directory), "test-commit", "profile-v0"
            )
            self.assertEqual({path.name for path in bundle.iterdir()}, EXPECTED_FILES)

    def test_checksums_cover_every_public_artifact(self):
        scenario = load_scenario(FIXTURE)
        report = replay(scenario, PROFILE)
        with TemporaryDirectory() as directory:
            bundle = write_run_bundle(
                report, scenario, Path(directory), "test-commit", "profile-v0"
            )
            lines = (bundle / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), len(EXPECTED_FILES) - 1)
            for line in lines:
                digest, name = line.split("  ", 1)
                self.assertEqual(digest, sha256((bundle / name).read_bytes()).hexdigest())

    def test_rejects_mismatched_or_ambiguous_identity_inputs(self):
        scenario = load_scenario(FIXTURE)
        report = replay(scenario, PROFILE)
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "scenario_id"):
                write_run_bundle(
                    replace(report, scenario_id="different"),
                    scenario,
                    Path(directory),
                    "test-commit",
                    "profile-v0",
                )
            for implementation, profile, expected in (
                (" ", "profile-v0", "implementation_version"),
                ("test-commit", " ", "profile_id"),
            ):
                with self.subTest(expected=expected):
                    with self.assertRaisesRegex(ValueError, expected):
                        write_run_bundle(
                            report,
                            scenario,
                            Path(directory),
                            implementation,
                            profile,
                        )


if __name__ == "__main__":
    unittest.main()
