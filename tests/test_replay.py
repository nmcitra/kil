from dataclasses import replace
from decimal import Decimal
from pathlib import Path
import unittest

from kil.domain import DecisionOutcome, ReductionProfile
from kil.evidence import EvidenceClass, LabeledValue
from kil.replay import ReplayReport, replay
from kil.scenario import load_scenario


FIXTURE = Path(__file__).parent / "fixtures/scenario-minimal-v1.json"
PROFILE = ReductionProfile(Decimal("0.25"), Decimal("25"), 3)


class ReplayTest(unittest.TestCase):
    def test_all_modes_consume_the_same_event(self):
        report = replay(load_scenario(FIXTURE), PROFILE)
        decision = report.decisions[0]
        self.assertEqual(decision.event_id, "hf-p1-cluster-api")
        self.assertTrue(decision.baseline_permit)
        self.assertEqual(decision.signed_state_only.outcome, DecisionOutcome.DENY)
        self.assertEqual(
            decision.signed_plus_local_reduce.outcome, DecisionOutcome.DENY
        )
        self.assertEqual(decision.evidence_class, EvidenceClass.MODELED)

    def test_historical_output_cannot_be_promoted_to_validated(self):
        report = replay(load_scenario(FIXTURE), PROFILE)
        self.assertEqual(report.evidence_class, EvidenceClass.MODELED)
        with self.assertRaisesRegex(ValueError, "modeled"):
            replace(report, evidence_class=EvidenceClass.VALIDATED)

    def test_denied_parent_marks_kil_descendant_unreachable_without_hiding_decision(self):
        scenario = load_scenario(FIXTURE)
        parent = scenario.events[0]
        child = replace(
            parent,
            event_id="child",
            request=replace(parent.request, request_id="child", timestamp_s=20),
            state_assumption=replace(
                parent.state_assumption,
                value=replace(
                    parent.state_assumption.value,
                    state_id="q-child",
                    charge=Decimal("80"),
                    history_count=5,
                ),
            ),
            depends_on=(parent.event_id,),
        )
        report = replay(replace(scenario, events=(parent, child)), PROFILE)
        descendant = report.decisions[1]
        self.assertTrue(descendant.baseline_reachable)
        self.assertFalse(descendant.signed_state_only_reachable)
        self.assertFalse(descendant.signed_plus_local_reduce_reachable)
        self.assertIsNotNone(descendant.signed_state_only)
        self.assertIsNotNone(descendant.signed_plus_local_reduce)

    def test_rejects_scenario_with_mislabeled_evidence(self):
        scenario = load_scenario(FIXTURE)
        event = scenario.events[0]
        mislabeled = replace(
            event,
            observed_summary=LabeledValue(
                event.observed_summary.value,
                EvidenceClass.VALIDATED,
                run_id="not-a-replay-run",
            ),
        )
        with self.assertRaisesRegex(ValueError, "observed_summary"):
            replay(replace(scenario, events=(mislabeled,)), PROFILE)

    def test_rejects_runtime_type_bypasses(self):
        scenario = load_scenario(FIXTURE)
        with self.assertRaisesRegex(ValueError, "scenario"):
            replay("scenario", PROFILE)
        with self.assertRaisesRegex(ValueError, "profile"):
            replay(scenario, "profile")


if __name__ == "__main__":
    unittest.main()
