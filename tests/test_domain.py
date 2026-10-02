from dataclasses import FrozenInstanceError, fields, replace
from decimal import Decimal
import unittest

from kil.domain import (
    ActionRequest,
    CompositeState,
    DecisionOutcome,
    DecisionRecord,
    EnforcementMode,
    FailureDisposition,
    LocalEvidence,
    ReasonCode,
    ReductionProfile,
)


def state(**changes):
    value = CompositeState(
        state_id="q-1",
        identity="worker",
        authority_class="admin",
        issued_at_s=10,
        not_before_s=10,
        expires_at_s=20,
        charge=Decimal("50"),
        threshold=Decimal("40"),
        history_count=5,
        minimum_history=2,
        authentic=True,
        veto_clear=True,
        envelope_allows=True,
        decay_rate=Decimal("0.1"),
        maximum_charge=Decimal("100"),
    )
    return replace(value, **changes)


def decision_record(**changes):
    values = {
        "request_id": "r-1",
        "state_id": "q-1",
        "mode": EnforcementMode.SIGNED_STATE_ONLY,
        "outcome": DecisionOutcome.PERMIT,
        "reasons": (ReasonCode.PERMITTED,),
        "signed_charge": Decimal("50"),
        "decayed_charge": Decimal("49"),
        "effective_charge": Decimal("49"),
    }
    return DecisionRecord(**(values | changes))


class DomainTest(unittest.TestCase):
    def test_composite_state_rejects_invalid_validity_window(self):
        invalid_windows = (
            {"issued_at_s": 11, "not_before_s": 10},
            {"not_before_s": 20, "expires_at_s": 20},
        )

        for changes in invalid_windows:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, "validity"):
                    state(**changes)

    def test_local_evidence_rejects_unbounded_divergence(self):
        with self.assertRaisesRegex(ValueError, "divergence"):
            LocalEvidence(Decimal("1.1"), Decimal("0"), True)

    def test_request_and_mode_values_are_stable(self):
        request = ActionRequest("r-1", "worker", "admin", 30)

        self.assertEqual(request.request_id, "r-1")
        self.assertEqual(
            EnforcementMode.SIGNED_STATE_ONLY.value, "signed_state_only"
        )
        self.assertEqual(
            EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE.value,
            "signed_plus_local_reduce",
        )

    def test_public_enum_values_are_stable(self):
        expected = {
            DecisionOutcome: {
                "PERMIT": "permit",
                "CONSTRAIN": "constrain",
                "DENY": "deny",
                "INDETERMINATE": "indeterminate",
            },
            FailureDisposition: {
                "CLOSED": "closed",
                "CONSTRAINED": "constrained",
            },
            ReasonCode: {
                "PERMITTED": "permitted",
                "IDENTITY_MISMATCH": "identity_mismatch",
                "CLASS_MISMATCH": "class_mismatch",
                "VETO": "immutable_veto",
                "OUTSIDE_ENVELOPE": "outside_environmental_envelope",
                "STATE_UNAUTHENTIC": "state_unauthentic",
                "STATE_NOT_YET_VALID": "state_not_yet_valid",
                "STATE_EXPIRED": "state_expired",
                "ARITHMETIC_FAILURE": "arithmetic_failure",
                "LOCAL_EVIDENCE_STALE": "local_evidence_stale",
                "INSUFFICIENT_CHARGE": "insufficient_charge",
                "INSUFFICIENT_HISTORY": "insufficient_history",
            },
        }

        for enum_type, members in expected.items():
            with self.subTest(enum=enum_type.__name__):
                self.assertEqual(
                    {name: member.value for name, member in enum_type.__members__.items()},
                    members,
                )

    def test_records_are_frozen_and_slotted(self):
        records = (
            ActionRequest("r-1", "worker", "admin", 30),
            state(),
            LocalEvidence(Decimal("0.2"), Decimal("1"), True),
            ReductionProfile(Decimal("0.25"), Decimal("25"), 3),
            DecisionRecord(
                request_id="r-1",
                state_id="q-1",
                mode=EnforcementMode.SIGNED_STATE_ONLY,
                outcome=DecisionOutcome.PERMIT,
                reasons=(ReasonCode.PERMITTED,),
                signed_charge=Decimal("50"),
                decayed_charge=Decimal("49"),
                effective_charge=Decimal("49"),
            ),
        )

        for record in records:
            with self.subTest(record=type(record).__name__):
                field_name = fields(record)[0].name
                with self.assertRaises(FrozenInstanceError):
                    setattr(record, field_name, getattr(record, field_name))
                self.assertFalse(hasattr(record, "__dict__"))

    def test_action_request_rejects_type_and_identifier_bypasses(self):
        cases = (
            ((7, "worker", "admin", 30), "request_id"),
            (("r-1", object(), "admin", 30), "identity"),
            (("r-1", "worker", None, 30), "authority_class"),
            (("r-1", "worker", "admin", True), "timestamp_s"),
            ((" ", "worker", "admin", 30), "request_id"),
            (
                (EnforcementMode.SIGNED_STATE_ONLY, "worker", "admin", 30),
                "request_id",
            ),
        )

        for arguments, field in cases:
            with self.subTest(field=field, value=arguments):
                with self.assertRaisesRegex(ValueError, field):
                    ActionRequest(*arguments)

    def test_action_request_rejects_unrepresentable_timestamp_immediately(self):
        huge_timestamp = 1 << 1_000_000

        with self.assertRaisesRegex(ValueError, "timestamp_s"):
            ActionRequest("r-1", "worker", "admin", huge_timestamp)

    def test_signed_64_bit_timestamp_boundaries_are_enforced(self):
        minimum = -(2**63)
        maximum = 2**63 - 1

        for timestamp in (minimum, maximum):
            with self.subTest(record="request", timestamp=timestamp):
                self.assertEqual(
                    ActionRequest("r-1", "worker", "admin", timestamp).timestamp_s,
                    timestamp,
                )

        valid_states = (
            {
                "issued_at_s": minimum,
                "not_before_s": minimum + 1,
                "expires_at_s": minimum + 2,
            },
            {
                "issued_at_s": maximum - 2,
                "not_before_s": maximum - 1,
                "expires_at_s": maximum,
            },
        )
        for changes in valid_states:
            with self.subTest(record="state", changes=changes):
                self.assertIsInstance(state(**changes), CompositeState)

        invalid_cases = (
            ("request", minimum - 1),
            ("request", maximum + 1),
            ("issued_at_s", minimum - 1),
            ("not_before_s", minimum - 1),
            ("expires_at_s", maximum + 1),
        )
        for field, timestamp in invalid_cases:
            with self.subTest(field=field, timestamp=timestamp):
                message = "timestamp_s" if field == "request" else field
                with self.assertRaisesRegex(ValueError, message):
                    if field == "request":
                        ActionRequest("r-1", "worker", "admin", timestamp)
                    else:
                        state(**{field: timestamp})

    def test_composite_state_rejects_type_bypasses(self):
        cases = (
            ({"state_id": 1}, "state_id"),
            ({"identity": b"worker"}, "identity"),
            ({"authority_class": object()}, "authority_class"),
            ({"issued_at_s": True}, "issued_at_s"),
            ({"not_before_s": Decimal("10")}, "not_before_s"),
            ({"expires_at_s": 20.0}, "expires_at_s"),
            ({"history_count": True}, "history_count"),
            ({"minimum_history": Decimal("2")}, "minimum_history"),
            ({"authentic": 1}, "authentic"),
            ({"veto_clear": "yes"}, "veto_clear"),
            ({"envelope_allows": None}, "envelope_allows"),
            ({"charge": 50}, "charge"),
            ({"threshold": "40"}, "threshold"),
            ({"decay_rate": 0.1}, "decay_rate"),
            ({"maximum_charge": 100}, "maximum_charge"),
        )

        for changes, field in cases:
            with self.subTest(field=field, value=changes[field]):
                with self.assertRaisesRegex(ValueError, field):
                    state(**changes)

    def test_composite_state_rejects_invalid_authority_profile(self):
        cases = (
            ({"charge": Decimal("NaN")}, "charge"),
            ({"threshold": Decimal("Infinity")}, "threshold"),
            ({"decay_rate": Decimal("-Infinity")}, "decay_rate"),
            ({"maximum_charge": Decimal("NaN")}, "maximum_charge"),
            ({"charge": Decimal("-1")}, "charge"),
            ({"threshold": Decimal("-1")}, "threshold"),
            ({"decay_rate": Decimal("-0.1")}, "decay_rate"),
            ({"maximum_charge": Decimal("-1")}, "maximum_charge"),
            ({"charge": Decimal("101")}, "maximum"),
            ({"history_count": -1}, "history"),
            ({"minimum_history": -1}, "history"),
        )

        for changes, message in cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, message):
                    state(**changes)

    def test_local_evidence_rejects_invalid_types_and_non_finite_values(self):
        cases = (
            (("0.2", Decimal("0"), True), "divergence"),
            ((Decimal("NaN"), Decimal("0"), True), "divergence"),
            ((Decimal("-0.1"), Decimal("0"), True), "divergence"),
            ((Decimal("0.2"), 0, True), "coupled_loss"),
            ((Decimal("0.2"), Decimal("Infinity"), True), "coupled_loss"),
            ((Decimal("0.2"), Decimal("-1"), True), "coupled_loss"),
            ((Decimal("0.2"), Decimal("0"), 1), "fresh"),
        )

        for arguments, field in cases:
            with self.subTest(field=field, value=arguments):
                with self.assertRaisesRegex(ValueError, field):
                    LocalEvidence(*arguments)

    def test_reduction_profile_enforces_decay_contract(self):
        cases = (
            (("0.25", Decimal("25"), 3), "divergence_threshold"),
            ((Decimal("NaN"), Decimal("25"), 3), "divergence_threshold"),
            ((Decimal("0"), Decimal("25"), 3), "divergence_threshold"),
            ((Decimal("0.25"), 25, 3), "loss_rate"),
            ((Decimal("0.25"), Decimal("Infinity"), 3), "loss_rate"),
            ((Decimal("0.25"), Decimal("-1"), 3), "loss_rate"),
            ((Decimal("0.25"), Decimal("25"), True), "exponent"),
            ((Decimal("0.25"), Decimal("25"), 1), "exponent"),
        )

        for arguments, field in cases:
            with self.subTest(field=field, value=arguments):
                with self.assertRaisesRegex(ValueError, field):
                    ReductionProfile(*arguments)

    def test_decision_record_rejects_runtime_bypasses_and_non_finite_charge(self):
        valid = {
            "request_id": "r-1",
            "state_id": "q-1",
            "mode": EnforcementMode.SIGNED_STATE_ONLY,
            "outcome": DecisionOutcome.PERMIT,
            "reasons": (ReasonCode.PERMITTED,),
            "signed_charge": Decimal("50"),
            "decayed_charge": Decimal("49"),
            "effective_charge": Decimal("49"),
        }
        cases = (
            ({"request_id": 1}, "request_id"),
            ({"state_id": None}, "state_id"),
            ({"mode": "signed_state_only"}, "mode"),
            ({"outcome": "permit"}, "outcome"),
            ({"reasons": [ReasonCode.PERMITTED]}, "reasons"),
            ({"reasons": ("permitted",)}, "reasons"),
            ({"signed_charge": Decimal("NaN")}, "signed_charge"),
            ({"decayed_charge": Decimal("Infinity")}, "decayed_charge"),
            ({"effective_charge": 49}, "effective_charge"),
            ({"effective_charge": Decimal("-1")}, "effective_charge"),
        )

        for changes, field in cases:
            with self.subTest(field=field, value=changes[field]):
                arguments = valid | changes
                with self.assertRaisesRegex(ValueError, field):
                    DecisionRecord(**arguments)

    def test_decision_record_rejects_increasing_authority(self):
        cases = (
            (
                {"decayed_charge": Decimal("51"), "effective_charge": Decimal("50")},
                "decayed_charge",
            ),
            ({"effective_charge": Decimal("50")}, "effective_charge"),
        )

        for changes, field in cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, field):
                    decision_record(**changes)

    def test_decision_record_enforces_outcome_reason_consistency(self):
        invalid_cases = (
            (
                {
                    "outcome": DecisionOutcome.PERMIT,
                    "reasons": (ReasonCode.PERMITTED, ReasonCode.VETO),
                },
                "PERMIT",
            ),
            (
                {"outcome": DecisionOutcome.PERMIT, "reasons": ()},
                "PERMIT",
            ),
            (
                {
                    "outcome": DecisionOutcome.DENY,
                    "reasons": (ReasonCode.PERMITTED,),
                },
                "PERMITTED",
            ),
            (
                {"outcome": DecisionOutcome.DENY, "reasons": ()},
                "DENY",
            ),
            (
                {"outcome": DecisionOutcome.CONSTRAIN, "reasons": ()},
                "CONSTRAIN",
            ),
        )

        for changes, message in invalid_cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, message):
                    decision_record(**changes)

    def test_decision_record_accepts_consistent_outcomes_and_reasons(self):
        valid_cases = (
            {},
            {
                "outcome": DecisionOutcome.DENY,
                "reasons": (ReasonCode.VETO,),
            },
            {
                "outcome": DecisionOutcome.CONSTRAIN,
                "reasons": (ReasonCode.LOCAL_EVIDENCE_STALE,),
            },
            {
                "outcome": DecisionOutcome.INDETERMINATE,
                "reasons": (ReasonCode.LOCAL_EVIDENCE_STALE,),
            },
        )

        for changes in valid_cases:
            with self.subTest(changes=changes):
                self.assertIsInstance(decision_record(**changes), DecisionRecord)


if __name__ == "__main__":
    unittest.main()
