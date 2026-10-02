from dataclasses import replace
from decimal import Decimal
import unittest

from kil.domain import (
    ActionRequest,
    CompositeState,
    DecisionOutcome,
    EnforcementMode,
    FailureDisposition,
    LocalEvidence,
    ReasonCode,
    ReductionProfile,
)
from kil.engine import decide


def state(**changes):
    value = CompositeState(
        state_id="q-1",
        identity="worker",
        authority_class="admin",
        issued_at_s=0,
        not_before_s=0,
        expires_at_s=100,
        charge=Decimal("80"),
        threshold=Decimal("40"),
        history_count=5,
        minimum_history=2,
        authentic=True,
        veto_clear=True,
        envelope_allows=True,
        decay_rate=Decimal("0"),
        maximum_charge=Decimal("100"),
    )
    return replace(value, **changes)


REQUEST = ActionRequest("r-1", "worker", "admin", 10)
PROFILE = ReductionProfile(Decimal("0.25"), Decimal("25"), 3)


class EngineTest(unittest.TestCase):
    def test_valid_signed_state_permits(self):
        record = decide(REQUEST, state(), EnforcementMode.SIGNED_STATE_ONLY)
        self.assertEqual(record.outcome, DecisionOutcome.PERMIT)
        self.assertEqual(record.reasons, (ReasonCode.PERMITTED,))

    def test_high_precision_signed_charge_produces_valid_monotonic_record(self):
        exact_charge = Decimal("0.99999999999999999999999999996")
        composite = state(
            charge=exact_charge,
            threshold=Decimal("0.5"),
            decay_rate=Decimal("0"),
            maximum_charge=Decimal("1"),
        )

        record = decide(REQUEST, composite, EnforcementMode.SIGNED_STATE_ONLY)
        repeated = decide(REQUEST, composite, EnforcementMode.SIGNED_STATE_ONLY)

        self.assertEqual(record, repeated)
        self.assertEqual(record.outcome, DecisionOutcome.PERMIT)
        self.assertLessEqual(record.effective_charge, record.decayed_charge)
        self.assertLessEqual(record.decayed_charge, record.signed_charge)

    def test_veto_cannot_be_overridden_by_high_charge(self):
        record = decide(
            REQUEST, state(veto_clear=False), EnforcementMode.SIGNED_STATE_ONLY
        )
        self.assertEqual(record.outcome, DecisionOutcome.DENY)
        self.assertIn(ReasonCode.VETO, record.reasons)

    def test_invalid_and_expired_state_deny(self):
        unauthentic = decide(
            REQUEST, state(authentic=False), EnforcementMode.SIGNED_STATE_ONLY
        )
        expired = decide(
            replace(REQUEST, timestamp_s=100),
            state(),
            EnforcementMode.SIGNED_STATE_ONLY,
        )
        self.assertIn(ReasonCode.STATE_UNAUTHENTIC, unauthentic.reasons)
        self.assertIn(ReasonCode.STATE_EXPIRED, expired.reasons)

    def test_binding_envelope_and_history_gates_are_independent(self):
        cases = (
            (
                replace(REQUEST, identity="other"),
                state(),
                ReasonCode.IDENTITY_MISMATCH,
            ),
            (
                replace(REQUEST, authority_class="read"),
                state(),
                ReasonCode.CLASS_MISMATCH,
            ),
            (REQUEST, state(envelope_allows=False), ReasonCode.OUTSIDE_ENVELOPE),
            (REQUEST, state(history_count=1), ReasonCode.INSUFFICIENT_HISTORY),
            (
                replace(REQUEST, timestamp_s=-1),
                state(),
                ReasonCode.STATE_NOT_YET_VALID,
            ),
        )
        for request, composite, expected in cases:
            with self.subTest(expected=expected):
                record = decide(
                    request, composite, EnforcementMode.SIGNED_STATE_ONLY
                )
                self.assertEqual(record.outcome, DecisionOutcome.DENY)
                self.assertIn(expected, record.reasons)

    def test_local_reduction_can_deny_but_never_increase(self):
        evidence = LocalEvidence(Decimal("0.9"), Decimal("0"), True)
        record = decide(
            REQUEST,
            state(),
            EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
            evidence,
            PROFILE,
        )
        self.assertEqual(record.outcome, DecisionOutcome.DENY)
        self.assertLessEqual(record.effective_charge, record.decayed_charge)

    def test_coupled_loss_only_reduces_effective_charge(self):
        plain = decide(
            REQUEST,
            state(),
            EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
            LocalEvidence(Decimal("0.1"), Decimal("0"), True),
            PROFILE,
        )
        coupled = decide(
            REQUEST,
            state(),
            EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
            LocalEvidence(Decimal("0.1"), Decimal("10"), True),
            PROFILE,
        )
        self.assertEqual(
            coupled.effective_charge, plain.effective_charge - Decimal("10")
        )

    def test_stale_local_evidence_fails_closed_by_default(self):
        evidence = LocalEvidence(Decimal("0.1"), Decimal("0"), False)
        record = decide(
            REQUEST,
            state(),
            EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
            evidence,
            PROFILE,
        )
        self.assertEqual(record.outcome, DecisionOutcome.DENY)
        self.assertIn(ReasonCode.LOCAL_EVIDENCE_STALE, record.reasons)

    def test_stale_local_evidence_can_fail_constrained_when_explicit(self):
        evidence = LocalEvidence(Decimal("0.1"), Decimal("0"), False)
        record = decide(
            REQUEST,
            state(),
            EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
            evidence,
            PROFILE,
            FailureDisposition.CONSTRAINED,
        )
        self.assertEqual(record.outcome, DecisionOutcome.CONSTRAIN)

    def test_veto_takes_precedence_over_stale_local_evidence(self):
        evidence = LocalEvidence(Decimal("0.1"), Decimal("0"), False)
        record = decide(
            REQUEST,
            state(veto_clear=False),
            EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
            evidence,
            PROFILE,
        )
        self.assertEqual(record.outcome, DecisionOutcome.DENY)
        self.assertIn(ReasonCode.VETO, record.reasons)

    def test_action_cannot_authorize_itself(self):
        evidence = LocalEvidence(Decimal("0"), Decimal("0"), True)
        record = decide(
            REQUEST,
            state(charge=Decimal("39")),
            EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
            evidence,
            PROFILE,
        )
        self.assertEqual(record.effective_charge, Decimal("39"))
        self.assertEqual(record.outcome, DecisionOutcome.DENY)

    def test_invalid_required_runtime_types_are_rejected(self):
        cases = (
            ((object(), state(), EnforcementMode.SIGNED_STATE_ONLY), "request"),
            ((REQUEST, object(), EnforcementMode.SIGNED_STATE_ONLY), "state"),
            ((REQUEST, state(), "signed_state_only"), "mode"),
        )
        for arguments, field in cases:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    decide(*arguments)

    def test_invalid_local_runtime_types_and_disposition_are_rejected(self):
        cases = (
            (
                (REQUEST, state(), EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE),
                {"local_evidence": object()},
                "local_evidence",
            ),
            (
                (REQUEST, state(), EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE),
                {
                    "local_evidence": LocalEvidence(
                        Decimal("0.1"), Decimal("0"), True
                    ),
                    "reduction_profile": object(),
                },
                "reduction_profile",
            ),
            (
                (REQUEST, state(), EnforcementMode.SIGNED_STATE_ONLY),
                {"failure_disposition": "closed"},
                "failure_disposition",
            ),
        )
        for arguments, keywords, field in cases:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    decide(*arguments, **keywords)

    def test_signed_only_mode_does_not_consume_local_reduction_inputs(self):
        record = decide(
            REQUEST,
            state(),
            EnforcementMode.SIGNED_STATE_ONLY,
            LocalEvidence(Decimal("0.9"), Decimal("80"), True),
            PROFILE,
        )

        self.assertEqual(record.outcome, DecisionOutcome.PERMIT)
        self.assertEqual(record.reasons, (ReasonCode.PERMITTED,))
        self.assertEqual(record.effective_charge, record.decayed_charge)

    def test_local_reduce_missing_inputs_follow_stale_failure_path(self):
        evidence = LocalEvidence(Decimal("0.1"), Decimal("0"), True)
        cases = (
            {},
            {"local_evidence": evidence},
            {"reduction_profile": PROFILE},
        )
        for keywords in cases:
            with self.subTest(keywords=keywords):
                record = decide(
                    REQUEST,
                    state(),
                    EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
                    **keywords,
                )
                self.assertEqual(record.outcome, DecisionOutcome.DENY)
                self.assertIn(ReasonCode.LOCAL_EVIDENCE_STALE, record.reasons)

    def test_unrepresentable_decay_fails_closed(self):
        record = decide(
            REQUEST,
            state(decay_rate=Decimal("1E+999999")),
            EnforcementMode.SIGNED_STATE_ONLY,
        )

        self.assertEqual(record.outcome, DecisionOutcome.DENY)
        self.assertIn(ReasonCode.ARITHMETIC_FAILURE, record.reasons)
        self.assertEqual(record.decayed_charge, Decimal("0"))
        self.assertEqual(record.effective_charge, Decimal("0"))

    def test_veto_reason_precedes_arithmetic_failure(self):
        record = decide(
            REQUEST,
            state(veto_clear=False, decay_rate=Decimal("1E+999999")),
            EnforcementMode.SIGNED_STATE_ONLY,
        )

        self.assertEqual(record.outcome, DecisionOutcome.DENY)
        self.assertEqual(record.reasons[0], ReasonCode.VETO)
        self.assertIn(ReasonCode.ARITHMETIC_FAILURE, record.reasons)


if __name__ == "__main__":
    unittest.main()
