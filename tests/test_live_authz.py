from decimal import Decimal
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kil.domain import (
    ActionRequest,
    DecisionOutcome,
    LocalEvidence,
    ReductionProfile,
)
from kil.live_authz import AuthorizationAdapter, LiveFixture, LiveTrack
from kil.q_state import QStateClaims, issue_q_state, key_id


SUBJECT = "spiffe://kil.local/workload/demo"
REQUEST = ActionRequest("v3a-request-1", SUBJECT, "admin_action", 105)
PROFILE = ReductionProfile(Decimal("0.25"), Decimal("25"), 3)


def q_claims(audience):
    return QStateClaims(
        schema_version="kil.q-state.v0",
        state_id=f"q-{audience}",
        issuer="https://lab-issuer.kil.invalid",
        subject=SUBJECT,
        audience=audience,
        authority_class="admin_action",
        action_class="consequential_admin",
        issued_at_s=100,
        not_before_s=100,
        expires_at_s=110,
        evidence_horizon_s=99,
        trust_proof_id="tp-v3a-1",
        trust_proof_digest="sha256:" + "a" * 64,
        envelope_result_id="ke-v3a-1",
        envelope_result_digest="sha256:" + "b" * 64,
        deployment_profile="kil-lab-v3@0",
        charge=Decimal("80"),
        threshold=Decimal("40"),
        history_count=5,
        minimum_history=2,
        veto_clear=True,
        envelope_allows=True,
        decay_rate=Decimal("0"),
        maximum_charge=Decimal("100"),
        model_version="kil-decay-v1",
        parameter_version="kil-v3a-fixture-v1",
    )


class LiveAuthorizationTest(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public_key = self.private_key.public_key()
        self.keys = {key_id(public_key): public_key}

    def fixture(self, track, *, audience=None, untrusted_headers=()):
        expected_audience = {
            LiveTrack.SIGNED_STATE_ONLY: "kil-v3-signed",
            LiveTrack.SIGNED_PLUS_LOCAL_REDUCE: "kil-v3-local",
        }.get(track)
        token = None
        if expected_audience is not None:
            token = issue_q_state(
                q_claims(audience or expected_audience), self.private_key
            )
        return LiveFixture(
            request=REQUEST,
            action_class="consequential_admin",
            credential_valid=True,
            policy_allows_action=True,
            q_state_jws=token,
            local_evidence=LocalEvidence(Decimal("0.9"), Decimal("0"), True),
            reduction_profile=PROFILE,
            untrusted_headers=untrusted_headers,
        )

    def test_same_case_differentiates_the_three_fixed_tracks(self):
        adapters = (
            AuthorizationAdapter(LiveTrack.CREDENTIAL_POLICY_BASELINE),
            AuthorizationAdapter(LiveTrack.SIGNED_STATE_ONLY, keys=self.keys),
            AuthorizationAdapter(
                LiveTrack.SIGNED_PLUS_LOCAL_REDUCE, keys=self.keys
            ),
        )
        tracks = tuple(LiveTrack)
        decisions = tuple(
            adapter.evaluate(self.fixture(track))
            for adapter, track in zip(adapters, tracks, strict=True)
        )
        self.assertEqual(
            tuple(item.outcome for item in decisions),
            (DecisionOutcome.PERMIT, DecisionOutcome.PERMIT, DecisionOutcome.DENY),
        )
        self.assertEqual(tuple(item.track for item in decisions), tracks)
        self.assertEqual(
            decisions[1].engine_record.effective_charge, Decimal("80")
        )
        self.assertEqual(decisions[2].engine_record.effective_charge, Decimal("0"))

    def test_request_metadata_cannot_change_adapter_mode(self):
        adapter = AuthorizationAdapter(
            LiveTrack.SIGNED_PLUS_LOCAL_REDUCE, keys=self.keys
        )
        decision = adapter.evaluate(
            self.fixture(
                LiveTrack.SIGNED_PLUS_LOCAL_REDUCE,
                untrusted_headers=(("x-kil-mode", "signed_state_only"),),
            )
        )
        self.assertEqual(decision.track, LiveTrack.SIGNED_PLUS_LOCAL_REDUCE)
        self.assertEqual(decision.outcome, DecisionOutcome.DENY)
        self.assertIn("untrusted_mode_header_ignored", decision.adapter_reasons)

    def test_adapter_track_cannot_be_reassigned_after_construction(self):
        adapter = AuthorizationAdapter(
            LiveTrack.SIGNED_PLUS_LOCAL_REDUCE, keys=self.keys
        )
        with self.assertRaises(AttributeError):
            adapter.track = LiveTrack.SIGNED_STATE_ONLY
        self.assertEqual(adapter.track, LiveTrack.SIGNED_PLUS_LOCAL_REDUCE)

    def test_wrong_track_audience_fails_closed(self):
        adapter = AuthorizationAdapter(
            LiveTrack.SIGNED_PLUS_LOCAL_REDUCE, keys=self.keys
        )
        decision = adapter.evaluate(
            self.fixture(
                LiveTrack.SIGNED_PLUS_LOCAL_REDUCE,
                audience="kil-v3-signed",
            )
        )
        self.assertEqual(decision.outcome, DecisionOutcome.DENY)
        self.assertEqual(
            decision.adapter_reasons, ("q_state_verification_failed",)
        )
        self.assertIsNone(decision.engine_record)

    def test_missing_state_fails_closed_on_kil_track(self):
        fixture = LiveFixture(
            request=REQUEST,
            action_class="consequential_admin",
            credential_valid=True,
            policy_allows_action=True,
            q_state_jws=None,
            local_evidence=None,
            reduction_profile=None,
        )
        decision = AuthorizationAdapter(
            LiveTrack.SIGNED_STATE_ONLY, keys=self.keys
        ).evaluate(fixture)
        self.assertEqual(decision.outcome, DecisionOutcome.DENY)
        self.assertEqual(decision.adapter_reasons, ("q_state_missing",))

    def test_decision_digest_is_stable_for_the_same_input(self):
        adapter = AuthorizationAdapter(LiveTrack.SIGNED_STATE_ONLY, keys=self.keys)
        fixture = self.fixture(LiveTrack.SIGNED_STATE_ONLY)
        first = adapter.evaluate(fixture)
        second = adapter.evaluate(fixture)
        self.assertEqual(first, second)
        self.assertEqual(len(first.decision_digest), 64)


if __name__ == "__main__":
    unittest.main()
