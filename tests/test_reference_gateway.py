from decimal import Decimal
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kil.domain import ActionRequest, DecisionOutcome, LocalEvidence, ReductionProfile
from kil.live_authz import AuthorizationAdapter, LiveFixture, LiveTrack
from kil.q_state import QStateClaims, issue_q_state, key_id
from kil.reference_gateway import ReferenceGateway, TargetMarker


SUBJECT = "spiffe://kil.local/workload/demo"


def claims(audience):
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


class ReferenceGatewayTest(unittest.TestCase):
    def setUp(self):
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public_key = private_key.public_key()
        keys = {key_id(public_key): public_key}
        request = ActionRequest("v3a-request-1", SUBJECT, "admin_action", 105)
        profile = ReductionProfile(Decimal("0.25"), Decimal("25"), 3)
        self.signed_fixture = LiveFixture(
            request=request,
            action_class="consequential_admin",
            credential_valid=True,
            policy_allows_action=True,
            q_state_jws=issue_q_state(claims("kil-v3-signed"), private_key),
            local_evidence=LocalEvidence(Decimal("0.9"), Decimal("0"), True),
            reduction_profile=profile,
        )
        self.local_fixture = LiveFixture(
            request=request,
            action_class="consequential_admin",
            credential_valid=True,
            policy_allows_action=True,
            q_state_jws=issue_q_state(claims("kil-v3-local"), private_key),
            local_evidence=LocalEvidence(Decimal("0.9"), Decimal("0"), True),
            reduction_profile=profile,
        )
        self.signed_adapter = AuthorizationAdapter(
            LiveTrack.SIGNED_STATE_ONLY, keys=keys
        )
        self.local_adapter = AuthorizationAdapter(
            LiveTrack.SIGNED_PLUS_LOCAL_REDUCE, keys=keys
        )

    def test_denied_request_has_no_target_marker(self):
        target = TargetMarker()
        result = ReferenceGateway(self.local_adapter, target).handle(
            self.local_fixture
        )
        self.assertEqual(result.decision.outcome, DecisionOutcome.DENY)
        self.assertFalse(result.forwarded)
        self.assertEqual(target.records, ())
        self.assertEqual(result.marker_count, 0)
        self.assertTrue(result.proof_valid)

    def test_permitted_request_has_exactly_one_target_marker(self):
        target = TargetMarker()
        result = ReferenceGateway(self.signed_adapter, target).handle(
            self.signed_fixture
        )
        self.assertEqual(result.decision.outcome, DecisionOutcome.PERMIT)
        self.assertTrue(result.forwarded)
        self.assertEqual(len(target.records), 1)
        self.assertEqual(
            target.records[0].request_id,
            self.signed_fixture.request.request_id,
        )
        self.assertEqual(result.marker_count, 1)
        self.assertTrue(result.proof_valid)


if __name__ == "__main__":
    unittest.main()
