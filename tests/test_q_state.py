from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kil.q_state import (
    QStateClaims,
    QStateVerificationError,
    issue_q_state,
    key_id,
    verify_q_state,
)


def claims(**changes):
    value = QStateClaims(
        schema_version="kil.q-state.v0",
        state_id="q-v3a-1",
        issuer="https://lab-issuer.kil.invalid",
        subject="spiffe://kil.local/workload/demo",
        audience="kil-v3-signed",
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
    return replace(value, **changes)


class QStateClaimsTest(unittest.TestCase):
    def test_round_trips_the_exact_payload(self):
        original = claims()
        self.assertEqual(QStateClaims.from_payload(original.to_payload()), original)

    def test_rejects_more_than_ten_seconds_of_validity(self):
        with self.assertRaisesRegex(ValueError, "ten seconds"):
            claims(expires_at_s=111)

    def test_rejects_unknown_payload_fields(self):
        payload = claims().to_payload()
        payload["mode"] = "signed_state_only"
        with self.assertRaisesRegex(ValueError, "unknown"):
            QStateClaims.from_payload(payload)

    def test_decimal_wire_values_are_canonical_fixed_point(self):
        for malformed in ("1e1", "+80", "-0", "080", "80.0", ".5"):
            with self.subTest(malformed=malformed):
                payload = claims().to_payload()
                payload["charge"] = malformed
                with self.assertRaisesRegex(ValueError, "canonical fixed-point"):
                    QStateClaims.from_payload(payload)
        self.assertEqual(
            claims(charge=Decimal("8E+1")).to_payload()["charge"], "80"
        )
        self.assertEqual(
            claims(charge=Decimal("0.2500")).to_payload()["charge"], "0.25"
        )
        self.assertEqual(
            claims(charge=Decimal("0E-100000")).to_payload()["charge"], "0"
        )
        self.assertEqual(
            claims(charge=Decimal("0E+100000")).to_payload()["charge"], "0"
        )
        with self.assertRaisesRegex(ValueError, "negative zero"):
            claims(charge=Decimal("-0"))
        for enormous in (Decimal("1E+1000000000"), Decimal("1E-1000000000")):
            with self.subTest(enormous=str(enormous)):
                with self.assertRaisesRegex(ValueError, "wire length"):
                    claims(charge=enormous, maximum_charge=enormous)

    def test_schema_uses_the_same_canonical_decimal_pattern(self):
        schema = json.loads(
            (Path(__file__).resolve().parents[1] / "schemas/q-state-v0.schema.json")
            .read_text(encoding="utf-8")
        )
        expected = r"^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$"
        for name in ("charge", "threshold", "decay_rate", "maximum_charge"):
            self.assertEqual(schema["properties"][name]["pattern"], expected)
            self.assertEqual(schema["properties"][name]["maxLength"], 64)

    def test_zero_with_extreme_exponent_bypasses_fixed_point_expansion(self):
        builtin_format = format

        def guarded_format(value, specification):
            if (
                isinstance(value, Decimal)
                and value.is_zero()
                and abs(value.as_tuple().exponent) > 64
            ):
                raise AssertionError("unsafe zero expansion")
            return builtin_format(value, specification)

        with patch("kil.q_state.format", side_effect=guarded_format, create=True):
            payload = claims(charge=Decimal("0E-100000")).to_payload()
        self.assertEqual(payload["charge"], "0")

    def test_converts_only_claimed_authority_to_v1_state(self):
        state = claims().to_composite_state()
        self.assertEqual(state.identity, "spiffe://kil.local/workload/demo")
        self.assertEqual(state.authority_class, "admin_action")
        self.assertTrue(state.authentic)


class QStateSignatureTest(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        public_key = self.private_key.public_key()
        other_public_key = self.other_key.public_key()
        self.keys = {key_id(public_key): public_key}
        self.other_keys = {key_id(other_public_key): other_public_key}

    def verify(self, token, **changes):
        arguments = {
            "keys": self.keys,
            "now_s": 105,
            "expected_subject": "spiffe://kil.local/workload/demo",
            "expected_audience": "kil-v3-signed",
            "expected_authority_class": "admin_action",
            "expected_action_class": "consequential_admin",
            "revoked_state_ids": frozenset(),
        }
        arguments.update(changes)
        return verify_q_state(token, **arguments)

    def test_issues_and_verifies_a_bound_compact_jws(self):
        token = issue_q_state(claims(), self.private_key)
        verified = self.verify(token)
        self.assertEqual(verified.claims, claims())
        self.assertEqual(verified.composite_state, claims().to_composite_state())
        self.assertEqual(verified.key_id, key_id(self.private_key.public_key()))

    def test_payload_or_signature_tampering_fails_closed(self):
        token = issue_q_state(claims(), self.private_key)
        parts = token.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        with self.assertRaisesRegex(QStateVerificationError, "signature"):
            self.verify(".".join(parts))

    def test_non_ascii_compact_segment_fails_through_verification_error(self):
        token = issue_q_state(claims(), self.private_key)
        header, _, signature = token.split(".")
        malformed = f"{header}.é.{signature}"
        with self.assertRaisesRegex(QStateVerificationError, "base64url"):
            self.verify(malformed)

    def test_unknown_verification_key_fails_closed(self):
        token = issue_q_state(claims(), self.private_key)
        with self.assertRaisesRegex(QStateVerificationError, "key"):
            self.verify(token, keys=self.other_keys)

    def test_time_and_revocation_checks_fail_closed(self):
        token = issue_q_state(claims(), self.private_key)
        cases = (
            ({"now_s": 99}, "not yet valid"),
            ({"now_s": 110}, "expired"),
            ({"revoked_state_ids": frozenset({"q-v3a-1"})}, "revoked"),
        )
        for changes, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(QStateVerificationError, reason):
                    self.verify(token, **changes)

    def test_subject_audience_authority_and_action_bindings_fail_closed(self):
        token = issue_q_state(claims(), self.private_key)
        cases = (
            ({"expected_subject": "spiffe://kil.local/workload/other"}, "subject"),
            ({"expected_audience": "kil-v3-local"}, "audience"),
            ({"expected_authority_class": "read"}, "authority class"),
            ({"expected_action_class": "benign_read"}, "action class"),
        )
        for changes, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(QStateVerificationError, reason):
                    self.verify(token, **changes)


if __name__ == "__main__":
    unittest.main()
