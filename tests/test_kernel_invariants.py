from decimal import Decimal, getcontext, localcontext
import unittest

from kil.canonical import (
    MAX_DEPTH,
    MAX_ITEMS,
    MAX_OUTPUT_BYTES,
    canonical_digest,
    canonical_json,
)
from kil.domain import (
    ActionRequest,
    CompositeState,
    DecisionOutcome,
    DecisionRecord,
    EnforcementMode,
    LocalEvidence,
    ReasonCode,
    ReductionProfile,
)
from kil.engine import decide


class KernelInvariantTest(unittest.TestCase):
    def setUp(self):
        self.request = ActionRequest("r", "i", "admin", 10)
        self.state = CompositeState(
            "q",
            "i",
            "admin",
            0,
            0,
            100,
            Decimal("80"),
            Decimal("40"),
            5,
            2,
            True,
            True,
            True,
            Decimal("0"),
            Decimal("100"),
        )
        self.profile = ReductionProfile(Decimal("0.25"), Decimal("25"), 3)

    def test_canonical_serialization_is_stable(self):
        left = {"b": Decimal("1.0"), "a": "value"}
        right = {"a": "value", "b": Decimal("1.0")}
        self.assertEqual(canonical_json(left), canonical_json(right))
        self.assertEqual(canonical_digest(left), canonical_digest(right))

    def test_decision_record_serializes_dataclasses_enums_and_decimals(self):
        record = DecisionRecord(
            "r",
            "q",
            EnforcementMode.SIGNED_STATE_ONLY,
            DecisionOutcome.PERMIT,
            (ReasonCode.PERMITTED,),
            Decimal("80.0"),
            Decimal("79.5"),
            Decimal("79.5"),
        )
        self.assertEqual(
            canonical_json(record),
            '{"decayed_charge":{"$kil.decimal":["795",-1]},'
            '"effective_charge":{"$kil.decimal":["795",-1]},'
            '"mode":"signed_state_only","outcome":"permit",'
            '"reasons":["permitted"],"request_id":"r",'
            '"signed_charge":{"$kil.decimal":["8",1]},"state_id":"q"}',
        )

    def test_nested_lists_and_tuples_are_normalized_recursively(self):
        self.assertEqual(
            canonical_json({"values": (Decimal("1.00"), [ReasonCode.VETO])}),
            '{"values":[{"$kil.decimal":["1",0]},["immutable_veto"]]}',
        )

    def test_decimal_encoding_is_typed_and_normalizes_equivalent_values(self):
        self.assertEqual(canonical_json(Decimal("80")), canonical_json(Decimal("80.0")))
        self.assertEqual(
            canonical_json(Decimal("79.5")), canonical_json(Decimal("79.50"))
        )
        self.assertEqual(canonical_json(Decimal("0")), canonical_json(Decimal("-0")))
        self.assertNotEqual(canonical_json(Decimal("1")), canonical_json("1"))
        with self.assertRaisesRegex(ValueError, "reserved canonical type tag"):
            canonical_json({"$kil.decimal": ["1", 0]})

    def test_large_decimal_exponent_remains_compact(self):
        encoded = canonical_json(Decimal("1E+100000"))
        self.assertLess(len(encoded), 80)
        self.assertIn("100000", encoded)

    def test_non_string_dictionary_keys_are_rejected(self):
        for value in ({1: "one"}, {True: "true"}, {Decimal("1"): "decimal"}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "dictionary keys must be strings"):
                    canonical_json(value)

    def test_unsupported_values_are_rejected(self):
        for value in ({"values": {"unordered"}}, {"raw": b"bytes"}, {"x": 1.5}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "unsupported canonical value"):
                    canonical_json(value)

    def test_nonfinite_decimals_are_rejected(self):
        for value in (Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "finite Decimal"):
                    canonical_json({"value": value})

    def test_decimal_serialization_is_independent_of_caller_context(self):
        value = {"value": Decimal("12345.678900")}
        original_precision = getcontext().prec
        with localcontext() as context:
            context.prec = 3
            low_precision = canonical_json(value)
        with localcontext() as context:
            context.prec = 50
            high_precision = canonical_json(value)
        self.assertEqual(low_precision, high_precision)
        self.assertEqual(getcontext().prec, original_precision)

    def test_lone_surrogates_in_strings_and_keys_are_rejected(self):
        for value in ({"value": "\ud800"}, {"\udfff": "value"}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "Unicode scalar"):
                    canonical_json(value)

    def test_cycles_are_rejected_explicitly(self):
        value = []
        value.append(value)
        with self.assertRaisesRegex(ValueError, "cycle"):
            canonical_json(value)

    def test_depth_limit_is_enforced(self):
        value = "leaf"
        for _ in range(MAX_DEPTH + 1):
            value = [value]
        with self.assertRaisesRegex(ValueError, "depth limit"):
            canonical_json(value)

    def test_item_limit_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "item limit"):
            canonical_json(list(range(MAX_ITEMS)))

    def test_output_limit_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "output size limit"):
            canonical_json("x" * MAX_OUTPUT_BYTES)

    def test_local_mode_never_exceeds_signed_mode(self):
        signed_state = CompositeState(
            "q",
            "i",
            "admin",
            0,
            0,
            100,
            Decimal("80"),
            Decimal("40"),
            5,
            2,
            True,
            True,
            True,
            Decimal("0.01"),
            Decimal("100"),
        )
        signed = decide(
            self.request, signed_state, EnforcementMode.SIGNED_STATE_ONLY
        )
        for step in range(0, 11):
            evidence = LocalEvidence(
                Decimal(step) / Decimal("10"), Decimal("0"), True
            )
            local = decide(
                self.request,
                signed_state,
                EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
                evidence,
                self.profile,
            )
            self.assertLessEqual(local.effective_charge, signed.effective_charge)

    def test_more_loss_never_produces_more_authority(self):
        charges = []
        for step in range(3, 11):
            evidence = LocalEvidence(
                Decimal(step) / Decimal("10"), Decimal("0"), True
            )
            charges.append(
                decide(
                    self.request,
                    self.state,
                    EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
                    evidence,
                    self.profile,
                ).effective_charge
            )
        self.assertEqual(charges, sorted(charges, reverse=True))


if __name__ == "__main__":
    unittest.main()
