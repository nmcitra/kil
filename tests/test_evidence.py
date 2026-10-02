from dataclasses import FrozenInstanceError
from decimal import Decimal
import unittest

from kil.evidence import EvidenceClass, LabeledValue


class EvidenceContractTest(unittest.TestCase):
    def test_observed_requires_source_reference(self):
        with self.assertRaisesRegex(ValueError, "source_ref"):
            LabeledValue(Decimal("1"), EvidenceClass.OBSERVED)

    def test_modeled_requires_rationale(self):
        with self.assertRaisesRegex(ValueError, "rationale"):
            LabeledValue(Decimal("0.9"), EvidenceClass.MODELED)

    def test_validated_requires_run_id(self):
        with self.assertRaisesRegex(ValueError, "run_id"):
            LabeledValue(Decimal("0"), EvidenceClass.VALIDATED)

    def test_evidence_class_rejects_string_and_arbitrary_bypasses(self):
        for invalid_class in ("observed", object()):
            with self.subTest(invalid_class=invalid_class):
                with self.assertRaisesRegex(ValueError, "evidence_class"):
                    LabeledValue(Decimal("1"), invalid_class)

    def test_required_metadata_must_be_nonblank_strings(self):
        cases = (
            (EvidenceClass.OBSERVED, {"source_ref": "   "}, "source_ref"),
            (EvidenceClass.OBSERVED, {"source_ref": 7}, "source_ref"),
            (EvidenceClass.MODELED, {"rationale": "\t"}, "rationale"),
            (EvidenceClass.MODELED, {"rationale": object()}, "rationale"),
            (EvidenceClass.VALIDATED, {"run_id": "\n"}, "run_id"),
            (EvidenceClass.VALIDATED, {"run_id": 7}, "run_id"),
        )

        for evidence_class, metadata, required_field in cases:
            with self.subTest(
                evidence_class=evidence_class,
                required_field=required_field,
                supplied=metadata[required_field],
            ):
                with self.assertRaisesRegex(ValueError, required_field):
                    LabeledValue(Decimal("1"), evidence_class, **metadata)

    def test_labeled_values_are_immutable(self):
        value = LabeledValue(
            Decimal("0.9"),
            EvidenceClass.MODELED,
            rationale="synthetic origin-distance feature",
        )

        with self.assertRaises(FrozenInstanceError):
            value.value = Decimal("1")


if __name__ == "__main__":
    unittest.main()
