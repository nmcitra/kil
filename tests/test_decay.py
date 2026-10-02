from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR, localcontext
import unittest

from kil.decay import (
    local_effective_charge,
    logistic_squash,
    passive_decay,
    superlinear_loss,
    weighted_diagonal_distance,
)


class TrustDecayArithmeticTest(unittest.TestCase):
    def test_public_arithmetic_is_independent_of_caller_decimal_context(self):
        operations = {
            "weighted_diagonal_distance": lambda: weighted_diagonal_distance(
                features={"x": Decimal("1.2345678901234567890123456789")},
                means={"x": Decimal("0")},
                scales={"x": Decimal("3.3333333333333333333333333333")},
                weights={"x": Decimal("0.7")},
            ),
            "logistic_squash": lambda: logistic_squash(
                Decimal("0.12345678901234567890123456789"), Decimal("1.7")
            ),
            "passive_decay": lambda: passive_decay(
                Decimal("80.123456789012345678901234567"),
                Decimal("0.123456789012345678901234567"),
                Decimal("5.7"),
            ),
            "superlinear_loss": lambda: superlinear_loss(
                Decimal("0.987654321098765432109876543"),
                Decimal("0.3"),
                Decimal("25.123456789012345678901234567"),
                3,
            ),
            "local_effective_charge": lambda: local_effective_charge(
                Decimal("80.123456789012345678901234567"),
                Decimal("0.111111111111111111111111111"),
                Decimal("0.222222222222222222222222222"),
                Decimal("100"),
            ),
        }

        for name, operation in operations.items():
            with self.subTest(operation=name):
                with localcontext() as caller_context:
                    caller_context.prec = 9
                    caller_context.rounding = ROUND_FLOOR
                    floor_result = operation()
                with localcontext() as caller_context:
                    caller_context.prec = 50
                    caller_context.rounding = ROUND_CEILING
                    ceiling_result = operation()
                self.assertEqual(floor_result, ceiling_result)

    def test_public_arithmetic_rejects_non_finite_decimal_operands(self):
        invalid_calls = {
            "weighted_diagonal_distance": lambda: weighted_diagonal_distance(
                features={"x": Decimal("NaN")},
                means={"x": Decimal("0")},
                scales={"x": Decimal("1")},
                weights={"x": Decimal("1")},
            ),
            "logistic_squash": lambda: logistic_squash(
                Decimal("NaN"), Decimal("1")
            ),
            "passive_decay": lambda: passive_decay(
                Decimal("Infinity"), Decimal("0.1"), Decimal("5")
            ),
            "superlinear_loss": lambda: superlinear_loss(
                Decimal("-Infinity"), Decimal("0.25"), Decimal("25"), 3
            ),
            "local_effective_charge": lambda: local_effective_charge(
                Decimal("NaN"), Decimal("1"), Decimal("1"), Decimal("100")
            ),
        }

        for name, invalid_call in invalid_calls.items():
            with self.subTest(operation=name):
                with self.assertRaises(ValueError):
                    invalid_call()

    def test_public_arithmetic_rejects_non_decimal_operands(self):
        invalid_calls = {
            "weighted_diagonal_distance": lambda: weighted_diagonal_distance(
                features={"x": "1"},
                means={"x": Decimal("0")},
                scales={"x": Decimal("1")},
                weights={"x": Decimal("1")},
            ),
            "logistic_squash": lambda: logistic_squash("0.5", Decimal("1")),
            "passive_decay": lambda: passive_decay(
                Decimal("80"), 0.1, Decimal("5")
            ),
            "superlinear_loss": lambda: superlinear_loss(
                Decimal("0.5"), Decimal("0.25"), 25, 3
            ),
            "local_effective_charge": lambda: local_effective_charge(
                Decimal("10"), Decimal("1"), "1", Decimal("100")
            ),
        }

        for name, invalid_call in invalid_calls.items():
            with self.subTest(operation=name):
                with self.assertRaises(ValueError):
                    invalid_call()

    def test_identical_feature_vectors_have_zero_distance(self):
        distance = weighted_diagonal_distance(
            features={"velocity": Decimal("2"), "volume": Decimal("10")},
            means={"velocity": Decimal("2"), "volume": Decimal("10")},
            scales={"velocity": Decimal("1"), "volume": Decimal("2")},
            weights={"velocity": Decimal("0.75"), "volume": Decimal("0.25")},
        )

        self.assertEqual(distance, Decimal("0"))

    def test_weighted_distance_rejects_zero_scale(self):
        with self.assertRaisesRegex(ValueError, "scale"):
            weighted_diagonal_distance(
                features={"velocity": Decimal("2")},
                means={"velocity": Decimal("1")},
                scales={"velocity": Decimal("0")},
                weights={"velocity": Decimal("1")},
            )

    def test_logistic_squash_maps_zero_to_zero_and_positive_below_one(self):
        self.assertEqual(logistic_squash(Decimal("0"), Decimal("1")), Decimal("0"))
        positive = logistic_squash(Decimal("2"), Decimal("1"))
        self.assertGreater(positive, Decimal("0"))
        self.assertLess(positive, Decimal("1"))

    def test_passive_decay_lowers_positive_charge_without_going_negative(self):
        decayed = passive_decay(
            charge=Decimal("80"),
            decay_rate=Decimal("0.1"),
            elapsed=Decimal("5"),
        )

        self.assertGreaterEqual(decayed, Decimal("0"))
        self.assertLess(decayed, Decimal("80"))

    def test_passive_decay_never_rounds_above_exact_signed_charge(self):
        exact_charge = Decimal("0.99999999999999999999999999996")

        decayed = passive_decay(
            charge=exact_charge,
            decay_rate=Decimal("0"),
            elapsed=Decimal("0"),
        )

        self.assertEqual(decayed, exact_charge)
        self.assertLessEqual(decayed, exact_charge)

    def test_superlinear_loss_is_zero_in_band_and_cubic_outside(self):
        threshold = Decimal("0.25")
        loss_rate = Decimal("25")
        exponent = 3

        self.assertEqual(
            superlinear_loss(threshold, threshold, loss_rate, exponent),
            Decimal("0"),
        )
        half_divergence_loss = superlinear_loss(
            Decimal("0.5"), threshold, loss_rate, exponent
        )
        full_divergence_loss = superlinear_loss(
            Decimal("1.0"), threshold, loss_rate, exponent
        )
        self.assertEqual(full_divergence_loss, Decimal("8") * half_divergence_loss)

    def test_superlinear_loss_requires_an_integer_exponent(self):
        with self.assertRaisesRegex(ValueError, "exponent"):
            superlinear_loss(
                divergence=Decimal("0.5"),
                threshold=Decimal("0.25"),
                loss_rate=Decimal("25"),
                exponent=Decimal("3"),
            )

    def test_local_effective_charge_clamps_to_zero_and_never_increases(self):
        depleted = local_effective_charge(
            decayed_charge=Decimal("10"),
            loss=Decimal("7"),
            coupled_loss=Decimal("5"),
            maximum=Decimal("100"),
        )
        capped = local_effective_charge(
            decayed_charge=Decimal("120"),
            loss=Decimal("0"),
            coupled_loss=Decimal("0"),
            maximum=Decimal("100"),
        )

        self.assertEqual(depleted, Decimal("0"))
        self.assertEqual(capped, Decimal("100"))
        self.assertLessEqual(capped, Decimal("120"))

    def test_local_effective_charge_does_not_round_above_exact_input(self):
        exact_decayed_charge = Decimal("0.99999999999999999999999999996")

        result = local_effective_charge(
            decayed_charge=exact_decayed_charge,
            loss=Decimal("0.000000000000000000000000000001"),
            coupled_loss=Decimal("0"),
            maximum=Decimal("2"),
        )

        self.assertLessEqual(result, exact_decayed_charge)


if __name__ == "__main__":
    unittest.main()
