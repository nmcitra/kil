"""Deterministic arithmetic for the KIL trust-decay reference kernel."""

from decimal import (
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    ROUND_HALF_EVEN,
    localcontext,
)
from typing import Mapping


ZERO = Decimal("0")
ONE = Decimal("1")

_KIL_DECIMAL_CONTEXT = Context(
    prec=28,
    rounding=ROUND_HALF_EVEN,
    Emin=-999999,
    Emax=999999,
    capitals=1,
    clamp=0,
    flags=[],
    traps=[InvalidOperation, DivisionByZero, Overflow],
)


def _require_finite_decimal(name: str, value: object) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValueError(f"{name} must be a finite Decimal")
    return value


def weighted_diagonal_distance(
    features: Mapping[str, Decimal],
    means: Mapping[str, Decimal],
    scales: Mapping[str, Decimal],
    weights: Mapping[str, Decimal],
) -> Decimal:
    """Return a weighted standardized distance over matching feature keys."""
    with localcontext(_KIL_DECIMAL_CONTEXT):
        keys = set(features)
        if set(means) != keys or set(scales) != keys or set(weights) != keys:
            raise ValueError("feature, mean, scale, and weight key sets must match")

        squared_distance = ZERO
        for key in sorted(keys):
            feature = _require_finite_decimal(f"features[{key!r}]", features[key])
            mean = _require_finite_decimal(f"means[{key!r}]", means[key])
            scale = _require_finite_decimal(f"scales[{key!r}]", scales[key])
            weight = _require_finite_decimal(f"weights[{key!r}]", weights[key])
            if scale <= ZERO:
                raise ValueError(f"scale for {key!r} must be greater than zero")
            if weight < ZERO:
                raise ValueError(f"weight for {key!r} must be nonnegative")
            standardized = (feature - mean) / scale
            squared_distance += weight * standardized * standardized
        return squared_distance.sqrt()


def logistic_squash(raw: Decimal, k: Decimal) -> Decimal:
    """Map a nonnegative raw distance into the half-open interval [0, 1)."""
    with localcontext(_KIL_DECIMAL_CONTEXT):
        raw = _require_finite_decimal("raw", raw)
        k = _require_finite_decimal("k", k)
        if raw < ZERO:
            raise ValueError("raw must be nonnegative")
        if k <= ZERO:
            raise ValueError("k must be greater than zero")
        return Decimal("2") / (ONE + (-k * raw).exp()) - ONE


def passive_decay(
    charge: Decimal, decay_rate: Decimal, elapsed: Decimal
) -> Decimal:
    """Apply exponential passive decay to a nonnegative charge."""
    with localcontext(_KIL_DECIMAL_CONTEXT):
        exact_charge = _require_finite_decimal("charge", charge)
        decay_rate = _require_finite_decimal("decay_rate", decay_rate)
        elapsed = _require_finite_decimal("elapsed", elapsed)
        if exact_charge < ZERO:
            raise ValueError("charge must be nonnegative")
        if decay_rate < ZERO:
            raise ValueError("decay_rate must be nonnegative")
        if elapsed < ZERO:
            raise ValueError("elapsed must be nonnegative")
        computed = exact_charge * (-decay_rate * elapsed).exp()

    return min(exact_charge, max(ZERO, computed))


def superlinear_loss(
    divergence: Decimal,
    threshold: Decimal,
    loss_rate: Decimal,
    exponent: int,
) -> Decimal:
    """Return zero in-band and a superlinear penalty above the threshold."""
    with localcontext(_KIL_DECIMAL_CONTEXT):
        divergence = _require_finite_decimal("divergence", divergence)
        threshold = _require_finite_decimal("threshold", threshold)
        loss_rate = _require_finite_decimal("loss_rate", loss_rate)
        if divergence < ZERO or divergence > ONE:
            raise ValueError("divergence must be between zero and one")
        if threshold <= ZERO:
            raise ValueError("threshold must be greater than zero")
        if loss_rate < ZERO:
            raise ValueError("loss_rate must be nonnegative")
        if type(exponent) is not int or exponent <= 1:
            raise ValueError("exponent must be an integer greater than one")
        if divergence <= threshold:
            return ZERO
        return loss_rate * (divergence / threshold) ** exponent


def local_effective_charge(
    decayed_charge: Decimal,
    loss: Decimal,
    coupled_loss: Decimal,
    maximum: Decimal,
) -> Decimal:
    """Apply reducing-only local losses and clamp the result to its bounds."""
    with localcontext(_KIL_DECIMAL_CONTEXT):
        values = {
            "decayed_charge": _require_finite_decimal(
                "decayed_charge", decayed_charge
            ),
            "loss": _require_finite_decimal("loss", loss),
            "coupled_loss": _require_finite_decimal("coupled_loss", coupled_loss),
            "maximum": _require_finite_decimal("maximum", maximum),
        }
        for name, value in values.items():
            if value < ZERO:
                raise ValueError(f"{name} must be nonnegative")

        reduced = (
            values["decayed_charge"] - values["loss"] - values["coupled_loss"]
        )
        return min(
            values["maximum"],
            values["decayed_charge"],
            max(ZERO, reduced),
        )
