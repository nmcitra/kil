"""Immutable decision-domain records for the deterministic KIL kernel."""

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum


ZERO = Decimal("0")
ONE = Decimal("1")
MIN_TIMESTAMP_S = -(2**63)
MAX_TIMESTAMP_S = 2**63 - 1


class EnforcementMode(str, Enum):
    SIGNED_STATE_ONLY = "signed_state_only"
    SIGNED_PLUS_LOCAL_REDUCE = "signed_plus_local_reduce"


class DecisionOutcome(str, Enum):
    PERMIT = "permit"
    CONSTRAIN = "constrain"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


class FailureDisposition(str, Enum):
    CLOSED = "closed"
    CONSTRAINED = "constrained"


class ReasonCode(str, Enum):
    PERMITTED = "permitted"
    IDENTITY_MISMATCH = "identity_mismatch"
    CLASS_MISMATCH = "class_mismatch"
    VETO = "immutable_veto"
    OUTSIDE_ENVELOPE = "outside_environmental_envelope"
    STATE_UNAUTHENTIC = "state_unauthentic"
    STATE_NOT_YET_VALID = "state_not_yet_valid"
    STATE_EXPIRED = "state_expired"
    ARITHMETIC_FAILURE = "arithmetic_failure"
    LOCAL_EVIDENCE_STALE = "local_evidence_stale"
    INSUFFICIENT_CHARGE = "insufficient_charge"
    INSUFFICIENT_HISTORY = "insufficient_history"


def _require_identifier(name: str, value: object) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonblank string")


def _require_integer(name: str, value: object) -> None:
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")


def _require_timestamp(name: str, value: object) -> None:
    _require_integer(name, value)
    if not MIN_TIMESTAMP_S <= value <= MAX_TIMESTAMP_S:
        raise ValueError(f"{name} must be a signed 64-bit integer")


def _require_boolean(name: str, value: object) -> None:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")


def _require_finite_decimal(name: str, value: object) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValueError(f"{name} must be a finite Decimal")
    return value


@dataclass(frozen=True, slots=True)
class ActionRequest:
    request_id: str
    identity: str
    authority_class: str
    timestamp_s: int

    def __post_init__(self) -> None:
        _require_identifier("request_id", self.request_id)
        _require_identifier("identity", self.identity)
        _require_identifier("authority_class", self.authority_class)
        _require_timestamp("timestamp_s", self.timestamp_s)


@dataclass(frozen=True, slots=True)
class CompositeState:
    state_id: str
    identity: str
    authority_class: str
    issued_at_s: int
    not_before_s: int
    expires_at_s: int
    charge: Decimal
    threshold: Decimal
    history_count: int
    minimum_history: int
    authentic: bool
    veto_clear: bool
    envelope_allows: bool
    decay_rate: Decimal
    maximum_charge: Decimal

    def __post_init__(self) -> None:
        _require_identifier("state_id", self.state_id)
        _require_identifier("identity", self.identity)
        _require_identifier("authority_class", self.authority_class)
        for name in ("issued_at_s", "not_before_s", "expires_at_s"):
            _require_timestamp(name, getattr(self, name))
        for name in ("history_count", "minimum_history"):
            _require_integer(name, getattr(self, name))
        for name in ("authentic", "veto_clear", "envelope_allows"):
            _require_boolean(name, getattr(self, name))

        charge_profile = {
            name: _require_finite_decimal(name, getattr(self, name))
            for name in (
                "charge",
                "threshold",
                "decay_rate",
                "maximum_charge",
            )
        }

        if not self.issued_at_s <= self.not_before_s < self.expires_at_s:
            raise ValueError("invalid state validity window")
        for name, value in charge_profile.items():
            if value < ZERO:
                raise ValueError(f"{name} must be nonnegative")
        if self.charge > self.maximum_charge:
            raise ValueError("charge exceeds maximum_charge")
        if self.history_count < 0 or self.minimum_history < 0:
            raise ValueError("history counts must be nonnegative")


@dataclass(frozen=True, slots=True)
class LocalEvidence:
    divergence: Decimal
    coupled_loss: Decimal
    fresh: bool

    def __post_init__(self) -> None:
        divergence = _require_finite_decimal("divergence", self.divergence)
        coupled_loss = _require_finite_decimal("coupled_loss", self.coupled_loss)
        _require_boolean("fresh", self.fresh)
        if not ZERO <= divergence <= ONE:
            raise ValueError("divergence must be between zero and one")
        if coupled_loss < ZERO:
            raise ValueError("coupled_loss must be nonnegative")


@dataclass(frozen=True, slots=True)
class ReductionProfile:
    divergence_threshold: Decimal
    loss_rate: Decimal
    exponent: int

    def __post_init__(self) -> None:
        threshold = _require_finite_decimal(
            "divergence_threshold", self.divergence_threshold
        )
        loss_rate = _require_finite_decimal("loss_rate", self.loss_rate)
        _require_integer("exponent", self.exponent)
        if threshold <= ZERO:
            raise ValueError("divergence_threshold must be greater than zero")
        if loss_rate < ZERO:
            raise ValueError("loss_rate must be nonnegative")
        if self.exponent <= 1:
            raise ValueError("exponent must be greater than one")


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    request_id: str
    state_id: str
    mode: EnforcementMode
    outcome: DecisionOutcome
    reasons: tuple[ReasonCode, ...]
    signed_charge: Decimal
    decayed_charge: Decimal
    effective_charge: Decimal

    def __post_init__(self) -> None:
        _require_identifier("request_id", self.request_id)
        _require_identifier("state_id", self.state_id)
        if not isinstance(self.mode, EnforcementMode):
            raise ValueError("mode must be an EnforcementMode")
        if not isinstance(self.outcome, DecisionOutcome):
            raise ValueError("outcome must be a DecisionOutcome")
        if not isinstance(self.reasons, tuple) or not all(
            isinstance(reason, ReasonCode) for reason in self.reasons
        ):
            raise ValueError("reasons must be a tuple of ReasonCode values")

        charges = {}
        for name in ("signed_charge", "decayed_charge", "effective_charge"):
            value = _require_finite_decimal(name, getattr(self, name))
            if value < ZERO:
                raise ValueError(f"{name} must be nonnegative")
            charges[name] = value

        if charges["decayed_charge"] > charges["signed_charge"]:
            raise ValueError("decayed_charge cannot exceed signed_charge")
        if charges["effective_charge"] > charges["decayed_charge"]:
            raise ValueError("effective_charge cannot exceed decayed_charge")

        if self.outcome is DecisionOutcome.PERMIT:
            if self.reasons != (ReasonCode.PERMITTED,):
                raise ValueError(
                    "PERMIT outcome requires exactly the PERMITTED reason"
                )
        elif ReasonCode.PERMITTED in self.reasons:
            raise ValueError("PERMITTED reason is invalid for a non-PERMIT outcome")

        if self.outcome in (DecisionOutcome.DENY, DecisionOutcome.CONSTRAIN):
            if not self.reasons:
                raise ValueError(
                    f"{self.outcome.name} outcome requires an actionable reason"
                )
