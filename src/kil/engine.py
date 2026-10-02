"""Deterministic decision engine for the KIL reference kernel."""

from decimal import Decimal, DivisionByZero, InvalidOperation, Overflow

from .decay import local_effective_charge, passive_decay, superlinear_loss
from .domain import (
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


def decide(
    request: ActionRequest,
    state: CompositeState,
    mode: EnforcementMode,
    local_evidence: LocalEvidence | None = None,
    reduction_profile: ReductionProfile | None = None,
    failure_disposition: FailureDisposition = FailureDisposition.CLOSED,
) -> DecisionRecord:
    """Evaluate one action against pre-existing signed authority state."""
    runtime_values = (
        ("request", request, ActionRequest),
        ("state", state, CompositeState),
        ("mode", mode, EnforcementMode),
        ("failure_disposition", failure_disposition, FailureDisposition),
    )
    for name, value, expected_type in runtime_values:
        if not isinstance(value, expected_type):
            raise ValueError(f"{name} must be a {expected_type.__name__}")
    if local_evidence is not None and not isinstance(local_evidence, LocalEvidence):
        raise ValueError("local_evidence must be a LocalEvidence or None")
    if reduction_profile is not None and not isinstance(
        reduction_profile, ReductionProfile
    ):
        raise ValueError("reduction_profile must be a ReductionProfile or None")

    reasons: list[ReasonCode] = []
    if request.identity != state.identity:
        reasons.append(ReasonCode.IDENTITY_MISMATCH)
    if request.authority_class != state.authority_class:
        reasons.append(ReasonCode.CLASS_MISMATCH)
    if not state.veto_clear:
        reasons.append(ReasonCode.VETO)
    if not state.envelope_allows:
        reasons.append(ReasonCode.OUTSIDE_ENVELOPE)
    if not state.authentic:
        reasons.append(ReasonCode.STATE_UNAUTHENTIC)
    if request.timestamp_s < state.not_before_s:
        reasons.append(ReasonCode.STATE_NOT_YET_VALID)
    if request.timestamp_s >= state.expires_at_s:
        reasons.append(ReasonCode.STATE_EXPIRED)

    try:
        elapsed = Decimal(max(0, request.timestamp_s - state.issued_at_s))
        decayed = passive_decay(state.charge, state.decay_rate, elapsed)
        effective = decayed

        if mode is EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE:
            if (
                local_evidence is None
                or reduction_profile is None
                or not local_evidence.fresh
            ):
                reasons.append(ReasonCode.LOCAL_EVIDENCE_STALE)
            else:
                loss = superlinear_loss(
                    local_evidence.divergence,
                    reduction_profile.divergence_threshold,
                    reduction_profile.loss_rate,
                    reduction_profile.exponent,
                )
                effective = local_effective_charge(
                    decayed,
                    loss,
                    local_evidence.coupled_loss,
                    state.maximum_charge,
                )
    except (DivisionByZero, InvalidOperation, Overflow):
        decayed = Decimal("0")
        effective = Decimal("0")
        reasons.append(ReasonCode.ARITHMETIC_FAILURE)

    if effective < state.threshold:
        reasons.append(ReasonCode.INSUFFICIENT_CHARGE)
    if state.history_count < state.minimum_history:
        reasons.append(ReasonCode.INSUFFICIENT_HISTORY)

    decisive_reasons = [
        reason
        for reason in reasons
        if reason is not ReasonCode.LOCAL_EVIDENCE_STALE
    ]
    if decisive_reasons:
        outcome = DecisionOutcome.DENY
    elif ReasonCode.LOCAL_EVIDENCE_STALE in reasons:
        outcome = (
            DecisionOutcome.CONSTRAIN
            if failure_disposition is FailureDisposition.CONSTRAINED
            else DecisionOutcome.DENY
        )
    else:
        outcome = DecisionOutcome.PERMIT
        reasons.append(ReasonCode.PERMITTED)

    return DecisionRecord(
        request.request_id,
        state.state_id,
        mode,
        outcome,
        tuple(reasons),
        state.charge,
        decayed,
        effective,
    )
