"""Paired historical replay over one immutable, evidence-labeled event stream."""

from dataclasses import dataclass

from .domain import (
    DecisionOutcome,
    DecisionRecord,
    EnforcementMode,
    ReductionProfile,
)
from .engine import decide
from .evidence import EvidenceClass
from .scenario import Scenario, ScenarioEvent


@dataclass(frozen=True, slots=True)
class PairedDecision:
    event_id: str
    baseline_permit: bool
    baseline_reachable: bool
    signed_state_only: DecisionRecord
    signed_state_only_reachable: bool
    signed_plus_local_reduce: DecisionRecord
    signed_plus_local_reduce_reachable: bool
    evidence_class: EvidenceClass = EvidenceClass.MODELED

    def __post_init__(self) -> None:
        if type(self.event_id) is not str or not self.event_id.strip():
            raise ValueError("event_id must be a nonblank string")
        for name in (
            "baseline_permit",
            "baseline_reachable",
            "signed_state_only_reachable",
            "signed_plus_local_reduce_reachable",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if not isinstance(self.signed_state_only, DecisionRecord):
            raise ValueError("signed_state_only must be a DecisionRecord")
        if not isinstance(self.signed_plus_local_reduce, DecisionRecord):
            raise ValueError("signed_plus_local_reduce must be a DecisionRecord")
        if self.signed_state_only.mode is not EnforcementMode.SIGNED_STATE_ONLY:
            raise ValueError("signed_state_only decision has the wrong mode")
        if (
            self.signed_plus_local_reduce.mode
            is not EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE
        ):
            raise ValueError("signed_plus_local_reduce decision has the wrong mode")
        if self.evidence_class is not EvidenceClass.MODELED:
            raise ValueError("historical replay decisions must remain modeled")


@dataclass(frozen=True, slots=True)
class ReplayReport:
    scenario_id: str
    decisions: tuple[PairedDecision, ...]
    evidence_class: EvidenceClass = EvidenceClass.MODELED

    def __post_init__(self) -> None:
        if type(self.scenario_id) is not str or not self.scenario_id.strip():
            raise ValueError("scenario_id must be a nonblank string")
        if not isinstance(self.decisions, tuple) or not self.decisions:
            raise ValueError("decisions must be a nonempty tuple")
        if not all(isinstance(item, PairedDecision) for item in self.decisions):
            raise ValueError("decisions must contain PairedDecision values")
        if self.evidence_class is not EvidenceClass.MODELED:
            raise ValueError("historical replay reports must remain modeled")


def _validate_event_evidence(event: ScenarioEvent) -> None:
    if not isinstance(event, ScenarioEvent):
        raise ValueError("scenario events must be ScenarioEvent values")
    if event.request.request_id != event.event_id:
        raise ValueError("event_id must match request_id")
    if event.observed_summary.evidence_class is not EvidenceClass.OBSERVED:
        raise ValueError("observed_summary must remain observed")
    for name in (
        "control_assumption",
        "state_assumption",
        "local_evidence_assumption",
    ):
        if getattr(event, name).evidence_class is not EvidenceClass.MODELED:
            raise ValueError(f"{name} must remain modeled")
    control = event.control_assumption.value
    if (
        not isinstance(control, tuple)
        or len(control) != 2
        or any(type(value) is not bool for value in control)
    ):
        raise ValueError("control_assumption must contain two booleans")


def replay(scenario: Scenario, profile: ReductionProfile) -> ReplayReport:
    if not isinstance(scenario, Scenario):
        raise ValueError("scenario must be a Scenario")
    if not isinstance(profile, ReductionProfile):
        raise ValueError("profile must be a ReductionProfile")
    if not scenario.events:
        raise ValueError("scenario events must not be empty")

    decisions: list[PairedDecision] = []
    baseline_success: set[str] = set()
    signed_success: set[str] = set()
    local_success: set[str] = set()
    seen: set[str] = set()

    for event in scenario.events:
        _validate_event_evidence(event)
        if event.event_id in seen:
            raise ValueError(f"duplicate event_id: {event.event_id}")
        if any(parent not in seen for parent in event.depends_on):
            raise ValueError(
                f"event dependencies must reference earlier events: {event.event_id}"
            )

        baseline_reachable = all(
            parent in baseline_success for parent in event.depends_on
        )
        signed_reachable = all(parent in signed_success for parent in event.depends_on)
        local_reachable = all(parent in local_success for parent in event.depends_on)
        credential_valid, policy_allows_action = event.control_assumption.value
        baseline_permit = credential_valid and policy_allows_action

        signed = decide(
            event.request,
            event.state_assumption.value,
            EnforcementMode.SIGNED_STATE_ONLY,
        )
        local = decide(
            event.request,
            event.state_assumption.value,
            EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
            event.local_evidence_assumption.value,
            profile,
        )
        decisions.append(
            PairedDecision(
                event_id=event.event_id,
                baseline_permit=baseline_permit,
                baseline_reachable=baseline_reachable,
                signed_state_only=signed,
                signed_state_only_reachable=signed_reachable,
                signed_plus_local_reduce=local,
                signed_plus_local_reduce_reachable=local_reachable,
            )
        )

        if baseline_reachable and baseline_permit:
            baseline_success.add(event.event_id)
        if signed_reachable and signed.outcome is DecisionOutcome.PERMIT:
            signed_success.add(event.event_id)
        if local_reachable and local.outcome is DecisionOutcome.PERMIT:
            local_success.add(event.event_id)
        seen.add(event.event_id)

    return ReplayReport(scenario.scenario_id, tuple(decisions))
