"""Process-level forward-or-withhold proof contract for Gate V3A."""

from dataclasses import dataclass

from .domain import DecisionOutcome
from .live_authz import AuthorizationAdapter, LiveDecision, LiveFixture, LiveTrack


@dataclass(frozen=True, slots=True)
class TargetRecord:
    request_id: str
    track: LiveTrack
    action_class: str


class TargetMarker:
    """Harmless in-memory marker for representative target invocation."""

    __slots__ = ("_records",)

    def __init__(self) -> None:
        self._records: list[TargetRecord] = []

    @property
    def records(self) -> tuple[TargetRecord, ...]:
        return tuple(self._records)

    def invoke(self, fixture: LiveFixture, track: LiveTrack) -> TargetRecord:
        if not isinstance(fixture, LiveFixture):
            raise ValueError("fixture must be a LiveFixture")
        if not isinstance(track, LiveTrack):
            raise ValueError("track must be a LiveTrack")
        record = TargetRecord(
            request_id=fixture.request.request_id,
            track=track,
            action_class=fixture.action_class,
        )
        self._records.append(record)
        return record


@dataclass(frozen=True, slots=True)
class GatewayResult:
    decision: LiveDecision
    forwarded: bool
    marker_count: int
    proof_valid: bool
    target_records: tuple[TargetRecord, ...]


class ReferenceGateway:
    """Reference process gate; it is explicitly not the V3B Envoy adapter."""

    __slots__ = ("_adapter", "_target")

    def __init__(
        self,
        adapter: AuthorizationAdapter,
        target: TargetMarker,
    ) -> None:
        if not isinstance(adapter, AuthorizationAdapter):
            raise ValueError("adapter must be an AuthorizationAdapter")
        if not isinstance(target, TargetMarker):
            raise ValueError("target must be a TargetMarker")
        self._adapter = adapter
        self._target = target

    def handle(self, fixture: LiveFixture) -> GatewayResult:
        if not isinstance(fixture, LiveFixture):
            raise ValueError("fixture must be a LiveFixture")
        decision = self._adapter.evaluate(fixture)
        if decision.outcome is DecisionOutcome.PERMIT:
            self._target.invoke(fixture, decision.track)
            forwarded = True
        else:
            forwarded = False
        matching = tuple(
            record
            for record in self._target.records
            if record.request_id == fixture.request.request_id
            and record.track is decision.track
        )
        marker_count = len(matching)
        proof_valid = (
            decision.outcome is DecisionOutcome.PERMIT
            and forwarded
            and marker_count == 1
        ) or (
            decision.outcome is not DecisionOutcome.PERMIT
            and not forwarded
            and marker_count == 0
        )
        return GatewayResult(
            decision=decision,
            forwarded=forwarded,
            marker_count=marker_count,
            proof_valid=proof_valid,
            target_records=matching,
        )
