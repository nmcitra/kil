"""Pure authorization adapter contract for the three Gate V3 tracks."""

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_digest
from .domain import (
    ActionRequest,
    DecisionOutcome,
    DecisionRecord,
    EnforcementMode,
    LocalEvidence,
    ReductionProfile,
)
from .engine import decide
from .q_state import QStateVerificationError, verify_q_state


class LiveTrack(str, Enum):
    CREDENTIAL_POLICY_BASELINE = "credential_policy_baseline"
    SIGNED_STATE_ONLY = "signed_state_only"
    SIGNED_PLUS_LOCAL_REDUCE = "signed_plus_local_reduce"


TRACK_AUDIENCE = MappingProxyType(
    {
        LiveTrack.SIGNED_STATE_ONLY: "kil-v3-signed",
        LiveTrack.SIGNED_PLUS_LOCAL_REDUCE: "kil-v3-local",
    }
)


def _nonblank(name: str, value: object) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonblank string")


@dataclass(frozen=True, slots=True)
class LiveFixture:
    """Server-side normalized facts for one live-lab authorization request."""

    request: ActionRequest
    action_class: str
    credential_valid: bool
    policy_allows_action: bool
    q_state_jws: str | None
    local_evidence: LocalEvidence | None
    reduction_profile: ReductionProfile | None
    untrusted_headers: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.request, ActionRequest):
            raise ValueError("request must be an ActionRequest")
        _nonblank("action_class", self.action_class)
        if type(self.credential_valid) is not bool:
            raise ValueError("credential_valid must be a boolean")
        if type(self.policy_allows_action) is not bool:
            raise ValueError("policy_allows_action must be a boolean")
        if self.q_state_jws is not None:
            _nonblank("q_state_jws", self.q_state_jws)
        if self.local_evidence is not None and not isinstance(
            self.local_evidence, LocalEvidence
        ):
            raise ValueError("local_evidence must be LocalEvidence or None")
        if self.reduction_profile is not None and not isinstance(
            self.reduction_profile, ReductionProfile
        ):
            raise ValueError("reduction_profile must be ReductionProfile or None")
        if type(self.untrusted_headers) is not tuple:
            raise ValueError("untrusted_headers must be a tuple")
        for header in self.untrusted_headers:
            if (
                type(header) is not tuple
                or len(header) != 2
                or type(header[0]) is not str
                or type(header[1]) is not str
            ):
                raise ValueError("untrusted_headers entries must be string pairs")


@dataclass(frozen=True, slots=True)
class LiveDecision:
    request_id: str
    track: LiveTrack
    outcome: DecisionOutcome
    adapter_reasons: tuple[str, ...]
    engine_record: DecisionRecord | None
    decision_digest: str


class AuthorizationAdapter:
    """Evaluate one fixed infrastructure track; request data cannot change mode."""

    __slots__ = ("_keys", "_revoked_state_ids", "_track")

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("AuthorizationAdapter configuration is immutable")
        object.__setattr__(self, name, value)

    @property
    def track(self) -> LiveTrack:
        return self._track

    def __init__(
        self,
        track: LiveTrack,
        *,
        keys: Mapping[str, Ed25519PublicKey] | None = None,
        revoked_state_ids: frozenset[str] = frozenset(),
    ) -> None:
        if not isinstance(track, LiveTrack):
            raise ValueError("track must be a LiveTrack")
        if keys is None:
            copied_keys: dict[str, Ed25519PublicKey] = {}
        elif isinstance(keys, Mapping):
            copied_keys = dict(keys)
        else:
            raise ValueError("keys must be a mapping or None")
        for kid, key in copied_keys.items():
            _nonblank("key identifier", kid)
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("verification keys must be Ed25519PublicKey values")
        if type(revoked_state_ids) is not frozenset or not all(
            type(item) is str and item for item in revoked_state_ids
        ):
            raise ValueError("revoked_state_ids must be a frozenset of identifiers")
        if track is not LiveTrack.CREDENTIAL_POLICY_BASELINE and not copied_keys:
            raise ValueError("KIL tracks require at least one verification key")
        self._track = track
        self._keys = MappingProxyType(copied_keys)
        self._revoked_state_ids = revoked_state_ids

    def _result(
        self,
        fixture: LiveFixture,
        outcome: DecisionOutcome,
        adapter_reasons: tuple[str, ...],
        engine_record: DecisionRecord | None,
    ) -> LiveDecision:
        identity = {
            "request_id": fixture.request.request_id,
            "track": self.track,
            "outcome": outcome,
            "adapter_reasons": adapter_reasons,
            "engine_record": engine_record,
        }
        return LiveDecision(
            request_id=fixture.request.request_id,
            track=self.track,
            outcome=outcome,
            adapter_reasons=adapter_reasons,
            engine_record=engine_record,
            decision_digest=canonical_digest(identity),
        )

    def evaluate(self, fixture: LiveFixture) -> LiveDecision:
        if not isinstance(fixture, LiveFixture):
            raise ValueError("fixture must be a LiveFixture")
        ignored_mode = any(
            name.lower() == "x-kil-mode" for name, _ in fixture.untrusted_headers
        )
        ignored_reasons = (
            ("untrusted_mode_header_ignored",) if ignored_mode else ()
        )

        if self.track is LiveTrack.CREDENTIAL_POLICY_BASELINE:
            baseline_reasons: list[str] = list(ignored_reasons)
            if not fixture.credential_valid:
                baseline_reasons.append("credential_invalid")
            if not fixture.policy_allows_action:
                baseline_reasons.append("policy_denied")
            if baseline_reasons and baseline_reasons != [
                "untrusted_mode_header_ignored"
            ]:
                outcome = DecisionOutcome.DENY
            else:
                outcome = DecisionOutcome.PERMIT
                baseline_reasons.append("baseline_permitted")
            return self._result(
                fixture,
                outcome,
                tuple(baseline_reasons),
                None,
            )

        if fixture.q_state_jws is None:
            return self._result(
                fixture,
                DecisionOutcome.DENY,
                ignored_reasons + ("q_state_missing",),
                None,
            )
        try:
            verified = verify_q_state(
                fixture.q_state_jws,
                self._keys,
                now_s=fixture.request.timestamp_s,
                expected_subject=fixture.request.identity,
                expected_audience=TRACK_AUDIENCE[self.track],
                expected_authority_class=fixture.request.authority_class,
                expected_action_class=fixture.action_class,
                revoked_state_ids=self._revoked_state_ids,
            )
        except QStateVerificationError:
            return self._result(
                fixture,
                DecisionOutcome.DENY,
                ignored_reasons + ("q_state_verification_failed",),
                None,
            )

        if self.track is LiveTrack.SIGNED_STATE_ONLY:
            record = decide(
                fixture.request,
                verified.composite_state,
                EnforcementMode.SIGNED_STATE_ONLY,
            )
        else:
            record = decide(
                fixture.request,
                verified.composite_state,
                EnforcementMode.SIGNED_PLUS_LOCAL_REDUCE,
                fixture.local_evidence,
                fixture.reduction_profile,
            )
        return self._result(
            fixture,
            record.outcome,
            ignored_reasons,
            record,
        )
