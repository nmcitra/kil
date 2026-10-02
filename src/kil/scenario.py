"""Strict, evidence-labeled loader for versioned KIL replay scenarios."""

from dataclasses import dataclass
from decimal import Decimal
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from .domain import ActionRequest, CompositeState, LocalEvidence
from .evidence import EvidenceClass, LabeledValue


SCHEMA_VERSION = "kil.scenario.v1"
DECIMAL_PATTERN = re.compile(r"^-?[0-9]+(?:\.[0-9]+)?$")
SCENARIO_FIELDS = {"schema_version", "scenario_id", "primary_source", "events"}
EVENT_FIELDS = {
    "event_id",
    "phase",
    "timestamp_s",
    "identity",
    "authority_class",
    "summary",
    "source_ref",
    "credential_valid",
    "policy_allows_action",
    "control_rationale",
    "state_rationale",
    "depends_on",
    "state",
    "modeled_context",
}
STATE_FIELDS = {
    "state_id",
    "issued_at_s",
    "not_before_s",
    "expires_at_s",
    "charge",
    "threshold",
    "history_count",
    "minimum_history",
    "authentic",
    "veto_clear",
    "envelope_allows",
    "decay_rate",
    "maximum_charge",
}
MODELED_FIELDS = {"divergence", "coupled_loss", "fresh", "rationale"}


@dataclass(frozen=True, slots=True)
class ScenarioEvent:
    event_id: str
    phase: int
    request: ActionRequest
    observed_summary: LabeledValue[str]
    control_assumption: LabeledValue[tuple[bool, bool]]
    depends_on: tuple[str, ...]
    state_assumption: LabeledValue[CompositeState]
    local_evidence_assumption: LabeledValue[LocalEvidence]


@dataclass(frozen=True, slots=True)
class Scenario:
    schema_version: str
    scenario_id: str
    primary_source: str
    events: tuple[ScenarioEvent, ...]


def _mapping(value: object, where: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{where} must be an object")
    return value


def _required(mapping: dict[str, Any], key: str) -> Any:
    if key not in mapping:
        raise ValueError(f"missing required field: {key}")
    return mapping[key]


def _expect_keys(mapping: dict[str, Any], allowed: set[str], where: str) -> None:
    if any(type(key) is not str for key in mapping):
        raise ValueError(f"field names in {where} must be strings")
    unknown = set(mapping) - allowed
    if unknown:
        raise ValueError(f"unknown fields in {where}: {sorted(unknown)}")


def _string(mapping: dict[str, Any], key: str) -> str:
    value = _required(mapping, key)
    if type(value) is not str or not value.strip():
        raise ValueError(f"{key} must be a nonblank string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{key} must contain valid UTF-8 text") from error
    return value


def _integer(mapping: dict[str, Any], key: str, minimum: int) -> int:
    value = _required(mapping, key)
    if type(value) is not int:
        raise ValueError(f"{key} must be an integer")
    if value < minimum:
        raise ValueError(f"{key} must be at least {minimum}")
    return value


def _boolean(mapping: dict[str, Any], key: str) -> bool:
    value = _required(mapping, key)
    if type(value) is not bool:
        raise ValueError(f"{key} must be a boolean")
    return value


def _decimal(mapping: dict[str, Any], key: str) -> Decimal:
    value = _required(mapping, key)
    if type(value) is not str or DECIMAL_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{key} must be a decimal string")
    parsed = Decimal(value)
    if not parsed.is_finite():
        raise ValueError(f"{key} must be finite")
    return parsed


def _uri(mapping: dict[str, Any], key: str) -> str:
    value = _string(mapping, key)
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{key} must be an absolute HTTP(S) URI")
    return value


def _dependencies(item: dict[str, Any], seen: set[str], event_id: str) -> tuple[str, ...]:
    raw = _required(item, "depends_on")
    if type(raw) is not list:
        raise ValueError("depends_on must be an array")
    dependencies = tuple(raw)
    if any(type(parent) is not str or not parent.strip() for parent in dependencies):
        raise ValueError("depends_on entries must be nonblank strings")
    if len(set(dependencies)) != len(dependencies):
        raise ValueError("depends_on entries must be unique")
    if any(parent not in seen for parent in dependencies):
        raise ValueError(
            f"event dependencies must reference earlier events: {event_id}"
        )
    return dependencies


def load_scenario(source: Path | dict[str, Any]) -> Scenario:
    if isinstance(source, Path):
        raw_value = json.loads(source.read_text(encoding="utf-8"))
    elif type(source) is dict:
        raw_value = source
    else:
        raise ValueError("scenario source must be a Path or object")

    raw = _mapping(raw_value, "scenario")
    _expect_keys(raw, SCENARIO_FIELDS, "scenario")
    if _string(raw, "schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported schema_version")
    scenario_id = _string(raw, "scenario_id")
    primary_source = _uri(raw, "primary_source")
    event_values = _required(raw, "events")
    if type(event_values) is not list or not event_values:
        raise ValueError("events must be a nonempty array")

    events: list[ScenarioEvent] = []
    seen: set[str] = set()
    for index, raw_event in enumerate(event_values):
        item = _mapping(raw_event, f"events[{index}]")
        _expect_keys(item, EVENT_FIELDS, "event")
        event_id = _string(item, "event_id")
        if event_id in seen:
            raise ValueError(f"duplicate event_id: {event_id}")
        phase = _integer(item, "phase", 1)
        timestamp = _integer(item, "timestamp_s", 0)
        identity = _string(item, "identity")
        authority_class = _string(item, "authority_class")
        summary = _string(item, "summary")
        source_ref = _string(item, "source_ref")
        credential_valid = _boolean(item, "credential_valid")
        policy_allows_action = _boolean(item, "policy_allows_action")
        control_rationale = _string(item, "control_rationale")
        state_rationale = _string(item, "state_rationale")
        dependencies = _dependencies(item, seen, event_id)

        state_raw = _mapping(_required(item, "state"), "state")
        modeled = _mapping(_required(item, "modeled_context"), "modeled_context")
        _expect_keys(state_raw, STATE_FIELDS, "state")
        _expect_keys(modeled, MODELED_FIELDS, "modeled_context")
        local_rationale = _string(modeled, "rationale")

        state = CompositeState(
            state_id=_string(state_raw, "state_id"),
            identity=identity,
            authority_class=authority_class,
            issued_at_s=_integer(state_raw, "issued_at_s", 0),
            not_before_s=_integer(state_raw, "not_before_s", 0),
            expires_at_s=_integer(state_raw, "expires_at_s", 1),
            charge=_decimal(state_raw, "charge"),
            threshold=_decimal(state_raw, "threshold"),
            history_count=_integer(state_raw, "history_count", 0),
            minimum_history=_integer(state_raw, "minimum_history", 0),
            authentic=_boolean(state_raw, "authentic"),
            veto_clear=_boolean(state_raw, "veto_clear"),
            envelope_allows=_boolean(state_raw, "envelope_allows"),
            decay_rate=_decimal(state_raw, "decay_rate"),
            maximum_charge=_decimal(state_raw, "maximum_charge"),
        )
        local_evidence = LocalEvidence(
            divergence=_decimal(modeled, "divergence"),
            coupled_loss=_decimal(modeled, "coupled_loss"),
            fresh=_boolean(modeled, "fresh"),
        )
        events.append(
            ScenarioEvent(
                event_id=event_id,
                phase=phase,
                request=ActionRequest(event_id, identity, authority_class, timestamp),
                observed_summary=LabeledValue(
                    summary,
                    EvidenceClass.OBSERVED,
                    source_ref=f"{primary_source}#{source_ref}",
                ),
                control_assumption=LabeledValue(
                    (credential_valid, policy_allows_action),
                    EvidenceClass.MODELED,
                    rationale=control_rationale,
                ),
                depends_on=dependencies,
                state_assumption=LabeledValue(
                    state,
                    EvidenceClass.MODELED,
                    rationale=state_rationale,
                ),
                local_evidence_assumption=LabeledValue(
                    local_evidence,
                    EvidenceClass.MODELED,
                    rationale=local_rationale,
                ),
            )
        )
        seen.add(event_id)

    return Scenario(SCHEMA_VERSION, scenario_id, primary_source, tuple(events))
