"""Evidence labels that keep claims inside their evidentiary boundary."""

from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar


class EvidenceClass(str, Enum):
    """The provenance class attached to a value used by KIL."""

    OBSERVED = "observed"
    MODELED = "modeled"
    VALIDATED = "validated"


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class LabeledValue(Generic[T]):
    """A value whose evidence class carries the required provenance metadata."""

    value: T
    evidence_class: EvidenceClass
    source_ref: str | None = None
    rationale: str | None = None
    run_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_class, EvidenceClass):
            raise ValueError("evidence_class must be an EvidenceClass instance")
        if self.evidence_class is EvidenceClass.OBSERVED and not _is_nonblank_string(
            self.source_ref
        ):
            raise ValueError("observed evidence requires source_ref")
        if self.evidence_class is EvidenceClass.MODELED and not _is_nonblank_string(
            self.rationale
        ):
            raise ValueError("modeled evidence requires rationale")
        if self.evidence_class is EvidenceClass.VALIDATED and not _is_nonblank_string(
            self.run_id
        ):
            raise ValueError("validated evidence requires run_id")


def _is_nonblank_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())
