"""Canonical serialization for deterministic KIL decision artifacts."""

from dataclasses import fields, is_dataclass
from decimal import Decimal
from enum import Enum
from hashlib import sha256
import json
from typing import Any


MAX_DEPTH = 64
MAX_ITEMS = 10_000
MAX_OUTPUT_BYTES = 1_000_000
_DECIMAL_TAG = "$kil.decimal"
_MAX_INTEGER_BITS = 4096


class _Traversal:
    __slots__ = ("active", "items")

    def __init__(self) -> None:
        self.active: set[int] = set()
        self.items = 0


def _validate_string(value: str) -> None:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(
            "canonical strings must contain only Unicode scalar values"
        ) from error
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError("canonical output size limit exceeded")


def _normalize_decimal(value: Decimal) -> dict[str, list[str | int]]:
    if not value.is_finite():
        raise ValueError("canonical values require a finite Decimal")
    sign, digits, exponent = value.as_tuple()
    if not any(digits):
        coefficient = "0"
        normalized_exponent = 0
    else:
        significant = list(digits)
        normalized_exponent = exponent
        while significant[-1] == 0:
            significant.pop()
            normalized_exponent += 1
        coefficient = "".join(str(digit) for digit in significant)
        if sign:
            coefficient = f"-{coefficient}"
    if len(coefficient) > MAX_OUTPUT_BYTES:
        raise ValueError("canonical output size limit exceeded")
    return {_DECIMAL_TAG: [coefficient, normalized_exponent]}


def _normalize(value: Any, state: _Traversal, depth: int) -> Any:
    if depth > MAX_DEPTH:
        raise ValueError("canonical depth limit exceeded")
    state.items += 1
    if state.items > MAX_ITEMS:
        raise ValueError("canonical item limit exceeded")

    if isinstance(value, Enum):
        return _normalize(value.value, state, depth + 1)
    if isinstance(value, Decimal):
        return _normalize_decimal(value)
    if type(value) is str:
        _validate_string(value)
        return value
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if value.bit_length() > _MAX_INTEGER_BITS:
            raise ValueError("canonical integer exceeds supported size")
        return value

    is_record = is_dataclass(value) and not isinstance(value, type)
    is_collection = is_record or isinstance(value, (dict, list, tuple))
    if is_collection:
        identity = id(value)
        if identity in state.active:
            raise ValueError("canonical value contains a cycle")
        state.active.add(identity)
        try:
            if is_record:
                return {
                    field.name: _normalize(
                        getattr(value, field.name), state, depth + 1
                    )
                    for field in fields(value)
                }
            if isinstance(value, dict):
                if not all(type(key) is str for key in value):
                    raise TypeError("canonical dictionary keys must be strings")
                for key in value:
                    _validate_string(key)
                if _DECIMAL_TAG in value:
                    raise ValueError(
                        "dictionary key uses a reserved canonical type tag"
                    )
                return {
                    key: _normalize(value[key], state, depth + 1)
                    for key in sorted(value)
                }
            return [_normalize(item, state, depth + 1) for item in value]
        finally:
            state.active.remove(identity)
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Return a stable UTF-8-ready JSON representation of ``value``."""
    text = json.dumps(
        _normalize(value, _Traversal(), 0),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("canonical output size limit exceeded")
    return text


def canonical_digest(value: Any) -> str:
    """Return the SHA-256 hex digest of the canonical JSON representation."""
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()
