"""Pinned draft fixture preflight only; not an implementation adapter."""
import hashlib
import json
import math
from pathlib import Path

EXPECTATIONS = frozenset({
    'decision', 'supervision', 'tightenedAtMost', 'undefinedRecorded',
    'repeatCount', 'identicalResultRequired', 'autonomyDemandNotLessThanCompared',
    'environmentalCapacityNotGreaterThanCompared', 'compareTo',
    'decisionNotLooserThan', 'supervisionAtLeast',
})


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f'non-JSON numeric constant: {value}')


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('JSON numeric overflow')
    return number


def load_fixture(path, digest):
    """Validate exact bytes before any future adapter receives request inputs."""
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('fixture SHA-256 mismatch')
    document = json.loads(raw, object_pairs_hook=_object,
                          parse_constant=_reject_constant, parse_float=_finite_float)
    if not isinstance(document, dict) or document.get('profile') != 'software-substrate-execution':
        raise ValueError('wrong profile or root')
    vectors = document.get('vectors')
    if not isinstance(vectors, list) or not vectors:
        raise ValueError('empty or missing vectors')
    seen = set()
    for vector in vectors:
        if not isinstance(vector, dict):
            raise ValueError('vector must be an object')
        identifier = vector.get('id')
        if not isinstance(identifier, str) or not identifier.strip() or identifier in seen:
            raise ValueError('empty or duplicate vector ID')
        seen.add(identifier)
        if not isinstance(vector.get('request'), dict):
            raise ValueError('missing request object')
        expected = vector.get('expect')
        if not isinstance(expected, dict) or not expected or set(expected) - EXPECTATIONS:
            raise ValueError('missing or unknown expectation')
    return document
