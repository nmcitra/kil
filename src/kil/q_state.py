"""Experimental signed composite-state profile for KIL live validation."""

from base64 import b64decode, urlsafe_b64encode
import binascii
from dataclasses import dataclass, fields
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .domain import CompositeState


Q_STATE_SCHEMA_VERSION = "kil.q-state.v0"
MAX_VALIDITY_SECONDS = 10
MAX_DECIMAL_WIRE_LENGTH = 64
_DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")
_DECIMAL_PATTERN = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$")
_DECIMAL_FIELDS = frozenset(
    {"charge", "threshold", "decay_rate", "maximum_charge"}
)


class QStateVerificationError(ValueError):
    """Raised when a signed composite state cannot be safely consumed."""


@dataclass(frozen=True, slots=True)
class VerifiedQState:
    claims: "QStateClaims"
    composite_state: CompositeState
    key_id: str


def _require_nonblank(name: str, value: object) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonblank string")
    return value


def _require_integer(name: str, value: object) -> int:
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    return value


def _require_boolean(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")
    return value


def _require_decimal(name: str, value: object) -> Decimal:
    if type(value) is not Decimal or not value.is_finite():
        raise ValueError(f"{name} must be a finite Decimal")
    if value.is_zero() and value.is_signed():
        raise ValueError(f"{name} cannot be negative zero")
    if value < 0:
        raise ValueError(f"{name} must be nonnegative")
    if _decimal_wire_length(value) > MAX_DECIMAL_WIRE_LENGTH:
        raise ValueError(f"{name} exceeds maximum wire length")
    return value


def _decimal_wire_length(value: Decimal) -> int:
    if value.is_zero():
        return 1
    _, raw_digits, raw_exponent = value.as_tuple()
    digits = list(raw_digits)
    exponent = raw_exponent
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    if exponent >= 0:
        return len(digits) + exponent
    split = len(digits) + exponent
    if split > 0:
        return len(digits) + 1
    return 2 - split + len(digits)


def _decimal_wire(value: Decimal) -> str:
    if value.is_zero():
        return "0"
    wire = format(value, "f")
    if "." in wire:
        wire = wire.rstrip("0").rstrip(".")
    return wire


@dataclass(frozen=True, slots=True)
class QStateClaims:
    """Strict payload claims for the experimental ``kil.q-state.v0`` profile."""

    schema_version: str
    state_id: str
    issuer: str
    subject: str
    audience: str
    authority_class: str
    action_class: str
    issued_at_s: int
    not_before_s: int
    expires_at_s: int
    evidence_horizon_s: int
    trust_proof_id: str
    trust_proof_digest: str
    envelope_result_id: str
    envelope_result_digest: str
    deployment_profile: str
    charge: Decimal
    threshold: Decimal
    history_count: int
    minimum_history: int
    veto_clear: bool
    envelope_allows: bool
    decay_rate: Decimal
    maximum_charge: Decimal
    model_version: str
    parameter_version: str

    def __post_init__(self) -> None:
        if self.schema_version != Q_STATE_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must be {Q_STATE_SCHEMA_VERSION}"
            )
        for name in (
            "state_id",
            "issuer",
            "subject",
            "audience",
            "authority_class",
            "action_class",
            "trust_proof_id",
            "envelope_result_id",
            "deployment_profile",
            "model_version",
            "parameter_version",
        ):
            _require_nonblank(name, getattr(self, name))
        for name in (
            "issued_at_s",
            "not_before_s",
            "expires_at_s",
            "evidence_horizon_s",
            "history_count",
            "minimum_history",
        ):
            _require_integer(name, getattr(self, name))
        for name in ("veto_clear", "envelope_allows"):
            _require_boolean(name, getattr(self, name))
        for name in _DECIMAL_FIELDS:
            _require_decimal(name, getattr(self, name))
        for name in ("trust_proof_digest", "envelope_result_digest"):
            value = getattr(self, name)
            if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
                raise ValueError(f"{name} must be a sha256 digest")

        if not self.issued_at_s <= self.not_before_s < self.expires_at_s:
            raise ValueError("invalid state validity window")
        if self.expires_at_s - self.issued_at_s > MAX_VALIDITY_SECONDS:
            raise ValueError("state validity cannot exceed ten seconds")
        if self.evidence_horizon_s > self.issued_at_s:
            raise ValueError("evidence_horizon_s cannot be later than issuance")
        if self.history_count < 0 or self.minimum_history < 0:
            raise ValueError("history counts must be nonnegative")
        if self.charge > self.maximum_charge:
            raise ValueError("charge exceeds maximum_charge")
        if self.threshold > self.maximum_charge:
            raise ValueError("threshold exceeds maximum_charge")

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {}
        for item in fields(self):
            value = getattr(self, item.name)
            payload[item.name] = (
                _decimal_wire(value) if item.name in _DECIMAL_FIELDS else value
            )
        return payload

    @classmethod
    def from_payload(cls, payload: object) -> "QStateClaims":
        if type(payload) is not dict:
            raise ValueError("q-state payload must be an object")
        expected = {item.name for item in fields(cls)}
        actual = set(payload)
        unknown = actual - expected
        missing = expected - actual
        if unknown:
            raise ValueError(f"unknown q-state payload fields: {sorted(unknown)}")
        if missing:
            raise ValueError(f"missing q-state payload fields: {sorted(missing)}")

        values: dict[str, Any] = dict(payload)
        for name in _DECIMAL_FIELDS:
            raw = values[name]
            if (
                type(raw) is not str
                or len(raw) > MAX_DECIMAL_WIRE_LENGTH
                or _DECIMAL_PATTERN.fullmatch(raw) is None
            ):
                raise ValueError(f"{name} must be canonical fixed-point decimal")
            try:
                values[name] = Decimal(raw)
            except InvalidOperation as error:
                raise ValueError(
                    f"{name} must be canonical fixed-point decimal"
                ) from error
        return cls(**values)

    def to_composite_state(self) -> CompositeState:
        return CompositeState(
            state_id=self.state_id,
            identity=self.subject,
            authority_class=self.authority_class,
            issued_at_s=self.issued_at_s,
            not_before_s=self.not_before_s,
            expires_at_s=self.expires_at_s,
            charge=self.charge,
            threshold=self.threshold,
            history_count=self.history_count,
            minimum_history=self.minimum_history,
            authentic=True,
            veto_clear=self.veto_clear,
            envelope_allows=self.envelope_allows,
            decay_rate=self.decay_rate,
            maximum_charge=self.maximum_charge,
        )


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _b64encode(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if type(value) is not str or not value:
        raise QStateVerificationError("malformed base64url")
    try:
        padding = "=" * (-len(value) % 4)
        decoded = b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError, binascii.Error) as error:
        raise QStateVerificationError("malformed base64url") from error
    if _b64encode(decoded) != value:
        raise QStateVerificationError("non-canonical base64url")
    return decoded


def key_id(public_key: Ed25519PublicKey) -> str:
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("public_key must be an Ed25519PublicKey")
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sha256(raw).hexdigest()[:16]


def issue_q_state(
    claims: QStateClaims,
    private_key: Ed25519PrivateKey,
) -> str:
    if not isinstance(claims, QStateClaims):
        raise ValueError("claims must be QStateClaims")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private_key must be an Ed25519PrivateKey")
    kid = key_id(private_key.public_key())
    header = {"alg": "EdDSA", "kid": kid, "typ": "KIL-Q+JWT"}
    header_part = _b64encode(_json_bytes(header))
    payload_part = _b64encode(_json_bytes(claims.to_payload()))
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature_part = _b64encode(private_key.sign(signing_input))
    return f"{header_part}.{payload_part}.{signature_part}"


def _json_object(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QStateVerificationError(f"malformed {label}") from error
    if type(value) is not dict:
        raise QStateVerificationError(f"malformed {label}")
    return value


def verify_q_state(
    token: str,
    keys: Mapping[str, Ed25519PublicKey],
    now_s: int,
    expected_subject: str,
    expected_audience: str,
    expected_authority_class: str,
    expected_action_class: str,
    revoked_state_ids: frozenset[str],
) -> VerifiedQState:
    if type(token) is not str or not token:
        raise QStateVerificationError("malformed token")
    if not isinstance(keys, Mapping):
        raise ValueError("keys must be a mapping")
    if type(now_s) is not int:
        raise ValueError("now_s must be an integer")
    for name, value in (
        ("expected_subject", expected_subject),
        ("expected_audience", expected_audience),
        ("expected_authority_class", expected_authority_class),
        ("expected_action_class", expected_action_class),
    ):
        _require_nonblank(name, value)
    if type(revoked_state_ids) is not frozenset or not all(
        type(item) is str and item for item in revoked_state_ids
    ):
        raise ValueError("revoked_state_ids must be a frozenset of identifiers")

    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise QStateVerificationError("malformed compact JWS")
    header_part, payload_part, signature_part = parts
    header_bytes = _b64decode(header_part)
    payload_bytes = _b64decode(payload_part)
    signature = _b64decode(signature_part)
    header = _json_object(header_bytes, "protected header")
    if set(header) != {"alg", "kid", "typ"}:
        raise QStateVerificationError("invalid protected header")
    if header["alg"] != "EdDSA" or header["typ"] != "KIL-Q+JWT":
        raise QStateVerificationError("invalid protected header")
    kid = header["kid"]
    if type(kid) is not str or not kid:
        raise QStateVerificationError("invalid key identifier")
    public_key = keys.get(kid)
    if not isinstance(public_key, Ed25519PublicKey):
        raise QStateVerificationError("verification key unavailable")

    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as error:
        raise QStateVerificationError("signature verification failed") from error

    payload = _json_object(payload_bytes, "payload")
    try:
        claims = QStateClaims.from_payload(payload)
    except ValueError as error:
        raise QStateVerificationError("invalid q-state claims") from error
    if claims.state_id in revoked_state_ids:
        raise QStateVerificationError("state revoked")
    if now_s < claims.not_before_s:
        raise QStateVerificationError("state not yet valid")
    if now_s >= claims.expires_at_s:
        raise QStateVerificationError("state expired")
    if claims.subject != expected_subject:
        raise QStateVerificationError("subject binding mismatch")
    if claims.audience != expected_audience:
        raise QStateVerificationError("audience binding mismatch")
    if claims.authority_class != expected_authority_class:
        raise QStateVerificationError("authority class binding mismatch")
    if claims.action_class != expected_action_class:
        raise QStateVerificationError("action class binding mismatch")
    return VerifiedQState(claims, claims.to_composite_state(), kid)
