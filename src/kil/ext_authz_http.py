"""Raw HTTP ``ext_authz`` boundary around the immutable KIL live adapter."""

from argparse import ArgumentParser
from base64 import b64decode
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from types import MappingProxyType
from typing import Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json
from .domain import ActionRequest, DecisionOutcome, LocalEvidence, ReductionProfile
from .live_authz import AuthorizationAdapter, LiveFixture, LiveTrack
from .q_state import key_id


CONFIG_SCHEMA_VERSION = "kil.v3b-authz-http.v1"
RECORD_SCHEMA_VERSION = "kil.v3b-authz-record.v1"
MAX_HEADER_BYTES = 16 * 1024
MAX_HEADER_COUNT = 64
MAX_PATH_BYTES = 2048
MAX_BODY_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_FIXTURES = 10_000
MAX_PUBLIC_KEYS = 32
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_METHOD = re.compile(r"^[A-Z]{1,16}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_TRUSTED_HEADERS = frozenset(
    {"x-request-id", "authorization", "x-kil-q-state"}
)
_IGNORED_TRANSPORT_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "x-envoy-expected-rq-timeout-ms",
        "x-envoy-internal",
    }
)
_PROHIBITED_BODY_HEADERS = frozenset({"transfer-encoding", "content-encoding"})


class ConfigError(ValueError):
    """Raised when the read-only authorization-service config is unsafe."""


def _require_nonblank(name: str, value: object) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonblank string")
    return value


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes = b""

    def __post_init__(self) -> None:
        if type(self.method) is not str or _METHOD.fullmatch(self.method) is None:
            raise ValueError("method must be an uppercase HTTP token")
        if (
            type(self.path) is not str
            or not self.path.startswith("/")
            or any(character in self.path for character in ("\r", "\n", "\x00"))
            or len(self.path.encode("utf-8")) > MAX_PATH_BYTES
        ):
            raise ValueError("path is invalid or exceeds the path limit")
        if type(self.headers) is not tuple or len(self.headers) > MAX_HEADER_COUNT:
            raise ValueError("headers must be a bounded tuple")
        header_bytes = 0
        for header in self.headers:
            if (
                type(header) is not tuple
                or len(header) != 2
                or type(header[0]) is not str
                or _HEADER_NAME.fullmatch(header[0]) is None
                or type(header[1]) is not str
                or any(
                    character in header[1] for character in ("\r", "\n", "\x00")
                )
            ):
                raise ValueError("header entries must be valid string pairs")
            try:
                header_bytes += len(header[0].encode("ascii"))
                header_bytes += len(header[1].encode("utf-8")) + 4
            except UnicodeError as error:
                raise ValueError("header encoding is invalid") from error
        if header_bytes > MAX_HEADER_BYTES:
            raise ValueError("request exceeds the total header limit")
        if type(self.body) is not bytes or len(self.body) > MAX_BODY_BYTES:
            raise ValueError("body must be bounded bytes")


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("status must be an HTTP status integer")
        if not isinstance(self.headers, Mapping):
            raise ValueError("headers must be a mapping")
        copied: dict[str, str] = {}
        for name, value in self.headers.items():
            if (
                type(name) is not str
                or _HEADER_NAME.fullmatch(name) is None
                or type(value) is not str
                or any(character in value for character in ("\r", "\n", "\x00"))
            ):
                raise ValueError("response headers must be valid string pairs")
            lowered = name.lower()
            if lowered in copied:
                raise ValueError("response headers must be unique")
            copied[lowered] = value
        if type(self.body) is not bytes:
            raise ValueError("response body must be bytes")
        object.__setattr__(self, "headers", MappingProxyType(copied))


@dataclass(frozen=True, slots=True)
class ServerFixture:
    """Read-only facts selected by request ID, never by client authority claims."""

    request_id: str
    method: str
    path: str
    identity: str
    authority_class: str
    action_class: str
    expected_authorization_sha256: str
    policy_allows_action: bool
    local_evidence: LocalEvidence | None
    reduction_profile: ReductionProfile | None

    def __post_init__(self) -> None:
        if type(self.request_id) is not str or _REQUEST_ID.fullmatch(
            self.request_id
        ) is None:
            raise ValueError("request_id is invalid")
        if type(self.method) is not str or _METHOD.fullmatch(self.method) is None:
            raise ValueError("fixture method is invalid")
        if (
            type(self.path) is not str
            or not self.path.startswith("/")
            or len(self.path.encode("utf-8")) > MAX_PATH_BYTES
        ):
            raise ValueError("fixture path is invalid")
        for name in ("identity", "authority_class", "action_class"):
            _require_nonblank(name, getattr(self, name))
        if (
            type(self.expected_authorization_sha256) is not str
            or _DIGEST.fullmatch(self.expected_authorization_sha256) is None
        ):
            raise ValueError("expected_authorization_sha256 must be a digest")
        if type(self.policy_allows_action) is not bool:
            raise ValueError("policy_allows_action must be a boolean")
        if self.local_evidence is not None and not isinstance(
            self.local_evidence, LocalEvidence
        ):
            raise ValueError("local_evidence must be LocalEvidence or None")
        if self.reduction_profile is not None and not isinstance(
            self.reduction_profile, ReductionProfile
        ):
            raise ValueError("reduction_profile must be ReductionProfile or None")


@dataclass(frozen=True, slots=True)
class AuthorizationHttpRecord:
    schema_version: str
    request_id: str | None
    track: LiveTrack
    method: str
    path: str
    outcome: str
    http_status: int
    decision_digest: str | None
    adapter_reasons: tuple[str, ...]
    engine_reasons: tuple[str, ...]
    untrusted_header_names: tuple[str, ...]
    monotonic_ns: int


class JsonlDecisionRecorder:
    """Thread-safe append-only canonical decision recorder."""

    __slots__ = ("_lock", "_path")

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("record path must be absolute")
        if not path.parent.is_dir():
            raise ValueError("record parent directory must exist")
        if path.is_symlink():
            raise ValueError("record path must not be a symbolic link")
        self._path = path
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def append(self, record: AuthorizationHttpRecord) -> None:
        if not isinstance(record, AuthorizationHttpRecord):
            raise ValueError("record must be an AuthorizationHttpRecord")
        payload = (canonical_json(record) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with self._lock:
            descriptor = os.open(self._path, flags, 0o600)
            try:
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        raise OSError("decision record append made no progress")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


ClockSeconds = Callable[[], int]
ClockNanoseconds = Callable[[], int]


class AuthorizationHttpApp:
    """Convert bounded HTTP facts to ``LiveFixture`` and delegate unchanged."""

    __slots__ = (
        "_adapter",
        "_clock_s",
        "_fixtures",
        "_lock",
        "_monotonic_ns",
        "_recorder",
        "_records",
    )

    def __init__(
        self,
        adapter: AuthorizationAdapter,
        fixtures: Mapping[str, ServerFixture],
        *,
        clock_s: ClockSeconds = lambda: int(time.time()),
        monotonic_ns: ClockNanoseconds = time.monotonic_ns,
        recorder: JsonlDecisionRecorder | None = None,
    ) -> None:
        if not isinstance(adapter, AuthorizationAdapter):
            raise ValueError("adapter must be an AuthorizationAdapter")
        if not isinstance(fixtures, Mapping) or not fixtures:
            raise ValueError("fixtures must be a nonempty mapping")
        copied: dict[str, ServerFixture] = {}
        for request_id, fixture in fixtures.items():
            if (
                type(request_id) is not str
                or not isinstance(fixture, ServerFixture)
                or request_id != fixture.request_id
            ):
                raise ValueError("fixture mapping does not match request IDs")
            copied[request_id] = fixture
        if not callable(clock_s) or not callable(monotonic_ns):
            raise ValueError("clocks must be callable")
        if recorder is not None and not isinstance(recorder, JsonlDecisionRecorder):
            raise ValueError("recorder must be JsonlDecisionRecorder or None")
        self._adapter = adapter
        self._fixtures = MappingProxyType(copied)
        self._clock_s = clock_s
        self._monotonic_ns = monotonic_ns
        self._recorder = recorder
        self._records: list[AuthorizationHttpRecord] = []
        self._lock = threading.Lock()

    @property
    def adapter(self) -> AuthorizationAdapter:
        return self._adapter

    @property
    def records(self) -> tuple[AuthorizationHttpRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def _header_groups(self, request: HttpRequest) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = {}
        for name, value in request.headers:
            grouped.setdefault(name.lower(), []).append(value)
        for name in _TRUSTED_HEADERS:
            if len(grouped.get(name, ())) > 1:
                raise ValueError(f"duplicate trusted header: {name}")
        if any(name in grouped for name in _PROHIBITED_BODY_HEADERS):
            raise ValueError("body-bearing transport headers are prohibited")
        content_lengths = grouped.get("content-length", [])
        if len(content_lengths) > 1 or (
            content_lengths and content_lengths[0].strip() != "0"
        ):
            raise ValueError("request body must be zero bytes")
        return grouped

    def _untrusted_names(self, grouped: Mapping[str, list[str]]) -> tuple[str, ...]:
        return tuple(
            sorted(
                name
                for name in grouped
                if name not in _TRUSTED_HEADERS
                and name not in _IGNORED_TRANSPORT_HEADERS
            )
        )

    def _safe_request_id(self, grouped: Mapping[str, list[str]]) -> str | None:
        values = grouped.get("x-request-id", [])
        if len(values) == 1 and _REQUEST_ID.fullmatch(values[0]) is not None:
            return values[0]
        return None

    def _append_memory(self, record: AuthorizationHttpRecord) -> None:
        with self._lock:
            self._records.append(record)

    def _commit(self, record: AuthorizationHttpRecord) -> None:
        if self._recorder is not None:
            self._recorder.append(record)
        self._append_memory(record)

    def _commit_error_best_effort(self, record: AuthorizationHttpRecord) -> None:
        if self._recorder is not None:
            try:
                self._recorder.append(record)
            except OSError:
                pass
        self._append_memory(record)

    def _error_response(
        self,
        request: HttpRequest,
        grouped: Mapping[str, list[str]],
        decision_digest: str | None = None,
    ) -> HttpResponse:
        record = AuthorizationHttpRecord(
            schema_version=RECORD_SCHEMA_VERSION,
            request_id=self._safe_request_id(grouped),
            track=self.adapter.track,
            method=request.method,
            path=request.path,
            outcome="error",
            http_status=503,
            decision_digest=decision_digest,
            adapter_reasons=(),
            engine_reasons=(),
            untrusted_header_names=self._untrusted_names(grouped),
            monotonic_ns=self._monotonic_ns(),
        )
        self._commit_error_best_effort(record)
        headers = (
            {}
            if decision_digest is None
            else {"x-kil-decision-digest": decision_digest}
        )
        return HttpResponse(503, headers, b"unavailable\n")

    def handle(self, request: HttpRequest) -> HttpResponse:
        if not isinstance(request, HttpRequest):
            raise ValueError("request must be an HttpRequest")
        if request.method == "GET" and request.path == "/healthz":
            try:
                if request.body:
                    raise ValueError("request body must be zero bytes")
                self._header_groups(request)
            except ValueError:
                return HttpResponse(503, {}, b"unavailable\n")
            return HttpResponse(200, {}, b"ok\n")

        grouped: dict[str, list[str]] = {}
        decision_digest: str | None = None
        try:
            if request.body:
                raise ValueError("request body must be zero bytes")
            grouped = self._header_groups(request)
            request_id = self._safe_request_id(grouped)
            if request_id is None:
                raise ValueError("x-request-id is required")
            fixture = self._fixtures.get(request_id)
            if fixture is None:
                raise ValueError("unknown request fixture")
            if request.method != fixture.method or request.path != fixture.path:
                raise ValueError("request does not match server-side fixture")

            authorization_values = grouped.get("authorization", [])
            authorization = authorization_values[0] if authorization_values else ""
            authorization_digest = sha256(authorization.encode("utf-8")).hexdigest()
            credential_valid = hmac.compare_digest(
                authorization_digest,
                fixture.expected_authorization_sha256,
            )
            q_state_values = grouped.get("x-kil-q-state", [])
            q_state = q_state_values[0] if q_state_values else None
            untrusted_names = self._untrusted_names(grouped)
            untrusted_headers = tuple(
                (name, "[ignored]") for name in untrusted_names
            )
            action_request = ActionRequest(
                request_id=request_id,
                identity=fixture.identity,
                authority_class=fixture.authority_class,
                timestamp_s=self._clock_s(),
            )
            live_fixture = LiveFixture(
                request=action_request,
                action_class=fixture.action_class,
                credential_valid=credential_valid,
                policy_allows_action=fixture.policy_allows_action,
                q_state_jws=q_state,
                local_evidence=fixture.local_evidence,
                reduction_profile=fixture.reduction_profile,
                untrusted_headers=untrusted_headers,
            )
            decision = self.adapter.evaluate(live_fixture)
            decision_digest = decision.decision_digest
            permitted = decision.outcome is DecisionOutcome.PERMIT
            status_code = 200 if permitted else 403
            engine_reasons = (
                ()
                if decision.engine_record is None
                else tuple(
                    reason.value for reason in decision.engine_record.reasons
                )
            )
            record = AuthorizationHttpRecord(
                schema_version=RECORD_SCHEMA_VERSION,
                request_id=request_id,
                track=decision.track,
                method=request.method,
                path=request.path,
                outcome=decision.outcome.value,
                http_status=status_code,
                decision_digest=decision.decision_digest,
                adapter_reasons=decision.adapter_reasons,
                engine_reasons=engine_reasons,
                untrusted_header_names=untrusted_names,
                monotonic_ns=self._monotonic_ns(),
            )
            self._commit(record)
            return HttpResponse(
                status_code,
                {"x-kil-decision-digest": decision.decision_digest},
                b"" if permitted else b"denied\n",
            )
        except Exception:
            return self._error_response(request, grouped, decision_digest)


@dataclass(frozen=True, slots=True)
class AuthorizationServiceRuntime:
    app: AuthorizationHttpApp
    bind_host: str
    bind_port: int


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError(f"duplicate config field: {key}")
        result[key] = value
    return result


def _exact_fields(
    name: str,
    value: object,
    expected: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict:
        raise ConfigError(f"{name} must be an object")
    actual = set(value)
    unknown = actual - expected
    missing = expected - actual
    if unknown:
        raise ConfigError(f"unknown {name} fields: {sorted(unknown)}")
    if missing:
        raise ConfigError(f"missing {name} fields: {sorted(missing)}")
    return value


def _config_string(name: str, value: object) -> str:
    try:
        return _require_nonblank(name, value)
    except ValueError as error:
        raise ConfigError(str(error)) from error


def _config_decimal(name: str, value: object) -> Decimal:
    if type(value) is not str or _DECIMAL.fullmatch(value) is None:
        raise ConfigError(f"{name} must be a canonical nonnegative decimal")
    try:
        return Decimal(value)
    except InvalidOperation as error:
        raise ConfigError(f"{name} must be a canonical decimal") from error


def _optional_local_evidence(value: object) -> LocalEvidence | None:
    if value is None:
        return None
    item = _exact_fields(
        "local_evidence",
        value,
        frozenset({"divergence", "coupled_loss", "fresh"}),
    )
    if type(item["fresh"]) is not bool:
        raise ConfigError("local_evidence.fresh must be a boolean")
    try:
        return LocalEvidence(
            _config_decimal("local_evidence.divergence", item["divergence"]),
            _config_decimal("local_evidence.coupled_loss", item["coupled_loss"]),
            item["fresh"],
        )
    except ValueError as error:
        raise ConfigError(str(error)) from error


def _optional_reduction_profile(value: object) -> ReductionProfile | None:
    if value is None:
        return None
    item = _exact_fields(
        "reduction_profile",
        value,
        frozenset({"divergence_threshold", "loss_rate", "exponent"}),
    )
    if type(item["exponent"]) is not int:
        raise ConfigError("reduction_profile.exponent must be an integer")
    try:
        return ReductionProfile(
            _config_decimal(
                "reduction_profile.divergence_threshold",
                item["divergence_threshold"],
            ),
            _config_decimal("reduction_profile.loss_rate", item["loss_rate"]),
            item["exponent"],
        )
    except ValueError as error:
        raise ConfigError(str(error)) from error


def _public_keys(value: object) -> dict[str, Ed25519PublicKey]:
    if type(value) is not list or len(value) > MAX_PUBLIC_KEYS:
        raise ConfigError("public_keys must be a bounded list")
    keys: dict[str, Ed25519PublicKey] = {}
    for raw_item in value:
        item = _exact_fields(
            "public key",
            raw_item,
            frozenset({"key_id", "raw_base64url"}),
        )
        identifier = _config_string("public key_id", item["key_id"])
        encoded = _config_string("public raw_base64url", item["raw_base64url"])
        if "=" in encoded or _BASE64URL.fullmatch(encoded) is None:
            raise ConfigError("public key must use canonical base64url")
        try:
            padding = "=" * (-len(encoded) % 4)
            raw_key = b64decode(
                encoded + padding,
                altchars=b"-_",
                validate=True,
            )
            public_key = Ed25519PublicKey.from_public_bytes(raw_key)
        except (ValueError, TypeError) as error:
            raise ConfigError("public key is not a valid Ed25519 key") from error
        if key_id(public_key) != identifier:
            raise ConfigError("public key identifier does not match key bytes")
        if identifier in keys:
            raise ConfigError("duplicate public key identifier")
        keys[identifier] = public_key
    return keys


def _fixtures(value: object) -> dict[str, ServerFixture]:
    if type(value) is not list or not value or len(value) > MAX_FIXTURES:
        raise ConfigError("fixtures must be a nonempty bounded list")
    expected = frozenset(
        {
            "request_id",
            "method",
            "path",
            "identity",
            "authority_class",
            "action_class",
            "expected_authorization_sha256",
            "policy_allows_action",
            "local_evidence",
            "reduction_profile",
        }
    )
    fixtures: dict[str, ServerFixture] = {}
    for raw_item in value:
        item = _exact_fields("fixture", raw_item, expected)
        if type(item["policy_allows_action"]) is not bool:
            raise ConfigError("policy_allows_action must be a boolean")
        try:
            fixture = ServerFixture(
                request_id=_config_string("request_id", item["request_id"]),
                method=_config_string("method", item["method"]),
                path=_config_string("path", item["path"]),
                identity=_config_string("identity", item["identity"]),
                authority_class=_config_string(
                    "authority_class", item["authority_class"]
                ),
                action_class=_config_string("action_class", item["action_class"]),
                expected_authorization_sha256=_config_string(
                    "expected_authorization_sha256",
                    item["expected_authorization_sha256"],
                ),
                policy_allows_action=item["policy_allows_action"],
                local_evidence=_optional_local_evidence(item["local_evidence"]),
                reduction_profile=_optional_reduction_profile(
                    item["reduction_profile"]
                ),
            )
        except ValueError as error:
            raise ConfigError(str(error)) from error
        if fixture.request_id in fixtures:
            raise ConfigError("duplicate fixture request_id")
        fixtures[fixture.request_id] = fixture
    return fixtures


def load_service_config(
    path: Path,
    *,
    clock_s: ClockSeconds = lambda: int(time.time()),
    monotonic_ns: ClockNanoseconds = time.monotonic_ns,
) -> AuthorizationServiceRuntime:
    """Load one closed read-only configuration and construct the fixed app."""
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise ConfigError("config path must be a regular file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o222:
        raise ConfigError("config path must be read-only")
    size = path.stat().st_size
    if size <= 0 or size > MAX_CONFIG_BYTES:
        raise ConfigError("config file exceeds the configured size limit")
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_closed_object,
        )
    except ConfigError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigError("config file is not valid UTF-8 JSON") from error
    top = _exact_fields(
        "config",
        raw,
        frozenset(
            {
                "schema_version",
                "track",
                "bind_host",
                "bind_port",
                "records_path",
                "public_keys",
                "revoked_state_ids",
                "fixtures",
            }
        ),
    )
    if top["schema_version"] != CONFIG_SCHEMA_VERSION:
        raise ConfigError("unsupported config schema_version")
    try:
        track = LiveTrack(_config_string("track", top["track"]))
    except ValueError as error:
        raise ConfigError("track must be a fixed LiveTrack value") from error
    if top["bind_host"] != "0.0.0.0":
        raise ConfigError("bind_host must be 0.0.0.0 inside the container")
    if type(top["bind_port"]) is not int or top["bind_port"] != 8080:
        raise ConfigError("bind_port must be 8080")
    records_path = Path(_config_string("records_path", top["records_path"]))
    try:
        recorder = JsonlDecisionRecorder(records_path)
    except ValueError as error:
        raise ConfigError(str(error)) from error
    keys = _public_keys(top["public_keys"])
    revoked_raw = top["revoked_state_ids"]
    if type(revoked_raw) is not list or any(
        type(item) is not str or not item for item in revoked_raw
    ):
        raise ConfigError("revoked_state_ids must be a list of identifiers")
    if len(set(revoked_raw)) != len(revoked_raw):
        raise ConfigError("revoked_state_ids must be unique")
    try:
        adapter = AuthorizationAdapter(
            track,
            keys=keys,
            revoked_state_ids=frozenset(revoked_raw),
        )
        app = AuthorizationHttpApp(
            adapter,
            _fixtures(top["fixtures"]),
            clock_s=clock_s,
            monotonic_ns=monotonic_ns,
            recorder=recorder,
        )
    except ValueError as error:
        raise ConfigError(str(error)) from error
    return AuthorizationServiceRuntime(app, "0.0.0.0", 8080)


class _AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        app: AuthorizationHttpApp,
        *,
        bind_and_activate: bool = True,
    ) -> None:
        self.app = app
        super().__init__(
            address,
            _AuthorizationHandler,
            bind_and_activate=bind_and_activate,
        )


class _AuthorizationHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = ""
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, response: HttpResponse) -> None:
        self.send_response_only(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.send_header("content-length", str(len(response.body)))
        self.send_header("connection", "close")
        self.end_headers()
        if self.command != "HEAD" and response.body:
            self.wfile.write(response.body)
        self.close_connection = True

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        try:
            self._send(HttpResponse(503, {}, b"unavailable\n"))
        except OSError:
            self.close_connection = True

    def _handle_authorization(self) -> None:
        try:
            headers = tuple(self.headers.raw_items())
            request = HttpRequest(self.command, self.path, headers, b"")
            response = self.server.app.handle(request)  # type: ignore[attr-defined]
        except Exception:
            response = HttpResponse(503, {}, b"unavailable\n")
        try:
            self._send(response)
        except OSError:
            self.close_connection = True

    do_GET = _handle_authorization
    do_POST = _handle_authorization
    do_PUT = _handle_authorization
    do_PATCH = _handle_authorization
    do_DELETE = _handle_authorization
    do_HEAD = _handle_authorization
    do_OPTIONS = _handle_authorization
    do_CONNECT = _handle_authorization
    do_TRACE = _handle_authorization


def create_http_server(
    app: AuthorizationHttpApp,
    host: str,
    port: int,
    *,
    bind_and_activate: bool = True,
) -> ThreadingHTTPServer:
    if not isinstance(app, AuthorizationHttpApp):
        raise ValueError("app must be an AuthorizationHttpApp")
    if host not in {"0.0.0.0", "127.0.0.1"}:
        raise ValueError("server host must be an approved container or test bind")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("server port is invalid")
    if type(bind_and_activate) is not bool:
        raise ValueError("bind_and_activate must be a boolean")
    return _AppServer(
        (host, port),
        app,
        bind_and_activate=bind_and_activate,
    )


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        runtime = load_service_config(arguments.config)
        server = create_http_server(
            runtime.app,
            runtime.bind_host,
            runtime.bind_port,
        )
    except (ConfigError, OSError, ValueError) as error:
        parser.error(str(error))
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
