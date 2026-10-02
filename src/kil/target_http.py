"""Harmless V3B target process with an append-before-response ledger."""

from argparse import ArgumentParser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Callable

from .canonical import canonical_json
from .ext_authz_http import HttpRequest, HttpResponse
from .live_authz import LiveTrack


CONFIG_SCHEMA_VERSION = "kil.v3b-target-http.v1"
RECORD_SCHEMA_VERSION = "kil.v3b-target-record.v1"
MAX_CONFIG_BYTES = 64 * 1024
MAX_RECORDS = 100_000
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 8 * 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_ROUTES = frozenset(
    {
        ("GET", "/benign/read"),
        ("POST", "/consequential/admin"),
    }
)
_JOIN_HEADERS = frozenset(
    {"x-request-id", "x-kil-track", "x-kil-decision-digest"}
)
_BODY_HEADERS = frozenset({"transfer-encoding", "content-encoding"})


class TargetConfigError(ValueError):
    """Raised when the target process configuration is not closed and safe."""


class DuplicateTargetRecord(ValueError):
    """Raised when a request ID would create an ambiguous target marker."""


@dataclass(frozen=True, slots=True)
class TargetRecord:
    """One harmless target invocation marker."""

    schema_version: str
    run_id: str
    request_id: str
    track: LiveTrack
    path: str
    decision_digest: str
    received_monotonic_ns: int
    response_monotonic_ns: int

    def __post_init__(self) -> None:
        if self.schema_version != RECORD_SCHEMA_VERSION:
            raise ValueError("unsupported target record schema_version")
        for name in ("run_id", "request_id"):
            value = getattr(self, name)
            if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
                raise ValueError(f"{name} is invalid")
        if not isinstance(self.track, LiveTrack):
            raise ValueError("track must be a LiveTrack")
        if type(self.path) is not str or not any(
            self.path == path for _, path in _ROUTES
        ):
            raise ValueError("path is not a harmless target path")
        if (
            type(self.decision_digest) is not str
            or _DIGEST.fullmatch(self.decision_digest) is None
        ):
            raise ValueError("decision_digest is invalid")
        if (
            type(self.received_monotonic_ns) is not int
            or type(self.response_monotonic_ns) is not int
            or self.received_monotonic_ns < 0
            or self.response_monotonic_ns < self.received_monotonic_ns
        ):
            raise ValueError("target timestamps are invalid")


ClockNanoseconds = Callable[[], int]


class TargetLedger:
    """Thread-safe canonical JSONL ledger with atomic duplicate detection."""

    __slots__ = ("_invalid", "_lock", "_path", "_records", "_request_ids")

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("ledger path must be absolute")
        if not path.parent.is_dir():
            raise ValueError("ledger parent directory must exist")
        if path.is_symlink():
            raise ValueError("ledger path must not be a symbolic link")
        if path.exists() and not path.is_file():
            raise ValueError("ledger path must be a regular file")
        self._path = path
        self._records: list[TargetRecord] = []
        self._request_ids: set[str] = set()
        self._invalid = False
        self._lock = threading.Lock()
        if path.exists():
            self._load_existing()

    def _load_existing(self) -> None:
        ledger_stat = self._path.stat()
        if stat.S_IMODE(ledger_stat.st_mode) != 0o600:
            raise ValueError("existing ledger must use owner-only mode 0600")
        if ledger_stat.st_size > MAX_LEDGER_BYTES:
            raise ValueError("existing ledger exceeds the size limit")
        try:
            payload = self._path.read_bytes()
            if payload and not payload.endswith(b"\n"):
                raise ValueError("existing ledger has an incomplete final record")
            for raw_line in payload.splitlines():
                if not raw_line or len(raw_line) > MAX_RECORD_BYTES:
                    raise ValueError("existing ledger record is invalid")
                record = _decode_target_record(raw_line)
                if record.request_id in self._request_ids:
                    raise ValueError("existing ledger contains duplicate request IDs")
                self._request_ids.add(record.request_id)
                self._records.append(record)
            if len(self._records) > MAX_RECORDS:
                raise ValueError("existing ledger exceeds the record limit")
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("existing ledger is not canonical JSONL") from error

    @property
    def path(self) -> Path:
        return self._path

    @property
    def records(self) -> tuple[TargetRecord, ...]:
        with self._lock:
            return tuple(self._records)

    @property
    def invalid(self) -> bool:
        with self._lock:
            return self._invalid

    def append_marker(
        self,
        *,
        run_id: str,
        request_id: str,
        track: LiveTrack,
        path: str,
        decision_digest: str,
        monotonic_ns: ClockNanoseconds,
    ) -> TargetRecord:
        """Append and fsync one marker before returning it to the caller."""
        with self._lock:
            if request_id in self._request_ids:
                self._invalid = True
                raise DuplicateTargetRecord("duplicate target request_id")
            if len(self._records) >= MAX_RECORDS:
                self._invalid = True
                raise OSError("target ledger record limit exceeded")
            try:
                received_ns = monotonic_ns()
                response_ns = monotonic_ns()
                record = TargetRecord(
                    schema_version=RECORD_SCHEMA_VERSION,
                    run_id=run_id,
                    request_id=request_id,
                    track=track,
                    path=path,
                    decision_digest=decision_digest,
                    received_monotonic_ns=received_ns,
                    response_monotonic_ns=response_ns,
                )
                payload = (canonical_json(record) + "\n").encode("utf-8")
                flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(self._path, flags, 0o600)
                try:
                    offset = 0
                    while offset < len(payload):
                        written = os.write(descriptor, payload[offset:])
                        if written <= 0:
                            raise OSError("target ledger append made no progress")
                        offset += written
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except Exception:
                self._invalid = True
                raise
            self._request_ids.add(request_id)
            self._records.append(record)
            return record


class TargetHttpApp:
    """Validate a fixed target join and emit only a harmless ledger marker."""

    __slots__ = ("_ledger", "_monotonic_ns", "_run_id", "_track")

    def __init__(
        self,
        run_id: str,
        track: LiveTrack,
        ledger: TargetLedger,
        *,
        monotonic_ns: ClockNanoseconds = time.monotonic_ns,
    ) -> None:
        if type(run_id) is not str or _IDENTIFIER.fullmatch(run_id) is None:
            raise ValueError("run_id is invalid")
        if not isinstance(track, LiveTrack):
            raise ValueError("track must be a LiveTrack")
        if not isinstance(ledger, TargetLedger):
            raise ValueError("ledger must be a TargetLedger")
        if not callable(monotonic_ns):
            raise ValueError("monotonic_ns must be callable")
        if any(
            record.run_id != run_id or record.track is not track
            for record in ledger.records
        ):
            raise ValueError("existing ledger does not match fixed run and track")
        self._run_id = run_id
        self._track = track
        self._ledger = ledger
        self._monotonic_ns = monotonic_ns

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def track(self) -> LiveTrack:
        return self._track

    @property
    def records(self) -> tuple[TargetRecord, ...]:
        return self._ledger.records

    @property
    def invalid(self) -> bool:
        return self._ledger.invalid

    def _join_values(self, request: HttpRequest) -> tuple[str, str] | None:
        grouped: dict[str, list[str]] = {}
        for name, value in request.headers:
            grouped.setdefault(name.lower(), []).append(value)
        if any(len(grouped.get(name, ())) != 1 for name in _JOIN_HEADERS):
            return None
        if any(name in grouped for name in _BODY_HEADERS):
            return None
        content_lengths = grouped.get("content-length", [])
        if len(content_lengths) > 1 or (
            content_lengths and content_lengths[0].strip() != "0"
        ):
            return None
        request_id = grouped["x-request-id"][0]
        track = grouped["x-kil-track"][0]
        digest = grouped["x-kil-decision-digest"][0]
        if (
            _IDENTIFIER.fullmatch(request_id) is None
            or track != self.track.value
            or _DIGEST.fullmatch(digest) is None
        ):
            return None
        return request_id, digest

    def handle(self, request: HttpRequest) -> HttpResponse:
        if not isinstance(request, HttpRequest):
            raise ValueError("request must be an HttpRequest")
        if request.method == "GET" and request.path == "/healthz":
            if request.body or self._join_values_for_health(request) is False:
                return HttpResponse(400, {}, b"invalid request\n")
            return HttpResponse(200, {}, b"ok\n")
        if (request.method, request.path) not in _ROUTES:
            return HttpResponse(404, {}, b"not found\n")
        if request.body:
            return HttpResponse(400, {}, b"invalid request\n")
        join = self._join_values(request)
        if join is None:
            return HttpResponse(400, {}, b"invalid request\n")
        request_id, digest = join
        try:
            self._ledger.append_marker(
                run_id=self.run_id,
                request_id=request_id,
                track=self.track,
                path=request.path,
                decision_digest=digest,
                monotonic_ns=self._monotonic_ns,
            )
        except DuplicateTargetRecord:
            return HttpResponse(409, {}, b"conflict\n")
        except Exception:
            return HttpResponse(503, {}, b"unavailable\n")
        return HttpResponse(200, {}, b"recorded\n")

    def _join_values_for_health(self, request: HttpRequest) -> bool:
        grouped: dict[str, list[str]] = {}
        for name, value in request.headers:
            grouped.setdefault(name.lower(), []).append(value)
        if any(name in grouped for name in _BODY_HEADERS):
            return False
        content_lengths = grouped.get("content-length", [])
        return not (
            len(content_lengths) > 1
            or (content_lengths and content_lengths[0].strip() != "0")
        )


@dataclass(frozen=True, slots=True)
class TargetServiceRuntime:
    app: TargetHttpApp
    bind_host: str
    bind_port: int


def _closed_record_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate target record field: {key}")
        result[key] = value
    return result


def _decode_target_record(raw_line: bytes) -> TargetRecord:
    try:
        text = raw_line.decode("utf-8")
        raw = json.loads(text, object_pairs_hook=_closed_record_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("target record is not valid UTF-8 JSON") from error
    expected = {
        "schema_version",
        "run_id",
        "request_id",
        "track",
        "path",
        "decision_digest",
        "received_monotonic_ns",
        "response_monotonic_ns",
    }
    if type(raw) is not dict or set(raw) != expected:
        raise ValueError("target record fields are not closed")
    if type(raw["track"]) is not str:
        raise ValueError("target record track must be a string")
    try:
        track = LiveTrack(raw["track"])
        record = TargetRecord(
            schema_version=raw["schema_version"],
            run_id=raw["run_id"],
            request_id=raw["request_id"],
            track=track,
            path=raw["path"],
            decision_digest=raw["decision_digest"],
            received_monotonic_ns=raw["received_monotonic_ns"],
            response_monotonic_ns=raw["response_monotonic_ns"],
        )
    except (TypeError, ValueError) as error:
        raise ValueError("target record values are invalid") from error
    if canonical_json(record) != text:
        raise ValueError("target record is not canonical JSON")
    return record


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TargetConfigError(f"duplicate config field: {key}")
        result[key] = value
    return result


def load_target_service_config(
    path: Path,
    *,
    monotonic_ns: ClockNanoseconds = time.monotonic_ns,
) -> TargetServiceRuntime:
    """Load a closed read-only target configuration."""
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise TargetConfigError("config path must be a regular file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o222:
        raise TargetConfigError("config path must be read-only")
    size = path.stat().st_size
    if size <= 0 or size > MAX_CONFIG_BYTES:
        raise TargetConfigError("config file exceeds the configured size limit")
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_closed_object,
        )
    except TargetConfigError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TargetConfigError("config file is not valid UTF-8 JSON") from error
    if type(raw) is not dict:
        raise TargetConfigError("target config must be an object")
    expected = {
        "schema_version",
        "run_id",
        "track",
        "bind_host",
        "bind_port",
        "ledger_path",
    }
    unknown = set(raw) - expected
    missing = expected - set(raw)
    if unknown:
        raise TargetConfigError(f"unknown config fields: {sorted(unknown)}")
    if missing:
        raise TargetConfigError(f"missing config fields: {sorted(missing)}")
    if raw["schema_version"] != CONFIG_SCHEMA_VERSION:
        raise TargetConfigError("unsupported config schema_version")
    if type(raw["run_id"]) is not str:
        raise TargetConfigError("run_id must be a string")
    if type(raw["track"]) is not str:
        raise TargetConfigError("track must be a string")
    try:
        track = LiveTrack(raw["track"])
    except ValueError as error:
        raise TargetConfigError("track must be a fixed LiveTrack value") from error
    if raw["bind_host"] != "0.0.0.0":
        raise TargetConfigError("bind_host must be 0.0.0.0 inside the container")
    if type(raw["bind_port"]) is not int or raw["bind_port"] != 8080:
        raise TargetConfigError("bind_port must be 8080")
    if type(raw["ledger_path"]) is not str:
        raise TargetConfigError("ledger_path must be a string")
    ledger_path = Path(raw["ledger_path"])
    try:
        ledger = TargetLedger(ledger_path)
        app = TargetHttpApp(
            raw["run_id"],
            track,
            ledger,
            monotonic_ns=monotonic_ns,
        )
    except ValueError as error:
        raise TargetConfigError(str(error)) from error
    return TargetServiceRuntime(app, "0.0.0.0", 8080)


class _TargetServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        app: TargetHttpApp,
        *,
        bind_and_activate: bool = True,
    ) -> None:
        self.app = app
        super().__init__(
            address,
            _TargetHandler,
            bind_and_activate=bind_and_activate,
        )


class _TargetHandler(BaseHTTPRequestHandler):
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
            self._send(HttpResponse(400, {}, b"invalid request\n"))
        except OSError:
            self.close_connection = True

    def _handle_target(self) -> None:
        try:
            request = HttpRequest(
                self.command,
                self.path,
                tuple(self.headers.raw_items()),
                b"",
            )
            response = self.server.app.handle(request)  # type: ignore[attr-defined]
        except Exception:
            response = HttpResponse(400, {}, b"invalid request\n")
        try:
            self._send(response)
        except OSError:
            self.close_connection = True

    do_GET = _handle_target
    do_POST = _handle_target
    do_PUT = _handle_target
    do_PATCH = _handle_target
    do_DELETE = _handle_target
    do_HEAD = _handle_target
    do_OPTIONS = _handle_target
    do_CONNECT = _handle_target
    do_TRACE = _handle_target


def create_target_http_server(
    app: TargetHttpApp,
    host: str,
    port: int,
    *,
    bind_and_activate: bool = True,
) -> ThreadingHTTPServer:
    if not isinstance(app, TargetHttpApp):
        raise ValueError("app must be a TargetHttpApp")
    if host not in {"0.0.0.0", "127.0.0.1"}:
        raise ValueError("server host must be an approved container or test bind")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("server port is invalid")
    if type(bind_and_activate) is not bool:
        raise ValueError("bind_and_activate must be a boolean")
    return _TargetServer(
        (host, port),
        app,
        bind_and_activate=bind_and_activate,
    )


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        runtime = load_target_service_config(arguments.config)
        server = create_target_http_server(
            runtime.app,
            runtime.bind_host,
            runtime.bind_port,
        )
    except (OSError, TargetConfigError, ValueError) as error:
        parser.error(str(error))
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
