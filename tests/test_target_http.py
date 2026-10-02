from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import stat
import tempfile
import unittest

from kil.canonical import canonical_json
from kil.ext_authz_http import HttpRequest, HttpResponse
from kil.live_authz import LiveTrack
from kil.target_http import (
    TargetConfigError,
    TargetHttpApp,
    TargetLedger,
    TargetRecord,
    create_target_http_server,
    load_target_service_config,
)


RUN_ID = "v3b-local-run-1"
REQUEST_ID = "v3b-target-request-1"
DIGEST = "a" * 64
TRACK = LiveTrack.SIGNED_STATE_ONLY


class SequenceClock:
    def __init__(self, *values: int) -> None:
        self._values = iter(values)

    def __call__(self) -> int:
        return next(self._values)


class TargetHttpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def app(
        self,
        *,
        clock: SequenceClock | None = None,
        ledger: TargetLedger | None = None,
    ) -> TargetHttpApp:
        return TargetHttpApp(
            RUN_ID,
            TRACK,
            ledger or TargetLedger(self.root / "targets.jsonl"),
            monotonic_ns=clock or SequenceClock(100, 200),
        )

    def request(
        self,
        path: str,
        request_id: str = REQUEST_ID,
        *,
        method: str | None = None,
        track: str = TRACK.value,
        digest: str = DIGEST,
        extra_headers: tuple[tuple[str, str], ...] = (),
        body: bytes = b"",
    ) -> HttpRequest:
        resolved_method = method or (
            "GET" if path == "/benign/read" else "POST"
        )
        return HttpRequest(
            resolved_method,
            path,
            (
                ("x-request-id", request_id),
                ("x-kil-track", track),
                ("x-kil-decision-digest", digest),
                *extra_headers,
            ),
            body,
        )

    def test_admin_marker_is_appended_before_success_response(self) -> None:
        app = self.app(clock=SequenceClock(101, 202))

        response = app.handle(self.request("/consequential/admin"))

        self.assertEqual(response, HttpResponse(200, {}, b"recorded\n"))
        self.assertEqual(len(app.records), 1)
        self.assertEqual(app.records[0].request_id, REQUEST_ID)
        self.assertEqual(app.records[0].path, "/consequential/admin")
        self.assertEqual(app.records[0].received_monotonic_ns, 101)
        self.assertEqual(app.records[0].response_monotonic_ns, 202)
        persisted = (self.root / "targets.jsonl").read_text(encoding="utf-8")
        self.assertEqual(persisted, canonical_json(app.records[0]) + "\n")

    def test_benign_read_appends_the_same_no_effect_marker_schema(self) -> None:
        app = self.app()

        response = app.handle(self.request("/benign/read"))

        self.assertEqual(response.status, 200)
        self.assertEqual(app.records[0].path, "/benign/read")
        self.assertEqual(app.records[0].track, TRACK)
        self.assertEqual(app.records[0].run_id, RUN_ID)
        self.assertEqual(app.records[0].decision_digest, DIGEST)

    def test_duplicate_request_id_is_an_evidence_conflict(self) -> None:
        app = self.app(clock=SequenceClock(100, 110, 120))
        first = app.handle(self.request("/benign/read"))

        response = app.handle(self.request("/benign/read"))

        self.assertEqual(first.status, 200)
        self.assertEqual(response, HttpResponse(409, {}, b"conflict\n"))
        self.assertTrue(app.invalid)
        self.assertEqual(len(app.records), 1)
        self.assertEqual(
            len((self.root / "targets.jsonl").read_text().splitlines()),
            1,
        )

    def test_duplicate_request_id_remains_a_conflict_after_restart(self) -> None:
        path = self.root / "targets.jsonl"
        first = self.app(ledger=TargetLedger(path))
        self.assertEqual(first.handle(self.request("/benign/read")).status, 200)

        restarted = self.app(ledger=TargetLedger(path))
        response = restarted.handle(self.request("/benign/read"))

        self.assertEqual(response, HttpResponse(409, {}, b"conflict\n"))
        self.assertTrue(restarted.invalid)
        self.assertEqual(len(restarted.records), 1)
        self.assertEqual(len(path.read_text().splitlines()), 1)

    def test_ledger_never_persists_authorization_or_q_state(self) -> None:
        app = self.app()
        request = self.request(
            "/consequential/admin",
            extra_headers=(
                ("authorization", "Bearer target-must-not-store"),
                ("x-kil-q-state", "eyJtarget-must-not-store"),
            ),
        )

        response = app.handle(request)

        self.assertEqual(response.status, 200)
        encoded = canonical_json(app.records[0])
        persisted = (self.root / "targets.jsonl").read_text(encoding="utf-8")
        for prohibited in (
            "authorization",
            "q-state",
            "Bearer",
            "eyJ",
            "target-must-not-store",
        ):
            self.assertNotIn(prohibited, encoded)
            self.assertNotIn(prohibited, persisted)

    def test_unknown_route_or_wrong_method_returns_404_without_a_marker(self) -> None:
        for request in (
            self.request("/unknown"),
            self.request("/benign/read", method="POST"),
            self.request("/consequential/admin", method="GET"),
        ):
            with self.subTest(method=request.method, path=request.path):
                app = self.app()
                self.assertEqual(app.handle(request).status, 404)
                self.assertEqual(app.records, ())
                self.assertFalse((self.root / "targets.jsonl").exists())

    def test_join_headers_are_required_bounded_unique_and_exact(self) -> None:
        cases = (
            HttpRequest("GET", "/benign/read", (), b""),
            self.request("/benign/read", request_id="bad request id"),
            self.request("/benign/read", track=LiveTrack.SIGNED_PLUS_LOCAL_REDUCE.value),
            self.request("/benign/read", digest="not-a-digest"),
            self.request(
                "/benign/read",
                extra_headers=(("X-KIL-TRACK", TRACK.value),),
            ),
        )
        for request in cases:
            with self.subTest(headers=request.headers):
                app = self.app()
                self.assertEqual(
                    app.handle(request),
                    HttpResponse(400, {}, b"invalid request\n"),
                )
                self.assertEqual(app.records, ())

    def test_body_bearing_requests_fail_without_a_marker(self) -> None:
        app = self.app()

        response = app.handle(
            self.request(
                "/consequential/admin",
                extra_headers=(("content-length", "1"),),
            )
        )

        self.assertEqual(response.status, 400)
        self.assertEqual(app.records, ())

    def test_health_check_never_creates_a_target_marker(self) -> None:
        app = self.app()

        response = app.handle(HttpRequest("GET", "/healthz", (), b""))

        self.assertEqual(response, HttpResponse(200, {}, b"ok\n"))
        self.assertEqual(app.records, ())

    def test_record_and_application_identity_are_immutable(self) -> None:
        app = self.app()
        app.handle(self.request("/benign/read"))
        record = app.records[0]

        with self.assertRaises(FrozenInstanceError):
            record.path = "/changed"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            app.track = LiveTrack.CREDENTIAL_POLICY_BASELINE  # type: ignore[misc]
        self.assertFalse(hasattr(record, "__dict__"))

    def test_append_failure_returns_503_and_invalidates_the_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = TargetLedger(Path(directory) / "targets.jsonl")
        app = self.app(ledger=ledger)

        response = app.handle(self.request("/benign/read"))

        self.assertEqual(response, HttpResponse(503, {}, b"unavailable\n"))
        self.assertTrue(app.invalid)
        self.assertEqual(app.records, ())

    def test_ledger_file_is_owner_only_and_canonical_jsonl(self) -> None:
        app = self.app()

        app.handle(self.request("/benign/read"))

        path = self.root / "targets.jsonl"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        raw = path.read_text(encoding="utf-8")
        self.assertEqual(json.loads(raw), json.loads(canonical_json(app.records[0])))

    def config_mapping(self, ledger_path: Path) -> dict[str, object]:
        return {
            "schema_version": "kil.v3b-target-http.v1",
            "run_id": RUN_ID,
            "track": TRACK.value,
            "bind_host": "0.0.0.0",
            "bind_port": 8080,
            "ledger_path": str(ledger_path),
        }

    def write_read_only_config(
        self,
        mapping: dict[str, object],
        *,
        mode: int = 0o444,
    ) -> Path:
        path = self.root / "target.json"
        path.write_text(json.dumps(mapping), encoding="utf-8")
        path.chmod(mode)
        return path

    def test_read_only_closed_config_fixes_run_track_bind_and_ledger(self) -> None:
        ledger_path = self.root / "targets.jsonl"
        config = self.write_read_only_config(self.config_mapping(ledger_path))

        runtime = load_target_service_config(
            config,
            monotonic_ns=SequenceClock(100, 200),
        )

        self.assertEqual(runtime.app.run_id, RUN_ID)
        self.assertEqual(runtime.app.track, TRACK)
        self.assertEqual(runtime.bind_host, "0.0.0.0")
        self.assertEqual(runtime.bind_port, 8080)
        self.assertEqual(runtime.app.handle(self.request("/benign/read")).status, 200)
        self.assertTrue(ledger_path.exists())

    def test_config_rejects_unknown_writable_or_relative_ledger_input(self) -> None:
        cases: list[tuple[dict[str, object], int, str]] = []
        unknown = self.config_mapping(self.root / "targets.jsonl")
        unknown["credential"] = "must-not-load"
        cases.append((unknown, 0o444, "unknown"))
        writable = self.config_mapping(self.root / "targets.jsonl")
        cases.append((writable, 0o644, "read-only"))
        relative = self.config_mapping(Path("targets.jsonl"))
        cases.append((relative, 0o444, "absolute"))

        for index, (mapping, mode, message) in enumerate(cases):
            with self.subTest(message=message):
                path = self.root / f"target-{index}.json"
                path.write_text(json.dumps(mapping), encoding="utf-8")
                path.chmod(mode)
                with self.assertRaisesRegex(TargetConfigError, message):
                    load_target_service_config(path)

    def test_target_http_server_constructs_without_binding(self) -> None:
        app = self.app()

        server = create_target_http_server(
            app,
            "127.0.0.1",
            0,
            bind_and_activate=False,
        )
        try:
            self.assertIs(server.app, app)
            self.assertTrue(server.daemon_threads)
            self.assertEqual(app.records, ())
        finally:
            server.server_close()

    def test_target_record_rejects_inverted_timestamps(self) -> None:
        with self.assertRaisesRegex(ValueError, "timestamp"):
            TargetRecord(
                schema_version="kil.v3b-target-record.v1",
                run_id=RUN_ID,
                request_id=REQUEST_ID,
                track=TRACK,
                path="/benign/read",
                decision_digest=DIGEST,
                received_monotonic_ns=200,
                response_monotonic_ns=100,
            )


if __name__ == "__main__":
    unittest.main()
