from base64 import urlsafe_b64encode
from dataclasses import FrozenInstanceError
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from kil.canonical import canonical_json
from kil.domain import LocalEvidence, ReductionProfile
from kil.ext_authz_http import (
    AuthorizationHttpApp,
    ConfigError,
    HttpRequest,
    HttpResponse,
    JsonlDecisionRecorder,
    ServerFixture,
    create_http_server,
    load_service_config,
)
from kil.live_authz import AuthorizationAdapter, LiveTrack
from kil.q_state import QStateClaims, issue_q_state, key_id


SUBJECT = "spiffe://kil.local/workload/demo"
AUTHORIZATION = "Bearer v3b-lab-credential"
AUTHORIZATION_DIGEST = sha256(AUTHORIZATION.encode()).hexdigest()
REQUEST_ID = "v3b-http-request-1"


def claims(audience: str) -> QStateClaims:
    return QStateClaims(
        schema_version="kil.q-state.v0",
        state_id=f"q-{audience}",
        issuer="https://lab-issuer.kil.invalid",
        subject=SUBJECT,
        audience=audience,
        authority_class="admin_action",
        action_class="consequential_admin",
        issued_at_s=100,
        not_before_s=100,
        expires_at_s=110,
        evidence_horizon_s=99,
        trust_proof_id="tp-v3b-1",
        trust_proof_digest="sha256:" + "a" * 64,
        envelope_result_id="ke-v3b-1",
        envelope_result_digest="sha256:" + "b" * 64,
        deployment_profile="kil-lab-v3@0",
        charge=Decimal("80"),
        threshold=Decimal("40"),
        history_count=5,
        minimum_history=2,
        veto_clear=True,
        envelope_allows=True,
        decay_rate=Decimal("0"),
        maximum_charge=Decimal("100"),
        model_version="kil-decay-v1",
        parameter_version="kil-v3b-fixture-v1",
    )


class ExtAuthzHttpTest(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.public_key = self.private_key.public_key()
        self.keys = {key_id(self.public_key): self.public_key}
        self.fixture = ServerFixture(
            request_id=REQUEST_ID,
            method="POST",
            path="/consequential/admin",
            identity=SUBJECT,
            authority_class="admin_action",
            action_class="consequential_admin",
            expected_authorization_sha256=AUTHORIZATION_DIGEST,
            policy_allows_action=True,
            local_evidence=LocalEvidence(Decimal("0.9"), Decimal("0"), True),
            reduction_profile=ReductionProfile(
                Decimal("0.25"), Decimal("25"), 3
            ),
        )
        self.signed_token = issue_q_state(
            claims("kil-v3-signed"), self.private_key
        )
        self.local_token = issue_q_state(
            claims("kil-v3-local"), self.private_key
        )

    def app(self, track: LiveTrack, *, recorder=None) -> AuthorizationHttpApp:
        adapter = (
            AuthorizationAdapter(track)
            if track is LiveTrack.CREDENTIAL_POLICY_BASELINE
            else AuthorizationAdapter(track, keys=self.keys)
        )
        return AuthorizationHttpApp(
            adapter,
            {REQUEST_ID: self.fixture},
            clock_s=lambda: 105,
            monotonic_ns=lambda: 123456,
            recorder=recorder,
        )

    def request(
        self,
        token: str | None,
        *,
        authorization: str | None = AUTHORIZATION,
        extra_headers: tuple[tuple[str, str], ...] = (),
        body: bytes = b"",
    ) -> HttpRequest:
        headers: list[tuple[str, str]] = [("x-request-id", REQUEST_ID)]
        if authorization is not None:
            headers.append(("authorization", authorization))
        if token is not None:
            headers.append(("x-kil-q-state", token))
        headers.extend(extra_headers)
        return HttpRequest(
            method="POST",
            path="/consequential/admin",
            headers=tuple(headers),
            body=body,
        )

    def test_http_records_are_frozen_and_slotted(self):
        request = self.request(self.signed_token)
        response = HttpResponse(200, {"x-test": "value"}, b"")

        with self.assertRaises(FrozenInstanceError):
            request.method = "GET"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            response.status = 403  # type: ignore[misc]
        with self.assertRaises(TypeError):
            response.headers["x-test"] = "changed"  # type: ignore[index]
        self.assertFalse(hasattr(request, "__dict__"))
        self.assertFalse(hasattr(response, "__dict__"))

    def test_permit_returns_200_and_only_the_decision_digest(self):
        app = self.app(LiveTrack.SIGNED_STATE_ONLY)

        response = app.handle(self.request(self.signed_token))

        self.assertEqual(response.status, 200)
        self.assertEqual(set(response.headers), {"x-kil-decision-digest"})
        self.assertEqual(response.body, b"")
        self.assertEqual(
            response.headers["x-kil-decision-digest"],
            app.records[0].decision_digest,
        )

    def test_policy_denial_is_generic_and_never_contains_internal_reason(self):
        app = self.app(LiveTrack.SIGNED_PLUS_LOCAL_REDUCE)

        response = app.handle(self.request(self.local_token))

        self.assertEqual(response.status, 403)
        self.assertEqual(response.body, b"denied\n")
        self.assertNotIn(b"threshold", response.body)
        self.assertNotIn(b"charge", response.body)
        self.assertEqual(set(response.headers), {"x-kil-decision-digest"})

    def test_unknown_headers_cannot_select_mode_or_supply_local_evidence(self):
        app = self.app(LiveTrack.SIGNED_PLUS_LOCAL_REDUCE)

        response = app.handle(
            self.request(
                self.local_token,
                extra_headers=(
                    ("x-kil-mode", "signed_state_only"),
                    ("x-kil-local-evidence", '{"divergence":"0"}'),
                    ("x-kil-verified-subject", "spiffe://attacker.invalid"),
                    ("x-kil-issuer", "https://attacker.invalid"),
                ),
            )
        )

        self.assertEqual(response.status, 403)
        self.assertEqual(app.adapter.track, LiveTrack.SIGNED_PLUS_LOCAL_REDUCE)
        self.assertEqual(
            app.records[0].untrusted_header_names,
            (
                "x-kil-issuer",
                "x-kil-local-evidence",
                "x-kil-mode",
                "x-kil-verified-subject",
            ),
        )

    def test_envoy_transport_headers_are_ignored_but_arbitrary_headers_are_not(self):
        app = self.app(LiveTrack.SIGNED_STATE_ONLY)

        response = app.handle(
            self.request(
                self.signed_token,
                extra_headers=(
                    ("x-envoy-expected-rq-timeout-ms", "250"),
                    ("x-envoy-internal", "true"),
                    ("x-client-controlled", "present"),
                ),
            )
        )

        self.assertEqual(response.status, 200)
        self.assertEqual(
            app.records[0].untrusted_header_names,
            ("x-client-controlled",),
        )

    def test_spoofed_subject_header_cannot_replace_server_side_identity(self):
        app = self.app(LiveTrack.SIGNED_STATE_ONLY)

        response = app.handle(
            self.request(
                self.signed_token,
                extra_headers=(("x-kil-verified-subject", "spiffe://evil"),),
            )
        )

        self.assertEqual(response.status, 200)

    def test_log_record_redacts_credential_and_signed_state(self):
        app = self.app(LiveTrack.SIGNED_STATE_ONLY)

        app.handle(self.request(self.signed_token))

        encoded = canonical_json(app.records[0])
        self.assertNotIn(AUTHORIZATION, encoded)
        self.assertNotIn(self.signed_token, encoded)
        self.assertNotIn("eyJ", encoded)
        self.assertNotIn("v3b-lab-credential", encoded)

    def test_baseline_credential_comparison_is_server_side(self):
        app = self.app(LiveTrack.CREDENTIAL_POLICY_BASELINE)

        permitted = app.handle(self.request(None))
        denied = app.handle(
            self.request(None, authorization="Bearer attacker-credential")
        )

        self.assertEqual(permitted.status, 200)
        self.assertEqual(denied.status, 403)

    def test_duplicate_trusted_header_fails_closed(self):
        app = self.app(LiveTrack.SIGNED_STATE_ONLY)
        request = self.request(
            self.signed_token,
            extra_headers=(("X-Request-ID", "ambiguous"),),
        )

        response = app.handle(request)

        self.assertEqual(response.status, 503)
        self.assertEqual(response.headers, {})
        self.assertEqual(response.body, b"unavailable\n")
        self.assertIsNone(app.records[0].decision_digest)

    def test_unknown_fixture_and_nonzero_body_fail_closed(self):
        app = self.app(LiveTrack.SIGNED_STATE_ONLY)
        unknown = HttpRequest(
            "POST",
            "/consequential/admin",
            (("x-request-id", "unknown"),),
            b"",
        )

        self.assertEqual(app.handle(unknown).status, 503)
        self.assertEqual(
            app.handle(self.request(self.signed_token, body=b"x")).status,
            503,
        )

    def test_host_and_content_length_are_ignored_transport_metadata(self):
        app = self.app(LiveTrack.SIGNED_STATE_ONLY)

        response = app.handle(
            self.request(
                self.signed_token,
                extra_headers=(("host", "gateway"), ("content-length", "0")),
            )
        )

        self.assertEqual(response.status, 200)
        self.assertEqual(app.records[0].untrusted_header_names, ())

    def test_health_check_does_not_invoke_authorization_or_create_a_record(self):
        app = self.app(LiveTrack.SIGNED_PLUS_LOCAL_REDUCE)

        response = app.handle(HttpRequest("GET", "/healthz", (), b""))

        self.assertEqual(response, HttpResponse(200, {}, b"ok\n"))
        self.assertEqual(app.records, ())

    def test_health_check_with_body_transport_fails_closed_without_a_record(self):
        app = self.app(LiveTrack.SIGNED_PLUS_LOCAL_REDUCE)

        response = app.handle(
            HttpRequest("GET", "/healthz", (("content-length", "1"),), b"")
        )

        self.assertEqual(response, HttpResponse(503, {}, b"unavailable\n"))
        self.assertEqual(app.records, ())

    def test_total_header_limit_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "header limit"):
            HttpRequest(
                "POST",
                "/consequential/admin",
                (("x-kil-q-state", "x" * 16_384),),
                b"",
            )

    def test_jsonl_recorder_writes_the_redacted_canonical_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decisions.jsonl"
            app = self.app(
                LiveTrack.SIGNED_STATE_ONLY,
                recorder=JsonlDecisionRecorder(path),
            )

            app.handle(self.request(self.signed_token))

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["http_status"], 200)
            self.assertNotIn(AUTHORIZATION, lines[0])
            self.assertNotIn(self.signed_token, lines[0])

    def test_recorder_failure_preserves_an_already_computed_decision_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            recorder = JsonlDecisionRecorder(Path(directory) / "decisions.jsonl")
            app = self.app(LiveTrack.SIGNED_STATE_ONLY, recorder=recorder)

        response = app.handle(self.request(self.signed_token))

        self.assertEqual(response.status, 503)
        self.assertEqual(set(response.headers), {"x-kil-decision-digest"})
        self.assertEqual(
            response.headers["x-kil-decision-digest"],
            app.records[0].decision_digest,
        )
        self.assertEqual(response.body, b"unavailable\n")

    def config_mapping(self, records_path: Path) -> dict[str, object]:
        raw_public_key = self.public_key.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        encoded_key = urlsafe_b64encode(raw_public_key).rstrip(b"=").decode()
        return {
            "schema_version": "kil.v3b-authz-http.v1",
            "track": "signed_state_only",
            "bind_host": "0.0.0.0",
            "bind_port": 8080,
            "records_path": str(records_path),
            "public_keys": [
                {"key_id": key_id(self.public_key), "raw_base64url": encoded_key}
            ],
            "revoked_state_ids": [],
            "fixtures": [
                {
                    "request_id": REQUEST_ID,
                    "method": "POST",
                    "path": "/consequential/admin",
                    "identity": SUBJECT,
                    "authority_class": "admin_action",
                    "action_class": "consequential_admin",
                    "expected_authorization_sha256": AUTHORIZATION_DIGEST,
                    "policy_allows_action": True,
                    "local_evidence": {
                        "divergence": "0.9",
                        "coupled_loss": "0",
                        "fresh": True,
                    },
                    "reduction_profile": {
                        "divergence_threshold": "0.25",
                        "loss_rate": "25",
                        "exponent": 3,
                    },
                }
            ],
        }

    def write_read_only_config(
        self,
        root: Path,
        mapping: dict[str, object],
    ) -> Path:
        path = root / "authz.json"
        path.write_text(json.dumps(mapping), encoding="utf-8")
        path.chmod(0o444)
        return path

    def test_read_only_config_fixes_track_bind_and_public_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mapping = self.config_mapping(root / "decisions.jsonl")
            path = self.write_read_only_config(root, mapping)

            runtime = load_service_config(
                path,
                clock_s=lambda: 105,
                monotonic_ns=lambda: 123456,
            )

            self.assertEqual(runtime.app.adapter.track, LiveTrack.SIGNED_STATE_ONLY)
            self.assertEqual(runtime.bind_host, "0.0.0.0")
            self.assertEqual(runtime.bind_port, 8080)
            response = runtime.app.handle(self.request(self.signed_token))
            self.assertEqual(response.status, 200)

    def test_config_rejects_unknown_or_private_key_material(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mapping = self.config_mapping(root / "decisions.jsonl")
            mapping["private_key"] = "must-never-load"
            path = self.write_read_only_config(root, mapping)

            with self.assertRaisesRegex(ConfigError, "unknown"):
                load_service_config(path)

    def test_config_must_be_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "authz.json"
            path.write_text(
                json.dumps(self.config_mapping(root / "decisions.jsonl")),
                encoding="utf-8",
            )
            path.chmod(0o644)

            with self.assertRaisesRegex(ConfigError, "read-only"):
                load_service_config(path)

    def test_threading_http_server_constructs_without_changing_the_app(self):
        app = self.app(LiveTrack.SIGNED_STATE_ONLY)
        server = create_http_server(
            app,
            "127.0.0.1",
            0,
            bind_and_activate=False,
        )
        try:
            self.assertIs(server.app, app)
            self.assertEqual(server.server_address, ("127.0.0.1", 0))
            self.assertTrue(server.daemon_threads)
            self.assertEqual(app.records, ())
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
