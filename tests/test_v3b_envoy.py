from importlib import import_module
import json
import unittest

from kil.canonical import canonical_json
from kil.live_authz import LiveTrack


TRACK = LiveTrack.SIGNED_PLUS_LOCAL_REDUCE
AUTHZ_HOST = "authz.kil-v3-local-reduce.svc.cluster.local"
TARGET_HOST = "target.kil-v3-local-reduce.svc.cluster.local"


class V3BEnvoyConfigTest(unittest.TestCase):
    def api(self):
        try:
            module = import_module("kil.v3b_envoy")
        except ModuleNotFoundError:
            self.fail("kil.v3b_envoy has not been implemented")
        for name in ("render_envoy_config", "render_envoy_json"):
            if not hasattr(module, name):
                self.fail(f"kil.v3b_envoy.{name} has not been implemented")
        return module.render_envoy_config, module.render_envoy_json

    def config(self) -> dict[str, object]:
        render_envoy_config, _ = self.api()
        return render_envoy_config(TRACK, AUTHZ_HOST, TARGET_HOST)

    def connection_manager(self) -> dict[str, object]:
        listener = self.config()["static_resources"]["listeners"][0]
        return listener["filter_chains"][0]["filters"][0]["typed_config"]

    def ext_authz(self) -> dict[str, object]:
        filters = self.connection_manager()["http_filters"]
        return next(
            item["typed_config"]
            for item in filters
            if item["name"] == "envoy.filters.http.ext_authz"
        )

    def virtual_host(self) -> dict[str, object]:
        return self.connection_manager()["route_config"]["virtual_hosts"][0]

    def test_renders_one_8080_listener_with_a_closed_static_shape(self) -> None:
        config = self.config()

        self.assertEqual(set(config), {"static_resources"})
        resources = config["static_resources"]
        self.assertEqual(set(resources), {"listeners", "clusters"})
        self.assertEqual(len(resources["listeners"]), 1)
        listener = resources["listeners"][0]
        self.assertEqual(
            set(listener), {"name", "address", "filter_chains"}
        )
        self.assertEqual(
            listener["address"],
            {
                "socket_address": {
                    "address": "0.0.0.0",
                    "port_value": 8080,
                }
            },
        )
        self.assertEqual(len(listener["filter_chains"]), 1)
        self.assertEqual(
            set(listener["filter_chains"][0]), {"filters"}
        )

    def test_ext_authz_immediately_precedes_the_router(self) -> None:
        filters = self.connection_manager()["http_filters"]

        self.assertEqual(
            [item["name"] for item in filters],
            [
                "envoy.filters.http.ext_authz",
                "envoy.filters.http.router",
            ],
        )

    def test_raw_http_authz_is_exactly_timed_and_fail_closed(self) -> None:
        authz = self.ext_authz()

        self.assertEqual(
            set(authz),
            {
                "@type",
                "http_service",
                "failure_mode_allow",
                "status_on_error",
                "validate_mutations",
                "allowed_headers",
            },
        )
        self.assertNotIn("grpc_service", authz)
        self.assertFalse(authz["failure_mode_allow"])
        self.assertEqual(
            authz["status_on_error"], {"code": "ServiceUnavailable"}
        )
        self.assertTrue(authz["validate_mutations"])
        server_uri = authz["http_service"]["server_uri"]
        self.assertEqual(
            server_uri,
            {
                "uri": f"http://{AUTHZ_HOST}:8080",
                "cluster": "kil-v3b-authz",
                "timeout": "0.250s",
            },
        )

    def test_authz_receives_only_the_two_explicit_allowed_headers(self) -> None:
        authz = self.ext_authz()
        http_service = authz["http_service"]

        self.assertEqual(
            set(http_service),
            {"server_uri", "authorization_response"},
        )
        self.assertEqual(
            authz["allowed_headers"],
            {
                "patterns": [
                    {"exact": "x-request-id"},
                    {"exact": "x-kil-q-state"},
                ]
            },
        )
        explicit = {
            pattern["exact"]
            for pattern in authz["allowed_headers"]["patterns"]
        }
        self.assertEqual(explicit, {"x-request-id", "x-kil-q-state"})
        for prohibited in (
            "x-kil-mode",
            "x-kil-local-evidence",
            "x-kil-verified-subject",
            "x-kil-subject",
            "x-kil-identity",
            "x-kil-issuer",
        ):
            self.assertNotIn(prohibited, explicit)

    def test_only_the_decision_digest_can_flow_from_authz(self) -> None:
        response = self.ext_authz()["http_service"]["authorization_response"]
        digest_matcher = {
            "patterns": [{"exact": "x-kil-decision-digest"}]
        }

        self.assertEqual(
            set(response),
            {
                "allowed_upstream_headers",
                "allowed_client_headers",
                "allowed_client_headers_on_success",
                "dynamic_metadata_from_headers",
            },
        )
        for name in response:
            self.assertEqual(response[name], digest_matcher)
        self.assertNotIn("allowed_upstream_headers_to_append", response)

    def test_digest_evidence_contract_distinguishes_authz_5xx(self) -> None:
        module = import_module("kil.v3b_envoy")

        self.assertTrue(
            hasattr(module, "DECISION_DIGEST_EXACT_AUTHZ_HTTP_STATUSES"),
            "the Envoy evidence contract must name digest-bearing statuses",
        )
        self.assertTrue(
            hasattr(module, "DECISION_DIGEST_AUTHZ_ERROR_VALUE"),
            "the Envoy evidence contract must name the 5xx missing value",
        )
        self.assertEqual(
            module.DECISION_DIGEST_EXACT_AUTHZ_HTTP_STATUSES,
            (200, 403),
        )
        self.assertEqual(module.DECISION_DIGEST_AUTHZ_ERROR_VALUE, "-")

        # Envoy raw-HTTP ext_authz extracts these matchers for permits and
        # policy denials. A raw authz 5xx becomes CheckStatus::Error before
        # header extraction, leaving this dynamic-metadata formatter empty.
        response = self.ext_authz()["http_service"]["authorization_response"]
        self.assertIn("allowed_client_headers_on_success", response)
        self.assertIn("allowed_client_headers", response)
        self.assertIn("dynamic_metadata_from_headers", response)
        access_line = self.connection_manager()["access_log"][0][
            "typed_config"
        ]["log_format"]["text_format_source"]["inline_string"]
        access_fields = json.loads(access_line)
        self.assertEqual(
            access_fields["decision_digest"],
            "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:"
            "x-kil-decision-digest)%",
        )

    def test_route_removes_secrets_and_overwrites_the_fixed_track(self) -> None:
        virtual_host = self.virtual_host()

        self.assertEqual(
            set(virtual_host),
            {
                "name",
                "domains",
                "routes",
                "request_headers_to_remove",
                "request_headers_to_add",
            },
        )
        self.assertEqual(
            virtual_host["request_headers_to_remove"],
            ["authorization", "x-kil-q-state"],
        )
        self.assertNotIn(
            "x-request-id", virtual_host["request_headers_to_remove"]
        )
        self.assertNotIn(
            "x-kil-decision-digest",
            virtual_host["request_headers_to_remove"],
        )
        self.assertEqual(
            virtual_host["request_headers_to_add"],
            [
                {
                    "header": {
                        "key": "x-kil-track",
                        "value": TRACK.value,
                    },
                    "append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
                }
            ],
        )

    def test_routes_and_clusters_are_fixed_process_configuration(self) -> None:
        config = self.config()
        route = self.virtual_host()["routes"][0]
        clusters = config["static_resources"]["clusters"]

        self.assertEqual(
            route,
            {
                "match": {"prefix": "/"},
                "route": {"cluster": "kil-v3b-target"},
            },
        )
        self.assertEqual(
            [cluster["name"] for cluster in clusters],
            ["kil-v3b-authz", "kil-v3b-target"],
        )
        self.assertEqual(
            [
                cluster["load_assignment"]["endpoints"][0]
                ["lb_endpoints"][0]["endpoint"]["address"]
                ["socket_address"]
                for cluster in clusters
            ],
            [
                {"address": AUTHZ_HOST, "port_value": 8080},
                {"address": TARGET_HOST, "port_value": 8080},
            ],
        )
        for cluster in clusters:
            self.assertEqual(
                set(cluster),
                {
                    "name",
                    "type",
                    "connect_timeout",
                    "lb_policy",
                    "load_assignment",
                },
            )
            self.assertEqual(cluster["type"], "STRICT_DNS")
            self.assertEqual(cluster["connect_timeout"], "0.250s")
            self.assertEqual(cluster["lb_policy"], "ROUND_ROBIN")
        encoded = canonical_json(config)
        self.assertNotIn("cluster_header", encoded)
        self.assertNotIn("weighted_clusters", encoded)

    def test_retries_and_route_cache_clearing_are_absent(self) -> None:
        encoded = canonical_json(self.config())

        self.assertNotIn("retry_policy", encoded)
        self.assertNotIn("clear_route_cache", encoded)

    def test_stdout_access_log_has_the_closed_join_schema(self) -> None:
        connection_manager = self.connection_manager()

        self.assertEqual(len(connection_manager["access_log"]), 1)
        access_log = connection_manager["access_log"][0]
        self.assertEqual(
            access_log["name"], "envoy.access_loggers.stdout"
        )
        self.assertEqual(
            set(access_log), {"name", "typed_config"}
        )
        self.assertEqual(
            set(access_log["typed_config"]), {"@type", "log_format"}
        )
        self.assertEqual(
            access_log["typed_config"]["@type"],
            "type.googleapis.com/"
            "envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
        )
        expected_record = {
            "run_id": "%REQ(X-KIL-RUN-ID)%",
            "request_id": "%REQ(X-REQUEST-ID)%",
            "track": TRACK.value,
            "response_code": "%RESPONSE_CODE%",
            "upstream_host": "%UPSTREAM_HOST%",
            "upstream_service_time": (
                "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%"
            ),
            "decision_digest": (
                "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:"
                "x-kil-decision-digest)%"
            ),
        }
        expected_line = canonical_json(expected_record) + "\n"
        self.assertEqual(
            access_log["typed_config"]["log_format"],
            {"text_format_source": {"inline_string": expected_line}},
        )
        self.assertEqual(json.loads(expected_line), expected_record)
        self.assertNotIn(
            "json_format", access_log["typed_config"]["log_format"]
        )
        log_text = canonical_json(access_log)
        self.assertNotIn("AUTHORIZATION", log_text.upper())
        self.assertNotIn("Q-STATE", log_text.upper())

    def test_rejects_non_live_tracks_and_unsafe_hosts(self) -> None:
        render_envoy_config, render_envoy_json = self.api()
        invalid_tracks = (
            TRACK.value,
            "LiveTrack.SIGNED_PLUS_LOCAL_REDUCE",
            None,
            1,
        )
        for track in invalid_tracks:
            with self.subTest(track=track):
                with self.assertRaisesRegex(ValueError, "track"):
                    render_envoy_config(track, AUTHZ_HOST, TARGET_HOST)
                with self.assertRaisesRegex(ValueError, "track"):
                    render_envoy_json(track, AUTHZ_HOST, TARGET_HOST)

        invalid_hosts = (
            "",
            " authz",
            "authz ",
            "AUTHZ",
            "authz:8080",
            "authz/override",
            "authz\ncluster: attacker",
            "-authz",
            "authz-",
            "authz..svc",
            "auth_z",
            "a" * 64,
            "a" * 254,
            None,
            8080,
        )
        for host in invalid_hosts:
            for name, authz_host, target_host in (
                ("authz_host", host, TARGET_HOST),
                ("target_host", AUTHZ_HOST, host),
            ):
                with self.subTest(name=name, host=host):
                    with self.assertRaisesRegex(ValueError, name):
                        render_envoy_config(TRACK, authz_host, target_host)

    def test_rendering_is_canonical_deterministic_and_fresh(self) -> None:
        render_envoy_config, render_envoy_json = self.api()
        first = render_envoy_config(TRACK, AUTHZ_HOST, TARGET_HOST)
        second = render_envoy_config(TRACK, AUTHZ_HOST, TARGET_HOST)

        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        encoded = render_envoy_json(TRACK, AUTHZ_HOST, TARGET_HOST)
        self.assertEqual(encoded, canonical_json(first))
        self.assertEqual(json.loads(encoded), first)
        self.assertEqual(
            encoded,
            render_envoy_json(TRACK, AUTHZ_HOST, TARGET_HOST),
        )

        first["static_resources"]["listeners"].clear()
        self.assertEqual(
            render_envoy_config(TRACK, AUTHZ_HOST, TARGET_HOST), second
        )


if __name__ == "__main__":
    unittest.main()
