"""Deterministic Envoy bootstrap rendering for the V3B laboratory boundary."""

import re

from .canonical import canonical_json
from .live_authz import LiveTrack


_CONTAINER_PORT = 8080
_TIMEOUT = "0.250s"
_AUTHZ_CLUSTER = "kil-v3b-authz"
_TARGET_CLUSTER = "kil-v3b-target"
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

# Envoy raw-HTTP ext_authz extracts configured response headers for a permit
# or policy denial. It converts an authz HTTP 5xx to CheckStatus::Error before
# that extraction, so the dynamic-metadata access-log formatter emits "-".
DECISION_DIGEST_EXACT_AUTHZ_HTTP_STATUSES = (200, 403)
DECISION_DIGEST_AUTHZ_ERROR_VALUE = "-"


def _validated_host(name: str, value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 253
        or any(
            _DNS_LABEL.fullmatch(label) is None or len(label) > 63
            for label in value.split(".")
        )
    ):
        raise ValueError(f"{name} must be a lowercase DNS host name")
    return value


def _exact_header_matcher(name: str) -> dict[str, object]:
    return {"patterns": [{"exact": name}]}


def _cluster(name: str, host: str) -> dict[str, object]:
    return {
        "name": name,
        "type": "STRICT_DNS",
        "connect_timeout": _TIMEOUT,
        "lb_policy": "ROUND_ROBIN",
        "load_assignment": {
            "cluster_name": name,
            "endpoints": [
                {
                    "lb_endpoints": [
                        {
                            "endpoint": {
                                "address": {
                                    "socket_address": {
                                        "address": host,
                                        "port_value": _CONTAINER_PORT,
                                    }
                                }
                            }
                        }
                    ]
                }
            ],
        },
    }


def render_envoy_config(
    track: LiveTrack,
    authz_host: str,
    target_host: str,
) -> dict[str, object]:
    """Return a fresh, closed Envoy bootstrap for one fixed live track."""
    if not isinstance(track, LiveTrack):
        raise ValueError("track must be a LiveTrack")
    authz = _validated_host("authz_host", authz_host)
    target = _validated_host("target_host", target_host)
    digest_matcher = _exact_header_matcher("x-kil-decision-digest")

    ext_authz = {
        "@type": (
            "type.googleapis.com/"
            "envoy.extensions.filters.http.ext_authz.v3.ExtAuthz"
        ),
        "http_service": {
            "server_uri": {
                "uri": f"http://{authz}:{_CONTAINER_PORT}",
                "cluster": _AUTHZ_CLUSTER,
                "timeout": _TIMEOUT,
            },
            "authorization_response": {
                "allowed_upstream_headers": digest_matcher,
                "allowed_client_headers": _exact_header_matcher(
                    "x-kil-decision-digest"
                ),
                "allowed_client_headers_on_success": _exact_header_matcher(
                    "x-kil-decision-digest"
                ),
                "dynamic_metadata_from_headers": _exact_header_matcher(
                    "x-kil-decision-digest"
                ),
            },
        },
        "failure_mode_allow": False,
        "status_on_error": {"code": "ServiceUnavailable"},
        "validate_mutations": True,
        "allowed_headers": {
            "patterns": [
                {"exact": "x-request-id"},
                {"exact": "x-kil-q-state"},
            ]
        },
    }
    access_record = {
        "run_id": "%REQ(X-KIL-RUN-ID)%",
        "request_id": "%REQ(X-REQUEST-ID)%",
        "track": track.value,
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
    connection_manager = {
        "@type": (
            "type.googleapis.com/"
            "envoy.extensions.filters.network.http_connection_manager.v3."
            "HttpConnectionManager"
        ),
        "stat_prefix": "kil_v3b_ingress",
        "route_config": {
            "name": "kil-v3b-target-routes",
            "virtual_hosts": [
                {
                    "name": "kil-v3b-target",
                    "domains": ["*"],
                    "routes": [
                        {
                            "match": {"prefix": "/"},
                            "route": {"cluster": _TARGET_CLUSTER},
                        }
                    ],
                    "request_headers_to_remove": [
                        "authorization",
                        "x-kil-q-state",
                    ],
                    "request_headers_to_add": [
                        {
                            "header": {
                                "key": "x-kil-track",
                                "value": track.value,
                            },
                            "append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
                        }
                    ],
                }
            ],
        },
        "access_log": [
            {
                "name": "envoy.access_loggers.stdout",
                "typed_config": {
                    "@type": (
                        "type.googleapis.com/"
                        "envoy.extensions.access_loggers.stream.v3."
                        "StdoutAccessLog"
                    ),
                    "log_format": {
                        "text_format_source": {
                            "inline_string": canonical_json(access_record) + "\n"
                        }
                    },
                },
            }
        ],
        "http_filters": [
            {
                "name": "envoy.filters.http.ext_authz",
                "typed_config": ext_authz,
            },
            {
                "name": "envoy.filters.http.router",
                "typed_config": {
                    "@type": (
                        "type.googleapis.com/"
                        "envoy.extensions.filters.http.router.v3.Router"
                    )
                },
            },
        ],
    }
    return {
        "static_resources": {
            "listeners": [
                {
                    "name": "kil-v3b-gateway",
                    "address": {
                        "socket_address": {
                            "address": "0.0.0.0",
                            "port_value": _CONTAINER_PORT,
                        }
                    },
                    "filter_chains": [
                        {
                            "filters": [
                                {
                                    "name": (
                                        "envoy.filters.network."
                                        "http_connection_manager"
                                    ),
                                    "typed_config": connection_manager,
                                }
                            ]
                        }
                    ],
                }
            ],
            "clusters": [
                _cluster(_AUTHZ_CLUSTER, authz),
                _cluster(_TARGET_CLUSTER, target),
            ],
        }
    }


def render_envoy_json(
    track: LiveTrack,
    authz_host: str,
    target_host: str,
) -> str:
    """Return the canonical JSON serialization of one Envoy bootstrap."""
    return canonical_json(render_envoy_config(track, authz_host, target_host))
