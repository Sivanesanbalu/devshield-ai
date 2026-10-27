"""Loopback HTTP tests proving authorization, throttling and fail-closed paths."""
import json
import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from devshield.postgres_store import QuotaDecision
from devshield.protected_api import make_handler

TOKEN = "test-secret-api-token-" + "x" * 48


class FakeStore:
    def __init__(self, *, healthy=True, allowed=True, fail=False):
        self.healthy = healthy
        self.allowed = allowed
        self.fail = fail
        self.calls = []

    def health(self):
        if self.fail:
            raise OSError("secret connection message")
        return self.healthy

    def check_quota(self, tenant, principal, *, limit, window_seconds):
        self.calls.append((tenant, principal, limit, window_seconds))
        if self.fail:
            raise ConnectionError("secret database connection")
        return QuotaDecision(self.allowed, 23 if not self.allowed else 0,
                             "allowed" if self.allowed else "rate_limit")


@contextmanager
def api(store):
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(store, token=TOKEN, tenant="trusted-tenant"),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(base, *, route="/v1/quote", token=TOKEN, payload=None, method="POST"):
    body = json.dumps(
        {"tier": "basic", "units": 2} if payload is None else payload
    ).encode()
    req = Request(
        base + route,
        data=body if method == "POST" else None,
        method=method,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json"},
    )
    try:
        with urlopen(req, timeout=2) as response:
            return response.status, json.load(response), dict(response.headers)
    except HTTPError as error:
        return error.code, json.load(error), dict(error.headers)


def test_successful_quote_uses_trusted_tenant():
    store = FakeStore()
    with api(store) as base:
        status, payload, headers = request(
            base, payload={"tier": "plus", "units": 2, "tenant": "attacker"}
        )
    assert (status, payload) == (200, {"currency": "DEMO", "total": 400})
    assert store.calls == [("trusted-tenant", "demo-api-client", 7, 60)]
    assert headers["Cache-Control"] == "no-store"


def test_reject_invalid_token_without_touching_database():
    store = FakeStore()
    with api(store) as base:
        status, payload, _ = request(base, token="wrong")
    assert status == 401 and payload["error"] == "unauthorized"
    assert store.calls == []


def test_rate_limit_uses_http_429_and_retry_after():
    store = FakeStore(allowed=False)
    with api(store) as base:
        status, payload, headers = request(base)
    assert status == 429
    assert headers["Retry-After"] == "23"
    assert payload["error"] == "rate limit exceeded"


def test_database_failure_is_503_without_quote_or_exception_leak():
    store = FakeStore(fail=True)
    with api(store) as base:
        status, payload, _ = request(base)
        health_status, health, _ = request(base, route="/healthz", method="GET")
    assert (status, payload) == (503, {"error": "security policy unavailable"})
    assert (health_status, health) == (503, {"status": "unavailable"})


@pytest.mark.parametrize("payload", [
    {"tier": "basic", "units": True},
    {"tier": "basic", "units": -3},
    {"tier": "plus", "units": 1001},
    {"tier": "admin", "units": 2},
    [],
])
def test_invalid_request_is_not_processed(payload):
    store = FakeStore()
    with api(store) as base:
        status, _, _ = request(base, payload=payload)
    assert status == 400
    assert store.calls == []


def test_empty_secret_is_rejected_at_startup():
    with pytest.raises(ValueError):
        make_handler(FakeStore(), token="short")
