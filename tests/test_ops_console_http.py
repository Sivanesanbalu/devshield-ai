"""Security regression tests for the local authenticated browser console."""
from contextlib import contextmanager
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener
import json

from devshield.ops_console import make_handler
from devshield.security_policy import Principal


class FakeStore:
    def __init__(self, role="operator"):
        self.role = role
        self.session = None
        self.fail = False
        self.calls = []

    def health(self):
        if self.fail:
            raise RuntimeError("secret database details")
        return True

    def login(self, *, tenant, user, password):
        if self.fail:
            raise RuntimeError("secret database details")
        if (tenant, user, password) != ("tenant-A", "alice", "correct password"):
            return None
        self.session = "session-" + "x" * 48
        return self.session, Principal("tenant-A", "alice", self.role)

    def resolve(self, token):
        if self.fail:
            raise RuntimeError("secret database details")
        return Principal("tenant-A", "alice", self.role) if token == self.session else None

    def metrics(self, tenant):
        self.calls.append(("metrics", tenant))
        return {"requests_24h": 3, "allowed_24h": 2, "throttled_24h": 1}

    def audit(self, tenant):
        self.calls.append(("audit", tenant))
        return [{"actor": "alice", "action": "login", "timestamp": 1}]

    def logout(self, token, principal):
        self.calls.append(("logout", principal.tenant_id))
        self.session = None


@contextmanager
def serve(store):
    server = ThreadingHTTPServer(("127.0.0.1", 0),
                                 make_handler(store, csrf_secret=b"A" * 32))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port), build_opener(
            HTTPCookieProcessor(CookieJar()))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def call(base, opener, route, payload=None, *, origin=True, extra=None, post=False):
    headers = dict(extra or {})
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode()
    if post or payload is not None:
        body = body if body is not None else b""
        if origin:
            headers["Origin"] = base
    req = Request(base + route, data=body, headers=headers,
                  method="POST" if body is not None else "GET")
    try:
        response = opener.open(req, timeout=3)
    except HTTPError as error:
        response = error
    with response:
        data = response.read()
        parsed = json.loads(data) if data.startswith((b"{", b"[")) else data
        return response.status, parsed, response.headers


def authenticate(base, opener):
    return call(base, opener, "/api/login", {
        "tenant": "tenant-A", "user": "alice", "password": "correct password"
    })


def test_cookie_and_authenticated_identity():
    with serve(FakeStore()) as (base, opener):
        status, result, headers = authenticate(base, opener)
        assert status == 200
        assert "HttpOnly" in headers["Set-Cookie"]
        assert "SameSite=Strict" in headers["Set-Cookie"]
        status, me, _ = call(base, opener, "/api/me")
        assert status == 200 and me["role"] == "operator"
        assert me["tenant"] == "tenant-A"
        assert len(me["csrf"]) == 64


def test_anonymous_and_bad_password_denied():
    with serve(FakeStore()) as (base, opener):
        assert call(base, opener, "/api/audit")[0] == 401
        assert call(base, opener, "/api/login", {
            "tenant": "tenant-A", "user": "alice", "password": "wrong"
        })[0] == 401


def test_tenant_scope_cannot_be_overridden_by_query_string():
    store = FakeStore()
    with serve(store) as (base, opener):
        authenticate(base, opener)
        status, result, _ = call(base, opener, "/api/metrics?tenant=tenant-B")
        assert status == 200 and result["allowed_24h"] == 2
        assert store.calls == [("metrics", "tenant-A")]


def test_auditor_permission_is_readonly_audit():
    store = FakeStore(role="auditor")
    with serve(store) as (base, opener):
        authenticate(base, opener)
        assert call(base, opener, "/api/metrics")[0] == 403
        assert call(base, opener, "/api/audit")[0] == 200


def test_cross_site_login_rejected():
    store = FakeStore()
    with serve(store) as (base, opener):
        status, _, _ = call(base, opener, "/api/login", {
            "tenant": "tenant-A", "user": "alice", "password": "correct password"
        }, origin=False)
        assert status == 403 and store.session is None


def test_logout_requires_csrf_and_revokes_session():
    store = FakeStore()
    with serve(store) as (base, opener):
        authenticate(base, opener)
        _, me, _ = call(base, opener, "/api/me")
        assert call(base, opener, "/api/logout", post=True)[0] == 403
        assert call(base, opener, "/api/logout", post=True,
                    extra={"X-CSRF-Token": "invalid"})[0] == 403
        assert call(base, opener, "/api/logout", post=True,
                    extra={"X-CSRF-Token": me["csrf"]})[0] == 200
        assert call(base, opener, "/api/me")[0] == 401
        assert store.calls == [("logout", "tenant-A")]


def test_database_unavailable_fails_closed():
    store = FakeStore()
    with serve(store) as (base, opener):
        authenticate(base, opener)
        store.fail = True
        assert call(base, opener, "/api/metrics")[0:2] == (
            503, {"error": "security policy unavailable"})
        assert call(base, opener, "/healthz")[0] == 503


def test_assets_and_restrictive_csp_are_served():
    with serve(FakeStore()) as (base, opener):
        status, html, headers = call(base, opener, "/")
        assert status == 200 and b"Security operations" in html
        assert "script-src 'self'" in headers["Content-Security-Policy"]
        assert call(base, opener, "/assets/console.js")[0] == 200
        assert call(base, opener, "/assets/console.css")[0] == 200
