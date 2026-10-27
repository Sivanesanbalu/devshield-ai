"""Loopback-only protected API demonstration using transactional DevShield policy.

This is a testable security integration, NOT a production HTTP application.
No TLS termination, distributed tracing, SSO or management UI is included.
"""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from devshield.postgres_store import PolicyUnavailable, PostgresStore


def make_handler(store, *, token: str, tenant: str = "demo",
                 limit: int = 7, window_seconds: int = 60):
    if not isinstance(token, str) or len(token) < 32:
        raise ValueError("a strong 32-character API token is required")
    if not tenant or type(limit) is not int or limit < 1:
        raise ValueError("trusted tenant and positive quota required")
    if type(window_seconds) is not int or window_seconds < 1:
        raise ValueError("positive window_seconds required")

    # Do not allow HTTP headers or request body to choose the effective tenant.
    subject = "demo-api-client"

    class Handler(BaseHTTPRequestHandler):
        server_version = "DevShield"
        sys_version = ""

        def log_message(self, format, *args):
            # Demo omits request-body/header logging. Production needs redacted audit logs.
            pass

        def respond(self, code: int, payload: dict, *, retry_after: int = 0):
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if retry_after > 0:
                self.send_header("Retry-After", str(retry_after))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path != "/healthz":
                return self.respond(404, {"error": "not found"})
            try:
                healthy = store.health()
            except (PolicyUnavailable, Exception):
                healthy = False
            return self.respond(
                200 if healthy else 503,
                {"status": "ok" if healthy else "unavailable"},
            )

        def do_POST(self):
            if self.path != "/v1/quote":
                return self.respond(404, {"error": "not found"})
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(
                supplied.encode("utf-8"), ("Bearer " + token).encode("utf-8")
            ):
                return self.respond(401, {"error": "unauthorized"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self.respond(400, {"error": "invalid request"})
            if not (0 < length <= 8192):
                return self.respond(413, {"error": "invalid payload size"})
            try:
                payload = json.loads(self.rfile.read(length))
                tier = payload["tier"]
                units = payload["units"]
                if tier not in ("basic", "plus") or type(units) is not int:
                    raise ValueError("invalid quote parameters")
                if not (1 <= units <= 1000):
                    raise ValueError("invalid quantity")
            except (ValueError, TypeError, KeyError, IndexError, AttributeError):
                return self.respond(400, {"error": "invalid quote request"})
            try:
                decision = store.check_quota(
                    tenant, subject, limit=limit, window_seconds=window_seconds
                )
            except Exception:
                # Unavailable DB or audit failure must NEVER yield a quote.
                return self.respond(503, {"error": "security policy unavailable"})
            if not decision.allowed:
                if decision.reason == "restricted":
                    return self.respond(
                        403, {"error": "client temporarily restricted"},
                        retry_after=max(1, decision.retry_after),
                    )
                return self.respond(
                    429, {"error": "rate limit exceeded"},
                    retry_after=max(1, decision.retry_after),
                )
            # Deliberately illustrative price engine, not proprietary customer logic.
            return self.respond(
                200, {"currency": "DEMO", "total": (100 if tier == "basic" else 200) * units}
            )

    return Handler


def main(argv=None):
    parser = argparse.ArgumentParser(description="Loopback-only guarded quote demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--init-schema", action="store_true")
    args = parser.parse_args(argv)
    if not ipaddress.ip_address(args.host).is_loopback:
        parser.error("only loopback addresses are permitted for this demonstration")
    dsn = os.environ.get("DEVSHIELD_POSTGRES_DSN")
    token = os.environ.get("DEVSHIELD_API_TOKEN", "")
    if not dsn:
        parser.error("DEVSHIELD_POSTGRES_DSN is required")
    store = PostgresStore(dsn)
    if args.init_schema:
        store.migrate()
    handler = make_handler(store, token=token)
    with ThreadingHTTPServer((args.host, args.port), handler) as server:
        print(f"DevShield demo listening on loopback {args.host}:{server.server_port}")
        server.serve_forever()


if __name__ == "__main__":
    main()
