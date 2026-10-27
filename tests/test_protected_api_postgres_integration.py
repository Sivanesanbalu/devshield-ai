"""Live end-to-end HTTP quota test; disposable PostgreSQL database only."""
import json
import os
import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

psycopg = pytest.importorskip("psycopg")
from devshield.postgres_store import PostgresStore
from devshield.protected_api import make_handler

TOKEN = "ci-local-demo-key-" + "z" * 48


@contextmanager
def serving(store, *, limit=2):
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(store, token=TOKEN, tenant="ci-demo", limit=limit),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def post(base, *, token=TOKEN):
    req = Request(
        base + "/v1/quote",
        data=json.dumps({"tier": "basic", "units": 2}).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + token},
    )
    try:
        with urlopen(req, timeout=2) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


def test_live_http_quota_and_audit_persist_atomically():
    dsn = os.getenv("DEVSHIELD_TEST_PG_DSN")
    if not dsn:
        pytest.skip("DEVSHIELD_TEST_PG_DSN is needed")
    store = PostgresStore(dsn)
    store.migrate()
    with psycopg.connect(dsn) as conn:
        conn.execute("TRUNCATE ds_quota, ds_event, ds_session")
    with serving(store) as base:
        assert post(base)[0] == 200
        assert post(base)[0] == 200
        assert post(base)[0] == 429
        assert post(base, token="wrong")[0] == 401
    with psycopg.connect(dsn) as conn:
        events = dict(conn.execute(
            "SELECT event, count(*) FROM ds_event GROUP BY event"
        ).fetchall())
    assert events == {"allowed": 2, "rate_limit": 1}


def test_live_http_returns_503_when_database_unreachable():
    dsn = os.getenv("DEVSHIELD_TEST_PG_DSN")
    if not dsn:
        pytest.skip("DEVSHIELD_TEST_PG_DSN is needed")
    broken = PostgresStore(
        "postgresql://unreachable:unreachable@127.0.0.1:1/no?connect_timeout=1"
    )
    with serving(broken) as base:
        code, message = post(base)
    assert (code, message) == (503, {"error": "security policy unavailable"})
