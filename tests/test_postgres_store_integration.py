"""Live PostgreSQL integration tests.

Run with DEVSHIELD_TEST_PG_DSN set to an isolated, disposable test database.
Never point this suite at a production database: the fixture truncates tables.
"""
import os
import uuid
from concurrent.futures import ProcessPoolExecutor

import pytest

psycopg = pytest.importorskip("psycopg")
from devshield.postgres_store import PolicyUnavailable, PostgresStore


def _quota_worker(args):
    dsn, tenant, idx = args
    store = PostgresStore(dsn)
    return store.check_quota(
        tenant, "shared-subject", limit=7, window_seconds=60,
        now=1_800_000_000,
    ).allowed


def _session_worker(args):
    dsn, tenant, idx = args
    return PostgresStore(dsn).create_session(
        f"session-{tenant}-{idx}", tenant=tenant, role="operator",
        capacity=4, ttl_seconds=300,
    )


@pytest.fixture
def store():
    dsn = os.getenv("DEVSHIELD_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Set DEVSHIELD_TEST_PG_DSN for live PostgreSQL tests")
    store = PostgresStore(dsn)
    store.migrate()
    # These tests require an isolated, disposable test database.
    with psycopg.connect(dsn) as conn:
        conn.execute("TRUNCATE ds_quota, ds_event, ds_session RESTART IDENTITY")
    return store


def test_migrations_are_repeatable(store):
    store.migrate()
    with psycopg.connect(store.dsn) as conn:
        versions = [
            row[0] for row in conn.execute(
                "SELECT version FROM ds_migrations ORDER BY version"
            ).fetchall()
        ]
    assert versions == [1, 2]


def test_tenant_isolation_and_audit(store):
    x = store.check_quota("tenant-A", "same-user", limit=1, window_seconds=60, now=1200)
    denied = store.check_quota("tenant-A", "same-user", limit=1, window_seconds=60, now=1200)
    y = store.check_quota("tenant-B", "same-user", limit=1, window_seconds=60, now=1200)
    assert x.allowed and y.allowed
    assert not denied.allowed and denied.retry_after == 60
    with psycopg.connect(store.dsn) as conn:
        count, = conn.execute("SELECT count(*) FROM ds_event").fetchone()
        assert count == 3


def test_25_separate_processes_cannot_exceed_seven_quota(store):
    tenant = "quota-" + uuid.uuid4().hex
    with ProcessPoolExecutor(max_workers=25) as pool:
        results = list(pool.map(
            _quota_worker, [(store.dsn, tenant, i) for i in range(25)]
        ))
    assert len(results) == 25
    assert sum(results) == 7


def test_16_separate_processes_respect_session_capacity_four(store):
    tenant = "sessions-" + uuid.uuid4().hex
    with ProcessPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(
            _session_worker, [(store.dsn, tenant, i) for i in range(16)]
        ))
    assert len(results) == 16
    assert sum(results) == 4


def test_session_is_tenant_scoped_and_revocable(store):
    assert store.create_session("secret-token", tenant="first", role="operator")
    assert store.get_session("secret-token", tenant="first") == "operator"
    assert store.get_session("secret-token", tenant="second") is None
    store.revoke_session("secret-token")
    assert store.get_session("secret-token", tenant="first") is None


def test_missing_database_fails_closed(store):
    # No actual service disruption; safely attempts an unavailable local port.
    dead = PostgresStore(
        "postgresql://wrong:wrong@127.0.0.1:1/nonexistent?connect_timeout=1"
    )
    with pytest.raises(PolicyUnavailable):
        dead.check_quota("tenant", "client", limit=3, window_seconds=60)
