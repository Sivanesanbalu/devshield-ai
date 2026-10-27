"""Offline tests: validation and failure handling without a PostgreSQL server."""
import pytest

from devshield.postgres_store import PolicyUnavailable, PostgresStore


def _not_connected(_dsn):
    raise ConnectionError("simulated database outage with hidden credentials")


def test_connect_failure_does_not_expose_connection_information():
    store = PostgresStore(
        "postgresql://secret_user:supersecret@localhost/test",
        connect=_not_connected,
    )
    with pytest.raises(PolicyUnavailable, match="database security policy unavailable") as exc:
        store.health()
    assert "supersecret" not in str(exc.value)


@pytest.mark.parametrize("limit,window", [
    (0, 60), (-1, 60), (7, 0), (True, 60), (7, True), ("7", 60)
])
def test_quota_settings_rejected_before_connect(limit, window):
    store = PostgresStore("not-used", connect=_not_connected)
    with pytest.raises(ValueError):
        store.check_quota("tenant", "user", limit=limit, window_seconds=window)


@pytest.mark.parametrize("tenant,principal", [
    ("", "user"), ("tenant", ""), (" ", "user"),
])
def test_missing_identity_rejected(tenant, principal):
    store = PostgresStore("not-used", connect=_not_connected)
    with pytest.raises(ValueError):
        store.check_quota(tenant, principal, limit=7, window_seconds=60)


def test_quota_fail_closed_on_connection_failure():
    store = PostgresStore("not-used", connect=_not_connected)
    with pytest.raises(PolicyUnavailable):
        store.check_quota("tenant", "user", limit=7, window_seconds=60)


@pytest.mark.parametrize("ttl,capacity", [(0, 1), (100, 0), (True, 1), (30, False)])
def test_session_settings_rejected(ttl, capacity):
    store = PostgresStore("not-used", connect=_not_connected)
    with pytest.raises(ValueError):
        store.create_session(
            "token", tenant="tenant", role="operator",
            ttl_seconds=ttl, capacity=capacity,
        )


def test_session_and_migration_fail_closed():
    store = PostgresStore("not-used", connect=_not_connected)
    with pytest.raises(PolicyUnavailable):
        store.migrate()
    with pytest.raises(PolicyUnavailable):
        store.create_session("token", tenant="tenant", role="operator")
    with pytest.raises(PolicyUnavailable):
        store.get_session("token", tenant="tenant")
    with pytest.raises(PolicyUnavailable):
        store.revoke_session("token")
