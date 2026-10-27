"""Live PostgreSQL operations-console session and tenant-isolation tests."""
import os
import secrets
import pytest

from devshield.ops_store import OpsStore

DSN = os.environ.get("DEVSHIELD_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="isolated test PostgreSQL required")


@pytest.fixture()
def store():
    obj = OpsStore(DSN)
    obj.migrate()
    return obj


def test_real_login_audit_logout_and_tenant_isolation(store):
    tenant = "ops-" + secrets.token_hex(8)
    other = "ops-" + secrets.token_hex(8)
    assert store.provision_user(
        tenant=tenant, user="alice", password="test strong password", role="org_admin")
    assert store.provision_user(
        tenant=other, user="alice", password="different password", role="auditor")
    assert not store.provision_user(
        tenant=tenant, user="alice", password="attempt overwrite", role="auditor")
    assert store.login(tenant=tenant, user="alice", password="incorrect") is None
    token, principal = store.login(
        tenant=tenant, user="alice", password="test strong password")
    assert principal.tenant_id == tenant and principal.role == "org_admin"
    assert store.resolve(token) == principal
    assert store.audit(tenant)[0]["action"] == "login"
    assert store.audit(other) == []
    assert store.metrics(tenant)["requests_24h"] == 0
    store.logout(token, principal)
    assert store.resolve(token) is None
    assert store.audit(tenant)[0]["action"] == "logout"
    assert store.audit(other) == []


def test_active_user_rechecked_each_request(store):
    tenant = "ops-active-" + secrets.token_hex(8)
    assert store.provision_user(
        tenant=tenant, user="auditor", password="test strong password", role="auditor")
    token, principal = store.login(
        tenant=tenant, user="auditor", password="test strong password")
    assert principal.role == "auditor"
    with store._connection() as conn:
        conn.execute("""
          UPDATE ds_console_user SET active=FALSE
          WHERE tenant_id=%s AND user_id='auditor'
        """, (tenant,))
    assert store.resolve(token) is None


def test_role_changes_affect_active_session(store):
    tenant = "ops-role-" + secrets.token_hex(8)
    assert store.provision_user(
        tenant=tenant, user="bob", password="test strong password", role="analyst")
    token, old = store.login(tenant=tenant, user="bob", password="test strong password")
    assert old.role == "analyst"
    with store._connection() as conn:
        conn.execute("""
          UPDATE ds_console_user SET role='auditor'
          WHERE tenant_id=%s AND user_id='bob'
        """, (tenant,))
    assert store.resolve(token).role == "auditor"
