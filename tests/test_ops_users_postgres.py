"""Disposable PostgreSQL tests for organization user lifecycle and session revocation."""
import os
import secrets
import pytest
from devshield.ops_store import OpsStore
from devshield.security_policy import Principal

DSN=os.environ.get("DEVSHIELD_TEST_PG_DSN")
pytestmark=pytest.mark.skipif(not DSN,reason="isolated PostgreSQL required")


@pytest.fixture
def store():
    db=OpsStore(DSN)
    db.migrate()
    return db


def test_admin_creates_tenant_scoped_users_and_disables_sessions(store):
    tenant="users-"+secrets.token_hex(8)
    other="users-"+secrets.token_hex(8)
    store.provision_user(tenant=tenant,user="alice",
                         password="strong admin password",role="org_admin")
    admin_token,principal=store.login(tenant=tenant,user="alice",
                                      password="strong admin password")
    assert principal.role=="org_admin"
    assert store.create_user(principal,user="bob",
                             password="strong bob password",role="operator")
    assert not store.create_user(principal,user="bob",
                                 password="another password",role="auditor")
    users=store.users(principal)
    assert {u["user"] for u in users}=={"alice","bob"}
    assert "password" not in str(users).lower()
    assert store.users(Principal(other,"other","org_admin"))==[]
    bob_token,bob=store.login(tenant=tenant,user="bob",
                              password="strong bob password")
    assert bob.role=="operator" and store.resolve(bob_token)==bob
    assert store.set_user_active(principal,user="bob",active=False)
    assert store.resolve(bob_token) is None
    assert store.login(tenant=tenant,user="bob",password="strong bob password") is None
    assert store.set_user_active(principal,user="bob",active=True)
    assert store.resolve(bob_token) is None
    assert store.login(tenant=tenant,user="bob",password="strong bob password")
    actions=[a["action"] for a in store.audit(tenant)]
    assert "user-created:bob" in actions and "user-disabled:bob" in actions
    assert "user-enabled:bob" in actions
    assert store.audit(other)==[]


def test_last_admin_self_disable_and_role_enforcement(store):
    tenant="users-"+secrets.token_hex(8)
    store.provision_user(tenant=tenant,user="alice",
                         password="strong admin password",role="org_admin")
    admin=Principal(tenant,"alice","org_admin")
    with pytest.raises(ValueError,match="own account"):
        store.set_user_active(admin,user="alice",active=False)
    # Invariant is validated even for a service principal; no active admins may be lost.
    with pytest.raises(ValueError,match="last active admin"):
        store.set_user_active(Principal(tenant,"maintenance","org_admin"),
                              user="alice",active=False)
    with pytest.raises(PermissionError):
        store.create_user(Principal(tenant,"evil","analyst"),user="bob",
                          password="strong password 123",role="org_admin")
    with pytest.raises(PermissionError):
        store.set_user_active(Principal(tenant,"evil","operator"),user="alice",active=False)
    with pytest.raises(ValueError):
        store.create_user(admin,user="bob",password="weak",role="auditor")
