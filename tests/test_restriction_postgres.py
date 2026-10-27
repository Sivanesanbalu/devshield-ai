"""Real PostgreSQL: restriction persistence, tenant isolation and quota enforcement.

Requires a disposable PostgreSQL test DB via DEVSHIELD_TEST_PG_DSN.
"""
import os
import secrets
import pytest
from devshield.ops_store import OpsStore
from devshield.security_policy import Principal

DSN=os.environ.get("DEVSHIELD_TEST_PG_DSN")
pytestmark=pytest.mark.skipif(not DSN,reason="test PostgreSQL DSN required")


@pytest.fixture
def store():
    db=OpsStore(DSN)
    db.migrate()
    return db


def test_restrictions_affect_api_quota_and_are_revocable(store):
    tenant="phase11-"+secrets.token_hex(8)
    actor=Principal(tenant,"operator","operator")
    subject="demo-api-client"
    before=store.db.check_quota(tenant,subject,limit=20,window_seconds=60)
    assert before.allowed
    result=store.restrict(actor,subject=subject,minutes=10)
    assert result["subject"]==subject
    restricted=store.db.check_quota(tenant,subject,limit=20,window_seconds=60)
    assert not restricted.allowed and restricted.reason=="restricted"
    assert restricted.retry_after>0
    items=store.restrictions(actor)
    assert len(items)==1 and items[0]["created_by"]=="operator"
    assert store.revoke_restriction(actor,subject=subject)
    restored=store.db.check_quota(tenant,subject,limit=20,window_seconds=60)
    assert restored.allowed
    audit=[e["action"] for e in store.audit(tenant)]
    assert "restrict:demo-api-client" in audit
    assert "unrestrict:demo-api-client" in audit


def test_restriction_is_isolated_by_tenant_and_subject(store):
    tenant="phase11-"+secrets.token_hex(8)
    other="phase11-"+secrets.token_hex(8)
    operator=Principal(tenant,"alice","org_admin")
    store.restrict(operator,subject="client-a",minutes=5)
    assert store.db.check_quota(tenant,"client-b",limit=10,window_seconds=60).allowed
    assert store.db.check_quota(other,"client-a",limit=10,window_seconds=60).allowed
    assert store.restrictions(Principal(other,"bob","operator"))==[]
    assert not store.revoke_restriction(Principal(other,"bob","operator"),
                                       subject="client-a")
    assert store.db.check_quota(tenant,"client-a",limit=10,window_seconds=60).reason=="restricted"


def test_roles_cannot_override_access_and_invalid_duration(store):
    tenant="phase11-"+secrets.token_hex(8)
    auditor=Principal(tenant,"eve","auditor")
    for operation in (
        lambda: store.restrict(auditor,subject="demo-api-client",minutes=10),
        lambda: store.revoke_restriction(auditor,subject="demo-api-client"),
        lambda: store.restrictions(auditor),
    ):
        with pytest.raises(PermissionError):
            operation()
    with pytest.raises(ValueError):
        store.restrict(Principal(tenant,"alice","operator"),
                       subject="demo-api-client",minutes=True)
