"""Loopback HTTP security checks for operator restriction routes."""
from devshield.ops_store import OpsStore
from devshield.security_policy import Principal
from test_ops_console_http import FakeStore, serve, call, authenticate


class RestrictionStore(FakeStore):
    def __init__(self, role="operator"):
        super().__init__(role)
        self.items = {}

    def restrictions(self, principal):
        self.calls.append(("list", principal.tenant_id))
        return list(self.items.values())

    def restrict(self, principal, *, subject, minutes):
        self.calls.append(("restrict", principal.tenant_id, subject, minutes))
        OpsStore._valid_subject(subject)
        if type(minutes) is not int or not 1 <= minutes <= 1440:
            raise ValueError("invalid duration")
        item = {"subject": subject, "created_by": principal.user_id,
                "expires_at": 1900000000}
        self.items[subject] = item
        return {"subject": subject, "expires_at": item["expires_at"]}

    def revoke_restriction(self, principal, *, subject):
        self.calls.append(("revoke", principal.tenant_id, subject))
        OpsStore._valid_subject(subject)
        return self.items.pop(subject, None) is not None


def test_unauthorized_anonymous_restriction_routes():
    store=RestrictionStore()
    with serve(store) as (base, opener):
        assert call(base,opener,"/api/restrictions")[0] == 401
        assert call(base,opener,"/api/restrictions",{"subject":"demo-api-client","minutes":10})[0] == 401
    assert store.calls == []


def test_auditor_cannot_mutate_or_list_restrictions():
    store=RestrictionStore(role="auditor")
    with serve(store) as (base,opener):
        authenticate(base,opener)
        csrf=call(base,opener,"/api/me")[1]["csrf"]
        assert call(base,opener,"/api/restrictions")[0] == 403
        result=call(base,opener,"/api/restrictions",
            {"subject":"demo-api-client","minutes":10},
            extra={"X-CSRF-Token":csrf})
        assert result[0] == 403
    assert store.calls == []


def test_operator_can_restrict_and_revoke_trusted_tenant():
    store=RestrictionStore(role="operator")
    with serve(store) as (base,opener):
        authenticate(base,opener)
        csrf=call(base,opener,"/api/me")[1]["csrf"]
        assert call(base,opener,"/api/restrictions",
            {"subject":"demo-api-client","minutes":10},
            extra={"X-CSRF-Token":csrf})[0] == 200
        status,items,_=call(base,opener,"/api/restrictions?tenant=attacker")
        assert status==200 and items[0]["subject"]=="demo-api-client"
        assert ("list","tenant-A") in store.calls
        assert ("restrict","tenant-A","demo-api-client",10) in store.calls
        assert call(base,opener,"/api/restrictions/revoke",
            {"subject":"demo-api-client"},extra={"X-CSRF-Token":csrf})[1]["revoked"]
        assert call(base,opener,"/api/restrictions")[1] == []


def test_restriction_write_requires_origin_and_csrf():
    store=RestrictionStore()
    with serve(store) as (base,opener):
        authenticate(base,opener)
        assert call(base,opener,"/api/restrictions",
            {"subject":"demo-api-client","minutes":10})[0]==403
        csrf=call(base,opener,"/api/me")[1]["csrf"]
        assert call(base,opener,"/api/restrictions",
            {"subject":"demo-api-client","minutes":10},
            origin=False,extra={"X-CSRF-Token":csrf})[0]==403
    assert not store.items


def test_invalid_inputs_rejected_before_store_mutation():
    store=RestrictionStore()
    with serve(store) as (base,opener):
        authenticate(base,opener)
        csrf=call(base,opener,"/api/me")[1]["csrf"]
        for payload in (
            {"subject":"","minutes":10},
            {"subject":"client","minutes":True},
            {"subject":"client","minutes":1441},
            {"subject":"client","minutes":0},
            {"subject":"client","minutes":"20"}
        ):
            assert call(base,opener,"/api/restrictions",payload,
                extra={"X-CSRF-Token":csrf})[0]==400
    assert not store.items
