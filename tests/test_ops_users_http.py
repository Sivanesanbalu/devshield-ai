"""HTTP permission, session CSRF, and tenant tests for account administration."""
from devshield.security_policy import Principal
from test_ops_console_http import FakeStore, serve, call, authenticate


class UsersStore(FakeStore):
    def __init__(self,role="org_admin"):
        super().__init__(role)
        self.accounts={}
    def users(self,principal):
        self.calls.append(("list-users",principal.tenant_id))
        return list(self.accounts.values())
    def create_user(self,principal,*,user,password,role):
        self.calls.append(("create-user",principal.tenant_id,user))
        if not isinstance(user,str) or not user.strip():
            raise ValueError("bad name")
        if not isinstance(password,str) or len(password)<12:
            raise ValueError("weak password")
        if role not in ("org_admin","operator","analyst","auditor"):
            raise ValueError("invalid role")
        if user in self.accounts:
            return False
        self.accounts[user]={"user":user,"role":role,"active":True}
        return True
    def set_user_active(self,principal,*,user,active):
        self.calls.append(("status",principal.tenant_id,user,active))
        if type(active) is not bool:
            raise ValueError("invalid active")
        if user==principal.user_id and not active:
            raise ValueError("cannot self-disable")
        if user not in self.accounts:
            return False
        self.accounts[user]["active"]=active
        return True


def test_users_requires_authenticated_admin():
    store=UsersStore("analyst")
    with serve(store) as (base,opener):
        assert call(base,opener,"/api/users")[0]==401
        authenticate(base,opener)
        token=call(base,opener,"/api/me")[1]["csrf"]
        assert call(base,opener,"/api/users")[0]==403
        assert call(base,opener,"/api/users",{
            "user":"bob","role":"analyst","password":"valid password 123"
        },extra={"X-CSRF-Token":token})[0]==403
    assert store.calls==[]


def test_admin_creates_and_disables_account_in_own_tenant():
    store=UsersStore()
    with serve(store) as (base,opener):
        authenticate(base,opener)
        token=call(base,opener,"/api/me")[1]["csrf"]
        status,body,_=call(base,opener,"/api/users",{
            "user":"bob","role":"operator","password":"valid password 123"
        },extra={"X-CSRF-Token":token})
        assert status==201 and body["created"]
        assert call(base,opener,"/api/users",{
            "user":"bob","role":"operator","password":"valid password 123"
        },extra={"X-CSRF-Token":token})[0]==409
        code,users,_=call(base,opener,"/api/users?tenant=attacker")
        assert code==200 and users==[{"user":"bob","role":"operator","active":True}]
        status,body,_=call(base,opener,"/api/users/status",{
            "user":"bob","active":False
        },extra={"X-CSRF-Token":token})
        assert status==200 and body["updated"]
        assert store.accounts["bob"]["active"] is False
    assert all(call[1]=="tenant-A" for call in store.calls)


def test_user_mutations_require_csrf_origin_and_validation():
    store=UsersStore()
    with serve(store) as (base,opener):
        authenticate(base,opener)
        token=call(base,opener,"/api/me")[1]["csrf"]
        payload={"user":"bob","role":"auditor","password":"valid password 123"}
        assert call(base,opener,"/api/users",payload)[0]==403
        assert call(base,opener,"/api/users",payload,origin=False,
            extra={"X-CSRF-Token":token})[0]==403
        assert call(base,opener,"/api/users",{
            "user":"bob","role":"auditor","password":"short"
        },extra={"X-CSRF-Token":token})[0]==400
        assert call(base,opener,"/api/users/status",{
            "user":"bob","active":"false"
        },extra={"X-CSRF-Token":token})[0]==400
    assert not store.accounts
