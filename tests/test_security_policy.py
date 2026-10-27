"""Security policy unit tests; no database or HTTP server required."""
import pytest

from devshield.security_policy import (
    Principal, ROLE_PERMISSIONS, can_access, enforce, hash_password,
    new_csrf_token, verify_csrf, verify_password,
)


@pytest.mark.parametrize("role,permission,allowed", [
    ("org_admin", "manage_users", True),
    ("org_admin", "issue_api_keys", True),
    ("operator", "manage_restrictions", True),
    ("operator", "manage_users", False),
    ("analyst", "view_metrics", True),
    ("analyst", "manage_restrictions", False),
    ("auditor", "view_audit", True),
    ("auditor", "view_metrics", False),
    ("invalid", "view_audit", False),
    ("org_admin", "unknown_permission", False),
])
def test_permission_matrix(role, permission, allowed):
    ctx = Principal("tenant-A", "user-123", role)
    assert can_access(ctx, tenant_id="tenant-A", permission=permission) is allowed


def test_cross_tenant_and_disabled_users_denied():
    ctx = Principal("tenant-A", "alice", "org_admin")
    assert not can_access(ctx, tenant_id="tenant-B", permission="manage_users")
    assert not can_access(
        Principal("tenant-A", "alice", "org_admin", active=False),
        tenant_id="tenant-A", permission="view_audit",
    )
    assert not can_access(None, tenant_id="tenant-A", permission="view_audit")
    with pytest.raises(PermissionError):
        enforce(ctx, tenant_id="tenant-B", permission="manage_users")


def test_password_hashes_use_unique_salts_and_verify():
    a = hash_password("correct horse battery staple")
    b = hash_password("correct horse battery staple")
    assert a != b
    assert verify_password("correct horse battery staple", a)
    assert not verify_password("incorrect", a)
    assert not verify_password("correct horse battery staple", a + "tampered")
    assert not verify_password("password", "plain:password")


@pytest.mark.parametrize("encoded", [
    "", "pbkdf2_sha256$10$bad$bad", "unknown$600000$bad$bad",
    "pbkdf2_sha256$99999999999$bad$bad", "$$$"
])
def test_reject_malformed_password_hash(encoded):
    assert not verify_password("password", encoded)


def test_csrf_generates_random_unpredictable_tokens():
    a, b = new_csrf_token(), new_csrf_token()
    assert a != b
    assert verify_csrf(a, a)
    assert not verify_csrf(a, b)
    assert not verify_csrf(a, None)
    assert not verify_csrf("", "")
    assert not verify_csrf(None, None)


def test_password_work_factor_is_not_configurable_below_floor():
    with pytest.raises(ValueError):
        hash_password("pw", iterations=100_000)
