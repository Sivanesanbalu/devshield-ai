"""Default-deny authorization primitives for authenticated DevShield consoles.

Integration contract: identities and tenant IDs must come from trusted
authentication, not client-supplied request headers or parameters.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass


PERMISSIONS = frozenset({
    "view_metrics", "view_audit", "manage_restrictions",
    "prune_data", "manage_users", "issue_api_keys",
})

ROLE_PERMISSIONS = {
    "org_admin": PERMISSIONS,
    "operator": frozenset({"view_metrics", "view_audit", "manage_restrictions"}),
    "analyst": frozenset({"view_metrics", "view_audit"}),
    "auditor": frozenset({"view_audit"}),
}


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    user_id: str
    role: str
    active: bool = True


def can_access(principal: Principal | None, *, tenant_id: str, permission: str) -> bool:
    """Never authorize cross-tenant or unknown permissions/roles."""
    if not isinstance(principal, Principal) or not principal.active:
        return False
    if not isinstance(tenant_id, str) or not tenant_id:
        return False
    if not principal.tenant_id or not principal.user_id:
        return False
    return (
        hmac.compare_digest(principal.tenant_id.encode('utf-8'), tenant_id.encode('utf-8'))
        and permission in ROLE_PERMISSIONS.get(principal.role, ())
        and permission in PERMISSIONS
    )


def enforce(principal: Principal | None, *, tenant_id: str, permission: str) -> None:
    if not can_access(principal, tenant_id=tenant_id, permission=permission):
        raise PermissionError("access denied")


def hash_password(password: str, *, iterations: int = 600_000) -> str:
    """PBKDF2-HMAC-SHA256 with fresh 128-bit salt, portable encoded format."""
    if not isinstance(password, str) or not password:
        raise ValueError("password is required")
    if type(iterations) is not int or iterations < 600_000:
        raise ValueError("insufficient PBKDF2 work factor")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return "pbkdf2_sha256$%d$%s$%s" % (
        iterations,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    if not isinstance(password, str) or not isinstance(encoded, str):
        return False
    try:
        alg, cost, salt64, digest64 = encoded.split("$")
        if alg != "pbkdf2_sha256":
            return False
        iterations = int(cost)
        # Prevent attacker-controlled unbounded work factors.
        if not (600_000 <= iterations <= 2_000_000):
            return False
        salt = base64.urlsafe_b64decode(salt64.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest64.encode("ascii"))
        if len(salt) != 16 or len(expected) != 32:
            return False
        # Reject noncanonical base64, including trailing bytes after '=' padding.
        if (base64.urlsafe_b64encode(salt).decode('ascii') != salt64 or
                base64.urlsafe_b64encode(expected).decode('ascii') != digest64):
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, UnicodeError, TypeError):
        return False


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def verify_csrf(cookie_token: str | None, request_token: str | None) -> bool:
    """Double-submit comparison; caller still must enforce Origin and cookie flags."""
    if not isinstance(cookie_token, str) or not isinstance(request_token, str):
        return False
    if len(cookie_token) < 32 or len(request_token) < 32:
        return False
    return hmac.compare_digest(cookie_token, request_token)
