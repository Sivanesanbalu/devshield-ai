"""Database-backed organization login, audit and sessions for a local console."""
from __future__ import annotations
import hashlib
import secrets
import time

from devshield.postgres_store import PolicyUnavailable, PostgresStore, _reference, _restriction_lock
from devshield.security_policy import Principal, ROLE_PERMISSIONS, enforce, hash_password, verify_password

OPS_MIGRATION = """
CREATE TABLE IF NOT EXISTS ds_console_user (
 tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('org_admin','operator','analyst','auditor')),
 active BOOLEAN NOT NULL DEFAULT TRUE, PRIMARY KEY(tenant_id,user_id)
);
CREATE TABLE IF NOT EXISTS ds_console_session (
 token_hash BYTEA PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL,
 expires_at DOUBLE PRECISION NOT NULL,
 FOREIGN KEY(tenant_id,user_id) REFERENCES ds_console_user(tenant_id,user_id)
);
CREATE INDEX IF NOT EXISTS ds_console_session_expiry ON ds_console_session(expires_at);
CREATE TABLE IF NOT EXISTS ds_console_audit (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id TEXT NOT NULL, actor_id TEXT NOT NULL,
 action TEXT NOT NULL, created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS ds_console_audit_tenant_time
 ON ds_console_audit(tenant_id,created_at DESC);
"""


def _identity(tenant, user):
    for field in (tenant, user):
        if not isinstance(field, str) or not 1 <= len(field) <= 128 or field != field.strip():
            raise ValueError("invalid organization identity")


def _digest(token):
    return hashlib.sha256(token.encode("utf-8")).digest()


class OpsStore:
    """Trusted tenant and role come from stored credentials and sessions."""

    def __init__(self, dsn, *, connect=None):
        self.db = PostgresStore(dsn, connect=connect)

    def _connection(self):
        return self.db._connection()

    def migrate(self):
        self.db.migrate()
        try:
            with self._connection() as conn:
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (685220042,))
                if not conn.execute("SELECT version FROM ds_migrations WHERE version=3").fetchone():
                    conn.execute(OPS_MIGRATION)
                    conn.execute("INSERT INTO ds_migrations(version) VALUES (3)")
        except Exception:
            raise PolicyUnavailable("security policy unavailable") from None

    def provision_user(self, *, tenant, user, password, role):
        _identity(tenant, user)
        if role not in ROLE_PERMISSIONS:
            raise ValueError("invalid role")
        encoded = hash_password(password)
        try:
            with self._connection() as conn:
                return conn.execute("""
                  INSERT INTO ds_console_user(tenant_id,user_id,password_hash,role)
                  VALUES (%s,%s,%s,%s)
                  ON CONFLICT(tenant_id,user_id) DO NOTHING RETURNING user_id
                """, (tenant, user, encoded, role)).fetchone() is not None
        except Exception:
            raise PolicyUnavailable("security policy unavailable") from None

    def login(self, *, tenant, user, password, ttl_seconds=1800):
        _identity(tenant, user)
        if not isinstance(password,str) or len(password)>1024:
            return None
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 86400:
            raise ValueError("invalid expiry")
        try:
            with self._connection() as conn:
                result=conn.execute("""
                  SELECT password_hash,role,active FROM ds_console_user
                  WHERE tenant_id=%s AND user_id=%s
                """, (tenant,user)).fetchone()
            if not result or not result[2] or not verify_password(password,result[0]):
                return None
            if result[1] not in ROLE_PERMISSIONS:
                return None
            token=secrets.token_urlsafe(40)
            with self._connection() as conn:
                conn.execute("""
                 INSERT INTO ds_console_session(token_hash,tenant_id,user_id,expires_at)
                 VALUES(%s,%s,%s,%s)
                """, (_digest(token),tenant,user,time.time()+ttl_seconds))
                conn.execute("""
                 INSERT INTO ds_console_audit(tenant_id,actor_id,action,created_at)
                 VALUES(%s,%s,'login',%s)
                """, (tenant,user,int(time.time())))
            return token, Principal(tenant,user,result[1])
        except Exception:
            raise PolicyUnavailable("security policy unavailable") from None

    def resolve(self, token):
        if not isinstance(token,str) or not 32 <= len(token) <= 256:
            return None
        try:
            with self._connection() as conn:
                row=conn.execute("""
                 SELECT s.tenant_id,s.user_id,u.role
                 FROM ds_console_session s
                 JOIN ds_console_user u ON s.tenant_id=u.tenant_id AND s.user_id=u.user_id
                 WHERE s.token_hash=%s AND s.expires_at>%s AND u.active=TRUE
                """, (_digest(token),time.time())).fetchone()
            if not row or row[2] not in ROLE_PERMISSIONS:
                return None
            return Principal(*row)
        except Exception:
            raise PolicyUnavailable("security policy unavailable") from None

    def logout(self, token, principal):
        try:
            with self._connection() as conn:
                conn.execute("DELETE FROM ds_console_session WHERE token_hash=%s",(_digest(token),))
                conn.execute("""
                 INSERT INTO ds_console_audit(tenant_id,actor_id,action,created_at)
                 VALUES(%s,%s,'logout',%s)
                """,(principal.tenant_id,principal.user_id,int(time.time())))
        except Exception:
            raise PolicyUnavailable("security policy unavailable") from None

    def metrics(self, tenant):
        tenant_ref=hashlib.sha256(tenant.encode("utf-8")).hexdigest()
        try:
            with self._connection() as conn:
                row=conn.execute("""
                 SELECT count(*),count(*) FILTER (WHERE event='allowed'),
                        count(*) FILTER (WHERE event='rate_limit')
                 FROM ds_event WHERE tenant_ref=%s AND created_at>=%s
                """,(tenant_ref,int(time.time())-86400)).fetchone()
            return dict(requests_24h=row[0],allowed_24h=row[1],throttled_24h=row[2])
        except Exception:
            raise PolicyUnavailable("security policy unavailable") from None

    def audit(self,tenant):
        try:
            with self._connection() as conn:
                rows=conn.execute("""
                 SELECT actor_id,action,created_at FROM ds_console_audit
                 WHERE tenant_id=%s ORDER BY id DESC LIMIT 50
                """,(tenant,)).fetchall()
            return [dict(actor=a,action=b,timestamp=c) for a,b,c in rows]
        except Exception:
            raise PolicyUnavailable("security policy unavailable") from None

    @staticmethod
    def _valid_subject(subject):
        if (not isinstance(subject, str) or not 1 <= len(subject) <= 128
                or subject != subject.strip() or any(ord(c) < 32 for c in subject)):
            raise ValueError("invalid client identifier")
        return subject

    def restrict(self, principal: Principal, *, subject: str, minutes: int):
        """Add/extend a temporary restriction and audit it in one transaction."""
        enforce(principal, tenant_id=principal.tenant_id, permission="manage_restrictions")
        self._valid_subject(subject)
        if type(minutes) is not int or not (1 <= minutes <= 1440):
            raise ValueError("duration must be between 1 and 1440 minutes")
        now = int(time.time())
        expires = now + minutes * 60
        tenant = principal.tenant_id
        try:
            with self._connection() as conn:
                conn.execute("SELECT pg_advisory_xact_lock(%s)",
                             (_restriction_lock(tenant, subject),))
                conn.execute("""
                    INSERT INTO ds_restriction
                        (tenant_ref, subject_ref, subject_label,
                         created_by, created_at, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_ref, subject_ref)
                    DO UPDATE SET subject_label = EXCLUDED.subject_label,
                        created_by = EXCLUDED.created_by,
                        created_at = EXCLUDED.created_at,
                        expires_at = EXCLUDED.expires_at
                """, (_reference(tenant), _reference(tenant + "\x00" + subject),
                      subject, principal.user_id, now, expires))
                conn.execute("""
                    INSERT INTO ds_console_audit(tenant_id, actor_id, action, created_at)
                    VALUES (%s, %s, %s, %s)
                """, (tenant, principal.user_id, "restrict:" + subject, now))
            return {"subject": subject, "expires_at": expires}
        except Exception:
            raise PolicyUnavailable("security policy unavailable") from None

    def revoke_restriction(self, principal: Principal, *, subject: str) -> bool:
        enforce(principal, tenant_id=principal.tenant_id, permission="manage_restrictions")
        self._valid_subject(subject)
        now = int(time.time())
        tenant = principal.tenant_id
        try:
            with self._connection() as conn:
                conn.execute("SELECT pg_advisory_xact_lock(%s)",
                             (_restriction_lock(tenant, subject),))
                deleted = conn.execute("""
                    DELETE FROM ds_restriction
                    WHERE tenant_ref = %s AND subject_ref = %s
                    RETURNING subject_ref
                """, (_reference(tenant),
                      _reference(tenant + "\x00" + subject))).fetchone()
                if deleted:
                    conn.execute("""
                        INSERT INTO ds_console_audit
                            (tenant_id, actor_id, action, created_at)
                        VALUES (%s, %s, %s, %s)
                    """, (tenant, principal.user_id, "unrestrict:" + subject, now))
            return deleted is not None
        except Exception:
            raise PolicyUnavailable("security policy unavailable") from None

    def restrictions(self, principal: Principal):
        enforce(principal, tenant_id=principal.tenant_id, permission="manage_restrictions")
        try:
            with self._connection() as conn:
                rows = conn.execute("""
                    SELECT subject_label, created_by, expires_at
                    FROM ds_restriction
                    WHERE tenant_ref = %s AND expires_at > %s
                    ORDER BY expires_at ASC LIMIT 100
                """, (_reference(principal.tenant_id), int(time.time()))).fetchall()
            return [{"subject": subject, "created_by": creator,
                     "expires_at": expires}
                    for subject, creator, expires in rows]
        except Exception:
            raise PolicyUnavailable("security policy unavailable") from None

    def health(self):
        return self.db.health()
