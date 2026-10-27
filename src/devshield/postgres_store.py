"""Transactional PostgreSQL quota and session store.

An optional backend for authorized DevShield integrations. No network connection
is made on import. PostgreSQL 16+ and psycopg 3 are required at runtime.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Callable


class PolicyUnavailable(RuntimeError):
    """A security-critical database operation could not complete."""


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    retry_after: int
    reason: str


_MIGRATIONS = (
    (1, """
    CREATE TABLE IF NOT EXISTS ds_quota (
        tenant_ref TEXT NOT NULL,
        subject_ref TEXT NOT NULL,
        bucket BIGINT NOT NULL,
        used INTEGER NOT NULL CHECK (used >= 0),
        PRIMARY KEY (tenant_ref, subject_ref, bucket)
    );
    CREATE TABLE IF NOT EXISTS ds_event (
        id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        tenant_ref TEXT NOT NULL,
        subject_ref TEXT NOT NULL,
        event TEXT NOT NULL,
        created_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ds_event_tenant_created
        ON ds_event (tenant_ref, created_at);
    """),
    (2, """
    CREATE TABLE IF NOT EXISTS ds_session (
        token_digest BYTEA PRIMARY KEY,
        tenant_ref TEXT NOT NULL,
        role TEXT NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ds_session_expires
        ON ds_session (expires_at);
    """),
    (4, """
    CREATE TABLE IF NOT EXISTS ds_restriction (
        tenant_ref TEXT NOT NULL,
        subject_ref TEXT NOT NULL,
        subject_label TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        PRIMARY KEY (tenant_ref, subject_ref)
    );
    CREATE INDEX IF NOT EXISTS ds_restriction_expires
        ON ds_restriction (expires_at);
    """),
)


def _reference(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _restriction_lock(tenant: str, subject: str) -> int:
    """Stable advisory key shared by quota checks and restriction mutations."""
    value = hashlib.sha256((tenant + "\x00" + subject).encode("utf-8")).digest()
    return int.from_bytes(value[:8], byteorder="big", signed=True)


def _required(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    return value


class PostgresStore:
    """Transaction-scoped database operations; quota calls fail closed.

    Connections are never shared between threads/processes. The caller must
    provide verified tenant/client identities, not trust incoming HTTP headers.
    """

    def __init__(self, dsn: str, *, connect: Callable | None = None):
        self.dsn = _required(dsn, "PostgreSQL DSN")
        if connect is None:
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError("Install psycopg[binary]>=3.2") from exc
            connect = psycopg.connect
        self._connect = connect

    def _connection(self):
        try:
            return self._connect(self.dsn)
        except Exception:
            raise PolicyUnavailable("database security policy unavailable") from None

    @staticmethod
    def _db_failure():
        raise PolicyUnavailable("database security policy unavailable") from None

    def migrate(self) -> None:
        """Apply ordered, idempotent schema migrations under a DB advisory lock."""
        try:
            with self._connection() as conn:
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (685220042,))
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS ds_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                """)
                completed = {
                    row[0] for row in conn.execute(
                        "SELECT version FROM ds_migrations"
                    ).fetchall()
                }
                for version, sql in _MIGRATIONS:
                    if version not in completed:
                        conn.execute(sql)
                        conn.execute(
                            "INSERT INTO ds_migrations (version) VALUES (%s)",
                            (version,),
                        )
        except PolicyUnavailable:
            raise
        except Exception:
            self._db_failure()

    def check_quota(
        self, tenant: str, principal: str, *, limit: int,
        window_seconds: int, now: int | None = None
    ) -> QuotaDecision:
        _required(tenant, "tenant")
        _required(principal, "principal")
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be a positive integer")
        if type(window_seconds) is not int or window_seconds < 1:
            raise ValueError("window_seconds must be a positive integer")
        stamp = int(time.time() if now is None else now)
        bucket = stamp // window_seconds
        tenant_ref = _reference(tenant)
        subject_ref = _reference(tenant + "\x00" + principal)
        try:
            with self._connection() as conn:
                # Serialize policy changes and request admission for the subject.
                conn.execute("SELECT pg_advisory_xact_lock(%s)",
                             (_restriction_lock(tenant, principal),))
                active = conn.execute("""
                    SELECT expires_at FROM ds_restriction
                    WHERE tenant_ref = %s AND subject_ref = %s
                      AND expires_at > %s
                """, (tenant_ref, subject_ref, stamp)).fetchone()
                if active:
                    conn.execute("""
                        INSERT INTO ds_event
                            (tenant_ref, subject_ref, event, created_at)
                        VALUES (%s, %s, 'restricted', %s)
                    """, (tenant_ref, subject_ref, stamp))
                    return QuotaDecision(
                        False, max(1, int(active[0] - stamp)), "restricted"
                    )
                row = conn.execute("""
                    INSERT INTO ds_quota (tenant_ref, subject_ref, bucket, used)
                    VALUES (%s, %s, %s, 1)
                    ON CONFLICT (tenant_ref, subject_ref, bucket)
                    DO UPDATE SET used = ds_quota.used + 1
                      WHERE ds_quota.used < %s
                    RETURNING used
                """, (tenant_ref, subject_ref, bucket, limit)).fetchone()
                event = "allowed" if row else "rate_limit"
                conn.execute("""
                    INSERT INTO ds_event
                        (tenant_ref, subject_ref, event, created_at)
                    VALUES (%s, %s, %s, %s)
                """, (tenant_ref, subject_ref, event, stamp))
        except PolicyUnavailable:
            raise
        except Exception:
            self._db_failure()
        return QuotaDecision(
            allowed=bool(row),
            retry_after=0 if row else ((bucket + 1) * window_seconds - stamp),
            reason=event,
        )

    def create_session(
        self, token: str, *, tenant: str, role: str,
        ttl_seconds: int = 1800, capacity: int = 256
    ) -> bool:
        _required(token, "session token")
        _required(tenant, "tenant")
        _required(role, "role")
        if type(ttl_seconds) is not int or ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity must be positive")
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        now = time.time()
        try:
            with self._connection() as conn:
                # Serializable global capacity through a transaction advisory lock.
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (685220041,))
                conn.execute(
                    "DELETE FROM ds_session WHERE expires_at <= %s", (now,)
                )
                count = conn.execute(
                    "SELECT count(*) FROM ds_session"
                ).fetchone()[0]
                if count >= capacity:
                    return False
                inserted = conn.execute("""
                    INSERT INTO ds_session
                        (token_digest, tenant_ref, role, expires_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (token_digest) DO NOTHING
                    RETURNING token_digest
                """, (digest, _reference(tenant), role, now + ttl_seconds)).fetchone()
                return inserted is not None
        except PolicyUnavailable:
            raise
        except Exception:
            self._db_failure()

    def get_session(self, token: str, *, tenant: str) -> str | None:
        _required(token, "session token")
        _required(tenant, "tenant")
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        try:
            with self._connection() as conn:
                row = conn.execute("""
                    SELECT role FROM ds_session
                     WHERE token_digest = %s AND tenant_ref = %s
                       AND expires_at > %s
                """, (digest, _reference(tenant), time.time())).fetchone()
                return row[0] if row else None
        except PolicyUnavailable:
            raise
        except Exception:
            self._db_failure()

    def revoke_session(self, token: str) -> None:
        _required(token, "session token")
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        try:
            with self._connection() as conn:
                conn.execute(
                    "DELETE FROM ds_session WHERE token_digest = %s", (digest,)
                )
        except PolicyUnavailable:
            raise
        except Exception:
            self._db_failure()

    def health(self) -> bool:
        try:
            with self._connection() as conn:
                return conn.execute("SELECT 1").fetchone() == (1,)
        except PolicyUnavailable:
            raise
        except Exception:
            self._db_failure()
