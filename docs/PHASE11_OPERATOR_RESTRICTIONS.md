# DevShield Phase 11 — Temporary Operator Restrictions

Status: **Pre-production feature; not an internet-exposed management service.**

## Implemented

- Migration version `4`: tenant/client-scoped `ds_restriction` table.
- Transactional restriction checks in `PostgresStore.check_quota()`.
- PostgreSQL advisory lock shared by quota admissions and restriction updates.
- Server-side role validation for `operator` and `org_admin` (`manage_restrictions`).
- POST `/api/restrictions` (body: `{"subject":"demo-api-client","minutes":30}`) and POST `/api/restrictions/revoke` (body: `{"subject":"demo-api-client"}`). Both require authenticated session, origin validation, and HMAC-CSRF header.
- GET `/api/restrictions` returns active restrictions for the **session's own tenant**.
- Protected API returns 403 with a retry duration for restricted clients; database outages still fail closed as 503.
- Console records create/revoke actions in the tenant-scoped audit table.
- UI includes temporary restriction form and active restriction list with revoke buttons.
- Integration tests use disposable PostgreSQL 16 and 18 service containers.

## Security boundaries

- This runs as a **loopback-only demo** with a preconfigured protected API client identity. An Internet-facing deployment requires verified principal-to-token mapping, TLS, MFA/SSO, login rate limiting, administrative review, and independent security assessment.
- Client identifiers are not read from request headers. The demo protected API uses the trusted `demo-api-client` identity.
- Restriction duration is bounded between 1 and 1,440 minutes (24 hours).
- Restricted API attempts are counted as `restricted` audit events; restrictions do not silently bypass quotas.
- Existing role policy prevents analysts and auditors from changing restrictions.
- Tenant identifiers derive from the validated login session, never query strings or mutation payloads.
- For the local UI, run `python -m devshield.ops_console` after setting up an isolated database and bootstrapping users as in `PHASE10_OPS_CONSOLE.md`.
- Run `python -m devshield.protected_api` with a distinct loopback port and the same test database to observe restriction enforcement.

## Next work

User lifecycle management, hardened rate-limited login, real-browser E2E, backup/restore and staging deployment remain outstanding. This feature is not a substitute for security certification.
