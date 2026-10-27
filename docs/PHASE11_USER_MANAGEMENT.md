# DevShield Phase 11B — Organization user management

Local-only admin user lifecycle, for authorized DevShield environments.

## Capabilities

- `GET /api/users`: list users in the session's tenant, without password hashes.
- `POST /api/users`: create user with role `org_admin`, `operator`, `analyst`, or `auditor`; initial password minimum 12 characters, maximum 256.
- `POST /api/users/status`: enable or disable a user. Disabled users cannot log in.
- Every change is PostgreSQL-transactionally audited; role checks on the server enforce `manage_users` for organization administrators only.
- Active session tokens are revoked on account enable/disable; a disabled account cannot reuse its prior session after reactivation.
- An admin cannot disable their own account, and the last remaining active `org_admin` cannot be disabled.
- Username and target tenant are validated; the effective tenant always comes from the authenticated cookie session.
- State-changing endpoints require same-origin/Host checks and an HMAC-CSRF header.

## Limits

This is a loopback-only demonstration, **not** a production Internet-accessible identity provider. MFA, brute-force protection, password reset, password breach checks, stronger username normalization, independently reviewed audit retention, account invitation flows, and secure TLS/SSO remain for subsequent phases.

Access the demo through `python -m devshield.ops_console` using a disposable PostgreSQL database; see `PHASE10_OPS_CONSOLE.md` for initial bootstrap.

Never commit real passwords, sessions, or database connection secrets.
