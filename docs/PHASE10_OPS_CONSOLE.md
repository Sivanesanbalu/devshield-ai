# Phase 10 — Local Security Operations Console

This implements a **local-only authenticated browser prototype**, not a production-ready control plane.

## Features

- PostgreSQL organization users with PBKDF2-HMAC-SHA256 password hashes
- High-entropy HTTP-only SameSite=Strict session cookies; session token digests stored in PostgreSQL
- Trusted tenant and effective role resolved server-side on every request
- CSRF using server-keyed HMAC token and strict Origin/Host checks
- Read-only per-tenant 24-hour quota metrics and login/logout audit timeline
- CSP-restricted browser dashboard, no dynamic untrusted HTML insertion
- Isolated PostgreSQL 16 and 18 CI tests and loopback HTTP regression tests

## Local run

Use an isolated PostgreSQL 16+ test database and Python 3.10+. Set `DEVSHIELD_POSTGRES_DSN` in your shell, without committing it.

```sh
python -m pip install -e . "psycopg[binary]>=3.2,<4"
python -m devshield.ops_console --init-schema
```

Stop the server after migration. Set `DEVSHIELD_BOOTSTRAP_PASSWORD` in the environment to a strong secret using your shell's private input method, then run:

```sh
python -m devshield.ops_console --bootstrap-tenant demo --bootstrap-user admin --bootstrap-role org_admin
unset DEVSHIELD_BOOTSTRAP_PASSWORD
python -m devshield.ops_console
```

Open http://127.0.0.1:8877. Login with the provisioned organization, username, and password.

## Boundaries

- Do **not** expose or reverse-proxy the HTTP listener to the public internet.
- HTTPS termination, ingress login throttling, SSO/MFA, key rotation, and an independent security audit are still necessary for production.
- The operator cannot create actual restrictions yet; the initial console is read-only except login and logout.
- Audit timeline currently tracks console login/logout; it is not a tamper-evident forensic log.
- Unit tests and PostgreSQL CI are not a substitute for browser E2E security validation.
