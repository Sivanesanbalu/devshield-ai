# DevShield — Software-IP Exposure and API-Abuse Defense

> **Active development — security-focused, pre-production.**

DevShield is an authorized, local-first research project for software-IP exposure scanning, binary release checks, API abuse prevention, and defensive engineering.

## Actual Python source

| Component | Files |
|---|---|
| Release and exposure scanner | [scanner core](src/devshield/core.py), [binary exposure](src/devshield/exposure.py), [CLI](src/devshield/cli.py) |
| Transactional PostgreSQL quotas and sessions | [postgres_store.py](src/devshield/postgres_store.py) |
| Auth primitives: tenant RBAC, password verification, CSRF tokens | [security_policy.py](src/devshield/security_policy.py) |
| HTTP protected API demonstration | [protected_api.py](src/devshield/protected_api.py) |
| Real DB concurrency and API tests | [tests](tests/) |
| CI (Python 3.10/3.12, PostgreSQL 16/18) | [.github/workflows](.github/workflows/) |
| Local VS Code scan integration (review pending) | [vscode-extension](vscode-extension/) |

### Run the scanner

```bash
python -m pip install -e . pytest
devshield --help
python -m pytest -q tests/test_core.py tests/test_exposure.py tests/test_security_policy.py tests/test_postgres_store_unit.py tests/test_protected_api.py
```

### Run the PostgreSQL demo (local only)

```bash
python -m pip install -e . "psycopg[binary]>=3.2,<4"
export DEVSHIELD_POSTGRES_DSN='postgresql://user:password@localhost/devshield_demo'
export DEVSHIELD_API_TOKEN='<generate-a-unique-long-random-token>'
python -m devshield.protected_api --init-schema --port 8765
```

Never reuse demo credentials. Do not run against a production database without a separate deployment, access and security review. The demo binds only to loopback and does not implement TLS, SSO, browser dashboard, or backup/recovery.

## Verified CI evidence

- [Python 3.10 and 3.12 foundation, RBAC and HTTP checks](https://github.com/Sivanesanbalu/devshield-ai/actions/runs/40539962250) — passed.
- [Real PostgreSQL 16 and 18 quota/session concurrency, migrations and isolation](https://github.com/Sivanesanbalu/devshield-ai/actions/runs/40539120772) — passed.
- [Real Chromium browser journeys on PostgreSQL 16/18](https://github.com/Sivanesanbalu/devshield-ai/actions/runs/40549623801) — passed on 2026-10-27.
- CI results are from disposable test services, not a deployed production environment.

## Remaining release gates

1. The **complete previously recovered local 197-file source** is **not yet in GitHub**. This repository has the working scanner foundation and new PostgreSQL/authorization/API modules, not all historical implementation.
2. The separately reported **293-test final source** has not been recovered or reproduced.
3. A **loopback-only**, PostgreSQL-backed authenticated operations console is committed and browser-tested, but production SSO/MFA, login throttling, TLS deployment and independent security assessment remain.
4. Real Chromium browser E2E passed in disposable CI. Authorized Ghidra/AI reconstruction evidence, penetration review, secrets management, staging, monitoring, backups and recovery still remain.
5. Public source requires ongoing code, dependency, secret and legal/licensing review. Production release is **not approved**.

[Phase 7 verification and gaps](docs/PHASE7_VERIFICATION.md) · [PostgreSQL integration notes](docs/PHASE7_POSTGRES_HTTP.md) · [Current release roadmap](docs/DEVSHIELD_RELEASE_ROADMAP.md) · [Release-gate issue #1](https://github.com/Sivanesanbalu/devshield-ai/issues/1)
