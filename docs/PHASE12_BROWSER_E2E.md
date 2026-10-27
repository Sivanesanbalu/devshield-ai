# DevShield Phase 12 — Playwright Chromium E2E verification

**Pre-production real-browser milestone.** This suite runs headless Chromium against a real HTTP operations server and an isolated PostgreSQL 16 or 18 service in GitHub Actions.

## Covered browser journeys

- Log in as a real PostgreSQL-provisioned organization admin.
- Check session cookie attributes, tenant-scoped metrics and dashboard visibility.
- Create and revoke a temporary restriction in the browser; verify the separate protected HTTP API responds **403** while restricted and **200** after revocation.
- Create an operator user using the browser and disable the user; verify fresh login fails.
- Check operator / analyst / auditor visibility and reject unauthorized direct server requests.
- Validate logout invalidates the active session.
- Render a deliberately malicious-looking client label as literal text, without inserting an HTML image.
- Execute the same journeys in CI on PostgreSQL 16 and 18, with Chromium installed by Playwright.

## Run manually (disposable test database only)

```sh
python -m pip install -e . "psycopg[binary]>=3.2,<4" pytest "playwright>=1.56,<2"
python -m playwright install chromium
export DEVSHIELD_TEST_PG_DSN="postgresql://user:password@127.0.0.1:5432/isolated_test_db"
python -m pytest -q -vv tests/test_browser_console_e2e.py
```

Never run E2E tests against a production database or customer records. Temporary browser test identities are generated independently per test.

## Not verified by these tests

This browser suite cannot certify Internet-exposed deployment, web authentication rate-limits, phishing resistance, cryptographic key management, SSO/MFA, Ghidra/LLM reconstruction, disaster recovery, or independent penetration testing.

The browser console remains **loopback-only** and is not suitable for a public reverse proxy.
