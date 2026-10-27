# Phase 7 — Recovered foundation verification (2026-10-27)

## Evidence observed

| Check | Result | Scope |
|---|---|---|
| Local regression | **285 passed** | Recovered foundation, Python pytest run |
| Publication heuristic scan | **PASS** | 180 files checked, zero flagged findings |
| Source snapshot | **Recovered** | `devshield-postgres-foundation.zip` |
| Reported final integrated suite | **Unverified** | 293-test result provided in narrative; later source unavailable |
| GitHub CI | **Not run** | Source has not yet been committed to GitHub |
| Production deployment | **Not performed** | No release approval |

## Source checks

The recovered foundation includes `examples/protected-ip-api/postgres_backend.py`, but these components claimed in the later report are **not present or not wired** in the recovered files:

- `PostgresGuard` integrated into the HTTP server
- `src/devshield/migration_runner.py` (versioned migrations)
- `src/devshield/rbac.py` and `src/devshield/org_store.py`
- `tests/test_postgres_multiprocess.py` and `tests/test_e2e_browser_workflow.py`
- `tests/test_postgres_outage_and_load.py`
- `src/devshield/rea_reconstruction_runner.py`
- `.github/workflows/postgres-ci.yml`

This is an **artifact mismatch**, not proof that the work was never completed elsewhere.

## Next development gates

1. **Recover & commit the genuine final source:** verify archive provenance, secret scan, review license and fixtures, keep release claims honest.
2. **CI:** test Python matrix and PostgreSQL 16/18 in isolated ephemeral services; do not report a passing result until workflows run.
3. **Transactional quotas and sessions:** concurrent processes, cross-tenant isolation, fail-closed database outages; use independent test processes and real PostgreSQL.
4. **Security console:** verify server-side RBAC and CSRF on every state-changing operation, password hashing parameters, secure cookie attributes, logout invalidation.
5. **REA reproducibility:** real authorized binaries, disassembly/decompiler provenance, same evidence budget, held-out functional tests and no ground-truth leakage; characterize accuracy only for the measured sample.
6. **Staging:** HTTPS, connection pool bounds, secrets manager, backup/restore, observability, security review, then a gated deployment decision.

## Claim boundaries

- The currently measured regression is **285**, not 293.
- Local tests and static heuristics are not proof of production readiness, absence of secret exposure, or universal reverse-engineering resistance.
- The project should remain **pre-production** until the live PostgreSQL, browser E2E, reconstruction and staging evidence are independently available.
