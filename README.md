# DevShield — Authorized Software-IP Exposure & API-Abuse Defense

> **Status: Pre-production / independent verification in progress.**

DevShield investigates software-IP exposure, release signing, client-side reverse-engineering risk, and API-abuse defenses in authorized test environments.

## Release checkpoint — 27 October 2026

- Recovered local foundation: `devshield-postgres-foundation.zip`; later 293-test revision **not available**.
- **287 passing local pytest tests** after an optional PostgreSQL HTTP policy adapter and two fake-backend integration tests were added.
- Source-publication heuristic scan: **PASS, 183 files checked, zero findings**; not proof that all secrets are absent.
- A separate milestone report claims 293 tests on a later revision; that revision has **not** been reproduced.
- **GitHub currently holds checkpoint documentation only.** The complete local source (~197 tracked files) has not been transferred to GitHub via the available connector.
- **Real PostgreSQL, Ghidra/LLM reconstruction, and production staging have not been executed for this checkpoint.**

## Verification & next work

- [Phase 7 verification](docs/PHASE7_VERIFICATION.md)
- [PostgreSQL HTTP adapter progress](docs/PHASE7_POSTGRES_HTTP.md)
- [Phase 7 tracking issue](https://github.com/Sivanesanbalu/devshield-ai/issues/1)

This repository is public. **Do not upload credentials, signing keys, customer data, production environment files, or database dumps.**

**Not production ready.** Passing local tests and static checks are not independent security certification.
