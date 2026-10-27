# DevShield — Authorized Software-IP Exposure & API-Abuse Defense

> **Status: Pre-production / independent verification in progress.**

DevShield investigates software-IP exposure, release signing, client-side reverse-engineering risk, and API-abuse defenses in authorized test environments.

## Release checkpoint — 27 October 2026

- Recovered source snapshot: `devshield-postgres-foundation.zip` from project archive (not yet uploaded to this repository).
- Locally reproduced regression suite: **285 passed** (2026-10-27; Python pytest).
- Heuristic source-publication audit: **PASS**, 180 files inspected and no findings. This is **not** a comprehensive credential/security audit.
- A separate report claims 293 passing tests on a later integrated revision; **that final revision is not present in the recovered source snapshot and has not been independently reproduced**.
- **The source code has not yet been pushed.** The local project contains 194 tracked files; the GitHub connection used for this checkpoint cannot transfer the local archive directly.
- No production deployment, live PostgreSQL 18 re-verification, Ghidra/LLM reconstruction benchmark, or security certification is being claimed.

## Verification & next work

See [Phase 7 verification](docs/PHASE7_VERIFICATION.md) for the evidence limits and next release gates. The actual source is required before GitHub CI can validate the runtime.

This repository is public. Do not upload credentials, private signing keys, customer data, production environment files, or database dumps.
