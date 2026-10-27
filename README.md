# DevShield — Software-IP Exposure and API-Abuse Defense

> **Foundation source code published. Full production platform is NOT yet pushed or independently verified.**

DevShield is a local-first, authorized security research project. This GitHub repository currently contains a **runnable scanner foundation** and project verification notes.

## Source code is here

- [Source scanner](src/devshield/core.py): redact-first static scan, deterministic file traversal, SHA-256 release manifests and verification.
- [Binary-exposure scanner](src/devshield/exposure.py): bounded binary marker inspection, no secret-value disclosure.
- [Command-line program](src/devshield/cli.py): `scan`, `exposure-scan`, `manifest`, `verify`.
- [Python package](pyproject.toml).
- [Scanner tests](tests/test_core.py) and [binary-exposure tests](tests/test_exposure.py).
- [GitHub Actions foundation CI](.github/workflows/foundation-ci.yml).

## Run it

Requires Python 3.10+.

```bash
python -m pip install -e . pytest
devshield scan src --fail-on none
devshield exposure-scan /path/to/authorized-release.exe --fail-on high
python -m pytest -q tests/test_core.py tests/test_exposure.py
```

**GitHub Actions foundation CI:** [successful run on Python 3.10 and 3.12](https://github.com/Sivanesanbalu/devshield-ai/actions/runs/40537589854).

## Important scope and verification status

- This repository currently holds **9 source/config/test/CI files**, in addition to the documentation. It is **not the complete ~197-file local DevShield project**.
- The separate local recovery build reported **287 passing tests** and an 183-file heuristic scan with zero flagged findings. These are **local** results, not tests of the complete GitHub source.
- The original milestone report claimed **293 passing tests** in a later version. That revision is not available in the recovered local ZIP and remains **unverified**.
- GitHub CI runs **7 committed foundation tests on each of Python 3.10 and 3.12**. It does not run the missing PostgreSQL, authentication, browser E2E, or Ghidra/AI experiments.
- No successful real PostgreSQL 18 validation, production security certification, or live deployment is claimed here.

## Remaining work

1. Recover and securely publish the full validated source with its 197 locally tracked files.
2. Reproduce PostgreSQL 16/18 transactions, quota concurrency, fail-closed outages, and role authorization.
3. Validate browser E2E, signed releases, and authorized Ghidra/AI reconstruction.
4. Perform staging and release gate review.

See [Phase 7 verification](docs/PHASE7_VERIFICATION.md) and [tracking issue #1](https://github.com/Sivanesanbalu/devshield-ai/issues/1).

**Security:** This repository is public. Never commit private signing keys, secrets, live DB dumps, or customer data.
