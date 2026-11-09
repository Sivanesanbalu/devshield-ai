# DevShield developer packaging path

**Preferred distribution:** a signed Python CLI wheel as the core, plus an
optional VS Code extension and GitHub CI integration.

A package is a delivery format, not reverse-engineering prevention.
Python wheels and browser JavaScript are inherently inspectable. Compiled
native binaries can be analyzed as well. Do not embed API secrets or private
business rules that must stay secret in any distributed package.

## Why start with the Python CLI?

- The existing scanner is written in Python and already has a CLI entrypoint.
- Developers can scan locally and in CI without sending source to a SaaS.
- A VS Code integration can invoke the installed scanner.
- Policy enforcement remains a separately authorized server-side integration.
- No login or customer database is required to test local developer scanning.

## Candidate-only CI

The workflow python-wheel-ci.yml builds a wheel on Python 3.10 and 3.12,
checks distribution metadata, installs into an isolated environment, and
tests a synthetic CLI invocation. Artifacts are retained for seven days.
It DOES NOT publish PyPI or create a GitHub release.

## Release gates

1. Resolve PR #8 scanner hardening and tests; review dependencies.
2. Reconcile historical full source and version claims (issue #1).
3. Decide version, maintainer, LICENSE, support policy and SECURITY.md.
4. Check legal boundaries, dependency CVEs and source secret exposure.
5. Produce SBOM and signed release provenance using protected CI review.
6. Verify tamper/downgrade and signature failure on a fresh environment.
7. Publish VS Code only after publisher and version-compatibility checks.
8. Integrate middleware in real apps and test policy bypass and outages.
9. Run independent security review before commercial release.

## Live demonstration

https://devshield-scanner-preview.vercel.app demonstrates browser-only
pattern detection and local redacted reports. It does not prove the full
Python runtime, API enforcement or reverse-engineering resistance.

## Test a local wheel

    python -m pip install build
    python -m build --wheel
    python -m pip install dist/*.whl
    devshield scan path/to/code --fail-on high --require-complete

A clean pattern scan does not guarantee an application is secure.
