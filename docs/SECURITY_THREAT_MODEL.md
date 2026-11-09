# DevShield threat model and release gates

Status: local-first, security-focused PRE-PRODUCTION. No automatic protection of arbitrary applications.

## Protection boundary

| Layer | Current capability | Residual risk |
|---|---|---|
| Source scanner | Heuristic redacted findings; opt-in coverage gate | Not a semantic vulnerability or Git history scanner |
| Binary scanner | Finds limited PEM/path/hostname markers | Does not stop decompilation, patching or reverse engineering |
| Protected API demo | Transactional PostgreSQL quota and restrictions | Only guards requests that explicitly pass through the demo |
| Operations console | Tenant RBAC, sessions and CSRF | Loopback only; production SSO, MFA and tested login throttling missing |
| Hash manifest | Byte comparison against unsigned inventory | An attacker can replace both files and manifest |
| VS Code extension | Manual local scans in draft PR #7 | Not merged, published or enabled automatically |

## Scanner weaknesses addressed by this patch

1. JSON quoted key/value secret assignment patterns were not matched.
2. Plain unquoted .env tokens were not matched.
3. Markdown and TOML were outside the eligible extension set.
4. Eligible source files larger than 1 MiB were silently skipped.
5. A scan of zero eligible files could exit successfully.

This patch adds patterns and extensions, redacted incomplete-file metadata
and an optional --require-complete gate (exit 3 for zero eligible scans or
skipped eligible source). Fixture secrets are synthetic; matched values are
not included in findings.

## Remaining bypasses and limitations

- Dynamic values, split/encoded/obfuscated secrets, history already pushed to Git,
  excluded vendor/build directories, unknown extensions, multi-line formats,
  UTF-16, symlinks, very large files, false positives and adversarial changes.
- Source detection is NOT enforcement; stolen tokens must be revoked and rotated.
- Gateway policy must apply to all real routes; direct-origin routes and backend
  jobs can bypass a guard that is not installed in their request path.
- Release inventory is unsigned; genuine release authenticity requires signing.
- The committed system is not a validated software anti-reverse-engineering control.

## Adversarial priorities

1. P0: Never publish the local HTTP demos unchanged. Harden TLS ingress,
   login throttling, MFA/SSO, trusted token-to-tenant binding and session policy.
2. P0: Test direct-origin and alternative-route bypass of API enforcement.
3. P1: Test cross-tenant query/body/header manipulation, broken authorization,
   stolen tokens, disabled sessions, replay and malformed input.
4. P1: Test concurrency, out-of-service database behavior and failure telemetry.
5. P1: Secure supply chain, key rotation, signed releases, dependency reviews.
6. P1: Execute permitted real Ghidra/LLM benchmarks on owned toy binaries
   with matched evidence and budgets before claiming reverse-engineering efficacy.
7. P2: Run backups/restores, staging load tests, monitoring and response drills.

## Reproduce

    python -m pip install -e . pytest
    python -m pytest -q tests/test_core.py tests/test_scanner_coverage.py
    devshield scan path/to/app --fail-on high --require-complete

An exit code 0 does not certify application security. It only reflects
threshold detection and eligible-file coverage checks for this scanner.

Before production: reconcile missing historic source (issue #1), finish
authorized benchmark (issue #6), review public repository visibility and
obtain independent security evaluation and owner approval.
