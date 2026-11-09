# DevShield release roadmap (2026-11-09)

Status: active development; NOT approved for production deployment or public Marketplace publication.

## Verified from the GitHub repository

- Python scanner, binary exposure checks, SHA-256 inventory, CLI, and release-oriented examples.
- Transactional PostgreSQL quotas and sessions, tenant-scoped role policy, local-only operations console.
- Successful PostgreSQL integration and Chromium browser E2E GitHub Actions runs on 2026-10-27.
- VS Code developer preview proposed in PR #7, awaiting CI and review; not a published extension.

## Blocking milestones

1. **Release provenance (issue #1):** reconcile the historical 197-file source snapshot and claimed 293-test suite with the audited committed subset. Review artifacts, licenses and secrets before any import. Do not infer completeness from prior reports.
2. **Harden security for staging:** add tested authentication throttling, MFA/SSO or equivalent, tenant-to-client identity binding, key rotation, TLS ingress, redacted audit retention, and threat model. Do not expose local-only HTTP servers to the Internet.
3. **Operational readiness:** choose an owner-approved environment; implement managed PostgreSQL backups with restore rehearsal, migrations/rollback, observability, incident response, alerting and load/fault tests.
4. **Developer integrations:** review and merge the opt-in VS Code scanner after CI; package supported CLI releases with signed provenance; design and separately permission-review a least-privilege GitHub App. No GitHub App is live.
5. **Security-efficacy evidence (issue #6):** run permitted, reproducible Ghidra + LLM reconstruction comparisons on owned toy binaries with matched budgets and recorded results. Do not claim impossible reverse engineering based on heuristics.
6. **Go/no-go:** independent application security assessment, dependency and supply-chain review, legal review, user acceptance tests, and explicit production approval.

## Repository visibility

The repository was observed as PUBLIC on 2026-11-09. A previously discussed private target and current public setting differ. Before publishing additional internal IP, the owner must review the intended visibility and inspect Git history for confidential material. Changing repository visibility is an administrator action outside this source-code PR.

## Evidence links

- Chromium browser E2E: https://github.com/Sivanesanbalu/devshield-ai/actions/runs/40549623801
- PostgreSQL integration: https://github.com/Sivanesanbalu/devshield-ai/actions/runs/40549380826
- Foundation: https://github.com/Sivanesanbalu/devshield-ai/actions/runs/40549624145
- Release issue: https://github.com/Sivanesanbalu/devshield-ai/issues/1
- Authorized benchmark issue: https://github.com/Sivanesanbalu/devshield-ai/issues/6
