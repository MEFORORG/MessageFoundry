# Security Remediation Ledger — 2026-06-26 audit wave

Single-writer coordination ledger for the 24-finding security remediation (SEC-001…SEC-024) opened as
10 lane PRs (#556–#565). **One session writes this file at a time** (last-write-wins otherwise); other
sessions read it. It is the human-readable companion to the audit report and the merge runbook.

- **Audit posture:** STRONG — a *parity* problem, not a competence problem. No critical/high
  unauthenticated RCE, SQLi, XXE, IDOR, or PHI-leak. 1 HIGH, 6 MEDIUM, 16 LOW, 1 INFO; every
  confirmed item is a control the project applies elsewhere but had not extended to a sibling path.
- **Method:** 13-dimension fan-out → 3-vote perspective-diverse adversarial verification (44 candidates →
  26 confirmed → 24 after merge) → file-disjoint lane partition → per-lane implement + regression test.
- **Status:** all 24 findings implemented. 9 lanes complete + open; 1 (IDE) draft pending a CI-only test host.

## Land-order queue

Merge in this order. Lanes 2–3 edit *disjoint regions* of files also touched by lane 1, so after lane 1
lands they should rebase cleanly; all others are fully file-disjoint and may merge in any order once green.

| # | Lane | PR | Findings | Merge gate | Depends on |
|---|------|----|----------|-----------|------------|
| 1 | listeners-x12-tcp | [#558](https://github.com/MEFORORG/MessageFoundry/pull/558) | SEC-002, 011 | green | — (**foundational, merge first**) |
| 2 | config-source-trust | [#564](https://github.com/MEFORORG/MessageFoundry/pull/564) | SEC-003, 019 | green | #558 (shares `config/wiring.py`) |
| 3 | pipeline-dos-guards | [#562](https://github.com/MEFORORG/MessageFoundry/pull/562) | SEC-013, 017 | green | #558 (shares `pipeline/wiring_runner.py`) |
| 4 | transports-tls-ssrf | [#560](https://github.com/MEFORORG/MessageFoundry/pull/560) | SEC-001, 010, 009 | green after crypto-inventory fix | — |
| 5 | dicom-scp-hardening | [#559](https://github.com/MEFORORG/MessageFoundry/pull/559) | SEC-012, 016 | green | — |
| 6 | api-scope-revocation | [#565](https://github.com/MEFORORG/MessageFoundry/pull/565) | SEC-008, 018, 020 | green | — |
| 7 | auth-rbac-consistency | [#563](https://github.com/MEFORORG/MessageFoundry/pull/563) | SEC-006, 015, 014, 024 | green | — |
| 8 | ide-trust-scope | [#561](https://github.com/MEFORORG/MessageFoundry/pull/561) | SEC-004, 005, 022 | **DRAFT** — Extension Host suite on CI xvfb | merge LAST |
| 9 | supplychain-ci | [#556](https://github.com/MEFORORG/MessageFoundry/pull/556) | SEC-007, 021 | green | — |
| 10 | redaction-freetext | [#557](https://github.com/MEFORORG/MessageFoundry/pull/557) | SEC-023 | green | — |

## Shared-file watch (contention map)

| File | Lanes | Strategy |
|------|-------|----------|
| `pipeline/wiring_runner.py` | #558, #562 | #558 lands first (adds `check_listener_tls_exposure`); #562 edits the disjoint worker-dispatch + non-HL7 ingress regions |
| `config/wiring.py` | #558, #564 | #558 lands first (X12 listens-set); #564 edits the disjoint `_assert_safe_config_source`/`_SiblingHelperFinder` regions |
| `store/store.py`, `store/base.py`, `store/postgres.py`, `store/sqlserver.py` | #565 | sole owner (the `list_connection_events` allowed_channels signature change) |
| `api/app.py` | #565 | sole owner (SEC-006 routed to `field_authz.py` in #563 to keep app.py single-owner) |
| `api/auth_routes.py` | #563 | sole owner |
| `ide/package.json` | #561 | sole owner |

## ADR registry (this wave)

| ADR | Title | PR |
|-----|-------|----|
| 0034 | Static-analysis (CodeQL) triage policy + accepted-risk register | #567 (concurrent, separate wave) |
| 0035 | IDE extension: workspace-trust gating, machine-scoped promote targets, fail-closed AI policy | #561 |
| 0036 | Windows config-source trust enforcement | #564 |

> Note: ADR numbers collided across concurrent worktrees (the known cross-worktree gotcha). #561's IDE
> ADR was renumbered 0034 → 0035 pre-merge. Then a concurrent branch (#567) merged its own 0034
> (static-analysis triage), so #564's config-source-trust ADR was renumbered 0034 → 0036 in a follow-up
> (this PR), which also repaired #561's stale 0034 H1 title.

## Post-open fixes already applied

- **#560 crypto-inventory gate** (ASVS 11.1.3): the FTPS fix added `ssl` to `transports/remotefile.py`,
  which the full-suite `test_security_static.py` + the `crypto-inventory` CI job flagged as undocumented
  (the lane's targeted test run had deselected it). Registered the file in
  `scripts/security/crypto_inventory_check.py` (rationale inline); gate verified clean locally (23 sites).
- **#561 ADR renumber** 0034 → 0035 (above).
- **#564 config-source trust guard** (SEC-003): the Windows guard hard-refused any dir where
  `BUILTIN\Users` has write — the default ACL on a Windows checkout — breaking CI + normal dev. Kept the
  production default **fail-closed** and added the audited `MEFOR_ALLOW_INSECURE_CONFIG_SOURCE` escape
  (off by default; never set in production; the installer locks the dir so production never trips it),
  mirroring `MEFOR_ALLOW_INSECURE_TLS`. Verified locally (ruff + mypy strict 172 files + 69 tests) and
  green on CI. Documented in ADR 0036 + SERVICE.md.

## Follow-ups before/after merge

1. **#561 (IDE):** run the VS Code **Extension Host** test suite on a CI runner with xvfb (it could not
   launch in the build sandbox — environment limitation, not a code defect; typecheck/compile/pure-helper
   tests all pass), then un-draft and merge last.
2. **CI security gates** (bandit / pip-audit / gitleaks / semgrep) were not run in the lane worktree venvs
   (not installed); they run on each PR's CI. No lane changed `requirements.lock`/`pyproject.toml` or added
   a subprocess/eval sink, so they are expected to pass — confirm green per PR before merging.
3. **Regression guards added** by these PRs (keep them): the new `check_listener_tls_exposure` parity test,
   the `field_authz` metadata drift-guard, the db_lookup read-only assertions, the dependabot-guardrails
   YAML test, and the `redact()` free-text + raise-fstring advisory lint.

---
*Generated as part of the audit→plan→fix→coordinate wave. Audit method and full finding detail: see the
session security-audit report. 🤖 Generated with [Claude Code](https://claude.com/claude-code).*
