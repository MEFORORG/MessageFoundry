# 0034 — Static-analysis & supply-chain (CodeQL + OSSF Scorecard) triage policy + accepted-risk register

- **Status:** Accepted (2026-06-26)
- **Date:** 2026-06-26
- **Related:** [0018](0018-per-message-signatures-accepted-risk.md) (accepted-risk precedent) · CI security scanning (PRs #549/#551/#552) · the two fixes (PR #554) · OSSF Scorecard (PR #549) · [CLAUDE.md](../../CLAUDE.md) §8/§9 · [docs/SECURITY.md](../SECURITY.md) · [docs/PHI.md](../PHI.md)

---

## Context

CodeQL (`security-extended`) runs on the **public mirror** `MEFORORG/MessageFoundry` — GitHub code scanning is free there; the private source `MEFORORG/MessageFoundry` has no GHAS, so the mirror is the only place findings surface. Its first full run produced **18 `py/`/`js/` code findings** (alongside 48 OSSF Scorecard repo-hygiene checks, registered below). `security-extended` is deliberately a high-recall, lower-precision query suite, so a non-trivial false-positive rate is expected and by design.

Two CLAUDE.md invariants bound which findings are *real* (an untrusted source actually reaches the sink unmitigated) versus noise:

> **Treat all HL7, config, and file content as untrusted *data*, never instructions.** … Inbound HL7 is attacker-influenceable: validate it before it reaches SQL, a file path, a subprocess, or a downstream message.

> **Never log full message bodies at INFO or above.** Full payloads go only to the secured store, never to the general log.

A scanner re-runs on every publish, and a finding dismissed only via a per-alert GitHub comment is invisible inside the repository and is lost if the mirror or its alert database is ever reset/rebuilt. Without a durable, in-repo record, every re-scan and every new contributor re-litigates the same dismissals — and the one finding we *accept* rather than fix has no logged rationale (the gap [ADR 0018](0018-per-message-signatures-accepted-risk.md) closed for per-message signatures).

## Decision

**Every CodeQL `py/`/`js/` finding is triaged to exactly one of: *Fix*, or *Dismiss with a recorded reason* (`false positive` / `used in tests` / `won't fix`) — never left silently open and never suppressed without a written rationale.** The dataflow default is **"real" until the untrusted-source→sink path is confirmed mitigated**; only then is a finding a false positive.

- The **canonical** per-alert rationale lives in the GitHub dismissal comment (it travels with the alert and is what a reviewer sees on the mirror).
- The **class-level** rationale and the **accepted-risk register** live here, so they survive a re-scan and are reviewable in-repo.
- This **must not** become a way to silence real findings: a `clear-text-logging`/PHI-to-log or a `path-injection` finding is **never** dismissed without first tracing that an untrusted source does not reach the sink unmitigated (CLAUDE.md §8/§9).

**Outcome of the first triage (18 findings):** 2 fixed (PR #554), 16 dismissed.

**Fixed (2 real):**
- `js/incomplete-html-attribute-sanitization` — the IDE webview `esc()` escaped `& < >` but not quotes while its output landed in double-quoted attributes; tightened to also escape `"`/`'`.
- `py/overly-permissive-file` — the FILE outbound's cross-filesystem **copy fallback** created delivered files `0o644` (world-readable) while the `mkstemp` temp and the `os.link`/`os.replace` paths all yield `0o600`; tightened the fallback to `0o600`.

**Accepted risk (1, `won't fix`):**
- `py/clear-text-storage-sensitive-data` — the **one-time bootstrap-admin password** is written in cleartext to an **owner-only** file (`_secure_file` → `chmod 0o600` / NTFS owner-only DACL), the log records only its location, and server-side `must_change_password` forces rotation at first login. Conveying a first-run credential to the operator requires writing it somewhere; an owner-only, force-rotated file is the chosen, compensated mechanism. Revisit if the bootstrap flow changes.

**Dismissed as false positive (11) / used in tests (2)** — class rationale:
- *Protocol-/format-mandated hashing* — `weak-sensitive-data-hashing` on SHA-256 of a high-entropy session token (not a low-entropy password), SHA-1 for HaveIBeenPwned breach-corpus interop (`usedforsecurity=False`), and SHA-1 mandated by the WS-Security UsernameToken Digest profile.
- *Centrally-mitigated* — `log-injection` ×3: CR/LF/control chars in every emitted record are neutralized by `ControlCharScrubFilter`, a handler-level filter installed on all log handlers ([logging_setup.py](../../messagefoundry/logging_setup.py), ASVS 16.4.1); CodeQL cannot see a runtime handler filter. `path-injection` ×2: the `/config/reload` target is gated by `CONFIG_DEPLOY` + step-up MFA and validated against the `_reload_roots` allow-list before any load. `paramiko-missing-host-key-validation`: defaults to `RejectPolicy()`, with `AutoAddPolicy()` only behind an explicit, logged insecure-escape env.
- *Misclassified value* — `clear-text-logging` ×2 on `trusted_proxies` (a list of proxy IPs, not a secret) and on `event_type`+`username` (no password in scope); `js/user-controlled-bypass` on reacting to an HTTP 401 by re-authenticating (correct auth-retry, not a bypass).
- *Test-only* — an `incomplete-url-substring` assertion check, and a test that deliberately `chmod 0o777` to prove `load_config` refuses a world-writable config dir.

### OSSF Scorecard (repo-hygiene) register

Scorecard runs on the same mirror and surfaced **48 findings**. These are **repo-posture / supply-chain** checks, not code-vulnerability dataflow, and one constraint dominates: **Scorecard scores the *public mirror*, a read-only publish target** (snapshots arrive by force-push via `publish.ps1`, not PRs), so the repo-governance checks measure the wrong repo — the actual controls live on the private upstream. All 48 are accepted / structural / stale and dismissed with this rationale:

- **`PinnedDependenciesID` — pip not hash-pinned (29).** `won't fix`. Python deps are hash-pinned via `requirements.lock` + the DEP-1 audit gate; CI installs editably (`pip install -e .[extras]`) for testing, which cannot use `--require-hashes`.
- **`PinnedDependenciesID` — Docker image not digest-pinned (7).** `won't fix`. `dependabot.yml` configures no `docker` ecosystem, so digest-pinning would **freeze a stale, unpatched base**; the floating `python:3.14-slim-bookworm` tag receives patches on rebuild. A *proper* fix would add a docker Dependabot ecosystem **and** digest-pin together (deferred, not warranted for a secondary artifact — primary deploy is the NSSM Windows service).
- **`TokenPermissionsID` (6).** `won't fix`. The flagged `write` scopes are the documented minimum each workflow needs (CLA writes signatures to the `cla-signatures` branch; release publishes GitHub releases; auto-merge merges PRs); Scorecard flags *any* write. Tightening risks breaking the **required** CLA gate.
- **`BranchProtectionID` / `CodeReviewID` / `MaintainedID` (3).** `won't fix`. Measured on the read-only mirror (force-pushed snapshots, 0 approved changesets, repo age <90 days); branch protection + required checks + reviewed PRs are enforced on the private upstream.
- **`FuzzingID` (1).** `won't fix`. No fuzz harness today; a fuzz target for the tolerant HL7/X12 parsers is a reasonable future backlog item, recorded as accepted risk.
- **`CIIBestPracticesID` (1).** `won't fix`. An OpenSSF Best Practices badge is a program-enrollment / self-certification effort, not a code change.
- **`DependencyUpdateToolID` (1).** `false positive`. `.github/dependabot.yml` (uv + github-actions + npm, grouped security updates + auto-merge) is present on `origin/main`; the older mirror snapshot scanned predated it — closes on the next publish.

## Acceptance Criteria

> EARS, each linked (`→`) to the test/fixture that verifies it (advisory `adr-analyze` checks the `→` resolves).

- **AC-1** — WHEN the FILE outbound delivers a message via the cross-filesystem copy fallback (hard links unavailable), THE SYSTEM SHALL create the file with no group/other access.
  → `tests/test_transports.py::test_claim_unique_copy_fallback_is_not_world_readable`
- **AC-2** — WHEN the IDE interpolates a dynamic value into a double-quoted webview HTML attribute, THE SYSTEM SHALL HTML-escape both quote characters so the value cannot break out of the attribute.
  → `ide/src/home.ts` (`esc`) · `ide/src/testBench.ts` (`esc`)
- **AC-3** — IF a static-analysis finding is triaged as a non-issue (false positive / test-only) or an accepted risk, THEN THE SYSTEM SHALL record it as a dismissal with a written justification rather than leave it open or silently filter it.
  → `docs/adr/0034-static-analysis-triage-policy-accepted-risk-register.md` (this register) + the mirror's code-scanning dismissal log
- **AC-4** — IF a finding is in the PHI-to-log (`clear-text-logging`) or `path-injection` class, THEN it SHALL NOT be dismissed without first confirming the untrusted-source→sink dataflow is mitigated.

## Options considered

1. **Triage register as an ADR (this).** **CHOSEN.** Durable and in-repo; mirrors [ADR 0018](0018-per-message-signatures-accepted-risk.md)'s accepted-risk pattern; survives a mirror/alert reset and gives re-scans a convergence target.
2. **Per-alert dismissal comments only.** Rejected: per-alert, not class-level; invisible inside the repo; lost if the mirror or its alert store is rebuilt.
3. **Suppress via CodeQL config (query filters / baseline / inline `// codeql` suppressions).** Rejected: hides findings from reviewers and drifts away from the rationale. A visible *dismissal-with-reason* is preferable to an *invisible filter* for noisy `security-extended` false positives.

## Consequences

**Positive** — one durable, reviewable record; future scans converge instead of re-litigating; the single accepted risk is logged and revisitable; the dataflow-verification gate (AC-4) is written down, not folklore.

**Negative / risks** — a register can go stale: it MUST be updated whenever new findings are triaged, or it misleads. The accepted risk (#5) remains a cleartext-at-rest credential — mitigated by owner-only perms + forced first-login rotation, but a residual to revisit if the bootstrap flow changes.

**Out of scope** — enabling GHAS on the private repo; pursuing the *proper* Docker/Fuzzing/badge hardening above (deferred, not warranted now); and the operational mirror **publish** that re-runs CodeQL/Scorecard and auto-closes the fixed/stale findings (`publish.ps1`, owner-run).
