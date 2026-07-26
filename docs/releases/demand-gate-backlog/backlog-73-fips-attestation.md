# DEMAND-GATE-BACKLOG · S11 · FIPS-mode attestation (report-only on /security/posture)

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S11` |
| **Wave** | 1 |
| **Status** | **🚧 In progress (ADR 0120)** |
| **Effort** | S |
| **Backlog items** | #73 |
| **Build order** | #73 |
| **ADR(s)** | (decision note) FIPS-provider mode attestation — report the OS OpenSSL FIPS state on /security/posture, enforce nothing (amend 0002 only if owner wants formal governance) |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | Yes |
| **Branch** | `dg-s11` (new.ps1 names branch after -Name) |
| **Depends on** | None |

## Items

| Item | Title | Status |
|---|---|---|
| #73 | Explicit FIPS-mode attestation | ○ open |

## Owned files / seams

- `messagefoundry/config/tls_policy.py (NEW pure helper: getattr-guarded _hashlib.get_fips_mode() → bool|None + ssl.OPENSSL_VERSION; add to __all__; leave APPROVED_KEX_GROUPS/validate_tls_ciphers untouched)`
- `messagefoundry/api/models.py (SecurityPosture: additive fips_mode/openssl_version, report-only, not secrets)`
- `messagefoundry/api/app.py (security_posture route ~970-1017 — populate the two fields; existing MONITORING_READ gate + security.posture_view audit cover it)`
- `messagefoundry_webconsole/pages/monitoring.py (attestation row), tests/`

## Notes, PHI & gotchas

No PHI/secret exposure — a boolean + version string are metadata, not key material (SECRET-1 respected). Route already MONITORING_READ-gated + audited; webconsole row is metadata-only. Stdlib only — no new dep. VERIFIER REFUTED the 'needs a mypy type:ignore[attr-defined]' claim: this repo's typeshed declares _hashlib.get_fips_mode()->int, so it type-checks clean — do NOT add a spurious ignore (keep a runtime getattr-guard only for alt/non-OpenSSL builds, returning None='undeterminable'). VERIFIER OVER-CLAIM GAP: _hashlib/ssl attests CPython's linked OpenSSL, NOT the separately-linked OpenSSL inside pyca cryptography that actually encrypts PHI at rest — scope the report/UI wording to 'the interpreter's ssl/_hashlib OpenSSL' (or also query cryptography's backend). Doc/UI must say 'reported', not 'FIPS-140 certified'. Demand-gated: build only when the procurement/compliance trigger fires.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s11\`, branch \`claude/backlog-73-fips-attestation\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
