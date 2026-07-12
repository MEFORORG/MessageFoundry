# PLAN-11 · Wave 8 · TLS / PKI transport enforcement

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `tls-pki-security` |
| **Wave** | 8 |
| **Status** | **🚧 Partially built** |
| **Effort** | 17 |
| **Backlog items** | #200 · #99 · #129 |
| **ADR** | 0083 (mTLS identity) · **0092** (#200 transport-refusal) · **0094** (#129 expiry relaxation). |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #200 | Transport enforcement: make the code refuse the insecure hop | 🚧 mostly shipped — ADR 0083 mTLS-identity + fail-closed off-loopback gate (#906/#911) + **posture-keyed transport-refusal tail (#954, ADR 0092)**; residual integration-test / audit-event / runtime-KEX open |
| #99 | AD/gMSA production-deployment hardening (turnkey Windows/AD install) | 🚧 partial — turnkey polish shipped #965 (installer gMSA preflight + `-AllowLocalSystem` opt-out + IIS/ARR ref + integrated/gMSA docs); domain-lab smoke (e) + cert-store key sourcing (c) → Wave 19 / scoped out |
| #129 | Granular 'Allow Expired Certificate' TLS relaxation | ✅ shipped #965 (ADR 0094) — per-connection `tls_allow_expired`, `X509_V_FLAG_NO_CHECK_TIME`, chain+hostname still validated |

## Owned files / seams

`api/app.py`, `api/tls.py`, `api/security.py`, `config/settings.py`, `config/tls_policy.py`, `config/models.py`, `__main__.py`, `transports/{mllp,remotefile,rest,fhir,soap,dicom}.py`, `scripts/service/install-service.ps1`, `webconsole/`

## Dependencies

None. Solo in W8 to hold `api/tls.py` + `tls_policy.py`; waved before crypto-integrity (W9), which also touches them.

## Notes & gotchas

**Progress:** #200 mostly shipped (ADR 0083 mTLS identity + fail-closed gate #906/#911 + posture-keyed transport-refusal tail #954/ADR 0092); **#129 ✅ shipped 2026-07-12 (#965, ADR 0094)** — a per-connection `tls_allow_expired` that ORs OpenSSL `X509_V_FLAG_NO_CHECK_TIME` onto an already-verifying context (chain + hostname still validate; NOT an insecure hop, so ADR 0092 never refuses it; default off = byte-identical); **#99 🚧 partial (#965)** — turnkey polish shipped, the domain-lab smoke and Windows cert-store *private-key* sourcing honestly deferred (Wave 19 / stdlib-infeasible, mirrors the #190 ECH scope-out). **Remaining: #200 residuals + the #99 domain-lab validation (Wave 19).**

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
