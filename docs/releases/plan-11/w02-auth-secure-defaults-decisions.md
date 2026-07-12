# PLAN-11 · Wave 2 · Auth secure-default decisions

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `auth-secure-defaults-decisions` |
| **Wave** | 2 |
| **Status** | **🚧 Partially built** |
| **Effort** | 12 |
| **Backlog items** | #189 · #193 · #203 · #98 |
| **ADR** | Yes — #189 default-flip, #98 EPA. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #189 | Validation + dual-control defaults | ✅ shipped #898 (PLAN-9 Wave 2) |
| #193 | Anti-automation: human-timing / minimum-inter-submission pacing floor | ✅ shipped #902 (PLAN-9 Wave 2) |
| #203 | Delegated identity + admin device posture: enforce or state the precondition | ✅ shipped #920 (opt-in precondition + delegation-boundary doc) |
| #98 | Kerberos SSO channel-binding (EPA) opt-in + acceptor-enforcement spike | ○ open |

## Owned files / seams

`config/settings.py`, `config/models.py`, `api/approvals.py`, `api/security.py`, `auth/service.py`, `auth/ldap.py`, `webconsole/routes/sso.py`, `docs/SECURITY.md`, `docs/security/*`

## Dependencies

None beyond wave serialization.

## Notes & gotchas

#189 ✅ (#898, dual-control-at-exposure warn gate + ASVS 2.2.1/2.2.3 signed deviation), #193 ✅ (#902), and #203 ✅ (#920, opt-in delegated-identity precondition + delegation-boundary doc) shipped. **Remaining: #98 (Kerberos EPA) only.** Owns W2 settings + models + `docs/SECURITY.md`.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
