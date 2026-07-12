# PLAN-11 · Wave 4 · Auth audit / secret-rotation / RBAC

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `auth-audit-rotation-rbac` |
| **Wave** | 4 |
| **Status** | **🚧 Partially built** |
| **Effort** | 8 |
| **Backlog items** | #195 · #177 |
| **ADR** | Yes — #195 rotation policy. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #195 | Audit completeness: log all authorization decisions; enforce secret rotation | ✅ shipped #902 (#195a) + #904 (#195b) (PLAN-9 Wave 2) |
| #177 | Effective-permission inspector for a user | ○ open |

## Owned files / seams

`api/security.py`, `auth/service.py`, `config/settings.py`, `store/crypto.py`, `store/keyprovider.py`, `pipeline/leader_tasks.py`, `pipeline/cert_expiry.py`, `api/auth_routes.py`, `api/auth_models.py`, `api/models.py`, `auth/identity.py`, `console/users_page.py`, `__main__.py`

## Dependencies

None beyond wave serialization. Waved off #190 (`crypto.py`, W9) + #197 (`crypto.py`, W16).

## Notes & gotchas

**#195 ✅ both halves shipped via PLAN-9 Wave 2** (#195a authorization-grant audit twin #902 + #195b secret-rotation reminder #904). **Remaining: #177 (effective-permission inspector).** Owns W4 settings + security + service + `__main__.py`.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
