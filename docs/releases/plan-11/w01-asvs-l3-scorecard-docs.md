# PLAN-11 · Wave 1 · ASVS L3 scorecard owner-decisions (zero code)

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `asvs-l3-scorecard-docs` |
| **Wave** | 1 |
| **Status** | **○ Not started** |
| **Effort** | 2 |
| **Backlog items** | #191 · #205 |
| **ADR** | No (owner decisions / docs only). |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #191 | SMART/OAuth outbound: exercise the built path, or scope it out | ○ open |
| #205 | Documented risk acceptances (ASVS L3 residuals) | ○ open |

## Owned files / seams

`docs/security/ASVS-L3-*`, `docs/SECURITY.md`, `docs/BACKLOG.md`

## Dependencies

None. Both are owner calls, not builds — resolve them first to close the session.

## Notes & gotchas

Zero code: #191 = scope-out-or-exercise the SMART/OAuth outbound path; #205 = sign the ASVS L3 risk-acceptance record (residuals stay Partial/Fail). Sole W1 owner of the ASVS scorecard + `docs/SECURITY.md`.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
