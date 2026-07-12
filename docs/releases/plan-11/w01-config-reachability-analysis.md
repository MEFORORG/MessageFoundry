# PLAN-11 · Wave 1 · Reverse-reachability / dead-config analysis

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `config-reachability-analysis` |
| **Wave** | 1 |
| **Status** | **✅ Complete** |
| **Effort** | 10 |
| **Backlog items** | #176 · #152 |
| **ADR** | No new engine seam. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #176 | Unused-object (dead-config) detection | ✅ core merged #919 |
| #152 | Reverse-dependency / impact analysis | ✅ core merged #919 |

## Owned files / seams

`checks.py`, `config/wiring.py`, `config/reachability.py`, `config/codeset_edit.py`, `ide/src/graphTree.ts`, `ide/src/connectionEditor.ts`, `ide/src/codeSetEditor.ts`

## Dependencies

None. #176 is a strict subset of #152; both share the reverse-reachability index.

## Notes & gotchas

**CORE MERGED #919** (reverse-reachability index — dead-config advisory + referrers). Per-item ✅ banner-flip on #176/#152 may still be pending. Owned the W1 `config/wiring.py` + IDE editor slot.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
