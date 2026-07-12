# PLAN-11 · Wave 2 · IDE code-set editors

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `ide-code-sets-editors` |
| **Wave** | 2 |
| **Status** | **🚧 Partially built** |
| **Effort** | 9 |
| **Backlog items** | #161 · #162 · #175 |
| **ADR** | Yes — #162 amends ADR 0033. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #161 | Code-set editor in-grid row search | ✅ shipped #921 |
| #162 | Unmapped-value policy on code-set lookups | ○ open |
| #175 | Clone-a-connection editor action | ✅ shipped #921 |

## Owned files / seams

`ide/src/codeSetEditor.ts`, `ide/src/codesetsTree.ts`, `ide/src/connectionEditor.ts`, `ide/src/connectionsTree.ts`, `__main__.py`, `config/code_sets.py`, `config/codeset_edit.py`, `config/reference.py`, `pipeline/reference_sync.py`

## Dependencies

None. Waved off W1 config-reachability + W5 console-display, which also touch the editor `.ts`.

## Notes & gotchas

**#161 (in-grid row search) + #175 (clone-a-connection) ✅ shipped (#921, TypeScript-only).** Remaining: #162 (unmapped-value policy on code-set lookups — the ADR-0033-amending item). Owns W2 `__main__.py`.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
