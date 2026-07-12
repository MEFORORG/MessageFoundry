# PLAN-11 · Wave 5 · Console display flags & theming

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `console-display-flags-theme` |
| **Wave** | 5 |
| **Status** | **○ Not started** |
| **Effort** | 12 |
| **Backlog items** | #137 · #164 · #133 · #131 |
| **ADR** | No (presentation-only). |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #137 | Configurable server display name in the operator console | ○ open |
| #164 | Console dark-mode / theming | ○ open |
| #133 | User-chosen display colour on configuration objects | ○ open |
| #131 | Object flagging — mark objects of interest + a Flagged Objects filter | ○ open |

## Owned files / seams

`console/shell.py`, `console/widgets.py`, `console/theme.py`, `console/connections.py`, `config/models.py`, `api/models.py`, `api/app.py`, `webconsole/pages/connections.py`, `ide/src/connectionEditor.ts`

## Dependencies

None. File-disjoint from streaming in W5.

## Notes & gotchas

Presentation-only. #131/#133 both add display fields to `config/models.py` + `api/models.py` (co-located).

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
