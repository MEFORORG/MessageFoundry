# PLAN-11 · Wave 15 · Shared-by-name message queues

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `shared-named-queues` |
| **Wave** | 15 |
| **Status** | **○ Not started** |
| **Effort** | 9 |
| **Backlog items** | #130 |
| **ADR** | Yes. |
| **Store schema / 3-backend** | Yes — preserves per-lane FIFO (not a channel element). |

## Items

| Item | Title | Status |
|---|---|---|
| #130 | Message queues shared by name across connections + shared-name delete protection | ○ open |

## Owned files / seams

store triad, `config/wiring.py`, `config/models.py`, `pipeline/wiring_runner.py`

## Dependencies

None. Owns W15 store-triad + wiring, disjoint from ai-assist.

## Notes & gotchas

Preserve per-lane FIFO; this is **not** a 'channel'/'route' element (§1 / §12 of CLAUDE.md).

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
