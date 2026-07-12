# PLAN-11 · Wave 16 · Log-search presets + PHI export (split half B)

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `log-search-presets-export` |
| **Wave** | 16 |
| **Status** | **○ Not started** |
| **Effort** | 10 |
| **Backlog items** | #151 · #124 |
| **ADR** | Yes — #151 preset table. |
| **Store schema / 3-backend** | Yes — #151. |

## Items

| Item | Title | Status |
|---|---|---|
| #151 | Saved / layered Log-Search filter presets | ○ open |
| #124 | Batch-export message bodies from a connection log to a file | ○ open |

## Owned files / seams

store triad, `api/app.py`, `api/models.py`, `api/security.py`, `console/search.py`, `console/widgets.py`, `webconsole/routes/search.py`, `webconsole/pages/messages.py`

## Dependencies

Split half B of the oversized log-search session; W16 is the earliest store-triad-clean slot after W7, so the two split halves never share a wave. File-disjoint from handler-sandbox.

## Notes & gotchas

**PHI-heavy mass export (#124) — keep per-view audit.**

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
