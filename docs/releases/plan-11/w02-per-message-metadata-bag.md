# PLAN-11 · Wave 2 · Author-appendable per-message history (on the shipped bag)

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `per-message-metadata-bag` |
| **Wave** | 2 |
| **Status** | **🚧 Partially built** |
| **Effort** | 5 |
| **Backlog items** | #150 · #169 |
| **ADR** | ADR 0081 (Accepted; the bag is shipped). |
| **Store schema / 3-backend** | Yes — bag merge verified on SQLite + SQL Server + Postgres (shipped). |

## Items

| Item | Title | Status |
|---|---|---|
| #150 | User-writable per-message metadata bag | ↪️ deferred → PLAN-10 **METADATA** · ✅ shipped #894 |
| #169 | Author-appendable per-message processing history | ○ open |

## Owned files / seams

store triad, `api/app.py`, `api/models.py`, `console/search.py`, webconsole messages

## Dependencies

#169 builds on the shipped `SetMeta` bag (#150/ADR 0081, #894) — dependency **satisfied**.

## Notes & gotchas

#150 was delivered by PLAN-10 METADATA (#894); this session's remaining work is #169 (append-history). #167 (W6) is likewise unblocked.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
