# PLAN-11 · Wave 12 · Alert mute / connection-control actions (alert wave 2/4)

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `alert-events-mute-actions` |
| **Wave** | 12 |
| **Status** | **○ Not started** |
| **Effort** | 6 |
| **Backlog items** | #144 · #143 |
| **ADR** | Yes — #144 lifecycle seam. |
| **Store schema / 3-backend** | Yes — #143 `suspend_until`. |

## Items

| Item | Title | Status |
|---|---|---|
| #144 | Alert-triggered connection-control action | ↪️ deferred → PLAN-10 **ALERTS-OPS** · not yet merged |
| #143 | Alert suspend / mute (windowed) | ○ open |

## Owned files / seams

`config/settings.py`, `pipeline/alerts.py`, `pipeline/alert_sinks.py`, `pipeline/wiring_runner.py`, `api/app.py`, `api/models.py`, store triad, `console/alerts_page.py`, `console/client.py`, `webconsole/pages/monitoring.py`

## Dependencies

#144 deferred to PLAN-10 ALERTS-OPS; this session builds **#143 only**. Second alert wave; solo W12.

## Notes & gotchas

#143 = windowed alert suspend/mute.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
