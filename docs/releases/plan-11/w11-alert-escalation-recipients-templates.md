# PLAN-11 · Wave 11 · Alert escalation / recipients / templates (alert wave 1/4)

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `alert-escalation-recipients-templates` |
| **Wave** | 11 |
| **Status** | **○ Not started** |
| **Effort** | 13 |
| **Backlog items** | #81 · #146 · #138 |
| **ADR** | Yes — #81 escalation state machine. |
| **Store schema / 3-backend** | Yes — #81 `alert_instance` (add `postgres.py`). |

## Items

| Item | Title | Status |
|---|---|---|
| #81 | Alert escalation tiers + day/time thresholds + content (Action-Point) alerting | ○ open |
| #146 | Per-rule alert recipients | ○ open |
| #138 | Customisable alert-email subject and body templates | ○ open |

## Owned files / seams

`pipeline/alerts.py`, `pipeline/alert_sinks.py`, `config/settings.py`, `store/store.py`, `store/sqlserver.py`, `store/base.py`, `store/postgres.py`, `api/app.py`, `api/models.py`, `console/alerts_page.py`

## Dependencies

First of four serialized alert waves (W11–W14); `alerts.py`/`alert_sinks.py`/`AlertRule` are co-touched by every alert item, so they cannot overlap.

## Notes & gotchas

#138 (email templates) is a decline-overturned demand-gate.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
