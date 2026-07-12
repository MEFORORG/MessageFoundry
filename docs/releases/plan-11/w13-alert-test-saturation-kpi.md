# PLAN-11 · Wave 13 · Alert-mail test + saturation KPI (alert wave 3/4)

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `alert-test-saturation-kpi` |
| **Wave** | 13 |
| **Status** | **○ Not started** |
| **Effort** | 8 |
| **Backlog items** | #118 · #93 |
| **ADR** | Yes — #93 saturation dimension (vs declined ADR 0014). |
| **Store schema / 3-backend** | Touches `store/store.py` + `pool_metrics.py`. |

## Items

| Item | Title | Status |
|---|---|---|
| #118 | Test the alert mail server (send test email / SMTP verification) | ↪️ deferred → PLAN-10 **ALERTS-OPS** · not yet merged |
| #93 | Engine + database performance monitoring — volume/connection KPI + saturation alert | ○ open |

## Owned files / seams

`api/app.py`, `api/models.py`, `pipeline/alert_sinks.py`, `pipeline/alerts.py`, `config/settings.py`, `pipeline/wiring_runner.py`, `store/store.py`, `store/pool_metrics.py`, `api/metrics.py`, `console/status.py`, `console/alerts_page.py`, `webconsole/`

## Dependencies

#118 deferred to PLAN-10 ALERTS-OPS; this session builds **#93 only**. Third alert wave; solo W13.

## Notes & gotchas

#93 = engine-wide volume/connection KPI roll-up + throughput-overload (saturation) alert.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
