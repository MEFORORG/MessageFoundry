# PLAN-11 · Wave 6 · Connector & store-backend breadth

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `connector-store-backend-breadth` |
| **Wave** | 6 |
| **Status** | **🚧 Partially built** — #66 + #45 shipped; #160 dropped |
| **Effort** | 12 |
| **Backlog items** | #66 · #160 · #45 |
| **ADR** | No (dep-adding — verify deps first). |
| **Store schema / 3-backend** | Touches `store/sqlserver.py`. |

## Items

| Item | Title | Status |
|---|---|---|
| #66 | Non-SQL-Server database connectors (Postgres / Oracle / MySQL / ODBC DSN) | ✅ shipped #969 — generic-ODBC dialect (no new Python dep; SQL-Server preset byte-identical); native async drivers scoped out |
| #160 | Timer-source cron / calendar schedule | ⛔ dropped — clean code-first time-filter workaround; #147 scheduler shipped adjacent |
| #45 | Per-store TLS CA-file knob for server-DB backends | ✅ shipped #969 — SQL Server `ServerCertificate` slice (Postgres half prior); never weakens verification |

## Owned files / seams

`transports/database.py`, `transports/timer.py`, `store/sqlserver.py`, `config/models.py`, `config/settings.py`, `pyproject.toml`, `requirements.lock`, `docs/CONNECTIONS.md`, `docs/CONFIGURATION.md`

## Dependencies

None. **Dep-adding (#66 drivers, #160 croniter) — verify each dependency exists before adding, then re-lock.**

## Notes & gotchas

Owns W6 pyproject/lock + settings + `sqlserver.py`.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
