# PLAN-11 · Wave 10 · Filterable / exportable audit report + log viewer

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `audit-log-viewer` |
| **Wave** | 10 |
| **Status** | **🚧 Partially built** |
| **Effort** | 10 |
| **Backlog items** | #170 · #171 |
| **ADR** | No (additive, no ACK/engine seam). |
| **Store schema / 3-backend** | Yes — `list_audit` filter query. |

## Items

| Item | Title | Status |
|---|---|---|
| #170 | Filterable / exportable audit report | ✅ shipped #964 — actor/action/since/until filters on `list_audit` (3-backend, parameterized) + `GET /audit` + `GET /audit/export` CSV behind `audit:export`, PHI-safe columns, CSV formula-injection neutralized (`_csv_safe`), self-audited export |
| #171 | Runtime log-verbosity control + in-product log viewer | ○ open (weak-provenance; deferred) |

## Owned files / seams

store triad, `api/auth_routes.py`, `api/auth_models.py`, `api/_ui_seam.py`, `api/app.py`, `api/models.py`, `logging_setup.py`, `config/settings.py`, `support/bundle.py`, `console/event_log_page.py`, `console/client.py`, `console/shell.py`, `console/log_viewer_page.py`, `webconsole/{pages,routes}/{audit,monitoring}.py`

## Dependencies

None. Solo W10.

## Notes & gotchas

**#170 ✅ shipped 2026-07-12 (#964).** Gotcha that surfaced: the `GET /audit` route function is passed directly into `AdminHandlers` and the webconsole `/ui/audit` page calls it **in-process**, so new `Query(...)`-default filter params leaked into the SQLite bind ("type Query is not supported") — fixed by extracting a plain-default `_audit_list` core + a plain `_audit_ui_list(service, _, limit)` seam wrapper (the route keeps its `Query(...)` validation). Direct **SQL Server + Postgres** filter-assertion tests → PLAN-11 Wave 19. #171 remains open (weak-provenance). Additive; no ACK/engine seam.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
