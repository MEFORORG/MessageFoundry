# PLAN-11 · Wave 1 · Application-log retention & lifecycle

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `log-retention-lifecycle` |
| **Wave** | 1 |
| **Status** | **🚧 Partially built** |
| **Effort** | 15 |
| **Backlog items** | #120 · #122 · #179 |
| **ADR** | Yes — #179 copy-then-purge. |
| **Store schema / 3-backend** | Yes — #179 archive. |

## Items

| Item | Title | Status |
|---|---|---|
| #120 | Application log-file retention (auto-delete after N days) | ✅ shipped #922 |
| #122 | Corrupted application-log detection, rollover, and connection-stop | ○ open |
| #179 | Archive-aged-rows to separate store | ○ open |

## Owned files / seams

`pipeline/retention.py`, `logging_setup.py`, `config/settings.py`, `pipeline/alerts.py`, store triad (`store.py`/`base.py`/`sqlserver.py`/`postgres.py`), `pipeline/engine.py`

## Dependencies

None beyond wave serialization. May also take `wiring_runner.py` for the #122 connection-stop hook (no W1 sibling touches it).

## Notes & gotchas

**#120 ✅ shipped (#922) — auto-delete app logs after N days.** Remaining: #122 (corrupted-log detection/rollover/connection-stop) + #179 (archive-aged-rows). Sole W1 owner of `alerts.py` + settings + store-triad.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
