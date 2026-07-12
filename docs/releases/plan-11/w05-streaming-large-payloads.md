# PLAN-11 · Wave 5 · Streaming path for very-large messages

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `streaming-large-payloads` |
| **Wave** | 5 |
| **Status** | **○ Not started** |
| **Effort** | 9 |
| **Backlog items** | #149 |
| **ADR** | Yes — touches ACK-on-receipt + the reliability invariant. |
| **Store schema / 3-backend** | Yes — chunked BLOB. |

## Items

| Item | Title | Status |
|---|---|---|
| #149 | Streaming path for very-large single messages | ○ open |

## Owned files / seams

`transports/mllp.py`, `store/store.py`, `store/sqlserver.py`, `store/base.py`, `store/postgres.py`, `pipeline/wiring_runner.py`, `config/settings.py`, `parsing/split.py`

## Dependencies

None. Runs effectively alone in W5 (invariant-bearing hotspots).

## Notes & gotchas

**Do not weaken the at-least-once / strict-FIFO / ACK-after-ingress invariant.**

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
