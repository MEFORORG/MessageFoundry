# PLAN-11 · Wave 4 · HTTP outbound proxy / per-message headers

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `http-outbound-connectors` |
| **Wave** | 4 |
| **Status** | **○ Not started** |
| **Effort** | 14 |
| **Backlog items** | #112 · #127 · #68 |
| **ADR** | Yes — #68 per-message carry. |
| **Store schema / 3-backend** | Yes — #68. |

## Items

| Item | Title | Status |
|---|---|---|
| #112 | Outbound forward web-proxy address ('Use Default Web Proxy') | ○ open |
| #127 | Web-proxy credential types (Basic / Digest / NTLM / Windows) | ○ open |
| #68 | Dynamic per-message outbound HTTP headers | ○ open |

## Owned files / seams

`transports/rest.py`, `soap.py`, `fhir.py`, `smart.py`, `dicomweb.py`, `config/models.py`, `config/wiring.py`, `pipeline/wiring_runner.py`, `store/store.py`, `store/postgres.py`, `store/sqlserver.py`

## Dependencies

#127 (proxy credential types) depends on #112 (proxy address) — intra-session order.

## Notes & gotchas

Owns W4 store-triad + models + `wiring_runner.py`.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
