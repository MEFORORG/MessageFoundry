# PLAN-11 · Wave 6 · IDE Test Bench cluster

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `ide-test-bench` |
| **Wave** | 6 |
| **Status** | **○ Not started** |
| **Effort** | 12 |
| **Backlog items** | #84 · #167 · #168 · #132 |
| **ADR** | No. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #84 | Diagnostic panes — hex body view + HL7-aware before/after diff + profiling/coverage | ○ open |
| #167 | Test Bench metadata seeding | ○ open |
| #168 | Test Bench saved regression collections | ○ open |
| #132 | Fixed 'now' test-time override (frozen clock for reproducible transform tests) | ○ open |

## Owned files / seams

`ide/src/hl7diff.ts`, `testBench.ts`, `traceView.ts`, `testBenchCollections.ts`, `ide/package.json`, `console/widgets.py`, `parsing/binary.py`, `pipeline/dryrun.py`, `api/app.py`, `__main__.py`, `checks.py`

## Dependencies

#167 needs the per-message-metadata bag — **satisfied** (#150/ADR 0081 shipped #894). Still sequence to W6 for `__main__.py` / `api/app.py` contention.

## Notes & gotchas

Owns W6 `__main__.py` + `dryrun.py` + `api/app.py`.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
