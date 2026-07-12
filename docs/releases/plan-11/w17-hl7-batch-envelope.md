# PLAN-11 · Wave 17 · Outbound batch aggregation (DEFERRED → PLAN-10 BATCH)

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `hl7-batch-envelope` |
| **Wave** | 17 |
| **Status** | **↪️ Deferred (session removed)** |
| **Effort** | — |
| **Backlog items** | #134 |
| **ADR** | ADR 0082 (Accepted; delivered by PLAN-10 #900). |
| **Store schema / 3-backend** | — |

## Items

| Item | Title | Status |
|---|---|---|
| #134 | Outbound batch aggregation — N messages into one BHS/BTS envelope on send | ↪️ deferred → PLAN-10 **BATCH** · ✅ shipped #900 |

## Owned files / seams

— (session removed)

## Dependencies

Entire session deferred to PLAN-10's BATCH lane.

## Notes & gotchas

**Entire session deferred; W17 vacated.** #134 has since **shipped via PLAN-10 (#900, ADR 0082)** — this doc is retained only as the deferral record. Do not open a second PR against `BACKLOG #134`.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
