# PLAN-11 · Wave 16 · Runtime sandbox for admin-authored Router/Handler code

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `handler-sandbox-isolation` |
| **Wave** | 16 |
| **Status** | **✅ Complete** |
| **Effort** | 9 |
| **Backlog items** | #197 |
| **ADR** | ADR 0087 (shipped). |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #197 | Runtime sandbox for admin-authored Router/Handler code | ✅ shipped #917 (ADR 0087) |

## Owned files / seams

`pipeline/wiring_runner.py`, `pipeline/dryrun.py`, `config/wiring.py`, `store/crypto.py`, `config/settings.py`, `docs/THREAT-MODEL.md`

## Dependencies

None. Isolated from shared-queues (`wiring_runner.py`) + crypto (`crypto.py`). Disjoint from the W16 log-search session.

## Notes & gotchas

**SHIPPED 2026-07-10 (ADR 0087, PR #917)** — opt-in `[sandbox]` per-inbound subprocess isolation (`mode=off` default, byte-identical; `mode=subprocess` persistent worker child). Closes the WP-L3-17 (ASVS 15.2.5) residual. Session complete.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
