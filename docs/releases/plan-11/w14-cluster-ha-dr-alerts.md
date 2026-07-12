# PLAN-11 · Wave 14 · Cluster HA/DR + failover alerts (alert wave 4/4)

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `cluster-ha-dr-alerts` |
| **Wave** | 14 |
| **Status** | **○ Not started** |
| **Effort** | 5 |
| **Backlog items** | #101 · #145 |
| **ADR** | Yes — #145 AlertSink protocol method; #101 lease-race. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #101 | `[cluster]` leader preference / non-promotable standby | ○ open |
| #145 | HA / DR failover event alert | ↪️ deferred → PLAN-10 **ALERTS-OPS** · not yet merged |

## Owned files / seams

`config/settings.py`, `pipeline/cluster.py`, `pipeline/cluster_sqlserver.py`, `api/app.py`, `api/models.py`, `pipeline/alerts.py`, `pipeline/alert_sinks.py`, `pipeline/dr.py`

## Dependencies

#145 deferred to PLAN-10 ALERTS-OPS; this session builds **#101 only**. Fourth/final alert wave; solo W14. Both #101/#145 edit `cluster*.py`.

## Notes & gotchas

#101 = `[cluster]` leader preference / non-promotable standby.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
