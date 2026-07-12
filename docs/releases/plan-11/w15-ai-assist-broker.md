# PLAN-11 · Wave 15 · Engine-brokered AI assistance

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `ai-assist-broker` |
| **Wave** | 15 |
| **Status** | **○ Not started** |
| **Effort** | 7 |
| **Backlog items** | #95 |
| **ADR** | Yes — design forks; verify any new SDK dep. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #95 | Engine-brokered AI assistance | ○ open |

## Owned files / seams

`api/app.py`, `api/models.py`, `config/settings.py`, `config/ai_policy.py`, `transports/ai_broker.py`, `auth/permissions.py`, `ide/src/{chat,aiPolicy,engineClient}.ts`, `docs/AI.md`

## Dependencies

None. Contends only on api/config hotspots → paired with shared-queues (store/wiring) in W15.

## Notes & gotchas

MVP assistant sends **code only** (`code_only`), never message bodies — see `docs/AI.md`.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
