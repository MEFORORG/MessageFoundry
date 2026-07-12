# PLAN-11 · Wave 7 · Uploaded-logs console page (split half A)

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `log-uploaded-files-console` |
| **Wave** | 7 |
| **Status** | **○ Not started** |
| **Effort** | 10 |
| **Backlog items** | #125 · #126 |
| **ADR** | Yes — #125 where uploaded logs live. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #125 | Uploaded Logs page — import external message files and browse them offline | ○ open |
| #126 | Delete an uploaded data file from the server | ○ open |

## Owned files / seams

`api/app.py`, `api/models.py`, `auth/permissions.py`, `console/shell.py`, `console/widgets.py`, `console/event_log_page.py`, `parsing/split.py`, `webconsole/mount.py`, `webconsole/pages/messages.py`, `webconsole/routes/search.py`

## Dependencies

#126 (delete uploaded file) hard-depends on #125 (uploaded-logs page) — intra-session order.

## Notes & gotchas

Split half A of the oversized log-search session; disjoint from connection-lifecycle in W7. (Half B = `log-search-presets-export`, W16 — must not share a wave.)

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
