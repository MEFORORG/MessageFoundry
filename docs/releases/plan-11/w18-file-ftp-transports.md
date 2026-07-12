# PLAN-11 · Wave 18 · File / FTP transport cluster

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `file-ftp-transports` |
| **Wave** | 18 |
| **Status** | **○ Not started** |
| **Effort** | 17 |
| **Backlog items** | #114 · #142 · #111 · #172 |
| **ADR** | Yes — #142 processed-file ledger, #111 SMB dep. |
| **Store schema / 3-backend** | Yes — #142. |

## Items

| Item | Title | Status |
|---|---|---|
| #114 | Directory validation toggle (perform vs suppress startup validation) | ○ open |
| #142 | 'Leave source file' — process-in-place file/FTP source disposition | ○ open |
| #111 | File-endpoint alternate Windows / network-share credentials | ○ open |
| #172 | Gzip/zip compression codec + file-connector option | ○ open |

## Owned files / seams

`transports/file.py`, `transports/remotefile.py`, `pipeline/wiring_runner.py`, store triad, `config/models.py`, `config/settings.py`, `parsing/compress.py`, `pyproject.toml`, `requirements.lock`, `docs/CONNECTIONS.md`

## Dependencies

None. Own final wave — every item edits `transports/file.py`; file + store + settings + pyproject all hot.

## Notes & gotchas

**Do not weaken the reliability invariant** for the #142 processed-file ledger.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
