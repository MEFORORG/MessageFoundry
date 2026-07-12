# PLAN-11 · Wave 1 · MLLP / TCP outbound delivery polish

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `mllp-tcp-outbound-delivery` |
| **Wave** | 1 |
| **Status** | **○ Not started** |
| **Effort** | 13 |
| **Backlog items** | #82 · #97 · #117 · #136 |
| **ADR** | Yes — #117 delivery-confirmation contract. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #82 | Sender transport-polish bundle — pacing · MSA-2↔MSH-10 matching · TCP keep-alive | ↪️ deferred → PLAN-10 **SENDER** · not yet merged |
| #97 | Keep-alive / persistent outbound connections | ○ open |
| #117 | Sender no-wait-for-ACK (fire-and-forward) option | ○ open |
| #136 | 'Waiting for Reply' per-message connection state + display delay | ○ open |

## Owned files / seams

`transports/mllp.py`, `transports/tcp.py`, `transports/x12.py`, `config/models.py`, `api/app.py`, `api/models.py`, `console/status.py`, `console/connections.py`

## Dependencies

Rebase on the PLAN-10 **SENDER** lane, which delivers #82 (ACK-matching fix) and owns `mllp.py`. All four items contend on `mllp.py`.

## Notes & gotchas

`#82` is deferred to PLAN-10 SENDER; this session builds #97/#117/#136. Owns the W1 `config/models.py` + `api/app.py` slot.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
