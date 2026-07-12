# PLAN-11 · Wave 3 · HL7 decode / serialize seam

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `hl7-parsing-serialization` |
| **Wave** | 3 |
| **Status** | **🚧 Partially built** |
| **Effort** | 8 |
| **Backlog items** | #107 · #108 · #89 |
| **ADR** | Yes — #107 parsing-contract. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #107 | Override HL7 v2 escape sequences | ○ open |
| #108 | Receiver-side 'Prefer BOM if present' encoding auto-detect | ○ open |
| #89 | hl7apy security hardening — dormant-upstream contingency + fuzz the strict-validate path | ✅ merged #891 (PLAN-9 Wave 1) |

## Owned files / seams

`parsing/message.py`, `parsing/_builtin_hl7.py`, `parsing/peek.py`, `parsing/validate.py`, `config/models.py`, `config/wiring.py`, `pipeline/wiring_runner.py`, `transports/mllp.py`

## Dependencies

None beyond wave serialization.

## Notes & gotchas

**#89 already merged (#891, PLAN-9 Wave 1) — residual only.** Remaining: #107 (escape-sequence override) + #108 (BOM auto-detect). Owns W3 `wiring_runner.py` + models + `mllp.py` + wiring slot.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
