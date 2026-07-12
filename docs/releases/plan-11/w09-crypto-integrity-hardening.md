# PLAN-11 · Wave 9 · PHI data-plane integrity defaults

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `crypto-integrity-hardening` |
| **Wave** | 9 |
| **Status** | **🚧 Partially built** |
| **Effort** | 8 |
| **Backlog items** | #190 |
| **ADR** | Yes. |
| **Store schema / 3-backend** | Yes — GCM counter + keyed audit chain. |

## Items

| Item | Title | Status |
|---|---|---|
| #190 | PHI data-plane integrity defaults: JWS signing, GCM rekey counter, keyed audit chain | 🚧 partial — GCM rekey counter + HMAC-keyed audit chain (#899); JWS signing remains |

## Owned files / seams

`store/crypto.py`, `store/base.py`, `store/store.py`, `store/postgres.py`, `store/sqlserver.py`, `store/keyprovider.py`, `transports/signing.py`, `config/settings.py`, `config/tls_policy.py`, `api/tls.py`

## Dependencies

None. Solo W9; isolated from tls-pki (W8) and the W4 `crypto.py` owner.

## Notes & gotchas

**#190 🚧 partially built** — GCM rekey counter + HMAC-keyed audit chain shipped (#899). **Remaining: JWS signing.**

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **3-backend tests (SQLite + Postgres + SQL Server / win2025 CI leg)** — this session touches the store schema.
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
