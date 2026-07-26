# PLAN-13 · Wave 2 · #207 loose end 2 — bytes/msg (owner decision + new ADR)

> **Phase document** of [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md).

| | |
|---|---|
| **Session** | `harness-207-bytes-per-msg` |
| **Wave** | 2 |
| **Status** | 🔢 Not started — **owner bytes-proxy decision required** |
| **Effort** | 1.5 |
| **Backlog items** | #207 loose end 2 (closes #207) |
| **ADR** | **Yes — allocate a fresh number at build via `alloc.ps1`** (do NOT pre-pick); index row same commit. Any published byte figure REVERSES A2's recorded refusal |
| **Store schema / 3-backend** | No — the live measured value is SQL-Server-rig-only anyway |

## The work

`body_copies` is a **copy count, not bytes**, and A2 explicitly refused to publish a byte figure as "plausible-but-wrong".
Publish the **owner-ratified** proxy in `report.py`'s `EngineSummary` — one of: **copies/msg** (`body_copies`, clearly
labelled not-bytes, **backend-named**) · a **measured bytes/msg** = `db_size_bytes`-delta / `acked` (the "real figure" A2's
own test docstring names; `report.py` already half-computes `db_growth_bytes`) · a **per-backend byte estimate**. Bump
`SCHEMA_VERSION` 2→3; guard the Postgres-reads-0 case (None / "not measured").

**Allocate the ADR atomically at build time** (`pwsh -NoProfile -File scripts/coord/alloc.ps1 -Kind adr -Title "..."`)
pinning WHICH proxy is published + its caveats (backend-dependence, NVARCHAR UTF-16 ×2, cipher expansion, tx-log); add the
`docs/adr/README.md` index row in the **same** commit. Amend `tests/test_bytes_per_message_amplification.py` (2+H+N).

## Owned files / seams

`harness/load/report.py` · `tests/test_bytes_per_message_amplification.py` · `docs/adr/README.md` (NEW appended row) ·
`docs/BACKLOG.md` (#207 @6388).

## Dependencies / gate

**Gate:** `harness-207-txn-per-msg` MERGED (shared `report.py` — rebase over its `EngineSummary` + SCHEMA 1→2) **AND** an
OWNER decision on which bytes/msg proxy to publish. SQLite store-once-dedups an identical fan-out (1 copy) while SQL Server
writes N — a copies/msg proxy MUST name the backend (rig/prod is SQL Server).

## Verification — Definition of Done

- `ruff` + `ruff format --check`; `mypy` locally (advisory); `$env:QT_QPA_PLATFORM='offscreen'; pytest -q`.
- The alloc'd ADR + its README row land in the same commit; a pre-commit hook rejects a number you did not allocate.
- Flips #207 banner ✅. **No `Co-Authored-By: Claude` trailer**; owner approves PR.

---
_Authored 2026-07-17 against `origin/main` @ `be1fbbab`._
