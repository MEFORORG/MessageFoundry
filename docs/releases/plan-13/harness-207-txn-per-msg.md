# PLAN-13 · Wave 1 · #207 loose end 1 — rendered MEASURED txn/msg

> **Phase document** of [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md).

| | |
|---|---|
| **Session** | `harness-207-txn-per-msg` |
| **Wave** | 1 |
| **Status** | 🚧 In progress (lane `plan13-harness-207-txn`, worktree off `origin/main`; build→adversarial-verify dispatched 2026-07-20). |
| **Effort** | 1.5 |
| **Backlog items** | #207 loose end 1 (measured txn/msg) |
| **ADR** | No — governed by **existing ADR 0051** (the `txn/msg = 3+2H+2N` cost model); renders an already-defined currency |
| **Store schema / 3-backend** | No — the store-side counters already ship (A1 PR #909/#862) |

## Step 0 — claim the item (🚧, before any code)

Per [master §D](../MULTISESSION-PLAN-13.md#d-coordination-rules--gotchas): this session is the **W1 banner owner for #207**.
Before writing code, commit a **🚧 in-progress claim** on #207 in `docs/BACKLOG.md` (its own commit), naming the lane —
`> 🚧 **Status — in progress (lane `plan13-harness-207-txn`, branch off `origin/main`).**`. **Defer the ✅ close** to the
W2 `harness-207-bytes-per-msg` session (which resolves the owner bytes/msg decision); this session leaves the banner at 🚧.

## The work

The live `committed_txns` counter is collected end-to-end (store → `/stats` → `EngineSample.committed_txns` → `poller.final`)
but no report divides a `committed_txns` delta by the run message count — the only `txn_per_message` rendered is the
**analytical** `3+2H+2D` formula. Wire a **measured** figure beside it, on the clean, self-differencing `report.py` surface.

1. In `harness/load/report.py`'s `EngineSummary` add `committed_txns` (delta) + `txn_per_message_measured` (float | None).
   `_engine_summary()` already differences `db_size_bytes` and `out_dead` — add `committed_txns = final − base` and derive
   the per-message figure against the run message count (`Counters.acked`, threaded in), rendering it **beside** the
   analytical formula on `to_json_dict['engine_side']` + `render_console()`; bump `SCHEMA_VERSION` 1→2.
2. **Postgres reads 0** (never wired) → render None / "not measured", **never a fabricated 0/msg** (guard test).

## Owned files / seams

`harness/load/report.py` (`EngineSummary`, `_engine_summary`, `to_json_dict`, `render_console`, `SCHEMA_VERSION`) ·
`harness/load/enginepoll.py` (`EngineSample` already carries `committed_txns`/`db_size_bytes` — no change expected) ·
`tests/test_load_report.py` · `tests/test_enginepoll_aggregate.py` · `tests/test_txn_per_message_cost_model.py` (weld the
rendered measured figure to the model) · `tests/test_live_cost_counters.py` (end-to-end SQLite drive at (1,1)/(8,8)/(20,4)).

## Explicitly NOT

- **Claims #207 (🚧, Step 0) but does NOT flip it ✅** — #207 stays at 🚧 until loose end 2 (`harness-207-bytes-per-msg`,
  W2) resolves the owner bytes/msg decision that closes the item.
- The two-box shardcert **ladder** measured figure is **excluded** (heavier/higher-contention; its files are owned by
  harness-229 this wave). `harness/load/report.py` **≠** `harness/load/connscale/report.py`.

## Dependencies

None — the store-side `committed_txns`/`body_copies` counters already ship on `/stats` → `EngineSample`.

## Verification — Definition of Done

- `ruff` + `ruff format --check`; `mypy` locally (advisory); `$env:QT_QPA_PLATFORM='offscreen'; pytest -q`.
- B-class ethos: a wrong parity counter must be caught by welding to the model test; the first published value is
  ULTRACODE-verified where reported.
- **No `Co-Authored-By: Claude` trailer**; owner approves PR.

---
_Authored 2026-07-17 against `origin/main` @ `be1fbbab`._
