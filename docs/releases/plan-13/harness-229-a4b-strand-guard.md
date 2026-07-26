# PLAN-13 · Wave 1 · #229 — per-stage strand breakdown for a sound H>D permit

> **Phase document** of [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md).

| | |
|---|---|
| **Session** | `harness-229-a4b-strand-guard` |
| **Wave** | 1 |
| **Status** | 🚧 In progress (lane `plan13-harness-229`, worktree off `origin/main`; build→adversarial-verify dispatched 2026-07-20). |
| **Effort** | 2 |
| **Backlog items** | #229 |
| **ADR** | No — bench-internal precision fix under ADR 0073 + the #209/#219 A4b lineage; bump `schema_version` 7→8 per file convention |
| **Store schema / 3-backend** | No — pure-function change, unit-tested without a DB |

## Step 0 — claim the item (🚧, before any code)

Per [master §D](../MULTISESSION-PLAN-13.md#d-coordination-rules--gotchas): this session is the **W1 banner owner for #229**.
Before writing code, commit a **🚧 in-progress claim** on #229 in `docs/BACKLOG.md` (its own commit), naming the lane —
`> 🚧 **Status — in progress (lane `plan13-harness-229`, branch off `origin/main`).**`. It stops a sibling worktree (or
the live `-harness-ratefix` line) double-building #229. Flip 🚧 → ✅ per *Definition of Done*.

## The work

The A4b cross-observer guard (`observers_inconclusive`) keys on `delivering` (D) and credits an `A×(H−D)` non-delivering
`free` budget (#209), but applies it **stage-blind** to the opaque `stranded + dead` total on the under-counting branch.

1. Factor a **pure `_summarize_queue_rows(rows)` helper** out of `_queue_breakdown`'s existing `GROUP BY stage, status`
   scan (unit-testable, no DB) splitting per-stage non-terminal **and** dead counts (dead rows keep their stage — split
   both).
2. Thread `ingress_stranded` / `routed_stranded` / `outbound_stranded` onto **BOTH** the `ENGINE_DRAINED` gate payload
   **and** the `ENGINE_RUNG_REPORT` payload + `ShardCertEngineReport` (a gate-only thread leaves the report-fallback path
   stage-blind). Read them in `build_rung_outcome` with a **`<0` sentinel default** (older payload → byte-identical
   opaque-total fallback), carry onto `RungOutcome` (+ `to_json_dict`, + `schema_version` 7→8), pass through `classify_rung`
   into `observers_inconclusive`.
3. Replace stage-blind `blocked = max(0, unclear − free)` on the under-counting branch with a **sound per-stage `blocked`**
   (ingress strand blocks D, outbound strand blocks 1, routed strand bounded **[0,1]**), gated to reduce **exactly** to
   `expected − unclear` at H==D and when per-stage counts are absent.

**Soundness tension (the whole difficulty):** the routed-strand [0,1] bound must credit non-delivering-handler rows as ~0
blocking, or a genuine H>D collapse (routed strands scale ~A×H) re-fabricates the INCONCLUSIVE this guard exists to prevent.

## Owned files / seams

`harness/load/shardcert.py` (`_queue_breakdown` + its two call sites + `ShardCertEngineReport`) · `shardcert_ladder.py`
(`_engine_rung_payload`, `build_rung_outcome`, `RungOutcome`, `classify_rung`, `observers_inconclusive`, `schema_version`) ·
`tests/test_shardcert_ladder_two_box.py` (imports `observers_inconclusive` — put the H>D regression test here, **NOT** the
reconcile's rough-file `test_shardcert_ladder.py`) · `tests/test_shardcert_partitioned.py` · `docs/BACKLOG.md` (#229 @6797).

## Dependencies

#209 already merged (PR #952). **Sole owner of `shardcert*.py` this wave** — harness-207-txn is scoped off the ladder.

## Verification — Definition of Done

- `ruff` + `ruff format --check`; `mypy` on the touched harness modules **locally** (harness out of CI mypy scope);
  `$env:QT_QPA_PLATFORM='offscreen'; pytest -q`.
- Correctness: (a) NEW H>D regression — an ingress/outbound strand in the old `free` window now → INCONCLUSIVE, a genuine
  H>D collapse still → COLLAPSED; (b) byte-identity at H==D and with per-stage counts absent (sentinel); (c) pure
  `_summarize_queue_rows` test with synthetic rows.
- Coordinate with the live `-harness-ratefix` worktree (touches shardcert); `git merge main` before push.
- **No `Co-Authored-By: Claude` trailer**; owner approves PR. Flips #229 banner.

---
_Authored 2026-07-17 against `origin/main` @ `be1fbbab`._
