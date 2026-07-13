# HANDOFF — **C4: is the pooled claim the store-CPU consumer at N=16?** (per-query attribution — the gap C3 left open)

**Date:** 2026-07-11 · **Continues C3** (`c3-tempdb-metadata-2026-07-10/HANDBACK_C3_*.md`). **Cheap** (2 arms, feature ON, no full sweep).

---

## 0. What C4 is, and what it is NOT

C3 proved the tempdb catalog PAGELATCH was real and that removing it **clears N=8 but not N=16** — and that with the latch
gone the N=16 wall is **store-CPU saturation (92–93%)**. But C3 stopped exactly one step short of the decision it feeds:
it has **zero per-query CPU attribution**. "That CPU is the pooled claim's per-cycle temp-object churn" is a *hypothesis*,
and it is the SAME adjacency inference C2 had to retract. C4 closes that gap and **nothing else**.

- **C4 IS:** at the latch-free N=16 arm, capture **per-query CPU** (`total_worker_time` by `query_hash` → statement text)
  and rank it. Answer one question: **does the pooled claim family dominate store CPU at N=16, and does its CPU-per-exec
  GROW with shard count?** A light passing arm (N=4) supplies the baseline so "grows" is measurable, not asserted.
- **C4 is NOT:** a throughput run, a fix, or a sweep. It does not change the engine. It does not decide deployment. Its
  entire job is to make the pooled-claim rewrite a **verified** lever or a **refuted** one *before* anyone builds it.
- **Why it matters:** if C4 CONFIRMS → the rewrite is the proven ceiling lever, build it. If C4 REFUTES (delivery/encrypt/
  finalizer CPU dominates, or CPU is spread thin) → the rewrite would **not** clear N=16, and a large engine build is
  saved. This is the cheapest possible de-risk of the most expensive next step.

---

## 1. PRE-FLIGHT GATE (blocking — do these first)

1. **Re-enable the feature** — C3 teardown reverted to OFF. Repeat the C3 §2 enable+verify sequence (RG pool `tempdb_xtp`
   @25% → `ALTER SERVER CONFIGURATION SET MEMORY_OPTIMIZED TEMPDB_METADATA = ON (RESOURCE_POOL='tempdb_xtp')` → restart →
   verify `SELECT SERVERPROPERTY('IsTempdbMetadataMemoryOptimized')` = **1** + ERRORLOG "Tempdb started with
   memory-optimized metadata"). **The latch MUST be gone**, or you are attributing C2's latch, not C3's residual.
   *(T-SQL is `MEMORY_OPTIMIZED TEMPDB_METADATA` — two keywords, a SPACE. The underscore form in the C3 handoff was a typo.)*
2. **Confirm the per-query DMV is populated** — run the §3 query once against the store DB while idle; if
   `sys.dm_exec_query_stats` returns rows joined to `sys.dm_exec_sql_text`, the instrument works. (It is **server-wide**
   and needs no per-DB setup — this sidesteps the schema-v3 per-run-store-teardown plan-eviction bug: sample it **live
   during** the soak, while plans are hot, not after the store DB is dropped.)
3. **(Optional, more robust) enable Query Store on the store DB** if the harness lets you reach it after creation:
   `ALTER DATABASE [<storedb>] SET QUERY_STORE = ON (OPERATION_MODE=READ_WRITE, QUERY_CAPTURE_MODE=ALL, DATA_FLUSH_INTERVAL_SECONDS=60)`.
   Query Store aggregates by `query_id` and survives plan eviction *within* the DB's life — a good cross-check on the live
   `dm_exec_query_stats` deltas. If the store DB is recreated per run and you can't reach it in time, skip — the live
   deltas are the primary instrument.

---

## 2. THE RUN — 2 arms, feature ON, everything else identical to C2/C3

Fixed 2/shard, `dests=8`, pooled, 900 s soak, `--drain-timeout 150` — **the only delta from C3 is that you also run the
per-query CPU capture in §3**. Do NOT change any pipeline variable.

| arm | N | why |
|---|---|---|
| **control** | **4** | latch-free, PASSES, fully drains (~19 ms claim). Baseline CPU-per-exec — the denominator for "grows with N". |
| **target** | **16** | latch-free, COLLAPSES, store CPU 92–93%. The arm whose CPU we are attributing. |

*(N=8 is optional if cheap — it's the marginal-clear midpoint (~60% store CPU) and would turn the two-point "grows" into a
three-point trend. Not required for the verdict.)*

For each arm, run the §3 capture: a snapshot at soak start (T0) and at soak end (T1, before store-DB teardown), plus
≥3 mid-soak samples. Attribute on the **T1−T0 delta** (per-arm), not cumulative server totals.

---

## 3. THE INSTRUMENT — per-query CPU by statement (exact query)

Snapshot this into a table/CSV at T0, mid-soak (×3+), and T1. Attribute on deltas.

```sql
-- Server-wide per-statement CPU + execution + waits. Key = query_hash (stable across recompiles).
SELECT
    qs.query_hash,
    qs.execution_count,
    qs.total_worker_time                          AS cpu_us_total,   -- CPU microseconds (THE attribution metric)
    qs.total_worker_time / NULLIF(qs.execution_count,0) AS cpu_us_per_exec,
    qs.total_elapsed_time,
    qs.total_logical_reads,
    SUBSTRING(st.text,
        (qs.statement_start_offset/2)+1,
        (CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(st.text)
              ELSE qs.statement_end_offset END - qs.statement_start_offset)/2 + 1) AS stmt_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
ORDER BY qs.total_worker_time DESC;
```

Also sample, every ~10 s across each arm (for the CPU-bound-vs-yielding read):

```sql
-- What the schedulers are actually running RIGHT NOW (RUNNING = burning CPU; RUNNABLE = queued for CPU).
SELECT r.status, r.wait_type, r.command, r.cpu_time, r.total_elapsed_time,
       SUBSTRING(t.text,(r.statement_start_offset/2)+1,
         (CASE r.statement_end_offset WHEN -1 THEN DATALENGTH(t.text)
               ELSE r.statement_end_offset END - r.statement_start_offset)/2+1) AS running_stmt
FROM sys.dm_exec_requests r CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE r.session_id > 50;
-- and scheduler pressure:
SELECT scheduler_id, current_tasks_count, runnable_tasks_count, active_workers_count
FROM sys.dm_os_schedulers WHERE status='VISIBLE ONLINE';
```

Keep the whole-box + per-core CPU capture on BOTH boxes exactly as C2/C3 did (`max_core%`, the validated substitute for
the broken per-PID collector). C4's per-QUERY CPU is a **SQL Server DMV** — it is unaffected by the OS per-PID 0.00 bug,
which is precisely why it can answer what the OS collector couldn't.

---

## 4. DECISION RULE (pre-registered — fixed before the run)

> ## ⚠️ SUPERSEDED 2026-07-11 — see `c4-familymap-ratification-2026-07-11\RATIFICATION_C4_familymap_2026-07-11.md`
>
> The CLAIM definition below is **wrong in one respect and right in another**, and the bench's pre-flight
> challenge caught it. The ratified map:
>
> - **CLAIM = the `claim_fifo_heads` batch IN FULL** — head probe + `@heads`/`@locked`/`@keep`/`@claimed`
>   DECLAREs and their INSERT/SELECT/DELETE + the final `UPDATE … OUTPUT inserted.*`. Sum every `query_hash`
>   the batch emits. **This IS the pooled claim** (`stage_dispatcher.py:559` calls it; the table-variable
>   DECLAREs are at `sqlserver.py:4337-4342`). ✅ *The table-variable half below was correct.*
> - ❌ **`#eligible` is NOT part of CLAIM — remove it.** It belongs to `purge_message_bodies`
>   (`sqlserver.py:3612-3647`), the retention purge, and it scans `messages` — a table far larger at N=16.
>   Folding it in would manufacture super-linear "claim" growth that is not intrinsic to the claim path:
>   **the C2 adjacency error, re-imported into the run built to avoid it.** → **OTHER/retention, FLAG only.**
> - ⛔ **Do NOT pin CLAIM to `claim_ready`.** That is the `per_lane` **UNORDERED** delivery path
>   (`wiring_runner.py:2879`); in a pooled + FIFO C4 arm it executes **zero times**, so CLAIM would measure
>   ~0% and the rule would auto-return a **fabricated REFUTED**.
> - ✅ **New abort assertion: `CLAIM (claim_fifo_heads) delta > 0`, else VOID the arm.** A near-zero `@heads`
>   delta means the pooled claim never ran — it is the *inverse* of a leak signal.

Bucket every statement in the §3 delta into families by matching `stmt_text`:
- **CLAIM family** = the pooled claim (`WITH due AS (SELECT TOP … WITH (READPAST, UPDLOCK, ROWLOCK) … ORDER BY
  next_attempt_at) UPDATE due SET … OUTPUT inserted.*`) **plus its per-cycle temp-object churn** — the `@heads` / `@locked`
  / `@keep` / `@claimed` table-variable INSERT/SELECTs and any `#eligible` DDL/populate. **Sum these together** — the churn
  IS the claim's constituent statements. *(← `#eligible` struck; see the SUPERSEDED box above.)*
- **DELIVERY** = `mark_done` / `mark_batch_done` / delivery UPDATEs.
- **INSERT** = ingress/routed/outbound row inserts (the body-copy writes).
- **FINALIZER** = the disposition-finalize statements.
- **OTHER** = everything else.

Then, comparing N=16 vs the N=4 control:

| verdict | condition | consequence |
|---|---|---|
| **CONFIRMED** | CLAIM family is the **#1 CPU consumer** at N=16 (≳ the next family, and a clear plurality of total `cpu_us`), **AND** its `cpu_us_per_exec` **rises materially** N=4 → N=16 | churn hypothesis holds. Pooled-claim rewrite is the **verified** ceiling lever → build it. |
| **REFUTED** | some OTHER family (delivery / insert / finalizer / encryption) dominates CPU at N=16, or CLAIM `cpu_us_per_exec` is **flat** N=4 → N=16 | the rewrite would **not** clear N=16. Re-target the build at whatever family dominates. Saves a wasted rewrite. |
| **AMBIGUOUS** | no family exceeds ~40% of total `cpu_us`; CPU is spread thin across many statements | the N=16 wall is **aggregate plumbing**, not one query. Neither the rewrite nor any single-statement fix clears it — escalate to a structural (batch/fusion) conversation, not a claim rewrite. |

**Do not soften a REFUTED/AMBIGUOUS into CONFIRMED because the rewrite "should" help.** The whole point of C4 is to let
the data veto the build. C2 was retracted for exactly the inference this rule forbids.

---

## 5. RISKS / CAVEATS

- **Plan eviction** — if the harness drops the store DB at run end, `dm_exec_query_stats` rows for that DB evict. Mitigation
  is already in §2/§3: sample **live during** the soak (plans hot), attribute on within-arm deltas, and cross-check with
  Query Store if you enabled it. Do not attribute on a post-teardown snapshot.
- **Parameterization / recompiles** — key on `query_hash` (stable across parameter values and recompiles), not `sql_handle`.
  If the claim shows as several `query_hash` values (e.g. per shard), SUM them into the CLAIM family — that's fine.
- **CPU µs, not %** — `total_worker_time` is the attribution metric. Corroborate the magnitude against the store box's
  whole-box CPU (should account for the bulk of the 92–93% at N=16). If the DMV CPU is a small fraction of box CPU, some
  consumer is outside query execution (background/GC) — report that; it changes the answer.
- **Feature-ON conditional** — every C4 number is conditional on `MEMORY_OPTIMIZED TEMPDB_METADATA=ON`. That's correct:
  C4 attributes the **residual** CPU that only appears once the latch is gone.
- **This does not measure the rewrite.** Even a CONFIRMED verdict does not prove the rewrite clears N=16 — it proves the
  claim is the CPU consumer, i.e. that the rewrite *targets the right thing*. Sufficiency is still shown only by building
  it and re-running this sweep. Say so in the handback.

## 6. TEARDOWN (return the rig to the C2 baseline)

```sql
ALTER SERVER CONFIGURATION SET MEMORY_OPTIMIZED TEMPDB_METADATA = OFF;   -- two keywords, space
-- RESTART the SQL Server service (disable also requires a restart).
-- if you enabled it:  ALTER DATABASE [<storedb>] SET QUERY_STORE = OFF;
-- optionally:  DROP RESOURCE POOL tempdb_xtp;  (after restart)
```

## 7. Do NOT (unchanged guardrails)

- Do not flip `claim_mode` to `per_lane` (inverts at scale).
- Do not raise `--drain-timeout` past ~300 s (re-arms B7). Keep 150.
- Do not change ANY pipeline variable between C3 and C4 — the added per-query capture is the only delta.
- Do not read `exit_code` as a throughput verdict — gate on `result`. (C4's verdict is the §4 CPU rule, not delivery %.)
- Do not report a CONFIRMED as "the rewrite fixes N=16" — it confirms the *target*, not the *sufficiency* (§5).

## 8. What to send back (`HANDBACK_C4_<date>.md`)

1. Proof the feature was active (`IsTempdbMetadataMemoryOptimized` = 1) — else void.
2. The ranked per-statement CPU delta table for **N=16** and **N=4** (family, `cpu_us_total`, `execution_count`,
   `cpu_us_per_exec`, % of total).
3. The **verdict against §4: CONFIRMED / REFUTED / AMBIGUOUS**, with the CLAIM-family `cpu_us_per_exec` N=4→N=16 ratio.
4. Scheduler read: at N=16, were the claim's requests predominantly RUNNING (CPU-bound) or RUNNABLE/SUSPENDED?
5. DMV-CPU vs whole-box-CPU reconciliation (does query execution account for the 92–93%?).
6. One-line read: **is the pooled-claim rewrite the verified N=16 lever, or not — and if not, what family is.**

## 9. Sources / notes

- Continues C3 (`HANDBACK_C3_memopt_tempdb_metadata_2026-07-10.md` §3 — the "no per-query CPU attribution" gap this run fills).
- Claim family shape from the pooled `claim_ready` query + the tempdb table-variable churn (`outbound-claim-wall`: the
  `@table`-var/`#eligible` DDL is 43% of fixed claim cost — C4 tests whether that fixed cost becomes the N=16 CPU wall).
- Read-only DMVs only. No secrets, hostnames, IPs, ports, or customer identifiers — public DMV/catalog names only.
