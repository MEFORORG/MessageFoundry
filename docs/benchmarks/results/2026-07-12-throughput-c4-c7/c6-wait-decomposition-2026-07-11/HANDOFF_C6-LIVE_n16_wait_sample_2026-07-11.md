# HANDOFF — **C6-LIVE: is the N=16 collapse blocked on a resource CONVOY (contention / spill), or is it aggregate/structural?**

**Date:** 2026-07-11 (rev-2, adversarially re-verified) · **This is the RUN doc — it SUPERSEDES the full
`HANDOFF_C6_n16_wait_decomposition.md` for the actual run, and it carries the full C6's instrument guards so it is
self-contained.** You do NOT need to read the full C6, the C4 handback, or the §3d follow-up to run this. Read-only DMVs;
public catalog names only; no secrets/IPs/PHI.

---

## ⚠️ AMENDMENT 2026-07-12 (v2) — C5 has RUN. One NEW arm, one rig change, one instrument warning.

**Read this before §0. Three changes; nothing else in the doc moves.**

### ① NEW ARM (the important one): **N=8 @ 3/shard** — a same-N PASS/FAIL pair
C5 returned **`R ∈ [2, 3)` → N-SIZING INSUFFICIENT** (2/shard sustains at N=8; **3/shard collapses, reproduced 2/2** —
~50% delivered, ~85k stranded, slope +108/+111). That hands this run a contrast its cross-N design cannot produce:

| | N=8 @ **2**/shard | N=8 @ **3**/shard |
|---|---|---|
| outcome | **PASS** (100% delivered, slope +1.9) | **COLLAPSE** (reproduced 2/2) |

**Same shard count. Only the per-shard rate varies.** That is precisely what the §3(a) convoy detector wants — a convoy
**present in the FAIL arm and absent in the matched PASS arm** — and it isolates the convoy from `N` itself, which the
N=4/N=8/N=16 ladder cannot do. **It is also the cheapest reproducible collapse the programme has.** Add it to §2. It is
now the arm most likely to actually name something: N=16 collapses from the start with **no plateau**, so it is expected
to route to AMBIGUOUS-STRUCTURAL *by construction* — the N=8 pair is where a convoy can be cleanly isolated.

### ② RIG CHANGE — the engine box is now **m7i.4xlarge (16 vCPU)**, not C4's m7i.2xlarge
Upsized for C5 (owner, 2026-07-12). **Keep it** — do not downsize for C6. The new 3/shard arm ran at engine `max_core`
≈ 38% on 16 cores; on the old 8-vCPU box that is ~76%, uncomfortably close to the 85% co-constraint bar. The bigger box
removes engine-side doubt entirely. **Store box is UNCHANGED (i4i.2xlarge)** — which is what §3(c)'s `n_sched=8`
denominator and every store-CPU comparison actually depend on. **Record the engine-box deviation from C4 in the
handback** (it does not affect the within-run convoy contrast, which is what names the verdict).

### ③ ⛔ INSTRUMENT WARNING — C5's handback made exactly the misread this instrument exists to prevent
C5's §6 named a *"serialization/write-path signature"* at the N=8 collapse, citing **`LOGMGR_QUEUE` + `CHECKPOINT_QUEUE`**.
**That is wrong, and it is the trap.** Both are **idle background waits** (log-writer / checkpoint threads *waiting for
work*) — **both are already on this doc's §3(c) benign-exclusion list.** In C5's own data they sit in a cluster of waits
each ≈ **800,000 ms over an 800 s window** — i.e. threads asleep for the *entire* run. `SOS_WORK_DISPATCHER` topped the
raw list at 74–92M ms (pure idle). And **`WRITELOG` — the wait that would actually prove a write-path wall — was absent
entirely**, as were `PAGEIOLATCH_*`, `LCK_*`, `RESOURCE_SEMAPHORE*`. C5's dump was **never filtered through the exclusion
set**. (Full working: `REVIEW_C5_handback_2026-07-12.md` §2.)

**Therefore, for this run — non-negotiable:**
- **Apply the §3(c) exclusion set. It is mandatory, not optional.** An unfiltered top-N by `wait_time_ms` is not a result.
- **The §4 anti-adjacency guard stands and is now battle-tested:** a verdict is named **ONLY** by a §3(a) convoy meeting
  the floor **and** absent in the control arm — **never** by a wait's rank in (c). C5 named a wall by rank and got it
  backwards. Do not repeat it.
- The only non-benign wait C5 saw was **`SOS_SCHEDULER_YIELD`** (~826k/834k tasks, reproduced) — a **CPU-pressure**
  signal. Treat it as **context, not a verdict** (§4 already says a scheduler/runnable read cannot name a verdict).

---

## 0. The one question, and what is ALREADY settled (do NOT re-derive)

Two prior results (both computed OFF-LINE from existing data — **no rig run**) narrowed the N=16 question to exactly one
live measurement:

- **Reconciliation = 64.4% → AMBIGUOUS** (store query-CPU does NOT cleanly explain the box CPU wall). **Consequence for
  this run: a clean "CPU-BOUND" verdict is already PRECLUDED — the live sample CANNOT upgrade the wall to CPU-BOUND.** The
  live run's job is *only* to find whether a specific **resource convoy** explains the collapse, or confirm it is
  aggregate/structural.
- **`list_fifo_lanes` cost = INTRINSIC** (cpu/read rises 2.06× N=4→16, and rises already at N=8/100%-delivered). One
  residual it could not close from history: at N=16, is that intrinsic cost genuine per-page work, or **collapse-induced
  cache-spill** (a `DISTINCT` over the ~208k-row pending set pressuring memory)? A spill is a *collapse effect*, not a
  design cost.

**So this run answers: what is the N=16 collapse BLOCKED ON — a lock/latch/store-page CONTENTION convoy, a MEMORY/tempdb
SPILL, or nothing dominant (aggregate/structural)?** That decides whether the next build is a contention fix, a
collapse-prevention effort, or a dispatcher lane-path rewrite — or none.

**This run is NOT:** a throughput run, a fix, a sustained-plateau characterization (N=16 has NO plateau — it collapses from
the start; that is the expected input, not a failure), a CPU re-attribution, or a re-run of the reconciliation/scan-confound.
It changes no engine code.

---

## 1. PRE-FLIGHT (blocking)

1. **Feature ON, verified:** `MEMORY_OPTIMIZED TEMPDB_METADATA = ON` (two keywords, a SPACE) — RG pool `tempdb_xtp` @25%,
   restart, confirm `SELECT SERVERPROPERTY('IsTempdbMetadataMemoryOptimized')` = **1** + the ERRORLOG line. A run with the
   latch present measures the wrong regime → **VOID**.
2. ⚠️ **Feature-OFF can masquerade as a result mid-run.** Even with pre-flight passed, if the live sample's modal wait is a
   **`PAGELATCH_*` on a tempdb (`database_id = 2`) SYSTEM-CATALOG page** (e.g. `2:1:97 = syssingleobjrefs` — the C2 wall),
   the feature silently reverted / the RG pool fell over → **VOID and re-verify, do NOT name it** (§4). Only a `PAGELATCH`
   on the **store DB's own USER pages** is a real contention signal.
3. **Engine commit `98bec81`** (same as C3/C4 — must match to compare).
4. **Confirm the DMVs populate** while idle: run §3(a)/(b) once; `dm_os_waiting_tasks` and `dm_os_schedulers` return rows.
5. Everything else identical to C2/C3/C4: `dests=8`, pooled, `--drain-timeout 150` (**do NOT raise past ~300 s** — re-arms
   harness defect B7), feature ON. **Light capture only** — the heavy per-query `dm_exec_query_stats` worker is NOT needed
   (a clean recapture proved capture weight does not move `claim_mean`; do not carry it).

## 2. THE RUN — 3 arms (a clean floor is required)

| arm | N | per-shard | expected | role |
|---|---|---|---|---|
| **clean control** | **4** | 2 | sustains, flat, delivers 100% | The guaranteed-healthy floor. A convoy present here is NOT the wall. **Required** — N=8@2 alone cannot be the floor (it is marginal/variable). |
| **midpoint** | **8** | 2 | delivers ~100% but **marginal, run-to-run variable** (sometimes strands) | Does a convoy appear at the *onset* of marginality, or only in deep collapse? **Doubles as the matched PASS control for the new arm below.** |
| ⭐ **NEW — the matched-pair FAIL** | **8** | **3** | **COLLAPSES** (~50% delivered, ~85k stranded, slope +108/+111, store CPU 62→81%) — **reproduced 2/2 by C5** | ⭐ **The arm most likely to NAME something.** Same `N` as the midpoint, only the rate differs → a convoy here that is **absent at N=8@2** is isolated from `N` and from deep-collapse artifacts. **The cleanest collapse the programme has, and the only one with a matched control.** (Added 2026-07-12 from the C5 result.) |
| **the target** | **16** | 2 | **COLLAPSES** (9.4% delivered, ~208k stranded, store 92–94% CPU, monotonic queue growth) | The original regime under test. **Expect AMBIGUOUS-STRUCTURAL by construction** — it collapses from the start, with no plateau. Still sample it; just do not be surprised when it names nothing. |

Feature ON, `dests=8`, pooled, `--drain-timeout 150`, 900 s soaks. Gate arm success on **`result`**, never `exit_code`.
**A COLLAPSED N=16 (and a collapsed N=8@3) is the EXPECTED INPUT to this run, not a void run.**

> **The primary contrast is now `N=8 @ 3/shard` (FAIL) vs `N=8 @ 2/shard` (PASS)** — same shard count, matched control.
> The `N=4` clean floor and the `N=16` target both remain, but a convoy that shows up in the N=8 pair is the strongest
> evidence this run can produce. **Run all four arms** — the pair is cheap and the N=16 arm is the one the original
> question was posed about.

## 3. THE INSTRUMENT

### (a) The convoy detector — the SOLE namer (sample every ~10 s across each arm's hold)
The **convoy** — many sessions blocked on the SAME resource — is what names the wall, NOT a wait's rank in the aggregate.
```sql
SELECT wt.session_id, wt.wait_type, wt.wait_duration_ms,
       wt.blocking_session_id,          -- populated for LOCK blocking (often NULL for LATCH — use resource_description)
       wt.resource_description,          -- the SHARED resource; group on this to detect a latch/page/grant convoy
       r.status, r.command, r.sql_handle -- resolve statement text POST-HOC for the few distinct sql_handles (see note)
FROM sys.dm_os_waiting_tasks wt
LEFT JOIN sys.dm_exec_requests r ON r.session_id = wt.session_id
WHERE wt.session_id > 50
ORDER BY wt.resource_description, wt.wait_duration_ms DESC;
```
> **Do NOT `OUTER APPLY sys.dm_exec_sql_text` in this recurring sample** — that adds DMV latch/scheduler load to the very
> collapsed box you are measuring. Capture `sql_handle` only; resolve the handful of distinct handles to statement text
> **once, post-hoc**, after the run.

A **convoy** = in an N=16 sample, **≥ 5 sessions SUSPENDED sharing one `resource_description`** (latch/page/grant), **OR** a
`blocking_session_id` chain **≥ 2 deep**, and this pattern present in **≥ 50 % of the N=16 samples**. Anything below that
floor is **not** a convoy.

### (b) Scheduler pressure (same cadence, context)
```sql
SELECT scheduler_id, current_tasks_count, runnable_tasks_count, active_workers_count, work_queue_count
FROM sys.dm_os_schedulers WHERE status = 'VISIBLE ONLINE';
```

### (c) Wait-stats DELTA (T0 hold-start / T1 hold-end) — CONTEXT ONLY, cannot name a wait
On the plateau-less N=16 arm this delta spans the collapse, so its #1 wait is a **backlog effect**; it corroborates the
(a) convoy, it does not name the wall. Use the **full enumerated benign-exclusion set** (a glob `NOT IN` is not valid
T-SQL):
```sql
SELECT wait_type, waiting_tasks_count, wait_time_ms, signal_wait_time_ms,
       (wait_time_ms - signal_wait_time_ms) AS resource_wait_ms, max_wait_time_ms
FROM sys.dm_os_wait_stats
WHERE wait_type NOT IN (
    'CLR_SEMAPHORE','LAZYWRITER_SLEEP','RESOURCE_QUEUE','SLEEP_TASK','SLEEP_SYSTEMTASK',
    'SQLTRACE_BUFFER_FLUSH','WAITFOR','LOGMGR_QUEUE','CHECKPOINT_QUEUE','REQUEST_FOR_DEADLOCK_SEARCH',
    'XE_TIMER_EVENT','BROKER_TO_FLUSH','BROKER_TASK_STOP','CLR_MANUAL_EVENT','CLR_AUTO_EVENT',
    'DISPATCHER_QUEUE_SEMAPHORE','FT_IFTS_SCHEDULER_IDLE_WAIT','XE_DISPATCHER_WAIT','XE_DISPATCHER_JOIN',
    'SQLTRACE_INCREMENTAL_FLUSH_SLEEP','ONDEMAND_TASK_QUEUE','BROKER_EVENTHANDLER',
    'SLEEP_BPOOL_FLUSH','SLEEP_DBSTARTUP','DIRTY_PAGE_POLL','HADR_FILESTREAM_IOMGR_IOCOMPLETION',
    'SP_SERVER_DIAGNOSTICS_SLEEP','QDS_PERSIST_TASK_MAIN_LOOP_SLEEP','QDS_ASYNC_QUEUE',
    'QDS_CLEANUP_STALE_QUERIES_TASK_MAIN_LOOP_SLEEP','QDS_SHUTDOWN_QUEUE',
    'WAIT_XTP_HOST_WAIT','WAIT_XTP_OFFLINE_CKPT_NEW_LOG','WAIT_XTP_CKPT_CLOSE','WAIT_XTP_RECOVERY',
    'HADR_WORK_QUEUE','HADR_TIMER_TASK','HADR_CLUSAPI_CALL','PWAIT_ALL_COMPONENTS_INITIALIZED',
    'PWAIT_DIRECTLOGCONSUMER_GETNEXT','LOGMGR_RESERVE_APPEND',
    'PREEMPTIVE_XE_GETTARGETSTATE','PREEMPTIVE_OS_FLUSHFILEBUFFERS','PREEMPTIVE_OS_LIBRARYOPS',
    -- Preemptive OS round-trips that rank high on an active server and are NOT the wall (the pooled claim opens/reuses
    -- many connections, so login/auth + pipe/registry preemptive waits churn — the "rank-1 by default" trap):
    'PREEMPTIVE_OS_WAITFORSINGLEOBJECT','PREEMPTIVE_OS_GETPROCADDRESS',
    'PREEMPTIVE_OS_AUTHENTICATIONOPS','PREEMPTIVE_OS_AUTHORIZATIONOPS',
    'PREEMPTIVE_OS_PIPEOPS','PREEMPTIVE_OS_QUERYREGISTRY',
    'CXCONSUMER',   -- benign parallelism consumer wait (CXPACKET/exchange deliberately NOT excluded: high = plan regression to REPORT)
    'STARTUP_DEPENDENCY_MANAGER','SLEEP_MASTERDBREADY','SLEEP_MASTERMDREADY','SLEEP_MASTERUPGRADED',
    'DBMIRROR_DBM_EVENT','DBMIRROR_EVENTS_QUEUE','DBMIRROR_WORKER_QUEUE','DBMIRRORING_CMD',
    'PARALLEL_REDO_WORKER_WAIT_WORK','PARALLEL_REDO_DRAIN_WORKER','PARALLEL_REDO_LOG_CACHE',
    'VDI_CLIENT_OTHER','SOS_WORK_DISPATCHER'
    -- SOS_SCHEDULER_YIELD deliberately NOT excluded (the CPU-oversubscription signal); but see §4 — it CANNOT name a verdict here.
)
ORDER BY wait_time_ms DESC;
```
> **Capture-session self-fence (required).** `dm_os_wait_stats` is server-wide, so this capture's OWN queries add waits to
> the delta. Record every monitoring `session_id`, snapshot `sys.dm_exec_session_wait_stats` for them at T0/T1, and
> **subtract the capture sessions' waits** before ranking. Report the fenced numbers.

Also keep box CPU + `max_core%` on **both** boxes (validated substitute; per-PID collector is broken).

## 4. DECISION RULE (pre-registered — the four verdicts are MUTUALLY EXCLUSIVE; there is NO CPU-BOUND verdict)

Read the **(a)-convoy structure in a FAIL arm**, contrasted against a **PASS control**. The (c) rank and the fleet
`signal/resource` fraction **cannot name a verdict** (on a CPU-saturated box a real contention wall also shows high signal
wait; a wait is rank-1 "by default" the moment the prior #1 goes to zero). **Only a convoy meeting the §3(a) floor names a
wall.**

**Two independent contrasts — read BOTH (added 2026-07-12):**
- ⭐ **The matched pair (PRIMARY): `N=8 @ 3/shard` (FAIL) vs `N=8 @ 2/shard` (PASS).** Same shard count, only the rate
  differs. A convoy present at 3/shard and **absent at 2/shard** is isolated from `N` and from deep-collapse artifacts.
  **This is the strongest evidence the run can produce** — treat a verdict from it as naming the wall.
- **The original: `N=16 @ 2/shard` (FAIL) vs `N=4 @ 2/shard` (clean floor).** Still run it, but expect
  AMBIGUOUS-STRUCTURAL by construction (no plateau).

Apply the table below to **each** contrast. **If they disagree, report both and name NEITHER** — a convoy that appears in
one contrast and not the other is not a wall, it is a clue. Say so plainly rather than picking the more interesting one.

*(Throughout the table, "**absent at N=4**" now reads "**absent in that contrast's PASS control**" — N=8@2 for the matched
pair, N=4@2 for the original.)*

| N=16 pattern | verdict | consequence |
|---|---|---|
| **VOID first:** the convoy's modal `resource_description` is a **tempdb (`database_id=2`) SYSTEM-CATALOG page** (`2:1:*`, e.g. `syssingleobjrefs`) | **VOID — feature reverted** | The tempdb-metadata feature is OFF/failed under load (this is the retracted C2 wall). Re-verify §1 and re-run. Do **not** name a verdict. |
| A **§3(a) convoy** (≥5 SUSPENDED on one resource / chain ≥2, in ≥50% of samples) on a **LOCK (`LCK_M_*`)** or a **store-DB USER-page/object `*LATCH*`**, **absent at N=4** | **WAIT-BOUND — CONTENTION** | The wall is contention, not a query-CPU problem. Fix = contention work (lock granularity / RCSI / partitioning). Name the wait + cite the chain (not the rank). |
| A **§3(a) convoy** whose modal resource is a **MEMORY-GRANT (`RESOURCE_SEMAPHORE*`)** or a **spill wait (`IO_COMPLETION`, sort/hash spill, non-catalog tempdb `PAGELATCH`)**, **absent at N=4** | **WAIT-BOUND — SPILL (collapse effect)** | `list_fifo_lanes`' intrinsic-vs-spill residual resolves toward SPILL: its N=16 cost is partly collapse-induced. Re-weight the fix toward preventing collapse, not a per-page CPU rewrite. |
| **No convoy meets the §3(a) floor** at N=16 (SUSPENDED sessions scattered across many resources; no chain; or the pattern also present at N=4) | **AMBIGUOUS — STRUCTURAL** *(the default)* | No single blocker. Consistent with the offline reconciliation (64.4%, ≤66% AMBIGUOUS band) — the collapse is aggregate plumbing, not one query or one lock. Neither a single contention fix nor a single-query CPU rewrite clears it → a batch/fusion/topology conversation. |

**Why there is no CPU-BOUND row:** the offline reconciliation (64.4%, in the ≤66% AMBIGUOUS band) already says store
query-CPU does not cleanly explain the wall, so the live sample **cannot** upgrade it to CPU-BOUND. A "runnable count looks
higher at N=16" observation is NOT admissible as a CPU-BOUND verdict — it is a rank-1-by-default-class inference on a
variable baseline. If you see high `runnable_tasks_count` **and** no convoy, the verdict is **AMBIGUOUS-STRUCTURAL**, not
CPU-BOUND. (Record the runnable read as context; it does not decide.)

**Anti-adjacency guard (hard, structural):** a verdict is named ONLY by a §3(a) convoy meeting the floor **and** absent at
N=4. No verdict may be named from a wait's rank in (c), from the fleet signal fraction, or from a scheduler count. This is
the exact inference discipline two prior results were retracted for skipping.

## 5. Do NOT

- Feature OFF ⇒ **VOID**; tempdb system-catalog PAGELATCH ⇒ **VOID** (feature reverted), not a verdict. · No `per_lane`. ·
  `--drain-timeout 150`, do not raise past ~300 s (B7). · Gate on **`result`**, never `exit_code`. · A COLLAPSED N=16 is the
  expected input, not a void run. · Do **not** characterize an N=16 *sustained plateau* — there is none. · Do **not** name a
  verdict from a wait's RANK, the fleet signal fraction, or a scheduler count — only a §3(a) convoy absent at N=4 names one.
  · Do **not** reach CPU-BOUND (precluded by the offline 64.4% reconciliation). · Do **not** re-run the reconciliation
  (§3c=64.4%) or the scan-confound (§3d=intrinsic) — done off-line.

## 6. What to send back (`HANDBACK_C6-LIVE_<date>.md`)

1. Proof the feature was active (`IsTempdbMetadataMemoryOptimized` = 1) on all arms — else VOID. **Also state the engine
   box (m7i.4xlarge — CHANGED from C4's m7i.2xlarge, see the amendment) and the store box (i4i.2xlarge, unchanged).**
2. ⭐ **The MATCHED-PAIR convoy read (PRIMARY): `N=8 @ 3/shard` (FAIL) vs `N=8 @ 2/shard` (PASS).** Fraction of samples
   meeting the §3(a) floor in the FAIL arm; the modal `resource_description` + `wait_type`; whether it is a lock chain, a
   shared latch, a memory-grant, a tempdb catalog page (→VOID), or a tempdb non-catalog/spill; chain depth; whether the
   chain head is a claim / dispatch / `list_fifo_lanes` statement (resolved post-hoc). **And critically: is it ABSENT in
   the 2/shard PASS arm?**
3. **The N=16 convoy read + the N=4 contrast:** same fields; was the convoy absent at the N=4 clean floor? **Do the two
   contrasts AGREE?** If they name different resources — or one names nothing — **say so and name NEITHER** (§4).
4. **All waits reported must be POST-EXCLUSION-SET** (§3(c)). An unfiltered top-N by `wait_time_ms` is not a result — it
   will put `SOS_WORK_DISPATCHER` / `LOGMGR_QUEUE` / `CHECKPOINT_QUEUE` (idle background threads) at the top and invite
   the exact misread C5's handback made. State explicitly that the set was applied.
5. **Scheduler context:** `runnable_tasks_count` median/max per arm (reported as context, not a verdict input). Note
   `SOS_SCHEDULER_YIELD` here too if present — C5 saw ~826k/834k tasks at the N=8@3 collapse. **Context, not a verdict.**
6. **The §4 verdict** — one line: **VOID / WAIT-BOUND-CONTENTION / WAIT-BOUND-SPILL / AMBIGUOUS-STRUCTURAL** — reported
   **per contrast** (matched pair; N=16-vs-N=4), and if they disagree, **name NEITHER**. If WAIT-bound, give the named
   wait + the blocking chain as evidence (**not** the rank).
7. The capture-session-FENCED (c) wait delta for all arms (context), and box CPU + `max_core%` on **all three** boxes.

## 7. Sources / notes

- Closes the two open items from the C4 arc: WAIT-vs-CPU (reconciliation was AMBIGUOUS at 64.4% — so this run cannot land
  CPU-BOUND, only find a convoy or confirm structural) and the `list_fifo_lanes` intrinsic-vs-spill residual (off-line §3d =
  intrinsic; the N=16 spill split needs this live read). Instrument guards (exclusion set, capture-session fence,
  no-recurring-`sql_text`, tempdb-catalog→VOID, convoy floor, anti-adjacency) are carried verbatim from
  `HANDOFF_C6_n16_wait_decomposition.md` §3/§4/§5 — full context there, not required to run.
- Read-only DMVs only. No secrets, hostnames, IPs, ports, or customer identifiers — public DMV/catalog names only.
