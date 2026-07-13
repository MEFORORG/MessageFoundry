# HANDOFF — **C6: is the N=16 wall WAIT-bound (and on which wait), or CPU-bound after all?**

**Date:** 2026-07-11 · **Continues C4** (`c4-cpu-attribution-2026-07-11/HANDBACK_C4_2026-07-11.md`) · **Cheap:**
3 arms + one no-capture control, feature ON, no full sweep. Engine commit **`98bec81`** (identical to C4/C3 — must match or
the run is not comparable). Read the C4 HANDBACK in full before running this.

---

## REVISION 2026-07-11 (per the C4 clean-recapture review — GOVERNS the sections below)

A clean lighter-capture recapture (~6× lighter: TopRows 5000→800, NOLOCK queue scan dropped) post-dates this
draft and corrects two premises woven through §2/§3/§5/§9. Where the older text below conflicts, **this block
wins:**

1. **The apparatus-perturbation premise is REFUTED.** Everywhere this handoff says C4's capture worker "made
   c4-16 run +68% claim_mean" / "flipped c4-8 sustained→not" and frames the **no-capture control arm** as bounding
   *a perturbation to remove* — that is wrong. The recapture left `claim_mean` **unmoved** (heavy 93.4 vs light
   92.6 ms), the light N=8 arm tipped **worse** (slope 13.0 vs 7.5, stranded 3,175 vs 0), and store CPU + the N=16
   family split reproduced heavy↔light to the decimal. **Capture weight does not drive `claim_mean`; the C3↔C4
   delta is run-to-run / drift variance.** → **KEEP the `c6-16-nocap` control** (a near-un-perturbed wait
   cross-check is still worth it) but set its **expected `claim_mean` to ~93 ms — NOT a recovery to C3's 55 ms** —
   and read it as a *wait cross-check*, not a perturbation subtraction.
2. **N=16 is PLATEAU-LESS; 0.93 is the N=4 arm** (see the §0 correction note). C6-16 will most likely route to
   **AMBIGUOUS-STRUCTURAL by construction**; that is the *expected* outcome.
3. **§3c and §3d do NOT need a fresh N=16 run — they are computable from the existing C4 3-arm CSVs.**
   - **§3c (reconciliation) is already answered:** on the honest phase-matched denominator (plateau 93.3%,
     C3-consistent) N=16 = **64.4% → the AMBIGUOUS band** (vs C4's idle-diluted 70.68%). Re-run only to
     corroborate, not to obtain it.
   - **§3d (the `list_fifo_lanes` coupling answer) is DONE — result: INTRINSIC, not a pure backlog-scan effect.**
     cpu/read rises **2.06×** N=4→16 (10.3 → 21.3 µs/read), and — the tell — **it already rises at N=8, which
     delivers 100% (pre-collapse)**. So a claim fix that merely prevents collapse would **not** clear
     `list_fifo_lanes`: **"claim-only rewrite is insufficient" is now PROVEN**, and the next CPU-reduction build (if
     CPU is the lever — the reconciliation is AMBIGUOUS) is the **whole lane-servicing path**, not claim-scoped.
   → **Right-sizes C6 to ONE remaining decisive live measurement:** §3d left a residual it *can't* close from
     historical data — at N=16, intrinsic per-page cost vs **collapse-induced cache-spill** (a `DISTINCT` over the
     208k pending set could spill). That is exactly what the **live §3b sample** settles (a spill surfaces as a
     **memory-grant / tempdb wait**), and the same §3b sample answers the still-open **WAIT-bound vs CPU-bound**
     question (a lock/latch convoy ⇒ WAIT; high runnable + no blocking ⇒ CPU). So a *fresh* run's value is now
     concentrated in the **N=16 live §3b blocking/wait sample** (plus the N=8 §3a trend as context) — the §3a
     aggregate at N=16 is expected AMBIGUOUS-STRUCTURAL (plateau-less) and §3c/§3d are already in hand.

---

## 0. What C6 is, and what it is NOT

C4's decomposition put per-query CPU on the table and — crucially — **withheld** the "store CPU is the wall" verdict. The
single most load-bearing thing C4 found is buried in its §5 / caveats: at N=16 the pooled claim spends ~72% of its ~540 ms
wall **off-CPU, in lock/latch WAIT** (cpu_us ÷ elapsed_us = **0.28**). Per-claim CPU is a real but **minority** slice of the
wall. That means "store CPU is the wall" is probably the **wrong frame**, and the next diagnostic that actually moves the
decision is a **WAIT decomposition** — *which* wait, and whether it is a **lock/latch CONTENTION** wall (a completely
different fix — granularity / RCSI / partitioning) or genuinely **CPU-scheduling** wait after all (schedulers oversubscribed
→ back to the CPU story). C6 closes that gap and nothing else.

> **⚠️ CORRECTION (C4-handback review + clean recapture, 2026-07-11) — do NOT enter C6 assuming the wall is
> WAIT-bound, and do NOT expect an N=16 plateau.** Two facts, the second from a clean lighter-capture recapture that
> post-dates the C4 handback:
> - The **`cpu/elapsed = 0.28` is the COLLAPSED N=16 state**, not a plateau reading. **N=16 is PLATEAU-LESS** — the
>   store sits at 93–94% CPU while the queue grows monotonically (415 → 230,394) with no flat-backlog window. The
>   `cpu/elapsed` **0.93 → 0.70 → 0.28 progression is ACROSS ARMS** (N=4 → N=8 → N=16), so **0.93 is the *N=4* arm, not
>   an N=16 plateau** (an earlier draft of this note mis-read it as within-N=16 — corrected). A collapsed arm's elapsed
>   is inflated by backlog, so 0.28 is *expected* in collapse and is not a design signal. **Do not read the 0.28 as "the
>   wall is WAIT-bound."**
> - **Because N=16 is plateau-less, C6's §3a plateau-existence gate will most likely route c6-16 to AMBIGUOUS-STRUCTURAL
>   by construction** — C6-16 will probably NOT name a single wall wait. State that as the *expected* outcome, not a
>   surprise. **The usable live-run signal is the N=8 trend (§3a across arms) + the §3b blocking/waiting-tasks sample**;
>   the reconciliation (§3c) and the coupling answer (§3d) do **not** need a fresh run — see the REVISION block at the
>   top of this file.
>
> **The COUPLING question is now ANSWERED off-line — INTRINSIC (§3d, done 2026-07-11).** The review had opened it
> as unproven: is `list_fifo_lanes`' cost a backlog collapse EFFECT (a claim fix that prevents collapse shrinks it
> too) or intrinsic? The §3d scan-confound control on the existing 3-arm data: **cpu/read RISES 2.06×** N=4→16
> (10.3 → 21.3 µs/read, beyond read-depth), **and it already rises at N=8 (100% delivered, pre-collapse)** — so it
> is **intrinsic**. → **"claim-only rewrite is insufficient" is PROVEN; next CPU build = the whole lane-servicing
> path, not claim-scoped** (conditional on CPU being the lever at all — the reconciliation is AMBIGUOUS). **§3d's
> one un-closable residual (from historical data): at N=16, intrinsic per-page cost vs collapse-induced cache-spill
> — that, and the WAIT-vs-CPU question, are what the live §3b sample settles.** So §3b (the live N=16 blocking/wait
> sample) is now C6's **primary** live deliverable, not a secondary one.

- **C6 IS:** at N=4 (control, sustains) / N=8 (marginal) / N=16 (collapses), with the latch-free feature ON, capture a
  **`sys.dm_os_wait_stats` DELTA over the sustained plateau** (not cumulative-since-restart), split **signal** (CPU-scheduling
  wait) vs **resource** (= wait − signal), normalized **per-message**; plus a **live blocking/waiting-tasks sample** at N=16 to
  catch a convoy (blocking chain) that aggregate wait_stats cannot see; plus a **corrected CPU reconciliation** with an honest
  phase-matched denominator; plus a **scan-confound control on `list_fifo_lanes`** (the one C4 applied only to
  `claim_fifo_heads`). One question: **is the N=16 wall WAIT-bound, and on which wait — contention or CPU?**
- **C6 is NOT:** a throughput run, a fix, a claim/dispatch rewrite, or an engine change. It changes **no engine code**. Its
  job is to name the wall's *class* so the next expensive build targets the right thing.
- **C6 is INDEPENDENT of the `list_fifo_lanes` family-map ratification.** The C4 HANDBACK left an OPEN RATIFICATION (does
  `list_fifo_lanes` count as CLAIM machinery or a separate DISPATCH family). That is a **CPU-attribution** decision and it
  stays with the spec author. **A WAIT decomposition does not need it resolved** — waits are attributed to wait *types* and
  to *blocking chains*, not to query families. Do not block C6 on the ratification, and do not let C6's result be read as
  settling it. The §3(d) scan-confound control on `list_fifo_lanes` is diagnostic input for the owner's ratification, not a
  ruling on it.

---

## 1. PRE-FLIGHT GATE (blocking — do these first)

1. **Feature ON, verified — identical to C3/C4.** RG pool `tempdb_xtp` @25% →
   `ALTER SERVER CONFIGURATION SET MEMORY_OPTIMIZED TEMPDB_METADATA = ON (RESOURCE_POOL='tempdb_xtp')`
   (**two keywords, a SPACE — `MEMORY_OPTIMIZED TEMPDB_METADATA`**, not the underscore form) → restart →
   verify `SELECT SERVERPROPERTY('IsTempdbMetadataMemoryOptimized')` = **1** and the ERRORLOG line
   "Tempdb started with memory-optimized metadata." **If it is not ON you are measuring C2's tempdb-catalog PAGELATCH, not
   C3/C4's residual — the entire run is VOID.** This is the single most important gate: a WAIT decomposition run with the
   latch present will show PAGELATCH_* #1 and you will "discover" C2's already-retracted wall.
2. **Engine commit `98bec81`** — confirm before starting. A different commit makes the wait profile non-comparable to C4.
3. **Confirm the WAIT DMVs populate while idle.** Run the §3(a) `sys.dm_os_wait_stats` query and the §3(b)
   `sys.dm_os_waiting_tasks` query once against an idle store box. `dm_os_wait_stats` is **server-wide, cumulative since
   last restart / last `DBCC SQLPERF('sys.dm_os_wait_stats', CLEAR)`** and must return rows (it always does — it is why we
   snapshot T0/T1 and diff, never read it cumulatively). `dm_os_waiting_tasks` returns **only currently-waiting tasks**, so
   idle it may return few/no rows — that is expected; you are confirming the query parses and the columns exist, not that
   anything is waiting yet.
4. **Everything else identical to C4/C3:** `dests=8`, **pooled** (do NOT flip `claim_mode` to `per_lane`), 2/shard,
   `--drain-timeout 150` (do NOT raise past ~300s — re-arms harness defect B7), 900 s soaks. Read-only DMVs only, public
   catalog names only, no secrets / IPs / hostnames / PHI.
5. **Store instance runs ONLY the store workload.** Confirm the store box runs only the store SQL instance and that no other
   active workload (the load-gen's own DB connections, a co-tenant, HA replica traffic) touches it during the plateau — the
   load-gen drives the ENGINE box; any load-gen DB connections must target the ENGINE, not the store instance.
   `dm_os_wait_stats` is **server-wide**, so a foreign workload's `LCK_*`/`LATCH_*`/`WRITELOG` would land in the delta and be
   mis-attributed to the claim path (the analog of C5's #1 "you may be measuring the load-gen's ceiling" risk). If any
   non-store session is unavoidable, capture its `session_id` and fence it out via `dm_exec_session_wait_stats` (§5).
6. **Box unchanged from C4** — same store box VM (8 schedulers, `n_sched=8` in §3c) and, per the throughput doc's Phase-5
   sizing, the same engine box as C4. If the store box VM changed, the signal/resource interpretation and the §3(c)
   denominator both shift — confirm the box matches C4 before comparing (see §5).

---

## 2. THE RUN — 3 arms + one no-capture control, feature ON, everything else identical to C4

Fixed **2/shard**, `dests=8`, **pooled**, 900 s soak, `--drain-timeout 150`. **The ONLY deltas from C4 are:**
(a) a **lighter capture** (see §3 — lower sampling frequency and/or out-of-process, plus a **no-capture control arm at N=16**
to bound the apparatus perturbation C4 exposed), and (b) **WAIT capture added** (§3a/§3b). **Do not change any pipeline
variable.** Do not flip `per_lane`. Do not raise the drain timeout.

| arm | N | expected | why |
|---|---|---|---|
| **c6-4**  | **4**  | sustains (flat, ~19 ms claim) | **Control / baseline.** The per-message wait floor. "Grew N=4→16" is measured against this — not asserted. |
| **c6-8**  | **8**  | marginal (delivers, backlog slope) | Midpoint — turns the two-point wait trend into three points; catches a wait that is already rising pre-collapse. |
| **c6-16** | **16** | COLLAPSES (~9% delivered, store CPU 92–93%) | The arm whose wall we are decomposing. Live blocking sample runs here. |
| **c6-16-nocap** | **16** | COLLAPSES | **NO-CAPTURE control — with a light WAIT cross-check.** Run N=16 with the §3b live loop and §3c/§3d rolling scans **OFF**, but keep **ONLY the two-snapshot §3a `dm_os_wait_stats` reads (T0/T1)** on (negligibly perturbing) so it yields a second, near-un-perturbed wait profile to diff against fully-instrumented c6-16. Plus box CPU + `max_core%`. Bounds how much of the c6-16 wall profile is the instrument, not the engine — in BOTH throughput proxies AND the wait profile. See §5. |

For each *captured* arm run the §3(a) wait-stats snapshot at **T0 = sustained-plateau start** and **T1 = sustained-plateau
end** (see §3(a) for how to pick the plateau — NOT soak-start and NOT the collapse tail), plus the §3(b) live sample every
~10 s at N=16, plus §3(c)/§3(d). Attribute on the **T1−T0 delta**, per-arm. Keep `max_core%` on **both** boxes for every arm.

---

## 3. THE INSTRUMENT — exact read-only T-SQL (the heart of C6)

> **Lighter than C4 — as discipline, not because a perturbation was proven.** C4's capture worker scanned
> `sys.dm_exec_query_stats` (whole plan cache) + a NOLOCK `COUNT_BIG … GROUP BY` every ~45 s **inside the store
> process**. That was *originally suspected* of making c4-16 run +68% `claim_mean` and flipping c4-8 — **but the
> clean recapture REFUTED it** (`claim_mean` unmoved 93.4→92.6 ms; see the top REVISION block). Keep C6's capture
> light anyway, as good hygiene, not to subtract a perturbation. Concrete lightening rules for every query below:
> - **Snapshot wait-stats only at T0 and T1** (two reads per arm), not on a rolling interval. `dm_os_wait_stats` is cheap but
>   the discipline is: minimize in-store reads.
> - **Prefer out-of-process:** run the capture from a *separate* control connection / a second box's `sqlcmd`, not a worker
>   threaded into the engine or the load-gen hot path.
> - **The live sample (§3b) is the one recurring query** (~every 10 s at N=16 only). It touches only
>   `dm_os_waiting_tasks`/`dm_exec_requests` (currently-waiting tasks — a *tiny* set), never the plan cache. This is far
>   lighter than C4's per-statement `dm_exec_query_stats` scan.
> - **Do NOT re-run C4's full `dm_exec_query_stats` rolling scan.** For §3(c)/§3(d) take **exactly two** `dm_exec_query_stats`
>   snapshots (T0/T1) and diff — you need the delta, not a time series.
> - The **no-capture control arm** (c6-16-nocap) runs with *all* of the above OFF, to bound whatever residual perturbation remains.

### (a) WAIT DECOMPOSITION — `sys.dm_os_wait_stats` deltas over the sustained plateau

**Plateau definition — a MECHANICAL rule, pinned before the run, applied IDENTICALLY to N=4/8/16 (do not choose the window
post-hoc by eyeballing where the knee fell — that degree of freedom is exactly what let C4 manufacture 70.68% by choosing
which snaps to include).** Define T0/T1 by these objective, pre-committed thresholds, the same thresholds for every arm:

- **T0** = the first snapshot where **store `max_core%` ≥ 85%** (N=16; use "≥ the arm's own steady band" for N=4/8) **AND**
  ingress-accepted rate is within **±10%** of offered for **2 consecutive snapshots** (drops the idle ramp — the min=0 snaps
  that carried C4's false pass).
- **T1** = the last snapshot **before** the `in_pipeline` backlog slope exceeds **+Z rows/s** (state Z before the run; use the
  same Z for all arms), i.e. the snapshot immediately before the backlog knee. **T1 must NOT fall in the collapse tail** — a
  collapse's waits are partly an *effect* of the 208k backlog, not the sustained wall.

**Plateau-EXISTENCE gate (pre-registered — do NOT fabricate a plateau from ramp snaps).** The window [T0..T1] is admissible for
the §4 verdict only if it is at least **M consecutive snapshots** (state M; suggest M such that T1−T0 ≥ ~120 s) **AND** the
window's **Δdelivered exceeds a stated floor** (state a minimum delivered-message count — tie it to the per-msg denominator in
the analysis notes below). **The N=16 arm is not guaranteed to have such a window** — C4's c4-16 ramped 0→37→…→94 and then into
the backlog knee, with no evidence of a flat, delivery-healthy, at-plateau steady state. **If N=16 exhibits no window meeting
this gate, the arm cannot yield a sustained-plateau verdict: declare the result AMBIGUOUS-STRUCTURAL (Verdict 4) by construction
and lean on the N=8 marginal arm's plateau for the growth trend — do NOT place T1 in a still-rising ramp (near-zero Δdelivered
denominator = the min=0 idle-ramp contamination that manufactured C4's 70.68%) and do NOT push T1 past the knee.**

Report, for every arm, the **actual T0/T1 snapshot indices**, the window's **Δdelivered**, and a **±1-snapshot sensitivity
check**: recompute the top wait's per-message delta over a window shifted by ±1 snap and confirm the GREW verdict is stable
(C4's lesson — a 1–2 snap shift flipped the reconciliation). If the GREW verdict flips under a ±1-snap shift, the wait is not a
confirmed grower.

**Separately**, for N=16 only, also capture a **collapse-tail** delta (T1..end) and report it **labelled as collapse profile,
kept OUT of the sustained verdict** — it is there to show the difference, not to attribute cause.

Snapshot this into a CSV/table at T0 and T1; the delta is `wait_time_ms`, `signal_wait_time_ms`, `waiting_tasks_count` at T1
minus T0, per `wait_type`. **Co-timestamp the delivered counter with each wait snapshot** (read `Δdelivered` at the SAME T0 and
T1 as the wait-stats reads — see the per-message normalization note below; a phase mismatch here is C4's numerator/denominator
retraction re-imported into the wait normalization).

**Delta validity guard (assert before using any delta — `dm_os_wait_stats` is cumulative and is RESET by a service restart or
`DBCC SQLPERF(... CLEAR)`):** capture `SERVERPROPERTY('sqlserver_start_time')` at both T0 and T1 and **VOID the arm if it
differs** (a restart occurred inside the window). Assert every top wait type's `wait_time_ms(T1) ≥ wait_time_ms(T0)`; if any
counter went backwards between the paired reads, the stats were cleared mid-window → VOID the arm. §1 requires a restart to
enable the feature, so this guard is not hypothetical — pin the window strictly after the enable-restart.

```sql
-- sys.dm_os_wait_stats: cumulative since restart. Snapshot at T0 and T1; the DELTA (T1 - T0) is the plateau wait profile.
-- Columns (public, confirmed against the documented DMV): wait_type, waiting_tasks_count, wait_time_ms,
--   max_wait_time_ms, signal_wait_time_ms.
--   resource_wait_ms  = wait_time_ms - signal_wait_time_ms   (time waiting for the RESOURCE: lock/latch/IO/etc.)
--   signal_wait_ms    = signal_wait_time_ms                  (time RUNNABLE, waiting for a CPU scheduler = CPU-scheduling wait)
SELECT
    wait_type,
    waiting_tasks_count,
    wait_time_ms,
    signal_wait_time_ms,
    (wait_time_ms - signal_wait_time_ms) AS resource_wait_ms,
    max_wait_time_ms
FROM sys.dm_os_wait_stats
WHERE wait_type NOT IN (
    -- Standard benign / idle-wait exclusion list (Paul Randal / SQLskills "Wait Statistics" set).
    -- These accumulate while the server is idle and would swamp the real signal. Exclude at analysis time.
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
    -- Preemptive OS round-trips that commonly rank high on an active server and are NOT the wall — the pooled claim
    -- opens/reuses many connections, so login/auth + pipe/registry preemptive waits churn. Any of these ranking #1 after
    -- the tempdb latch is gone is precisely the "rank-1 by default" trap (§4 guard). Exclude them:
    'PREEMPTIVE_OS_WAITFORSINGLEOBJECT','PREEMPTIVE_OS_GETPROCADDRESS',
    'PREEMPTIVE_OS_AUTHENTICATIONOPS','PREEMPTIVE_OS_AUTHORIZATIONOPS',
    'PREEMPTIVE_OS_PIPEOPS','PREEMPTIVE_OS_QUERYREGISTRY',
    -- CXCONSUMER is a benign parallelism CONSUMER wait that grows with concurrency and can spuriously pass the
    -- grown-per-msg guard — exclude it. (CXPACKET/exchange are deliberately NOT excluded: if they rank high the store
    -- unexpectedly went parallel — a plan regression to REPORT, not a contention wall to attribute. See analysis notes.)
    'CXCONSUMER',
    'STARTUP_DEPENDENCY_MANAGER','SLEEP_MASTERDBREADY','SLEEP_MASTERMDREADY','SLEEP_MASTERUPGRADED',
    'DBMIRROR_DBM_EVENT','DBMIRROR_EVENTS_QUEUE','DBMIRROR_WORKER_QUEUE','DBMIRRORING_CMD',
    'PARALLEL_REDO_WORKER_WAIT_WORK','PARALLEL_REDO_DRAIN_WORKER','PARALLEL_REDO_LOG_CACHE',
    'VDI_CLIENT_OTHER','SOS_WORK_DISPATCHER'
    -- NOTE: SOS_SCHEDULER_YIELD is deliberately NOT excluded — it is the KEY CPU-oversubscription signal (§4).
)
ORDER BY wait_time_ms DESC;
```

**Then, in analysis (per arm):**
- Compute `Δwait_time_ms`, `Δsignal_wait_ms`, `Δresource_wait_ms`, `Δwaiting_tasks_count` per `wait_type` (T1 − T0).
  **`Δwait_time_ms` in `dm_os_wait_stats` is SUMMED ACROSS ALL CONCURRENTLY-WAITING TASKS** (parallel waits accumulate
  together; it is not bounded by wall-clock), so it scales with the number of concurrent waiters. N=16 has ~4× the worker
  threads of N=4, so any aggregate wait grows ~4× from concurrency ALONE even if per-operation contention is unchanged — do
  not read that as intensification.
- **`Δdelivered` — define and phase-match it.** `Δdelivered` = the increment of the harness report JSON's **delivered-message
  counter** (the same `delivered` count the soak PASS bar and the collapse% are computed from), read at the **SAME T0 and T1
  snapshots** as the wait-stats delta (co-timestamped — §3a). Not the whole-soak delivered count; not a separately-timed read.
- **Normalize THREE ways — a per-message rise ALONE is not admissible.** The anti-adjacency test's denominator (`Δdelivered`)
  **collapses at exactly the arm under test** (N=16 delivers ~9%), so a wait whose absolute `Δwait_time_ms` did not surge per
  unit of *work* can still show "GREW N=4→16" purely because fewer messages drained in the window — the same
  fixed/mis-scaled-denominator artifact that fabricated the B1–B10 ladder results and carried C4's 70.68%. Guard the
  denominator by reporting all of:
  1. **`resource_wait_ms_per_msg`** = `Δresource_wait_ms / Δdelivered` (per-work, delivered-based) — report it, but it is
     **inflated and noisy at N=16** where `Δdelivered` is small; never credit "GREW" on this alone.
  2. **`resource_wait_ms_per_sec`** = `Δresource_wait_ms / (T1−T0 seconds)` (per-plateau-second, wall-time) — a shrinking
     delivered denominator cannot fabricate growth here.
  3. **mean wait DURATION per event** = `Δresource_wait_ms / Δwaiting_tasks_count` (per WAIT EVENT) — this **removes the
     concurrency/waiter-count confound**: a per-msg rise with a *flat* per-event duration is "more waiters, same contention"
     (concurrency scaling), NOT an intensifying wall.

  Also report the **absolute `Δresource_wait_ms`** alongside so a reviewer can see whether a per-message rise is a real surge
  or a denominator artifact. *(A work-based denominator that does not collapse — per-claim-attempt or ingress-accepted — is
  preferable to per-delivered where available; report it if the harness exposes the count. Delivered collapses precisely where
  the ratio is load-bearing.)*
- **Signal vs resource split — per WAIT TYPE, as context; NOT a fleet-level CPU-vs-contention discriminator.** Compute
  `Δsignal_wait / Δwait_time` **per wait type**, and report a fleet aggregate only as descriptive context. **Do NOT use the
  fleet-level `Σ signal / Σ wait` to decide CPU-vs-contention.** `signal_wait_time_ms` is present on **EVERY** wait type — it is
  the RUNNABLE-queue latency a task pays AFTER its resource is granted, before it gets back on a scheduler. On a CPU-saturated
  box (the N=16 store runs 92–93%, C3), a **genuine LOCK/LATCH contention wall ALSO shows a high fleet `Σsignal/Σwait`**,
  because each of the many short lock/latch grants pays scheduler-queue latency on a saturated box, and the sheer *count* of
  short resource waits (each re-queuing) inflates the aggregate signal fraction. The fleet fraction therefore **cannot
  discriminate contention from CPU-scheduling when the box is CPU-saturated** — reading it as "SIGNAL dominant ⇒ CPU-bound"
  can mis-classify a pure-contention wall as CPU-BOUND (the exact false-mechanism-from-adjacency error, inverted). A high
  signal fraction is **necessary-not-sufficient** for the CPU branch; it must be reconciled against the per-wait-type
  breakdown — **is the signal concentrated in `SOS_SCHEDULER_YIELD` (oversubscription), or smeared across `LCK_*`/`LATCH_*`
  (contention with re-queue churn)?** The latter is contention, not a CPU wall. A high signal fraction ON a `LCK_*`/`PAGELATCH`
  resource is consistent with CONTENTION on a CPU-saturated box — it is NOT evidence of CPU-scheduling wait.
- Rank the surviving (non-benign) wait types by the triple above. The candidate contention waits to watch (do **not** pre-judge
  which — let the delta rank them): `LCK_M_*` (row/page/object locks — true blocking contention),
  `PAGELATCH_EX/SH/UP` (in-memory page latch — hot-page contention. **Which page matters: inspect `resource_description` /
  the waited page's `database_id`. PAGELATCH on tempdb (`database_id = 2`) SYSTEM-catalog pages ⇒ the feature is likely OFF ⇒
  re-verify §1 / VOID. PAGELATCH on the STORE db's own USER pages (e.g. a hot FIFO index page) is a legitimate,
  feature-INDEPENDENT hot-page contention finding — do NOT void it; it is a valid Verdict-1 candidate.** The §3b sample
  captures `resource_description` — use it to distinguish the two before invoking VOID),
  `PAGEIOLATCH_*` (data-page IO — a storage wall, different again), `WRITELOG` (log flush), `LATCH_EX/SH` (non-page latch, incl.
  some XTP structures). `SOS_SCHEDULER_YIELD` is tracked separately as the CPU-oversubscription signal (§4).
- **If `CXPACKET`/`CXCONSUMER`/exchange waits rank high, the store unexpectedly went PARALLEL** — that is a plan issue, not a
  contention wall. Report it, do not attribute it as the wall (`CXCONSUMER` is in the benign exclusion list — see below — but
  `CXPACKET`/exchange are not, deliberately, so an unexpected-parallelism regression surfaces).

### (b) LIVE BLOCKING / WAITING-TASKS sample — the independent corroboration (N=16)

Aggregate `dm_os_wait_stats` **cannot** tell a **convoy** (a blocking chain — session A holds a lock, B..Z wait on A) from
diffuse independent waits that merely sum to a large number. Naming a wait "the wall" from aggregate rank alone is exactly the
telemetry-adjacency error that got C2 (and nearly C4) retracted. This sample is the corroboration the §4 rule **requires**
before any wait can be called the wall. Run it every **~10 s** at **N=16** (c6-16 only; skip on the no-capture control):

```sql
-- Currently-waiting tasks joined to what they're running and WHO is blocking them.
-- dm_os_waiting_tasks returns ONLY tasks waiting right now (small set) -> this is a LIGHT query.
-- Public columns confirmed: dm_os_waiting_tasks(waiting_task_address, session_id, wait_type, wait_duration_ms,
--   resource_description, blocking_task_address, blocking_session_id).
SELECT
    wt.session_id,
    wt.wait_type,
    wt.wait_duration_ms,
    wt.blocking_session_id,                 -- non-NULL and != session_id  =>  a real blocking chain (a CONVOY)
    wt.resource_description,                 -- the exact lock/latch resource (e.g. KEY/PAGE/OBJECT id, latch class)
    r.status,                               -- RUNNING (on CPU) | RUNNABLE (queued for CPU) | SUSPENDED (waiting on resource)
    r.command,
    r.cpu_time,
    r.total_elapsed_time,
    r.wait_resource,
    SUBSTRING(t.text,(r.statement_start_offset/2)+1,
        (CASE r.statement_end_offset WHEN -1 THEN DATALENGTH(t.text)
              ELSE r.statement_end_offset END - r.statement_start_offset)/2 + 1) AS running_stmt
FROM sys.dm_os_waiting_tasks wt
LEFT JOIN sys.dm_exec_requests r ON r.session_id = wt.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE wt.session_id > 50
ORDER BY wt.wait_duration_ms DESC;
```

Also capture scheduler pressure each sample (RUNNABLE queue = tasks waiting for CPU = the SOS_SCHEDULER_YIELD story). **Capture
it on N=4 and N=8 too — it is trivially light and Verdict 2 needs a baseline** (see below):

```sql
SELECT scheduler_id, current_tasks_count, runnable_tasks_count, active_workers_count, work_queue_count
FROM sys.dm_os_schedulers WHERE status = 'VISIBLE ONLINE';
```

**What to extract — a convoy is EITHER of two forms (a latch convoy is NOT visible via `blocking_session_id`):**
- **(a) Lock convoy:** the fraction of samples in which **`blocking_session_id` is populated (non-NULL, ≠ own session_id)** — a
  blocking chain (session A holds a lock, B..Z wait on A). Record chain depth (how many sessions blocked on one head) and
  whether the head is a claim/dispatch statement.
- **(b) Latch convoy:** for **`PAGELATCH_*` / `LATCH_*` contention, `blocking_session_id` is frequently NULL even though the
  latch IS a genuine contention convoy** — the contention shows as **multiple sessions simultaneously SUSPENDED on the SAME
  `resource_description`**, not as a `blocking_session_id` chain. So **also** count, per sample, the number of distinct
  sessions sharing each `resource_description` (and its latch class), and flag a resource with several concurrent SUSPENDED
  waiters as a latch convoy. **A NULL `blocking_session_id` does NOT rule out latch contention** — the candidate contention
  wall here (post-tempdb-metadata XTP/hot-page residual) is most likely a latch, so this branch is the one most likely to fire.

Record the modal blocking `wait_type` and `resource_description` for whichever form is present. **The §4 corroboration accepts
EITHER form.** A high `runnable_tasks_count` across schedulers with neither convoy form present ⇒ CPU-scheduling wait (points to
CPU); a persistent lock chain OR a shared-latch convoy on a `LCK_*`/latch resource ⇒ contention (points to a
granularity/RCSI/partitioning fix).

**`runnable_tasks_count` is an instantaneous gauge — report it as a DISTRIBUTION with a BASELINE, never a point read.** Per
arm, report the per-scheduler **median and max** of `runnable_tasks_count` across all samples (not a single spiky sample).
Verdict 2 (§4) may cite "high runnable_tasks" **only** if the **N=16 median is materially above the sustaining N=4 control's
median** (pre-registered — a lone spike cannot tip the CPU verdict). This is why the scheduler sample runs on N=4/N=8 too.

**Bound §3b's own cost + fence its own waits out (the §3b/§3a instrument feeds the SAME server-wide `dm_os_wait_stats` the
verdict reads).** Record the capture connection's own `execution_count` and `total_worker_time` (from its session) at T0/T1 and
report it as a fraction of plateau store CPU — **if it exceeds ~1–2%, treat the wait profile as instrument-contaminated.**
Prefer to drop the `OUTER APPLY sys.dm_exec_sql_text` from the recurring 10 s sample (capture only
`session_id`/`wait_type`/`blocking_session_id`/`resource_description`/`status` each 10 s; resolve statement text for the few
distinct `sql_handle`s **once, post-hoc**) so the recurring query stays a tiny read even when the N=16 waiting-tasks set is
large under collapse. **Capture the `session_id` of every §3a/§3b/§3c/§3d monitoring connection** so they can be fenced out at
analysis time — see §5's fencing procedure (`dm_os_wait_stats` is server-wide and cannot be session-filtered directly, so the
capture sessions' own LCK/LATCH/SOS waits land in the delta unless subtracted via `dm_exec_session_wait_stats`).

### (c) FIXED CPU RECONCILIATION — the honest denominator (secondary, corroborating)

C4's reconciliation "passed" the ≥70% pre-gate **only** at 70.68%, and only because the denominator was an arithmetic mean of
25 instantaneous `store_proc_cpu` gauges **deflated by idle-ramp snaps** (snap0=0%, snap1=37%) that the delta numerator never
credits. Every phase-matched / sustained denominator gave **64.5–69.6%** (INCONCLUSIVE band), and the plateau intervals (box
92–94%, the actual wall) never exceeded ~69%; the pass was carried entirely by 4 **collapse-tail** intervals where box CPU
*drops off the wall*. Redo it honestly:

1. Take **two** `dm_exec_query_stats` snapshots (T0/T1 = the **same sustained plateau** as §3a — NOT soak-start, NOT the
   collapse tail). Use the §3 query from the C4 handoff (query_hash, total_worker_time, execution_count, total_logical_reads,
   stmt_text) — **two reads, diffed**, not a rolling scan.
2. **Numerator** = attributed query-CPU util = `Σ family cpu-s over [T0..T1] / (window_s × n_sched)` (C4 used `n_sched = 8`).
3. **Denominator** = **phase-matched sustained-plateau box store CPU** — the mean of the `store_proc_cpu` gauges **inside
   [T0..T1] only**, with the idle-ramp snaps (min=0) **dropped**. **Bake in the C3 cross-check:** the store box ran **92–93%**
   at N=16 (C3-corroborated) — the honest sustained denominator should sit near there, ~92–94%, NOT C4's idle-diluted 84.4%.
4. Report the **corrected ratio** = numerator ÷ (honest sustained denominator). C4's own recomputations under this denominator
   landed **64.5–69.6%** (idle-diluted, it read 70.68%). **Apply the §4 band, NOT a hard 70% knife-edge** (C4's whole lesson is
   that the pivot lands inside a 64.5–70.68% instrument band): **≥ 72% ⇒ CPU-BOUND (Verdict 3); ≤ 66% ⇒ AMBIGUOUS (Verdict 4);
   66–72% ⇒ INCONCLUSIVE-INSTRUMENT (Verdict INC) — do NOT name a verdict, report both denominators.** If C6 reproduces ≤ 66%
   on the honest denominator, the CPU story does **not** clear and the wall is not explained by query CPU — consistent with a
   WAIT-bound frame.

State the corrected ratio explicitly **with the phase-matched, C3-consistent denominator**, report the idle-diluted ratio
beside it, and say which band it lands in — this is the one number that makes the CPU story finally honest, and the band (not a
1-point knife-edge) is what keeps it honest.

### (d) SCAN-CONFOUND CONTROL for `list_fifo_lanes` — is its 47% intrinsic or a backlog effect?

C4 applied the cpu/exec-vs-reads scan control (MUST-FIX 18) **only to `claim_fifo_heads`**, leaving `list_fifo_lanes` (the
dispatcher's read-only ready-lane discovery scan, the #1 raw-CPU consumer at 47.46%) **uncontrolled**. Its `O(pending rows)`
`DISTINCT` + `CROSS APPLY` scan grows with the 208k backlog, so its N=16 dominance may be a **collapse effect**, not a cause.
From the same T0/T1 `dm_exec_query_stats` deltas, for the `list_fifo_lanes` hash(es) — match on **statement-shape fingerprint**
across arms (C4 found raw `query_hash` drifts because pyodbc emits per-parameter `nvarchar(<len>)` headers + variable
`(VALUES …)` lane lists; sum the hashes that share the normalized shape), compute across **N=4 / N=8 / N=16**:

| metric | source | reading |
|---|---|---|
| `cpu_us_per_exec`      | `Σ total_worker_time / Σ execution_count`   | does per-call CPU rise with N? |
| `logical_reads_per_exec` | `Σ total_logical_reads / Σ execution_count` | does the scan get **deeper** with the backlog? |
| `cpu_us_per_read`      | `Σ total_worker_time / Σ total_logical_reads` | **the confound control** — roughly **flat** ⇒ the growth is the deeper scan (a backlog *effect*); **rising** ⇒ genuinely-decoupled intrinsic per-call cost |

Report the three values per arm and the verdict: **`list_fifo_lanes` 47% is a backlog-scan EFFECT** (cpu/read flat, reads/exec
explodes with backlog — the same pattern C4 found for claim, where cpu/read stayed ~28–41 us while reads/exec grew ~50×) **or
an intrinsic cost** (cpu/read rises). This is **diagnostic input for the owner's ratification decision, not a ruling on it**
(see §0) — it tells the owner whether folding `list_fifo_lanes` into claim-machinery would import a collapse-effect artifact.

### Whole-box CPU
Keep **`max_core%` on both boxes** for every arm (the validated substitute; the per-PID collector is bug #220, fixed in #861
but shardcert has no in-harness per-PID sampler → read `max_core%`). This is the box-CPU ground truth the §3(c) denominator
and the §4 signal/resource split are reconciled against (store box 92–93% at N=16, C3-verified).

---

## 4. DECISION RULE (PRE-REGISTERED — fixed before the run)

Computed on the **sustained-plateau** wait deltas (§3a) — normalized THREE ways (per-message, per-plateau-second, and
per-wait-event), never per-message alone (its denominator collapses at N=16) — corroborated by the live convoy sample (§3b),
cross-checked by the corrected reconciliation (§3c). **All conditions below refer to the sustained plateau, NOT the collapse
tail.** If N=16 has no qualifying plateau (§3a existence gate), the arm is AMBIGUOUS-STRUCTURAL (Verdict 4) by construction.

**Pinned numeric definitions (fixed before the run — so no branch is analyst-selectable):**
- **`GREW`** (the anti-adjacency growth floor, consistent with C4's 1.12 per-step discipline): a wait's growth metric at
  N=16 is **≥ K× its N=4 value AND monotonic through N=8**, with **K pre-registered (state K; C4 used a 1.12 per-step floor —
  pick and pin a value)**. "GREW" requires the growth to hold on **BOTH** a work/time-based metric (`resource_wait_ms_per_sec`
  **and** the per-event mean duration `Δresource_wait_ms/Δwaiting_tasks_count`) — **not** the delivered-based
  `resource_wait_ms_per_msg` alone (its denominator collapses at N=16 and fabricates growth, §3a). The **absolute
  `Δresource_wait_ms`** must also have risen N=4→16. **And the rise must EXCEED the c6-16 vs c6-16-nocap perturbation band
  (§5)** — a per-message rise within the no-capture delta is instrument, not a confirmed grower.
- **`DOMINATES`**: the candidate wait is **≥ 50% of the summed non-benign `resource_wait_ms_per_sec`** at N=16 **AND ≥ 2× the
  next-ranked wait**. (A wait that is merely rank-1 does not "dominate".)
- **`convoy present`**: §3b shows a lock chain OR a shared-latch convoy (either form, §3b) on that resource in **≥ X% of
  samples** (state X).
- **`little/no blocking`**: `blocking_session_id` populated AND no shared-latch convoy in **< X%** of §3b samples (same X).

| # | verdict | condition | consequence / fix class |
|---|---|---|---|
| **1** | **WAIT-BOUND — CONTENTION** | A single **RESOURCE** wait (e.g. `LCK_M_*`, `PAGELATCH_EX/UP`, `LATCH_EX`) **DOMINATES** (pinned def) the non-benign resource-wait delta at N=16, **it GREW N=4→N=16** (pinned `GREW` floor + ±1-snap stable, §3a), **AND** the §3(b) live sample shows a **convoy** (lock chain OR shared-latch, pinned def) on that same resource. | **Name the wait.** The wall is **contention**, not CPU. The fix is **contention reduction** — lock granularity, RCSI/`READ_COMMITTED_SNAPSHOT`, row/partition-level access, hot-page/hot-key partitioning — **NOT a CPU/SQL rewrite** of claim or dispatch. This **re-scopes the whole throughput plan** away from the pooled-claim CPU rewrite. |
| **2** | **CPU-BOUND — scheduler oversubscription** | **`SOS_SCHEDULER_YIELD` itself DOMINATES (pinned def) the non-benign resource-wait delta AND GREW N=4→N=16 (pinned `GREW` floor + ±1-snap stable — the SAME anti-adjacency gate as Verdict 1, applied to SOS)**, **AND** independent corroboration: the §3b **`runnable_tasks_count` MEDIAN rose materially N=4→N=16** (above the sustaining N=4 control — not merely "high" at N=16), store box **`max_core%` at/near saturation (92–93%, C3)**, requests predominantly **RUNNING/RUNNABLE not SUSPENDED**, **AND `little/no blocking`** (pinned def) in §3(b). | Genuinely **CPU-bound after all.** Back to the dispatch-path CPU question — **and the §3(c) corrected denominator governs** which query family (the C4 ratification stays with the owner). The pooled-claim / dispatch CPU rewrite is back on the table as the lever. |
| **3** | **CPU-BOUND — reconciliation clears** | Wait is **spread thin** — no wait DOMINATES + GREWs (Verdicts 1 and 2 both fail their gate) — **AND** the §3(c) corrected reconciliation **clears the honest phase-matched denominator: ratio ≥ 72%** (see the band below). | **CPU-bound.** Re-open the dispatch-path CPU question; the honest denominator (not C4's idle-diluted 70.68%) is now the basis. |
| **4** | **AMBIGUOUS — structural** | No wait DOMINATES + GREWs, **AND** the corrected CPU reconciliation is **≤ 66%** on the honest denominator — **OR** the N=16 plateau-existence gate (§3a) is not met. | The N=16 collapse is **aggregate / structural**, not a single wait and not a single query. **Escalate to a batching / fusion / topology conversation** (group-commit, thread-hop fusion, `accepts=`/txn-per-event levers, engine-shard topology) — **not** a single-query or single-wait fix. |
| **INC** | **INCONCLUSIVE — INSTRUMENT** | No wait DOMINATES + GREWs, **AND** the corrected reconciliation lands in the **66–72% band** (C4 landed 64.5–70.68% here — this band is real and expected). | **Do NOT name a verdict.** Report BOTH the idle-diluted and the honest phase-matched denominators and the ratio each yields. The knife-edge is instrument-carried (C4's lesson); a 1-point move must not flip CPU-BOUND↔AMBIGUOUS. |

**PRE-REGISTERED PRECEDENCE (Verdicts 1 and 2 are NOT mutually exclusive — pin the tie-break before the run).** Under a real
N=16 collapse a profile can satisfy BOTH: a grown `LCK_*`/latch convoy (blocked holders back up while descheduled) AND a risen
runnable queue with substantial `SOS_SCHEDULER_YIELD` (the collapse oversubscribes schedulers at the same time). **If a
resource-wait convoy clears Verdict 1's full gate, Verdict 1 takes precedence over Verdict 2 regardless of
`runnable_tasks_count`** — a backed-up scheduler is an **EFFECT** of blocked holders, not independent oversubscription. Verdict
2 may be declared **only** when Verdict 1's convoy gate is NOT met (the pinned `little/no blocking` condition holds).

### PRE-REGISTERED ANTI-ADJACENCY GUARD (the landmine this run exists to avoid)

This workstream **RETRACTED TWO results** (C2, and nearly C4) for asserting a mechanism from telemetry **adjacency**. Bind
these before naming anything "the wall":

- **Rank-1 is NOT a surge.** A wait being the #1 wait_type is INVALID as evidence when it is #1 only **by default** — e.g.
  because the previous #1 (`PAGELATCH` on the tempdb catalog) collapsed to ~0 once C3's feature removed it. Something can
  become the largest remaining wait without its own magnitude changing at all. **`SOS_SCHEDULER_YIELD` is the single most
  likely wait to be rank-1-BY-DEFAULT after PAGELATCH is removed** — so the guard below binds it EXACTLY as hard as it binds
  any `LCK_*`/latch wait. This guard is **symmetric across Verdicts 1 and 2**: a CPU-BOUND verdict reached by "SOS is #1 now"
  is the C2 retraction re-imported into the run built to avoid it, just pointing at a different wait.
- **Require a GROWN delta, on a pinned FLOOR, on a non-collapsing denominator.** Before naming ANY wait the wall — a resource
  wait (Verdict 1) OR `SOS_SCHEDULER_YIELD` (Verdict 2) — it must clear the **pinned `GREW` floor** (§4 definitions: ≥ K×
  N=4→16, monotonic through N=8, K pre-registered à la C4's 1.12). "GREW" is **binary and un-floored is forbidden** — any
  nonzero rise clearing it is how apparatus noise (§5's +68%-class perturbation) mints a false grower. The growth must hold on
  the **`resource_wait_ms_per_sec` (per-plateau-second) AND per-event-duration** metrics, **NOT** `resource_wait_ms_per_msg`
  alone: the delivered denominator **collapses at N=16 (the arm under test)** and inflates the per-msg ratio mechanically —
  the same fixed/mis-scaled-denominator failure that fabricated the B1–B10 ladder and carried C4's 70.68%. The **absolute
  `Δresource_wait_ms` must also have risen**, and the rise must **exceed the c6-16-nocap perturbation band (§5)**.
- **Require independent corroboration — for BOTH verdicts.** Verdict 1 requires the §3(b) live sample to show a **convoy**
  (lock chain OR shared-latch convoy — §3b) on that resource. **Verdict 2 requires the mirror-image positive evidence, not an
  absence:** the `runnable_tasks_count` **median must have RISEN materially N=4→N=16** (against the sustaining N=4 control —
  not merely be "high" at N=16), corroborated by store `max_core%` at/near saturation (92–93%, C3) and requests predominantly
  RUNNING/RUNNABLE (not SUSPENDED). An aggregate rank plus a per-message rise, with no convoy (V1) or no risen runnable queue
  (V2), is **not** sufficient. Aggregate `dm_os_wait_stats` **cannot** distinguish a convoy from a sum, and it cannot
  distinguish scheduler oversubscription from a saturated box's re-queue churn; that is exactly why §3(b) exists.
- **`SOS_SCHEDULER_YIELD` being rank-1 at N=16 is NOT sufficient for Verdict 2.** It is the most likely rank-1-by-default wait
  after PAGELATCH is removed. It must show a GROWN delta (pinned floor, non-collapsing denominator) AND a risen RUNNABLE queue,
  or the profile is spread-thin → Verdict 3/4, not Verdict 2.
- **Separate the SUSTAINED-PLATEAU profile from the COLLAPSE profile.** A collapse's waits are partly an **effect** of the
  208k backlog (the same defect that carried C4's false 70.68% — the pass was manufactured by the off-wall collapse-tail
  intervals). **Do not attribute cause from the collapse tail.** The verdict is computed on the sustained-plateau delta only;
  the collapse-tail delta is reported **labelled and excluded** from the verdict. And if N=16 has no qualifying plateau at all
  (§3a existence gate), the arm is AMBIGUOUS-STRUCTURAL by construction — a plateau is not fabricated from ramp snaps.

**Do not soften.** If §4 lands on WAIT-BOUND-CONTENTION or AMBIGUOUS, do not upgrade it toward "the CPU rewrite still helps."
That is a hypothesis C6 does not test. Report the class the data names. **Symmetrically, do not soften toward CPU-BOUND
(Verdict 2/3) either** — reviving the assumed pooled-claim rewrite on a flat-per-message SOS that is merely rank-1-by-default is
the same adjacency error. Neither direction is the safe default.

---

## 5. RISKS / CAVEATS

- **Apparatus perturbation was REFUTED for throughput — but the WAIT profile still needs a control.** The premise that
  C4's `dm_exec_query_stats` scan made c4-16 run +68% `claim_mean` and flipped c4-8 was **disproved by the clean recapture**
  (`claim_mean` unmoved 93.4→92.6 ms; light c4-8 tipped *worse*, not better — top REVISION block). So the no-capture control
  is **not** here to subtract a proven throughput perturbation. It exists because the **WAIT profile** is a different question:
  `dm_os_wait_stats` is server-wide, so the capture's own queries can add waits even when `claim_mean` is unmoved. `c6-16-nocap`
  runs N=16 with all DMV capture OFF; report the **claim_mean / stranded / delivered% delta** (expected ~0 per the recapture)
  **and** — the actual point — the WAIT-profile delta.
  **BUT the deliverable is a WAIT profile, and `claim_mean`/`stranded`/`delivered%` are ENGINE-throughput proxies — a matched
  claim_mean does NOT license "the wait profile is un-perturbed."** Two failure modes the throughput-proxy comparison misses,
  and their fixes:
  1. **The instrument's own waits are INSIDE the measurement.** `dm_os_wait_stats` is server-wide; the §3a/§3b/§3c/§3d capture
     connections issue queries that themselves WAIT (DMV internal latches, `sql_text` lookups, scheduler entry), and those
     waits land in the very same server-wide T1−T0 delta the verdict is computed from. **Fence them out:** at T0/T1 also
     snapshot **`sys.dm_exec_session_wait_stats`** (session-scoped) for **every** capture/monitoring `session_id` (collected in
     §3b), and **SUBTRACT** their contribution from the server-wide `dm_os_wait_stats` delta. **Report BOTH the raw and the
     fenced per-wait numbers.** The verdict is computed on the **fenced** numbers.
  2. **The nocap arm as written produces NO wait profile to diff.** A near-zero claim_mean delta does not prove the wait
     profile is clean — a capture worker can be light on claim_mean while still injecting its own LCK/LATCH/SOS into the shared
     `dm_os_wait_stats`. **Give the nocap arm a WAIT cross-check:** run `c6-16-nocap` with **ONLY the two-snapshot §3a
     wait-stats reads (T0/T1) enabled** and everything else OFF (the ~10 s §3b live loop OFF, no §3c/§3d rolling scan) — that
     single pair of reads is negligibly perturbing yet yields a **second, near-un-perturbed wait profile**. Diff the
     top-ranked resource wait's per-second and per-event delta between fully-instrumented c6-16 and this nocap wait profile.
     **If they differ materially, the wait profile IS instrument-sensitive → VOID or down-weight the verdict.** This is the
     quantification the claim_mean-only comparison cannot provide. (The `GREW` floor in §4 already requires the growth to
     exceed this c6-16-vs-nocap band.)
  If the delta (throughput OR wait) is large, the c6-16 wait profile is partly the instrument — say so, and treat the wait
  numbers as an upper bound on contention.
- **Other workload on the store instance (the "you may be measuring the load-gen's waits" analog of C5's #1 risk).** The
  server-wide `dm_os_wait_stats` delta includes **any** session active on the store instance during the plateau — the load-gen
  if it connects there, any HA/DBMIRROR/background activity, or a per-run store-DB teardown/create landing inside the window.
  **Pre-flight (add to §1): confirm the store box runs ONLY the store SQL instance and no other active workload during the
  plateau — the load-gen drives the ENGINE box, and any load-gen DB connections target the ENGINE, not the store instance.**
  If any non-store session is active on the store instance, fence it out via the same `dm_exec_session_wait_stats` subtraction
  as above. The benign-exclusion list handles idle *system* waits but NOT another real workload's `LCK_*`/`LATCH_*`/`WRITELOG`.
- **Collapse-vs-cause.** The 208k N=16 backlog **inflates** waits (deeper scans, more lock holders) — a wait can be large at
  N=16 purely because the queue is deep, which is an *effect* of the collapse, not its cause. This is why the verdict is on the
  **sustained-plateau** delta and why §3(d) scan-controls `list_fifo_lanes`. Never read cause from the collapse tail.
- **Anti-adjacency trap (restated).** Rank-1-by-default ≠ surge. Two results were retracted for this. §4's guard is mandatory,
  not advisory.
- **Feature-OFF = VOID.** If `PAGELATCH_*` on tempdb system tables shows up #1, the most likely cause is the feature is OFF
  (§1) — you are measuring C2's already-retracted latch. Re-verify `IsTempdbMetadataMemoryOptimized = 1` before trusting any
  wait profile.
- **A WAIT-bound verdict re-scopes the ENTIRE throughput plan.** If §4 lands on WAIT-BOUND-CONTENTION, the pooled-claim /
  dispatch **CPU** rewrite (the currently-assumed load-bearing lever) is **not** the fix — the fix is contention reduction
  (granularity / RCSI / partitioning), a different build entirely. This is a big result and must be reported as such, with the
  §3(b) blocking chain as the evidence, not the aggregate rank.
- **`n_sched` and box specifics** are inherited from C4 (8 schedulers on the store box). If the store box VM changed, the
  signal/resource interpretation and the §3(c) denominator both shift — confirm the box matches C4 before comparing.

---

## 6. TEARDOWN (return the rig to the C2 baseline)

Only after the C6 handback is banked (and after C4/C5 if they were run in the same session):

```sql
ALTER SERVER CONFIGURATION SET MEMORY_OPTIMIZED TEMPDB_METADATA = OFF;   -- two keywords, a SPACE
-- RESTART the SQL Server service (disable also requires a restart).
-- optionally:  DROP RESOURCE POOL tempdb_xtp;   (after the restart)
```

Keep SQL Server running otherwise (instance-store D: wipes on STOP/START; reboot is fine).

## 7. Do NOT

- **Feature OFF = VOID** — a run with the tempdb latch present measures C2's wall, not C3/C4's residual. Verify
  `IsTempdbMetadataMemoryOptimized = 1` first.
- Do **not** flip `claim_mode` to `per_lane` (inverts at scale; and CLAIM would measure ~0% under FIFO+pooled).
- Do **not** raise `--drain-timeout` past ~300 s (re-arms harness defect B7). Keep **150**.
- Do **not** read `exit_code` as a verdict — gate on **`result`**. Every collapsed arm serializes `exit_code = 0`.
- Do **not** quote `ceiling.sustained_events_per_s` from a **collapsed** arm — it is populated even when
  `result = SOAK_NOT_SUSTAINED` (reads 145.359 on c3-16, an arm that delivered 27.9%). It is a trap.
- Do **not** name any wait "the wall" from **rank-1-by-default** — require a GROWN delta (pinned `GREW` floor, on
  per-second AND per-event metrics, exceeding the nocap band, ±1-snap stable) **and** convoy/runnable corroboration (§4 guard).
  This binds `SOS_SCHEDULER_YIELD`/Verdict 2 **exactly as hard** as it binds `LCK_*`/latch/Verdict 1 — SOS is the most likely
  rank-1-by-default wait after PAGELATCH is removed. This is the specific error that retracted C2 and nearly C4.
- Do **not** credit "GREW" from `resource_wait_ms_per_msg` alone — its `Δdelivered` denominator **collapses at N=16** (the arm
  under test) and fabricates growth (the B1–B10 / C4-70.68% failure class). Require per-second AND per-event AND absolute rise.
- Do **not** fabricate a plateau from ramp snaps. If N=16 has no window meeting the §3a plateau-existence gate, the arm is
  AMBIGUOUS-STRUCTURAL — do not place T1 in a rising ramp (near-zero denominator) or past the knee.
- Do **not** read the fleet `Σsignal/Σwait` as the CPU-vs-contention discriminator — on a CPU-saturated box a contention wall
  also shows a high signal fraction. Concentrate signal in `SOS_SCHEDULER_YIELD` (CPU) vs smeared across `LCK_*`/`LATCH_*`
  (contention) per wait type.
- Do **not** trust a matched `claim_mean` (c6-16 vs c6-16-nocap) as proof the WAIT profile is un-perturbed — diff the nocap
  arm's two-snapshot wait profile too, and fence the capture sessions' own waits out via `dm_exec_session_wait_stats` (§5).
- Do **not** declare Verdict 2 (CPU) when Verdict 1's convoy gate is met — Verdict 1 takes precedence (a backed-up scheduler is
  an effect of blocked holders, not independent oversubscription).
- Do **not** change any pipeline variable vs C4 (2/shard, dests=8, pooled, drain 150). The only deltas are the lighter capture,
  the WAIT capture, and the no-capture control arm.
- Do **not** attribute cause from the collapse tail — sustained-plateau delta only.
- Do **not** treat §3(d) as ratifying the `list_fifo_lanes` family map — that stays with the owner.

## 8. What to send back (`HANDBACK_C6_2026-07-11.md`)

1. **Proof the feature was active** (`IsTempdbMetadataMemoryOptimized` = 1) on every arm — else VOID. Engine commit `98bec81`.
2. **The wait-delta table (SUSTAINED PLATEAU)** for **N=4 / N=8 / N=16**: per wait type, **all three normalizations**
   (`resource_wait_ms_per_msg`, `resource_wait_ms_per_sec`, per-event `Δresource_wait_ms/Δwaiting_tasks_count`), the absolute
   `Δresource_wait_ms`, `signal_wait_ms` per type, and the signal-vs-resource split **per wait type** (fleet aggregate as
   context only, NOT as the CPU-vs-contention discriminator). Report **RAW and capture-session-FENCED** numbers (§5). Mark
   which waits cleared the **pinned `GREW` floor** (on per-sec AND per-event AND absolute, exceeding the nocap band, ±1-snap
   stable). State the **actual T0/T1 snapshot indices, the window's `Δdelivered`, and the plateau-existence gate result** for
   every arm. Include the N=16 **collapse-tail** delta **separately, labelled, excluded from the verdict**.
3. **The live convoy sample at N=16** (§3b): fraction of samples with (a) a populated `blocking_session_id` chain AND (b) a
   shared-latch convoy (multiple SUSPENDED sessions on one `resource_description`); the modal blocking `wait_type` +
   `resource_description`; chain depth; whether the head is a claim/dispatch statement; and the **per-scheduler
   `runnable_tasks_count` median/max** at N=4/N=8/N=16 (baseline for Verdict 2). Report it even if it is "no convoy of either
   form observed" (that steers §4 toward CPU — but only with a RISEN runnable median, not merely a high one). Report §3b's own
   `execution_count`/`total_worker_time` as a fraction of plateau store CPU (the instrument-cost bound).
4. **The corrected CPU reconciliation ratio** (§3c) — numerator ÷ **honest phase-matched sustained denominator** (C3-consistent
   ~92–93%), and which **§4 band** it lands in (**≥72% CPU-BOUND / ≤66% AMBIGUOUS / 66–72% INCONCLUSIVE-INSTRUMENT** — NOT a
   hard 70% knife-edge). State it next to C4's idle-diluted 70.68% so the correction is visible.
5. **The `list_fifo_lanes` scan-confound result** (§3d) — **ALREADY ANSWERED off-line from the existing 3-arm data:
   INTRINSIC** (cpu/read 10.3 → 14.2 → 21.3 µs, 2.06× N=4→16, rising already at N=8/100%-delivered). A fresh run does
   **not** re-derive this; instead **close §3d's one residual** — at N=16, is the intrinsic cost genuine per-page work
   or **collapse-induced cache-spill**? Read it off the §3b live sample: a spill shows as a **memory-grant / tempdb
   wait** in the N=16 blocking sample; its absence supports genuine-intrinsic.
6. **The no-capture-control perturbation delta** (c6-16 vs c6-16-nocap): claim_mean / stranded / delivered% — how much of the
   wall profile is the instrument.
7. **The §4 VERDICT** with the one-line read: **"is the N=16 wall WAIT-bound (on WHICH wait — contention or CPU-scheduling) or
   CPU-bound?"** — and if WAIT-BOUND-CONTENTION, name the wait and cite the blocking chain as the evidence (not the rank).

## 9. Sources / notes

- Continues **C4** (`c4-cpu-attribution-2026-07-11/HANDBACK_C4_2026-07-11.md`): verdict WITHHELD; N=16 wall ~72% off-CPU
  lock/latch WAIT (cpu/elapsed = 0.28); `list_fifo_lanes` 47.46% raw-CPU #1 (uncontrolled) vs claim 40.33% #2; reconciliation
  cleared 70% only on idle-diluted denominator (sustained = 64.5–69.6%); the "+68% instrument perturbation" premise was
  REFUTED by the clean recapture (claim_mean unmoved 93.4→92.6 ms — it is run-to-run/drift variance). C3 cross-check: store
  box 92–93% at N=16.
- House style / prereg discipline / Do-NOT list: C4 & C5 handoffs (`HANDOFF_C4_n16_cpu_attribution.md`,
  `HANDOFF_C5_n8_per_shard_headroom.md`).
- The anti-adjacency landmine (C2 retraction; nearly C4): a wait being rank-1 **by default** is not a surge — demand a
  normalized per-message delta AND a blocking-chain corroboration before naming any wait the wall.
- **Read-only DMVs only. Public DMV / catalog names only.** No secrets, hostnames, IPs, ports, or customer identifiers.
- Benign-wait exclusion list: the standard SQLskills "Wait Statistics" idle set (CLR*/SLEEP*/BROKER*/XE*/LAZYWRITER_SLEEP/
  WAIT_XTP_HOST_WAIT/QDS*/HADR*/PREEMPTIVE_OS_* idle waits, etc.), with **`SOS_SCHEDULER_YIELD` deliberately NOT excluded** —
  it is the CPU-oversubscription signal for §4.
