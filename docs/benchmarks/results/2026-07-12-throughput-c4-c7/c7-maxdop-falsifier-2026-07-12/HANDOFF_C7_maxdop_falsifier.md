# HANDOFF — **C7: is the store's ceiling partly SELF-INFLICTED intra-query PARALLELISM?**

**Date:** 2026-07-12 · **Continues C6** · **Runs on the C6 rig, feature ON, build `98bec81`** · **Cheap:** 3 arms (+1
conditional), no full sweep, **no engine code change.**
**This is a one-sided FALSIFIER. It is designed to KILL a hypothesis cheaply, not to confirm one.**
Read-only DMVs + one **database-scoped** config change. Public catalog names only; no secrets/IPs/PHI.

---

## 0. The question, and the honest status of the thing being tested

C6's fenced, exclusion-set-filtered wait delta showed **`CXSYNC_PORT` (intra-query parallelism exchange) is the
fastest-growing real wait in the run — by a wide margin** (`d_resource_ms`, 720 s window):

| wait | N=4@2 | N=8@2 | N=8@3 | N=16@2 | growth N=4→16 |
|---|---:|---:|---:|---:|---:|
| `WRITELOG` | 127,962 | 191,348 | 250,947 | 577,773 | 4.5× |
| **`CXSYNC_PORT`** | **10,782** | **50,020** | **130,588** | **366,796** | **⭐ 34.0×** |

Corroborating it: `WRITELOG`'s **signal fraction** (`d_signal_ms/d_wait_ms`) climbs **20% → 41% → 50% → 47%** across the
ladder — signal wait is time queueing for a **CPU after the resource was granted**, i.e. tasks increasingly wait on
**schedulers, not on the log.** Consistent with parallel plans oversubscribing the store's 8 schedulers.

**And C6's convoy detector is STRUCTURALLY BLIND to this.** The §3(a) floor needs ≥5 sessions suspended on **one shared**
`resource_description`. Parallelism exchange is **per-query** — it can never share a resource, never meet the floor, and
will **always** return "no convoy," however dominant it is. So C6's **AMBIGUOUS-STRUCTURAL is correct and does not
exclude this.** The instrument could not have found it.

### ⛔ But this is a HYPOTHESIS, and a weak-provenance one. State that plainly.
- **`CXSYNC_PORT` is present on the healthy N=4 arm too** (10.8 s). By this programme's own standard, **a wait that
  appears when the system is healthy cannot be named a wall by its rank or its growth rate.** Naming parallelism the
  wall off that table would be the *exact* inference class that got **C2 and C4 walked back** — and that this
  coordinator retracted an argument for **yesterday** (`REVIEW_C5_handback §2(c)`).
- **The growth may be an EFFECT of collapse, not a cause:** deeper queue scans → larger row estimates → the optimiser
  picks parallel plans. That is precisely the effect-vs-cause trap that left C4 **WITHHELD**.
- **The one thing weakly cutting the other way:** `CXSYNC_PORT` already grows **4.6×** from N=4 to **N=8@2 — a
  100%-delivered, PRE-COLLAPSE arm** (10,782 → 50,020) at only 2× the shards. Suggestive. **Not conclusive.**

**C7 exists because the hypothesis is cheap to KILL.** It does not name parallelism the wall; it runs the A/B that
either kills it or forces it to be taken seriously. **A null result is a fully successful run** — it closes the question
and the programme proceeds to the `txn/event` levers with one less open thread.

**C7 does NOT displace the txn/event levers** (Phase-3 `accepts=`, Phase-4 group-commit). Those remain the primary path
on C5+C6's combined evidence, **whatever C7 returns.** A C7 win would make every event *cheaper*; it would not make
N-sizing *sufficient* on its own. Do not let a positive C7 be read as "we don't need group-commit."

---

## 1. ⚠️ DESIGN NOTE — the test arm is **N=8@3**, NOT N=16. This is deliberate; do not "improve" it back to N=16.

The obvious instinct is to A/B the N=16 collapse. **Don't. N=16's delivered% is NOT reproducible enough to A/B on:**
C3/C4 delivered **9.4%**; C6's `n16x2` delivered **26.2%**. That is a ~17-point spread on the *same* config — an A/B
against that baseline could not detect anything smaller than the noise.

**`N=8@3` is the most reproducible collapse the programme has — 3 for 3:**

| run | delivered | `in_pipeline` slope |
|---|--:|--:|
| C5-b | 51.9% | +108.7 |
| C5-b2 | 50.0% | +110.9 |
| C6 `n8x3` | 50.1% | +112.5 |

**~50–52% delivered, slope +108…+112.5.** That is a *tight* baseline — tight enough to A/B against. It is also
**cheaper** (24/s fleet vs 32/s) and it is the arm that already has a **matched PASS control** (N=8@2).

**And it makes C7 sharper than a wait-stats question:** N=8@3 is the rung that **defines `R`**. C5 set `R ∈ [2,3)`
*because 3/shard collapses.* So C7 asks, in the most decision-relevant form available:

> **Is `R` itself being depressed by a store CONFIG DEFAULT?**

---

## 2. PRE-FLIGHT (blocking)

1. **Feature ON, verified:** `SELECT SERVERPROPERTY('IsTempdbMetadataMemoryOptimized')` = **1** (+ RG pool
   `tempdb_xtp` @25%). Feature OFF ⇒ **VOID** — you would be measuring C2's retracted latch.
2. **Engine build `98bec81`** — pinned, unchanged from C3/C4/C5/C6. **Do NOT `git pull`. C7 changes NO engine code.**
3. **Boxes unchanged from C6:** engine **m7i.4xlarge**, store **i4i.2xlarge** (`dm_os_schedulers VISIBLE ONLINE = 8` —
   confirm it; the whole hypothesis is about oversubscribing these 8 schedulers).
4. **Record the store's CURRENT parallelism settings BEFORE changing anything** — you must be able to restore them:
   ```sql
   SELECT name, value_in_use FROM sys.configurations
    WHERE name IN ('max degree of parallelism','cost threshold for parallelism');
   SELECT name, value FROM sys.database_scoped_configurations WHERE name = 'MAXDOP';  -- in the store DB
   ```
   **Report both in the handback.** (Expect instance MAXDOP 0 = "use all schedulers", CTFP 5 = the notoriously low
   default. If they are *already* non-default, say so loudly — it changes how C6 should be read.)
5. Everything else identical to C5/C6: pooled, `dests=8`, `--drain-timeout 150` (**do NOT raise past ~300 s** — re-arms
   B7), 900 s soaks, light capture + the C6 convoy sampler.

## 3. THE INTERVENTION — database-scoped, reversible, no restart

Apply to the **store database only** (`mfbench`) — **not** instance-wide, so nothing else on the box is disturbed:

```sql
-- in the store DB:
ALTER DATABASE SCOPED CONFIGURATION SET MAXDOP = 1;
ALTER DATABASE SCOPED CONFIGURATION CLEAR PROCEDURE_CACHE;   -- REQUIRED: else cached PARALLEL plans are reused
```

**Revert (run this at teardown, and before any baseline arm):**
```sql
ALTER DATABASE SCOPED CONFIGURATION SET MAXDOP = 0;          -- or the value you recorded in §2.4
ALTER DATABASE SCOPED CONFIGURATION CLEAR PROCEDURE_CACHE;
```

> **Clearing the procedure cache is not optional.** Without it SQL Server happily reuses the existing **parallel** plans
> and the intervention silently does nothing — you would measure a null result that means only "I forgot to clear the
> cache." The §5 manipulation check exists to catch exactly this.

## 4. THE ARMS (900 s soaks; gate on `result`, never `exit_code`)

| arm | N | /shard | store MAXDOP | role |
|---|---|---|---|---|
| **C7-base** | 8 | 3 | **default** (as recorded) | **Same-session DRIFT CONTROL.** Reproduce the ~50%/+110 baseline *today, on this rig*. **Required** — the arc has been bitten by drift before (the N=8@2 slope is genuinely +4…+13 run-to-run). Do not A/B against a historical number. |
| ⭐ **C7-dop1** | 8 | 3 | **1** | **THE TEST.** Same rung, same rig, same session. Only MAXDOP differs. |
| **C7-dop1-pass** | 8 | 2 | **1** | **HARM CHECK.** N=8@2 currently **PASSES**. Does MAXDOP=1 *break* the healthy case? A config that fixes the collapse but breaks the working rung is not a fix. |
| **C7-dop1-rep** *(conditional)* | 8 | 3 | **1** | **REPRODUCTION — MANDATORY before any positive claim.** Run **only if** C7-dop1 shows material improvement or PASS. **A single un-reproduced win must NOT be reported as a win.** |

Run them **in that order.** If C7-dop1 lands in the null band (§6), **stop** — C7-dop1-rep is unnecessary and
C7-dop1-pass is still worth the 15 minutes for the record.

## 5. THE MANIPULATION CHECK (blocking — this decides whether the run is even valid)

**`CXSYNC_PORT` must collapse to ≈ 0** in the fenced, exclusion-set-filtered wait delta of the MAXDOP=1 arms. Under
`MAXDOP 1` there are **no parallel plans**, therefore **no exchange operators**, therefore **no `CXSYNC_PORT`**.

| observation | meaning |
|---|---|
| `CXSYNC_PORT` `d_resource_ms` falls to ≈0 (say **<5% of the C7-base value**) | ✅ The intervention took effect. The run is valid. Proceed to §6. |
| `CXSYNC_PORT` is still substantial | ⛔ **VOID.** The setting did not apply, or the plan cache was not cleared. **Fix and re-run. Do NOT report a null result** — you have measured your own mistake, not the system. |

Also report, per arm: the fenced filtered wait delta (top 15), the C6 convoy summary (floor/group/chain — cheap, already
built, and a convoy *appearing* under MAXDOP=1 would itself be news), store CPU%, `max_core%` on **all three** boxes,
and `SOS_SCHEDULER_YIELD` task count.

## 6. DECISION RULE (PRE-REGISTERED — fixed before the run; do not tune these to fit a result)

Baseline for comparison = **C7-base** (the same-session drift control), sanity-checked against the historical
50–52% / +108…+112.5. **Primary axis = the store-truth PASS bar** (drained ≤150 s, `stranded 0`, `dead 0`, FIFO intact) —
the same bar C5 used to define `R`. Secondary = delivered % and `in_pipeline` slope.

| C7-dop1 outcome | verdict | consequence |
|---|---|---|
| `CXSYNC_PORT` **not** ≈0 | **VOID** | Intervention didn't apply (§5). Fix, re-run. Not a result. |
| **Meets the PASS bar** (3/shard now sustains) | 🚨 **PARALLELISM WAS A REAL, SELF-INFLICTED CEILING** | **Extraordinary — and suspect it before believing it.** `R` moves to **≥ 3**, which **reopens the C5 ladder**: you would then have to re-run **C5-c (3.62/shard)** to learn whether `R` clears the 3.62 threshold. ⚠️ **A PASS here does NOT by itself resurrect N-sizing** — it moves `R` into the bracket where the question becomes live again. **REPRODUCTION (C7-dop1-rep) IS MANDATORY** before this is reported anywhere. |
| **Still collapses, but delivered ≥ 65% OR slope ≤ +60** | **PARALLELISM IS A REAL COST, NOT THE WALL** | Roughly a halving of the deficit. Worth a config change on its own merits (it makes every event cheaper), but it does **not** move `R` across 3, and the `txn/event` levers remain the path. **Reproduce before claiming.** |
| **Delivered 45–57% AND slope +95…+125** (the null band) | ✅ **PARALLELISM EXONERATED** | Indistinguishable from baseline. `CXSYNC_PORT`'s 34× growth was a **collapse EFFECT, not a cause** — exactly as the C4 `list_fifo_lanes` trap predicted. **Close the question. This is a SUCCESSFUL run.** Proceed to the `txn/event` levers with one fewer open thread. |
| **Materially WORSE** (delivered < 45% or slope > +125) | **PARALLELISM WAS HELPING** | MAXDOP=1 *hurts* — the store benefits from parallelism at this load. Also exonerates the hypothesis, **and warns against the config change.** Report it; it is a real finding. |
| **C7-dop1-pass (N=8@2) FAILS the PASS bar** | ⛔ **CONFIG IS HARMFUL — overrides any win above** | A setting that breaks the currently-healthy rung is **not adoptable**, regardless of what it does to 3/shard. Report this **first** if it happens. |

**The null band is pre-registered at ±~6 delivered-points / ±~15 slope around a 3-run baseline of ~51% / ~+110.** Do not
widen it after seeing the number, and do not narrow it to manufacture a signal.

## 7. Do NOT

- Do **not** change engine code. Build stays `98bec81`. **C7 is a config A/B, nothing else.**
- Do **not** run the intervention **instance-wide** (`sp_configure`) — use the **database-scoped** setting (§3).
- Do **not** skip `CLEAR PROCEDURE_CACHE` — you will silently measure nothing (§5).
- Do **not** A/B against C6's historical number — run **C7-base** in the same session (§4).
- Do **not** report a positive result without **reproduction** (C7-dop1-rep). One arm is not a finding.
- Do **not** name parallelism the wall from `CXSYNC_PORT`'s **rank or growth rate** — only the **A/B outcome** decides.
  (`CXSYNC_PORT` is rank-2 on a *healthy* arm; rank names nothing. This is the C5 §6 / C2 / C4 error class.)
- Do **not** read a positive C7 as "N-sizing is back" or "group-commit is unnecessary" (§0).
- Do **not** raise `--drain-timeout` past ~300 s (B7). Keep **150**. Gate on **`result`**, never `exit_code`. Do **not**
  quote `ceiling.sustained_events_per_s` from a collapsed arm.

## 8. CONFIG REVERT — and ⛔ **do NOT tear down the instances**

> ### ⛔ INSTANCE LIFECYCLE IS THE **OWNER'S** CALL. DO NOT TEAR DOWN.
> **Do not stop, terminate, or deallocate any EC2 instance** (engine box, store box, load-gen) — not when C7 is banked,
> not when the queue looks empty, not ever on your own initiative. **When C7 is banked: report it and HOLD THE RIG.**
> The owner decides what happens next.
>
> This is not bookkeeping — **an unsanctioned STOP is destructive on this rig:** the store's instance-store volume
> **wipes `mfbench` on STOP/START.** A "helpful" teardown destroys the store.

**What you SHOULD revert (software only, no instance action):**

**1. The MAXDOP scoped config — revert it as soon as C7's arms are done.** Leaving the store on `MAXDOP = 1` would
silently invalidate every future run against the C1–C6 ladder.
```sql
-- in the store DB:
ALTER DATABASE SCOPED CONFIGURATION SET MAXDOP = 0;          -- or the value recorded in §2.4
ALTER DATABASE SCOPED CONFIGURATION CLEAR PROCEDURE_CACHE;
```

**2. The tempdb-metadata feature — ONLY on the owner's explicit instruction.** It is shared with C3/C4/C5/C6 and any
queued follow-up (a positive C7 reopens the C5 ladder at 3.62/shard — §6 — which needs the feature ON). **Do not turn it
off pre-emptively.** When instructed:
```sql
ALTER SERVER CONFIGURATION SET MEMORY_OPTIMIZED TEMPDB_METADATA = OFF;   -- two keywords, a SPACE
-- RESTART SQL Server (disable also requires a restart).
-- optionally:  DROP RESOURCE POOL tempdb_xtp;   (after restart)
```

## 9. What to send back (`HANDBACK_C7_<date>.md`)

1. Feature-active proof (`IsTempdbMetadataMemoryOptimized` = 1), build (`98bec81`), boxes (engine m7i.4xlarge, store
   i4i.2xlarge, `n_sched=8`).
2. **The store's parallelism settings as found** (§2.4: instance MAXDOP, **cost threshold for parallelism**, DB-scoped
   MAXDOP) — **before** the change. If they were already non-default, say so **first**.
3. **The §5 manipulation check:** `CXSYNC_PORT` `d_resource_ms` in C7-base vs C7-dop1. **If it did not collapse, the run
   is VOID — say so and stop.**
4. Per-arm table: `result`, delivered %, stranded, dead, `in_pipeline` slope, store CPU%, `max_core%` (all 3 boxes),
   `SOS_SCHEDULER_YIELD` tasks, `CXSYNC_PORT` + `WRITELOG` (+ its **signal fraction**) from the fenced filtered delta,
   convoy floor/group/chain.
5. **The §6 verdict**, one line, from the table — and if positive, **the reproduction arm**. State explicitly whether
   **C7-dop1-pass (N=8@2) still PASSES.**
6. One-line read: **is the store's ceiling partly a config default, or is `CXSYNC_PORT` a collapse effect?**
   *(A null answer is a good answer. Do not go looking for a signal.)*

## 10. Sources
- `CXSYNC_PORT` / `WRITELOG` / signal-fraction table: `c6_convoy_*.json` → `wait_delta_fenced_filtered_top`
  (C6 handback package, 2026-07-12).
- The convoy detector's structural blindness to per-query costs: `REVIEW_C6_handback_2026-07-12.md` §3.
- The hypothesis, and why it is only a hypothesis: `REVIEW_C6_handback_2026-07-12.md` §4.
- N=8@3 baseline (3 runs): `HANDBACK_C5_2026-07-12.md` §2 (c5-b, c5-b2) + `HANDBACK_C6-LIVE_2026-07-12.md` §2 (n8x3).
- The `R` ladder and the store-truth PASS bar: `HANDOFF_C5_n8_per_shard_headroom.md` §3.1.
- Effect-vs-cause trap (why a growth rate names nothing): C4 = WITHHELD, `mf-c4-attribution-result`.
