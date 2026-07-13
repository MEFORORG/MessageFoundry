# HANDBACK — C6-LIVE: is the collapse blocked on a resource CONVOY, or aggregate/structural?

**Date:** 2026-07-12 · engine build `98bec81` (pinned, = C3/C4/C5) · store i4i.2xlarge, engine **m7i.4xlarge**

## 0. Verdict (one line)
**AMBIGUOUS — STRUCTURAL**, on **both** pre-registered contrasts (they agree). The N=8 and N=16 collapses are
**NOT blocked on a resource convoy** — no lock chain, no shared latch/page/grant convoy, no spill convoy. The
collapse is aggregate: the runnable queue grows past the scheduler count (scheduler/CPU pressure), which §4
records as **context and explicitly forbids upgrading to CPU-BOUND** (precluded by the offline 64.4%
reconciliation). Fix path: **not** a contention fix and **not** a single-query CPU rewrite → a batch/fusion/
topology conversation (the C5 `txn/event` levers).

## 1. Feature-active proof + rig
- **`IsTempdbMetadataMemoryOptimized = 1`** verified pre-flight (post-reboot), `tempdb_xtp` @25%, `n_sched=8`.
  **No VOID on any arm:** across 288 convoy samples the only `PAGELATCH` waits were on **`mfbench` (db_id=5)
  USER pages** (scattered, different page each sample) — **never** a tempdb (`2:1:*`) system-catalog page.
  `void_tempdb_catalog_samples = 0` on all four arms. The latch-free feature held throughout.
- **Engine box = m7i.4xlarge (16 vCPU) — CHANGED from C4's m7i.2xlarge** (upsized for C5, kept for C6 per the
  amendment). **Store box = i4i.2xlarge (unchanged)** — `dm_os_schedulers VISIBLE ONLINE = 8` confirms it.
  The change does not affect the within-run convoy contrast, which is what names the verdict.
- Build `98bec81` embedded in all four report JSONs. Light apparatus; pooled; `dests=8`; drain 150; 900 s soaks.

## 2. Arms — throughput + convoy (gate on `result`; convoy is the sole namer, §3(a)/§4)

| arm | role | `result` | deliv % | slope | store CPU% | engine max_core% | **convoy?** | max group / chain | runnable med→ (max) |
|---|---|---|--:|--:|--:|--:|:--:|--:|--:|
| N=4@2 | clean floor | PASS | 100 | 0.0 | 2→27 | 23 | **no** | 0 / 0 | 1 (3) |
| N=8@2 | PASS control | PASS | 100 | 4.3 | 16→64 | 37 | **no** | 1 / 1 | 3 (9) |
| **N=8@3** | **⭐ FAIL primary** | SOAK_NOT_SUSTAINED | 50.1 | 112.5 | 10→81 | 38 | **no** | 1 / 1 | 9 (20) |
| N=16@2 | target | SOAK_NOT_SUSTAINED | 26.2 | 196.3 | 81→94 | 40 | **no** | 2 / 1 | 17 (52) |

Load-gen CPU <1.3% mean (peak 11) every arm — never the limiter. Engine max_core ~23–40% — cool throughout;
the store is the saturating resource (94% at N=16), but **not via a convoy**.

## 3. The convoy read (§3(a)) — PRIMARY contrast: N=8@3 (FAIL) vs N=8@2 (PASS)
- **Fraction of samples meeting the §3(a) floor: 0/72 in BOTH arms.** The floor (≥5 sessions suspended on one
  `resource_description`, OR a blocking chain ≥2 deep) was met in **zero** samples. Across all 288 samples (4
  arms) the **largest suspended group ever seen was 2 sessions** (once, at N=16); the max blocking-chain depth
  was **1**. There is no convoy to name.
- **What the (few) waiters were on:** at N=8@3, 37/72 samples had ≥1 waiting task — scattered `mfbench` USER-page
  `PAGELATCH_SH/EX` (a different page each time — not a hot page) and `CXSYNC_PORT` (intra-query parallelism
  exchange). None shared a resource across sessions. A convoy present at 3/shard and **absent** at 2/shard would
  have named the wall; **there is none in either arm.** → **AMBIGUOUS-STRUCTURAL.**

## 4. Secondary contrast: N=16@2 (target) vs N=4@2 (clean floor)
- N=16@2: no convoy (max group 2, frac 0), waiters scattered on `mfbench` pages + `CXSYNC_PORT`. N=4@2 floor: no
  convoy (max group 0). → **AMBIGUOUS-STRUCTURAL** (as the doc predicted "by construction" — N=16 collapses from
  the start, no plateau). **Both contrasts AGREE**, so there is no §4 "name NEITHER" disagreement — they concur.

## 5. Why NOT a WAIT-BOUND or CPU-BOUND verdict (the guardrails held)
- **Not WAIT-BOUND-CONTENTION:** no LOCK convoy (`LCK_M_*` small and shrinking with load; max chain 1) and no
  shared USER-page/object latch convoy (max group ≤2, pages scattered).
- **Not WAIT-BOUND-SPILL:** no `RESOURCE_SEMAPHORE*` memory-grant convoy, no non-catalog tempdb spill `PAGELATCH`
  convoy, no growing `IO_COMPLETION` convoy. So the C4 `list_fifo_lanes` intrinsic-vs-spill residual does **not**
  resolve toward spill — no collapse-induced spill convoy was observed.
- **Not CPU-BOUND (precluded):** runnable climbs hard (median 1→3→9→17; max 3→9→20→**52** on 8 schedulers) and
  `SOS_SCHEDULER_YIELD` grows to millions of tasks — a strong scheduler/CPU-pressure signal. **Per §4 this is
  context, not a verdict:** the offline 64.4% reconciliation already precludes CPU-BOUND, and a high runnable
  count with no convoy is AMBIGUOUS-STRUCTURAL, not CPU-BOUND.

## 6. Wait deltas are CONTEXT ONLY — the §3(c) exclusion set was applied (and it matters)
All wait numbers are **post-exclusion-set** (the full enumerated §3(c) `NOT IN` list) and **capture-session
fenced** (monitor `spid` subtracted via `dm_exec_session_wait_stats`). The rank-1 wait in **every** arm —
**including the healthy N=4 floor** — is **`WRITELOG`** (128 s at N=4 → 578 s at N=16), growing monotonically with
throughput. That is exactly why a wait's rank cannot name a wall: `WRITELOG` is rank-1 on a 100%-delivered arm.
`CXSYNC_PORT` (parallelism) grows similarly. Reported as context; **named nothing** (this is the discipline the
C5 §6 misread lacked — see `REVIEW_C5_handback §2`).

## 7. Adversarial pass (shipping gate) — false-negative ruled out
The "no convoy" is not a sampler miss: (a) the sampler **saw** waits — 37/72 (N=8@3) and 51/72 (N=16) samples had
≥1 waiting task — they were simply scattered, never grouped; (b) **runnable tracked the collapse building**
(N=16: median 0 early → 39 late, max 52), so the instrument captured the collapsed state; (c) 288 samples,
max group 2, is decisive against a sustained ≥5 convoy; (d) the physics is self-consistent — high runnable +
low/scattered suspended = CPU/scheduler-bound, which by definition produces no resource convoy. The N=8@3
collapse throughput also **reproduced a third time** (50.1% / +112.5, vs C5-b/b2 50–52% / +108–111). Both
contrasts agree; no VOID; feature intact.

## 8. What this settles
**The collapse is not one blocker.** It is not a lock, not a shared latch/page, not a memory-grant or spill, and
not (admissibly) a single CPU-bound query. It is aggregate plumbing — consistent with the 64.4% reconciliation
and with C5's `R<3.62` N-sizing-insufficient result. **Consequence (§4 AMBIGUOUS-STRUCTURAL row):** neither a
single contention fix nor a single-query CPU rewrite clears it → the `txn/event` levers (Phase-3 `accepts=`,
Phase-4 group-commit / batch-fusion / topology) are the path. This closes the C4 WAIT-vs-CPU and
intrinsic-vs-spill open items: no convoy, no spill.

## 9. Sources / notes
Per-arm `out/c6-*/`: `c6-*.json` (throughput), `c6_convoy_*.json` (convoy summary), `c6_samples_*.json` (raw
per-sample), `cpu_soak.csv`/`loadgen_cpu_soak.csv`/`storedmv_soak.txt` (CPU). Sampler: `shardcert/c6_convoy_
sample.py` (§3(a)/(b)/(c) + fence + exclusion set). Read-only DMV / public catalog names only; no secrets, IPs,
hostnames, ports, or PHI.
