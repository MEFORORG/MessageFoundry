# REVIEW — C5 handback (`HANDBACK_C5_2026-07-12.md`)

**Date:** 2026-07-12 · **Reviewer:** coordinator · **Re:** the C5 run (R at N=8, latch-free)
**Bottom line: VERDICT ACCEPTED. One §6 mechanism claim is REFUTED by the run's own data and must not propagate.**

> ### ⚠️ SELF-CORRECTION 2026-07-12 (after C6 ran) — read this with §2
> §2's **conclusion holds**, but **argument (c) was WRONG and is RETRACTED.** I claimed `WRITELOG` was *absent* from
> C5's waits and inferred "no write-path pressure." It was never absent — it was **below the ~792,000 ms noise floor
> of C5's unfiltered top-14**, crowded out by the same idle waits I was criticising. **I inferred absence from a
> truncated list — the mirror image of the handback's own error.** C6's fenced, filtered delta shows `WRITELOG` is
> **rank-1 in all four arms**, including the healthy 100%-delivered N=4 floor.
>
> **This makes the refutation stronger, not weaker:** §6's "write-path signature" fails not because the write wait is
> missing, but because it is **rank-1 even when the system is perfectly healthy** — so it cannot name a wall. See §2(c).
> Arguments (a), (b), (d) are unaffected and independently sufficient.

---

## 1. The verdict is ACCEPTED — `R ∈ [2, 3)` → **N-SIZING INSUFFICIENT**, not deferred

This is the falsifier firing. It is correctly derived, and I could not break it. Verified against the raw artifacts:

- **Build pin holds.** `run.commit_sha = 98bec81d0a5ca74bfb98c52a59281cc74cd5f1c1` is embedded in **all three** report
  JSONs — the C3/C4 build. No newer snapshot was pulled. (§1.5 satisfied.)
- **The ladder follows the pre-registered rule exactly.** C5-a (2/shard) `result = PASS` — `drained: true`,
  `stranded: 0`, `dead_total: 0`, `lane_inversions: 0`, `lane_repeats: 0`, slope **+1.94**. C5-b (3/shard)
  `result = SOAK_NOT_SUSTAINED` — 83,337 stranded, slope **+108.7**; reproduced by c5-b2 — 86,629 stranded, slope
  **+110.9**. Highest rate meeting the PASS bar = **2/shard**. `R ∈ [2, 3)`.
- **Stopping the ladder at C5-b was CORRECT, not a shortcut.** §2 pre-registers *"stop at the first rung that fails the
  bar."* 3/shard failed (twice). C5-c/d/e are all **higher** rates than a reproduced collapse. Running them would have
  been ceremony. `R < 3` ⟹ `R < 3.62` — the threshold is cleared by inequality, not by needing the 3.62 rung.
- **The §3.2 carve-out correctly does NOT fire.** At the collapse, engine `max_core%` ≈ **38–39%** (on 16 cores) and
  load-gen ≈ **1.2%** (peak 7–8.5%). Both are *far* below the ~85% bar, in **both** collapse runs. Neither the
  engine-box nor the load-gen carve-out applies, and the co-limited seam (both within ~5 pts) is nowhere near. This is
  a legitimate design verdict, **not** a deferred lower bound. The m7i.4xlarge upsize bought exactly what it was
  supposed to buy: a decisive answer.
- **The known traps were all avoided.** Gated on `result`, not `exit_code`. Did **not** quote
  `ceiling.sustained_events_per_s` from a collapsed arm (it reads **146.15** on c5-b — the trap was sitting right
  there, populated, on a 51.9%-delivered arm). Used `max_core%` rather than the broken per-PID collector (#861).
  Correctly identified the climb-vs-soak trap (both 3/shard *climb* rungs drained clean at 60 s; the collapse is a
  900 s phenomenon).

**Consequence, unchanged from the handback:** even a fully cleared N=16 misses 520.83 ev/s. The `txn/event` levers
(Phase-3 `accepts=`, Phase-4 group-commit) are **mandatory co-requisites, not follow-ons.**

---

## 2. ⛔ DEFECT — §6's mechanism claim is REFUTED by the run's own wait data. Strike it.

§6 states the store *"walled at ~80% CPU … with a **serialization/write-path signature** (`SOS_SCHEDULER_YIELD` +
`LOGMGR_QUEUE`/`CHECKPOINT_QUEUE`) **rather than raw CPU exhaustion**."* §3 echoes it ("rising `SOS_SCHEDULER_YIELD` +
`LOGMGR_QUEUE`/`CHECKPOINT_QUEUE`"). **This reads two idle background waits as a write-path wall. It is backwards.**

**(a) `LOGMGR_QUEUE` and `CHECKPOINT_QUEUE` are IDLE waits.** They are the log-writer and checkpoint background threads
**waiting for work**. A high value means those threads were **asleep** — it is not evidence of log or checkpoint
pressure, and if anything points the other way. **Both are on the C6 handoff's own enumerated benign-exclusion list**,
which exists precisely to stop this inference.

**(b) The magnitudes prove they are idle.** Over the **800 s** capture window, `c5-b` shows a cluster of waits each
≈ **800,000 ms** — i.e. threads asleep for the *entire* window:

| wait | wait_time_ms | what it is |
|---|---:|---|
| `DIRTY_PAGE_POLL` | 801,918 | background, asleep |
| `SQLTRACE_INCREMENTAL_FLUSH_SLEEP` | 801,815 | background, asleep |
| `HADR_FILESTREAM_IOMGR_IOCOMPLETION` | 801,710 | background, asleep |
| `LAZYWRITER_SLEEP` | 801,676 | background, asleep |
| `REQUEST_FOR_DEADLOCK_SEARCH` | 801,403 | background, asleep |
| `XE_TIMER_EVENT` | 800,415 | background, asleep |
| **`CHECKPOINT_QUEUE`** | **792,684** (391 tasks) | **background, asleep — sits squarely in this cluster** |
| **`LOGMGR_QUEUE`** | **1,582,100** | **≈ 2× the window → two log-writer threads asleep** |

`SOS_WORK_DISPATCHER` tops the raw list at **74.5M ms** (c5-b) / **92.4M ms** (c5-b2) — pure SQLOS idle, and also on
the benign-exclusion list. **The dump was never filtered through the exclusion set**; it is a raw top-N by
`wait_time_ms`. That is the "rank-1 by default" trap.

**(c) ⛔ RETRACTED 2026-07-12 — this argument was WRONG. I made the mirror image of the error I was criticising.**

> **What I originally wrote:** *"The wait that WOULD prove a write-path wall is ABSENT. `WRITELOG` does not appear
> anywhere in the wait output. A log-bound store would show `WRITELOG` at the top. It shows nothing."*
>
> **That is false, and C6 proves it.** `WRITELOG` was in C5's store the whole time. It did not appear in C5's dump
> because that dump is an **unfiltered top-14 whose noise floor is ~792,000 ms** (the idle-wait cluster) — and
> `WRITELOG` at N=8@3 measures **504,760 ms**, which sits *below* that floor. It was **crowded out by the very idle
> waits I was pointing at.** I inferred absence from a truncated list. That is the *same* truncation artifact I had
> just criticised the handback for; I simply read it in the other direction.
>
> **C6's properly-fenced, exclusion-set-filtered delta** (`c6_convoy_*.json` → `wait_delta_fenced_filtered_top`) shows
> `WRITELOG` is **rank-1 in every single arm**, growing monotonically with load (`d_resource_ms`): **128 s (N=4) →
> 191 s (N=8@2) → 251 s (N=8@3) → 578 s (N=16)**.
>
> **The conclusion of this section is UNCHANGED — and the correct argument is STRONGER than the one I made.**
> `WRITELOG` is rank-1 **on the N=4 arm, which delivers 100% and is perfectly healthy.** A wait that ranks #1 on a
> healthy arm **cannot name the wall on a collapsed one.** That — not a phantom absence — is why §6's "write-path
> signature" names nothing. The refutation never needed `WRITELOG` to be missing; it needed `WRITELOG` to be
> *everywhere*, which it is.
>
> Points (a), (b) and (d) below stand unaltered and are independently sufficient.

*(Original text, retained for the record: `PAGEIOLATCH_*`, `LCK_*`, `RESOURCE_SEMAPHORE*` and `PAGELATCH_*` did not
appear in C5's top-14 — but by the same truncation logic, that observation is also uninformative and should not have
been offered. C6's filtered delta shows `LCK_M_X` present and **shrinking** with load, and `IO_COMPLETION` present and
roughly flat. Neither is a wall; neither was ever "absent".)*

**(d) The one real signal points the OPPOSITE way.** The only non-benign wait of consequence is
**`SOS_SCHEDULER_YIELD`** — 825,767 tasks (c5-b) / 833,941 (c5-b2), reproduced. That is **quantum exhaustion**: tasks
using their full 4 ms slice and yielding. It is a **CPU-pressure** signal. Together with store CPU climbing **62→81%**,
the honest read is that the store was **CPU-pressured** — the very thing §6 rules out.

### Why this matters (and why it is worth a whole section)
§6 is the paragraph that **steers the next build**. As written it hands the Phase-4 **group-commit / durable-write**
lever a piece of evidence it has not earned. Group-commit may well still be the right lever — it has **independent**
justification from the txn-per-event arithmetic (§6 of the throughput doc / ADR 0051) — but **C5 provides no support
for it**, and citing C5 in its favour is the same adjacency inference that got **C2 and C4 walked back**. This
workstream's whole discipline is that a wall is named by a *convoy*, never by a wait's *rank*. §6 names one by rank —
and on excluded, idle waits at that.

### The fix
**Strike §6, or invert it to what the data supports:**

> *The only non-benign wait observed at the 3/shard collapse was `SOS_SCHEDULER_YIELD` (≈826k/834k tasks, reproduced),
> a CPU-pressure signal, alongside store CPU 62→81%. **No write-path wait was observed** — `WRITELOG`, `PAGEIOLATCH_*`,
> `LCK_*` and `RESOURCE_SEMAPHORE*` are all absent. The `LOGMGR_QUEUE`/`CHECKPOINT_QUEUE` values are **idle background
> waits** (both on the standard benign-exclusion list) and are **not** evidence of log pressure. **C5 does not name the
> N=8 wall** — naming it requires the C6 convoy instrument. C5 measures `R`; that is all it measures.*

**The verdict in §1 is UNAFFECTED.** It rests on the PASS-bar ladder plus the cool engine/load-gen — none of which
touch the wait interpretation. **Accept the verdict; strike the mechanism.**

---

## 3. Minor — one over-worded phrase (same family, not verdict-changing)

§3 calls the store *"the **sole binding resource**"* at ~80% CPU. 80% is **not** saturation (C3's N=16 wall was
92–93%). The pre-registered rule does not need it: §3.2 routes a fail with **"NEITHER box saturated"** to a
*legitimate design verdict, read the table straight* — which is exactly this case, since engine (38%) and load-gen
(<8%) are cool. **So the verdict reads straight regardless.** But the phrase should not reach the status doc as
*"store CPU was the wall at N=8"* — that would be a new, unearned mechanism claim of precisely the retracted class.
Prefer: *"neither the engine nor the load-gen was saturated, so the carve-out does not fire and the verdict reads
straight."*

---

## 4. What C5 hands C6 — a better arm than C6 was designed with

C6-LIVE contrasts **N=4 / N=8 / N=16, all at 2/shard**, and its own review predicts the N=16 arm routes to
**AMBIGUOUS-STRUCTURAL by construction** (N=16 collapses from the start — there is no plateau to sample).

C5 has now produced something C6's cross-N design cannot give it: a **same-N PASS/FAIL pair**.

- **N=8 @ 2/shard → PASS** (clean, slope +1.9, 100% delivered)
- **N=8 @ 3/shard → COLLAPSE, reproduced 2/2** (~50% delivered, ~85k stranded)

That is exactly the contrast the §3(a) convoy detector needs — **a convoy present in the FAIL arm and absent in the
PASS arm, at the same shard count**, with only the per-shard rate varying. It isolates the convoy from N itself. **Add
`N=8 @ 3/shard` as a C6 arm** (see the amended `HANDOFF_C6-LIVE`). It is the cheapest, cleanest collapse the programme
has, and unlike N=16 it has a matched control.

---

## 5. Sources
Raw artifacts under `HANDBACK_2026-07-12/`: `c5-a|c5-b|c5-b2/*.json` (`result`, `commit_sha`, `stranded`,
`in_pipeline_slope`, `lane_inversions`), `storedmv_soak.txt` (the wait dumps quoted above), `cpu_soak.csv`,
`loadgen_cpu_soak.csv`. Benign-exclusion set: `HANDOFF_C6-LIVE_n16_wait_sample_2026-07-11.md` §3(c).
Read-only DMV / public catalog names only; no secrets, IPs, hostnames, ports, or PHI.
