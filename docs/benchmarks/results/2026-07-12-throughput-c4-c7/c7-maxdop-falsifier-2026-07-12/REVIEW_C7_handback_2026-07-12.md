# REVIEW — C7 handback (`HANDBACK_C7_2026-07-12.md`)

**Date:** 2026-07-12 · **Reviewer:** coordinator (author of the refuted hypothesis)
**Bottom line: VERDICT ACCEPTED. The hypothesis I raised is DEAD, and dead in the most informative direction —
parallelism is not the wall, it is LOAD-BEARING. Every number reconciles. The falsifier worked exactly as designed.**

---

## 1. Verified against the raw artifacts — all of it holds

| arm | `result` | ingress | delivered | stranded | slope | `CXSYNC_PORT` | store CPU | runnable med/max |
|---|---|--:|--:|--:|--:|--:|--:|--:|
| **C7-base** (8@3, MAXDOP 8) | SOAK_NOT_SUSTAINED | 24/s | **49.2%** (85,067/172,800) | 87,656 | +115.1 | **135,361** | 67→81 | 5/11 |
| ⭐ **C7-dop1** (8@3, **MAXDOP 1**) | SOAK_NOT_SUSTAINED | 24/s | **20.6%** (35,632/172,800) | 137,194 | **+154.7** | **0** | 49→**89** | **10/19** |
| **C7-dop1-pass** (8@2, **MAXDOP 1**) | **SOAK_NOT_SUSTAINED** | 16/s | **75.6%** (87,084/115,200) | 28,106 | +38.4 | **0** | 53→74 | 4/8 |

- **Build pinned** — `commit_sha = 98bec81d0a5…` on all three arms. No engine change. FIFO intact everywhere
  (`lane_inversions = 0`, `lane_repeats = 0`).
- **The §5 manipulation check PASSES decisively.** `CXSYNC_PORT` `d_resource_ms`: **135,361 → 0** (exactly zero, on
  *both* MAXDOP=1 arms; the pre-registered bar was <5% = 6,768). Under `MAXDOP 1` there are no parallel plans, hence no
  exchange operators, hence no `CXSYNC_PORT`. **The intervention unambiguously took effect — this is not a
  forgot-to-clear-the-cache null.** That gate was the single biggest validity risk and it is cleanly passed.
- **The drift control did its job.** C7-base reproduced the N=8@3 baseline **in the same session** — 49.2% / +115.1
  against the 3-run historical 50–52% / +108…+112.5. **No drift.** The A/B is against a live control, not a memory.
- **The delivered percentages check out arithmetically.** Offered outbound events = `rate × shards × 900 s × 8 dests`:
  8@3 → 172,800; 8@2 → 115,200. Every delivered% in the handback matches its `phase_timing.deliveries` to within
  rounding.

## 2. The pre-registered rule fires on TWO independent triggers — there is no wiggle room

- **C7-dop1 = "materially WORSE."** The §6 threshold was *delivered < 45% **or** slope > +125*. It hit **both**:
  **20.6%** delivered and slope **+154.7**. → **PARALLELISM WAS HELPING.**
- **C7-dop1-pass FAILED the PASS bar** — 75.6% delivered, not drained, 28,106 stranded, on a rung that **PASSES at
  100% under the default**. § 6 pre-registered this as **"CONFIG IS BROADLY HARMFUL — overrides any win above."**
  → **MAXDOP=1 is not adoptable, full stop.**
- **No reproduction arm** — correct. C7-dop1-rep was mandatory only ahead of a *positive* claim. This is negative.

**Two independent pre-registered triggers, both firing the same way, on a validated intervention, against a
same-session control.** This is as clean as a negative result gets.

## 3. The mechanism is physically coherent (which is why I believe it)

Forcing serial plans made the store spend **MORE CPU for LESS work**:

| | C7-base (parallel) | C7-dop1 (serial) |
|---|--:|--:|
| store CPU | 81% | **89%** |
| runnable med/max | 5 / 11 | **10 / 19** |
| `SOS_SCHEDULER_YIELD` tasks | 622,888 | **748,325** |
| delivered | 49.2% | **20.6%** |
| `WRITELOG` `d_resource_ms` | 258,283 | 266,842 (**unmoved**) |

Serial plans take longer in wall-clock, so **more queries are in flight concurrently** → more runnable tasks → *more*
scheduler contention, not less. The parallel plans were **efficiently using** the 8 schedulers; removing them did not
free capacity, it wasted it. And `WRITELOG` **barely moved** (258k → 267k) — removing parallelism did not reduce the log
wait, it just made everything slower around it. The story is internally consistent from four independent angles.

## 4. My accounting — the hypothesis was mine, and it was wrong

I raised `CXSYNC_PORT` off its **34× growth rate** (vs `WRITELOG`'s 4.5×) and the rising `WRITELOG` signal fraction. The
one piece of evidence I called "suggestive, not conclusive" was that `CXSYNC_PORT` grows **4.6× by N=8@2 — a healthy,
pre-collapse arm.** **That was the weak link, and it broke.**

**Where the reasoning went wrong: I read a *growing cost* as a *growing waste*.** `CXSYNC_PORT` rising on a healthy arm
means parallelism is doing **more work** as load rises — which is **expected and beneficial**, not pathological. Growth
on a healthy arm is, if anything, evidence *for* a mechanism that is functioning.

**What I got right was the process, not the guess.** The hypothesis was labelled a hypothesis, never written into a
handback as a finding, given a pre-registered kill-criterion, a manipulation check, a drift control, and a harm check —
and it died in one cheap run. **That is the falsifier working.** The cost of being wrong was ~3 arms; the cost of *not*
testing it would have been an unresolved thread hanging over every future store result, and a live temptation to
"explain" the wall with it later. **A dead hypothesis is a successful run.**

*(The C4 `list_fifo_lanes` trap — "is this a collapse EFFECT or a cause?" — claimed a second victim, and I walked
straight into it after citing it. Worth remembering: on a collapsing system, **almost everything grows**. Growth rate is
not evidence of causation, and a pre-collapse arm showing growth is not the escape hatch I thought it was.)*

## 5. What stands after C5 + C6 + C7

Three independent runs now converge on the same answer:

- **C5:** `R ∈ [2,3) < 3.62` → **N-sizing is insufficient on its own.**
- **C6:** no convoy, on either contrast → **not a lock, latch, memory-grant, or spill.** No single blocker to fix.
- **C7:** **not a parallelism config default** either — and parallelism is *load-bearing*, so that lever is not just
  absent, it is **negative**.

**→ The `txn/event` levers are the path, and nothing left in the store is a shortcut around them.** Phase-3 `accepts=`
is merged (#952/#213); **Phase-4 group-commit / batch-fusion is the build.** C7 does not displace them and never could
have — a C7 win would only have made each event cheaper, not made N-sizing sufficient.

**Still open, and now lower-stakes:** the CPU-BOUND preclusion (the offline 64.4% reconciliation) and C4's
`list_fifo_lanes` family ratification. **The recommendation is robust to both** — if the store *is* CPU-bound, the fix
is still "fewer store round-trips per event," which is still the same levers. Not worth re-litigating before the build.

## 6. Sources
`HANDBACK_2026-07-12/c7-{base,dop1,dop1-pass}/`: `c7-*.json` (`result`, `commit_sha`, `stranded`, `in_pipeline_slope`,
`phase_timing.deliveries`, FIFO), `c6_convoy_*.json` (`wait_delta_fenced_filtered_top` → `CXSYNC_PORT`, `WRITELOG` +
signal fraction; convoy floor; runnable), `cpu_soak.csv`. Baselines: `HANDBACK_C5_2026-07-12.md` §2,
`HANDBACK_C6-LIVE_2026-07-12.md` §2. Hypothesis as raised: `REVIEW_C6_handback_2026-07-12.md` §4.
Read-only DMV / public catalog names only; no secrets, IPs, hostnames, ports, or PHI.
