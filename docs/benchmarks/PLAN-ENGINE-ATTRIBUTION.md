# RUN-A — The Fixed-Cost Probe

**Status:** proposed, pre-registered, awaiting owner "go"
**Supersedes:** the latency-injection ladder (demoted to a conditional Phase 2 — see §3)
**Discipline:** ADR 0101
**Date:** 2026-07-13

---

## 1. THE ONE-LINE RECOMMENDATION

> **Turn the one knob that changes how much work the STORE does without changing how many MESSAGES flow through it — `pooled_sweep_interval`, a pure config value — in BOTH directions, at N=1 and N=4, and read the SIGN of the throughput response.**

**What it will tell us:** whether the store's 80–94% CPU is *causally load-bearing at all*. Roughly half of that CPU is a **clock-driven, message-rate-independent scan** (`list_fifo_lanes`, 47.5% of store CPU at N=16 per C4, called from `StageDispatcher._sweep_loop` on a 0.25 s timer). Slowing the clock 4× frees ~35% of the store's CPU **without touching the per-message path**. Nobody has ever done this. It is the only exogenous manipulation of store load available to this programme.

**What it will NOT tell us:** it will not raise throughput to 520 events/s, and it is not a lever hunt (§8). Its most likely outcome is a **null** — and the null is the point: *if you free a third of the store's CPU and throughput does not move, then "the store is CPU-bound" — the reading that drove four consecutive failed runs (C4/C5/C6/C7) — is dead.* That assumption has never been tested. It has only been inferred from a saturation reading.

**Riding along, at zero rig cost:** a per-stage wall-clock decomposition mined from `message_events` rows that **every past soak already wrote to disk**, plus three harness fixes that repair numbers this programme currently quotes as fact.

---

## 2. WHERE THE HYPOTHESIS STANDS AFTER THE COUNTER-EVIDENCE

### The serial-chain hypothesis is wounded. Do not spend a rig session on it.

You asked for this in the first paragraph, so here it is plainly: **the per-message serial round-trip chain is not the wall on this rig, and three independent numbers say so — none of which is the B5 result you flagged.**

**First, B5 is *not* the counter-evidence.** ADR 0071 line 145 says it outright: *"it cuts marshaling crossings, not network hops."* B5 deleted ~10 thread-marshaling crossings of ~50 µs each and left every ~10–13 ms store round-trip intact. A chain model denominated in store round-trips **predicts** that this buys nothing; it bought +6–10%. **B5 over-performed the chain model.** Anyone using B5's 6× to kill the chain is using the wrong currency. (The genuinely awkward half of B5 — ACK p50 down 7–10×, pool-wait p95 down 5×, for +8% throughput — is a real latency/throughput *decoupling*, but under `ack_after=ingest` that is a queueing win, not a chain-depth win.)

**The chain dies on arithmetic instead, from the committed `c6-n4x2.json` PASS artifact — all figures below re-derived and verified against the file:**

| Fact | Source (verified) |
|---|---|
| `result: "PASS"`, `no_loss: true`, 900 s, 4 shards, fan-out 8, 16 lanes | `c6-n4x2.json` — quotable, not collapsed |
| `claim_mean_ms` **13.316**, `claims` **134,932**, `mark_done_mean_ms` **9.983**, `send_ack_mean_ms` **0.52** | `soak.claim_timing`, `soak.phase_timing` |
| `sink_received` **57,600**, `lanes_observed` **16** | `soak` |
| `ceiling.pinned_ingress_rate` **7.684** vs `soak.sustainable_ingress_rate` **7.955** | **the soak ran AT capacity** — everything below is measured at the ceiling, not at a low offered load |

**(a) The only serial store-round-trip loop in the engine is idle.** In pooled mode (`claim_mode` default `pooled`) the sole bounded serial claim loop is `StageDispatcher._claimer_loop`, and `pooled_claimers_per_stage` defaults to **1** (`config/settings.py:892`).

```
149.9 claims/s  ×  13.316 ms  =  2.00 claimer-seconds per second of busy time
claimer tasks   =  4 shards × 3 stages × K=1  =  12
duty cycle      =  2.00 / 12  =  17%
```

The harness bug in §4.1 blends the four stages' claim windows into one mean — **but the aggregate busy-time survives it exactly** (Σ nᵢ·meanᵢ = blended_mean × Σ nᵢ), so this number is sound. And the **worst-case bound survives too**: even if *all* 2.00 claimer-seconds fell on a single stage's 4 claimers, that stage would be **50% busy**. Under *every* possible allocation, **no claimer is saturated at N=4.** A serial loop that idles ≥50% of the time is not a throughput wall.

**(b) The outbound lanes are 90% idle at the ceiling.**

```
deliveries  = 57,600 / 900 s = 64/s over 16 lanes  ⇒  per-lane episode = 250 ms
measured on that episode:  claim 13.32 + mark_done 9.98 + send_ack 0.52 = 23.8 ms  (9.5%)
RESIDUAL: ~226 ms = 90.5%  — not store round-trips, not the partner, not engine CPU
```

**(c) The engine is not computing.** `py_all_cpu%` is a *sum of process CPU* — thread migration cannot hide from it. Across all 26 committed `cpu_soak.csv` artifacts, the worst case is **~0.36 cores/shard** against 1.0 available. The engine box is decisively **not CPU-bound and not GIL-bound**, and that conclusion needs no per-PID data at all.

**(d) The pooled claim is batching nothing.** `lanes_per_claim` **1.081**, `rows_per_claim` **0.903** — against `pooled_claim_lane_chunk = 256`. The whole purpose of pooled claiming is to amortise the claim round-trip across many ready lanes. It is amortising across **one**. Lanes are not queued up waiting to be claimed; **they are not ready.**

### The picture that falls out, and it reframes the programme

> **At the measured ceiling, NOTHING on the per-message path is saturated.** Engine ≤0.36 cores/shard. Claimers ≤50% busy in the worst case. Outbound lanes 90% idle. Yet the store sits at **80–94% CPU**, roughly **half of it** on a scan driven by a **0.25 s clock** that does not scale with traffic.
>
> **The store is busy — but not with your messages.**

That is not a hypothesis; it is arithmetic over a committed PASS artifact. And it means **the single most load-bearing untested assumption in this programme is that the store's CPU saturation is causal.** A saturated resource is not necessarily the bottleneck. This run tests exactly that, with a knob.

*(P0's elasticity of −0.115 — tripling committed transactions costs only 12% of throughput — is the fourth independent number pointing the same way, and it already bounds the entire per-message-work lever class.)*

---

## 3. WHY THIS AND NOT THE OTHERS

Four angles were designed and adversarially judged. None was fatal; all four contribute. Here is what dies and what is grafted in.

**⛔ Latency injection (WinDivert δ-ladder on the engine→store link) — DEMOTED to a conditional Phase 2.** It is the best-disciplined design of the four and I have taken its pre-flight arithmetic, its manipulation ladder and its session-validity gate wholesale. But **its own author predicts a null at 70–80%**, for the reasons in §2 — you cannot slow down a loop that is 83% idle and expect throughput to notice. Worse, the knee it would use as its *positive* deliverable is **not identifiable**: injecting δ saturates the 12 serial claimers at δ ≈ 67 ms (149.9 claims/s × (13.3 + δ) ms), manufacturing a new bottleneck at almost exactly the δ where it predicts its lane-slack knee. Both mechanisms produce the same curve. **Do not spend 8–10 rig hours confirming a negative that `settings.py:894` predicts for free.** *(Kept as Phase 2, gated on Phase 1 finding the per-message path matters at all.)*

**⛔ Direct time-budget decomposition (Tier 1) — the ~180-LOC engine build is DEFERRED; its free tier is TAKEN.** Its Tier 1 needs a new engine module plus 8 probe sites in the hot path, and its own author concedes the prior evidence predicts the outcome where "every term is elastic and a message accounting structurally cannot see the constraint." Its **closure gate is also not mechanically specified** (probe #8 `pool_acquire` is a sub-interval of terms already counted, and the 8× fan-out makes "Σ mean terms vs mean E2E" arithmetically ill-defined). **But its Tier 0 is free and I am taking all of it** — see §4.2. It found the `_CLAIM_RE` stage-blend bug, and it noticed that `message_events` has already written engine-clock stage-boundary timestamps in every soak this programme has ever run.

**⛔ Engine-side CPU attribution — KILLED as a soak slot; its 35-line rider is TAKEN.** The aggregate already proves the conclusion: **no shard burns meaningful CPU (~0.06–0.36 cores)**. Fixing BACKLOG **#208** would buy a more precise measurement of a number we already know is small. **Recommend closing #208 as superseded**, citing the `py_all_cpu%` bound. Two things survive and are folded in: the engine exoneration itself, and `store_service_ms = claim_mean_ms − acquire_wait_mean_ms` — the first-ever split of a store round-trip into engine-side pool queueing vs real store service (§4.2). *(Caveat carried forward: `acquire_wait` is one global histogram across ~68 call sites, so this subtraction is an estimate, not an identity. Report it as such.)*

**⛔ Lane-scaling / the "wake gap" — its MECHANISM is REFUTED BY CODE; its KNOB is PROMOTED to primary.** The design claimed a cross-shard outbound lane is hard-capped at one delivery per 0.25 s sweep tick = **exactly 4 msg/s**, and built its whole retrodiction table on it. **That is not what the engine does.** `stage_dispatcher.py:861-877` (**T13b, greedy backlog drain**) re-arms a sweep-readied lane *immediately* whenever the claim came back FULL — and at OUTBOUND `per_lane_limit` is forced to **1** (`:246`), so **every non-empty claim IS full**. Its own docstring says T13b exists precisely so a wake-less lane does *not* "advance only one claim per `sweep_interval`." Under backlog — which every cert arm has — cross-shard lanes **drain greedily**. The 4 msg/s floor does not exist, and the observed 4.0 deliveries/lane/s is the *offered* load (8 ingress/s × 8 dests ÷ 16 lanes), not a clock. **The coincidence with 4 Hz is a coincidence, and I will not name a mechanism from it.**

> **But the knob it identified is the right knob — for the opposite reason.** `pooled_sweep_interval` does not gate the message path (T13b). What it *does* do is set the frequency of an `O(backlog)` store-side scan that C4 measured at **47.5% of store CPU**. That makes it the one available **exogenous manipulation of store CPU load that is orthogonal to message flow**. That is the run.

---

## 4. THE MEASUREMENT

**Rig:** the existing AWS two-box pair (engine m7i.4xlarge / store i4i.2xlarge local-NVMe), `harness/load/shardcert.py`, pooled mode (the shipped default).

**Held FIXED in every arm:** `MEMORY_OPTIMIZED TEMPDB_METADATA = ON`. It is the best deployable baseline (90 → 144 events/s, +60%, measured) and it removes C3's tempdb-latch as a confound. **It should be adopted in production regardless of this run** — it is a SQL Server config, not Enterprise-only, not code, and it is currently REVERTED. See §9.

### 4.1 ZERO ENGINE CODE — verified

Both knobs are existing settings fields, and `"pipeline"` is in `_ENV_OVERRIDE_SECTIONS` (`config/settings.py:116`), so `MEFOR_*` env overrides already resolve. `MEFOR_PIPELINE_CLAIM_MODE` and `MEFOR_PIPELINE_PER_LANE_WAKE` are the working precedents.

| Knob | Field | Default | Env var |
|---|---|---|---|
| Sweep clock | `pooled_sweep_interval` (`settings.py:894`) | **0.25 s** | `MEFOR_PIPELINE_POOLED_SWEEP_INTERVAL` |
| Claim supply | `pooled_claimers_per_stage` (`settings.py:892`) | **1** | `MEFOR_PIPELINE_POOLED_CLAIMERS_PER_STAGE` |

**Harness delta: ~40 lines**, no engine change, no new dependency, no rig reconfiguration.

### 4.2 THE FREE TIER — do this BEFORE booking rig time

Four items. All are zero rig hours. Two of them repair numbers this programme currently quotes as measured fact.

**(i) `_CLAIM_RE` does not capture `stage=`. Every claim number in this programme is a four-stage blend.**
`harness/load/shardcert_ladder.py:120` — the regex has no `stage` group, while the engine emits `"claim phase timing (stage=%s): claim n=%d mean=%.2fms …"` (`phase_timing.py:210`), one line **per stage per 5 s**. `aggregate_claim_timing` n-weights INGRESS + ROUTED + OUTBOUND + RESPONSE into a single `claim_mean_ms`. **The "claim_mean 28 → 557 ms" figure the programme reasons from is not the outbound claim and is not any single stage.** ~15 lines. *(As shown in §2(a), the aggregate busy-time is unaffected — but per-stage attribution is currently impossible.)*

**(ii) shardcert records the end-to-end latency histogram and throws it away.**
`shardcert.py` builds `LiveMetrics(..., e2e=Histogram())` at `:696`, `:1808`, `:2031`, `:2198`, the sink records into it — and `:842` summarises **`ack` only**. `metrics.e2e` is never surfaced. **It is the only measurement of a full message's life that exists anywhere in this repo.** One line. *(Valid only in the drive-half topology, where sender and sink share one process and one clock; in the split-sink path the correlator lives in another process and every arrival is a `correlation_miss`.)*

**(iii) The pool acquire-wait mean and count are exposed and not sampled.**
`PoolWaitInfo` carries `count` (`api/models.py:515`) and `mean_ms` (`:520`); `harness/load/enginepoll.py:55` reads p50/p95/p99/max and skips both. Two lines. Differencing `mean_ms × count` across the soak window yields **`store_service_ms = claim_mean_ms − acquire_wait_mean_ms`** — the first split of a store round-trip into engine-side queueing vs store service, and the retirement of the **2.84 ms round-trip that was only ever `20 ÷ 7`, never measured.**

**(iv) ★ `message_events` already holds a per-stage wall-clock decomposition of every soak ever run.**
`message_events` (`store/sqlserver.py:705`, indexed on `(message_id, ts)`) is written at four points — `received` / `routed` / `transformed` / `delivered` — each with `ts` stamped by the **engine's** clock. Verbosity defaults to `"all"` (`settings.py:1041`) and no harness overrides it. **Every C5/C6/C7/P0 soak wrote these rows.** There is no cross-box clock-skew problem. A post-hoc SQL query over a retained store DB gives, for free:

```
A = ts(routed)      − ts(received)     ingress residency + claim + route_only
B = ts(transformed) − ts(routed)       routed residency  + claim + transform_one
C = ts(delivered)   − ts(transformed)  outbound residency + claim + send + complete
```

**Run this first. It may pre-empt the rig session entirely.** If it does not, it calibrates it.

### 4.3 THE ARMS — a sign table, not a lever hunt

The sweep knob is **confounded by construction**: it moves *discovery latency* and *store scan CPU* **in opposite directions**. That is not a defect — **it is the instrument.** The two live models predict **opposite signs**:

| Model | sweep 0.25 → **0.0625 s** (4× faster clock, 4× MORE scan CPU) | sweep 0.25 → **1.0 s** (4× slower clock, 4× LESS scan CPU) |
|---|---|---|
| **CLOCK-GATE** — discovery latency binds | throughput **UP** | throughput **DOWN** |
| **SCAN-TAX** — store CPU binds | throughput **DOWN** | throughput **UP** |
| **NEITHER** — null | flat | flat |

**And the N axis deconfounds them.** At **N=1** there is one process, no cross-shard wake drops, and the sweep is a pure backstop — so its effect at N=1 is **~pure CPU tax**, with the discovery term stripped out. The N=4 − N=1 difference isolates the discovery term. *This is why N=1 is an arm and not decoration.*

| # | Arm | N | `sweep` | `K` | Purpose |
|---|---|---|---|---|---|
| **C1** | control | 4 | 0.25 | 1 | shipped default — **interleaved, run 3×** (start/middle/end) |
| **S-fast** | fast clock | 4 | 0.0625 | 1 | sign test |
| **S-slow** | slow clock | 4 | **1.0** | 1 | **★ the load-bearing arm** — frees ~35% of store CPU |
| **S-xslow** | extreme | 4 | 4.0 | 1 | dose-response; confirms S-slow's sign or exposes a knee |
| **K4** | claim supply | 4 | 0.25 | **4** | positive control on the claim path (predicted FLAT, §2a) |
| **N1-C** | control | **1** | 0.25 | 1 | deconfounder baseline |
| **N1-S** | slow clock | **1** | **1.0** | 1 | **isolates the pure CPU-tax term** |

**N=16 is excluded.** It collapses; ADR 0101 forbids quoting `ceiling.sustained_events_per_s` from a collapsed arm.

**Primary metric:** sustained delivered events/s, **gated on the harness `result` field — never `exit_code`.**

---

## 5. THE PRE-REGISTERED DECISION RULE

*Written before the run. Not revisable after seeing data.*

Let `R(arm) = sustained_events_per_s(arm) / mean(interleaved C1 controls)`.

### Decision table

| Outcome | Condition | Verdict |
|---|---|---|
| **SCAN-TAX LIVE** | `R(S-slow) ≥ 1.08` **at N=4 AND N=1**, monotone with S-xslow | **The store's clock-driven fixed cost is causally load-bearing.** The first positive in eight runs. **Reproduce before publishing.** |
| **CLOCK-GATE LIVE** | `R(S-fast) ≥ 1.08` **and** `R(S-slow) ≤ 0.92` at N=4, **and flat at N=1** | Discovery latency gates the message path — i.e. T13b is not doing what its docstring says. **Reproduce before publishing.** |
| **CLAIM SUPPLY LIVE** | `R(K4) ≥ 1.08` | The serial claim loop binds after all, and my §2(a) arithmetic is wrong. **Reproduce.** |
| **★ NULL — THE STORE IS EXONERATED AS A CPU-BOUND RESOURCE** | **All arms within ±8% of C1, manipulation checks GREEN** — *including* a **verified ≥30% drop in store CPU** on S-slow | See below. **This is a successful run.** |
| **CANCELLATION** | throughput flat **but store CPU did NOT move** on S-slow | The knob did not engage → **VOID, not a refutation.** Re-run. |
| **INDETERMINATE** | anything else | Report INCONCLUSIVE. **Name no mechanism. Do not rescue post-hoc.** |

### NULL band: ±8%

Run-to-run variance on this rig has been ±5–8%. **A null is a successful run.**

### ★ The result that makes us ABANDON the entire engine-attribution class

> **Store CPU falls ≥30% on S-slow (manipulation check GREEN) and throughput does not move outside ±8%, at both N=1 and N=4 — and K4 is also flat.**

Then: you freed a third of the store's CPU and bought nothing. Combined with the already-established bounds — engine ≤0.36 cores/shard, claimers ≤50% busy, lanes 90% idle, P0 elasticity −0.115 — **the store's CPU saturation is NOT causal, the per-message path is not saturated, and the clock-driven overhead is not the wall.** Every engine-side and store-CPU-side attribution angle is then dead, including this one.

That is not a consolation prize. **It retires the interpretation that drove C4, C5, C6 and C7** — four runs that all read "store at 90% CPU" as "store-bound" and hunted the store. It converts C4's *"~72% of the wall is off-CPU WAIT"* from a curiosity into the headline, and it forces the next run into the one class the status doc's own red box names as never tested: **per-call store service time, per-query spill, allocator churn, scheduler queueing** — i.e. what the store is *waiting on*, not what it is *burning*.

### Manipulation checks — a failure is VOID, not a refutation

1. **★ The store-CPU check (this is the one that matters).** `sys.dm_exec_query_stats` for `list_fifo_lanes`: `execution_count` must scale **≥ 10×** across S-fast → S-slow (a 16× interval range), and its `total_worker_time` share must fall correspondingly. **Total store-box CPU must drop ≥ 30% on S-slow.** If store CPU does not move, the knob never engaged and **nothing else in the run means anything.**
2. **The claimer check.** The `claim phase timing` line reports `claimers=K` (`phase_timing.py:210`). It must read **4** in the K4 arm. Free.
3. **The idle-poll check.** `/stats` `empty_claims_idle_poll` must track `1/sweep_interval`.
4. **Zero-loss + drained.** `no_loss: true`, `engine.drained: true`, `in_pipeline_final: 0`. Else the arm is collapsed and its throughput is **not quotable**.
5. **FIFO integrity.** `lane_inversions == 0`, `lane_repeats == 0` at `sweep = 1.0` and `4.0`. **If a slow sweep breaks FIFO or loses a message, the sweep is on the hot path, not a backstop — and that is itself the finding, stated louder.**

### Same-session control + the session-validity gate

**C1 runs three times, interleaved** (start / middle / end). **If their spread exceeds ±10% of their mean, the session is VOID and nothing may be quoted.** Historical A/B against C5/C6/C7 numbers is **forbidden** — run-to-run variance on this rig is real and has already produced two retractions.

**No mechanism may be named from a wait's rank, share, or growth rate.** Every claim in this run rests on a **manipulated knob with a pre-committed sign and magnitude**, plus a store-side check that the manipulation engaged.

---

## 6. WHAT IT COSTS

**Engine production code: ZERO.** Both knobs are existing settings fields reachable by env var (§4.1).

**Harness code: ~40 lines**, none of it on the message path:
- `shardcert.py` — pass the two `MEFOR_PIPELINE_*` vars into the `serve --shard` subprocess env (~10)
- `shardcert_ladder.py:120` — `_CLAIM_RE` stage capture (~15)
- `shardcert.py:842` — surface `metrics.e2e.summary()` (~1)
- `enginepoll.py:55` — sample `acquire_wait.mean_ms` + `.count` (~2)
- report schema plumbing (~12)

**Rig: 9 soaks (7 arms + 2 extra C1 controls), ~25 min each including climb and drain ⇒ ~4 h hold, ~6–7 h wall with bring-up. One session. One rig config. No box moves, no network shaping, no new hardware.** Comparability with the C-series baseline is untouched — and the design does not depend on it anyway (same-session interleaved control).

**Free tier (§4.2): ~0 rig hours.** Item (iv) — the `message_events` mine — needs only a retained store DB from any prior soak. **Do it before booking the rig.**

---

## 7. THE WEAKEST POINT

**Stated by us, at full force:**

> *"You have re-derived a store-side story and dressed it as a clock. The programme has hunted the store four times and failed four times. And your own primary arm is confounded on purpose — `sweep_interval` moves discovery latency and scan CPU at once. If they CANCEL, you will read FLAT and wrongly declare the null. You will have spent a rig day to produce the eighth negative, with a confounded knob."*

**Three answers, and the third is the honest one.**

1. **The cancellation risk is handled by measuring store CPU directly, not by inferring it from throughput.** Manipulation check #1 reads the store box's CPU and `list_fifo_lanes`' `total_worker_time` from the DMVs. If store CPU falls 35% and throughput does not move, **the SCAN-TAX model is dead regardless of what the clock model is doing.** The two are separated by a *store-side observable*, not by the throughput sign alone.
2. **The N=1 arm strips the confound.** At N=1 there are no cross-shard wake drops and the sweep is a pure backstop, so `N1-S` measures the **CPU-tax term alone**. `(N=4 effect) − (N=1 effect)` is the discovery term.
3. **I expect the CLOCK-GATE leg to null, and I am saying so before the run.** T13b (`stage_dispatcher.py:861-877`) means a backlogged lane drains greedily; the code says the sweep should not gate anything under load. **The live leg is SCAN-TAX, and I will not pretend otherwise.** If the owner wants only one arm, it is **S-slow at N=4 and N=1** — two soaks, ~1 hour, and it carries the whole decision.

**The second-weakest point:** `store_service_ms = claim_mean − acquire_wait_mean` subtracts a **fleet-wide** acquire-wait mean (one histogram, ~68 call sites) from a **claim-only** mean. That is valid only if acquire waits are homogeneous across call sites — which a contended pool would violate. **Report it as an estimate with that caveat attached, not as an identity.** It is a free by-product, not a deliverable.

**And a methodological kill exists:** if the three interleaved C1 controls spread more than ±10%, the rig cannot resolve an 8% effect and **nothing from the session may be quoted.**

---

## 8. WHAT THIS DOES NOT DO

**It does not raise throughput.** Say the best case lands: S-slow frees 35% of store CPU and throughput rises 20%. That takes 144 → ~173 events/s against a target of **520.83**. **Still ~3× short.** This is an **attribution run**. It buys a mechanism, not a lever. Anyone reading a throughput number out of it as a deliverable has misread it.

**It does not test the serial-chain hypothesis.** A null here says nothing about round-trip latency. That is Phase 2 (§3), and it should only be built if Phase 1 shows the per-message path matters at all — which §2 says it does not.

**It does not explain *why* any store call costs what it costs.** Mechanism-naming from a DMV table is C4's grave. If `list_fifo_lanes` costs 47.5% of store CPU, this run tells you whether that cost is *causal*, not why the query is expensive.

**It does not measure lane queueing.** The 226 ms residual (§2b) is characterised by the free `message_events` mine (§4.2 iv) only as far as *stage residency*; splitting residency into "waiting for a claim" vs "waiting for a slot" needs engine code and is out of scope.

**And it may return nothing but a null.** That is the pre-registered, most-likely outcome — and per §5, the null is the most valuable result available, because it kills a reading that four runs have already been spent on.

---

## 9. THE BANKED, UNSPENT IMPROVEMENT — adopt it regardless

**`MEMORY_OPTIMIZED TEMPDB_METADATA = ON`** is a **measured 90 → 144 events/s (+60%)**, currently **REVERTED**.

- It is a **SQL Server configuration**, not code. **Not Enterprise-only.**
- C3 measured it: the tempdb system-catalog PAGELATCH is **eliminated**; it clears the N=8 knee (N=16 still collapses — it buys **one doubling**, not the frontier).
- **It is the best deployable configuration we have and it is not deployed.**

**Adopt it in production independently of this run**, and hold it **fixed ON in every arm** here — both because it is the honest baseline and because it removes the tempdb latch as a confound.

**It does not close the gap.** 144 / 520.83 ⇒ **still 3.62× short.** It is banked headroom, not a solution.

---

## Files that matter

- `messagefoundry/pipeline/stage_dispatcher.py` — `_claimer_loop`, `_claim_and_dispatch` (the serial `await claim_fifo_heads`), **`_lane_done` T13b greedy re-arm (`:861-877`)**, `per_lane_limit` forced to 1 at OUTBOUND (`:246`), `_sweep_loop` → `list_fifo_lanes`
- `messagefoundry/config/settings.py` — `pooled_claimers_per_stage=1` (`:892`), `pooled_sweep_interval=0.25` (`:894`), `"pipeline"` in `_ENV_OVERRIDE_SECTIONS` (`:116`), `message_events="all"` (`:1041`)
- `messagefoundry/pipeline/phase_timing.py` — `MEFOR_DELIVERY_PHASE_TIMING` gate; emits `claim phase timing (stage=%s)` (`:210`)
- `messagefoundry/store/sqlserver.py` — `message_events` table (`:705`); `_acquire()` — the single pool chokepoint
- `messagefoundry/api/models.py` — `PoolWaitInfo.count` (`:515`), `.mean_ms` (`:520`)
- `harness/load/shardcert_ladder.py:120` — **`_CLAIM_RE`, missing the `stage` group**
- `harness/load/shardcert.py:842` — **`metrics.e2e` built and discarded**
- `harness/load/enginepoll.py:55` — `_pool_wait_attr`, skips `mean_ms`/`count`
- `docs/benchmarks/results/2026-07-12-throughput-c4-c7/…/c6-n4x2/c6-n4x2.json` — **the PASS artifact every number in §2 is derived from**

## Backlog actions

- **Close #208** ("fix the per-PID engine CPU collector") **as superseded.** `py_all_cpu%` already gives an admissible aggregate engine-CPU verdict (≤0.36 cores/shard). Per-PID would refine a number we know is small.
- **#220 stays P3.** It lives in `connscale`, which `shardcert` does not use, so it cannot block a shardcert-based throughput spec.
- **New:** adopt `MEMORY_OPTIMIZED TEMPDB_METADATA = ON` (§9).
- **New:** the three harness defects in §4.2 (i)–(iii) are real bugs and should be fixed whatever happens to this plan.
