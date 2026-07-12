# Throughput: where we stand, and the path to 45M messages/day

**Date:** 2026-07-10 · **Last updated:** **2026-07-12** (folds in **C5 / C6 / C7** and the C4-handback review
caveats) · **Code assessed:** `origin/main` @ `aba035f`; all C3–C7 rig runs pinned to engine commit `98bec81` ·
**Method:** multi-agent audit of every ADR, commit, bench artifact and rig handback, with each measurement
adversarially verified and validity-tagged.

> **Artifact provenance — read before quoting any C4–C7 number.**
>
> - **The C5/C6/C7 raw artifacts are held OUTSIDE this repository**, under
>   `OneDrive/Desktop/MEFOR/aws-bench/{c5-n8-headroom,c6-wait-decomposition,c7-maxdop-falsifier}-*/HANDBACK_2026-07-12/`
>   (`c5-*.json`, `c6-*.json`, `c6_convoy_*.json`, `c6_samples_*.json`, `c7-*.json`, `cpu_soak.csv`,
>   `loadgen_cpu_soak.csv`, `storedmv_soak.txt`). Every C5/C6/C7 figure below was reconciled against those files on
>   2026-07-12. **Committing them under `docs/benchmarks/results/` is an open owner decision** — until then this
>   document's strongest verdicts are not auditable from the repo alone.
> - **⚠️ C4 handed back NO artifact at all** — its folder holds two `.md` files and zero JSON. **Every C4 number in
>   this document is prose-only and unauditable**, including the 47.46% / 40.33% family split, `cpu/elapsed = 0.28`,
>   and the 9.4% N=16 delivered rate. Tag them accordingly wherever they are quoted.
> - **⚠️ The rig CHANGED mid-arc.** C1–C4 ran on an **8-vCPU** engine box (m7i.2xlarge); C5/C6/C7 ran on a **16-vCPU**
>   box (m7i.4xlarge), upsized 2026-07-12 (`cpu_soak.csv` header: `engine cores=8` at C3, `engine cores=16` at
>   C5/C6/C7). **C4's N=16 arm is therefore 16 shard processes on 8 vCPU** — a configuration §8's own rig table calls
>   *"core contention, not store scaling."* See the C4 row in §3.

> **This document supersedes the throughput narrative that preceded it.** Several widely-quoted numbers are
> retracted below, including the claim that the engine misses its target by ~52×.
>
> **⭐ 2026-07-12 — the store-side search is CLOSED.** C5, C6 and C7 each returned a **negative** result, and
> together they retire the three levers this document previously treated as the path: **more shards** (C5:
> per-shard ceiling `R ∈ [2, 3)` < the 3.62/shard a cleared N=16 needs), **a store-side contention/SQL rewrite**
> (C6: **no shared-resource convoy observed** on either pre-registered contrast — no convoy for a rewrite to
> remove), and **a parallelism config change** (C7: `MAXDOP=1` is *negative* — it made the collapse worse and
> degraded a rung that passes under the default). **The wall is UNNAMED, and naming it is no longer on the
> critical path.** The `txn/event` levers are the plan — Phase 3 `accepts=` (**MERGED**, #952/#213, ADR 0084) and
> Phase 4 group-commit / batch-fusion (**the only candidate standing — and CONTINGENT, see below**).
> Anywhere this document still reads as though a claim-or-dispatcher rewrite or a higher shard count is the
> lever, **it is stale** — see §8, "The store-side search is closed."
>
> ⚠️ **Two limits on that banner, stated here rather than 1,000 lines down, because this is the paragraph that
> gets quoted:**
>
> 1. **"No convoy" is not "nothing is there."** C6's detector is **blind by construction** to any cost that is not
>    a *shared* `resource_description` — per-query CPU, per-query spill, per-session grant pressure, allocator
>    churn and scheduler queueing **can never form a convoy** and would always return this null. And the null
>    itself comes from **72 point-in-time `dm_os_waiting_tasks` snapshots per arm at a 10 s cadence**; a convoy
>    that forms and clears inside that window is not excluded. C6 excludes *convoys of the sampled classes at a
>    10 s cadence*. It does not excise the classes themselves.
> 2. **Phase 4 group-commit is the last candidate standing, NOT a validated one — and its OWN falsifier currently
>    points against it.** That falsifier reads: *"if measured `txn/s` at the rig sits far below the store's
>    ~27–29k c/s commit ceiling, group-commit buys little."* The best available estimate is **~350 txn/s** at the
>    measured pooled bracket (derived, not measured: 90 events/s × 3.89 txn/event) and **~2,416 txn/s = 9% of the
>    ceiling** even at the full 520.83 target — i.e. the antecedent appears **satisfied**, which points *against*
>    group-commit. **Phase 0's `txn/s` counter must be measured BEFORE the build is funded.** C5/C6/C7 provide
>    **zero** evidence for group-commit specifically; they say what *isn't* the lever.

---

## 1. The short answer

**The goal counts every message the engine handles — inbound *and* outbound.** `45,000,000 / 86,400 =`
**520.83 total message events/s**. The harness constant does not implement this (see B10), which has inflated
every published gap figure by a factor of `1 + dests`.

**The engine's binding wall is not CPU, not the store's commit bandwidth, and not `mark_done` — and as of
2026-07-12 it is *not named at all*.** For months the **pooled outbound claim query** was the answer here:
`claim_mean` **33.6 ms** returning ~1 row, a *runaway* 12 → 20 → 33 → 43 → **127 ms** as load rises. Those
measurements still stand. The **attribution** does not. C4 demoted the claim to the **#2** N=16 store-CPU
consumer (40.33%, behind the dispatcher's `list_fifo_lanes` discovery scan at 47.46% — *prose-only; C4 handed
back no artifact, and its N=16 arm ran 16 shards on 8 vCPU*), and **C6 went looking for the contention that
would name a wall and found none** — **no convoy** on either pre-registered contrast: no lock convoy, no shared
latch/page convoy, no memory-grant convoy, no spill convoy (`convoy_present = false` on all four arms; the
detector's floor was met in **0 of 288 samples**). **The wall is UNNAMED. Say so, and do not fill in the
blank.**

**The store-side search is CLOSED — and that is the useful result.** Three runs on 2026-07-12 each killed a
tempting lever, and a negative result is a result:

- **C5** — the per-shard ceiling at N=8, latch-free, is **`R ∈ [2, 3)`** (2/shard PASSes at 100%; 3/shard
  collapses, reproduced 3×). That is **below the 3.62/shard** a cleared N=16 would need ⇒ **more shards cannot
  get there.** Decisive, not deferred: **the pre-registered co-constraint bar is 85% `max_core%`; the C5
  collapse arms peaked at 59.7% (c5-b: mean 39.5 / p95 50.5 / max 59.7) with the load-gen at 8.5% peak — the
  carve-out did not fire.** *(Always check the bar against the PEAK, never the mean.)*
- **C6** — **no convoy observed** ⇒ **AMBIGUOUS-STRUCTURAL** ⇒ **no shared-resource blocker for a contention fix
  to remove.** *(Not "nothing is there" — see the banner's limit 1.)*
- **C7** — `MAXDOP=1` made the collapse **worse** (49.4% → 20.6% delivered) *and* degraded a rung that passes
  under the default (N=8@2 → 75.7%, 28,106 stranded) ⇒ **parallelism is not a removable cause; it is
  load-bearing.** That lever is not merely absent, it is **negative.**

**So the plan is no longer store-side.** **Four** store-side levers are measured dead: more shards, a contention
fix, a claim/dispatcher CPU rewrite, and a parallelism config change. **The `txn/event` levers — Phase 3
`accepts=` (MERGED, #952/#213, ADR 0084) and Phase 4 group-commit / batch-fusion — are the best-supported
REMAINING candidate, not the only conceivable one.** This is an argument from elimination over a candidate set
that was never shown to be exhaustive. **Untested classes, named so no one mistakes "last man standing" for a
mechanism:** per-call store CPU, allocator churn, scheduler queueing, per-query spill, network RTT to a remote
store, and **everything engine-side** (the per-PID collector still reads `0.00` — §4's honest caveat). The
conclusion is **robust to the one dispute still open** (§9 #1, the CPU-BOUND preclusion): even if the store *is*
CPU-bound, the fix is still *"fewer store round-trips per event"* — the same levers. **Do not wait on
re-litigating it** — but do not read "closed" as "solved" either.

---

## 2. What 45M/day actually means

**Owner rulings (2026-07-10):**

1. 45M/day is a count of **all messages — inbound and outbound**. Internal staged-pipeline rows
   (`ingress → routed → outbound`) are the *same* message persisted across stages and do **not** count.
2. Scope is **HL7 in and out**. File, REST, SOAP, DB, DICOM and X12 surfaces are out of scope.
3. **The target is a flat, sustained run — ~520.83 events/s, all day, no peak multiplier.** A capacity claim
   of 45M/day means the engine holds 520.83 events/s continuously; it does not mean it must absorb a
   diurnal burst on top. (Real estates *do* peak — see §6 — but the parity claim is sized flat.)

So `total events = ingress × (1 + dests)`, and the goal is **fan-out invariant**:

| dests | events per ingress msg | required ingress/s | required delivered/s |
|---:|---:|---:|---:|
| 1 | 2 | 260.42 | 260.42 |
| 2 | 3 | 173.61 | 347.22 |
| 4 (production shape) | 5 | 104.17 | 416.67 |
| 8 (bench) | 9 | 57.87 | 462.96 |

### Provenance: a parity ceiling backed by three decades of the incumbent's field experience

The forcing artifact is the incumbent's **qualified Server System Requirements (05/2026)**, read directly
(cf. [ADR 0051](../adr/0051-corepoint-throughput-parity-strategy.md)). Its required configuration reads,
verbatim:

> **"Up to forty-five million messages daily, 1500 connections, and remote database."**

| | |
|---|---|
| Application server | **20 cores**, 48 GB RAM |
| Database server | **16 cores**, 128 GB RAM, **15 TB RAID10** data drive |
| Qualified disk (Diskspd) | **9,200 IOPS** 8 KB random write · 72 MB/s · **3.5 ms** avg latency |
| Database growth | *"approximately 30 days of log retention at **500 GB per day**"* |
| HA | **AlwaysOn Availability Groups**, with a **synchronous-commit** secondary + automatic failover |
| Topology | **Remote** database — every committed transaction crosses the network |

The document names the driver explicitly: *"the speed of the disk of the database server's data drive is the
leading performance driver in message flow."*

**Treat the number as real demand.** The incumbent has three decades of field experience; the spec reflects
customer needs, not marketing. 45M/day is therefore a **capacity claim on top-spec hardware**, support for
**large-IDN requirements**, and — for essentially every individual deployment — **headroom**.

### Three constraints the spec hands us for free

**1. A hard byte budget.** `500 GB/day ÷ 45M messages =` **10.9 KB written per message.** A directly
comparable parity number — and **MessageFoundry has never measured its own bytes/msg.** (This independently
confirms ADR 0051's "~11 KB/msg", now from the primary source rather than a secondary quote.)

**2. `1500 connections` dissolves the hot-feed alarm and converts it into a concentration rule.**
`520.83 events/s ÷ 1,500 = ` **0.347 events/s per connection**, on average. See §7.

**3. Synchronous-commit AlwaysOn roughly doubles commit latency**, since every commit waits for the
secondary to harden its log. On a **serial** per-lane chain that cost is paid in full — concurrency cannot
hide it.

### ⚠️ B10 — the harness target is a units defect

`harness/load/shardcert_ladder.py` defines `TARGET_INGRESS_PER_S = 45_000_000 / 86_400` and gates on
`pinned_ingress_rate >= TARGET_INGRESS_PER_S`. That compares an **ingress** rate against a **total-events**
budget. At `dests=8` it demands 4,688 events/s — **9× the actual goal**. In general the gate is
`(1 + dests)`× too strict, and the module docstring states the wrong reading explicitly.

**Correct gate:** `ingress_rate × (1 + dests) >= 520.83`.

This alone accounts for a factor of 9 in every "we are ~52× short" statement.

---

## 3. What we have actually measured

Every figure below is sourced and validity-tagged. Configuration is load-bearing: an ingress rate at
`dests=8` is not comparable to one at `dests=1`, and a 60 s climb rung is a **volume** test, not a rate test.

### Trustworthy

| measurement | value | config | source |
|---|---|---|---|
| **Sustained e2e (the definitive point)** | **10 ingress/s** = 80 delivered/s = **90 total events/s** | pooled, `dests=8`, 4-shard fleet, one SQL Server store, **900 s soak** | `redo-pooled-soak10-01.json` |
| First failing rate | 12 ingress/s — lossless but **non-draining** (`in_pipeline_final=825`, slope +12.17) | as above | `redo-pooled-soak12-01.json` |
| **`per_lane` sustained** | **≥ 28 ingress/s** = 224 delivered/s = **≥252 total events/s** | `per_lane`, `dests=8`, 16 lanes, **540 s soak** | claim-mode A/B, 2026-07-09 |
| `pooled` collapse | collapses at **16 ingress/s** | `pooled`, same topology, 300 s soak | claim-mode A/B |
| **Claim is the dominant store-op LATENCY** *(the latency ordering stands; the inference "therefore the claim is the wall" is **WITHDRAWN** — C4 put the claim at **#2** by N=16 store CPU, C6 found no convoy)* | `claim_mean` **28.06 ms** ≫ `mark_done` 9.60 ms ≫ `send_ack` 0.59 ms | pooled, `dests=8` | claim-mode A/B |
| Per-delivered-row claim cost | pooled **25.03 ms** vs `per_lane` **~5.6 ms** — **4.5×** | `dests=8` | claim-mode A/B |
| Claim runaway | 12 → 20 → 33 → 43 → **127 ms** as load rises; tempdb table-vars = **43%** of fixed claim cost | pooled, SQL Server | `outbound-claim-wall.md` |
| Single-engine ceiling-walk | ~97 sustainable / ~107 peak ingress/s | `dests=1`, SQL Server | ADR 0066 at-scale, 2026-07-03 |
| Engine **intake** wall | 193 msg/s (1 engine), 383 (2 engines) — **ACK only, no delivery** | `dests=1`, SQLite | PR #713 / #719 |
| Single strict-FIFO interface e2e | ~60 ingress/s | fan-out ~1, SQL Server LAN | `docs/THROUGHPUT.md` |
| Store commit capacity | ~23,600 c/s (SQLite NVMe); **~27–29k c/s (SQL Server)** vs a ~750 c/s pipeline demand — **36× headroom** | microbench | ADR 0069 |
| **Fleet N-shard scaling (C1, two-point)** | per-shard capacity **DECLINES** with `N`: whole-fleet peak **11.33 → 15.42 ingress/s = 1.36× for 4× shards** (N=1 → N=4). Direction firm; magnitudes soft (both 900 s soaks collapsed — climb-peak overstates; see note). | pooled, `dests=8`, one SQL Server store, 2026-07-10 | `c1-arm-a-n1.json` / `c1-arm-b-n4.json` |
| C1 — the shard penalty is **load-dependent** | near-linear at light load (**1.01×** at 2/shard) → **1.53×** at 6/shard → **collapse** at 12/shard, where N=1 still sustains | matched per-shard offered load, pooled, `dests=8` | C1 handback |
| C1 — `claim_mean` rises with shard count | N=1 flat ~13 ms; N=4 runs away **12.6 → 48.8 ms**, tracking the throughput penalty almost exactly | pooled, SQL Server, `dests=8` | C1 handback |
| **Fleet N-shard scaling (C2, light-load sweep)** | at a *fixed* 2/shard load a true 900 s soak **sustains N=1/2/4 (100% delivered)** and **collapses at N=8 (18%) / N=16 (5%)** — light-load scaling **BREAKS beyond N=4** | pooled, `dests=8`, 2/shard, 900 s soaks, one SQL Server store, 2026-07-10 | `c2-arm-*.json` |
| C2 — the wall is **store-side**, not engine/CPU/sink | engine box CPU p95 ~16%, busiest single core **≤43%** (GIL wall excluded); load-gen idle; `send_ack` flat; `claim`+`mark_done` run away (claim_mean 19 → ~262 → ~557 ms across N=4/8/16) | C2 handback |
| C2 — localized to **tempdb system-catalog PAGELATCH** | `PAGELATCH_SH/EX` **14.6× dominant** (N=8); hottest page **2:1:97 = `syssingleobjrefs`**; I/O + `LCK_*` waits absent — the pooled claim's per-cycle temp-object churn | store `dm_os_wait_stats` + `dm_os_waiting_tasks`, 2026-07-10 | C2 handback |
| **Fleet N-shard scaling (C3, latch-removed counterfactual)** | identical 2/shard sweep with `MEMORY_OPTIMIZED TEMPDB_METADATA=ON`: the C2 catalog PAGELATCH is **eliminated** at both arms (page `2:1:97` hits 3 365→**3**, 11 557→**43**). **N=8 collapse (18%)→ PASS 100%** (drained, stranded 0); **N=16 (4.8%)→ still COLLAPSE, 27.9%** (~6×). Knee moves **exactly one shard-doubling**: (4,8]→(8,16]. **PARTIAL — a diagnostic, not a deployment fix.** | pooled, `dests=8`, 2/shard, RG pool @25%, one SQL Server store, 2026-07-10 | C3 handback |
| C3 — N=16 residual is **store-CPU saturation**, mechanism UNPROVEN | latch gone → store box CPU **92–93%**; top wait `SOS_SCHEDULER_YIELD` is #1 only *by default* (PAGELATCH→~0), it did **not** surge (+11%). Store CPU was already ~87% in C2 — **unmasked, not new**. **No per-query CPU attribution** — churn→CPU link is a hypothesis; pooled-claim rewrite sufficiency at N=16 **UNVERIFIED** *(C4 attempted the attribution — see the C4 row below and §8; it did **not** establish sufficiency either way, and its own reconciliation gate failed)*. Engine box far from saturation (busiest core ≤44%). | store DMVs + `cpu_soak.csv`, 2026-07-10 | C3 handback |
| **Per-query CPU attribution (C4) — VERDICT: WITHHELD** ⚠️ **and the ordinal is NOT ADMISSIBLE as-is — see the rig caveat** | ran the attribution C3 lacked. **#1 N=16 query-CPU consumer = `list_fifo_lanes` (dispatcher discovery scan) at 47.46%; CLAIM #2 at 40.33%** → AMBIGUOUS (two families >40%). Reconciliation pre-gate does **not** robustly clear 70% (70.68% only on idle-diluted denominator + off-wall collapse-tail; every sustained/phase-matched denominator 64.5–69.6%) ⇒ **family precedence is not authoritative at any N**. CLAIM `cpu_us_per_exec` rises 8.4× N=4→16 (honest, not spin/empty-claim) but "deeper-queue-scan driven (~4.3× reads growth)", a **necessary target, not sufficiency**. **Claim-only rewrite: NOT SUPPORTED AS SUFFICIENT — an inference, not a proof** *(downgraded 2026-07-12 from "PROVEN insufficient"; see the three reasons in the rig caveat)*. ⚠️ **RIG CAVEAT — read before quoting ANY C4 number.** **(1)** C4 ran on the **8-vCPU** engine box (`cpu_soak.csv`: `engine cores=8`), so its **N=16 arm is 16 shard processes on 8 vCPU** — the configuration §8's own rig table calls *"core contention, not store scaling."* **Per-query CPU shares are exactly the quantity that contention distorts**, so the 47.46/40.33 ordinal is **not admissible as-is**; C6 re-ran N=16@2 on the upsized 16-vCPU box and reproduced the **collapse** (26.2%), but **the CPU attribution was never re-run post-upsize.** **(2)** C4 handed back **zero JSON** — every C4 figure here is **prose-only and unauditable**. **(3)** The `cpu/elapsed = 0.28` "~72% off-CPU WAIT" reframe is a **COLLAPSE-STATE artifact** — 0.93 → 0.70 → 0.28 is **ACROSS ARMS** (N=4 → N=8 → N=16-collapse), *not* an N=16 plateau (N=16 is plateau-less). **Do not re-target the fix to lock/latch WAIT on the strength of 0.28.** The "intrinsic `list_fifo_lanes`" leg (cpu/read **+2.06×**, 10.3 → 21.3 µs/read, already rising at the 100%-delivered N=8 arm) is the strongest surviving leg, but it isolates only the **per-read** factor; the **dominant** factor is the **4.3× read-count growth, which is backlog-coupled** — i.e. the collapse-effect confound is *not* closed. Source: `FOLLOWUP_C6_3d-result_2026-07-11.md` (working: `REVIEW_C6_recapture-corrections_2026-07-11.md` §4), computed off-line from C4's 3-arm qstats deltas — **and therefore inheriting the same 8-vCPU rig.** *(The separate "apparatus perturbed — C4 ran ~68% heavier than C3" caveat IS **REFUTED**: a clean ~6× lighter recapture left `claim_mean` **unmoved** (93.4 → 92.6 ms), so the C3↔C4 delta is run-to-run/drift variance, not the instrument.)* | pooled, `dests=8`, 2/shard, N=4/8/16, same commit as C3, **8-vCPU engine box (m7i.2xlarge)**, 2026-07-11 | C4 handback + recapture *(prose only — **no JSON artifact exists**)* |
| **Per-shard ceiling at N=8, latch-free (C5) — VERDICT: `N`-SIZING INSUFFICIENT** | ran the capacity-frontier falsifier. Per-shard ceiling **`R ∈ [2, 3)`**: **2/shard PASSes** (100.0% delivered, 115,200/115,200; stranded 0; drained; slope **+1.94**; `claim_mean` 18.2 ms) and **3/shard COLLAPSES, reproduced 2/2** (51.93% / 50.01% delivered; stranded 83,337 / 86,629; slope **+108.7 / +110.9**) — plus a **3rd replicate** on C6's heavier instrument (`c6-n8x3`: 50.11%, slope +112.5). *(Third **replicate**, not an independent reproduction: same rig, same commit, same config — only the instrument weight differs.)* `R < 3` ⇒ **`R < 3.62/shard`**, the rate a cleared N=16 needs ⇒ **`N`-sizing alone cannot reach 520.83 events/s.** Cleared **by inequality**, so the un-run 3.62 / 5 / 7.23 rungs were correctly skipped. **Bridging premise, stated:** applying an **N=8** ceiling to an **N=16** requirement assumes per-shard capacity does not *increase* with `N` — established by C1/C2/C3 (it declines). ⚠️ **The LOWER bound `R ≥ 2` is soft:** the N=8@2 rung is marginal and run-to-run-variable (C4's recapture stranded 3,175 at slope +13; C6's `n8x2` PASSed at 100%/0-stranded/slope +4.3). **The verdict rests entirely on the UPPER bound `R < 3`, reproduced 3×** — which is unaffected. **Decisive, not deferred:** the pre-registered co-constraint bar is **85% `max_core%`** (C5 handoff §3.2); at the c5-b collapse the engine peaked at **max 59.7%** (mean 39.5 / p95 50.5, nearest-rank, on 16 cores) with the load-gen at **8.5% peak** — the carve-out did **not** fire. *(The other collapse arm, c5-b2: mean 38.3 / p95 48.9 / max 56.7, load-gen peak 7.4%.)* **C5 measures `R` and nothing else — it names no wall.** FIFO intact (0 inversions / 0 repeats, all arms). ⚠️ Both 3/shard *climb* rungs drained clean in ~29–33 s: **a 60 s test would have falsely passed.** | pooled, `dests=8`, **N=8**, `MEMORY_OPTIMIZED TEMPDB_METADATA=ON`, 900 s soak, **engine box upsized to m7i.4xlarge (16 vCPU)**, commit `98bec81`, 2026-07-12 | `c5-a.json` / `c5-b.json` / `c5-b2.json` |
| **WAIT decomposition / convoy detector (C6) — VERDICT: AMBIGUOUS-STRUCTURAL** | went looking for the contention that would *name* the wall. **None was observed.** *(Not "there is none" — see the scope caveat: this is a null from an instrument with two stated blind spots.)* Both pre-registered contrasts agree — PRIMARY (N=8@3 FAIL vs N=8@2 PASS, **same shard count**) and SECONDARY (N=16@2 vs the healthy N=4@2 floor): **`convoy_present = false` on all four arms**; the convoy floor (≥5 sessions suspended on one shared `resource_description`, **or** a blocking chain ≥2 deep) was met in **0 of 288 samples**; largest suspended group anywhere = **2** (once, at N=16); max chain depth = **1**. **What it excludes — a CONVOY of each class, nothing more:** no lock **convoy**, no shared latch/page **convoy**, no memory-grant (`RESOURCE_SEMAPHORE`) **convoy**, no spill **convoy**; plus a tempdb-catalog VOID (zero `2:1:*` pages across 288 convoy samples — C3's latch fix held). It does **NOT** exclude a per-query spill, a per-query latch-acquisition cost, or per-session grant pressure — **those cannot form a convoy and would always return this null.** **Explicitly does NOT upgrade to CPU-BOUND** despite every temptation (store at 94%, runnable 52 on 8 schedulers, `SOS_SCHEDULER_YIELD` in the millions of ms) — that is precluded by the offline **64.4%** reconciliation *(source: `HANDBACK_C4_2026-07-11.md` §0 — N=16 attributed query-CPU over the honest plateau denominator, store box = 93.3%; relayed in `REVIEW_C6_recapture-corrections_2026-07-11.md` §4. **Prose only — no JSON artifact computes it, and no C6 artifact backs it.**)* and is recorded as **context, not verdict**. ⭐ Cleanest proof in the arc that **rank names nothing**: `WRITELOG` is the **#1** wait by `d_resource_ms` on **every** arm — including the healthy, 100%-delivered N=4 floor (127,962 → 191,348 → 250,947 → 577,773 ms). ⚠️ **Scope — two blind spots, quote both.** **(1) Class:** the detector is **blind by construction** to any cost that is not a *shared* `resource_description` (per-query CPU, intra-query parallelism exchange, per-query spill, allocator churn, scheduler queueing **can never form a convoy**). **(2) Time:** the null comes from **72 point-in-time `dm_os_waiting_tasks` snapshots per arm at a 10 s cadence** over a 900 s soak — **a convoy that forms and clears inside that window is not excluded**, and the detector's minimum detectable convoy duration/duty-cycle was never stated. **"No convoy observed" is not "there is no convoy," and neither is "nothing is there."** | pooled, `dests=8`, N=4@2 / N=8@2 / N=8@3 / N=16@2, 900 s soaks, 72 × 10 s convoy samples per arm, fenced + exclusion-set-filtered wait deltas, commit `98bec81`, 2026-07-12 | `c6_convoy_*.json` / C6 handback |
| **Intra-query-parallelism falsifier (C7) — REFUTED as a removable cause, and the lever is NEGATIVE** | pre-registered A/B against the one hypothesis C6's null could not see: `CXSYNC_PORT` (C6's #2 real wait at N=16, growing **34×** across the ladder — the tempting "self-inflicted parallelism overhead" story). **Manipulation check PASSED:** `CXSYNC_PORT` 135,361 ms at base → **≤ 90 ms** under DB-scoped `MAXDOP=1` (~75× below the pre-registered <5% bar: `0.05 × 135,361 = 6,768`). *(Cite the **bound**: 90 ms is the **top-15 floor** in `c6_convoy_c7-dop1.json` — `CXSYNC_PORT` is simply absent from the list, so the artifact establishes `≤ 90`, **not** the handback's "exactly zero.")* **Same-session drift control PASSED:** C7-base reproduced the 3-run N=8@3 baseline in-session (49.44% delivered, slope +115.1, vs 51.9 / 50.0 / 50.1% and +108.7 / +110.9 / +112.5). **Result — `MAXDOP=1` is WORSE on both pre-registered limbs:** delivered **49.44% → 20.63%** (below the <45% trigger) *and* slope **+115.1 → +154.7** (past the >+125 trigger). ⇒ **Parallelism is not a removable cause — it is load-bearing.** `MAXDOP=1` is not merely absent as a lever, it is **NEGATIVE: do not adopt.** ⚠️ **What C7 does NOT establish:** it refutes `CXSYNC_PORT` as a *removable cause* (eliminating it made things worse). It does **not** show the 34× growth is *caused by* the collapse — **no healthy-but-high-load `CXSYNC_PORT` control was run.** Whether the growth is a collapse artifact or the signature of load-bearing parallel work is **UNTESTED. Do not name it either way.** *(An earlier version of this row called it a "collapse EFFECT, not a cause" — that is the same unearned substitution the workstream has retracted twice, and it is withdrawn.)* **C7 yields no publishable capability number** — all three arms collapsed (`result: SOAK_NOT_SUSTAINED`). ⚠️ **Scope:** established at **N=8** (3/shard and 2/shard); **N=16 was not run**, so extension there is **inference, not measurement**. *(The former reason given — "N=16's delivered% is too irreproducible to A/B, 9.4% at C3/C4 vs 26.2% at C6" — is **WITHDRAWN as false**: C3's N=16 delivered **27.95%** (`c3-16.json`: 64,392/230,400) and C6's **26.16%** — they agree to within 1.8 points. **9.4% is C4's N=16 arm ALONE**, prose-only in `HANDBACK_C4_2026-07-11.md`, no artifact — and C4 is the arm that ran 16 shards on 8 vCPU. On the two arms that HAVE artifacts, N=16 reproduces fine, so the irreproducibility excuse does not survive: **the N=16 C7 arm is testable and was simply not run.**)* ⚠️ **The harm-check arm:** `MAXDOP=1` degraded N=8@2 to **75.73% / not drained / 28,106 stranded** — against a default-config baseline for that rung that is **itself run-to-run variable** (C6 `n8x2`: 100%/drained/0-stranded/slope +4.3; C4 recapture: 3,175 stranded, slope +13). The comparison is **cross-session, with no same-session control**. The magnitude (28,106 stranded at slope **+38.4**, ~9× the worst baseline strand and ~3× outside the +4..+13 slope band) makes the **direction credible but not proven**. | pooled, `dests=8`, N=8 @ 3/shard and 2/shard, DB-scoped `MAXDOP=1` (reverted + plan cache cleared after), 900 s soaks, commit `98bec81`, 2026-07-12 | `c7-base.json` / `c7-dop1.json` / `c7-dop1-pass.json` |

> **C1 magnitude caveat.** Both of C1's 900 s soaks collapsed at their auto-picked pinned rate, so its per-shard
> figures are *climb-peak* rates that overstate the sustainable rate — the definitive 900 s N=4 point is still the
> 10 ingress/s = 2.5/shard row above. C1 measured the *scaling shape* (per-shard declines with `N`, load-dependently),
> not a new sustainable magnitude. Its job was to test whether shard count can *close* the ~5.8× gap; it cannot do so
> efficiently (4× shards → 1.36×). See Phase 5.
>
> **C2 update.** C2's fixed-2/shard sweep settled what C1 left open: the near-linear light-load scaling **does not
> survive beyond N=4** — a shared store tolerates ~4 lightly-loaded shards, then falls off a cliff. The wall is a real
> store-side one (tempdb system-catalog PAGELATCH), not a harness/CPU artifact. So shard count cannot buy the target
> beyond N=4 **on the current SQL config** — and "config" is load-bearing: C2 established correlation, not a proven
> remedy (see Phase 5 / C3).
>
> **C3 update — PARTIAL (the config counterfactual).** Rerunning the identical 2/shard sweep with `MEMORY_OPTIMIZED
> TEMPDB_METADATA=ON` **eliminated** the C2 catalog PAGELATCH at both arms, which **proves the mechanism** C2 fingered
> was real — and it **cleared N=8** (18% → 100% delivered, drained). But it moved the knee only **one shard-doubling**
> (N=16 still collapses, 27.9% vs 4.8%), so it is a **diagnostic, not a deployment fix**. With the latch gone the N=16
> wall is **store-CPU saturation (92–93%)** that the latch had *masked* (store CPU was already ~87% in C2) — **not** a
> newly-emerged wall. Critically, C3 gives **no per-query CPU attribution**, so the hypothesis that this CPU is the
> pooled claim's temp-object churn is *unproven*, and the pooled-claim rewrite's sufficiency at N=16 is **UNVERIFIED** —
> it must be measured against this exact sweep, not assumed. Two handoff errata the run corrected: the enabling T-SQL is
> `MEMORY_OPTIMIZED TEMPDB_METADATA` (two keywords, **not** the underscore form), and the feature is **not**
> Enterprise-only (available on all editions since SQL 2019, subject to In-Memory OLTP memory limits — confirm against
> current licensing before treating edition as a deployment constraint). Config was **torn down** to the C2 baseline
> after the run. §8 stays **unflipped**; `per_lane` stays off.
>
> **C5/C6/C7 update — the store-side search is CLOSED (2026-07-12).** The three rows above walked the scaling
> *shape*; C4 *attempted* the CPU attribution (on an 8-vCPU box, with no artifact — see its rig caveat); the
> three rows below tested the three remaining store-side escapes and **all three came back negative.**
> `N`-sizing cannot get there (**C5**: `R ∈ [2, 3)` < 3.62/shard). **No shared-resource convoy was observed** for
> a contention fix to remove (**C6**: no convoy on either contrast — *at a 10 s cadence, and blind to non-shared
> costs*). And it is not a parallelism config default (**C7**: `MAXDOP=1` is *negative* — it made the collapse
> worse and degraded a rung that passes under the default). **The wall
> at N=8/N=16 is therefore still UNNAMED, and naming it is no longer on the critical path** — because the fix
> does not depend on the name. See "The store-side search is closed" in §8. This is a **good** outcome: it
> retires three tempting dead ends. ⚠️ **But it does not leave "exactly one path standing" in any exhaustive
> sense** — it leaves the `txn/event` levers as the **best-supported remaining candidate** over a candidate set
> that was never partitioned. See §8's "elimination" caveat.

### Retracted

| number | why |
|---|---|
| 36 ingress/s soak collapse, `stranded=238,180` | **B6** truncated all 8 sink tallies *and* **B8** auto-picked a soak rate ~3× sustainable. Over-determined collapse; magnitude uncalibrated. |
| Every 60 s "drained-clean" climb rung read as a rate (40/s, 13.05/s, 12/16/20/s …) | A 60 s climb is a **volume** test. It overstates the sustainable rate by `(hold+drain)/hold`. The honest per-rung rate *declines* 13.05 → 10.93/s as offered climbs 16 → 36/s. |
| All pooled collapse magnitudes (`stranded` counts) | Collapse **verdicts** stand; **magnitudes** are B6-truncated. |
| "We are at per-server parity" | Benchmarked against competitor **marketing** (~500 msg/s), not the qualified spec. (ADR 0051 records this.) |
| "~2× storage vs the incumbent" | Unvalidated estimate against a brochure number. |
| "in_pipeline is 4× overcounted" | Fixed (D4). Do **not** re-apply the divisor. |

---

## 4. The four "contradictory" numbers, reconciled

They are all real, and they measure different walls in different regimes. Normalizing to ingress msg/s:

| # | number | fan-out | store | metric | binding resource |
|---|---|---|---|---|---|
| a | 10/s fleet (2.5/s per shard) | 8 | SQL Server | sustained e2e, 900 s | **store-side — but UNNAMED** *(was "pooled claim runaway (tempdb)"; C4 demoted the claim to #2, C6 found no convoy — see §8)* |
| b | 193/s | 1 | SQLite | **intake / ACK only** | engine GIL plumbing |
| c | 60/s | ~1 | SQL Server LAN | sustained e2e, 1 lane | serial per-lane latency |
| d | 23,600 c/s | n/a | SQLite NVMe | store microbench | none (commit capacity not binding) |

The arithmetic that dissolves it:

- **(a) vs (c).** (a)'s 87 delivered/s across 16 lanes is **5.44/s per lane** — far *below* (c)'s 60/s per-lane
  ceiling. Those lanes are starved **upstream** by a **store-side** wall, not by their own latency. *(This line
  formerly read "by the shared pooled claim" — that attribution is **withdrawn**: C4 demoted the claim to #2 and
  C6 observed no convoy. The **measurement** — 5.44/s per lane, an order below the per-lane ceiling — is
  unaffected, and it is the point.)*
- **(a) vs (b).** (b) is *intake* at fan-out 1 on SQLite: no delivery, no claim, no tempdb. It says nothing
  about delivered throughput.
- **vs (d).** The store's **commit** bandwidth is ~36× the pipeline's demand, so **commit bandwidth is not the
  wall.** The wall *is* store-side. **But do not fill in the blank.** This line used to end *"…the claim query
  is"* — that is now **withdrawn**: C4 demoted the claim to the **#2** N=16 CPU consumer (40.33%, behind
  `list_fifo_lanes` at 47.46%), and C6's convoy detector found **no shared-resource contention at all** on
  either contrast. The honest form is *"commit bandwidth is not the wall; the wall is store-side and, as of
  2026-07-12, **unnamed**"* — never *"the store is never binding,"* and never a named store-side culprit the
  data does not carry. **Naming it is no longer a prerequisite for the fix** (§8, "The store-side search is
  closed").

**Ordered:** store capacity ≫ engine-CPU intake (193) > single-lane latency (60) ≫ the actual `dests=8`
pooled rig (2.5/shard). Each lower number is a wall the higher ones never reach, because the configuration
changed underneath.

> **Honest caveat.** Per-process engine CPU read a constant `0.00` on the SQL Server rig, so a GIL-bound core
> cannot be *formally* excluded — only circumstantially. **The attribution is rigorous store-side and blind
> engine-side.** Fixing the engine-side collector is a prerequisite for any CPU claim.

---

## 5. Why the measurement programme kept failing

Nine harness defects in eight days. They are not nine bugs — they are **one bug wearing nine costumes**, plus
one methodological error.

**The defect class:** *a fixed constant bounding an interval that scales with a run parameter, which on
expiry **silently fabricates a plausible result** rather than failing loudly.*

| | defect | fabrication |
|---|---|---|
| B1 | `DRIVER_DONE` wait hardcoded 600 s | a 900 s soak aborts mid-send |
| B6 | sink `DRIVE_COMPLETE` wait hardcoded 600 s, on a *wider* window | every sink truncates its tally; the engine reads a real `stranded>0`; **a collapse indistinguishable from a product collapse** |
| B7 | `ENGINE_DRAINED` gate hardcoded 300 s | a healthy soak reads `FROZEN_TAIL` (false negative) |
| B8 | `pick_soak_rate` returned the **offered** rate while the report published the **honest** one | the soak ran at ~2.8× the ceiling the same report printed, and **collapsed by construction** |
| B9 | a collapsed soak serialized `result: "PASS"`, exit 0 | a saturating run published a passing headline |
| B10 | target compares ingress against a total-events budget | every gap figure inflated by `1 + dests` |

**The methodological error, which is worse than any of them:** the 60-second climb rung is a **volume** test
(`offered = rate × hold`, then a fixed `hold + drain` budget to clear it) being read as a **rate** test. The
ladder's own pinned ceiling therefore overstates the sustainable rate, and B8 then fed that overstatement
back in as the soak's offered rate. The instrument was, structurally, unable to measure the quantity the
decision needed.

**A validity rule that falls out of B6, and rescues several numbers:** a *sustaining* run drains in seconds,
so its sink window stays under 600 s; a *collapsing* run drains long and trips the bug. **B6 preferentially
contaminates collapses, not sustains.** This is why the 540 s `per_lane` sustain is clean (verified: no
`partial tally` fingerprint in any of its artifacts) while every pooled collapse magnitude is not.

**The through-line, beyond the harness:** *confident numbers with the wrong provenance.* The retracted
per-server-parity claim, the retracted 2×-storage estimate, the 3.5× volume overstatement, the 52× gap — each
was quoted with certainty and each was wrong. The instrument was fixed this week; the habit needs the same
attention.

---

## 6. The cost model: transactions, not messages

The durable-write cost per message (ADR 0051): `txn/msg = 3 + 2H + 2N`, where `H` = handlers the router
**selects** and `N` = outbound destinations.

**The `2H` term is charged before the handler runs** — therefore before it can decide to filter.

| act | cost |
|---|---|
| a **Router** filters | **0 transactions** |
| a **Handler** filters | **2 transactions** |

Same conceptual act; a two-transaction price difference; **the engine gives the author no signal about it.**

### A reference estate, measured

A large multi-hospital IDN currently running the incumbent engine, whose configuration has been ported to
MessageFoundry (75 inbound feeds). Static analysis of that configuration:

- **72% of feeds are the simple shape** (`H=1, N=1` → 7 txn/msg). Median `H`=1, `N`=1.
- Only **four fan-out hubs** exist (`H` = 20, 14, 10, 8).
- The **ADT hub**: the router selects **20** handlers; **~4** deliver. The other 16 self-filter on trigger,
  patient class, PID or OBX content. `txn/msg = 3 + 40 + 8 = 51`.

> **32 of those 51 transactions — 63% — produce no counted message.**

| topology | H | N | txn/msg | events/msg | **txn per event** |
|---|---:|---:|---:|---:|---:|
| simple feed | 1 | 1 | 7 | 2 | **3.50** |
| bench (`dests=8`) | 8 | 8 | 35 | 9 | **3.89** |
| **production ADT hub** | **20** | **4** | **51** | **5** | **10.20** |

**The bench models the wrong shape.** It ties one handler to one destination, so `routed == delivered`. It
therefore *understates* transform-stage work by 2.5× and *overstates* outbound work by 2× relative to the
real ADT hub — and the outbound claim is precisely the wall it went looking for.

### Estate volume, and the honest headroom

| | events/day (in + out) | events/s |
|---|---:|---:|
| busiest day observed | 1,591,976 | 18.4 daily-avg |
| typical weekday | 1,422,161 | 16.5 |
| typical weekend | 649,341 | 7.5 |
| **typical weekday peak hour** | ~135,000/hr | **37.5** |
| **maximum observed hour** (month-start) | ~171,000/hr | **47.5** |

Peaking factor **2.28×** typical, **2.89×** at the month-start spike — which the owner confirms is
structural (a start-of-month eligibility sweep across all active patients). That spike is **not ADT**
(ADT peak-hour moves 0.99× across the month boundary), so it is composed of low-fan-out traffic.

Weighting by cost (ADT is 17% of events at 10.20 txn/event; the rest ~3.50):
**estate = 4.64 txn/event.**

| | events/s | txn/s |
|---|---:|---:|
| measured engine (pooled bracket) | 90 | ~350 |
| estate month-start peak | 47.5 | ~220 |

**The engine as measured already carries this estate with ~1.6× cost-weighted headroom over the single
busiest hour it has ever recorded** — and the 45M/day goal is **28× that estate's busiest day.**

---

## 7. Two structural ceilings the bench never saw

**A single hot feed cannot be sharded.** `store.py`: *"outbound lanes key on `destination_name`; ingress,
routed, and response lanes on `channel_id`."* One inbound connection's entire routed stage is **one strict-FIFO
lane**, and engine shards partition **by connection** (ADR 0037). So a feed's ceiling is one lane, on one
shard, on one core — and adding shards cannot split it. This is ADR 0051's *"a single hot feed is pinned to one
core,"* now confirmed in the store's lane keying.

Per-feed ceiling ≈ `1 / (H × 2 × t_txn)` ingress msg/s. **For the ADT hub, `H=20` is a 20-fold serial
multiplier on the hottest feed in the estate.**

**Therefore 45M/day is reachable only if traffic spreads across many inbound connections**, none individually
exceeding a single lane's ceiling.

### The spec pairs 45M/day with **1500 connections** — so this is a CONCENTRATION rule, not a scale limit

`520.83 events/s ÷ 1,500 connections = ` **0.347 events/s per connection**, on average — nowhere near any
lane's ceiling. ADR 0066 sizes against exactly this shape (*"1,500 inbound MLLP lanes, 2 engines, 1 shared
SQL Server store"*).

So the constraint is not total volume. It is **how concentrated the volume is on any one connection.**

Lane ceiling ≈ `1 / (2H × t_txn)` ingress msg/s:

| feed shape | serial txn/msg | ceiling @3.5 ms | @7.0 ms (sync-commit AG) |
|---|---:|---:|---:|
| simple (`H=1, N=1`) | 2 | ~143 msg/s | ~71 msg/s |
| **ADT hub (`H=20, N=4`)** | **40** | **~7.1 msg/s** | **~3.6 msg/s** |

**Does a realistic hot feed fit?** The reference estate's ADT hub carries **12.7×** the volume of its average
inbound feed. Applying that concentration at spec scale:

`0.347 events/s × 12.7 = 4.42 events/s = 0.88 ingress msg/s`

| | lane ceiling | headroom |
|---|---:|---:|
| at the spec's 3.5 ms disk latency | 7.14 msg/s | **8.1×** |
| at ~7 ms (synchronous-commit AG) | 3.57 msg/s | **4.0×** |

**It fits, comfortably.** The earlier alarm in this document — that a single ADT hub would be 2.5× short —
assumed one hub carrying 17% of a 45M/day enterprise. That is a **254× concentration** relative to the
average, and it is not what 1,500 connections looks like. **Retracted.**

> **The design rule that survives:** a single `H=20` hub saturates its routed lane at ~7.1 ingress msg/s
> (~3.6 under sync-commit AG). Beyond that, split the feed across connections, or cut `H`. Publish this as a
> per-connection capacity bound; it is invisible in every fleet-aggregate measurement taken so far.

**The levers that raise the hot-feed lane ceiling** (all attack the serial chain, not the fleet aggregate):

| change | serial txn | lane ceiling @3.5 ms | nature |
|---|---:|---:|---|
| today | 40 | 7.1 msg/s | — |
| `fifo_claim_batch > 1` (ships OFF) | 21 *(K≥20)* · ~34 *(K=8)* | 13.6 · ~12.7 msg/s | config |
| `accepts=` seam (`H` 20 → 4) | 8 | 35.7 msg/s | config + seam |
| both | 5 | 57.1 msg/s | config + seam |
| **+ intra-message concurrency** | ~1 | ~286 msg/s | **engine, new** |

> **The `fifo_claim_batch` row is `H·(1 + 1/K)`, not a flat `H+1`** — so `21` requires **`K ≥ H = 20`**, while
> the shipped guidance is **K = 8–16**. It is a **claim-only** batch (verified 2026-07-11, §8 Phase 3(2)); that
> is *why* the cost is `H+1` and not `~2`. It **cannot** touch the OUTBOUND claim (hard-1).

The last row is a **verified, unexploited opportunity.** `fifo_claim_batch` batches the *claim* into one
commit, but the dispatcher then loops `for item in items:` — *"processed in FIFO order below"* —
**sequentially**, one handoff commit each. Yet the 20 routed rows of a *single* message target **20 different
destinations** and carry **no mutual ordering dependency**: per-destination FIFO is enforced *across* messages,
by the outbound lane (keyed on `destination_name`), not *within* one. They could be transformed concurrently
while message-level FIFO is preserved. No ADR contemplates this.

### `H` is also a STORAGE amplifier — and the spec gives us a budget to check it against

`store.py`: *"Both `ingress` and `routed` rows hold the raw body"* — **one routed row per selected handler,
each a full copy of the raw message.** Body copies written per ingress message scale as `(2 + H + N)`:

| feed | queue rows written | body copies written |
|---|---:|---:|
| simple (`H=1, N=1`) | 3 | 4 |
| bench (`dests=8`) | 17 | 18 |
| **ADT hub (`H=20, N=4`)** | **25** | **26** |

> ✅ **Corrected 2026-07-10 (step A2); now pinned by `tests/test_bytes_per_message_amplification.py`.**
> This read `(1 + H + N)`. Measured against the real store methods, `enqueue_ingress` writes **two** copies
> of the raw — `messages.raw`, retained for the message's lifetime, *and* the ingress `queue.payload` — in
> one transaction. The hub writes **26** body copies, not 25.
>
> A second correction, in the same direction: **SQL Server does not deduplicate identical fan-out bodies.**
> SQLite implements store-once-deliver-many (`shared_body` + `body_ref`); `sqlserver.py`'s own schema
> comment records that *"on SQL Server `body_ref` stays NULL today"*. So `N` identical delivery bodies cost
> **1** copy on SQLite and **N** on SQL Server — the backend the rig and production actually run. Any
> storage figure measured on SQLite understates SQL Server.

The incumbent's budget is **10.9 KB per message** (`500 GB/day ÷ 45M`). A first-order estimate for
MessageFoundry — assuming a ~2 KB raw HL7 body and ~2.67× encoding inflation (`NVARCHAR(MAX)` at 2 B/char ×
base64 of the `mfenc` ciphertext) — puts the estate-weighted figure at **~11 KB/event**, i.e. roughly at
parity; but the ADT hub alone is **~27 KB/event**, about **2.5× the budget**.

> ⚠️ **That is an estimate with stated assumptions, not a measurement.** `bytes/msg` has **never been
> measured**. Measuring it is free, and it is a first-class parity number the incumbent publishes outright.
> The structural claim does not depend on the raw size: **write volume, like transaction count, scales with
> `H`.** Cutting `H` from 20 to 4 cuts both — and the 15 TB / 30-day drive sizing an adopter is told to buy
> depends on it.
>
> **Do not publish the `~11 KB` / `~27 KB` figures.** Step A2 pinned the copy count exactly (`2 + H + N`),
> but converting copies to *durable bytes* needs three multipliers that remain unmeasured: character width
> (`NVARCHAR(MAX)` is UTF-16 — 2 B/ASCII char — with no UTF-8 collation on this schema), cipher expansion
> (`mfenc` ≈ `4/3·raw + 64`, and **off by default**), and everything the database writes that is not the
> body — row and page overhead, indexes, and above all the **transaction log**, which durably records each
> of the `3 + 2H + 2N` transactions. Copies × width is a *lower bound* on body bytes, not a figure for
> durable bytes. The honest measurement is a `db.size_bytes` delta over a live run at a known message count
> — the harness already samples it as `EngineSample.db_size_bytes`. Until then this row is **UNKNOWN**, and
> a confident number here would be exactly the failure this audit documents.

---

## 8. The plan

Measurement-led. Every phase states what it buys, and what result would prove it wrong.

### Phase 0 — Fix the yardstick *(hours, no rig)*

Fix **B10**: gate on `ingress × (1 + dests) >= 520.83`. Restate every published figure in total events/s.
Add two counters to the harness, both currently unmeasured and both first-class parity numbers the incumbent
publishes outright:

- **`txn/msg`** — committed transactions per message. The currency the disk actually serves.
- **`bytes/msg`** — against the spec's stated **10.9 KB/message** (`500 GB/day ÷ 45M`). It determines the
  15 TB / 30-day drive an adopter is told to buy.

*Buys:* an honest denominator, and two directly comparable parity metrics. Removes a 9× phantom from every
gap statement.

### Phase 1 — Resolve the claim mode **at realistic lane counts** *(rig runs)*

> ⚠️ **Do NOT simply flip to `per_lane`.** An earlier draft of this document recommended exactly that, on the
> strength of the claim-mode A/B. **That A/B ran at 16 lanes. The target deployment is ~1,500.** The
> recommendation does not survive the scale it is meant to serve — and making it would have repeated this
> programme's signature failure inside the document diagnosing it.

Both claim modes have a *measured* pathology, in **different regimes**:

| mode | pathology | measured at |
|---|---|---|
| `pooled` (shipped default) | outbound claim query's **tempdb-metadata churn**: `claim_mean` 33.6 ms for ~1 row, runaway 12 → 127 ms under load; tempdb table-vars = **43%** of fixed claim cost | 16 lanes, `dests=8`, SQL Server |
| `per_lane` (opt-out) | **claim storm**: ~4,500 per-(lane×stage) claim loops → **~18k empty `UPDLOCK` claims/s saturating the store at *zero messages*** (92% CPU, `LCK_M_U` convoy 40–70 ms). **Drops messages at high fan-out.** | **1,500 lanes**, 2 engines (ADR 0066) |

So `per_lane`'s 4.5×-cheaper claim is real **at 16 lanes**, and `pooled` exists precisely because `per_lane`
is untenable at 1,500. Neither number generalises to the other's regime.

**Run the A/B as a lane-count sweep** — 16 → 100 → 500 → 1,500 lanes — on the fixed harness at a 900 s soak,
and find the crossover. Then decide.

> ⚠️ **WITHDRAWN 2026-07-12 — the "targeted SQL rewrite" recommendation is off the plan.** This paragraph used
> to read: *"The likely answer is neither mode as shipped: the pooled claim's **tempdb table variables are 43%
> of its fixed cost**, and removing them attacks the default path directly, at every lane count. That is a
> targeted SQL rewrite, not a mode flip."* **Do not build it.** C4 demoted the claim to the **#2** N=16 CPU
> consumer and the §3d coupling computation proved a claim-only rewrite **insufficient**; C6 then found **no
> convoy** on any arm, so there is **no single store-side blocker for *any* rewrite to remove** — claim-scoped
> or whole-dispatcher. The 43%-of-fixed-cost measurement stands; the **inference that removing it clears the
> wall does not.**
>
> The lane-count sweep itself retains **diagnostic** value (it would characterise `per_lane`'s knee — open
> question #6) but it is **no longer on the critical path to 45M/day** and must not be funded as one. See "The
> store-side search is closed".

*Falsifier:* if pooled's `claim_mean` stays flat as lane count rises, the tempdb churn is not scale-driven and
the crossover story is wrong.

### Phase 2 — Make the instrument model production *(harness change + one run)*

Teach the ladder `routed_fanout ≠ delivered` (`H=20, N=4`). Measure `txn/msg` and IOPS/msg at that shape.

*Falsifier:* if the ceiling at `(H=20, N=4)` matches the ceiling at `(8, 8)`, then `H` does not matter and the
entire `2H` thesis is wrong.

### Phase 3 — Cut `2H` *(config, then engine)*

1. **An `accepts=` seam.** A pure predicate evaluated in the **router** stage, before any `routed` row is
   materialized. Declined handlers cost 0 transactions instead of 2. **Purity is enforced for free** —
   `db_lookup`/`fhir_lookup` already raise outside a live Handler. It is a Python callable, so it does not
   violate the no-declarative-`Filter` rule. Verified feasible: **all 20 ADT gates are pure message-field
   reads**; the hub's `db_lookup` runs *inside the transform, after the gate*.
   *Buys:* ADT `txn/msg` **51 → 19 (2.68×)**; estate 4.64 → 3.55 txn/event; that feed's lane ceiling **×5**.
   *Costs:* the per-destination `FILTERED` disposition row disappears. **Needs an ADR** — it touches the
   count-and-log invariant.
2. **`fifo_claim_batch > 1`.** `_PREFIX_STAGES = {INGRESS, ROUTED}` (`pipeline/wiring_runner.py:237`) supports
   claiming the contiguous due head-prefix in one commit (ADR 0058/0066), and one message's routed rows share a
   lane (keyed on `channel_id`). It ships **`default=1` = OFF**.

   **RESOLVED 2026-07-11 (was open question #3) — and the question was posed backwards.** The dispatcher batches
   the **claim only**; the handoff stays one commit per row, by explicit design (`stage_dispatcher.py:797-800`
   loops `for item in items: await self._process_item(...)`; ADR 0058 calls batched handoff a non-goal — *"the
   `N`/msg handoff commits remain the floor"*). But `2H → H+1` **is the claim-only figure** — H claim commits
   collapse to 1, the H handoff commits remain. So the **13.6 msg/s lane ceiling in §7 was never conditional on
   anything**, and the "unverified" flag was misplaced. Had the handoff *also* batched, the cost would be ~2, not
   `H+1`.

   *Correction to the §7 table:* the steady-state serial cost is `H·(1 + 1/K)`, not a flat `H+1`. **`H+1 = 21`
   requires `K ≥ H = 20`.** At the shipped guidance of **K = 8–16** (`docs/CONFIGURATION.md`,
   `docs/AOAG-DEPLOYMENT.md`), the H=20 hub lands at ~34 txn/msg (a **~33% cut**, lane ceiling ~12.7 msg/s), not
   21/13.6.

   ⚠️ **It is a `txn`/event lever, NOT a shard-wall lever.** `per_lane_limit` is **hard-clamped to
   1 for OUTBOUND/RESPONSE** in three independent layers (`wiring_runner.py:237`, `stage_dispatcher.py:246`, and
   each store — e.g. `store/sqlserver.py:4302`), so `fifo_claim_batch` **cannot batch the outbound claim** — the
   one C1/C2/C3 actually measured and the one carrying `dests`× the rows. Its real effect is on **claim-*call*
   count per event** (up to 8× at the swept shape, where a message's 8 routed rows share one lane), and that is
   the axis that matters. **Any shard-wall rationale is DEAD:** this item used to add *"…and the tempdb catalog
   latch is a store-wide shared resource"* — **C3 removed that latch**, and **C6 observed no convoy of any class**.
   Still **unmeasured**: no artifact records a per-stage claim-call rate — the captured `claim_phase_soak`
   telemetry is **outbound-only** (see #227).
3. **Advisory lint** in `messagefoundry check`: flag handlers whose leading statements are pure guards ending
   in `return None`, and price them.

### Phase 4 — Durable-write *(ADR 0051's own #1 lever)* — **the only candidate standing, and CONTINGENT (2026-07-12)**

**Group-commit is not built.** Amortize fsyncs across concurrent transactions. Reduce carriage bytes
(`NVARCHAR(MAX)` at 2 B/char + base64 of the `mfenc` ciphertext).

> ⭐ **PROMOTED 2026-07-12 — this and Phase 3 are what is left.** With the store-side search closed
> (C5/C6/C7: shards, contention fixes, SQL rewrites and parallelism configs are all dead ends), the `txn/event`
> levers are the only path standing. **Phase 3's `accepts=` seam is MERGED** (#952/#213, ADR 0084).
>
> The old sequencing note here — *"**Sequence Phase 4 after Phase 1, not before**"* — is **WITHDRAWN**: Phase 1's
> claim-mode sweep is off the critical path (see the Phase 1 banner), so there is nothing left to sequence
> behind. **But Phase 4 DOES wait on one thing — Phase 0's `txn/s` counter. See the falsifier.**
>
> ⚠️ 🔴 **PHASE 4's OWN FALSIFIER CURRENTLY POINTS AGAINST IT — do not fund the build until Phase 0 resolves
> this.** The falsifier below asks whether measured `txn/s` sits far below the store's ~27–29k c/s commit
> ceiling. **The best available estimate says it does, by two orders of magnitude:** ~**350 txn/s** at the
> measured pooled bracket (*derived, not measured*: 90 events/s × 3.89 txn/event) and ~**2,416 txn/s = 9% of
> the ceiling** even at the full 520.83 target. §4(d) independently records **36× commit headroom** and says
> commit bandwidth **is not the wall**. On its own stated rule, that is the antecedent of Phase 4's falsifier
> **satisfied** — which points *against* group-commit buying much. **`txn/s` has never actually been measured
> (that is precisely what Phase 0's counter is for). Measure it FIRST.**
>
> ⚠️ **And justify it on its OWN arithmetic.** **C5, C6 and C7 provide *zero* evidence for group-commit
> specifically.** They say what *isn't* the lever; they do not say group-commit *is*. Its case must rest on the
> `txn`-per-event arithmetic (§6/§7) and ADR 0051 — **citing C5/C6/C7 in its favour would be exactly the
> adjacency inference that walked back C2 and C4.** **"The only candidate standing" is not "the right
> candidate."**

*Falsifier (updated):* if measured `txn/s` at the rig sits far below the store's ~27–29k c/s commit ceiling,
group-commit buys little **and the binding cost is elsewhere in the store**. ⚠️ This falsifier's *old* second
clause — *"…and the wall is the **claim query**, not the commit — which is what the evidence currently says"* —
is **withdrawn**: C4 demoted the claim to the #2 N=16 CPU consumer and C6 observed **no convoy**, so the wall is
**store-side and unnamed**. The falsifier still bites — and, on the derived estimate above, **it appears already
to have fired.** **Measure `txn/s` (Phase 0's counter) before building. This is a gate, not a formality.**

### The sizing arithmetic, at the flat 520.83 events/s target

> ⚠️ **SUPERSEDED as a *plan* (2026-07-12) — retained as the record of the arithmetic that motivated Phase 5.**
> Every "shards needed" figure below assumes shard scaling is **linear**. **It is not, and the sizing path is
> now measured shut:** C5 puts the per-shard ceiling at N=8, latch-free, at **`R ∈ [2, 3)`** — *below* the
> **3.62/shard** a cleared N=16 would need. Read the tables as *what would have been true if scaling held*, not
> as a plan. They are still the reason Phase 5 was the right experiment to run.

| configuration | ingress/s | total events/s | gap to target | per shard | shards needed (if linear) |
|---|---:|---:|---:|---:|---:|
| **pooled** — the shipped default | 10 | 90 | **5.79×** | 22.5 | **23.1** |
| **`per_lane`** — knee not yet found | ≥28 | ≥252 | **≤2.07×** | 63.0 | **≤8.3** |

And if `per_lane`'s knee is higher than the 28/s it was last tested at, the shard count falls proportionally:

| `per_lane` knee | fleet events/s | shards needed |
|---:|---:|---:|
| 28/s (last tested; not a ceiling) | 252 | 8.3 |
| 36/s | 324 | 6.4 |
| 44/s | 396 | 5.3 |
| **56/s** | **504** | **4.1** |
| 64/s | 576 | 3.6 |

The spec's app server is **20 cores**. Engine shards are I/O-bound on the database, so 4–9 shards on a 20-core
box would be unremarkable. **On this arithmetic, parity *would be* a sizing exercise — provided shard scaling
holds.** That proviso was the whole of Phase 5.

**It has now been measured, and it does not hold.** C1 → C2 → C3 established that per-shard capacity *declines*
with `N` and **breaks beyond N=4** (N=8 only with the tempdb latch removed); **C5 (2026-07-12)** then measured
the per-shard ceiling at N=8 latch-free at **`R ∈ [2, 3)`**, below the **3.62/shard** a cleared N=16 requires.
**Parity is NOT a sizing exercise.** See Phase 5, "The capacity frontier — RESOLVED", and "The store-side search
is closed" below.

### Phase 5 — Size to the spec *(the decisive experiment)*

**Does per-shard throughput stay flat as `N` grows?** Run `N = 1, 2, 4, 8, 16` at fixed per-shard load on one
unified store.

- **Flat** → parity is an `N`-sizing exercise on the 20-core spec. Publish `N × per-shard × 0.5` (the D4 rule:
  publish at ≤50% of the measured ceiling).
- **Declining** → a shared bottleneck (the store's claim path). Phases 3–4 become the whole game and shards
  buy nothing.

This separates "sizing problem" from "engine problem." It is cheaper than any lever, and every lever's value
depends on it.

> ✅ **ANSWERED: DECLINING** (C1 → C2 → C3, 2026-07-10/11; **C5, 2026-07-12**). Shards buy nothing beyond N=8
> even latch-free, and per-shard headroom at N=8 (`R ∈ [2, 3)`) is too low to make up the difference. **Phases
> 3–4 are the whole game**, exactly as the rule said. One correction to the rule's own wording: the "shared
> bottleneck" it anticipated turned out **not to be a single bottleneck at all** — C6's convoy detector found
> **none**, on any arm. So the consequence is *"compose the `txn/event` levers"*, **not** *"fix the store's
> claim path."* The parenthetical *(the store's claim path)* in the Declining branch is a **pre-C4 guess and is
> withdrawn.**

**C1 (2026-07-10) ran the first two points — N=1 vs N=4 — and the answer is DECLINING, but load-dependently.**
Per-shard capacity is near-linear at light load (1.01× penalty at 2/shard) and degrades as each shard is driven
harder (1.53× at 6/shard; collapse at 12/shard, a load the solo shard still holds); whole-fleet peak scaled only
**1.36× for 4× shards**. `claim_mean` rose 12.6 → 48.8 ms with shard count, tracking the penalty — the shared
pooled claim is the measured wall, reconciling with the claim-runaway row in §3. Two things C1 deliberately did
**not** settle, and neither can be settled from two points: (1) whether the penalty **compounds or saturates**
past N=4; (2) whether the near-linear **light-load (2/shard)** scaling — the *only* regime that could reach
520.83 events/s, since driving few shards hard just triggers the collapse — survives to N=8/N=16. C1 also could
not localize the wall (tempdb-metadata churn vs store-CPU vs the UPDLOCK storm) without SQL wait-stats; per-PID
CPU stayed `UNKNOWN` by design (a wrong number is worse than none).

**C2 (2026-07-10) ran that light-load sweep — N = 1/2/4/8/16 at a fixed 2/shard — and the answer is BREAKS beyond
N=4.** A true 900 s soak sustains cleanly at N=1/2/4 (100% delivered) and collapses at N=8 (18%) and N=16 (5%): a
shared store tolerates ~4 lightly-loaded shards, then falls off a cliff. The collapse is **store-side, decisively** —
engine box CPU p95 ~16% with the busiest single core ≤43% (the `max_core%` reading finally excludes a GIL-bound
thread, closing the per-PID-`0.00` loophole), load-gen idle, `send_ack` flat, while `claim` and `mark_done` run away.
SQL wait-stats localize it to **tempdb system-catalog PAGELATCH** (14.6× dominant at N=8; hottest page `2:1:97` =
`syssingleobjrefs`; I/O and lock waits absent) — the pooled claim's per-cycle temp-object churn, now shown to scale
with shard count at fixed per-shard load. So the "many lightly-loaded shards" path to 520.83 events/s is dead **beyond
N=4 on the current SQL config** — with the load-bearing caveat that C2 established *correlation*, not a proven remedy.

**C3 (2026-07-10/11) ran that counterfactual — the identical 2/shard sweep with `MEMORY_OPTIMIZED TEMPDB_METADATA=ON`
— and the answer is PARTIAL: the latch was real, but removing it buys exactly one shard-doubling.** The feature
converted the C2 catalog tables to latch-free memory-optimized structures and the hot page `2:1:97` collapsed to near
zero at both arms — so the mechanism C2 fingered is **proven**. That **cleared N=8 outright** (18% → 100% delivered,
backlog drained to zero, stranded 0) but left **N=16 collapsing** (27.9%, up ~6× from 4.8%): the knee moved (4,8] →
(8,16] and no further. With the latch gone, the N=16 residual is **store-CPU saturation (92–93%)** — but read that
carefully, because it is the same adjacency trap C2 was retracted for: `SOS_SCHEDULER_YIELD` is #1 only *by default*
(PAGELATCH went to ~0), it did **not** surge (+11%), and store CPU was **already ~87% in C2**. The honest framing is
that the store's pre-existing CPU cost was **unmasked**, not that a successor wall emerged — and C3 has **zero
per-query CPU attribution**, so pinning that CPU on the pooled claim's temp-object churn is a *hypothesis*, not a
result. **Consequences for the plan:** (1) the `N`-sizing path is **not** resurrected — even latch-free, the shared
store tops out at N=8 (and N=8 is a *marginal* clear: backlog slope +4 rows/s, store CPU climbing 40→60% through the
soak, headroom above 16/s uncharacterized — a longer/higher-rate N=8 soak is an unretired re-check before calling it
durable). (2) The pooled-claim rewrite was C3's leading durable, edition-portable lever, **but its sufficiency
at N=16 was UNVERIFIED** — and **C4 (2026-07-11) attempted the per-query attribution C3 lacked. It did not
settle sufficiency: it reported the claim as the **#2** N=16 store-CPU consumer (40.33%) behind the dispatcher's
`list_fifo_lanes` discovery scan (47.46%), so a `claim_fifo_heads`-only rewrite would leave `list_fifo_lanes`
#1 and standing.** ⚠️ **Three caveats travel with every one of those numbers, and none may be dropped:**
(i) **C4's own reconciliation pre-gate FAILED** (64.5–69.6% on every phase-matched denominator, against a 70%
bar) — so, in C4's own words, *"family precedence is not authoritative at any N."* **The ordinal cannot carry a
proof.** (ii) **C4 ran 16 shards on an 8-vCPU engine box** — the configuration §8's rig table calls *"core
contention, not store scaling"* — and **per-query CPU shares are exactly what that contention distorts.** The
attribution was **never re-run** after the 16-vCPU upsize. (iii) **C4 handed back no artifact**; the figures are
prose-only. Its **`cpu/elapsed = 0.28` "~72% off-CPU WAIT"** line is a **collapse-state artifact** (the
0.93 → 0.70 → 0.28 progression is **across arms**, N=4 → N=8 → N=16; N=16 is plateau-less) — **do not re-target
the fix to lock/latch WAIT on the strength of it.** C4's own verdict is **WITHHELD** — not confirmed, not
refuted. See the dedicated "C4 — the per-query CPU attribution result" subsection at the end of §8. Two
handoff errata the C3 run fixed: the T-SQL is `MEMORY_OPTIMIZED
TEMPDB_METADATA` (two keywords, not the underscore form), and the feature is **not** Enterprise-only (all editions
since SQL 2019, subject to In-Memory OLTP limits). Config was torn down to the C2 baseline. §8 stays unflipped;
`per_lane` stays off.

**C5 (2026-07-12) ran the one thing C3 left uncharacterized — per-shard *headroom* at N=8, latch-free — and it
CLOSES this phase.** C3's N=8 clear was at a deliberately light **2/shard** probe; its "pinned ceiling" was a
self-declared floor, and the capacity frontier below shows a cleared N=16 still needs **3.62/shard**. C5 drove
the rung: **2/shard PASSes** (100% delivered, drained, stranded 0, slope +1.94) and **3/shard COLLAPSES**
(≈50–52% delivered, ~85k stranded, slope +109/+111, **reproduced 2/2** — and a 3rd time on C6's instrument). So
**`R ∈ [2, 3)`**, and `R < 3 < 3.62`: the requirement is cleared **by inequality**, which is why the higher
3.62 / 5 / 7.23 rungs were correctly never run. **`N`-sizing is insufficient on its own — decisively, not
pending further work.** The verdict is *decisive* rather than *deferred* precisely because the engine box was
upsized to **m7i.4xlarge (16 vCPU)** first: at the collapse the engine sat at `max_core%` ≤ 59.7% and the
load-gen under 8.5%, so the pre-registered "both boxes hot ⇒ inconclusive" carve-out **did not fire** and the
table reads straight. **C5 measures `R`. It does not name the N=8 wall** — and the run that was built to name
it (C6) found nothing to name. Phase 5 is **done**; the answer is DECLINING, and the plan moves to Phases 3–4.

### The capacity frontier — RESOLVED 2026-07-12: the conditional FIRED, and `N`-sizing is dead as a standalone path

> ✅ **RESOLVED (C5, 2026-07-12).** This section's central conditional — *"the sizing path only reopens if a
> shard sustains ≳3.6/s at N=8/16"* — **has been tested, and it fired *against* the sizing path.** C5 measured
> the per-shard ceiling at N=8, latch-free: **`R ∈ [2, 3)`** (2/shard PASSes at 100%; 3/shard collapses,
> reproduced 3× across two instrument sets). **`R < 3 < 3.62` ⇒ a shard does *not* sustain ≳3.6/s ⇒ the sizing
> path does not reopen.** The falsifier at the foot of this section is **discharged, negative**.
>
> Two consequences, and the first contradicts this section's own former heading:
>
> 1. **"Clearing N=16 is *necessary*" is now WRONG.** Clearing N=16 is **moot**, not necessary — even a fully
>    cleared N=16 at the *measured* per-shard ceiling misses 520.83 events/s. The old heading read "clearing
>    N=16 is necessary, and demonstrably not sufficient"; the honest heading is that it is **neither**.
> 2. **The lever this section was written to *price* — a pooled-claim (or whole-dispatcher) rewrite — is not
>    worth building.** C6 then found **no convoy for any such rewrite to remove**, and C7 killed the
>    parallelism-config alternative. **The store-side search is closed.**
>
> Everything below is preserved as **the arithmetic that got us here** — it is why C5 was the right experiment.
> Read it as history. **The live conclusion is "The store-side search is closed" below.**

C1/C2/C3 each answered a *scaling-shape* question. None of them ever stated the *capacity* consequence, and
the arithmetic had never been written down. It is worth writing down, because it changes what a successful
pooled-claim rewrite is worth.

**The sustained ledger.** Gate on `result`, count only arms that fully drained (`drained: true`,
`stranded: 0`). ⚠️ **RAW ≠ PUBLISHABLE.** Phase 5's own **D4 rule** (stated below, and in
`docs/benchmarks/shardcert-ceiling-ladder.md`) is *publish at **≤50%** of the measured ceiling*. **The raw column
is a measurement; the publishable column is the capability claim. Never quote the raw figure as a capability.**

| config | best **sustained** fleet (RAW) | **publishable (D4, ×0.5)** | shape | vs 520.83 (raw) | **vs 520.83 (publishable)** |
|---|---:|---:|---|---:|---:|
| **shipped default** (pooled, `MEMORY_OPTIMIZED TEMPDB_METADATA=OFF`) | 90.0 events/s | **45.0 events/s** | 10 ingress/s, N=4, `dests=8`, 900 s (`redo-pooled-soak10`) | 5.79× short | **11.57× short** |
| **C3 config** (`…TEMPDB_METADATA=ON`, reverted after the run) | 144.0 events/s | **72.0 events/s** | N=8 × 2/shard × (1+8), 900 s (`c3-8`) | 3.62× short | **7.23× short** |
| *any* mode, for the record | ≥252 events/s | **≥126 events/s** | `per_lane`, 16 lanes, 540 s | ≤2.07× short | **≤4.13× short** |

> **The honest capability statement is therefore "72.0 events/s publishable, 7.23× short"** — not "144.0 / 3.62×".
> *(One deliberate exception, and it is safe: the **3.62/shard bar** C5 was tested against is derived the same RAW
> way — but there the direction is conservative, since failing the raw bar implies failing the derated 7.23 bar.
> **C5's inequality verdict is unaffected and must NOT be re-derated.** This D4 note governs the ledger's and any
> ADR's *capability* statements only.)*

The `per_lane` row is **excluded from the shard-scaling story, not from the record**: it ships OFF, it was
measured at 16 lanes and storms the store at the 1,500-lane target, and its run had engine-box CPU at 88.4%
p95 — so the `≥` may be a *bench-box* bound rather than an engine one.

⚠️ **`c2-4`'s 72.0 events/s is NOT the shipped-default ceiling** — it is a pinned 2/shard probe that was
simply offered less than `redo-pooled-soak10` was. Reading it as a capacity number is the same error class
as B8/B10: a run parameter mistaken for a measurement.

**The consequence.** If the pooled-claim rewrite fully cleared N=16 *at the swept probe load*, the fleet
would sit at `16 × 2 × 9 = 288 events/s` — still **1.81× short**. That 288 is a **floor, not a ceiling**:
2/shard is a deliberately light scaling probe and per-shard headroom at N=8/N=16 has **never been
characterized** (C3 never drove N=8 above 16/s; its "pinned ceiling" is a self-declared floor). So the honest
statement is not "a cleared N=16 delivers 288" — it is:

> **Closing the residual 1.81× requires *either* ~3.62 ingress/s per shard at N=16 — a rate *above* the
> 3/shard load that already failed to drain at N=4 on the pooled default — *or* roughly two further
> shard-doublings past a knee that has already collapsed twice ((4,8] pre-C3, (8,16] post-C3). ~~Neither has
> been measured.~~**
>
> ✅ **The first limb HAS now been measured — C5, 2026-07-12 — and it FAILS.** Per-shard headroom at N=8,
> latch-free, is **`R ∈ [2, 3)`**: 3/shard collapses (≈50% delivered, ~85k stranded, reproduced 3×), so the
> **~3.62/shard the residual demands is above a rate that already does not drain.** The second limb (two
> further shard-doublings past a twice-collapsed knee) is not worth measuring: the knee has never survived a
> doubling, and C6 observed **no shared-resource convoy** whose removal could move it. **Both escapes are shut.**

What per-shard headroom *is* characterized, all on the pooled default at N=4: **2.5/shard sustains**
(10 ingress/s, drained); **3/shard fails to drain** (12 ingress/s, `in_pipeline_final` 825, slope +12.17);
and C1's matched-load penalty *worsens* monotonically with per-shard load (1.01× @2/sh → 1.53× @6 → 3.12×
@10; collapse @12) — direction firm, **magnitudes soft** (both C1 soaks collapsed). Every one of those points
says the same thing: the store gets *less* tolerant as you drive a shard harder, so the "raise per-shard load"
escape runs into the wall from the other side.

**Therefore (as this stood on 2026-07-11):** clearing N=16 is **necessary but not sufficient** — and **C4
(below) has now STRENGTHENED this conclusion twice over:** the pooled claim is *not even the N=16 wall's #1 CPU
consumer* (the dispatcher's `list_fifo_lanes` discovery scan is), and a claim-only rewrite would not clear it —
*and* the N=16 wall is ~72% off-CPU WAIT, so "reduce store CPU" may be the wrong lever entirely. Even the
earlier, more optimistic "a CONFIRMED C4 + a successful rewrite would still leave a gap" framing was too
generous: **C4 came back WITHHELD, and the rewrite as previously scoped is now known INSUFFICIENT.** The
rewrite is not a parity plan on its own; it has to be *composed* with the `txn/event` levers (Phase 3) rather
than sequenced ahead of them — and Phase 3 (the just-merged `accepts=` seam, #213) is correspondingly *more*
important now, not less. **Do not read C4 as "the rewrite gets us to 45M/day"** — read it as "the rewrite, even
hypothetically CONFIRMED, was never sufficient, and its target was mis-identified."

> ⚠️ **SUPERSEDED 2026-07-12 — the paragraph above still treats the rewrite as a *component* of the parity
> plan, "composed with" Phase 3. It is not a component. It is off the plan.** C5 killed `N`-sizing as a
> standalone path (`R ∈ [2, 3)`), and C6 observed **no convoy for a rewrite to remove** — no shared-resource
> blocker, claim-scoped or whole-dispatcher. So the `txn/event` levers are **not a co-requisite of a
> store-side rewrite; they are what is left.** Phase 3's `accepts=` seam is **MERGED** (#952/#213,
> ADR 0084); Phase 4 group-commit / batch-fusion is **the only candidate standing — contingent on Phase 0's
> `txn/s` counter, which currently points AGAINST it.** *(Phase 4 must still be justified on its own
> `txn`-per-event arithmetic / ADR 0051 — **C5, C6 and C7 provide zero evidence for group-commit**, and citing
> them in its favour would be exactly the adjacency inference that walked back C2 and C4.)*

*Falsifier (DISCHARGED — NEGATIVE, C5, 2026-07-12):* measure per-shard headroom at N=8 latch-free. If a shard
sustains ≳3.6/s at N=8/16, the sizing path reopens and this section is wrong. **It does not.** C5 measured
`R ∈ [2, 3)`: 2/shard PASSes at 100% delivered; 3/shard collapses, reproduced 3× across two instrument sets.
`R < 3 < 3.62` — **the sizing path stays shut.** This section's *conclusion* survives; its *framing* does not
(clearing N=16 is now **moot**, not "necessary" — see the RESOLVED banner at the top of this section).

### C4 — the per-query CPU attribution result (VERDICT: WITHHELD)

**C4 (2026-07-11) ran the per-query CPU attribution C3 lacked — the "is the N=16 store CPU the pooled claim's
temp-object churn?" question — and the verdict is WITHHELD: not confirmed, not refuted.** It captured
`sys.dm_exec_query_stats` deltas + `sched.store_proc_cpu` per arm (N=4/8/16, 2/shard, same engine commit as
C3), then ran the prereg reconciliation contract. Two independent, compounding failures — either sufficient
on its own — block CONFIRMED:

1. **The blocking reconciliation pre-gate does not robustly clear 70%.** The contract required attributed
   query-CPU to explain ≥70% of the box store-CPU at N=16 before family precedence is authoritative. It
   "passes" at exactly **70.68%** — but only on the idle-diluted prereg denominator (window-mean 84.4%,
   contaminated by snap0=0% / snap1=37% idle-ramp samples the CPU-delta numerator never credits), and only
   via the 4 **collapse-tail** intervals where the box has *dropped off the wall* (92–94% → 82–88%). Every
   sustained / phase-matched / C3-consistent denominator lands at **64.5–69.6%** (the INCONCLUSIVE-INSTRUMENT
   band): plateau(6–20)=64.6%, drop-ramp-only=69.6%, C3-consistent sustained wall (box 92–94%)=64.5%. The
   plateau intervals — the *actual* wall — never exceed 69.1%. With no arm robustly passing, **family
   precedence is not authoritative at any N → CONFIRMED is unreachable.**
2. **Under the ratified family map, CLAIM is not the plurality at N=16.** The **#1 query-CPU consumer is
   `list_fifo_lanes` at 47.46%** (2446 cpu-s) — the pooled `StageDispatcher`'s read-only, clock-driven
   ready-lane **discovery** scan (`sqlserver.py:4378`, `_sweep_loop` backstop). CLAIM (`claim_fifo_heads`, 13
   hashes) is **#2 at 40.33%** (2079 cpu-s). Two families both >40% → **AMBIGUOUS**. The single heaviest hash
   (one `list_fifo_lanes` shape, 45.81%) alone exceeds all 13 CLAIM hashes summed. The metrics-scan rival
   hypothesis is REFUTED (8.60%, distant third).

**The headline for the plan — the mechanism was mis-identified.** The N=16 store-CPU wall's #1 consumer is
the dispatcher's `list_fifo_lanes` discovery scan, **not the claim.** So the previously-leading fix — a
`claim_fifo_heads`-only SQL rewrite — removes 40.33% (2079 cpu-s) but leaves `list_fifo_lanes` (2446 cpu-s,
still #1, faster-growing, an O(pending-rows) DISTINCT+CROSS APPLY scan) standing → **it would NOT clear the
N=16 wall.** Even a *hypothetical* CONFIRMED is a TARGET condition, not sufficiency.

**The deeper reframe — the N=16 wall may be WAIT-bound, not CPU-bound.** Per-claim CPU is a real but
**minority** slice of the wall: ~72% of the ~540 ms N=16 claim wall is **off-CPU lock/latch WAIT**
(`cpu/elapsed=0.28`). So "store CPU is the wall" is itself the wrong frame at N=16 — reducing store CPU
(claim *or* dispatch) may not clear a WAIT-bound wall at all. This subsumes and reframes the §8 store-CPU
narrative: the CPU is real, but it is not most of the ~540 ms.

> **⚠️ Review caveat + resolution** *(independent critique of the C4 handback, 2026-07-11 — code claims verified
> against `origin/main`; **both of its open questions have since been CLOSED**, by the §3d coupling computation
> and by C6, 2026-07-12).* The two plan-shaping claims above were the handback's *weakest*, and it slightly
> over-read its own data. The critique stands; the questions it opened are now answered — do **not** hold them
> open.
>
> - **"A claim-only rewrite would NOT clear the wall" — the review opened this as UNPROVEN, and it STAYS
>   unproven.** *(A previous version of this bullet upgraded it to "PROVEN insufficient" on the strength of the
>   §3d coupling computation. **That upgrade is WITHDRAWN — it does not survive three independent objections.**)*
>   The open question was whether `list_fifo_lanes`' cost is a *backlog collapse EFFECT* (a claim fix that
>   prevents collapse would shrink it too) or **intrinsic**. **The §3d computation** — source
>   `FOLLOWUP_C6_3d-result_2026-07-11.md`, full working in `REVIEW_C6_recapture-corrections_2026-07-11.md` §4,
>   computed **off-line from C4's 3-arm qstats deltas** — reports `list_fifo_lanes` **cpu/read rising 2.06×**
>   N=4→16 (10.3 → 21.3 µs/read), **already at the 100%-delivered N=8 arm** (pre-deep-collapse, no 208k backlog).
>   That is real evidence, and it is the **strongest surviving leg**. But it does **not** prove insufficiency:
>   1. **It isolates the WRONG factor.** Total `list_fifo_lanes` CPU = **reads × cpu/read**. §3d shows the
>      *cpu-per-read* factor rises **2.06×** — but the doc's own numbers say the growth is *"largely
>      deeper-queue-scan driven (**~4.3× reads growth**)"*, and **read count is backlog-coupled**. So §3d
>      establishes intrinsic-ness for the **smaller** factor while the **dominant** one remains exactly the
>      collapse-effect confound it was run to close. A claim fix that prevented collapse **would** shrink the
>      read count, and most of that CPU with it.
>   2. **The family map it argues over is not authoritative.** C4's reconciliation pre-gate **failed**
>      (64.5–69.6% vs a 70% bar) — *"family precedence is not authoritative at any N."* A verdict cannot be
>      *WITHHELD because the attribution is not authoritative* and simultaneously *PROVEN using that attribution.*
>   3. **The rig.** §3d inherits C4's data, and C4's N=16 arm is **16 shards on 8 vCPU** — the configuration this
>      document calls invalid for store scaling.
>   → **Claim-only rewrite: NOT SUPPORTED AS SUFFICIENT (an inference from a non-authoritative family map, with
>   the dominant factor still confounded). NOT "proven insufficient."** The NO-GO can stand on **cost and risk** —
>   it must not stand on a proof word. *Residual, still OPEN:* §3d cannot separate intrinsic per-page cost from
>   collapse-induced **cache-spill at N=16** (a `DISTINCT` over 208k rows could pressure cache). **C6's convoy
>   null does NOT close it** — a per-query spill is *precisely* the non-shared cost the detector is blind to, so
>   it would return this null whether or not a spill exists. *(An earlier version of this bullet claimed "C6
>   independently confirms it does not resolve to spill." **Cut — that is a null-inference over-read of the same
>   class that walked back C2 and C4.**)* The **N=8 pre-collapse rise** is what carries "intrinsic," and it is
>   unaffected by any of this.
> - **The "~72% off-CPU WAIT → the wall may be WAIT-bound" reframe is a COLLAPSE-STATE artifact — and there is
>   no N=16 plateau to read.** A clean lighter-capture recapture (2026-07-11) confirmed **N=16 is
>   plateau-less**: the store sits at 93–94% CPU while the queue grows monotonically (415 → 230,394), with no
>   flat-backlog window. The `cpu/elapsed` **0.93 → 0.70 → 0.28 progression is ACROSS ARMS** (N=4 → N=8 →
>   N=16-collapse), so **0.93 is the *N=4* arm, not an N=16 plateau** (an earlier version of this caveat
>   mis-read it as within-N=16 — corrected). Either way a collapsed arm's elapsed is inflated by backlog, so
>   0.28 describes the **collapsed state**. **Do not re-target the fix from CPU to lock/latch WAIT on the
>   strength of 0.28.** ✅ **C6 then tested the contention reading directly:** its convoy detector observed
>   **no convoy on any arm** (floor met in 0 of 288 samples; largest suspended group 2; max chain depth 1) — so
>   there is **no lock convoy, no shared latch/page convoy, no memory-grant convoy, no spill convoy**. ⚠️ **Say
>   "convoy" every time.** C6 excludes *shared-resource convoys of those classes, at a 10 s snapshot cadence*; it
>   does **not** exclude a per-query spill, a per-query latch-acquisition cost, or per-session grant pressure —
>   those cannot form a convoy and would always return this null. The WAIT-bound reframe is **not supported as a
>   target**; that is weaker than "refuted," and it is what the instrument can carry.
>   *(This answers old §9 open question #1 — see §9.)*
> - **What the review does NOT shake:** the **WITHHELD verdict** (the reconciliation-gate failure alone forces
>   it and is well-argued) and **every code-mechanism claim** — all verified against `origin/main`, no
>   load-bearing mismatch (the handback's line numbers are mirror-relative and stale; its facts are correct).
>   ⚠️ **What this review DID leave standing, and the 2026-07-12 audit does not:** the `list_fifo_lanes > claim`
>   **ordinal** (47.46% vs 40.33%). It was measured on **16 shards on an 8-vCPU engine box** — the configuration
>   this document calls invalid for store scaling — and **per-query CPU shares are exactly what core contention
>   distorts.** The ordinal is **not admissible as-is** and was **never re-run** after the 16-vCPU upsize.
> - **Consequence — the family-map ratification is a RED HERRING for the build decision.** The reconciliation
>   pillar alone forces WITHHELD, and the build turns on *"does fixing the store clear the wall,"* which no fold
>   choice answers. **Do not authorize the whole-`StageDispatcher`-path rewrite** — and, post-C5/C6/C7, **not at
>   all, not merely "not on this handback."** The original text here said *"C6 is designed to settle exactly
>   these two open questions — run it first."* ✅ **C6 RAN (2026-07-12), and it settled ONE of the two:** it
>   observed **no shared-resource convoy** on either contrast, so the *contention* reading is not supported.
>   ⚠️ **It did NOT settle the second** — `list_fifo_lanes`-intrinsic-vs-cache-spill is **still open**, because a
>   per-query spill cannot form a convoy and is invisible to C6's detector by construction. *(An earlier version
>   claimed C6 settled both. Corrected.)* Combined with C5
>   (`N`-sizing insufficient regardless) and C7 (`MAXDOP=1` is *negative*), **the store-side search is closed**
>   and the ratification is a red herring **full stop** — the owner should not spend that decision. The
>   `txn/event` levers are what is left: `accepts=` (MERGED, #952/#213, ADR 0084) + Phase-4
>   group-commit / batch-fusion (**the only candidate standing — contingent on Phase 0's `txn/s` counter**). This
>   is **robust to the still-open CPU-BOUND preclusion**: if
>   the store *is* CPU-bound, the fix is still "fewer store round-trips per event" — the same levers. **Do not
>   re-litigate it before building.**

**What survives cleanly.** CLAIM `cpu_us_per_exec` rises **8.4× monotonically** N=4→16 (826.9 → 6971 µs) and
it is honest query CPU — *not* spin-inflation (`cpu/elapsed` DROPS 0.93→0.70→0.28; the excess is off-CPU
WAIT, not counted in worker_time), *not* an empty-claim storm (`empty_claim_ratio` falls, rows/claim≈1.0).
**But** it is "largely deeper-queue-scan driven (~4.3× reads growth) with a ~2× per-page-cost elevation" —
**not** the "intrinsic per-cycle churn" the hypothesis assumed — and it is a **necessary target condition
only, not sufficiency**, gated by the reconciliation that now fails.

**Apparatus caveat — REFUTED by the clean recapture (2026-07-11).** C4 *appeared* to run heavier than C3 (c4-16
`claim_mean` 93.4 ms vs C3's 55.7 ms, +68%; c4-8 slope 7.48 vs 4.04), and the original hypothesis blamed the
qstats capture worker's in-store DMV scan. **A ~6× lighter recapture (TopRows 5000→800, NOLOCK queue scan
dropped) disproved that:** `claim_mean` did **not** move (heavy 93.4 vs light 92.6 ms), and the light N=8 arm
tipped **worse** (slope 13.0 vs 7.5, stranded 3,175 vs 0); store CPU and the N=16 family split reproduced
heavy↔light to the decimal. So **capture weight does not drive `claim_mean`; the C3↔C4 delta is run-to-run /
C3-vs-C4 drift variance, not the instrument.** Every C4 figure is admissible as load-bearing. (Consequence: the
N=8/2-shard operating point is genuinely **marginal and run-to-run-variable** — slope +4 to +13 — which is why
per-shard headroom at N=8 had to be measured directly rather than inferred. ✅ **C5 did exactly that
(2026-07-12): `R ∈ [2, 3)`** — 2/shard PASSes, 3/shard collapses, reproduced — **vs the 3.62/shard a cleared
N=16 would need ⇒ `N`-sizing is insufficient on its own.** Decisive, not deferred: at the collapse the engine
box was ≤59.7% `max_core%` and the load-gen under 8.5%, both far under the ~85% co-constraint bar, so the
pre-registered carve-out did **not** fire — the engine upsize to m7i.4xlarge is what bought that.)

**OPEN RATIFICATION (owner decision, NOT self-decided).** Does `list_fifo_lanes` count as **CLAIM machinery**
(fold → 87.79% combined, a decisive plurality) or as a **separate DISPATCH family** (keep separate →
AMBIGUOUS)? **Even folding does NOT yield CONFIRMED** — the reconciliation pre-gate fails independently. The
coordinator's **recommendation is to keep them separate → AMBIGUOUS** (rationale: `list_fifo_lanes` is an
independent clock-driven `_sweep_loop` backstop, a pure RCSI read with no locking hints / no OUTPUT / zero
temp objects, is not per-claim triggered — `sweep_now` fires only on reload/resume/recovery — and needs a
*different* fix than the claim batch), **but that is a recommendation, not a decision.** Recorded OPEN in §9.

**Consequence for the plan** *(as recorded 2026-07-11 — superseded on the (1) and (3) limbs; see the banner
below)*. (1) Do **not** build the `claim_fifo_heads`-only rewrite as the sole wall fix — sufficiency analysis
shows it would not clear N=16 (`list_fifo_lanes` remains #1). Re-target CPU reduction to the **pooled
`StageDispatcher` lane-servicing path as a whole** (discovery scan *and* claim batch) — *if* CPU is even the
lever, which the 72%-WAIT reframe puts in doubt. (2) The `txn/event` levers (Phase 3, `accepts=` #213, just
merged) are relatively **more** important now. (3) Ratify the family question and instrument-fix before any
re-run (phase-matched denominator, C3 cross-check, a scan-confound control for `list_fifo_lanes`, a lighter
capture worker).

> ⚠️ **SUPERSEDED 2026-07-12 by C5 + C6 + C7 — do not act on limbs (1) or (3).**
>
> - **(1) is withdrawn.** The re-target — "the pooled `StageDispatcher` lane-servicing path as a whole" — kept a
>   **store-side rewrite as the lever**. It is not one. **C6 observed no convoy on any arm**, so there is no
>   shared-resource blocker for a *wider* rewrite to remove either; **C5** showed that even a fully cleared N=16
>   misses the target at the measured per-shard ceiling; **C7** killed the parallelism-config alternative and
>   showed the lever is *negative*. **Build no store-side rewrite.**
> - **(2) is upgraded.** The `txn/event` levers are not "relatively more important" — they are
>   **the best-supported remaining path.** `accepts=` is **MERGED** (#952/#213, ADR 0084); Phase-4 group-commit /
>   batch-fusion is **the only candidate standing — contingent on Phase 0's `txn/s` counter** (which, on the best
>   available estimate, points *against* it — see Phase 4).
> - **(3) is moot.** Those instrument fixes gated an *attribution re-run*. With the store-side search closed,
>   **no re-run is queued**, and the family ratification it depended on is a **red herring** (it changes no build
>   decision — see the review caveat above). One listed fix was discharged: the "lighter capture worker" premise
>   was **refuted** by the clean recapture. ⚠️ **The scan-confound control is only PARTLY discharged** (§3d
>   answers *intrinsic* for the per-read factor; the dominant backlog-coupled read-count factor stands, and C6
>   cannot see a per-query spill), and **the 8-vCPU rig objection is not discharged at all** — any revived
>   attribution run must be on the **16-vCPU** box.
>
> **Robustness:** this stands even if the CPU-BOUND preclusion (§9 #1) is later overturned — if the store *is*
> CPU-bound, the fix is *still* "fewer store round-trips per event," i.e. **the same levers.**

### The store-side search is CLOSED — C5 + C6 + C7 (2026-07-12)

**Three independent runs, three negative results, one convergent conclusion: no store-side lever reaches
45M/day.** This is the capstone of the C1→C7 arc, and it is a **good** outcome — a negative result is a result.
It retires three tempting dead ends that between them would have consumed months of engine work, and it leaves
exactly one path standing.

| run | question it asked | verdict | what it kills |
|---|---|---|---|
| **C5** | Is per-shard headroom at N=8 latch-free above the ~3.62/s a cleared N=16 needs? | **`N`-SIZING INSUFFICIENT** — `R ∈ [2, 3)` | **more shards** |
| **C6** | Which lock/latch class is the wall? | **AMBIGUOUS-STRUCTURAL** — **no convoy observed**, either contrast | **a contention fix** (no shared-resource blocker to remove) |
| **C7** | Is it self-inflicted intra-query parallelism (`CXSYNC_PORT`)? | **REFUTED as a removable cause** — and `MAXDOP=1` is *worse* | **a parallelism config change** — the lever is **negative** |

**C5 — more shards cannot get there.** The per-shard ceiling at N=8, latch-free, pooled, is **`R ∈ [2, 3)`**:
2/shard PASSes (100.0% delivered, stranded 0, drained, slope +1.94); **3/shard collapses, reproduced 2/2**
(51.93% / 50.01%, ~85k stranded, slope +108.7 / +110.9) — and a **third replicate** on C6's heavier instrument
(`c6-n8x3`: 50.11%). *(Replicate, not independent reproduction: same rig, same commit `98bec81`, same config.)*
`R < 3`, and the target needs **3.62/shard at N=16**, so the requirement is cleared **by
inequality** — which is why the higher 3.62 / 5 / 7.23 rungs were correctly never run (the pre-registered rule
is *stop at the first rung that fails*). **Bridging premise:** applying an N=8 ceiling to an N=16 requirement
assumes per-shard capacity does not *increase* with `N` — established by C1/C2/C3 (it declines). **Decisive, not
deferred:** the engine box was upsized to m7i.4xlarge (16 vCPU) *before* the run, and **the pre-registered
co-constraint bar is 85% `max_core%` — checked against the PEAK, never the mean.** At the **c5-b** collapse the
engine peaked at **max 59.7%** (mean 39.5 / p95 50.5, nearest-rank) with the load-gen at **8.5% peak**; the
other collapse arm, **c5-b2**, peaked at **56.7%** (mean 38.3 / p95 48.9, load-gen 7.4%). Both far under the
bar ⇒ the "both-boxes-hot ⇒ inconclusive" carve-out **did not fire** and the table reads straight. **C5 measures
`R` and names no wall.**

**C6 — no shared-resource blocker to fix.** Both pre-registered contrasts — PRIMARY (N=8@3 FAIL vs
N=8@2 PASS, *same shard count*, the matched control C5 made possible) and SECONDARY (N=16@2 vs the healthy
N=4@2 floor) — return **`convoy_present = false`**. The convoy floor (≥5 sessions suspended on one shared
`resource_description`, **or** a blocking chain ≥2 deep) was met in **0 of 288 samples**; the largest suspended
group anywhere in the run was **2** (once); max chain depth **1**. **So: no lock CONVOY, no shared latch/page
CONVOY, no memory-grant (`RESOURCE_SEMAPHORE`) CONVOY, no spill CONVOY** — plus a tempdb-catalog
VOID (zero `2:1:*` pages in 288 samples — C3's latch fix held). And it supplies **the cleanest proof in the
whole arc that rank names nothing**: `WRITELOG`
is the **#1** wait by `d_resource_ms` on *every* arm — including the healthy, 100%-delivered N=4 floor
(127,962 → 191,348 → 250,947 → 577,773 ms). A wait that is rank-1 when everything is healthy cannot name a wall
when things collapse.

> 🔴 **Do NOT drop the word "convoy," and do not call this a proof.** Two things bound what C6 can carry:
>
> - **CLASS.** C6 excludes **convoys** of those classes. It does **not** exclude a **per-query spill**, a
>   per-query latch-acquisition cost, or per-session grant pressure — a spill's cost is per-query tempdb work,
>   **precisely the non-shared class the detector cannot see**, and it would return this identical null whether or
>   not spills are happening. *(This is why the "C6 confirms `list_fifo_lanes` does not resolve to spill" claim
>   was cut from the C4 caveat above: a null from a blind instrument confirms nothing.)*
> - **DETECTION POWER.** The instrument is **72 point-in-time `dm_os_waiting_tasks` snapshots per arm, at a 10 s
>   cadence, over a 900 s soak** (`interval_s: 10`, `samples_total: 72`). **The minimum convoy duration/duty-cycle
>   it could have detected was never stated.** A convoy that forms and clears inside the sampling interval is
>   invisible to it at essentially any prevalence. **A null from an instrument of unstated sensitivity is "we did
>   not observe one," not "there is none."**
>
> **Therefore: "no convoy was observed at a 10 s snapshot cadence; convoys shorter than the sampling resolution
> are not excluded."** Not *"positively excludes."* Not *"there is none."* Not *"no blocker exists."* The three
> escalations that phrase has been through in this document are the same error the workstream retracted C2 and
> C4 for — pointed in the negative direction.

> ⚠️ **Quote this scope wherever AMBIGUOUS-STRUCTURAL is quoted, or the phrase will harden into "we looked and
> there is nothing there."** The convoy detector is, **by construction, blind to any cost that is not a
> *shared* `resource_description`.** Costs that are **per-session or per-query** — intra-query parallelism
> exchange (each query's exchange is its *own* resource), per-call CPU, allocator churn, scheduler queueing —
> **can never form a convoy** and will *always* return "no convoy," no matter how dominant they are. **A null
> from this instrument is not evidence of absence for that entire class.** AMBIGUOUS-STRUCTURAL is therefore
> consistent with *both* (a) aggregate `txn`/event volume (the reading C5 independently supports) *and* (b)
> self-inflicted per-query overhead the instrument cannot see. **C7 was run precisely to test the leading
> candidate for (b) — and refuted it.**
>
> **C6 also explicitly does NOT upgrade to CPU-BOUND**, despite every temptation (store at 94%, runnable 52 on
> 8 schedulers, `SOS_SCHEDULER_YIELD` in the millions of ms). That is precluded by the offline **64.4%**
> reconciliation — **sourced to `HANDBACK_C4_2026-07-11.md` §0** (N=16 attributed query-CPU over the honest
> plateau denominator, store box = 93.3%), relayed in `REVIEW_C6_recapture-corrections_2026-07-11.md` §4.
> **It is prose-only: no JSON artifact computes it, and no C6 artifact backs it — do not cite C6 for it.**
> *(It is the same reconciliation quantity as the §3 C4 row's 64.5–69.6% band, at a slightly different
> denominator: 64.4% on the plateau box = 93.3%; 64.6% on the server-side `qstats_agg` plateau(6–20); 64.5% on
> the C3-consistent sustained wall. All land in the **INCONCLUSIVE-INSTRUMENT** band, all below the 70% gate.)*
> Recorded as **context, not verdict**. **Do not quote C6 as having established a CPU-bound store.** It records
> the **absence of an observed convoy**, and nothing more.

**C7 — not a parallelism config default either, and the lever is *negative*.** C6's #2 real wait at N=16 was
`CXSYNC_PORT`, growing **34×** across the ladder (10,782 → 366,796 ms `d_resource_ms`) — exactly the kind of
per-query cost C6's detector is blind to, and a tempting "self-inflicted parallelism overhead" story. C7 tested
it with a pre-registered A/B rather than by staring at the table. **Manipulation check passed**
(`CXSYNC_PORT` 135,361 ms → **≤ 90 ms** under `MAXDOP=1`, ~75× below the <5% bar of 6,768 ms — *cite the
**bound**: 90 ms is the top-15 floor in `c6_convoy_c7-dop1.json`, from which `CXSYNC_PORT` is simply absent. The
handback's "exactly zero" is an over-read the artifact does not carry*).
**Same-session drift control passed** (C7-base reproduced the 3-run N=8@3 baseline: 49.44%, slope +115.1).
**And `MAXDOP=1` made it WORSE on both pre-registered limbs** — delivered **49.44% → 20.63%** (below the <45%
trigger) *and* slope **+115.1 → +154.7** (past the >+125 trigger). It also **degraded the N=8@2 rung** to
**75.73%, not drained, 28,106 stranded, slope +38.4** — see the harm-check caveat below.
So parallelism is **not a removable cause — it is load-bearing**, and `MAXDOP=1` is not merely absent as a lever
but **NEGATIVE: do not adopt it.** This is the **first hypothesis on this workstream caught by a pre-registered
falsifier *before* publication** rather than after (C2 retracted, C4 WITHHELD, C7 refuted-by-experiment).

> ⚠️ **What C7 does NOT license — and the trap it very nearly walked into itself.**
>
> - **`CXSYNC_PORT`'s 34× growth: do NOT name it a "collapse EFFECT."** C7 establishes exactly one thing —
>   removing intra-query parallelism removes `CXSYNC_PORT` **and makes the collapse worse**, therefore
>   `CXSYNC_PORT` is **not a removable cause**. It establishes **nothing** about what *causes* the growth: **no
>   healthy-but-high-load `CXSYNC_PORT` control was run.** Indeed the better reading is three words away — *if
>   parallelism is load-bearing, `CXSYNC_PORT` waits are the **price of useful parallel work** and scale with it*,
>   which is neither a cause nor a collapse effect. **Refuting a cause does not license substituting an effect.**
>   *(An earlier version of this section did exactly that, in a paragraph congratulating itself for catching that
>   trap. Withdrawn.)*
> - **The harm-check is directional, not proven.** `MAXDOP=1` degraded N=8@2 to 75.73% / not drained / 28,106
>   stranded / slope +38.4 — but **the default-config baseline for that rung is itself run-to-run variable**
>   (C6 `n8x2`: 100% / drained / 0 stranded / slope +4.3; the C4 recapture: **3,175 stranded**, slope +13). The
>   comparison is **cross-session with no same-session control**. The magnitude — ~9× the worst baseline strand,
>   ~3× outside the +4..+13 slope band — makes the **direction credible**, not proven. State it that way.
> - **Scope: N=8 only. The N=16 arm was NOT run.** *(The reason previously given — "N=16's delivered% is too
>   irreproducible to A/B, 9.4% at C3/C4 vs 26.2% at C6" — is **WITHDRAWN as false.** C3's N=16 delivered
>   **27.95%** (`c3-16.json`) and C6's **26.16%** (`c6-n16x2.json`) — **agreement within 1.8 points.** The 9.4%
>   is **C4's N=16 arm alone**, prose-only, no artifact — and C4 is the arm that ran **16 shards on 8 vCPU**. On
>   the two arms that have artifacts, **N=16 reproduces fine**, so the "too irreproducible" excuse dissolves.
>   **The N=16 C7 arm is testable; it was simply not run.** If the scope limit is to be kept, keep it on that
>   honest ground.)*

#### The convergent conclusion

**Neither more shards, nor a contention fix, nor a single-query CPU rewrite, nor a parallelism config change
reaches 45M/day.** The wall at N=8/N=16 remains **UNNAMED** — and naming it is **no longer on the critical
path**, because *the fix does not depend on the name.* **Four** store-side escapes have been tested and shut:

- a **claim-only** rewrite — **not supported as sufficient** (C4 + the §3d coupling computation — an inference
  from a family map whose own reconciliation gate failed, measured on an 8-vCPU box at N=16; **not a proof**);
- a **whole-dispatcher** rewrite — **no shared-resource convoy to remove** (C6: none observed on any arm);
- **more shards** — **cannot reach the required per-shard rate** (C5: `R ∈ [2, 3)` < 3.62);
- a **parallelism config** — **negative** (C7: `MAXDOP=1` is worse, and degrades a rung that passes by default).

> 🔴 **This is elimination, and the candidate set was never shown to be EXHAUSTIVE.** "What is left standing" is
> only a valid inference over a partitioned space, and this space is not partitioned. **Four levers were tested.
> Whole classes were not:** per-call store CPU, **per-query spill**, allocator churn, scheduler queueing (C6's own
> scope caveat names these as invisible to its detector — C7 tested only *one* of them, intra-query parallelism),
> **network RTT** to a remote store, and **everything engine-side** — §4's honest caveat still stands, *"per-process
> engine CPU read a constant `0.00` … the attribution is rigorous store-side and **blind engine-side**."*
> **"Last man standing" is not a mechanism.**

**The `txn/event` levers are the best-supported REMAINING candidate — not the only conceivable one, and not a
measured cause:**

1. **Phase 3 — the `accepts=` seam. MERGED** (#952 / BACKLOG #213, ADR 0084). Declined handlers cost 0
   transactions instead of 2; ADT `txn/msg` 51 → 19 (2.68×).
2. **Phase 4 — group-commit / batch-fusion. The only candidate standing — and CONTINGENT on Phase 0's `txn/s`
   counter, whose best current estimate (~350 txn/s vs a ~27k c/s ceiling) *satisfies Phase 4's own falsifier*,
   i.e. points AGAINST it. Measure before funding.**

> **Robustness — why the build should NOT wait on the one dispute still open.** The remaining live disagreement
> is the **CPU-BOUND preclusion** (the unratified offline 64.4% reconciliation; §9 #1). **The recommendation
> survives it either way.** If the store *is* CPU-bound, the fix is still *"fewer store round-trips per
> event"* — which is **still the `txn/event` levers**. Re-litigating the preclusion changes the *explanation*,
> not the *build*. **Do not sequence the build behind it.**
>
> **The one honest limit on this recommendation:** *"we measured no convoy"* is **not** *"aggregate `txn` volume
> causes the collapse."* No causal mechanism has been established. The `txn/event` recommendation is an
> **inference from C5 + C6 + C7 jointly, plus the robustness argument above** — not a measured mechanism. It is
> the best-supported path standing, and it is the only one standing; it is not a proven cause. **Say it that
> way.** *(Likewise: Phase 4 group-commit must be justified on its **own** `txn`-per-event arithmetic / ADR
> 0051. C5/C6/C7 provide **zero** evidence for group-commit specifically, and citing them in its favour would
> be exactly the adjacency inference that walked back C2 and C4.)*

### Rig sizing — do the AWS boxes need to grow?

**Short answer: not yet. The engine box becomes the constraint at roughly the next frontier (~28 ingress
msg/s), and the parity certification needs a deliberate, temporary upsizing — in both directions: more CPU,
and a *slower*, spec-honest disk.**

**What the rig is** (all Windows, us-east-2). ⚠️ **The engine box CHANGED mid-arc — normalize every engine-CPU
figure against the right one:**

| box | instance | vCPU / RAM | spec calls for |
|---|---|---|---|
| engine — **runs through C4** (≤ 2026-07-11) | m7i.2xlarge | **8** / 32 GiB | **20-core** app server, 48 GB |
| engine — **C5 / C6 / C7** (2026-07-12) | **m7i.4xlarge** | **16** / 64 GiB | as above |
| SQL Server (**unchanged throughout**) | i4i.2xlarge (local NVMe) | 8 / 64 GiB | **16-core / 128 GB**, disk qualified at **9,200 IOPS / 3.5 ms** |
| load-gen | m7i.2xlarge | 8 / 32 GiB | n/a |

> **Sourced:** `cpu_soak.csv` header records `engine cores=8` on the C3 arms and `engine cores=16` on all ten
> C5/C6/C7 arms; the C6 handback states it outright (*"Engine box = m7i.4xlarge (16 vCPU) — **CHANGED from C4's
> m7i.2xlarge**"*). The store box is confirmed unchanged by `n_sched = 8` in all seven convoy JSONs.
>
> 🔴 **Consequence — C4's N=16 arm is not a valid store-scaling measurement.** The Phase-5 row below states the
> rule: *"16 shards on 8 vCPU measures core contention, not store scaling."* **C4 ran N=16 on the 8-vCPU box.**
> Its per-query CPU shares (`list_fifo_lanes` 47.46% vs CLAIM 40.33%, `cpu/elapsed = 0.28`, the ~540 ms claim
> wall) are **exactly the quantity core contention distorts.** C6 re-ran N=16@2 post-upsize and reproduced the
> **collapse** (26.2% vs C3's 27.9%) — which rescues *C3's* verdict — but **the CPU attribution was never re-run
> on the 16-vCPU box.** Every C4-derived number in this document carries that caveat, and no NO-GO may rest on
> it unqualified.
>
> Anyone normalizing C5's `max_core%` (mean 39.5 / p95 50.5 / max 59.7 at c5-b) must divide by **16**, not 8 —
> mis-scaling it is what would turn C5's *decisive* verdict back into a *deferred* one.

**What the telemetry says** (whole-box counters; these are valid — it is only the *per-PID* collector that
reads 0.00):

| run | engine box CPU (mean / p95 / max) | reading |
|---|---|---|
| `per_lane` 28/s **SUSTAINED** (540 s) | 38.5% / **88.4% / 91.9%** | **near saturation** — the 8-vCPU engine box is the next wall |
| `pooled` 16/s **COLLAPSED** | 17.1% / 23.1% / 26.3% | collapse happened with the engine box *idle* — **the wall is store-side, not compute** *(this cell formerly read "the wall was the claim query"; that attribution is **withdrawn** — C4 demoted the claim to #2, C6 found no convoy. The **measurement** — engine idle at collapse — is unaffected and is the point.)* |
| load-gen during the sustained run | 1.3% / 2.8% / 5.6% | grossly oversized; never a constraint |

Two conclusions fall out immediately. The pooled claim wall is **not** a box-size problem — buying CPU for
the current default would change nothing. And the `per_lane` "≥28/s, ceiling never found" figure is suspect
in a new way: **the ceiling that was approaching may have been the bench box, not the engine design.**

**Phase-by-phase:**

| phase | current rig adequate? | note |
|---|---|---|
| 0 (yardstick, counters) | yes | no rig at all |
| 1 (claim-mode lane sweep) | yes | pooled arm runs cold; per_lane arm failing at high lane counts is the *finding*, not a rig artifact — but record whole-box CPU so an engine-side ceiling is not misread as a store-side one |
| 2 (production shape `H=20, N=4`) | **watch it** | 2.5× the transform work per message; if engine p95 CPU exceeds ~80%, upsize before trusting the number |
| 3 (cut `2H`) | yes | measured at the same shapes as Phase 2 |
| 5 (shard curve `N = 1…16`) | ~~**no**~~ → **DONE; upsize was made and used** | 16 shards on 8 vCPU measures core contention, not store scaling. **The engine box WAS upsized to m7i.4xlarge (16 vCPU) for C5/C6/C7 (2026-07-12)** — and that upsize is exactly what makes C5's verdict *decisive* rather than *deferred*: with the engine cool at the collapse (`max_core%` ≤ 59.7%), the co-constraint carve-out could not fire. **Phase 5 is closed (DECLINING; `R ∈ [2, 3)`) — no further shard-curve runs are planned, so the m7i.8xlarge N=16 upsize is NOT needed.** |
| parity certification | **no — twice over** | see below |

**The goal is NOT to replicate the incumbent's hardware** *(owner ruling, 2026-07-10: "I don't care about
exactly matching Corepoint's system req. What I care about is having a setup that will match the 45M/day
across 1500 interfaces.")* So: our stack, our disks — the i4i NVMe stays, no throttled-disk rider. The one
honesty obligation that survives is to **publish the disk assumption** alongside any capacity number, since
NVMe is far faster than the SAN-class storage many adopters run.

**What the 45M/day-across-1,500-connections demo load actually is** (at the measured estate mix — 17% of
events hub-shaped `H=20, N=4`, the rest simple `H=1, N=1`):

| | value | against measured capacity |
|---|---:|---|
| total events | **520.8/s** | — |
| ingress | 233.9/s (17.7 hub + 216.1 simple) | — |
| deliveries | 287.0/s | — |
| **committed txn** | **~2,416/s** | **9%** of the store's measured ~27k commits/s ceiling |
| per connection | 0.347 events/s | ~1/20th of even the `H=20` lane ceiling |

**Engine compute, bounded by the two measured efficiencies:** the `per_lane` sustained run delivered
**~82 events/s per vCPU** (252 events/s on 38.5% of 8 vCPU). At that efficiency, 520.8 events/s needs
**~6.4 vCPU** — the *current* 8-vCPU engine box is borderline-sufficient, and an **m7i.4xlarge
(16 vCPU / 64 GiB)** carries it with 2.5× margin plus the RAM for 1,500 sockets and ~8–23 shard processes.
At today's *pooled* per-shard rate (22.5 events/s, bound by a **store-side wall at ~17% engine CPU** — the
engine is idling against the store), the same target would need ~23 shards. **No box size helps** — and, since
C5, **no shard count helps either**: per-shard headroom at N=8 latch-free is `R ∈ [2, 3)`, so "~23 shards" was
never an available configuration. *(This line formerly read "claim-wall-bound" and "idling against the store's
**claim query**" — that attribution is **withdrawn**: C4 demoted the claim to #2 and C6 found no convoy. The
engine idles against a store-side wall that is **unnamed**. The *measurement* — engine at 17%, store binding —
is unaffected.)*

**So the deciding variable for the 45M/1,500 demo is not EC2 — it is:**

1. ~~**The claim-path fix at scale** (Phase 1's lane-count sweep + the tempdb rewrite).~~ **WITHDRAWN
   (2026-07-12).** There is no claim-path fix worth making: a claim-only rewrite is **not supported as
   sufficient** (C4 + §3d — an inference from a non-authoritative family map measured on an 8-vCPU box, **not a
   proof**), a wider dispatcher rewrite has **no observed convoy to remove** (C6), and shards cannot make up the
   difference anyway (C5: `R ∈ [2, 3)` < 3.62). **The deciding variable is now the `txn/event` levers** —
   Phase 3 `accepts=` (MERGED, #952/#213) and Phase 4 group-commit / batch-fusion. They move the answer by
   cutting transactions *per event*, which is the **best-supported remaining** axis. See "The store-side search
   is closed".
2. **A harness that can drive 1,500 connections with traffic.** Today's instruments each cover half:
   `connscale` proved the 1,500-lane *idle* claim storm (ADR 0066); `shardcert` drives *traffic* over
   4 shards × 8 destinations. Neither runs the demo shape — ~1,500 connections at 0.35 events/s each with
   the estate's 72%-simple / hub mix. **Building that mode is the actual investment**, and it is harness
   code, not hardware.
3. Boxes are elastic and per-campaign: start the demo attempt on **m7i.4xlarge / i4i.2xlarge** (the store
   sits at 9% of its commit ceiling), and let the measured CPU/claim telemetry — not the spec sheet —
   justify anything larger.

**Why a second engine box is NOT the answer** *(correction — an earlier draft suggested it as the "more
representative" option; that was wrong).* In the shipped architecture a second box can only be the **passive
node of the active-passive HA pair**: exactly one node — the leader — runs the graph, every other node is a
warm standby (`docs/CLUSTERING.md`), and **active-active scale-out was dropped 2026-06-18 with its code
removed** (per-lane ownership, `renew_leases`, the `lane_leases` table). Engine sharding (ADR 0037) is a
**supervisor spawning N `serve --shard` subprocesses on the box it runs on** — single-box by construction.
So a second box contributes zero capacity: it would idle at ~0% CPU while box one saturates, and any
"two-box shard split" the bench harness could contrive (harness-spawned shards, no HA gate) would certify a
topology **no adopter can run**. Note the symmetry: the incumbent's Assured Availability is likewise
primary/backup, so its 45M/day spec is *also* one active app server — **parity is one-active-box vs
one-active-box, and the single-bigger-box test is the correct shape, not a compromise.** (A two-box bench
split retains exactly one legitimate use: as a *diagnostic control* if the big-box run is ambiguous —
holding N constant while halving per-box CPU pressure separates a store droop from a box-CPU droop. Bench
plumbing only; do not publish numbers from it.) The capacity story for an adopter is therefore: the passive
box is the HA cost, not a throughput resource — sizing statements must say "N shards on the **active** node."

**Cost and operational notes.** These are per-campaign hours, not standing upgrades — the boxes are only up
during runs. Indicative on-demand rates scale roughly linearly with size (a 4xlarge ≈ 2× the current hourly
cost, an 8xlarge ≈ 4×; verify current pricing before the campaign). Two cautions: **resizing the i4i wipes
its instance-store data drive** (stop/start loses `D:`; the SQL rebuild is a ~15-minute runbook step, but
plan it), and **fix the per-PID CPU collector first** — on a bigger box with more processes, whole-box
percentages alone cannot attribute anything.

### Do not do

| lever | status | why |
|---|---|---|
| Free-threaded CPython (ADR 0053) | **NO-GO** | measured below the bar |
| Executor-round-trip fusion (ADR 0071 B5) | **NO-GO** | < 10% bar; ~107 msg/s ceiling |
| Database-tier sharding (ADR 0039) | **shelved** | the unified store wins (ADR 0063) |
| Language rewrite | **rejected** | guts the code-first-Python differentiator; re-proves the whole core |
| Raising `--drain-timeout` past ~300 s | **re-arms B7** | |
| Quoting any pre-2026-07-10 collapse magnitude | **B6-contaminated** | verdicts stand; magnitudes do not |
| **Store `MAXDOP=1`, DB-scoped, at N=8 on this workload** | **NO-GO — actively harmful** | **C7:** made the N=8@3 collapse *worse* (49.4% → 20.6% delivered, slope +115 → +155) **and degraded the N=8@2 rung** (75.7% / not-drained / 28,106 stranded, against a variable default baseline of 0–3,175 stranded). Parallelism is **load-bearing**. ⚠️ **Scope — C7 refutes `MAXDOP=1`, NOT the parallelism-tuning class.** Intermediate settings (**MAXDOP=2/4**), **cost-threshold-for-parallelism** tuning, and query-level hints are **UNTESTED** — and the finding *"parallelism is load-bearing"* is what makes MAXDOP=2 a **live** hypothesis, not a dead one. Do not extend this row to them. |
| **A pooled-claim SQL rewrite** (`claim_fifo_heads` tempdb table-vars) | **NO-GO — not supported as sufficient** *(cost/risk, NOT a proof)* | **C4 + §3d:** claim reported as the **#2** N=16 CPU consumer (40.33%, behind `list_fifo_lanes` at 47.46%), with `list_fifo_lanes`' **cpu/read** rising 2.06× already at the 100%-delivered N=8 arm. ⚠️ **This is an inference, not a proof, and "PROVEN insufficient" is WITHDRAWN:** C4's own reconciliation gate **failed** (*"family precedence is not authoritative at any N"*), §3d isolates only the **per-read** factor while the **dominant 4.3× read-count growth stays backlog-coupled**, C4 handed back **no artifact**, and its N=16 arm ran **16 shards on 8 vCPU**. The NO-GO stands on **cost and risk**; it must not be quoted as proof. |
| **A whole-`StageDispatcher` lane-path rewrite** (discovery scan + claim batch) | **NO-GO — no convoy to remove** | **C6:** **no convoy observed** on any arm (floor met 0/288 samples; largest suspended group 2; max chain depth 1). **No lock CONVOY, no shared latch/page CONVOY, no memory-grant CONVOY, no spill CONVOY.** ⚠️ Keep the word **convoy**: the detector is blind to per-query spill / per-call CPU / scheduler queueing, and samples at a 10 s cadence — **"no shared-resource blocker was observed"**, not "none exists." |
| **Buying the target with more engine shards** (`N`-sizing) | **NO-GO — measured shut** | **C5:** per-shard ceiling at N=8 latch-free is `R ∈ [2, 3)` — 3/shard collapses (reproduced 3×) — **below the 3.62/shard** a cleared N=16 needs. Even a fully cleared N=16 misses 520.83 events/s. |
| **Quoting `ceiling.sustained_events_per_s` from a COLLAPSED arm** | **NEVER** | The field is **populated even on a 20%-delivered arm.** In C5, C6 **and** C7, every collapsed arm serializes a plausible-looking ceiling — **several of them ABOVE the fleet's true best sustained figure (144.0 raw / 72.0 publishable).** **The values are deliberately not reproduced here**: printing them is how they get transcribed. Gate on **`result`**, never `exit_code` — **every collapsed arm serializes `exit_code = 0`.** |

---

## 9. Open questions, ranked

> **Read this first (2026-07-12).** C5 + C6 + C7 **closed the store-side search** (§8). The four questions that
> topped this list on 2026-07-11 were all *store-side attribution* questions — **three are now answered and one
> is moot.** They have moved to the Answered block below. Critically, **the two that remain genuinely open are
> now LOWER-STAKES than they were**, because *the build no longer depends on either of them*: the `txn/event`
> levers are the recommendation whichever way both resolve (§8, "Robustness"). **Do not sequence the build
> behind them.**

1. **Is the store CPU-BOUND — and is the offline 64.4% reconciliation sound?** *(Still genuinely open; the one
   live dispute in the arc.)* C6 refused to upgrade its finding to CPU-BOUND despite every temptation (store at
   94%, runnable 52 on 8 schedulers, `SOS_SCHEDULER_YIELD` in the millions of ms), because CPU-BOUND is
   **precluded by an offline 64.4% reconciliation**. **Sourced** (2026-07-12) to **`HANDBACK_C4_2026-07-11.md`
   §0** — N=16 attributed query-CPU over the honest plateau denominator (store box = 93.3%) — and relayed in
   `REVIEW_C6_recapture-corrections_2026-07-11.md` §4. It is the **same reconciliation quantity** as the §3 C4
   row's 64.5–69.6% band at a slightly different denominator (64.4% plateau-box; 64.6% server-side `qstats_agg`
   plateau(6–20); 64.5% C3-consistent sustained wall) — **all below the 70% gate.** ⚠️ **But it is prose-only:
   no JSON artifact computes it, no C6 artifact backs it (do NOT cite C6 for it), and it is unratified** — an
   unaudited figure carrying a load-bearing preclusion. So the store's CPU status is formally
   unresolved. ⚠️ **Lower-stakes than it looks, and it must not gate the build:** if the store *is* CPU-bound,
   the fix is *still* "fewer store round-trips per event" — **the same `txn/event` levers**. Resolving it
   changes the *explanation*, not the *build*.
2. **What actually IS the N=8 / N=16 wall?** *(UNNAMED — and, for the first time in this arc, that is an
   acceptable state.)* C6's convoy detector was built to name it and **observed no convoy to name**: no lock
   **convoy**, no shared latch/page **convoy**, no memory-grant **convoy**, no spill **convoy** (floor met in 0
   of 288 samples). C7 then refuted one leading *per-query* candidate the detector was blind to (intra-query
   parallelism) — **one of several.** ⚠️ **Remember the detector's two blind spots:** **(class)** it cannot see
   any cost that is not a *shared* resource — per-call CPU, **per-query spill**, allocator churn, scheduler
   queueing can never form a convoy; **(time)** it is 72 point-in-time snapshots per arm at a **10 s cadence**,
   so a convoy shorter than that interval is not excluded. **"No convoy observed" is not "there is no convoy,"
   and neither is "nothing is there."** The honest state is **UNNAMED**, not *nonexistent*. **Off the critical
   path:** the fix does not depend on the name (§8). Worth naming eventually for the engineering record;
   **not** worth blocking Phase 4 on.
3. **Does `list_fifo_lanes` count as CLAIM machinery or a separate DISPATCH family?** *(C4 OPEN RATIFICATION,
   owner decision — still formally unratified, now a **RED HERRING**.)* **Separate** (the coordinator's
   recommendation) → two families >40% → **AMBIGUOUS**. **Folded** → 87.79% combined plurality. **Neither
   yields CONFIRMED** (the reconciliation pre-gate fails independently), and — the point — **no fold choice
   changes a build decision.** The rewrite it would have scoped is **not being built** (C4 + §3d: claim-only
   insufficient; C6: no blocker for a wider one). **Recommendation to the owner: do not spend this decision.**
   Recorded OPEN for the record only.
4. **What is `per_lane`'s real ceiling** at a 900 s hold on the fixed harness? *(Unchanged, and now the most
   valuable *remaining* rig question — though still not on the critical path: `per_lane` ships OFF and storms
   the store at the 1,500-lane target.)*
5. **What does `fifo_claim_batch > 1` contribute to the *shard wall*** (as opposed to the cost model, where it
   is settled)? It cannot batch the outbound claim (hard-1), but it can cut INGRESS/ROUTED claim-*call* count.
   **Unmeasurable today: the `claim_phase_soak` telemetry is outbound-only.** Needs a per-stage claim-call rate
   (#227). *(Note the framing has shifted: the old rationale — "and the tempdb catalog latch is store-wide" —
   is dead. C3 removed that latch, and C6 found no convoy of any kind. This is now a **`txn`/event** question,
   which is the axis that matters.)*
6. **What is the realistic HL7 fan-out** for a target deployment? It selects which bottleneck you measure —
   `dests=8` is outbound-heavy (89% of events); `dests=1..2` shifts the load onto the ACK-serialized inbound
   commit.

*(**ANSWERED 2026-07-12 — old #5, "is per-shard headroom at N=8 latch-free above ~3.6 ingress/s?"**: **NO.**
C5 measured the per-shard ceiling at **`R ∈ [2, 3)`** — 2/shard PASSes at 100%; 3/shard collapses, reproduced
3× across two instrument sets. `R < 3 < 3.62`, so **the sizing path does not reopen and `N`-sizing is
insufficient on its own.** This was the *falsifier for the capacity frontier*; it is **discharged, negative**.
Decisive rather than deferred: the engine box was upsized to m7i.4xlarge first, and sat at ≤59.7% `max_core%`
at the collapse with the load-gen under 8.5% — the co-constraint carve-out did not fire.)*

*(**ANSWERED 2026-07-12 — old #1, "is the N=16 wall CPU-bound or WAIT-bound?"**: **it is not an observed
contention wall.** C6's convoy detector observed **no convoy on either pre-registered contrast**
(`convoy_present = false` on all four arms; the ≥5-sessions-on-one-shared-resource floor met in **0 of 288
samples**; largest suspended group 2; max chain depth 1) → **AMBIGUOUS-STRUCTURAL**. It excludes a lock
**convoy**, a shared latch/page **convoy**, a memory-grant **convoy** and a spill **convoy** — *at a 10 s
snapshot cadence, and it cannot see any non-shared cost at all.* The "~72% off-CPU WAIT" reframe that motivated
this question is a **collapse-state artifact** — the `cpu/elapsed` 0.93 → 0.70 → 0.28 progression is
**across arms** (N=4 → N=8 → N=16-collapse), not within an N=16 plateau, and N=16 is **plateau-less** *(and it
was measured on the 8-vCPU box, at 16 shards)*. **Do not re-target the fix to lock/latch WAIT.** ⚠️ C6 also
**explicitly refused to upgrade to CPU-BOUND** — that residual is now §9 #1. See "The store-side search is
closed" in §8.)*

*(**ANSWERED 2026-07-12 — old #4, "does *any* rewrite of the pooled `StageDispatcher` lane-servicing path clear
N=16 — and is `N`-sizing viable at all?"**: **`N`-sizing is NOT viable (C5), and NO rewrite is worth building.**
The claim-only rewrite is **not supported as sufficient** — an inference (§3d coupling: `list_fifo_lanes`
cpu/read rises **2.06×** N=4→16 and **already rises at the 100%-delivered N=8 arm**), **not a proof**: C4's
reconciliation gate failed, §3d leaves the dominant backlog-coupled read-count factor confounded, and the data
came from a 16-shards-on-8-vCPU arm. *(The former "**insufficient — proven**" is **WITHDRAWN**.)* The *wider*
dispatcher rewrite has **no observed convoy to remove** (C6). And C7 refuted one remaining per-query candidate
(`MAXDOP=1` made it **worse** and degraded a rung that passes by default — parallelism is **load-bearing**).
**The store-side search is CLOSED** on those four levers; the `txn/event` levers are the best-supported
remaining path — **an elimination over a non-exhaustive set, not a measured mechanism.**)*

*(**MOOT 2026-07-12 — old #3, "what instrument fixes are needed before any attribution re-run?"**: **no
attribution re-run is queued**, so the question no longer gates anything. Item (d) — "re-capture with a lighter
qstats worker because C4 ran ~68% heavier under a perturbed regime" — is **REFUTED and dropped**: the clean ~6×
lighter recapture left `claim_mean` **unmoved** (93.4 → 92.6 ms), so the C3↔C4 delta is run-to-run/drift
variance, **not** the instrument. ⚠️ **Item (c), the scan-confound control for `list_fifo_lanes`, is only
PARTLY discharged** — §3d answers *intrinsic* for the **per-read** factor, but the **dominant 4.3× read-count**
factor is still backlog-coupled, and **C6 does NOT close the N=16 intrinsic-vs-cache-spill split** (its detector
is blind to a per-query spill by construction — see §8). ⚠️ **And the C4 rig caveat is NOT discharged by any of
this:** C4's N=16 arm ran **16 shards on 8 vCPU**, which the rig table calls invalid for store scaling, and C4
handed back **no artifact**. **"Every C4 number is admissible" is WITHDRAWN** — the *apparatus-weight* objection
is refuted, but the *rig* and *provenance* objections stand. Should an attribution run ever be revived, it must
be on the **16-vCPU** box, and items (a)/(b) survive as instrument hygiene.)*

*(Answered 2026-07-11 — the old "is the N=16 store-CPU the pooled claim's temp-object churn?" attribution
question: **C4 verdict WITHHELD** — not confirmed, not refuted. The #1 N=16 query-CPU consumer is the
dispatcher's `list_fifo_lanes` discovery scan (47.46%), **not** the claim (#2, 40.33%); the reconciliation
pre-gate does not robustly clear 70%; and the wall is ~72% off-CPU WAIT. The claim-only rewrite is INSUFFICIENT.
This "answered" only closes "is it the claim?" — it opened three NEW questions, **all of which C5/C6/C7 have
since answered or mooted (above)**. See the "C4 — the per-query CPU attribution result" subsection in §8.)*

*(Resolved 2026-07-10: the claim is a **flat** 520.83 events/s sustained, not a peak-honoured figure. The
estate's own 2.28–2.89× diurnal peaking in §6 characterises the estate, not the target.)*

*(Resolved 2026-07-11 — old #3, "does a batched ROUTED claim also batch the handoff commit?": **the claim
only**, and the question was posed backwards — `2H → H+1` **is** the claim-only figure, so §7's 13.6 msg/s
lane ceiling was never conditional on it. See §8 Phase 3(2) for the resolution, the `K ≥ H` correction, and
the OUTBOUND hard-1 clamp that keeps it out of the shard-wall story.)*

*(Resolved 2026-07-11 — old #4, "is a GIL-bound core co-binding?": the per-PID `0.00` was diagnosed and fixed
in **#861** (A3). There is no in-harness per-PID sampler in shardcert at all — it only advertises `node_pids`
for an external capture; the connscale `FdSampler` now degrades a flat counter to `None` rather than
rendering `0.00`, and re-walks the subtree so a sharded engine's children are seen. `max_core%` remains the
validated substitute for shardcert runs, and it already excluded a GIL-pegged thread at C2/C3 (≤43%). The
residual is **#220** — differencing subtree CPU sums taken over *different* process sets is not a delta.)*
