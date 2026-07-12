# Throughput: where we stand, and the path to 45M messages/day

**Date:** 2026-07-10 · **Code assessed:** `origin/main` @ `aba035f` · **Method:** multi-agent audit of every
ADR, commit, bench artifact and rig handback, with each measurement adversarially verified and validity-tagged
(26 trustworthy · 9 contaminated · 1 memory-only).

> **This document supersedes the throughput narrative that preceded it.** Several widely-quoted numbers are
> retracted below, including the claim that the engine misses its target by ~52×.

---

## 1. The short answer

**The goal counts every message the engine handles — inbound *and* outbound.** `45,000,000 / 86,400 =`
**520.83 total message events/s**. The harness constant does not implement this (see B10), which has inflated
every published gap figure by a factor of `1 + dests`.

**The engine's binding wall is not CPU, not the store's commit bandwidth, and not `mark_done`.** It is the
**pooled outbound claim query's tempdb-metadata churn**: `claim_mean` **33.6 ms** returning ~1 row, and it is
a *runaway* — 12 → 20 → 33 → 43 → **127 ms** as load rises. The `per_lane` claim mode avoids that machinery
entirely and is **4.5× cheaper per delivered row**. It ships **off by default**.

**The plan is therefore measurement-led, not lever-led.** Three of the four independent plan proposals were
scored by three independent judges; all three judges picked *measure first*. The single most valuable
experiment — does per-shard throughput stay flat as shard count grows? — **has never been run.**

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
| **Claim is the wall** | `claim_mean` **28.06 ms** ≫ `mark_done` 9.60 ms ≫ `send_ack` 0.59 ms | pooled, `dests=8` | claim-mode A/B |
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
| C3 — N=16 residual is **store-CPU saturation**, mechanism UNPROVEN | latch gone → store box CPU **92–93%**; top wait `SOS_SCHEDULER_YIELD` is #1 only *by default* (PAGELATCH→~0), it did **not** surge (+11%). Store CPU was already ~87% in C2 — **unmasked, not new**. **No per-query CPU attribution** — churn→CPU link is a hypothesis; pooled-claim rewrite sufficiency at N=16 **UNVERIFIED** *(C4 has since supplied the attribution — see the C4 row below and §8; the rewrite as scoped is now INSUFFICIENT)*. Engine box far from saturation (busiest core ≤44%). | store DMVs + `cpu_soak.csv`, 2026-07-10 | C3 handback |
| **Per-query CPU attribution (C4) — VERDICT: WITHHELD** | ran the attribution C3 lacked. **#1 N=16 query-CPU consumer = `list_fifo_lanes` (dispatcher discovery scan) at 47.46%; CLAIM #2 at 40.33%** → AMBIGUOUS (two families >40%). Reconciliation pre-gate does **not** robustly clear 70% (70.68% only on idle-diluted denominator + off-wall collapse-tail; every sustained/phase-matched denominator 64.5–69.6%). CLAIM `cpu_us_per_exec` rises 8.4× N=4→16 (honest, not spin/empty-claim) but "deeper-queue-scan driven", a **necessary target, not sufficiency**. The ~540 ms **N=16 CLAIM wall is ~72% off-CPU WAIT** (`cpu/elapsed=0.28`) — CPU may be the wrong lever. **Claim-only rewrite would NOT clear the wall** (`list_fifo_lanes` remains #1). Apparatus perturbed: C4 ran ~68% heavier `claim_mean` than C3; c4-8 flipped sustained→not. | pooled, `dests=8`, 2/shard, N=4/8/16, same commit as C3, 2026-07-11 | C4 handback |

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
| a | 10/s fleet (2.5/s per shard) | 8 | SQL Server | sustained e2e, 900 s | **pooled claim runaway (tempdb)** |
| b | 193/s | 1 | SQLite | **intake / ACK only** | engine GIL plumbing |
| c | 60/s | ~1 | SQL Server LAN | sustained e2e, 1 lane | serial per-lane latency |
| d | 23,600 c/s | n/a | SQLite NVMe | store microbench | none (commit capacity not binding) |

The arithmetic that dissolves it:

- **(a) vs (c).** (a)'s 87 delivered/s across 16 lanes is **5.44/s per lane** — far *below* (c)'s 60/s per-lane
  ceiling. Those lanes are starved **upstream** by the shared pooled claim, not by their own latency.
- **(a) vs (b).** (b) is *intake* at fan-out 1 on SQLite: no delivery, no claim, no tempdb. It says nothing
  about delivered throughput.
- **vs (d).** The store's **commit** bandwidth is ~36× the pipeline's demand. But the current wall *is* a
  store-side operation — the pooled claim **query**. Say *"commit bandwidth is not the wall; the claim query
  is,"* never *"the store is never binding."*

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

*The likely answer is neither mode as shipped:* the pooled claim's **tempdb table variables are 43% of its
fixed cost**, and removing them attacks the default path directly, at every lane count. That is a targeted
SQL rewrite, not a mode flip.

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

   ⚠️ **It is a cost-model lever, not (demonstrably) a shard-wall lever.** `per_lane_limit` is **hard-clamped to
   1 for OUTBOUND/RESPONSE** in three independent layers (`wiring_runner.py:237`, `stage_dispatcher.py:246`, and
   each store — e.g. `store/sqlserver.py:4302`), so `fifo_claim_batch` **cannot batch the outbound claim** — the
   one C1/C2/C3 actually measured and the one carrying `dests`× the rows. Its effect on the tempdb churn is
   therefore **not zero but UNMEASURED**: it *can* cut INGRESS/ROUTED claim-*call* count (up to 8× at the swept
   shape, where a message's 8 routed rows share one lane), and the tempdb catalog latch is a **store-wide shared**
   resource. No artifact records a per-stage claim-call rate — the captured `claim_phase_soak` telemetry is
   **outbound-only**. **Do not publish it as a shard-wall non-factor without that measurement** (see #227).
3. **Advisory lint** in `messagefoundry check`: flag handlers whose leading statements are pure guards ending
   in `return None`, and price them.

### Phase 4 — Durable-write *(ADR 0051's own #1 lever)*

**Group-commit is not built.** Amortize fsyncs across concurrent transactions. Reduce carriage bytes
(`NVARCHAR(MAX)` at 2 B/char + base64 of the `mfenc` ciphertext).

*Falsifier:* if measured `txn/s` at the rig sits far below the store's ~27–29k c/s commit ceiling, group
commit buys little and the wall is the **claim query**, not the commit — which is what the evidence currently
says. **Sequence Phase 4 after Phase 1, not before.**

### The sizing arithmetic, at the flat 520.83 events/s target

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
box is unremarkable. **On this arithmetic, parity is a sizing exercise — provided shard scaling holds.** That
proviso is the whole of Phase 5, and it is unmeasured.

### Phase 5 — Size to the spec *(the decisive experiment)*

**Does per-shard throughput stay flat as `N` grows?** Run `N = 1, 2, 4, 8, 16` at fixed per-shard load on one
unified store.

- **Flat** → parity is an `N`-sizing exercise on the 20-core spec. Publish `N × per-shard × 0.5` (the D4 rule:
  publish at ≤50% of the measured ceiling).
- **Declining** → a shared bottleneck (the store's claim path). Phases 3–4 become the whole game and shards
  buy nothing.

This separates "sizing problem" from "engine problem." It is cheaper than any lever, and every lever's value
depends on it.

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
at N=16 was UNVERIFIED** — and **C4 (2026-07-11) has since supplied the per-query attribution C3 lacked and the
answer is worse than "unverified": the claim-only rewrite is now known INSUFFICIENT.** The N=16 store-CPU
wall's #1 consumer is the dispatcher's `list_fifo_lanes` discovery scan (47.46%), **not** the claim (#2,
40.33%) — a `claim_fifo_heads`-only rewrite removes 40.33% but leaves `list_fifo_lanes` #1 and standing.
Worse, ~72% of the ~540 ms N=16 CLAIM wall is off-CPU WAIT (`cpu/elapsed=0.28`), so reducing store CPU may
not clear it at all. C4's own verdict is **WITHHELD** (reconciliation pre-gate fails to robustly clear 70%; CLAIM is not the
plurality). See the dedicated "C4 — the per-query CPU attribution result" subsection at the end of §8. Two
handoff errata the C3 run fixed: the T-SQL is `MEMORY_OPTIMIZED
TEMPDB_METADATA` (two keywords, not the underscore form), and the feature is **not** Enterprise-only (all editions
since SQL 2019, subject to In-Memory OLTP limits). Config was torn down to the C2 baseline. §8 stays unflipped;
`per_lane` stays off.

### The capacity frontier — clearing N=16 is necessary, and demonstrably not sufficient

C1/C2/C3 each answered a *scaling-shape* question. None of them ever stated the *capacity* consequence, and
the arithmetic had never been written down. It is worth writing down, because it changes what a successful
pooled-claim rewrite is worth.

**The sustained ledger.** Gate on `result`, count only arms that fully drained (`drained: true`,
`stranded: 0`):

| config | best **sustained** fleet | shape | vs 520.83 |
|---|---:|---|---:|
| **shipped default** (pooled, `MEMORY_OPTIMIZED TEMPDB_METADATA=OFF`) | **90.0 events/s** | 10 ingress/s, N=4, `dests=8`, 900 s (`redo-pooled-soak10`) | **5.79× short** |
| **C3 config** (`…TEMPDB_METADATA=ON`, reverted after the run) | **144.0 events/s** | N=8 × 2/shard × (1+8), 900 s (`c3-8`) | **3.62× short** |
| *any* mode, for the record | ≥252 events/s | `per_lane`, 16 lanes, 540 s | ≤2.07× short |

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
> shard-doublings past a knee that has already collapsed twice ((4,8] pre-C3, (8,16] post-C3). Neither has
> been measured.**

What per-shard headroom *is* characterized, all on the pooled default at N=4: **2.5/shard sustains**
(10 ingress/s, drained); **3/shard fails to drain** (12 ingress/s, `in_pipeline_final` 825, slope +12.17);
and C1's matched-load penalty *worsens* monotonically with per-shard load (1.01× @2/sh → 1.53× @6 → 3.12×
@10; collapse @12) — direction firm, **magnitudes soft** (both C1 soaks collapsed). Every one of those points
says the same thing: the store gets *less* tolerant as you drive a shard harder, so the "raise per-shard load"
escape runs into the wall from the other side.

**Therefore:** clearing N=16 is **necessary but not sufficient** — and **C4 (below) has now STRENGTHENED
this conclusion twice over:** the pooled claim is *not even the N=16 wall's #1 CPU consumer* (the dispatcher's
`list_fifo_lanes` discovery scan is), and a claim-only rewrite would not clear it — *and* the N=16 wall is
~72% off-CPU WAIT, so "reduce store CPU" may be the wrong lever entirely. Even the earlier, more optimistic
"a CONFIRMED C4 + a successful rewrite would still leave a gap" framing was too generous: **C4 came back
WITHHELD, and the rewrite as previously scoped is now known INSUFFICIENT.** The rewrite is not a parity plan
on its own; it has to be *composed* with the `txn/event` levers (Phase 3) rather than sequenced ahead of them
— and Phase 3 (the just-merged `accepts=` seam, #213) is correspondingly *more* important now, not less.
**Do not read C4 as "the rewrite gets us to 45M/day"** — read it as "the rewrite, even hypothetically
CONFIRMED, was never sufficient, and its target was mis-identified."

*Falsifier:* measure per-shard headroom at N=8 latch-free. If a shard sustains ≳3.6/s at N=8/16, the sizing
path reopens and this section is wrong.

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

**What survives cleanly.** CLAIM `cpu_us_per_exec` rises **8.4× monotonically** N=4→16 (826.9 → 6971 µs) and
it is honest query CPU — *not* spin-inflation (`cpu/elapsed` DROPS 0.93→0.70→0.28; the excess is off-CPU
WAIT, not counted in worker_time), *not* an empty-claim storm (`empty_claim_ratio` falls, rows/claim≈1.0).
**But** it is "largely deeper-queue-scan driven (~4.3× reads growth) with a ~2× per-page-cost elevation" —
**not** the "intrinsic per-cycle churn" the hypothesis assumed — and it is a **necessary target condition
only, not sufficiency**, gated by the reconciliation that now fails.

**Apparatus caveat — every C4 number is under a perturbed regime.** C4 ran measurably heavier than the clean
C3 baseline (same commit `98bec81`; the qstats capture worker's own in-store DMV scan is the sole differing
variable): **c4-8 flipped sustained→not** (backlog slope 7.48 vs C3's 4.04), **c4-16 `claim_mean` 93.4 ms vs
C3's 55.7 ms (+68%)**, stranded 208,766 vs 166,231. A lighter / out-of-process re-capture is a recommendation
before any C4 figure is treated as load-bearing.

**OPEN RATIFICATION (owner decision, NOT self-decided).** Does `list_fifo_lanes` count as **CLAIM machinery**
(fold → 87.79% combined, a decisive plurality) or as a **separate DISPATCH family** (keep separate →
AMBIGUOUS)? **Even folding does NOT yield CONFIRMED** — the reconciliation pre-gate fails independently. The
coordinator's **recommendation is to keep them separate → AMBIGUOUS** (rationale: `list_fifo_lanes` is an
independent clock-driven `_sweep_loop` backstop, a pure RCSI read with no locking hints / no OUTPUT / zero
temp objects, is not per-claim triggered — `sweep_now` fires only on reload/resume/recovery — and needs a
*different* fix than the claim batch), **but that is a recommendation, not a decision.** Recorded OPEN in §9.

**Consequence for the plan.** (1) Do **not** build the `claim_fifo_heads`-only rewrite as the sole wall fix —
sufficiency analysis shows it would not clear N=16 (`list_fifo_lanes` remains #1). Re-target CPU reduction to
the **pooled `StageDispatcher` lane-servicing path as a whole** (discovery scan *and* claim batch) — *if* CPU
is even the lever, which the 72%-WAIT reframe puts in doubt. (2) The `txn/event` levers (Phase 3, `accepts=`
#213, just merged) are relatively **more** important now. (3) Ratify the family question and instrument-fix
before any re-run (phase-matched denominator, C3 cross-check, a scan-confound control for `list_fifo_lanes`,
a lighter capture worker).

### Rig sizing — do the AWS boxes need to grow?

**Short answer: not yet. The engine box becomes the constraint at roughly the next frontier (~28 ingress
msg/s), and the parity certification needs a deliberate, temporary upsizing — in both directions: more CPU,
and a *slower*, spec-honest disk.**

**What the rig is** (all Windows, us-east-2):

| box | instance | vCPU / RAM | spec calls for |
|---|---|---|---|
| engine | m7i.2xlarge | 8 / 32 GiB | **20-core** app server, 48 GB |
| SQL Server | i4i.2xlarge (local NVMe) | 8 / 64 GiB | **16-core / 128 GB**, disk qualified at **9,200 IOPS / 3.5 ms** |
| load-gen | m7i.2xlarge | 8 / 32 GiB | n/a |

**What the telemetry says** (whole-box counters; these are valid — it is only the *per-PID* collector that
reads 0.00):

| run | engine box CPU (mean / p95 / max) | reading |
|---|---|---|
| `per_lane` 28/s **SUSTAINED** (540 s) | 38.5% / **88.4% / 91.9%** | **near saturation** — the 8-vCPU engine box is the next wall |
| `pooled` 16/s **COLLAPSED** | 17.1% / 23.1% / 26.3% | collapse happened with the engine box *idle* — the wall was the claim query, not compute |
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
| 5 (shard curve `N = 1…16`) | **no** | 16 shards on 8 vCPU measures core contention, not store scaling. Needs m7i.4xlarge for N≤8, m7i.8xlarge for N=16 — **on one box; see below, a second box is NOT a capacity option** |
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
At today's *pooled* per-shard rate (22.5 events/s, claim-wall-bound at **17% engine CPU**), the same target
needs ~23 shards — and no box size helps, because the engine is idling against the store's claim query.

**So the deciding variable for the 45M/1,500 demo is not EC2 — it is:**

1. **The claim-path fix at scale** (Phase 1's lane-count sweep + the tempdb rewrite). It moves the answer
   between "fits on the current box" and "needs 23 shards".
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

---

## 9. Open questions, ranked

1. **Is the N=16 wall even CPU-bound, or is it WAIT-bound?** *(NEW — C4, 2026-07-11.)* This now precedes the
   rewrite question, because C4 showed **~72% of the ~540 ms N=16 claim wall is off-CPU lock/latch WAIT**
   (`cpu/elapsed=0.28`) — per-claim CPU is a real but **minority** slice. If the wall is WAIT-bound, reducing
   store CPU (claim *or* dispatch) may not clear it at all, and the entire "store-CPU rewrite" framing is
   attacking the wrong resource. A WAIT-decomposition at N=16 (which lock/latch classes dominate the 72%) is
   unrun and is the highest-leverage next diagnostic.
2. **Does `list_fifo_lanes` count as CLAIM machinery or a separate DISPATCH family?** *(NEW — C4 OPEN
   RATIFICATION, owner decision.)* C4's #1 N=16 query-CPU consumer is `list_fifo_lanes` (47.46%), CLAIM #2
   (40.33%). **Separate** (coordinator's recommendation) → two families >40% → **AMBIGUOUS**, CLAIM not the
   plurality. **Folded** → 87.79% combined plurality. **Even folding does NOT yield CONFIRMED** (the
   reconciliation pre-gate fails independently). This is a spec-author ratification C4 was forbidden to
   self-decide; recorded OPEN. Recommendation rationale: `list_fifo_lanes` is an independent clock-driven
   `_sweep_loop` backstop, a pure RCSI read (no locking hints / no OUTPUT / zero temp objects), not per-claim
   triggered, needing a *different* fix than the claim batch — flagged as recommendation, **not** decision.
3. **What instrument fixes are needed before any attribution re-run?** *(NEW — C4.)* C4's reconciliation
   pre-gate did not robustly clear 70% under any sustained/phase-matched denominator (64.5–69.6%). Before a
   re-run: (a) bake a **phase-matched / sustained-plateau denominator** into the analyzer (drop the min=0
   idle-ramp contamination that carried the lone 70.68% pass); (b) add the **C3 cross-consistency check**
   (store at 92–93%) the prereg's INC-16 skipped; (c) add a **scan-confound control for `list_fifo_lanes`**
   (cpu/exec vs reads/exec, as MUST-FIX 18 did for claim) before calling its 47% share a wall *cause* rather
   than a collapse *effect*; (d) re-capture with a **lighter / out-of-process qstats worker** (C4 ran ~68%
   heavier `claim_mean` than C3 and c4-8 flipped sustained→not — the decomposition is under a perturbed
   regime).
4. **Does *any* rewrite of the pooled `StageDispatcher` lane-servicing path clear N=16 — and is `N`-sizing
   viable at all?** (Phase 5 / C3 / C4.) C1→C2→C3 (2026-07-10) walked the scaling shape: light-load 2/shard
   scaling *declines*, **BREAKS beyond N=4**; the C2 wall was the tempdb system-catalog PAGELATCH; C3's
   `MEMORY_OPTIMIZED TEMPDB_METADATA=ON` **removes that latch and clears N=8 but only buys one shard-doubling**
   (N=16 still collapses). **C4 (2026-07-11) supplied the per-query attribution C3 lacked and changed the
   target:** the N=16 store-CPU wall's #1 consumer is the dispatcher's `list_fifo_lanes` discovery scan
   (47.46%), **not** the claim (#2, 40.33%). So a `claim_fifo_heads`-only rewrite is now known **INSUFFICIENT**
   — it removes 40.33% but leaves `list_fifo_lanes` #1 and standing. Re-target to the **whole pooled
   lane-servicing path** (discovery scan *and* claim batch) — *if* CPU is even the lever (see #1). Any such
   rewrite must be built *and* measured against this exact 2/shard sweep before `N`-sizing is called viable or
   dead. A cheaper unretired re-check sits alongside it: a longer/higher-rate **N=8** soak, to confirm C3's N=8
   clear is durable and not marginal.
5. **Is per-shard headroom at N=8 latch-free above ~3.6 ingress/s?** This is the *falsifier for the capacity
   frontier* (§8): clearing N=16 at the swept 2/shard probe load still lands 1.81× short, so the sizing path
   only reopens if a shard sustains ≳3.6/s at N=8/16. C3 never drove N=8 above 16/s — its "pinned ceiling" is a
   self-declared floor. **Cheap, unrun, and it bounds the value of any lane-servicing-path rewrite.**
6. **What is `per_lane`'s real ceiling** at a 900 s hold on the fixed harness?
7. **What does `fifo_claim_batch > 1` contribute to the *shard wall*** (as opposed to the cost model, where it
   is now settled)? It cannot batch the outbound claim (hard-1), but it can cut INGRESS/ROUTED claim-*call*
   count, and the tempdb catalog latch is store-wide. **Unmeasurable today: the `claim_phase_soak` telemetry is
   outbound-only.** Needs a per-stage claim-call rate (#227).
8. **What is the realistic HL7 fan-out** for a target deployment? It selects which bottleneck you measure —
   `dests=8` is outbound-heavy (89% of events); `dests=1..2` shifts the load onto the ACK-serialized inbound
   commit.

*(Answered 2026-07-11 — the old "is the N=16 store-CPU the pooled claim's temp-object churn?" attribution
question: **C4 verdict WITHHELD** — not confirmed, not refuted. The #1 N=16 query-CPU consumer is the
dispatcher's `list_fifo_lanes` discovery scan (47.46%), **not** the claim (#2, 40.33%); the reconciliation
pre-gate does not robustly clear 70%; and the wall is ~72% off-CPU WAIT. The claim-only rewrite is INSUFFICIENT.
This "answered" only closes "is it the claim?" — it opens the three NEW questions #1–#3 above. See the "C4 —
the per-query CPU attribution result" subsection in §8.)*

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
