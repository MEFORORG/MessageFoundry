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
| **Fleet N-shard scaling** | **UNMEASURED.** `N` was never varied by any throughput run. | — | — |

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
| `fifo_claim_batch > 1` (ships OFF) | 21 | 13.6 msg/s | config |
| `accepts=` seam (`H` 20 → 4) | 8 | 35.7 msg/s | config + seam |
| both | 5 | 57.1 msg/s | config + seam |
| **+ intra-message concurrency** | ~1 | ~286 msg/s | **engine, new** |

The last row is a **verified, unexploited opportunity.** `fifo_claim_batch` batches the *claim* into one
commit, but the dispatcher then loops `for item in items:` — *"processed in FIFO order below"* —
**sequentially**, one handoff commit each. Yet the 20 routed rows of a *single* message target **20 different
destinations** and carry **no mutual ordering dependency**: per-destination FIFO is enforced *across* messages,
by the outbound lane (keyed on `destination_name`), not *within* one. They could be transformed concurrently
while message-level FIFO is preserved. No ADR contemplates this.

### `H` is also a STORAGE amplifier — and the spec gives us a budget to check it against

`store.py`: *"Both `ingress` and `routed` rows hold the raw body"* — **one routed row per selected handler,
each a full copy of the raw message.** So bytes written per ingress message scale as `(1 + H + N)`:

| feed | rows written | of which are raw copies |
|---|---:|---:|
| simple (`H=1, N=1`) | 3 | 2 |
| bench (`dests=8`) | 17 | 9 |
| **ADT hub (`H=20, N=4`)** | **25** | **21** |

The incumbent's budget is **10.9 KB per message** (`500 GB/day ÷ 45M`). A first-order estimate for
MessageFoundry — assuming a ~2 KB raw HL7 body and ~2.67× encoding inflation (`NVARCHAR(MAX)` at 2 B/char ×
base64 of the `mfenc` ciphertext) — puts the estate-weighted figure at **~11 KB/event**, i.e. roughly at
parity; but the ADT hub alone is **~27 KB/event**, about **2.5× the budget**.

> ⚠️ **That is an estimate with stated assumptions, not a measurement.** `bytes/msg` has **never been
> measured**. Measuring it is free, and it is a first-class parity number the incumbent publishes outright.
> The structural claim does not depend on the raw size: **write volume, like transaction count, scales with
> `H`.** Cutting `H` from 20 to 4 cuts both — and the 15 TB / 30-day drive sizing an adopter is told to buy
> depends on it.

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
2. **`fifo_claim_batch > 1`.** `_PREFIX_STAGES = {INGRESS, ROUTED}` already supports claiming the contiguous
   due head-prefix in one commit (ADR 0058/0066), and one message's routed rows share a lane. It ships
   **`default=1` = OFF**.
   *Unverified:* whether a batched claim also batches the **handoff** commit, or only the claim.
   **Read the ROUTED dispatcher before quoting a number.**
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

This separates "sizing problem" from "engine problem." It is cheaper than any lever, every lever's value
depends on it, and **it has never been run.**

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

1. **Does shard scaling hold?** (Phase 5.) Everything else is downstream of this.
2. **What is `per_lane`'s real ceiling** at a 900 s hold on the fixed harness?
3. **Does a batched ROUTED claim also batch the handoff commit?** Decides whether `fifo_claim_batch` is a
   default-flip or a no-op.
4. **Is a GIL-bound core co-binding?** The engine-side CPU collector reads `0.00` on the SQL Server rig. Until
   it is fixed, no CPU claim is admissible.
5. **What is the realistic HL7 fan-out** for a target deployment? It selects which bottleneck you measure —
   `dests=8` is outbound-heavy (89% of events); `dests=1..2` shifts the load onto the ACK-serialized inbound
   commit.

*(Resolved 2026-07-10: the claim is a **flat** 520.83 events/s sustained, not a peak-honoured figure. The
estate's own 2.28–2.89× diurnal peaking in §6 characterises the estate, not the target.)*
