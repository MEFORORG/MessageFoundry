# Throughput execution plan — to 45M messages/day across 1,500 connections

**Date:** 2026-07-10 · **Companion to:** [THROUGHPUT-STATUS-2026-07-10.md](THROUGHPUT-STATUS-2026-07-10.md)
(the audit this plan executes against) · **Method:** synthesised from three independently authored plans
(risk-first, evidence-first, demo-first), scored by two independent judges. Both judges selected the
**risk-first** spine — order the work by what could invalidate the whole effort, and fire the cheapest
potential killer first — and grafted onto it the demo instrument, a smallest-credible-demo, an explicit
falsifier for the `2H` thesis, a cannot-claim ledger, and a persistence phase. This document is that synthesis.

Every msg/s, txn/msg, bytes/msg, and CPU figure below traces to the audit. **No number here is new.** Where a
value is genuinely unknown it is written **UNKNOWN** and never extrapolated — that discipline is the whole
point of the correction this plan follows from.

---

## 0. What this plan is for

The goal, in the owner's own terms (ruling 2026-07-10): **a setup that DEMONSTRATES 520.83 total message
events/s** — inbound plus outbound, flat and sustained, no peak multiplier, HL7 in and out only — **across
~1,500 connections on our own stack.** `45,000,000 / 86,400 = 520.83 events/s`. This is a **capability demo on
our stack**, explicitly **not hardware parity** with the incumbent ("I don't care about exactly matching
[the incumbent's] system req … having a setup that will match the 45M/day across 1500 interfaces").

The **honest gap** to that target is **5.79×** on the shipped `pooled` claim mode (definitive point: 10 ingress/s
= 90 total events/s, `pooled`, `dests=8`, 4-shard fleet, one SQL Server store, 900 s soak) and **≤2.07×** on
`per_lane` (≥28 ingress/s = ≥252 events/s, 16 lanes, 540 s — a knee-onset lower bound, not a ceiling). Every
prior "~52× short" was a units defect (B10), inflated by `1 + dests` (9× at the bench).

**Two numbers decide everything, and neither has ever been measured:**

1. **The shard curve.** Does per-shard events/s stay *flat* as shard count `N` grows on one unified store?
   `N` was never varied by any throughput run; every "per-shard × N → 520.83" is a **projection off a single
   4-shard point.** Flat ⇒ parity is an `N`-sizing exercise on the 20-core-class active box. Declining ⇒ a
   shared store-side wall that no shard count and no box closes.
2. **The claim path at scale.** The binding wall today is the `pooled` outbound claim query's tempdb-metadata
   churn (`claim_mean` 33.6 ms for ~1 row, runaway 12 → 20 → 33 → 43 → 127 ms; tempdb table-vars = 43% of fixed
   claim cost). `per_lane` avoids it (4.5× cheaper per delivered row **at 16 lanes**) but is catastrophic **at
   1,500 lanes** (~18k empty `UPDLOCK` claims/s at zero messages; drops messages). The crossover has never been
   found.

Everything downstream of those two measurements is a projection until they exist. This plan sequences to
retire them as cheaply and as early as the rig allows.

---

## 1. How to read this plan — the annotation scheme

**Every step carries an annotation** — one, or, where a step both *builds* a lever and *measures* what it
bought, the pair `⚙️ SOLO` to build + `🧠 ULTRACODE` to verify (steps F1, F3, F4). The scheme exists because
this programme's failures were never
crashes — they were **confident, self-consistent, WRONG numbers** (B1/B6/B7/B8/B9/B10, the 3.5× volume
overstatement, the retracted per-server-parity claim, the "52×" gap). Only adversarial refutation catches
those. So the annotation is a statement about *failure mode*, not about difficulty.

- **🧠 ULTRACODE** — a multi-agent `Workflow` with adversarial verification. Use when the output is a **number
  that will be published or gate a decision**; when changing **measurement or verdict semantics**; when the
  failure mode is a **plausible-but-wrong result** (the entire B-class); when **interpreting rig results**.
  Rationale: confident wrong numbers are only caught by adversarial refutation.
- **🔍 FABLE REVIEW** — a fast single-model review pass (`/code-review`, or a Fable-model diff review) before
  merge. Use for **mechanical code changes, config flips, doc errata, PR review** — where being wrong is cheap
  and tests catch it. *Operational note: Fable's auto-mode safety classifier intermittently blocks shell
  commands with a transient "Stage 2 classifier error"; retrying usually succeeds. Prefer Read/Grep over Bash
  in Fable sessions, and avoid `rm -rf`, compound `git push && gh pr create`, and heredocs.*
- **⚙️ SOLO** — trivial/mechanical; CI is sufficient review.

**Rule of thumb:** if a step *produces or interprets a msg/s, txn/msg, or bytes/msg number* → ULTRACODE. If it
*changes code that produces one* → build SOLO, then ULTRACODE-verify the result. If it is *plumbing, docs, or a
flag* → SOLO + FABLE REVIEW.

Two consequences of the scheme are load-bearing in the phases below. **The per-PID CPU collector fix is
ULTRACODE, not SOLO** — its failure mode is a plausible-but-wrong CPU number, which is the exact B-class
disease. And **every rig experiment is ULTRACODE**, because interpreting a rig result into a verdict is where
this programme has repeatedly manufactured a self-consistent wrong number.

---

## 2. Phases

The order is **cheapest-killer-first**, not pipeline order. Phase A retires the cheap risks and fixes the
yardstick with **no rig**. Phase B prototypes the tempdb rewrite on a **laptop**, before any engine change or
AWS hour. Phase C spends the AWS campaign **cheap → decisive**, firing the 2-point shard probe (the single
cheapest experiment that could kill the whole effort) as early as the rig allows. Phases D–H build only what a
Phase-A/B/C measurement has licensed.

> **Honest sequencing note (inherited from the risk-first spine).** Phase A/B is up to ~2 weeks of zero/cheap
> work that precedes the C1 shard probe. A pure expected-value order would fire C1 in parallel with Phase A.
> The only genuine prerequisite for C1 is **A3** (the per-PID CPU collector — without it a box-CPU wall cannot
> be told from a store wall in the probe). So **A3 is on the critical path to C1; the rest of Phase A is not,
> and should run concurrently with the C1 rig session, not gate it.**

---

### Phase A — Zero-rig risk retirement and the yardstick *(no AWS; hours–days each)*

**Goal.** Fix the denominator, stand up the two unmeasured parity counters, make the engine-side CPU collector
trustworthy, install a structural guard against the B-class fabrication, and settle two code-facts by reading
code rather than extrapolating — all before a rig hour is spent.

**Why now (verified).** The gate is currently `(1 + dests)`× too strict; `txn/msg` and `bytes/msg` have
**never been measured**; per-PID CPU reads a constant `0.00`; and the nine harness defects are one bug class
(a fixed constant bounding a parameter-scaled interval that, on expiry, silently fabricates a plausible
result). None of this needs a rig.

**Steps.**

- **A0 — Fix the yardstick (B10).** Change the gate to `ingress × (1 + dests) >= 520.83`; fix the
  `TARGET_INGRESS_PER_S` docstring/constant prose; restate every published figure in **total events/s** and the
  honest gap as **5.79× (pooled) / ≤2.07× (per_lane)**, retiring the "~52×".
  *Falsifier:* a unit test asserting the gate fires exactly at `ingress = 520.83 / (1 + dests)` for
  `dests ∈ {1,2,4,8,16}`; if any row disagrees with the owner ruling, the formula is wrong. — **🧠 ULTRACODE**
  (changes the headline verdict/measurement semantics and republishes every gap number).

- **A1 — Build the `txn/msg` and `bytes/msg` counters.** Instrument committed staged-queue transactions per
  ingress message, and durable bytes written per ingress message. Both are currently unmeasured; both are
  first-class parity numbers the incumbent publishes outright.
  *Falsifier:* none standalone — the counter is validated by A2 and C3b. — **⚙️ SOLO** (instrumentation that
  *produces* a number; the number itself is ULTRACODE-verified downstream).

- **A2 — Measure `bytes/msg` against the 10.9 KB budget.** Run the A1 counter (or a static
  `(1 + H + N) × encoded-body` estimate) and compare estate-weighted and ADT-hub `bytes/msg` to the spec's
  **10.9 KB/message** (`500 GB/day ÷ 45M`). `ingress` + each `routed` row hold a full raw copy, so bytes scale
  as `(1 + H + N)`; the ADT hub writes 21 raw copies, first-order **~27 KB/event ≈ 2.5× the budget** — but this
  has never been measured.
  *Falsifier:* if measured estate-weighted `bytes/msg` ≤ 10.9 KB, the storage-parity alarm is retracted; if the
  ADT hub is ≫ the ~27 KB estimate, drive sizing needs the `accepts=`/`H`-reduction lever to close, not tuning.
  — **🧠 ULTRACODE** (produces a published parity number that gates adopter drive sizing).

- **A3 — Fix the per-PID engine CPU collector and validate it reads true.** Repair the sampler that reads a
  constant `0.00` on the SQL Server rig.
  *Falsifier (grafted, the stronger of the two):* run the fixed sampler against the sustained `per_lane` 28/s
  run and **reconcile the per-PID CPU sum against the existing whole-box telemetry (engine p95 88.4% / max
  91.9%) to within sampling error**; additionally, it must not still read `0.00` or a constant under any run
  whose whole-box CPU is demonstrably > 50%. Either failure means the collector is still wrong.
  — **🧠 ULTRACODE** (grafted upgrade from SOLO: its failure mode is a plausible-but-wrong CPU number — the exact
  B-class disease — and no CPU verdict is admissible until it reads true).

- **A4 — Harness-invariant property test + a representable UNKNOWN.** (a) A property test asserting, for
  `hold ∈ {60..1800}` and `drain ∈ {30..300}`, that every `_derive_*_timeout` **strictly exceeds** the interval
  it guards, and that `sustainable_ingress_rate` is **invariant to `hold`** when the true rate is held fixed.
  (b) Make the reduction step emit **`INCONCLUSIVE`** unless all four observers agree they measured the same
  window (generalising the B9 `SOAK_UNCONFIRMED` label into a cross-observer consistency check).
  *Falsifier:* re-run the four burned artifact configs through the guarded harness; if any previously
  *fabricated* collapse now reproduces as a *real* one, or the observers disagree without emitting
  `INCONCLUSIVE`, the guard is incomplete. — **🔍 FABLE REVIEW** (test/guard code; being wrong is cheap and CI
  catches it).

- **A5 — Read the ROUTED dispatcher + finalizer (settle two code-facts, do not extrapolate).** (i) Does a
  batched ROUTED **claim** also batch the **handoff** commit, or only the claim? `fifo_claim_batch` (ships
  `default=1` = OFF) batches the claim into one commit, but the dispatcher then loops `for item in items:`
  sequentially — whether `2H` collapses to `H+1` or to ~1 is **UNVERIFIED**. (ii) Can a lightweight
  `message_event` row preserve per-destination "considered and declined" visibility if `accepts=` suppresses
  the `routed` row?
  *Falsifier:* if the dispatcher commits one handoff per routed row regardless of claim batching,
  `fifo_claim_batch` is a **no-op** for `2H` and D2/F2 is dropped. — **🧠 ULTRACODE** (a code-fact that gates two
  lever decisions; extrapolation-from-unread-code is this programme's signature failure).

- **A6 — Draft the `accepts=` ADR + advisory-lint spec.** An ADR for a pure `accepts=pred` predicate evaluated
  in the router stage (declined handlers cost 0 txn, not 2), plus a `messagefoundry check` advisory lint that
  prices selected-but-filtering handlers. All 20 ADT gates are pure message-field reads (the hub's `db_lookup`
  runs *inside* the transform, after the gate), so every gate can legally move to `accepts=`; purity is enforced
  for free (`db_lookup`/`fhir_lookup` already raise outside a live Handler). It is a Python callable, so it does
  not violate the no-declarative-`Filter` rule. Record the count-and-log impact settled in A5.
  *Falsifier:* if A5 shows count-and-log cannot be preserved without machinery heavier than a `message_event`
  row, the ADR must justify the invariant change or the lever is deferred. — **🔍 FABLE REVIEW** (a design
  document; being wrong is cheap and review catches it).

**Falsifier (phase).** If any real run's `ingress × (1 + dests)` still misses 520.83 by the old ~52×, the units
were not the whole story (expected: the gap collapses to 5.79×).

**Exit criteria.** Gate restated in total events/s; `txn/msg` and `bytes/msg` counters emitting; `bytes/msg`
compared to budget; CPU collector reconciles with whole-box telemetry; property-test guard green; the two A5
code-facts written down (not extrapolated); the `accepts=` ADR drafted.

**Effort (estimate, not a measurement).** ~1–1.5 weeks elapsed, engineering-only, ~$0.

---

### Phase B — Cheap-rig risk retirement: the tempdb prototype *(laptop SQL Server container; no AWS)*

**Goal.** Prove — or kill — the pooled-claim tempdb rewrite in isolation, before any engine change or AWS
campaign spends on it.

**Why now (verified).** The binding wall is the pooled claim's tempdb-metadata churn (tempdb table-vars = 43%
of fixed claim cost). The claim-wall microbench already runs on a laptop SQL Server container, so the premise
"removing the tempdb table variables moves `claim_mean`" can be falsified in **hours**, not rig-days.

**Steps.**

- **B1 — Prototype a tempdb-table-var-free pooled claim; micro-bench `claim_mean` in isolation.** Rewrite the
  pooled outbound claim query to remove the four tempdb table variables (e.g. a set-based `UPDATE … OUTPUT`,
  stored-proc temp-object caching, or `MEMORY_OPTIMIZED TEMPDB_METADATA=ON` as a deploy prereq); micro-bench
  `claim_mean` on the laptop container.
  *Falsifier:* if the rewrite does **not** move `claim_mean` off its 43% tempdb component in isolation, do
  **not** build it into the engine (F3 is dropped), and the claim-mode question (C2) becomes the only pooled-side
  option. **Do NOT respond by flipping the default to `per_lane`** — catastrophic at 1,500 lanes. — **🧠
  ULTRACODE** (produces a `claim_mean` number that gates whether the default-path rewrite gets built).

**Exit criteria.** A go/no-go on the tempdb rewrite backed by an isolated `claim_mean` number.

**Effort (estimate).** ~1–2 days on the laptop container.

---

### Phase C — The rig experiments, ordered cheapest-killer-first *(AWS; prerequisite: A3 reads true)*

**Goal.** Retire the two decisive risks — the shard curve and the claim path at scale — and re-measure the
ceiling at the production fan-out shape, in that priority order.

**Why now (verified).** The 90 events/s definitive point is a **4-shard-fleet** number; `N` was never varied.
A second engine box adds **zero** capacity (active-passive HA; one leader runs the graph; engine shards are
subprocesses on one box), so **`N` shards on one active box is the only axis that can close the gap** — and it
is unmeasured.

**Prerequisite.** A3 must read true, so a box-CPU wall is distinguishable from a store-claim wall on every run.

**Steps (cheap → decisive).**

- **C1 — The 2-point shard probe (N=1 vs N=4). THE cheapest potential killer; fire it as early as the rig
  allows.** N=1 and N=4 at fixed per-shard offered load, `dests=8`, 900 s soak, whole-box **and** per-PID CPU
  recorded. Two points cheaply distinguish "flat" from "already declining."
  *Falsifier / decision:* if per-shard events/s at N=4 is materially below N=1, the curve is **declining** →
  the entire "parity is an N-sizing exercise" thesis is dead with 2 points → **skip C4's full sweep**, and the
  levers (Phase F) become the whole game because shards buy nothing. — **🧠 ULTRACODE** (interprets the rig
  result that gates the entire sizing thesis).

- **C2 — Claim-mode lane-count sweep (16 → 100 → 500 → 1,500 lanes).** Run `pooled` and `per_lane` at a 900 s
  soak across the lane counts; record `claim_mean`, whole-box CPU, loss, and drain; find the crossover. **This
  is a measurement to find the crossover, not a licence to flip.** `per_lane`'s 4.5×-cheaper claim is real **at
  16 lanes**; `pooled` exists **because** `per_lane` is untenable at 1,500 (~18k empty `UPDLOCK` claims/s at
  zero messages). Neither number generalises to the other's regime.
  **Sequencing (resolves the instrument dependency).** Driving lane counts beyond `shardcert`'s current 16 lanes
  **with traffic** requires the many-lane traffic driver built in Phase D (**D2 / backlog #216**) — `connscale`
  proved 1,500 lanes *idle*, `shardcert` drives only 16 lanes *with traffic*, and no other instrument reaches the
  upper rungs. So **C2's upper rungs (toward 1,500 lanes) are gated on #216** and sequence once D2 exists (Phase D
  may run in parallel with the C1/C4 shard-curve work — §3). The cheap shard probe **C1 is NOT gated on #216** (it
  runs on the existing `shardcert` fleet at `dests=8`); only C2's lane sweep is — there is no cycle, because D2 is
  C2's prerequisite, not the reverse.
  *Falsifier:* if pooled's `claim_mean` stays **flat** as lane count rises, the tempdb churn is not scale-driven,
  the crossover story is wrong, and the B1 rewrite buys nothing at scale. — **🧠 ULTRACODE** (interprets rig
  results across regimes; a naive read here would repeat the programme's signature failure).

- **C3a — Teach the harness `routed_fanout ≠ delivered`.** Extend the ladder so `N` handlers are routed of
  which `M` deliver (production shape `routed=20, delivered=4`), independent of `dests`. The bench today ties
  one handler to one destination (`routed == delivered`), understating transform-stage work ~2.5× and
  overstating outbound work ~2× versus the real ADT hub.
  *Falsifier:* mechanical; the finding is in C3b. — **⚙️ SOLO** (harness plumbing that *produces* a number;
  ULTRACODE-verified in C3b).

- **C3b — Re-measure the ceiling at the production shape; the `2H` thesis's own falsifier.** Run
  `routed=20, delivered=4` at 900 s; publish `txn/msg` and IOPS/msg (A1 counters live). Cost model
  `txn/msg = 3 + 2H + 2N`; the ADT hub is 51 txn/msg of which 32 (63%) produce no counted message.
  *Falsifier (the falsifier for BOTH `2H` levers):* if the ceiling at `(H=20, N=4)` **matches** the ceiling at
  `(8, 8)`, then `H` does not matter, the `2H`-dominates story is wrong, and **both** the `accepts=` seam (F1)
  **and** the `fifo_claim_batch` flip (F2) are dead. — **🧠 ULTRACODE** (produces the decision-relevant
  `txn/msg`/IOPS numbers at the real shape; explicitly gates both 2H levers).

- **C4 — Full shard curve N = 1, 2, 4, 8, 16 (only if C1 was ambiguous).** The full per-shard-vs-`N` curve at
  fixed per-shard load on one unified store; **skipped if C1 already showed a clear decline.**
  *Falsifier / decision:* **Flat** ⇒ parity is an `N`-sizing exercise; publish `N × per-shard × 0.5` (publish at
  ≤50% of the measured ceiling). **Declining** ⇒ a shared store-claim wall; shards buy nothing and Phase F is
  the whole game. — **🧠 ULTRACODE** (the decisive rig interpretation on which the whole effort turns).

**Exit criteria.** Shard curve known (flat or declining); claim-mode crossover located; production-shape
ceiling and `txn/msg`/IOPS published; the `2H` thesis confirmed or refuted.

**Effort (estimate).** C1 ~1 rig session on the current 8-vCPU boxes; C2 ~1 campaign; C3a ~2–3 days harness
code; C3b ~1 rig session; C4 ~1 week **needs bigger boxes** (m7i.4xlarge for N≤8, m7i.8xlarge for N=16 — 16
shards on 8 vCPU measures core contention, not store scaling; a second box is **not** a capacity option).

---

### Phase D — Build the demo instrument *(the actual investment; harness code, not hardware; value-gated on the C1/C4 shard-curve result — its D2 traffic driver is itself the prerequisite for C2's 1,500-lane rung)*

**Goal.** Build the one instrument that can drive the demo shape — ~1,500 connections at ~0.347 events/s each,
72%-simple / hub mix, over `N` engine shards on one unified store, with both reliability authorities clean.
This is **the owner's actual deliverable**, promoted from a buried optional line to a first-class staged build.

**Why now (verified).** No existing instrument drives the demo shape. `connscale` proved the 1,500-lane
**idle** claim storm (uniform per-connection rate, single engine, no validity machinery); `shardcert` drives
**traffic** over 4 shards × 8 dests (16 lanes, `routed == delivered`, cannot express 1,500 connections). The
demo load — 520.8 events/s = 233.9 ingress/s (17.7 hub + 216.1 simple) + 287.0 deliveries/s ≈ **2,416 committed
txn/s = 9% of the store's measured ~27k commits/s ceiling** — is driveable by neither. **Sequenced after the
C1/C4 shard-curve result** so its value is known: if C1/C4 showed a declining curve, the instrument still gets
built, but the demo report publishes the shared-wall finding alongside. The D2 traffic driver is **not** gated on
C2 — it is C2's own prerequisite for the 1,500-lane rung, so there is no cycle: **C1/C4 (`shardcert`, current
boxes) → D2 driver → C2's upper rungs + the full demo.**

**Steps.**

- **D1 — Estate-mix config generator.** A parametric generator emitting a ~1,500-connection code-first graph:
  a majority of **simple** feeds (`H=1, N=1`) plus a few **hubs**, including an ADT-shaped hub (`H=20` routed,
  ~4 delivered) whose **17 surplus handlers self-filter on pure message-field guards** — real
  `routed ≠ delivered`. Weighted so ADT is ~17% of events. Synthetic HL7 only (`generators/`); no PHI, no
  site/partner names.
  *Falsifier:* `messagefoundry check` / dryrun on the generated graph disagrees with the intended `(H, N)` per
  feed ⇒ the generator does not model the shape it claims. — **🔍 FABLE REVIEW** (mechanical code generation;
  dryrun + CI catch errors cheaply, and it emits topology, not a msg/s number).

- **D2 — Demo driver (connscale N-conn driver × estate mix × N-shard fan-in).** Extend the connscale driver
  (one aggregate token bucket, round-robin over `N` persistent MLLP connections, shared correlator + live
  metrics + no-loss reconcile) to (a) assign each connection its generated feed shape, (b) span `N` engine
  shards on one unified store, (c) meter a **flat** aggregate at the target events/s.
  *Falsifier:* the driver's own event loop becomes a bottleneck (load-gen CPU high, per-connection mean rate
  drifts from `R/N`) ⇒ it is confounding the measurement, as connscale's docstring warns N independent timers
  would. — **🧠 ULTRACODE** (the metering + no-loss reconcile *is* the headline number; its failure mode is
  fabrication).

- **D3 — Port the derived validity gates + cross-observer check.** Carry over the B1/B6/B7/B8/B9-fixed
  derivations (`_derive_driver_done_timeout`, `_derive_drive_complete_timeout`, `_derive_engine_drained_timeout`,
  the honest `sustainable_ingress_rate` pick, the `SOAK_NOT_SUSTAINED`/`SOAK_UNCONFIRMED` labels) plus the A4
  cross-observer consistency check and representable UNKNOWN, so a collapse cannot post a plausible pass. The
  demo at 1,500 conns / 900 s exercises exactly the long-drain window B6 preferentially contaminates.
  *Falsifier:* inject a known collapse (offer > measured knee) and confirm the driver labels it not-sustained
  and posts no PASS; if it fabricates a clean tally, a gate is still hardcoded. — **🧠 ULTRACODE** (verdict
  semantics on the exact surface that fabricated for eight days).

**Exit criteria.** An instrument that drives ~1,500 mixed-shape connections over `N` shards, meters a flat
aggregate, reconciles loss against socket truth, and cannot post a fabricated pass.

**Effort (estimate).** D1 ~2–4 sessions; D2 ~4–6 sessions; D3 ~2–3 sessions — instrument subtotal ~8–13
sessions before the first full-scale demo hour.

---

### Phase E — The smallest credible demo *(first honest at-scale number; current, unfixed engine)*

**Goal.** Before scaling to the full 520.83, shake the instrument out and get one un-fabricated sustained
number at the demo shape — and let it **name the binding wall at 1,500-connection scale**, so Phase F builds
only that lever.

**Why now (verified).** The instrument is new and the failure history is fabrication; a shakeout is cheap
insurance. Running the demo shape on the **current (pooled, claim-path-unfixed) engine** reveals which wall
actually binds at scale with real fan-out — that identity is what tells you which Phase-F lever to build.

**Steps.**

- **E1 — Dry-run + tiny-scale shakeout.** Run the generated graph + demo driver at small `N` (offscreen /
  single box, tens of connections) to validate wiring, correlation, and the validity gates end-to-end. No
  published number.
  *Falsifier:* no-loss reconcile disagrees with sink socket-truth at small `N` ⇒ correlation is broken before
  scale. — **⚙️ SOLO** (plumbing shakeout; CI + the reconcile assertion suffice).

- **E2 — Run the smallest credible demo.** ~1,500 connections, estate mix, flat aggregate **walked up to the
  knee the current engine holds** (do not pre-assume 520.83), on the current rig with the engine box upsized to
  m7i.4xlarge (16 vCPU) and the i4i.2xlarge store, 900 s soak, both authorities clean. Record whole-box **and**
  per-PID CPU (A3 fixed), `txn/msg`, `bytes/msg`.
  *What it PROVES:* the **concentration rule** (0.347 events/s × 12.7 hot-feed factor = 0.88 ingress msg/s vs a
  7.1 msg/s `H=20` lane ceiling = 8.1× headroom, so no single lane should saturate); the **binding wall's
  identity** at scale; a trustworthy sustained total-events/s on our stack; that the instrument does not
  fabricate.
  *What it does NOT prove:* the full 520.83; the month-start 2.89× peak (owner-stated structural, but the demo
  is flat by ruling); an adopter's slower SAN disk (we run NVMe — publish the disk assumption); multi-hour/day
  stability; real-PHI byte sizes (only as good as the synthetic corpus).
  *Falsifier:* a single lane saturates **below** its computed ceiling at 0.347 events/s/conn ⇒ the concentration
  model is wrong and 1,500 connections does not dissolve the hot-feed limit. — **🧠 ULTRACODE** (interprets a
  rig result into a published number).

**Exit criteria.** One honest sustained events/s at the demo shape on the current engine, and a named binding
wall at 1,500-connection scale.

**Effort (estimate).** E1 ~1 session; E2 ~1–2 rig sessions + analysis.

---

### Phase F — Build the measured-binding levers *(build ONLY what a measurement named)*

**Goal.** Build the single lever the C-phase A/Bs and the E2 smallest-demo identified as binding — nothing
speculative.

**Why now (verified).** Measure-before-build is the whole discipline. Each lever below is gated on a named
measurement; if the gate did not clear, the lever is not built.

**Gate map.**

| lever | build ONLY if… | falsifier that kills it |
|---|---|---|
| `accepts=` seam (F1) | C3b shows the ceiling moves with `H`, and E2/A5 confirm transform-stage (not claim) binding | moving pure gates leaves `txn/msg` unchanged |
| `fifo_claim_batch` flip (F2) | A5 showed the handoff **also** batches, and C3b shows `H` matters | `txn/msg` unchanged with batching on ⇒ no-op |
| pooled tempdb claim rewrite (F3) | B1 moved `claim_mean` in isolation **and** C2 showed `claim_mean` rises with lane count | flat `claim_mean` across 16→1,500 lanes |
| group-commit (F4) | rig `txn/s` sits **near** the ~27–29k c/s commit ceiling | measured `txn/s` far below ceiling ⇒ wall is the claim query, not commit |
| intra-message concurrent transform (F5) | C3b shows `H` binds the **transform** stage **and** the cheaper `2H` levers (F1/F2) did not already clear the hub lane ceiling | hub ceiling flat with concurrent transform ⇒ the serial handoff was not the wall |

**Steps.**

- **F1 — Build the `accepts=` seam.** Implement `@handler(…, accepts=pred)` evaluated in the router worker;
  declined handlers cost 0 txn. Cuts ADT `txn/msg` **51 → 19 (2.68×)**, estate 4.64 → 3.55 txn/event, that
  feed's lane ceiling **×5**. Removes the per-destination `FILTERED` disposition row (needs the A6 ADR — touches
  the count-and-log invariant; replace with a lightweight `message_event`). — **⚙️ SOLO** to build; then
  **🧠 ULTRACODE**-verify the measured `txn/msg` reduction on the rig.

- **F2 — Flip `fifo_claim_batch > 1` default (only if A5 proved the handoff also batches).** Change the shipped
  `default=1` (OFF) and confirm with a rig A/B at the ADT shape. — **🔍 FABLE REVIEW** (a default flip; tests +
  a rig A/B catch a regression).

- **F3 — Integrate the tempdb claim rewrite into the engine.** Ship the B1 rewrite as the pooled claim query;
  correctness re-cert (FIFO / atomicity / poison-guard) is **mandatory**. Attacks the default path at every
  lane count. — **⚙️ SOLO** to build; then **🧠 ULTRACODE**-verify the post-rewrite ceiling on the rig.

- **F4 — Group-commit (ADR 0051's own #1 lever; sequence LAST).** Amortise fsyncs across concurrent
  transactions; reduce carriage bytes (`NVARCHAR(MAX)` at 2 B/char + base64 of the `mfenc` ciphertext).
  *Falsifier / why last:* if measured `txn/s` at the rig sits far below the ~27–29k c/s commit ceiling,
  group-commit buys little and the wall is the **claim query**, not the commit — which is what the evidence
  currently says. — **⚙️ SOLO** to build; then **🧠 ULTRACODE**-verify.

- **F5 — Intra-message concurrent transform of a message's routed rows (backlog #214).** Transform the multiple
  `routed` rows of a **single** message concurrently while preserving message-level FIFO, instead of the current
  sequential `for item in items:` handoff loop. The 20 routed rows of one ADT message target **20 different**
  destinations and carry **no mutual ordering dependency** (per-destination FIFO is enforced *across* messages by
  the outbound lane, keyed on `destination_name`), so they may run concurrently; this collapses the serial chain
  from ~40 txn to ~1 and lifts the hub lane ceiling from 7.1 toward **~286 ingress msg/s** — the single largest
  hub-ceiling lift in the audit. No ADR contemplates this. It is **P3**: build **only if** C3b shows `H` binds the
  transform stage **and** the cheaper `2H` levers (F1/F2) did not already clear the hub ceiling; it touches the
  same ROUTED dispatcher as A5/F2, so ordering-safety re-certification is **mandatory**. — **🧠 ULTRACODE** (a new
  engine concurrency primitive whose ordering-safety **and** speedup both need adversarial verification).

**Exit criteria.** The binding lever built, re-certified, and its ceiling gain ULTRACODE-verified on the rig;
non-binding levers explicitly not built (with the falsifier that ruled them out recorded).

**Effort (estimate).** F1 ~3–5 days + ADR; F2 hours + a rig A/B; F3 ~3–5 days + re-cert; F4 ~1–2 weeks;
F5 ~1–2 weeks + mandatory ordering-safety re-cert.

---

### Phase G — The full demo and publish

**Goal.** Drive the full flat 520.83 events/s across ~1,500 connections at the estate mix on the fixed engine,
sustained with both authorities clean, and publish it honestly.

**Why now (verified).** This is the owner's stated goal. The demo-load model says ~2,416 txn/s = 9% of the
store's commit ceiling. A first-order engine sizing of **~6.4 vCPU** (82 events/vCPU × 520.83) is
**measurement-gated, not a prediction**: 82 events/vCPU is a *mean* box CPU (38.5%) read off a **single
near-saturated** run (p95 88.4% / max 91.9%) and then extrapolated linearly to ~2× the load **and** across claim
modes — precisely the confident-self-consistent-wrong pattern this plan exists to catch. Treat it as **UNKNOWN
until A3/E2/G1 measure it**, and publish **no** vCPU or margin figure ahead of E2. If the claim path is fixed it
points to ~6.4 vCPU; if not, ~23 shards and no box helps — Phases C/F decide which.

**Steps.**

- **G1 — The full demo.** Drive the full 520.83 total events/s across ~1,500 connections at the estate mix,
  ≥900 s (ideally multi-hour) soak, both authorities clean, on the box size the Phase-C shard curve justifies
  (start on m7i.4xlarge / i4i.2xlarge — the store sits at 9% of its commit ceiling — and let measured CPU/claim
  telemetry, not the spec sheet, justify anything larger). Record per-PID CPU, txn/s, bytes/msg.
  *Falsifier:* the run cannot be sustained flat for the full hold with both authorities clean at any box size
  the shard curve predicts ⇒ a wall Phase F did not close remains. — **🧠 ULTRACODE** (the headline capability
  claim).

- **G2 — Publish the demo report.** A `docs/benchmarks/` report stating the result at **N × per-shard × 0.5**
  (publish at ≤50% of the measured ceiling), with the **PROVES / does NOT prove** discipline from E2 carried
  forward — explicitly disclaiming the flat-vs-month-start-2.89×-peak, the adopter-SAN-vs-our-NVMe disk,
  multi-hour stability, and real-PHI byte sizes. Ratios only; no customer/site/partner/host/IP. Run
  `python scripts/publish/scan_forbidden.py --published` first.
  *Falsifier:* `scan_forbidden.py --published` flags content ⇒ a denylisted term leaked. — **🔍 FABLE REVIEW**
  (a doc; the scan gate + review catch leaks cheaply).

**Exit criteria.** A published, un-fabricated capability number at ≤50% of the measured ceiling, with its
limits stated.

**Effort (estimate).** G1 ~1–2 rig sessions; G2 ~1 session.

---

### Phase H — Persist the audit *(repo + memory; honour conventions)*

**Goal.** Land the audit and this plan as backlog items and corrected project memory, in the required formats.

**Why now (verified).** Repo convention: `docs/BACKLOG.md` CI (`scripts/docs/backlog_status_check.py`) fails on
`main` without a status banner; the throughput memories hold superseded numbers (e.g. "193 msg/s", "52×
short") that must be corrected **in place**, not duplicated.

**Steps.**

- **H1 — Backlog items `#206+` for each build lever.** One entry per lever/experiment (demo instrument, the
  `txn/msg` + `bytes/msg` counters, the per-PID CPU collector, the tempdb rewrite, the `accepts=` seam ADR, the
  shard-curve experiment, the **2-point shard probe (#218)**, the **harness-invariant guard (#219)**, and the
  **intra-message concurrent-transform lever (#214)**), each with the mandatory `🔢`/`🚧` status banner. Next free
  number after this pass **#220**.
  *Falsifier:* `backlog_status_check.py` fails ⇒ a banner is missing/malformed. — **🔍 FABLE REVIEW**
  (mechanical doc edits; the status-check CI catches format errors).

- **H2 — Update the throughput memories (do not duplicate).** Update in place — `mf-throughput-plan-2026-07`,
  `mf-shardcert-ladder-defects`, `mf-outbound-claim-wall`, `mf-per-interface-throughput-bound`,
  `mf-bench-attribution-policy`, `mf-aws-bench-rig-ops`, `mf-pipeline-commit-bottleneck` — with the
  total-events reframe, the 5.79×/≤2.07× honest gap, the harness-gap finding, and the plan spine; one fact per
  file, frontmatter (`name`/`description`/`metadata.type`), one `MEMORY.md` index line each, `[[slug]]`
  cross-links. Correct the stale numbers rather than appending.
  *Falsifier:* a stale number survives in a memory file after the pass ⇒ the update missed it. — **⚙️ SOLO**
  (mechanical memory writes).

**Exit criteria.** Backlog banners pass CI; the seven memories corrected in place with cross-links.

**Effort (estimate).** H1 ~1 session; H2 ~1 session.

---

## 3. The critical path

The plan's value is front-loaded onto **one cheap experiment**. Everything expensive is gated behind it.

| step | annotation | gates | note |
|---|---|---|---|
| **A3** per-PID CPU collector | 🧠 | **C1, C2, C3b, C4, E2, G1** — every CPU-attributed verdict | the one Phase-A step on the critical path to C1 |
| A0 yardstick (B10) | 🧠 | every published gap figure | removes the 9× phantom |
| A5 code-facts (ROUTED dispatcher) | 🧠 | F1 (`accepts=`), F2 (`fifo_claim_batch`) | read, don't extrapolate |
| B1 tempdb prototype (laptop) | 🧠 | F3 (engine tempdb rewrite) | kills the lever in hours, not rig-days, if flat |
| **C1 2-point shard probe (N=1 vs N=4)** | 🧠 | **C4, Phase D instrument, Phase F levers, G1** | **the single cheapest experiment that could kill the plan** |
| C2 claim-mode lane sweep | 🧠 | F3 (rewrite value at scale), any claim-mode choice | finds the crossover; no flip; **upper rungs (→1,500 lanes) gated on the D2/#216 traffic driver** |
| C3b production-shape ceiling | 🧠 | F1 **and** F2 (both 2H levers) | the `2H` thesis's own falsifier |
| C4 full shard curve | 🧠 | any shard count for parity | skipped if C1 already declines |
| D1–D3 demo instrument | 🔍/🧠 | E1, E2, G1 | the owner's actual deliverable |
| E2 smallest credible demo | 🧠 | which Phase-F lever to build | names the wall at real scale |
| F1–F5 levers | ⚙️→🧠 | G1 (full demo) | build only the measured-binding one; F5 (intra-message concurrent transform, #214) is the largest single hub-ceiling lift but P3 — build only if F1/F2 didn't clear it |

**The single cheapest experiment that could kill the plan is C1 — the 2-point shard probe (N=1 vs N=4).** It
runs in ~1 session on the current 8-vCPU boxes and needs only A3 as a prerequisite. If it shows a declining
per-shard curve, the "parity is an `N`-sizing exercise" thesis is dead with two points, the full C4 sweep is
skipped, and the whole effort re-centres on Phase F levers rather than shard scaling. **Fire it as early as the
rig allows — in parallel with the rest of Phase A, gated only by A3 — not after Phase A/B completes.**

Fast paths through the tree: **if C1 declines**, skip C4 and re-prioritise F3/F4 (shared-store levers) over the
instrument's headline. **If B1 is flat**, drop F3 and rely on the claim-mode measurement (C2) alone — **never**
by flipping to `per_lane`. **If C3b matches `(8,8)`**, drop both F1 and F2.

Downstream of the C1/C4 shard curve, the demo-instrument build (Phase D) and the cheap-lever pre-work can proceed
in parallel — and **C2's 1,500-lane rung specifically depends on D2's traffic driver, so it interleaves with
Phase D rather than fully preceding it** (C1, the cheap killer, does not). The smallest-credible-demo (E2) is the
bridge that names the at-scale wall and so decides which Phase-F lever is worth finishing first.

---

## 4. What we cannot claim yet

Each row is a statement that is **not yet supportable**, and the single measurement that would license it.
Nothing in this list may be published ahead of its measurement.

| blocked claim | unblocked by | until then |
|---|---|---|
| any engine-vs-store attribution; any CPU/GIL verdict | **A3** (per-PID CPU) | attribution is blind engine-side; a plateau is unassignable |
| any honest gap figure | **A0** (B10 units) | every "52×" is 9× inflated; true fleet gap is 5.79× |
| any capacity/headroom stated in txn/s | **A1/C3b** (`txn/msg`) | `3 + 2H + 2N` is a model, never a measurement; the 4.64 txn/event and ~1.6× headroom are assumption-blocked |
| the parity byte-budget claim; adopter drive sizing | **A2** (`bytes/msg`) | never measured; ~11 KB and ~27 KB/event are estimates with stated assumptions |
| the estate's real weighted cost | static `(H,N)` over all inbound modules | the non-ADT traffic is an `H=1, N=1` assumption |
| which bottleneck production actually has | **C3b** (production-shape ceiling) | `dests=8` measures an outbound mix production lacks |
| whether `fifo_claim_batch` is a default-flip or a no-op | **A5** (read the ROUTED dispatcher) | UNVERIFIED whether a batched claim also batches the handoff |
| any claim-mode choice; that `per_lane` "generalises" | **C2** (lane sweep) | pathologies are regime-specific; the crossover is unknown |
| that the tempdb rewrite helps at the real lane count (~1,500) | **B1 + C2** | isolated `claim_mean` gain and its scale-dependence both unmeasured |
| the `2H`-reduction levers are worth building | **C3b** (`H` moves the ceiling) | if `(20,4)` == `(8,8)`, `H` does not matter |
| **any shard count for parity; that horizontal scaling closes the gap at all** | **C1 → C4** (shard curve) | 90 events/s is a 4-shard-fleet point; `N` was never varied |
| any 45M/day capacity claim | **G1** (the full demo) | everything upstream is a projection until the flat run sustains |

On its own, the measurement work delivers **zero additional msg/s.** It delivers the ability to *believe the
next number*, and a decision tree whose branches are settled by experiments that do not yet exist. The path to
520.83 is horizontal — `N`-active shards on one unified store — and whether that path exists at all is C1/C4,
**the one experiment nobody has run.**

---

## 5. Do-not-do

Settled; do not resurrect without new evidence.

| lever / action | status | why |
|---|---|---|
| **Flip the `claim_mode` default to `per_lane`** | **NO-GO** | catastrophic at 1,500 lanes: ADR 0066 measured ~18k empty `UPDLOCK` claims/s at **zero messages** (92% CPU, `LCK_M_U` convoy), and it **drops messages** at high fan-out. `pooled` is the default *because of* connection scale. The fix is the tempdb rewrite of the pooled claim (F3), never a mode flip. |
| Free-threaded CPython (ADR 0053) | **NO-GO** | measured below the ≥10% bar |
| Executor-round-trip fusion (ADR 0071 B5) | **NO-GO** | < 10% bar; ~107 msg/s ceiling |
| Database-tier sharding (ADR 0039) | **shelved** | the unified store wins (ADR 0063) |
| Language rewrite | **rejected** | guts the code-first-Python differentiator; re-proves the whole core |
| Raising `--drain-timeout` past ~300 s | **re-arms B7** | a healthy soak then reads `FROZEN_TAIL` (false negative) |
| Quoting any pre-2026-07-10 collapse magnitude | **B6-contaminated** | collapse **verdicts** stand; **magnitudes** are truncated by the sink-window bug |
| A second engine box as a capacity lever | **NO-GO** | active-passive HA — one leader runs the graph; engine shards are subprocesses on one box; active-active was dropped 2026-06-18 with its code removed. A second box idles at ~0% while box one saturates. It is the HA cost, not a throughput resource. |
| Publishing any shard count or capacity number ahead of its measurement | **forbidden** | every prior confident-but-wrong number had the wrong provenance; see §4 |
