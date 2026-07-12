# 0099 — Phase 4 reconciled: group-commit is WITHDRAWN; the surviving lever is gated behind a measurement

> ⚠️ **The allocated filename reads *"Phase-4 group commit — amortize the per-event transaction cost."* That was the
> title I allocated before reading the ledger. **It is wrong.** Group-commit is not being built — it is being
> **withdrawn**. The filename is retained because the ledger gate keys on the *number*; **the H1 above is the
> authoritative title.**

- **Status:** **Accepted (2026-07-12)** for the withdrawal + the gate. The *build* it gates (inline fusion) remains
  **Proposed and unfunded** until the P0 measurement clears its bar.
- **Date:** 2026-07-12
- **Supersedes:** **[ADR 0055](0055-group-commit-durable-write.md)** — *Group-commit for the staged queue, the
  durable-write ceiling-mover* (Proposed 2026-06-29). **WITHDRAWN by this ADR.**
- **Ratifies:** **[ADR 0069](0069-durable-write-throughput-lever.md)** — *Durable-write is not the throughput wall*
  (Proposed 2026-07-03). Its conclusion stands and is adopted.
- **Gates:** **[ADR 0057](0057-inline-step-a-fast-path.md)** — *Inline Step-A fast-path* (Proposed 2026-06-30).
- **Related:** [ADR 0098](0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md)
  (the four dead ends) · [ADR 0101](0101-pre-registered-falsifier-discipline-for-performance-measurement.md) (the
  discipline this ADR obeys) · [ADR 0071](0071-cut-executor-round-trips-b5.md) (the cautionary precedent) ·
  [ADR 0075](0075-per-hop-sql-statement-batching.md) (promoted default-ON) · [ADR 0051](0051-corepoint-throughput-parity-strategy.md) ·
  `docs/benchmarks/PLAN-PHASE4-GROUP-COMMIT.md` (the design work behind this)

---

## Context

### The ledger has been contradicting itself for nine days, and nobody noticed

Two ADRs, both still `Proposed`, both live, four days apart:

| ADR | date | says |
|---|---|---|
| **[0055](0055-group-commit-durable-write.md)** | 2026-06-29 | *"Group-commit for the staged queue — **the durable-write ceiling-mover**."* The build is *"**authorized now as a no-regret lever**."* |
| **[0069](0069-durable-write-throughput-lever.md)** | 2026-07-03 | *"**Durable-write is NOT the throughput wall**; the lever is engine feed concurrency."* |

**0069 measured 0055's premise and refuted it — and 0055 was never withdrawn.** The ledger simultaneously authorizes
a group-commit build and records that the thing group-commit optimizes is not the constraint. Any reader (human or
agent) picking up "Phase 4" inherits whichever one they find first. **This ADR ends that.**

### The measured case against group-commit

- **The commit tier is ~9% utilised.** ADR 0069 measured the store absorbing **~27–29k commits/s**; the demand at the
  *full* 45M/day target is **~2,416 commits/s**. **You cannot buy throughput by reducing your consumption of a
  resource you are barely using.**
- **~47.5% of the store CPU at N=16 is CLOCK-driven, not rate-driven — verified in code.** `list_fifo_lanes` is
  called from `StageDispatcher._sweep_loop`
  ([stage_dispatcher.py:972](../../messagefoundry/pipeline/stage_dispatcher.py#L972)), which fires on
  `pooled_sweep_interval` (**default 0.25 s**, [settings.py:854](../../messagefoundry/config/settings.py#L854)) —
  `await asyncio.wait_for(self._sweep_now.wait(), timeout=self._sweep_interval)`. **It runs at the same rate whether
  the pipeline is carrying 1 message/s or 1,000.** No transaction-reduction lever touches it. *(The 47.5% share is
  C4-derived and carries C4's rig caveat — see ADR 0098. The **clock-driven** property does not: it is read directly
  off the code and is unconditional.)*
- **The in-repo counterexample.** `claim_mode="pooled"` — the shipped default — commits **far fewer** transactions per
  event than `per_lane` (`claim_fifo_heads` coalesces many lanes' claims into one commit) and is **~2.8× slower**. If
  txn/event were the binding constraint, that ordering would be impossible. *(Not a clean contrast — pooled also adds
  the `list_fifo_lanes` scans, and per `mf-outbound-claim-wall` the `per_lane` advantage **inverts at 1,500 lanes**.
  It is not proof. It is enough to stop anyone calling the txn→throughput link established.)*
- **The precedent.** [ADR 0071](0071-cut-executor-round-trips-b5.md) (B5) cut thread crossings **6×** and pool-wait
  p95 **5×**, and delivered **+6.5 / +9.3 / +10.0%** — and was a **NO-GO to promote**. A large reduction in a
  plausible cost bought almost nothing. **That is the base rate for this class of lever in this codebase.**
- **C6 found no convoy and no single blocker** ([ADR 0098](0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md)),
  so there is no measured bottleneck for group-commit to point at.

### The invariant case against group-commit

Group-commit as ADR 0055 scoped it **cannot be built without breaking CLAUDE.md §2**:

- **Delayed durability breaks at-least-once, on PHI.** `DELAYED_DURABILITY` returns from `COMMIT` *before* the log
  block is flushed. `enqueue_ingress` commits → the listener **ACKs** → the sender drops its copy → a power failure
  loses up to 60 KB of unflushed log. **An ACKed message that does not exist.** The invariant is explicit: the inbound
  is ACKed *"only after the raw message is durably committed to the ingress stage."*
- **An app-side group committer on a pooled server DB is a concurrency *reduction*.** A transaction is bound to a
  connection: to put M handoffs in one transaction you must run them on **one connection, serially**, paying ~5(M−1)
  serialised round-trips to save (M−1) log flushes of ~0.17 ms. It gets **worse with distance** — the exact inverse of
  [ADR 0075](0075-per-hop-sql-statement-batching.md), which was promoted *because* it helps at distance.
- **SQL Server's log manager already group-commits** (ADR 0069's own `commit_storm.txt`). The only knob that raises
  its ratio is *concurrency* — which is ADR 0069's actual recommendation, and already exists.

## Decision

**1. [ADR 0055](0055-group-commit-durable-write.md) (group-commit) is WITHDRAWN — superseded by this ADR.** It is not
"deprioritised" or "deferred": its premise was measured false by ADR 0069, and its mechanism breaks the reliability
invariant. **Do not resurrect it. Do not enable `DELAYED_DURABILITY` on the store, ever.**

**2. [ADR 0069](0069-durable-write-throughput-lever.md)'s conclusion is RATIFIED and adopted:** durable-write is not
the throughput wall.

**3. The surviving Phase-4 mechanism is [ADR 0057](0057-inline-step-a-fast-path.md) inline stage-fusion — NOT
group-commit.** It reduces transactions by **fusing stages**, not by batching commits. **It is already implemented and
shipping in the tree, and it has never been enabled in a single rig run.**

**4. NO PRODUCTION CODE WILL BE WRITTEN FOR PHASE 4 UNTIL A PRE-REGISTERED MEASUREMENT (P0) CLEARS ITS BAR.** Per
[ADR 0101](0101-pre-registered-falsifier-discipline-for-performance-measurement.md), P0 must carry a decision rule
fixed before the run, a **manipulation check** (`SqlServerStore.committed_txns` — the counter already exists and is
already polled by `harness/load/enginepoll.py`), a **same-session OFF control**, a **stated null band**, and a
**regression band** — because a fusion that removes stage-level overlap can plausibly make throughput *worse*
(this is structurally the trade **C7's `MAXDOP=1` made, and it lost**).

**The first thing P0 must measure is `txn/s` itself — a number this programme has never measured.** If measured
`txn/s` sits far below the store's ~27–29k commits/s ceiling (best estimate: **~350 txn/s** at the current bracket;
**~2,416 txn/s** even at the full target), **the entire Phase-4 premise is dead and we stop.**

**This decision must not break:** at-least-once + ACK-after-durable-ingress-commit; count-and-log; strict per-lane
FIFO; finalizer-as-sole-disposition-authority; idempotent stage re-run. **Any Phase-4 build that cannot demonstrate
all five is rejected regardless of its throughput.**

## Options considered

1. **Withdraw group-commit; ratify 0069; gate inline fusion behind P0. CHOSEN.** It resolves the ledger
   contradiction, refuses to build on an unmeasured mechanism, and costs ~zero production code to find out.
2. **Build group-commit per ADR 0055.** Rejected: premise measured false (0069), commit tier ~9% utilised, and the
   delayed-durability variant **breaks at-least-once on PHI**.
3. **Build inline fusion (0057) now, without P0.** Rejected: the payoff is **derived, not observed**; there is no
   measured bottleneck it targets; and ADR 0071 is a standing example of a 6× cost reduction buying ~8%. **Also — it
   is already in the tree; we would be "building" something we could simply *turn on and measure* first.**
4. **Leave 0055 and 0069 both Proposed and pick later.** Rejected: that *is* the defect. Two live contradictory ADRs
   is how the wrong thing gets built by whoever reads the wrong one first.

## Consequences

**Positive**
- **The ledger tells one story again.** The next reader of "Phase 4" cannot be misled by 0055.
- **A build that was "authorized as a no-regret lever" — and would have broken at-least-once on PHI — is stopped.**
- **P0 is nearly free.** The mechanism ships already; the counter exists; the harness already polls it. We can learn
  whether the premise is alive for roughly zero production code.
- **`txn/s` finally gets measured.** The programme has argued about transactions for a month without ever counting them.

**Negative / risks**
- **We may find the whole Phase-4 premise is dead**, and be left with **no identified lever at all** — the wall is
  formally **UNNAMED** (C6). That is an uncomfortable but *honest* place to be, and better than building on a guess.
- **Withdrawing 0055 loses its storage/design work.** Its `shared_body` "store-once-deliver-many" idea may be worth a
  separate, correctly-designed BACKLOG item — but the version in 0055 was judged **fatal on invariants** (a non-atomic
  refcount release races an increment on the SQL Server pool and can **dead-letter an already-routed message**).
- **Turning ADR 0057 on may make things worse**, per the C7-shaped risk above. That is what the regression band is for.

**Out of scope**
- The **engine-side** wall. The per-PID CPU collector still reads `0.00`; **nothing in this programme has attributed
  engine-side cost.** ADR 0098's four dead ends are all *store-side*. This is now arguably the biggest unexplored area.
- A **latent bug found during this design work, unrelated to the decision but real:** `mark_batch_done`
  (`store/sqlserver.py`) iterates its finalize set in **dict insertion order** while the sorted helper
  `_lock_finalize_batch` sits **unused** — an unsorted multi-applock acquisition, i.e. a **live 1205 deadlock exposure
  today**. **Fix it independently of Phase 4; do not bundle it.**

## To resolve on acceptance

- [x] Do 0055 and 0069 contradict? — **Yes**, and 0055 is withdrawn.
- [x] Is group-commit buildable within the invariants? — **No** (delayed durability breaks at-least-once on PHI).
- [ ] **What is the measured `txn/s`?** — **UNMEASURED. This is P0's first job and the gate on everything else.**
- [ ] Does enabling ADR 0057 inline fusion move sustained events/s — up, down, or not at all? **Pre-register the null
      band and the regression band before the run.**
- [ ] Owner: commit the C5/C6/C7 rig artifacts into `docs/benchmarks/results/`? They currently exist **only on a
      OneDrive folder**, and three verdicts + two Accepted ADRs now rest on them.
