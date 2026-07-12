# 0098 — Four store-side scaling levers are measured dead ends

> ⚠️ **TITLE CORRECTION (2026-07-12, same day).** The allocated filename still reads
> *"…transaction amortization is the only path to 45M/day."* **That title was WRONG and is withdrawn.** It asserted a
> *positive* conclusion ("txn amortization is the path") that this ADR's evidence **does not support** — an
> **elimination inference**: rule out four levers, crown the survivor. That is the precise error class
> [ADR 0101](0101-pre-registered-falsifier-discipline-for-performance-measurement.md) exists to forbid, and
> [ADR 0069](0069-durable-write-throughput-lever.md) had *already measured against it* nine days earlier.
> **What this ADR establishes is entirely NEGATIVE: four levers are dead ends.** What comes next is
> **[ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md)**, which withdraws group-commit
> and gates the survivor behind a measurement. The filename is retained because the number was allocated against it
> (the ledger gate keys on the number); **the H1 above is the authoritative title.**

- **Status:** **Accepted (2026-07-12)** — this ADR *closes* options. **It authorizes no build and endorses no lever.**
  What to do next is [ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md).
- **Date:** 2026-07-12
- **Related:** [ADR 0051](0051-corepoint-throughput-parity-strategy.md) (parent — its *measure-first* phase is what
  produced this) · [ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md) (the build) ·
  [ADR 0037](0037-multi-process-sharding-l3.md) (engine sharding) ·
  [ADR 0063](0063-no-split-store-unified-store-for-sharding.md) ·
  [ADR 0071](0071-cut-executor-round-trips-b5.md) (the prior fusion attempt) ·
  [ADR 0084](0084-accepts-router-seam.md) (`accepts=`, the first txn/event lever, **merged**) ·
  `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` (the evidence) · CLAUDE.md §2

---

## Context

[ADR 0051](0051-corepoint-throughput-parity-strategy.md) set the strategy: **measure first**, prefer durable-write
levers, **no engine rewrite**. It has stood as *Proposed* since 2026-06-28 precisely because the measurements had not
been taken. **They have now been taken.** This ADR records what they foreclose.

The target is **45,000,000 messages/day = 520.83 TOTAL events/s, flat**, across **1,500 connections**
(`events = ingress × (1 + dests)`; see `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` §2 and the ADR 0051 update).

The working hypothesis for most of this programme was that the gap was a **store-side** problem — that enough shards,
or a fix to the one hot query, or the removal of one contention point, would close it. **Seven rig runs (C1–C7) say
otherwise.** The last three are decisive and are the basis of this ADR:

| run | question | result |
|---|---|---|
| **C5** | how hard can ONE shard be driven at N=8, latch-free? | **`R ∈ [2, 3)`** — 2/shard sustains; **3/shard collapses, reproduced**. The rate a cleared N=16 would need is **3.62/shard**. → **`R < 3.62`.** |
| **C6** | is the collapse blocked on a resource **convoy**? | **AMBIGUOUS-STRUCTURAL.** The convoy floor was met in **0 of 288 samples**; largest suspended group **2**; max blocking-chain depth **1**. **No lock CONVOY, no shared latch/page CONVOY, no memory-grant CONVOY, no spill CONVOY.** ⚠️ **Keep the word "convoy."** The detector samples `dm_os_waiting_tasks` at a **10 s cadence** and is **blind by construction to any non-shared cost** — a per-query spill, a per-call CPU cost or scheduler queueing **cannot form a convoy** and would always return this null. **"No convoy observed" ≠ "not a spill."** |
| **C7** | is the ceiling a **parallelism** config default? | **`MAXDOP=1` refuted as a removable cause — and parallelism is LOAD-BEARING.** DB-scoped `MAXDOP=1` made the collapse **worse** (49.4% → 20.6% delivered) **and degraded the N=8@2 rung** (→ 75.7%, 28,106 stranded) — against a baseline for that rung that is itself run-to-run variable (0–3,175 stranded). Direction credible; cross-session, no same-session control. |

**C5 is decisive, not a rig artifact.** The pre-registered co-constraint bar is **85% `max_core%`, checked against
the PEAK**. At the c5-b collapse the engine box **peaked at 59.7%** (mean 39.5 / p95 50.5, on the upsized 16-vCPU
m7i.4xlarge) with the load-gen at **8.5% peak** — far under the bar, so the carve-out that would have deferred the
verdict did **not** fire. *(Do not quote the mean against the bar.)*

> 🔴 **RIG CAVEAT — C4 is not on the same rig as C5/C6/C7, and this ADR must not rest on it unqualified.** C1–C4 ran
> on an **8-vCPU** engine box; C5/C6/C7 on **16 vCPU** (upsized 2026-07-12). **C4's N=16 arm is therefore 16 shard
> processes on 8 vCPU** — a configuration the STATUS doc's rig table calls *"core contention, not store scaling"* —
> and **per-query CPU shares are exactly what core contention distorts.** C4 also handed back **no artifact at all**.
> The CPU attribution was **never re-run** post-upsize. Every C4-derived number below is tagged accordingly.

**The CLAUDE.md invariants that bound every candidate fix** (§2, verbatim):

> the transactional **staged queue on SQLite (WAL)** gives at-least-once delivery, retries, replay, and dead-lettering
> *without* a separate broker. The inbound connection is ACKed **only after** the raw message is durably committed to
> the **ingress** stage … Every subsequent stage **handoff** (ingress→routed, routed→outbound) is a **single committed
> transaction** (claim → produce-next-stage rows → complete-this-stage), so a message is never lost or partially
> handed off

> **every received message is persisted before the ACK** … nothing is accepted-and-dropped

That invariant is the cost model. **A message's price is denominated in committed transactions, not in messages** —
and no store-side tuning changes the count of them.

## Decision

**The store-side search is CLOSED. Four candidate levers are declared measured dead ends and will not be pursued:**

1. **More engine shards (N-sizing) — DEAD as a standalone path.** C5: `R ∈ [2,3) < 3.62`. Even a *fully cleared* N=16
   would still miss 520.83 events/s. Adding shards cannot get there.
2. **A contention / lock-granularity fix — NOT PURSUED.** C6 observed **no convoy** — no lock, latch, page, grant or
   spill **convoy** — so there is no shared-resource blocker for such a fix to remove. ⚠️ **This is a null from an
   instrument with two stated blind spots** (non-shared costs; a 10 s sampling cadence whose minimum detectable
   convoy duration was never established). **"No convoy observed" is not "there is nothing there,"** and it says
   nothing about a *per-query* spill. Not pursued — not proven absent.
3. **A single-query CPU rewrite — NOT SUPPORTED, on cost and risk.** This covers the `claim_fifo_heads` rewrite, the
   `list_fifo_lanes` rewrite, **and** the whole-`StageDispatcher` lane-servicing-path rewrite. C6 observed **no
   convoy** to target, and **C5 showed the ceiling is below target even if one were removed** — that second leg is
   the load-bearing one and it is artifact-backed. ⚠️ **The "claim-only rewrite is PROVEN insufficient" claim is
   WITHDRAWN.** It rested on C4's family map (claim #2 at 40.33%, behind `list_fifo_lanes` at 47.46%) plus a §3d
   coupling computation — but **C4's own reconciliation gate failed** (*"family precedence is not authoritative at
   any N"*), **§3d isolates only the per-read factor** while the dominant **4.3× read-count growth remains
   backlog-coupled**, and **the data came from a 16-shards-on-8-vCPU arm with no artifact.** The NO-GO stands on
   cost and risk. It is **not a proof.** **[ADR 0071](0071-cut-executor-round-trips-b5.md) is the cautionary
   precedent** — a prior fusion/round-trip-cut that was a **NO-GO to promote** and ships default-OFF.
4. **`MAXDOP=1` (DB-scoped, at N=8 on this workload) — DEAD, and actively harmful.** C7: serial plans made things
   worse and degraded a rung that passes under the default. **Do not set `MAXDOP=1` on the store.** ⚠️ **Scope: C7
   refutes `MAXDOP=1`, not the parallelism-tuning class.** MAXDOP=2/4, cost-threshold tuning and query hints are
   **UNTESTED** — and *"parallelism is load-bearing"* is what keeps them live.

**→ What remains is a CANDIDATE, not a conclusion.** Reducing committed transactions per event ("txn/event") is the
only lever of the original four-plus-one set still standing — but *standing* is all it is. **This ADR does NOT endorse
it.** [ADR 0084](0084-accepts-router-seam.md)'s `accepts=` seam (merged, #952/#213) already shipped one instance of it,
and **[ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md) — which WITHDRAWS group-commit
([ADR 0055](0055-group-commit-durable-write.md)) and gates the survivor behind a pre-registered measurement — is what
happens next.** Do not read "last man standing" as "the answer."

> 🔴 **This is an ELIMINATION over a candidate set that was never shown to be exhaustive — and Phase 4's own
> falsifier currently points AGAINST it.** Four levers were tested; whole classes were not (per-call store CPU,
> per-query spill, allocator churn, scheduler queueing, network RTT, **and everything engine-side** — the per-PID
> CPU collector still reads `0.00`). **"Last man standing" is not a mechanism.** And Phase 4's pre-registered
> falsifier reads *"if measured `txn/s` sits far below the store's ~27–29k c/s commit ceiling, group-commit buys
> little"* — the best available estimate is **~350 txn/s** at the measured bracket and **~2,416 txn/s (9% of the
> ceiling)** even at the full target. **`txn/s` has never been measured. ADR 0099 must measure it BEFORE the build
> is funded.**

**This decision must not break:** nothing. It authorizes no code. It *removes* options.

## Options considered

1. **Close the store-side search; commit to transaction amortization. CHOSEN.** It is the only lever the evidence
   leaves standing, and it attacks the quantity the reliability invariant actually prices in.
2. **Keep scaling N (more engine shards).** Rejected: **measured insufficient** (C5, `R < 3.62`). Note this does *not*
   retire engine sharding as a *feature* ([ADR 0037](0037-multi-process-sharding-l3.md)) — it retires it as *the path
   to 45M/day*.
3. **Rewrite the pooled claim / dispatcher lane path for CPU.** Rejected: C6 found no single blocker; C5 shows the
   ceiling is short even if one were removed; ADR 0071 shows this class of fix has already failed to promote here.
4. **Hunt the contention point harder (more wait decomposition).** Rejected: C6 *was* that hunt, it was
   pre-registered, and it returned **no convoy in 288 samples**. Repeating it is not a plan.
5. **Tune store parallelism (`MAXDOP` / cost-threshold).** Rejected: C7 measured it **harmful**.
6. **Database-tier sharding (split the store).** Already shelved by
   [ADR 0063](0063-no-split-store-unified-store-for-sharding.md)/[ADR 0039](0039-database-tier-sharding-l5.md); nothing
   here revives it.

## Consequences

**Positive**
- **Three tempting dead ends are removed before anyone builds them.** The claim/dispatcher rewrite in particular was
  weeks of work aimed, as it turns out, at a query that C6 shows is not a blocker.
- **[ADR 0051](0051-corepoint-throughput-parity-strategy.md)'s measure-first premise is vindicated** — measuring first
  is exactly what prevented the wrong build.
- **The plan collapses to one lever**, which is a far easier thing to design, cost, and falsify.
- **`accepts=` (ADR 0084) is retroactively promoted** from a co-requisite to the first delivered piece of *the* plan.

**Negative / risks**
- **There is no measured bottleneck to point group-commit at — and its own falsifier currently points against it.**
  C6's AMBIGUOUS-STRUCTURAL means the gain from ADR 0099 is **derived from arithmetic (fewer commits per event), not
  observed**. Worse: Phase 4's pre-registered falsifier (*"if measured `txn/s` sits far below the ~27–29k c/s commit
  ceiling, group-commit buys little"*) has an antecedent that the **best available estimate satisfies** — ~350 txn/s
  measured-bracket, ~2,416 txn/s (9% of ceiling) at full target. **`txn/s` has never actually been measured.** This is
  the single most important caveat in this ADR and it is inherited by 0099, which **must measure `txn/s` before the
  build is funded**. **Do not let "the store-side search is closed" be read as "group-commit will work."** Those are
  different claims — and the second is currently *unsupported*.
- **C7 is a standing warning that an intervention can make things WORSE.** `MAXDOP=1` was a plausible, cheap,
  well-reasoned change that *hurt*. Group-commit must be default-OFF and cleanly backoutable.
- **The remaining gap is large — and larger than the raw number says.** Best *sustained* pooled fleet measured to
  date is **144.0 events/s RAW** (C3 config, N=8 × 2/shard × 9) against a 520.83 target = 3.62× short. ⚠️ **RAW is
  not PUBLISHABLE.** Under the project's **D4 publish rule** (*publish at ≤50% of the measured ceiling* —
  `docs/benchmarks/shardcert-ceiling-ladder.md`), the **publishable capability is 72.0 events/s and the honest gap
  is 7.23×.** **Quote 72.0 / 7.23×, not 144.0 / 3.62×.** *(The 3.62/shard **bar** C5 was tested against is derived
  the same raw way — but there the direction is conservative, so **C5's inequality verdict is unaffected and must
  not be re-derated.**)* Transaction amortization alone is **not** assumed to close it (see *Out of scope*).

**Out of scope**
- **This ADR does not claim group-commit reaches 45M/day.** It claims every *other* store-side route does not. What
  else is needed remains open and is 0099's problem to bound honestly.
- **Engine sharding as a feature** (ADR 0037) is untouched — it remains how the engine scales across processes; it is
  simply not the road to 520.83 events/s on its own.
- The **CPU-BOUND preclusion** (the offline 64.4% reconciliation — sourced to `HANDBACK_C4_2026-07-11.md` §0;
  **prose-only, no artifact computes it, and no C6 artifact backs it**) and **C4's `list_fifo_lanes` family
  ratification** remain formally unresolved — **and are now low-stakes**: the recommendation is robust either way,
  because if the store *is* CPU-bound the fix is still *"fewer store round-trips per event"*, which is still this
  lever. **Do not re-litigate them before building.**
- **C4's per-query CPU attribution was never re-run on the 16-vCPU box.** If any future decision needs the family
  ordinal, it must be **re-measured** — the existing one is from a 16-shards-on-8-vCPU arm. No decision in *this* ADR
  depends on it (the C5 inequality and the C6 null carry the load), which is why it is recorded here rather than
  blocking acceptance.
- **The C5/C6/C7 raw artifacts live outside the repo** (`OneDrive/Desktop/MEFOR/aws-bench/…/HANDBACK_2026-07-12/`).
  Committing them under `docs/benchmarks/results/` is an open owner decision; until then this ADR's evidence base is
  not auditable from the repo alone.

## To resolve on acceptance

- [x] Does `R < 3.62` survive the engine-box co-constraint carve-out? — **Yes.** The bar is **85% `max_core%`, checked
      against the PEAK**: the c5-b collapse **peaked at 59.7%** (mean 39.5 / p95 50.5) with the load-gen at **8.5%
      peak**; the carve-out did not fire (C5 §3.2). *(An earlier draft quoted the **mean** (~38%) against the bar —
      corrected. Always check the peak.)*
- [x] Was a convoy **observed**? — **No.** 0/288 samples met the floor (C6). ⚠️ *Observed*, not *excluded*: the
      detector is blind to non-shared costs and samples at a 10 s cadence.
- [x] Is it a parallelism config default? — **`MAXDOP=1` is not, and forcing serial plans is harmful** (C7).
      *(MAXDOP=2/4 and cost-threshold tuning remain UNTESTED.)*
- [ ] **Does transaction amortization actually buy throughput?** — **OPEN, and it is the whole bet.** Owned by
      [ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md), which must carry a
      pre-registered rig falsifier (a decision rule, a manipulation check, a same-session control, a stated null band,
      and an explicit *what result makes us abandon this*) in the style of C5/C6/C7.
