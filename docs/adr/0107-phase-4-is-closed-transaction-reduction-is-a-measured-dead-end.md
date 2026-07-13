# 0107 — Phase 4 is closed: transaction reduction is a measured dead end

- **Status:** **Accepted (2026-07-13)** — closes options; authorizes no build. **Do not build F2 or F3.**
- **Date:** 2026-07-13
- **Closes:** **[ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md)** §Decision 4 — the P0
  gate it pre-registered has **run and returned ABANDON**. This ADR is the closure 0099 pre-committed to writing.
- **Terminates:** **[ADR 0057](0057-inline-step-a-fast-path.md)** (inline Step-A fast-path) — **⛔ DO NOT PROMOTE.**
  Stays default-OFF, permanently.
- **Related:** [ADR 0098](0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md)
  (the four store-side dead ends) · [ADR 0101](0101-pre-registered-falsifier-discipline-for-performance-measurement.md)
  (the discipline P0 obeyed) · [ADR 0071](0071-cut-executor-round-trips-b5.md) (B5 — the NO-GO band P0's ceiling lands in) ·
  [ADR 0055](0055-group-commit-durable-write.md) (withdrawn) · [ADR 0051](0051-corepoint-throughput-parity-strategy.md) ·
  [ADR 0084](0084-accepts-router-seam.md) (`accepts=`, merged) · `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md`

---

## Context

[ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md) withdrew group-commit, ratified
[ADR 0069](0069-durable-write-throughput-lever.md), and left exactly one surviving throughput lever: **reduce committed
transactions per event**, whose shipped instance is **inline stage-fusion ([ADR 0057](0057-inline-step-a-fast-path.md))** —
already in the tree, never once enabled in a rig run. 0099 refused to authorize the build and **pre-registered a
falsifier (P0)** with a decision rule fixed before the run, a manipulation check, a same-session control, a stated null
band, and a regression band.

**P0 ran on 2026-07-13. It returned ABANDON.** This ADR records the closure.

### What P0 measured (engine build `28f860e`, m7i.4xlarge engine / i4i.2xlarge store, feature ON, `H=D=dests=1`)

**The intervention unambiguously engaged.** `committed_txns/msg` fell **10.4746 → 7.4865** — a **2.99 absolute drop
(28.5%)**, far clear of the pre-registered ≥0.9 floor. The disarmed-arm trap (`H=8` ⇒ the `len(names)==1` gate never
fires) was avoided and shape-verified on every arm.

**And throughput did not move.**

| arm | sustainable ingress | `committed_txns/msg` |
|---|--:|--:|
| **A** — inline OFF (3 reps) | **23.697** | **10.4746** |
| **B** — inline ON (3 reps) | **23.565** | **7.4865** |
| **B vs A** | **−0.56%** | −2.99 (−28.5%) |

**−0.56% is inside the pre-registered NULL BAND (−3%…+3%)** and **smaller than either arm's own replicate spread**
(A ±1.70%, B ±2.76%). FIFO `0/0`, `stranded=0`, `no_loss` ✓ on all 16 rungs.

### ⭐ The decisive result is ARM E — it bounds the whole lever class, not just fusion

Arm E swept **H ∈ {1,2,4,8}** at fixed `D=1` on the **unmodified split path** with no-op transforms — i.e. it measured
the cost of the **entire `2H` term by ADDING it**, which is exactly what F2 exists to remove:

| H | measured `committed_txns/msg` | sustainable ingress |
|--:|--:|--:|
| 1 | 9.89 | 22.182 |
| 2 | 13.58 | 21.809 |
| 4 | 18.80 | 20.850 |
| **8** | **29.20** | **19.588** |

**A ~3× swing in actual committed transactions per message (×2.95) moves throughput by −11.7%.**

> ### **Elasticity `d(ln throughput) / d(ln txn) = −0.115`.**

**That single number closes Phase 4.** A lever that weak cannot close a **5.79× gap**. To buy even the pre-registered
**+8% PROCEED bar** you would have to cut `txn/msg` by **~50%**.

### The one hole this WEAKENS but does NOT close — "P0 only ran H=1, fusion's *weakest* shape"

> ## ⚠️ CORRECTION (2026-07-13, same day, caught in adversarial verify). An earlier draft of this ADR claimed **"F2 cannot clear the bar at any shape"** and that F2's best case **"lands inside ADR 0071 B5's already-rejected band."** **Both were FALSE, and they were mine.**
> **The arithmetic:** arm E's bound on F2 at H=8 is **+13.2%**. The pre-registered PROCEED bar is **+8%**. B5's band is
> **+6.5…+10.0%**. So **+13.2% is ABOVE the bar, and ABOVE B5's band — not inside it.** *A bound that permits clearing
> the bar cannot prove the bar cannot be cleared.* Even subtracting the **measured** H=1 give-back (−4.49 pts) leaves
> **+8.75%, still above +8%.**
> **The ABANDON verdict is UNAFFECTED** — it rests on the **pre-registered primary A/B null (−0.56%)**, not on arm E.
> Arm E is corroborating context, **not a proof of impossibility.** This was a textbook over-read of the exact class
> this programme has retracted two results for; it is recorded rather than quietly fixed.

A fair objection: F2's value is removing the `2H` term, which is trivial at H=1 and large at the production shape
(H≈20). **Here is exactly how far arm E takes us, and where it stops:**

- **F2's absolute best case at H=8** — recovering everything arm E lost by adding the `2H` term — is
  `22.182 / 19.5885 = **+13.2%**`. **That is ABOVE the +8% PROCEED bar.** Arm E therefore **does not exclude** F2
  clearing the bar at high H. **Say so plainly.**
- **Two deratings apply — and both are ARGUED, not measured:**
  (i) arm E's fall is **not purely transactional** — raising H also adds H routed rows, H routed-lane claims and H
  **transform executions**; **F2 removes the stage, not the transforms**, so it recovers strictly less than 11.7%.
  (ii) fusion pays a **stage-overlap give-back that grows with H** (it serializes H transforms onto the ingress lane —
  the ADR 0001 Step-B split exists precisely to prevent that). At H=1 that give-back was **measured**: arm E's
  elasticity predicts **+3.93%** for fusion's 28.5% cut, and fusion **delivered −0.56%** — a **−4.49 pt** give-back.
  **Applying that H=1 give-back to the H=8 ceiling still leaves +8.75% — above the bar.** The case for "below the bar"
  rests on the give-back *growing* with H, **which is not measured.**
- **⛔ AND F2 CANNOT BE MEASURED WITHOUT BUILDING IT.** The fusion gate is `inline and len(names) == 1`
  ([`wiring_runner.py:3712`](../../messagefoundry/pipeline/wiring_runner.py#L3712)) — **inline fusion is H=1-only by
  construction.** *That is why P0 ran at H=1.* Extending fusion to H>1 **is** F2. **There is no cheap arm that settles
  the high-H question; the only way to measure F2 is to build the large 3-backend surface first.**

**So the honest statement is:** *fusion buys nothing at the only shape it can be measured at; its best conceivable case
at high H is thin (+13.2% raw, ~+8.75% once the measured give-back is applied — i.e. hovering at the bar); and it
cannot be tested without building it.* **That is a decision on evidence, cost and risk — not a proof of impossibility.**

## Decision

**1. Phase 4 is CLOSED. `txn/event` reduction is a MEASURED DEAD END.** Do **not** build **F2** (complete the fused
primitive so `H` leaves the transaction formula) or **F3** (adaptive idle-sweep backoff — its premise was the same txn
theory). It joins the four store-side dead ends of
[ADR 0098](0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md).

**2. [ADR 0057](0057-inline-step-a-fast-path.md) is ⛔ DO NOT PROMOTE.** Inline stage-fusion **works** — it cut
committed transactions by 28.5% exactly as designed — and it **buys nothing**. It stays **default-OFF, permanently**.
Do not enable `inline=` on a production inbound.

**3. State the conclusion PRECISELY** — the loose version invites a re-open:

> ⛔ **Do NOT write "the wall is per-message, not per-transaction."** Arm E shows transactions **do** affect throughput —
> the elasticity is **−0.115**, not zero. The defensible claim is:
> **"The txn→throughput coupling is real but far too weak to be a lever. A 3× swing in committed transactions moves
> throughput ~12%. No transaction-reduction mechanism — fusion, group-commit, or any other — can close a 5.79× gap
> against an elasticity of −0.115."**
> The loose version invites someone to point at arm E's monotonic fall and reopen a settled question.

**4. F1 SURVIVES, but not as a throughput lever.** Folding `record_ack_sent` into `enqueue_ingress` removes one
pure-overhead transaction from the **ACK critical path** on every message, every path, every backend. P0 provides **no
evidence against it** and it was never load-bearing here. **Ship it, if at all, on latency/cleanliness grounds — never
on a throughput claim** (the elasticity forbids one). Owner's call; it is not gated by this ADR.

**5. Do NOT open a fifth store-side falsifier.** Four have now returned negative (C5, C6, C7, P0). **The search is not
converging because it is aimed at the wrong box** (see *Consequences*).

**This decision must not break:** nothing. It authorizes no code and removes options.

## Options considered

1. **Close Phase 4; mark 0057 do-not-promote. CHOSEN.** The pre-registered rule fired, and arm E independently bounds
   the lever class below the bar at every shape.
2. **Build F2 anyway, betting it pays off at production H (≈20).** **Rejected — but on cost/risk, NOT on a proof that
   it would fail.** Be honest about the trade: arm E caps F2's best case at **+13.2%** at H=8, which is **above** the
   +8% bar; applying the measured H=1 give-back (−4.49 pts) leaves **+8.75%**, still marginally above it. So the
   quantified case does **not** exclude F2 clearing the bar. What rejects it: **(a)** fusion delivered **−0.56%** at the
   only shape where it can be measured, despite cutting 28.5% of transactions; **(b)** the deratings that would push it
   below the bar (transform executions F2 can't remove; a give-back growing with H) are **plausible but unmeasured**;
   **(c)** [ADR 0071](0071-cut-executor-round-trips-b5.md) B5 is a standing precedent for exactly this class —
   a 6× round-trip reduction that delivered +6.5…+10% and was a **NO-GO to promote**; **(d)** F2 is a **large,
   permanent, 3-backend surface** (3 backends × 3 statement variants) touching the code where the prior SQL Server
   per-lane FIFO **release blocker** lived. **Paying that cost to chase a best case that is thin even if everything
   breaks our way is a bad bet — but it is a bet we are declining, not a possibility we have excluded.**
3. **Build F2 *just enough* to measure it at H=8, then decide.** **Rejected, and this is the option worth naming
   explicitly** — because it is the only one that would actually settle the question. **You cannot measure F2 without
   building it:** the fusion gate is `inline and len(names) == 1`, so inline fusion is **H=1-only by construction**, and
   extending it to H>1 *is* F2. There is no cheap arm. So the choice is binary — **pay the full build cost to learn the
   answer, or decline on the evidence above.** We decline. **If the owner ever wants the question truly settled, this is
   the only path, and it is not cheap.**
4. **Widen the null band / re-cut the decision rule.** Rejected — that is precisely the post-hoc goalpost-moving
   [ADR 0101](0101-pre-registered-falsifier-discipline-for-performance-measurement.md) forbids, and the reason two prior
   results were retracted.

## Consequences

**Positive**
- **A large, permanent, 3-backend build (F2) was stopped by a measurement that cost zero production code.** F2's own
  plan called it *"the real cost of this plan… not 'flip a flag'"* — 3 backends × 3 statement variants, touching the
  code where the prior SQL Server per-lane FIFO **release blocker** lived.
- **The lever class is bounded, not merely one instance of it.** Arm E's elasticity kills group-commit, fusion, and any
  future *"just batch/fuse/reduce the transactions"* proposal in one number. **Write it down so nobody re-derives it.**
- **The measurement programme worked.** Four pre-registered falsifiers, four honest negatives, zero retractions.

**Negative / risks**
- **We now have NO identified throughput lever, and the wall is UNNAMED.** That is the honest position. It is
  substantially better than having built F2 and discovered it at the end.
- **The 45M/day target has no measured path today.** Any parity claim must say so.

**Out of scope — and this is now the frontier**
- ⭐ **The ENGINE side has never been attributed.** Every falsifier in this arc (C1–C7, P0) was aimed at the **store**.
  Meanwhile the engine box sat at **~38–60% `max_core`** while the store saturated, and the earlier WS-B work put the
  per-box wall at *"76% plumbing"*. [ADR 0098](0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md)
  already flagged it: *"the per-PID CPU collector still reads `0.00`; nothing in this programme has attributed
  engine-side cost."*
- **Prerequisite:** the per-PID CPU collector must be **fixed** before an engine-side falsifier can be posed — its being
  broken is *why* the question was never asked. That is the next piece of work, and it is instrumentation, not a build.

## To resolve on acceptance

- [x] Does cutting `txn/event` move sustained throughput? — **No.** B vs A = **−0.56%**, null band, with the
      manipulation check passing (−2.99 txn/msg).
- [~] Does it help at a shape where fusion has more to remove (H=8, H=20)? — **NOT SETTLED, and we are declining to
      settle it.** Arm E bounds the entire `2H` term at **≤11.7%** of throughput → F2's ceiling at H=8 is **+13.2%**,
      which is **ABOVE the +8% bar** (and above B5's band). Applying the *measured* H=1 give-back leaves **+8.75%** —
      still above. **So the data does not exclude F2 clearing the bar at high H.** And **F2 cannot be measured without
      being built** (the fusion gate is `len(names)==1`; inline fusion is H=1-only by construction). We decline on
      cost/risk/evidence — see *Options considered* #2 and #3. **Do not record this as proven.**
- [x] Is the premise ("per-message txn count is the constraint") alive? — **No.** Elasticity **−0.115**.
- [ ] **Where is the wall?** — **OPEN, and now the only question that matters.** Not the store (C5/C6/C7/P0). Fix the
      per-PID CPU collector, then pose an **engine-side** falsifier.
- [ ] **F1** — ship the ACK-audit fold on latency/cleanliness grounds? **Owner's call**, not gated by this ADR.
