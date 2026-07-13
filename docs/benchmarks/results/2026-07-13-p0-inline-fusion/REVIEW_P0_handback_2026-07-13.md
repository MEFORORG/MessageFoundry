# REVIEW — P0 handback (`HANDBACK_P0_2026-07-13.md`)

**Date:** 2026-07-13 · **Reviewer:** coordinator · **Re:** P0, the Phase-4 gate
**Bottom line: VERDICT ACCEPTED — ABANDON. Every number reconciles. This is the best-executed run of the arc.**
**But the handback UNDER-SELLS its own decisive evidence: arm E does not merely "corroborate" the null — it BOUNDS the
entire lever class and independently kills F2 at every shape, including the ones P0 never ran.** That closes the one
hole a reader would otherwise poke in this result (§3). Two minor corrections (§4), and two errors of mine (§5).

---

## 1. The verdict is ACCEPTED — the pre-registered rule fired and was applied straight

Verified against the raw per-arm JSONs:

| arm | `result` | txn/msg | sustainable ingress | drained | stranded | FIFO | H/D/dests | build |
|---|---|--:|--:|:--:|--:|:--:|:--:|:--:|
| A r1 | PASS | 10.4746 | 23.496 | ✓ | 0 | 0/0 | 1/1/1 | `28f860e` |
| A r2 | PASS | 10.5115 | 23.898 | ✓ | 0 | 0/0 | 1/1/1 | `28f860e` |
| A r3 | SOAK_NOT_SUSTAINED | 10.453 | — | ✗ | 0 | 0/0 | 1/1/1 | `28f860e` |
| B r1 | PASS | 7.556 | 23.952 | ✓ | 0 | 0/0 | 1/1/1 | `28f860e` |
| B r2 | PASS | 7.4865 | 23.445 | ✓ | 0 | 0/0 | 1/1/1 | `28f860e` |
| B r3 | PASS | 7.4676 | 23.297 | ✓ | 0 | 0/0 | 1/1/1 | `28f860e` |

- **The manipulation check passes decisively.** `committed_txns/msg` **10.4746 → 7.4865** = a **2.99 absolute drop
  (28.5%)**, far clear of the ≥0.9 floor. **Fusion unambiguously engaged.** The disarmed-arm trap was avoided —
  `H=D=dests=1` on **every** arm (verified in every JSON), with a live `SHARDS_READY` shape cross-check per arm.
- **B vs A = −0.56%** — inside the pre-registered **NULL BAND** (−3%…+3%), and **smaller than either arm's own
  replicate spread** (A ±1.70%, B ±2.76%). Indistinguishable from noise.
- **All gates green:** FIFO `0/0` on all 16 rungs, `stranded=0`, `no_loss` ✓, build pinned `28f860e` throughout.
- **The rule was applied straight, not re-cut after the fact.** `R_sustain` was fixed by calibration *before* the
  decisive arms. C/D were correctly skipped per the doc's own decisive-first rule.

**The methods transparency is exemplary** — three two-box wiring bugs found and fixed (the engine CLI hardcoding
`--dests 8` would have silently run the wrong shape and produced a fabricated null; the load-gen box running a separate
checkout meant *both* recorders were silently absent from every report). Any one of those, unnoticed, would have voided
the run while looking clean. Finding them **before** committing rig time is exactly the discipline ADR 0101 exists to
enforce. The refusal to `git reset --hard` an unauthorized checkout, cloning `rig-p0` instead, was the right call.

---

## 2. Arm E is not "weak support" — it is the strongest result in this run

The handback files arm E under *"consistent with, does not contradict"* the null. **That badly undersells it.** Arm E
is the only measurement in the entire programme that puts a **hard, empirical bound on the whole `txn/event` lever
class** — and it does so on the *unmodified split path*, with zero code.

**What arm E actually measured** (means of 2 reps, from the raw JSONs — the *measured* `committed_txns/msg`, not the
modelled figure the handback tabulated):

| H | measured txn/msg | sustainable ingress |
|--:|--:|--:|
| 1 | 9.89 | 22.182 |
| 2 | 13.58 | 21.809 |
| 4 | 18.80 | 20.850 |
| 8 | **29.20** | **19.588** |

**A ~3× swing in actual committed transactions per message (9.89 → 29.20, ×2.95) moves throughput by −11.7%.**
Elasticity `d(ln throughput)/d(ln txn) = **−0.115**`.

**That is the number that kills Phase 4.** A lever with an elasticity of −0.115 cannot close a 5.79× gap. To buy even
the pre-registered **+8% PROCEED bar**, you would have to cut `txn/msg` by **~50%** — and to close the actual 45M/day
gap you would need to cut it by more than exists to cut.

---

## 3. ⭐ THE HOLE THIS CLOSES — "but P0 only ran H=1, the *weakest* shape for fusion"

This is the objection a reader will raise, and it is a fair one: **F2's entire value is removing the `2H` term, which is
negligible at H=1 and large at the production shape (the estate is H≈20).** P0 tested fusion where it has least to
remove. So does the null at H=1 really kill F2 at H=8 or H=20?

**Yes — and arm E is what proves it, which is why it deserves the headline.**

**Arm E measured the cost of the entire `2H` term by ADDING it.** Going H=1 → H=8 on the split path *is* adding exactly
what F2 would remove. It cost **11.7%** of throughput.

> **So F2's absolute best case at H=8 — removing the whole `2H` term and recovering everything arm E lost — is
> `22.182 / 19.588 = +13.2%`.**

And **+13.2% is a ceiling that over-states F2 twice over:**

1. **Arm E's 11.7% fall is not purely transactional.** Raising H also adds H routed rows, H routed-lane claims, and H
   transform executions. **F2 removes the stage, not the transforms** — the handlers still run. So the portion F2 can
   actually recover is **strictly less** than 11.7%.
2. **Fusion must pay a cost that scales with H — and at H=1 that cost already ate the entire gain.** Apply arm E's own
   elasticity to fusion's measured 28.5% txn cut: it **predicts +3.93%**. Fusion **delivered −0.56%**. That is a
   **−4.5 point shortfall** — the ADR 0001 Step-B overlap loss, exactly the risk the plan pre-registered. **F2 at H=8
   would serialize *eight* transforms onto the ingress lane instead of one**, so that give-back gets **worse** with H,
   while the benefit is capped at +13.2%.

**Net:** F2's best conceivable number is a **B5-sized result** — and **[ADR 0071](../../../docs/adr/0071-cut-executor-round-trips-b5.md)
B5 measured +6.5 / +9.3 / +10.0% and was a NO-GO to promote.** The realistic number, net of an overlap cost that grows
with H, sits **inside or below** that already-rejected band.

**F2 cannot clear the bar at any shape. Not at H=1 (measured). Not at H=8 (bounded by arm E). The angle is closed, and
it is closed by measurement, not by inference from a single null.** This is a *stronger* kill than the handback claims,
and it should be the ADR's headline.

---

## 4. Two corrections (neither changes the verdict)

**(a) "B converges to the theoretical minimum (7.4865 vs 7)" — the reasoning is wrong; the conclusion doesn't need it.**
`3+2H+2D = 7` is the model for the **SPLIT** path (arm A), not the fused one. Fusion removes the `2H` term, so B's own
model is **~5**, not 7. B landing near 7 is therefore *not* "converging to the theoretical minimum" — it is coincidence.
(Both arms sit ~2.5–3.5 above their respective models, because `committed_txns` counts *all* engine store commits —
pooled sweeps, claim episodes, finalizer, ACK-audit — not just the modelled per-message handoffs. The offsets are
consistent: A +3.5, B +2.5.) **The arming proof is the 2.99 drop, which is unambiguous. Drop the "converges to the
minimum" line; it adds nothing and invites a challenge.**

**(b) "The wall is per-message, not per-transaction" is slightly over-stated.** Arm E shows transactions **do** affect
throughput — the elasticity is **−0.115**, not zero. The defensible claim is sharper and more useful:

> **The txn→throughput coupling is real but far too weak to be a lever.** A 3× swing in committed transactions moves
> throughput ~12%. No transaction-reduction mechanism — fusion, group-commit, or anything else — can close a 5.79× gap
> against an elasticity of −0.115.

That framing survives scrutiny; "not per-transaction" invites someone to point at arm E's monotonic fall and reopen it.

---

## 5. My own errors, on the record

**(a) The "≥ 0.9" units ambiguity is my fault, and the bench resolved it correctly.** I wrote *"drops by ≥ 0.9"* without
naming the units. The bench flagged both readings, showed the relative (≥90%) reading is **physically impossible** (it
would require B ≤ 1.05 against a modelled floor of 7), and correctly adopted the **absolute** reading — which is what I
meant, and what my own worked example (*"5→3 … well above the ≥0.9 floor"*, a drop of **2 absolute**) implies.
**Flagging the ambiguity rather than silently picking the convenient reading is exactly right.** My phrasing should have
been "≥ 0.9 **txn/msg** (absolute)". The verdict never depended on it — it rests on `sustainable_ingress_rate`.

**(b) The recorder I specified failed; the one the bench added independently worked.** My coordinator-side capture
(`sample_once()` at `DRIVE_START`) returned **`None` on every arm**, even after a 5× retry — root cause unresolved. The
bench's **engine-side** instrument (riding the existing `in_pipeline_trace` poller, hold-start→hold-end) worked cleanly
and reproducibly (std < 0.06 txn/msg across A's reps, < 0.09 across B's). **The run was saved by their redundancy, not
my design.** Recording it because the failure mode matters: a single-shot poll at a process-startup boundary is fragile,
and building two independent instruments was the right instinct.

---

## 6. What this closes — and what is now left

**All four falsifiers in the arc have now fired negative:**

| run | lever | verdict |
|---|---|---|
| **C5** | more engine shards (N-sizing) | insufficient — `R ∈ [2,3) < 3.62` |
| **C6** | a contention fix | no convoy — 0/288 samples; no single blocker |
| **C7** | a parallelism config change | exonerated — and `MAXDOP=1` is *harmful* |
| **P0** | **`txn/event` (fusion / group-commit)** | **NULL — elasticity −0.115; bounded below the bar at every shape** |

**The store-side search and the txn/event lever are both measured dead ends. There is no identified lever left, and the
wall remains UNNAMED.** That is an uncomfortable but honest position, and it is far better than having built F2.

**The one large unexplored area is the ENGINE side.** [ADR 0098](../../../docs/adr/0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md)
§Out-of-scope already flagged it: *"the per-PID CPU collector still reads 0.00; nothing in this programme has attributed
engine-side cost."* Every falsifier so far has been aimed at the **store**. Meanwhile the engine box sat at ~38–60%
`max_core` while the store saturated — and the prior WS-B work put the per-box wall at *"76% plumbing."* **Engine-side
attribution is the obvious next question, and it has never been asked properly.** It needs a working per-PID CPU
collector first (the known-broken one is why it was never asked).

**Do NOT open a fifth store-side falsifier.** Four have now returned negative. The search is not converging because it
is pointed at the wrong box.

## 7. Consequences
- **Write the ADR closing Phase 4** (pre-committed in ADR 0099 §Decision 4). `txn/event` joins the measured-dead-end
  list. **Do not build F2 or F3.**
- **F1 survives on its own narrow merit** and is untouched by this verdict — one pure-overhead transaction off the ACK
  critical path. It was never load-bearing here, and P0 provides no evidence against it. **It is not a throughput
  lever** (elasticity −0.115 says so); ship it, if at all, as latency/cleanliness.
- **ADR 0057 (inline fusion)** should be marked **⛔ DO NOT PROMOTE** — measured, at its own weakest and best shapes,
  to buy nothing. It ships default-OFF and must stay that way.

## 8. Sources
`HANDBACK_2026-07-13/p0-{a,b,cal,e}-*/*.json` (all 16 rungs verified: `result`, `commit_sha`, `committed_txns_per_msg`,
`sustainable_ingress_rate`, `lane_inversions`/`lane_repeats`, `stranded`, `handlers`/`delivering`/`dests`). Elasticity
and the F2 bound computed from the arm-E measured `committed_txns_per_msg` (not the modelled figure).
Read-only DMV / public catalog names only; no secrets, IPs, hostnames, ports, or PHI.

---

> # ⚠️ CORRECTION (2026-07-13, same day) — §3 of this review OVER-READ arm E. The verdict stands; the *proof* does not.
> This review claimed **"F2 cannot clear the bar at any shape"** and that F2's best case **"lands in ADR 0071 B5's
> already-rejected band."** **Both are FALSE.**
> - F2's arm-E ceiling at H=8 is **+13.2%**. The pre-registered PROCEED bar is **+8%**; B5's band is **+6.5…+10.0%**.
>   **+13.2% is ABOVE both.** A bound that *permits* clearing the bar cannot prove the bar cannot be cleared.
> - Even subtracting the **measured** H=1 give-back (−4.49 pts) leaves **+8.75% — still above the bar.**
> - The deratings that would push F2 below the bar (transform executions it cannot remove; a give-back growing with H)
>   are **argued, not measured.**
> - **And F2 cannot be measured without being built:** the fusion gate is `inline and len(names) == 1`, so inline
>   fusion is **H=1-only by construction** — extending it to H>1 *is* F2. There is no cheap arm.
>
> **The ABANDON verdict is UNAFFECTED** — it rests on the **pre-registered primary A/B null (−0.56%)**, not on arm E.
> Arm E's real contribution is the **elasticity (−0.115)**: the txn lever is *weak*, which is a different and defensible
> claim. Phase 4 is declined on **cost/risk/evidence, not on a proof of impossibility** — see
> [ADR 0107](../../../adr/0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md).
> *Recorded rather than quietly edited: this was the same over-read class the programme has retracted two results for.*
