# The outbound throughput wall is the CLAIM round-trip

**Status:** measured 2026-07-09 · **Instrument:** PR #845 (`messagefoundry/pipeline/phase_timing.py`)
**Supersedes** the `mark_done` attribution in the PR-C2 ceiling-pin handoff.

This document records what actually limits outbound delivery throughput, how it was measured, and the
three hypotheses that measurement **refuted**. It exists because three consecutive investigations
attributed this ceiling to the wrong phase — each time because the instrument could only see two of the
three phases in a delivery.

---

## 1. The model

For an outbound stage with `L` lanes (an outbound lane **is** a `destination_name`; `per_lane_limit` is
forced to 1 — "hard-1", ADR 0058/H2):

```
aggregate_deliveries_per_second  =  L / (T_claim + T_deliver)
```

where `T_deliver = send_ack + mark_done` and `T_claim` is one claim round-trip.

**Why the two terms add rather than overlap.** In pooled mode a stage runs `K` claimer tasks
(`pooled_claimers_per_stage`, default 1). A claimer's loop is serial: assemble a chunk of READY lanes →
`await claim_fifo_heads` → dispatch → repeat. It never awaits delivery, but it also **cannot re-claim a
lane that is still PROCESSING**. So claiming and delivering **alternate**, and the store round-trip is
dead time for every lane, every cycle.

**Validation (no database).** Feeding a synthetic `T_claim` to the *real* `StageDispatcher` — real
claimer loop, real lane partition, real slot accounting, real hard-1 — reproduces the relation to within
the ~20% asyncio overhead of the harness. The mechanism is a property of the dispatcher, not of any store.

---

## 2. `T_claim` decomposed (SQL Server 2022, loopback, synthetic payloads)

Timing `claim_fifo_heads` against a real store while sweeping the chunk size `n` (lanes per claim):

```
T_claim(n)  =  11.4 ms  +  0.79 ms × n
```

At `n = 8` (the rig's `dests`) that is **17.6 ms, of which 64% is fixed cost**. The fixed term is what
matters, so it was decomposed further — at `n = 1`, on a single connection, with **zero contention**:

| term | ms | share of the claim |
|---|---:|---:|
| plumbing floor (`SELECT 1` through the pool) | 0.88 | 7% |
| the claim query's real work | 6.15 | 50% |
| **the 4 tempdb table variables** | **5.35** | **43%** |
| **total** | **12.38** | |

`claim_fifo_heads` declares `@heads`, `@locked`, `@keep`, `@claimed` per execution. Because the batch is
an ad-hoc parameterized statement rather than a compiled module, SQL Server cannot cache those temporary
objects, so every claim creates and drops them in tempdb's system catalog.

**Therefore the tempdb cost is per-claim allocation *work*, not latch contention.** The rig's
`PAGELATCH_EX/SH` waits on `sysallocunits` / `sysschobjs` / `syscolpars` / `syssingleobjrefs` are what
that work becomes under concurrency — a *consequence*, not the cause. Confirmed: a single-connection
claim storm at ~29 claims/s accrued **3 ms** of PAGELATCH over three seconds.

**The lever is removing the per-claim tempdb churn.** Options, in the order they should be evaluated:
wrap the batch in a stored procedure (temp-object caching applies to modules); replace the table
variables with a single set-based statement; or, as a *deployment* prerequisite rather than a code fix,
`ALTER SERVER CONFIGURATION SET MEMORY_OPTIMIZED TEMPDB_METADATA = ON`. Any rewrite must preserve the
claim's stated invariants: `SET LOCK_TIMEOUT 0` non-blocking claim, the H1 fencing token, the
contiguous-DUE cutoff, and the H2 skip-and-complete.

---

## 3. Three refuted hypotheses — do not re-chase

### 3.1 `mark_done` is **not** the wall

It is 9–18 ms of a 62–190 ms per-lane cycle: **10–17%**. The per-delivery timer added in PR #842
measured only `send_ack` and `mark_done`, and its own module comment stated the premise — the wall "is
**either** the connector send→ACK round-trip **or** the store completion round-trip." The claim was never
a candidate, so the instrument was structurally blind to 81–91% of every delivery.

**Never validate an outbound fix by watching `mark_done` fall.** It is a symptom; it inflates because
work queues behind the claim.

### 3.2 `pooled_claimers_per_stage` (K) is **not** a lever

Measured flat at K = 1, 2, 4, 8. One `claim_fifo_heads` already batches **every** ready lane, so
splitting them across `K` claimers claims no more lanes per second — it only splits the batch. K helps
only if `T_claim` is *per-lane* dominated; it is 64% *fixed*. **ADR 0066's `K=1` default is correct.**

(ADR 0066 justified `K=1` on the estimate that "claim traffic is ~12–50 RT/s — far below one task's
capacity." A measured `T_claim` of 12–190 ms puts one claimer at 5–80 RT/s, so the *estimate* was
optimistic even though the *default* is right.)

### 3.3 ADR 0075 statement batching cannot touch this

It has been default-ON since #835, batches only `INGRESS→ROUTED` and `ROUTED→OUTBOUND` handoffs
(`_PREFIX_STAGES`), and OUTBOUND is explicitly excluded by the hard-1/H2 invariant. It was active
throughout the run whose ceiling it was later proposed to fix.

---

## 4. The unexplored variable: claim **mode**

Per-cycle claim wall time to re-feed `L` outbound lanes (median of 7, same store, synthetic):

| L | `pooled` (ms) | `per_lane` (ms) | winner | speedup |
|---:|---:|---:|---|---:|
| 1 | 12.55 | 7.35 | per_lane | 1.71× |
| 2 | 13.78 | 7.45 | per_lane | 1.85× |
| 4 | 16.87 | 9.80 | per_lane | 1.72× |
| 8 | 21.78 | 10.19 | **per_lane** | **2.14×** |
| 16 | 26.98 | 19.17 | per_lane | 1.41× |

`pooled` folds all lanes into one claim and pays the fixed cost once — a large win at ~1500 lanes, which
is exactly why ADR 0066 built it (`per_lane` there storms the store: 92% store CPU at zero messages).
At `L = 8` the fixed cost never amortizes, and `per_lane`'s concurrency simply wins. `pooled` has been
the shipped default since #744.

`per_lane` is shard-safe: `wiring_runner` gates delivery-worker spawn on `_owns_destination`, preserving
the ADR 0073 single-delivery-consumer-per-outbound-lane invariant.

> **Do not flip the `claim_mode` default on this evidence.** It is a low-lane-count win only, measured on
> a loopback store in isolation from delivery. The crossover above 16 lanes is unmeasured, and the whole
> reason `pooled` exists lives on the other side of it.

---

## 5. The instrument (PR #845)

`MEFOR_DELIVERY_PHASE_TIMING=1` (default OFF; the off path is a single bool check) now emits, per
process, every 5 s:

```
delivery phase timing (stage=…): send_ack n= mean= max= | mark_done n= mean= max=
claim phase timing    (stage=…): claim n= mean= max= | lanes/claim= rows/claim= rearm= empty= claimers=K
```

Both are metrics only — counts, means, ratios. An outbound lane *is* a `destination_name`, so lane names
never reach a log. `rearm` counts lanes the claim consumed in place via the H2 skip-and-complete: real
work, not empty overhead. In `per_lane` mode `claim_next_fifo` returns `None` both for "nothing pending"
and for an H2 in-place completion, so its `empty` is an **upper bound** — the two modes' `empty` are not
directly comparable.

The harness's `_PHASE_RE` matches the delivery line only; a regression test pins that the claim line
cannot false-match it.

---

## 6. What the next rig run must establish

Pre-registered, with falsifiers, so the result cannot be rationalized afterwards.

1. **The model.** Under `pooled` at low load, measured `claim mean` should land near **~53 ms** — the
   residual `cycle − send_ack − mark_done` from the PR-C2 soak. This is the first *independent* test:
   every `T_claim` figure to date was obtained by that subtraction, which is circular.
   *Falsifier:* a small `claim mean` (<15 ms) alongside a ~62 ms cycle means the claim is **not** the
   residual, and the remaining suspect is engine-side plumbing — the ~76%-of-CPU asyncio/executor
   round-trip per store op — which has never been excluded, because the PR-C2 per-PID CPU sampler reads
   a constant zero.
2. **The A/B.** `per_lane`'s `claim mean` ≈ half `pooled`'s at `dests=8`; sustained ingress ceiling
   1.5–2× higher. *Falsifier:* no reduction ⇒ the loopback result did not transfer (likeliest cause:
   `L` concurrent claims saturate the store or the connection pool in a way one batch does not).
3. **The fix.** If (1) and (2) hold, de-churning the claim query is worth ~43% of the claim before
   contention, more under it. *Falsifier:* `claim mean` tracks `lanes/claim` with a small intercept ⇒
   the `CROSS APPLY` seeks dominate and the table variables are a red herring.

Runbook: `aws-bench/HANDOFF_rig_claim-mode-AB_2026-07-09.md`.
**Nothing here certifies `SYSTEM-REQUIREMENTS` §8.** No run has ever varied `N` (shard count).

---

## 7. Reading the harness's numbers

Do not take `shardcert_ladder`'s reported rates at face value — see
[`shardcert-ceiling-ladder.md`](shardcert-ceiling-ladder.md) §"Measurement caveats". In particular the
climb's `pinned_ingress_rate` overstates sustainable ingress by exactly `(hold+drain)/hold`, and
`in_pipeline` is 4× overcounted on a unified store.
