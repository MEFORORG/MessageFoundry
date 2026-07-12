# Phase-4 "Group-Commit" — Implementation Plan

**Status:** PROPOSED — owner approval required before any code is written.
**Date:** 2026-07-12
**Supersedes the Phase-4 scope in** `docs/benchmarks/THROUGHPUT-EXECUTION-PLAN.md`.
**Amends (on approval):** ADR 0057 (stage fusion), ADR 0055 / ADR 0069 (durable-write tier). ADR numbers to be
allocated via `scripts\coord\alloc.ps1` — **never grepped**.

---

## 0. Read this paragraph first

**Group-commit is dead.** Not "measured to be small" — structurally dead, for reasons that do not depend on any
new measurement. What survives of Phase 4 is a *different* mechanism (stage fusion), it is **already implemented
and shipping in the tree**, it has **never been enabled in a single rig run**, and **the throughput case for it
is derived, not measured**. There is also a real possibility — which we cannot currently exclude — that the whole
Phase-4 premise ("reduce transactions per event") is wrong, and that the wall is per-*message*, not
per-*transaction*. **This plan tells you how to find that out for roughly zero production code, before committing
to a build.**

---

## 1. THE ONE-LINE RECOMMENDATION

> **Do not build anything yet. Run a 3-arm, zero-production-code measurement campaign (P0) that (a) tests the
> Phase-4 premise itself and (b) benchmarks the stage fusion we already shipped and never turned on. Only if P0
> clears a pre-registered bar do we build F1 → F2 → F3 (fold the ACK-audit txn; complete the fused primitive so
> `H` leaves the transaction formula; suppress the idle ROUTED sweep).**

**Honest expected gain, stated in the two currencies separately:**

| currency | value | status |
|---|---|---|
| **Committed transactions per message** (dedicated, pooled mode, H=1 D=1) | **5 → 3 (−40%)** | **DERIVED** — arithmetic from the ledger in §3. Will be **verified as a manipulation check** by `SqlServerStore.committed_txns` (`store/sqlserver.py:1027`), a counter that already exists and is already polled (`harness/load/enginepoll.py:101,347`). |
| **Committed transactions per message** (ADT hub, H=20 D=4) | **27 → 6 (−78%)** | **DERIVED.** |
| **Sustained events/s (the thing that matters)** | **UNKNOWN.** Our honest band is **0.95×–1.30×**, and **negative is a live outcome.** | **NOT MEASURED. NOT PREDICTED.** We refuse to give a point estimate. |

**What would measure it:** P0 (§7) — the shardcert C5 ladder run with `inline=` as the sole contrast at an
`H=D=1` shape, with a same-session OFF control, a manipulation check on `committed_txns/msg`, and a pre-registered
two-sided decision rule including a **regression** band.

**Why we will not state a throughput number:** the nearest measurements point *away* from this lever. ADR 0069
measured the store absorbing ~27–29k commits/s against a ~2,416 commits/s demand at the full 45M/day target —
**commit bandwidth is ~9% utilised.** C4 measured ~72% of the wall as **off-CPU WAIT**, and of the ~28% that is
store CPU, **87.8% is the claim path** (`list_fifo_lanes` 47.5% + `claim_fifo_heads` 40.3%) — which no
transaction-reduction lever can touch. ADR 0071 B5 cut thread crossings 6× and pool-wait p95 5× and delivered
**+6.5 / +9.3 / +10.0%** — and was a **NO-GO**. Anyone who tells you Phase 4 is worth 1.5× is guessing.

---

## 2. WHY THIS AND NOT THE OTHERS

Four designs were built and adversarially judged. Three lost. Here is why, in their judges' terms.

### ☠️ KILLED — **WAL / durability tier** (delayed durability, log-flush batching, app-side group commit)
**Two fatal votes. This is the angle Phase 4 was named for, and it cannot be built.**

1. **It breaks Invariant 1 and Invariant 2 by construction.** `DELAYED_DURABILITY` returns from `COMMIT`
   *before* the log block is flushed. `enqueue_ingress` (`store/sqlserver.py:2242`) commits, the listener ACKs,
   the sender drops its copy — and up to 60 KB of unflushed log is lost on power failure. **An ACKed message that
   does not exist.** On PHI. There is no partial fence: `fk_queue_message` means a crash-erased `messages` row
   takes its whole subtree with it.
2. **An app-side group committer on a *pooled* server DB is definitionally a concurrency reduction.** A
   transaction is bound to a connection. Today M handoffs run on M pool connections *in parallel*. To put them in
   one transaction you must run them on **one connection, serially**: you pay ~5(M−1) serialised round-trips to
   save (M−1) log flushes at ~0.17 ms each. It gets **worse with distance** — the exact inverse of ADR 0075,
   which was promoted *because* it helps at distance. And every parked member holds a `StageDispatcher`
   PROCESSING slot (`pipeline/stage_dispatcher.py:28` conservation law), which is the scarcest resource in the
   system.
3. **SQL Server's log manager already group-commits** (ADR 0069's `commit_storm.txt`: ~19:1 at 128 threads,
   ~1.5–2.3:1 at the 16–32 concurrency the pipeline actually runs). The only knob that raises the ratio is
   *concurrency* — i.e. ADR 0069 Decision 2, which already exists. The angle collapses into a lever we already have.
4. **Ceiling:** even a physically impossible zero-cost store removes only ~170 µs of a ~2.84 ms serial path =
   **~6%**, against a **579%** gap.

Its one surviving build (S1, "store-once-deliver-many" on SQL Server) was judged **FATAL on invariants** — the
`shared_body` refcount protocol it copies from SQLite is safe *only* because SQLite serialises every writer behind
one write lock; on SQL Server's pool, a non-atomic release races an increment and **permanently dead-letters an
already-routed message with its outbound body destroyed** — and **FATAL on gain** (it removes exactly zero
transactions). **It is dead. Do not resurrect it.** (Its *storage* argument may be worth a separate,
correctly-designed BACKLOG item; it is not Phase 4 and it is not this plan.)

**Grafted from it:** one harness-only measurement (§7, P0-C) — `mean_writelog_ms = Δwritelog_ms / Δcommitted_txns`
— that closes the durable-write file with a *number* instead of an argument, for ~20 lines of harness code and
zero production code.

### ☠️ KILLED — **Pipeline coalescing** (batch the stage handoffs across messages)
**One fatal vote (gain).** It is invariant-clean and buildable, and it still buys nothing:

- **The claim is un-batchable.** The outbound `per_lane_limit` is hard-clamped to 1 in three independent layers
  (`wiring_runner.py`, `stage_dispatcher.py:246`, `sqlserver.py`) for H2 skip-and-complete atomicity, and the
  claim's `attempts+1` must be durable *before* the work (Hazard A poison-guard). So the design's own ceiling is
  exactly **2× txn/event no matter how large the batch** — against a 5.79× gap.
- **Its #1 target is invisible to it.** `list_fifo_lanes` — C4's largest store-CPU consumer at N=16 (47.5%) — is
  driven by a **fixed clock** (`pooled_sweep_interval = 0.25 s`, `config/settings.py:854`), not by message rate.
  **Coalescing messages reduces it by exactly zero.** Half the store CPU at the collapse point is out of reach by
  construction.
- **It plausibly makes things worse.** Batching M messages means holding M `sp_getapplock` finalize locks and a
  16×-longer RCSI write transaction, pressing directly on the tempdb metadata `PAGELATCH` that C2/C3 identified as
  the actual N=8/N=16 collapse — i.e. it risks *manufacturing* the convoy C6 measured as absent (0 of 288 samples).
  That is a C7-shaped regression risk that bites hardest at exactly the load where the lever finally fills.

**Grafted from it (three things, all real):**
1. The **`list_fifo_lanes` is clock-driven, not rate-driven** insight → this is the *entire* basis for our
   redesigned **F3** (§3), and it is why F3 is a sweep change, not a batching change.
2. The **fill-factor law** (`M ≈ 1 + λ_scope × W`): at 520.83 events/s across 1,500 connections, a single lane
   sees ~0.43 msg/s. Any design whose gain is a *batch size* is dead on this load shape unless the queue is
   backlogged — and a backlogged lane at the sustained target is a failing lane. **This law kills every future
   "just batch it" proposal in this workstream. Write it down.**
3. A **real latent bug**, independently found by two angles: `mark_batch_done` (`sqlserver.py:4767`) iterates its
   finalize set in **dict insertion order** (`:4808`) while the sorted helper `_lock_finalize_batch` (`:1816`) sits
   unused — an unsorted multi-applock acquisition, i.e. a live 1205 deadlock exposure **today**. Fix it
   independently of this plan.

### ☠️ KILLED — **Store-layer batching** (group the handoff commits behind a dedicated connection)
**No fatal vote, but the lowest gain score of the four (3/10).** It reduces the *cheap* commits and leaves the
expensive path untouched: the claim path is 87.8% of store CPU and is structurally un-batchable (above). It cuts
~12.5% off a commit tier that is **~9% utilised**. And it carries the workstream's most inconvenient
counterexample, which we are keeping (§5): **`claim_mode="pooled"` — the shipped default — commits *far fewer*
transactions per event than `per_lane`, and is 2.8× slower.**

**Grafted from it:**
- The **`record_ack_sent` finding** → our **F1**. It is a per-message `SELECT MAX` + `INSERT` + `COMMIT`
  (`sqlserver.py:2948`), **default-ON** (`diagnostics.response_sent = True`, `settings.py:984`), **awaited on the
  ACK critical path**, and **absent from the store's own `3 + 2H + 2N` cost model** (`sqlserver.py:1034`) — so the
  cost model has been understating the real ledger by exactly 1 txn/msg this whole time.
- The **"instrument, don't ship" discipline** — inverted. Its proposal to build the group committer *as a
  benchmark instrument* is exactly the ADR 0071 B5 mistake (a permanent flag bought for a predicted null). **We
  refuse it.** We take the measurement without the mechanism.
- Multi-row `VALUES` inserts for the H routed / D outbound rows: a *statement*-count lever, not a *transaction*
  lever. **De-scoped.** It is not Phase 4; file it.

### ✅ WINNER — **Topology / stage fusion**
Highest total (27.5), **zero fatal votes**, and the only angle that:
- works on **all three backends** (`store.handoff` is implemented in `store/store.py`, `store/sqlserver.py:2309`,
  and `store/postgres.py`; contract at `store/base.py:258`);
- removes `H` from the transaction formula *entirely*, rather than dividing it;
- is **~80% already in the tree** and can be **measured before it is built**;
- found a **real shipped FIFO bug** on the way (§4.2).

It also has the sharpest criticisms against it, which the plan below adopts rather than hides.

---

## 3. THE DESIGN

### 3.1 The mechanism that already exists (and has never been switched on)

`store.handoff(...)` consumes the in-flight **ingress** row, inserts the outbound rows, and sets the disposition —
**skipping the `routed` stage entirely, in one transaction.** It is reached from `RegistryRunner._process_ingress_item`
(`pipeline/wiring_runner.py:3585`, inline branch at `:3683`), gated by:

- **graph-level** (`_inline_ok`, `wiring_runner.py:662`): opted-in via `inbound(..., inline=True)`
  (`config/wiring.py:1821`) · no live `db_lookup`/`fhir_lookup` anywhere in the graph · `ack_after=ingest` · not
  LOOPBACK;
- **per-message** (`wiring_runner.py:3683`): **`len(names) == 1`** · deliveries non-empty · no state ops · no
  pass-through · no `SetMeta`.

Anything else **falls back to `route_handoff`** — the split path.

**Verified: `inline=` appears nowhere in `harness/` or `samples/`. Every rig run C1–C7 ran the fusion OFF.**

### 3.2 The transaction ledger — three versions, because two of them are wrong

**(A) The model in the code** (`sqlserver.py:1034`): `3 + 2H + 2N`. **It omits `record_ack_sent`.** It has
understated the real ledger by 1 txn/msg since it was written.

**(B) The un-amortised ledger:** `T = 4 + 2H + 2D`.

**(C) The pooled reality — what every rig run actually did.** In `claim_mode="pooled"` (the default),
`claim_fifo_heads` (`sqlserver.py:4281`) claims one head per lane **across all lanes in ONE execute + ONE commit**.
The claim commits are therefore **amortised across lanes, not one per message.** Per-message *dedicated* commits:

```
T_ded = 1 enqueue_ingress
      + 1 record_ack_sent          (default-ON)
      + 1 route_handoff
      + H transform_handoff
      + D mark_done
      = 3 + H + D          (+ amortised claim commits ≈ (1 + H + D)/L, L ≤ 256 lanes/episode)
```

**Use (C). Do not quote (A) or (B) at the owner.** Every number below is (C), and every number below will be
**checked against the measured `committed_txns` counter** rather than trusted.

### 3.3 After F1 + F2

```
T_ded' = 1 enqueue_ingress   (now carries the ACK-audit row — F1)
       + 1 handoff           (route + all H transforms + all D outbound rows, ONE txn — F2)
       + D mark_done
       = 2 + D              (+ amortised claim commits ≈ (1 + D)/L — the ROUTED claim episodes are GONE)
```

**`H` leaves the formula.** `events/msg = 1 + D`.

| topology | T_ded today | T_ded after | txn/event today → after |
|---|---:|---:|---|
| simple feed (H=1, D=1) | **5** | **3** | 2.50 → **1.50** (−40%) |
| shardcert bench (H=8, D=8) | 19 | 10 | 2.11 → **1.11** (−47%) |
| ADT hub (H=20, D=4) | 27 | 6 | 5.40 → **1.20** (−78%) |
| ADT hub *post-`accepts=`* (H=2, D=4) | 9 | 6 | 1.80 → **1.20** (−33%) |

Off-ledger, and real: the **finalizer** (a per-message `sp_getapplock` + a `GROUP BY` over the message's queue
rows, `sqlserver.py:1824`) fires `H + D` times today → **`D`**. At the ADT hub that is **24 → 4**.

> **⚠️ Composition warning — do NOT add these gains to `accepts=`.** On a *fused* inbound, `accepts=` (#213 /
> #952 / ADR 0084) no longer saves transactions, because `H` is not in the formula any more. It still saves
> transform CPU and still cuts `D`. **The two levers are not additive on a fused inbound. Anyone who adds them is
> double-counting.**

### 3.4 The four increments

**P0 — MEASURE (zero production code; harness + config only).** §7. Gating. May be the last thing we do.

**F1 — Fold `record_ack_sent` into `enqueue_ingress`.** Removes **1 dedicated txn from every message on every
path and every backend**, fused or not, and removes a full store round-trip **from the ACK critical path**
(`_capture_ack` is already awaited before the AA frame is returned, `wiring_runner.py:~2985`).
`build_ack(peek, …)` is a **pure function of the peek** — computable *before* `enqueue_ingress` — so the response
row can be inserted **inside the ingress transaction** with no change to *when* the ACK is released.
- Scope: **success path only.** The three NAK paths (decode / parse / strict-validate) have **no ingress row to
  fold into** and keep the standalone insert. They are rare and they already write an `ERROR` message row.
- The `SELECT MAX(seq)` in today's body must go (it is an extra round-trip and it is the exact leading-SELECT shape
  the ADR 0075 `_BatchAccumulator` asserts reject, `sqlserver.py:453`). Golden-SQL gate on the replacement.
- **Honest semantic change:** capture is **fail-soft** today (a warning; the ACK still goes out). Folded, an audit-row
  failure rolls back the ingress commit → NAK → sender resends. That is *strictly stronger* (no ACK without its
  audit row) but *louder*. **Ship behind `[diagnostics].ack_capture_inline`, default OFF, flip after a green arm.**
- **Zero-code alternative, offered for the owner's decision:** flip `[diagnostics].response_sent` to default
  **False** and delete the transaction outright. Same 1 txn saved, no code, no semantic change — **at the cost of
  the ACK-disposition audit row.** F1 exists because we assume you want to keep the row. If you don't, take the
  free win and skip F1.

**F2 — Complete the fused primitive so no message ever falls back.** Extend `handoff` on all three backends to
carry what `transform_handoff` carries, so **every** message on a fused inbound fuses:
- **H > 1** — run all H transforms in the ingress-lane hop, emit Σ D_h outbound rows in the one txn. *(This is
  where the entire `2H` term goes.)*
- **zero-delivery (a filtering handler)** — call `_maybe_finalize`; the finalize applock is **already taken** inside
  `handoff` (`sqlserver.py:~2338`), so this is small. **It also closes ADR 0057's G2 stranding hazard.**
- **state MERGEs / pass-through children / `SetMeta`** — reuse `transform_handoff`'s existing statement bodies.
- **Error path unchanged:** a transform raise goes to `_apply_router_internal_error`. It produces **no outbound
  row**, so it cannot invert anything.
- **This is not optional polish. It is a correctness prerequisite** — see §4.2. Until F2 exists, `inline=True` must
  never be promoted beyond a homogeneous rig arm.
- **On SQL Server, `handoff` must gain a `batch_handoff_statements` twin** (`route_handoff` and `transform_handoff`
  both have one; `handoff` does **not** — verified). Without it, fusion silently forfeits ADR 0075. See §7.

**F3 — Suppress the idle ROUTED sweep. (REDESIGNED — the original was broken; see §4.6.)**
The original proposal was *"when every inbound is fused, don't build the ROUTED `StageDispatcher` at all."*
**That is dead.** `replay()` / `replay_dead()` (`sqlserver.py:5110` / `:5527`) `UPDATE queue SET status=PENDING …
WHERE message_id=?` — **scoped by `message_id`, not by stage** (verified). They are *runtime writers into the ROUTED
stage*. A dead-letter replay after the flip would resurrect a PENDING routed row with **no dispatcher alive to claim
it** → never delivered, never dead-lettered, never finalized, and `replay()` sets `messages.status = RECEIVED` → the
message is **stranded and misreported forever.** That breaks Invariant 1 *and* Invariant 2.

**F3 as we will build it: adaptive idle backoff on the sweep, never deletion of the stage.**
In `StageDispatcher._sweep_loop`, when a stage's `list_fifo_lanes` returns **zero lanes**, issue one cheap
`EXISTS`-shaped probe for *any* row at that stage (any status — this is what keeps a not-yet-due retry row from
being starved). If the stage is **truly empty**, back the sweep interval off geometrically from
`pooled_sweep_interval` (0.25 s) to a bounded `pooled_sweep_idle_max` (default 4.0 s). Reset to base on any
`mark_ready` or any non-empty sweep.
- **Correctness:** a replayed routed row is still discovered within ≤ `idle_max`. **No strand. No new class of
  bug.** The stage always exists, always recovers, always finalizes.
- **Gain (DERIVED):** with every inbound fused, the ROUTED stage holds **zero rows**, so its sweep fires ~16×
  less. `list_fifo_lanes` is 47.5% of store CPU at N=16, spread over ~3 stages → removing one stage's sweep is
  **≈16% of store CPU ≈ 4.5% of the wall** (store CPU is ~28%; ~72% is off-CPU WAIT). **Derived. Not measured.**
- **It is independently shippable and independently measurable** — it helps the RESPONSE stage and any idle stage
  **today**, with or without fusion. This is a strictly better lever than the original F3, and it is the graft from
  the pipeline-coalesce angle's best finding.
- Flag: `[pipeline].idle_sweep_backoff = false` (default OFF).

### 3.5 Config surface

| flag | scope | default | note |
|---|---|---|---|
| `inbound(..., inline=True)` — **existing** (`config/wiring.py:1821`) | per-inbound | **OFF, and it stays OFF** | Fusion trades intake head-of-line isolation (the ADR 0001 Step-B rationale) for transaction count. Right for 1,500 flat lanes at ~0.35 msg/s each; **wrong for one hot feed with a slow transform.** It must remain the operator's per-feed choice — **never a global default.** |
| `[diagnostics].ack_capture_inline` — **new (F1)** | global | **OFF** → ON after a green arm | Backout switch for the fail-soft → fail-together change. |
| `[pipeline].idle_sweep_backoff` — **new (F3)** | global | **OFF** | Backout switch. |
| `[pipeline].inline_strict` — **new (F2 interlock)** | global | **ON** once F2 lands | On a fused inbound, a message that somehow fails the per-message gates is **ERRORed, never fallen back**. See §4.2. |

---

## 4. HOW EACH HARD INVARIANT SURVIVES

### 4.1 At-least-once (INV-1) — and the ACK boundary
The ACK boundary is **untouched**. `enqueue_ingress` still commits the raw before the AA is released; F1 only adds
a row *to that same transaction*. The fused unit runs **entirely after** the ACK.

`handoff`'s guard is `DELETE FROM queue OUTPUT deleted.id WHERE id=? AND stage='ingress' AND status='INFLIGHT'`
(verified, `sqlserver.py:~2327`). On a re-run of an already-committed handoff it returns no row → the whole fused
handoff is an **idempotent no-op** (`return False`). A crash *before* the commit rolls everything back; the ingress
row stays INFLIGHT; `reset_stale_inflight` re-pends it; the **pure** router + **pure** transforms (INV-4) re-derive
identical output. **No message is lost and no message is partially handed off.**

### 4.2 FIFO (INV-3) — and the shipped bug we found
**This is where the owner should push hardest, so we lead with the bad news.**

**`_lane_col` (`sqlserver.py:3915`): the lane is `channel_id` for INGRESS and ROUTED, but `destination_name` for
OUTBOUND. Outbound `seq` is an IDENTITY assigned at INSERT.** The harness's FIFO contract
(`harness/load/failover_track.py:19-22`) is **receipt-order → delivery-order per destination.**

Now take **one inbound with heterogeneous traffic** — the production ADT case — with `inline=True` **as shipped
today**:

| t | msg | shape | path taken | when its outbound row is INSERTed |
|---|---|---|---|---|
| 1 | **B** | 2 handlers | **falls back** to the split path | later, at `transform_handoff`, after the ROUTED lane claims it |
| 2 | **A** | 1 handler, delivers | **fuses** | **immediately**, inside the ingress-lane `handoff` |

**A's outbound row gets a lower `seq` than B's, though B was received first.** On a shared destination lane that is
a genuine `lane_inversions > 0` — **a hard-gate violation, in code that ships today.**

It has never fired because (a) the feature is default-OFF and (b) the load graph is **homogeneous**, so the
harness cannot produce the interleaving. `tests/test_inline_fast_path.py` tests correctness, not cross-message
ordering.

**The rule this forces on the design, and it is not negotiable:**

> **Fusion is an all-or-nothing property of the INBOUND, never a per-message decision. No message on a fused
> inbound may ever fall back into the `routed` stage, because a fused sibling will overtake it on a shared outbound
> lane.**

This is why **F2 is a correctness prerequisite, not an optimisation**, and why `[pipeline].inline_strict` exists.
It also kills the tempting "speculative fusion with free fallback" idea outright.

**With F2 in place, FIFO survives, in two legs:**
- *Per-lane:* INGRESS and ROUTED **key on the same column — `channel_id`.** Collapsing ROUTED into INGRESS does not
  repartition anything; the transform work moves from one `channel_id`-serialised lane to another. Per-inbound
  transform order stays receipt order. The `StageDispatcher`'s one-live-serializer-per-lane rule
  (`stage_dispatcher.py:625-627`) and its strictly-sequential `_drain_lane` (`:781`) are untouched.
- *Cross-message on a shared outbound destination:* guaranteed by the all-or-nothing rule — **every message on a
  fused inbound fuses**, so outbound rows are always inserted in receipt order for that inbound.

**Stated scope limit, because it is honest:** fusion is per-**inbound**; the outbound FIFO lane is per-**destination**.
Two *different* inbounds fanning to the same destination have **never** had a mutual receipt-order guarantee (their
outbound rows race today, in two concurrent `transform_handoff` transactions). Fusion does not change that, and does
not claim to.

**F3 does not touch FIFO at all** — it changes a *poll interval*, not an ordering column, a claim predicate, or a
lane assignment.

### 4.3 Count-and-log + finalizer authority (INV-2)
F2 adds `_maybe_finalize` to the zero-delivery case inside `handoff`, so a filtering handler reaches **`FILTERED`**
instead of stranding — **this fixes ADR 0057's G2 hazard, it does not create one.** The finalizer remains the sole
disposition authority; it simply runs `D` times instead of `H + D` times. Because **all** of a message's outbound
rows are now inserted in **one** transaction, the "a delivered handler finalizes while a sibling's routed row is
still in flight" window is **removed**, not widened. Nothing is accepted-and-dropped: a rollback returns rows to
PENDING, never to a terminal state.

**F3's residual risk, named:** an idle-backed-off stage could delay discovery of a row written by a path that does
not call `mark_ready` — i.e. `replay()` and a not-yet-due retry. The `EXISTS` probe before backing off is
*specifically* there to prevent the retry case, and the bounded `idle_max` (4 s) bounds the replay case. **A
bounded latency drift, never a strand.** This is exactly the failure the original F3 walked into, and we are
building the version that cannot.

### 4.4 Idempotent re-run (INV-4) + crash recovery (INV-5)

| moment | outcome |
|---|---|
| crash before `enqueue_ingress` commits | no ACK, no row — the partner resends. **Unchanged.** |
| crash after ingress commit, before the ACK is on the wire | durable as `RECEIVED`; partner resends → duplicate, absorbed by outbound idempotency. **Unchanged.** |
| **crash mid-fused-unit** (during route / any of the H transforms) | nothing committed; ingress row INFLIGHT → `reset_stale_inflight` → PENDING → re-run. Pure functions re-derive identical output. |
| crash after `handoff` commits, before the delivery wake | outbound rows are durable and PENDING; the delivery dispatcher's sweep finds them. **No loss.** |
| re-run of an already-committed `handoff` | the INFLIGHT DELETE-guard finds nothing → `False` → **no-op. No duplicate outbound rows.** |
| **deterministic process crash inside the fused unit** (segfault / OOM — no exception to catch) | **already solved:** ADR 0057's **G6 ingress-lane attempts ceiling** (`wiring_runner.py:3608-3629`) dead-letters an item whose `attempts` reach the delivery cap. **F2 widens the fused unit, so G6 becomes MORE load-bearing — it must be tested under H > 1.** |

`reset_stale_inflight` is unchanged and still recovers **every** stage. The fused unit's in-flight row is an
**INGRESS** row — a stage it already recovers. The ROUTED stage keeps its recovery path (and, per F3-redesigned, its
dispatcher).

### 4.5 Cross-backend (INV-6)
**All three.** `store.handoff` is already implemented in `store/store.py` (SQLite), `store/sqlserver.py:2309`, and
`store/postgres.py`, against the contract at `store/base.py:258`. F1 touches all three stores. F2 extends all three.
F3 is dispatcher-level and backend-agnostic.

**This is the angle's structural moat, and it is the reason it won:** group-commit is SQLite-only, and SQL Server is
*architecturally closed* to it (ADR 0055's `DELAYED_DURABILITY` rejection). ADR 0075 is SQL-Server-only. **Stage
fusion is the only lever in the family that works everywhere.**

**Stated honestly:** the rig proves it on **SQL Server only**. SQLite and Postgres FIFO/no-loss will be
**test-proven, not rig-measured**. We are not going to pretend otherwise.

### 4.6 asyncio (INV-7)
The router and the transforms already run off-loop via `asyncio.to_thread` (`wiring_runner.py:3650`, `:3705`); F2
adds H−1 more of the same hops. **No DB connection is held across a to_thread hop** (ADR 0057 G5). Every worker
stays cooperatively cancellable. F3's sweep loop is an existing cancellable task; only its sleep changes.

---

## 5. THE WEAKEST POINT (stated by us)

**The payoff mechanism is a hypothesis, and the nearest measurements point the other way.**

We are proposing to remove transactions from a store whose commit tier is measured at **~9% utilisation**. Our
defence — *"it isn't the commits, it's the interactions: pool acquires, round-trips, applocks, claim episodes,
pending rows, a whole lane class"* — is **exactly the sort of unfalsified mechanism story ADR 0071 B5 told right
before it delivered +6.5%.** Nothing in this repo attributes the wall to per-transaction cost. C6 explicitly calls
it **AMBIGUOUS-STRUCTURAL: no lock, no latch, no memory grant, no spill, no convoy — no single blocker to fix.**

**If the wall is per-MESSAGE — lane head-of-line serialisation, or the finalize applock, or an off-CPU wait we have
not named — then cutting 5 → 3 transactions per message buys exactly nothing, because the number of MESSAGES is
unchanged. Fusion cannot touch a per-message wall. That is the scenario in which this entire plan is worth zero,
and we cannot currently rule it out.**

And there is a worse case. **This is a concurrency-REMOVING intervention in a regime that is ~72% off-CPU WAIT with
the engine box at only ~38% max_core.** Fusion collapses three independently-scheduled pipeline stages into two,
moves the router *and* all H transforms onto the serialised INGRESS lane (undoing the ADR 0001 Step-B split that
exists precisely to stop a slow transform from blocking intake), and F3 quiets a dispatcher. **If throughput at
1,500 lanes depends on stage-level overlap, lengthening the per-lane service unit while removing a stage that used
to overlap with it can plausibly REDUCE throughput.** That is structurally the same trade `MAXDOP=1` made in **C7 —
less overhead, less parallelism, worse result, and it broke a previously-healthy rung.**

**Two in-repo counterexamples we are keeping on the table, not burying:**
1. **`claim_mode="pooled"` — the shipped default — commits far fewer transactions per event than `per_lane`
   (`claim_fifo_heads` coalesces up to 256 lanes' claims into ONE commit), and is 2.8× slower.** If txn/event were
   the binding constraint, that ordering would be impossible. *(Caveat, stated: it is not a clean contrast — pooled
   also **adds** the `list_fifo_lanes` discovery scans and the tempdb table variables — and per
   `[[mf-outbound-claim-wall]]` the per_lane advantage **inverts at 1,500 lanes**. We are not over-reading it. We
   are saying it is enough to stop anyone claiming the txn→throughput link is established.)*
2. **`list_fifo_lanes` — 47.5% of store CPU at N=16 — is CLOCK-driven, not rate-driven.** No amount of transaction
   reduction touches it. That is why F3 exists and why it is a *sweep* change.

**Therefore: P0 is not a formality. It is the plan.** We will not write production code for a mechanism whose
payoff we have not observed, and we have pre-registered the result that makes us walk away.

---

## 6. BUILD PHASES

Each phase is independently shippable, default-OFF, and cleanly backed out. **Nothing after P0 is authorised by
this plan** — P0's result decides.

| # | what | prod code | flag | gate to proceed |
|---|---|---|---|---|
| **B0** | **The FIFO bug (§4.2), fixed as a finding, not as a feature.** Add the heterogeneous-traffic shared-destination ordering test (it must **FAIL** on today's `inline=True` — that is the bug report). Add an `inline_fallbacks` counter to `/stats`. Add the BACKLOG item + a `⚠️ DO NOT PROMOTE` banner on ADR 0057. **Ships regardless of whether Phase 4 proceeds.** | tiny | n/a | none — do it |
| **B0b** | Fix `mark_batch_done`'s unsorted multi-applock acquisition (`sqlserver.py:4808` → use `_lock_finalize_batch`, `:1816`). A live 1205 exposure **today**, found independently by two angles. | tiny | n/a | none — do it |
| **P0** | **THE MEASUREMENT.** §7. Harness + config only. ~20 lines in `shardcert.py` to record `committed_txns` per arm (the counter and the poller already exist), an `H=D=1` shape via the existing `MEFOR_SHARDCERT_HANDLERS` / `_DELIVERING` / `_DESTS` env knobs, an `inline=` knob on the bench inbound, and the batching de-confound (§7.2). **Zero production code.** | **zero** | n/a | **gates everything below** |
| **F1** | Fold `record_ack_sent` into `enqueue_ingress` (3 stores + the ACK path). Removes 1 dedicated txn/msg on **every** message, **every** path, **every** backend — fused or not — and a round-trip off the ACK critical path. Golden-SQL gate on the new body. | small, sensitive | `[diagnostics].ack_capture_inline` (OFF) | **Arguably worth shipping even if P0 kills the angle** — it is a pure-overhead txn on the critical path. Owner's call. |
| **F2** | Complete `handoff` (H>1, zero-delivery finalize, state, pass-through, `SetMeta`) on all 3 backends + a `batch_handoff_statements` twin for `handoff` on SQL Server + `[pipeline].inline_strict`. **This is the phase where `H` leaves the formula.** | **large** (3 backends × 3 statement variants: async, ADR 0075 batched, ADR 0071 sync twins) | `inline=` per-inbound (OFF) | P0 PROCEED |
| **F3** | Adaptive idle-sweep backoff + the `EXISTS` probe (`stage_dispatcher.py`). **Independently measurable — it helps any idle stage today.** | small | `[pipeline].idle_sweep_backoff` (OFF) | may be measured **before** F2 |

**Backout:** every flag off ⇒ byte-identical to today. `inline` is already default-False and already shipping;
`ack_capture_inline` and `idle_sweep_backoff` are new and default-False. No migration. No schema change. No
retirement of an existing path.

**Do NOT under-price F2.** "Reuse `transform_handoff`'s statement bodies" hides a **3 backends × 3 variants**
matrix (plain async, the ADR 0075 batched twin, the ADR 0071 sync twin — `handoff` has *none* of the last two), and
it touches the code where the prior SQL Server per-lane FIFO **release blocker** lived. If P0 passes, F2 is the
real cost of this plan, and the true cost of shipping fusion is **F2-complete, not "flip a flag."**

---

## 7. HOW WE PROVE IT — P0, the pre-registered falsifier

In the C5/C6/C7 style: a decision rule fixed **before** the run, a manipulation check that proves the arm was
actually armed, a same-session control, and a stated null band.

### 7.0 The disarmed-arm trap we nearly walked into (read this before anything else)

The obvious experiment — *"flip `inline=True` on the bench inbound and re-run the C5 ladder"* — **is null by
construction and would have killed the angle on a fabricated result.**

- The inline fast path's per-message gate is **`if inline and len(names) == 1`** (`wiring_runner.py:3683` —
  **verified**).
- The shardcert ladder's default shape is **`H = D = dests = 8`** (`harness/config/shardcert/_shape.py:152-155` —
  **verified**).

**At H=8, `len(names) == 1` is never true. ZERO messages fuse. The ON arm is byte-identical to the OFF arm, the
result is ~0%, and the angle dies on a contrast that never engaged.** That is precisely the **B1–B10 disarmed-arm
defect class** — a fixed constant bounding a parameter-scaled interval, producing a fabricated verdict. We are not
running that experiment.

### 7.1 The arms (all in one session, on the same rig, same rungs)

| arm | shape | `inline` | `batch_handoff_statements` | purpose |
|---|---|---|---|---|
| **A — control** | H=1, D=1 | OFF | **OFF** | Same-session OFF baseline at the fusible shape. |
| **B — treatment** | H=1, D=1 | **ON** | **OFF** | The clean fusion contrast. |
| **C — deployed control** | H=1, D=1 | OFF | ON (shipped default) | What production actually runs today. |
| **D — deployed treatment** | H=1, D=1 | **ON** | ON | The honest as-shipped number (see the confound below). |
| **E — premise check** | **H ∈ {1,2,4,8}, D=1**, no-op transforms | OFF | ON | **The zero-code test of the Phase-4 premise itself.** See §7.4. |

### 7.2 The de-confound (this would have rigged the result)
**`handoff` has NO `batch_handoff_statements` dispatch** — verified: it goes straight to `_acquire()`, while
`route_handoff` (`sqlserver.py:~2371`) and `transform_handoff` both dispatch to `_route_handoff_batched` /
`_transform_handoff_batched` (ADR 0075), **and `batch_handoff_statements` defaults to True** (`settings.py:936`).
Separately, `wiring_runner.py:3635` (`if self._fusion_active and not inline:`) **explicitly excludes a fused inbound
from the ADR 0071 B5 sync path** — verified.

**So a naive `inline=True` flip compares a fused-but-UNBATCHED, B5-EXCLUDED path against a split-WITH-BOTH path.**
That is not stage-fusion-vs-split; it is fusion-minus-two-existing-optimisations vs split-with-them. A null would
kill a viable angle on a rigged comparison. **Arms A/B (both unbatched) are the primary contrast. Arms C/D are
reported as the as-shipped delta, with the confound named in the writeup.**

### 7.3 Manipulation check — MANDATORY, and it decides whether the run counts at all
`SqlServerStore.committed_txns` (`sqlserver.py:1027`, incremented in `_commit` at `:1030`) is on `/stats` and is
**already polled and summed across shards** by `harness/load/enginepoll.py:101,347` — **shardcert simply never
records it** (it reports the *modelled* `3 + 2H + 2D` instead). ~20 lines to record `Δcommitted_txns` per arm.

- **Predicted:** measured `committed_txns/msg` drops by **≥ 0.9** between arm A and arm B (the `transform_handoff`
  commit plus the entire ROUTED claim-episode stream).
- **`inline_fallbacks` (B0's new counter) must be exactly 0 in arms B and D.** If it is not, some messages took the
  split path and the FIFO hazard of §4.2 is live in the run — **void the arm.**
- **If the txn/msg drop is < 0.9, the arm was DISARMED. The run is VOID — it is NOT a refutation.** Fix the shape
  and re-run.

### 7.4 The premise check (arm E) — the most valuable thing in this plan
Hold `D = 1` (so `events/msg = 2` is **constant**) and sweep `H ∈ {1, 2, 4, 8}` with **no-op transforms** on the
**existing, unmodified split path**. `T_ded = 4 + H`, so txn/msg goes **5 → 12** while events/msg stays fixed.

- **If sustained events/s is FLAT across H=1..8** → per-message transaction count is **not** the constraint, and
  **Phase 4's entire premise is refuted with zero production code.** F2's whole value is removing the `2H` term; if
  the `2H` term costs nothing, removing it gains nothing. **We stop, write the ADR that closes Phase 4, and go find
  the real wall.**
- **If sustained events/s falls with H** → the premise survives, but the inference is **one-directional and we will
  say so:** H also adds routed rows, routed lanes and (a little) CPU, so a fall is *ambiguous*. **A flat result is a
  clean kill; a falling result is only weak support.** We are stating that asymmetry up front so nobody
  over-reads it later. *(This workstream has already retracted two results for over-reading. Not a third.)*

Arm E costs **one config sweep** and it is the highest-information experiment available to us.

### 7.5 The hard gates (non-negotiable, on every arm)
- **FIFO:** `lane_inversions == 0` **and** `lane_repeats == 0` on sink socket truth (`harness/load/shardcert.py:310-318`),
  **with the `lanes_observed >= 2` non-vacuity guard.** A collapsed arm still populates `ceiling.sustained_events_per_s`
  and **every collapsed arm exits 0** — **gate on `result`, and only quote a rung that delivered 100%.**
- **No loss:** `no_acknowledged_loss` / `acked_not_delivered == 0` under the two-node SIGKILL-under-load harness
  (`harness/load/failover.py`), with the kill injected **inside the fused unit** (between the ingress claim and the
  `handoff` commit).
- **Attribution:** per `[[mf-bench-attribution-policy]]` — client isolation, `max_core%` on both boxes, and
  **verified-nonzero collectors**. No bottleneck claim without them.

### 7.6 THE DECISION RULE (pre-registered; we do not get to move it afterwards)
Metric: **`sustained_events_per_s`, arm B vs arm A, at the last 100%-delivered rung AND at the collapse rung.**
Manipulation check must have passed. FIFO and loss gates must be green. Report median of ≥3 replicates with the
arm-to-arm noise floor stated.

| result | verdict |
|---|---|
| **≥ +8%** | **PROCEED.** Build F1 → F2 → F3. At H=1 fusion removes only 1 of 5 dedicated commits; F2 removes 8 of 12 at H=8 and the whole ROUTED stage — so an +8% at the *weakest* shape is a defensible lower bound on the mechanism. |
| **+3% to +8%** | **INCONCLUSIVE — HALT AND REPORT.** This is inside ADR 0071 B5's measured band (+6.5 / +9.3 / +10.0%), which was a **NO-GO to promote**. Do **not** auto-build. Owner decides whether F2's large, permanent, 3-backend surface is worth a B5-sized number. |
| **−3% to +3% (the NULL BAND)** | **ABANDON THE ANGLE.** The wall is per-**message**, not per-**transaction**. F2 and F3 must not be built. Write the ADR that closes Phase 4 and record `txn/event` as a **measured dead end**, so no future session re-opens it. *(F1 may still ship on its own merits — one pure-overhead txn off the ACK critical path.)* |
| **< −3% (REGRESSION)** | **ABANDON, AND ESCALATE.** This is **C7-shaped evidence**: concurrency removal hurts. F2 and F3 remove *more* concurrency than F0, so they would hurt *more*. This result is itself a **finding** — it says stage-level overlap is load-bearing, which reframes the whole search. |
| **Arm E flat across H=1..8** | **ABANDON, regardless of arm B.** The premise is refuted. This dominates every other result. |

We are pre-registering the **regression** band deliberately: the original design's kill criterion was one-sided
(*"≥15% or dead"*), which cannot see the harm this intervention could plausibly do.

### 7.7 One free rider (harness-only, ~20 lines, no production code)
While the `committed_txns` recorder is being added, also record **`mean_writelog_ms = Δwritelog_ms / Δcommitted_txns`**
per arm. This is the graft from the (otherwise dead) durability angle, and it **closes the durable-write file with a
number instead of an argument**: C6 found `WRITELOG` rank-1, but on a *healthy, 100%-delivered* arm — and a wait that
is rank-1 while the system meets its SLO is by construction not the constraint. **Predicted: `mean_writelog_ms` is
FLAT at 0.10–0.30 ms from N=4 to N=16.** If instead it inflates **>3×** while log bytes/event stay flat, there is a
shared-log serialisation under concurrency that ADR 0069's `commit_storm.txt` structurally could not see (it used one
heap table per thread — zero shared-index contention), and that would be a genuine new finding worth chasing. **Either
way, ADR 0055/0069 get amended with a measurement.**

### 7.8 F2/F3 gates (only if we get there)
- **The inverse identity gate.** Every prior lever here shipped a gate proving it did **not** move a commit boundary
  (ADR 0071 B5: `commits/msg == 2.000`; ADR 0075: same). **This lever is the mirror image — it MUST move it, by
  exactly the predicted amount and nothing else.** Pin measured `committed_txns/msg` **5 → 3** at H=1,D=1 and
  **19 → 10** at H=8,D=8, **while a golden-row assertion proves identical outbound rows, identical `seq` order,
  identical final dispositions, identical `message_events`.** This is the ADR 0075 count-gate pattern, inverted, and
  it makes "we only moved a commit boundary" a **fact** rather than a claim.
- **The heterogeneous-ordering test (B0)** must go from FAIL (today) to PASS (post-F2).
- **The G6 poison-crash gate** under **H > 1** fusion — the widened unit is exactly what G6 was written for.
- **`reset_stale_inflight`** recovers a fused in-flight ingress row **and** a drain-mode routed row in one startup.
- **A replay gate:** dead-letter-replay a ROUTED row on a fully-fused engine with F3 active, and assert it is
  claimed, delivered and finalized within `idle_max`. *(This is the exact hole that killed the original F3.)*
- **SQLite + Postgres:** FIFO and no-loss **test-proven** (not rig-measured). Say so in the writeup.

---

## 8. WHAT THIS DOES NOT DO

**It does not reach 45M/day. Not close. Not on its own. Not even if every optimistic number lands.**

- **The gap:** 45M/day = **520.83 total events/s, flat, across 1,500 connections**. Estate-wide that is **5.79×**
  from where we are. Per shard, **C5** puts the ceiling at **R ∈ [2,3)** against the **3.62/shard** a cleared N=16
  would need — a **1.21×–1.81×** per-shard shortfall, and **N-sizing alone is measured insufficient.**
- **Our best case is the top of that band, and only in combination.** Even a +30% fusion result plus F3's derived
  ~4.5% does not close 1.21×–1.81× with margin, and it does nothing for the estate multiple.
- **Half the store CPU is structurally out of reach of every transaction-reduction lever.** `list_fifo_lanes` —
  C4's #1 consumer at N=16 (47.5%) — is **clock-driven at 4 Hz**, not message-driven. F3 attacks it *only* for an
  idle stage. The rest is untouched by anything in this plan.
- **The claim path is out of reach too.** `claim_fifo_heads` (40.3%) cannot be batched (Hazard A poison-guard) and
  the outbound claim is hard-clamped to one row per lane (H2 skip-and-complete). **87.8% of store CPU is claim
  work that Phase 4 cannot reduce.**
- **~72% of the wall is off-CPU WAIT with no identified blocker** (C6: AMBIGUOUS-STRUCTURAL — convoy floor met in
  0 of 288 samples; largest suspended group = 2; max blocking-chain depth = 1). **There is no single blocker to
  fix**, and this plan does not claim to have found one.

**What else would be needed, honestly:**
1. **The store-side wall must still be cleared** — but per C4/C5 that is **necessary and not sufficient**, and the
   mechanism was **mis-identified** (`list_fifo_lanes` is #1, not the claim), so the previously-proposed
   claim-only rewrite is **insufficient by construction**. That work needs re-scoping before it is re-started.
2. **The engine-side plumbing wall** (~76% of per-box cost, ~193 events/s/engine — `[[mf-wsb-resolution-engine-cpu-wall]]`)
   is untouched by anything here.
3. **`accepts=` (#213 / #952, ADR 0084) is merged and is a CO-REQUISITE, not a competitor** — but **remember §3.3:
   on a fused inbound its transaction saving disappears (H is gone from the formula). Do not add the two gains.**
4. **Sequence-lane concentration.** The per-interface bound (~60 msg/s e2e) means 1,500 connections at ~0.35 msg/s
   each is a *concentration* problem, not a per-lane throughput problem. Nothing in Phase 4 changes that.

**And the most valuable single sentence in this document, which we would rather say now than have you find later:**

> **The Phase-4 premise — "the only lever left is reducing transactions per event" — is DERIVED, not MEASURED.**
> It follows from ruling out the other levers (C5 N-sizing, C6 convoy, C7 parallelism), not from any positive
> evidence that per-transaction cost binds. **Arm E (§7.4) tests that premise directly, for zero production code,
> in one config sweep.** If arm E comes back flat, **Phase 4 is dead — and the two days it costs will be the
> cheapest result this workstream has bought.**

---

## 9. Key files

`messagefoundry/pipeline/wiring_runner.py` — `_inline_ok` :662 · stage list :2220-2222 · ACK site ~:2985 ·
`_capture_ack` (fail-soft) ~:3022-3038 · `_process_ingress_item` :3585 · G6 attempts ceiling :3608-3629 ·
B5-excludes-inline :3635 · **`if inline and len(names) == 1` :3683** · per-message gates :3714-3721
`messagefoundry/store/sqlserver.py` — `committed_txns`/`_commit` :1027-1030 · cost model (`3+2H+2N`) :1034 ·
`_lock_finalize_batch` (sorted, **unused**) :1816 · `_maybe_finalize` :1824 · `enqueue_ingress` :2242 ·
**`handoff` :2309 (no `batch_handoff_statements` dispatch)** · `route_handoff` ~:2371 (has one) ·
`record_ack_sent` :2948 · `_lane_col` :3915 · `claim_fifo_heads` :4281 · `list_fifo_lanes` ~:4623 ·
`mark_batch_done` :4767 (**unsorted finalize loop :4808**) · **`replay` :5110 / `replay_dead` :5527 (scoped by
`message_id`, NOT stage)**
`messagefoundry/store/base.py:258` (the `handoff` contract) · `messagefoundry/store/store.py` ·
`messagefoundry/store/postgres.py`
`messagefoundry/pipeline/stage_dispatcher.py` — conservation law :28 · outbound clamp :246 ·
`_spawn_serializer` :625-627 · `_drain_lane` :781 · sweep loop ~:1000
`messagefoundry/config/settings.py` — `group_commit_window_ms=0.0` :257 · `fifo_claim_batch` :273 ·
`pooled_sweep_interval=0.25` :854 · `pooled_max_processing_lanes=256` :859 · `batch_handoff_statements=True` :936 ·
`diagnostics.response_sent=True` :984
`messagefoundry/config/wiring.py:1821` — `inbound(..., inline=False)`
`harness/load/shardcert.py` (:310-318 FIFO gates; :~2356 the *modelled* txn number) ·
`harness/load/enginepoll.py` (:101,:347 — `committed_txns` already polled, never recorded) ·
`harness/load/failover.py` (SIGKILL) · `harness/load/failover_track.py:19-22` (the FIFO contract) ·
`harness/config/shardcert/_shape.py:152-155` (**H = D = dests = 8 by default — the disarmed-arm trap**) ·
`tests/test_inline_fast_path.py`
