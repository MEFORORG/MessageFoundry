# 0075 — Per-hop SQL statement batching (`batch_handoff_statements`)

- **Status:** Accepted (2026-07-07) — owner ratified; prototype built (#820, CI SS-gated). **Promote target reframed 2026-07-07: `default-ON` gated on a _harmless-near + helps-far_ rig result (see Amendment below), not the single-RTT ≥10% bar.**
- **Deciders:** throughput working group (owner ratifies; build + promote gated on a live-rig A/B)
- **Related:** **builds the lever [ADR 0069](0069-durable-write-throughput-lever.md) named and left un-attacked** ("batching SQL statements per executor hop" — the round-trip half of the feed wall, distinct from its rejected durable-write levers) · **complements [ADR 0071](0071-cut-executor-round-trips-b5.md)** (B5 thread-hop fusion — NO-GO 2026-07-06; cut executor→loop *crossings* but not the per-hop *network round-trips* the fusion NO-GO explicitly attributed part of its dilution to) · [ADR 0055](0055-group-commit-durable-write.md) / [ADR 0053](0053-free-threaded-multicore-engine.md) (the other throughput levers) · [ADR 0001](0001-staged-pipeline-architecture.md) / [ADR 0066](0066-pooled-stage-claimers.md) (staged-pipeline + pooled-claimer invariants) · CLAUDE.md §2 (reliability / at-least-once / count-and-log invariants) · the throughput-microbench statement/RT inventory (`docs/benchmarks/results/2026-07-04-adr0071-b5-executor-marshaling/statement_rt_inventory.py`)

---

## Amendment (2026-07-07) — reframed as a distance-insurance lever; target is **default-ON**

The rig measured the current bench placement at **~0.2 ms** engine↔store RTT (same-AZ cluster). Because this
lever's value is **proportional to engine↔store RTT**, a single-RTT "≥10% throughput lift" bar (§Gate / AC-6
below) mis-frames it: it is not a raw speed lever but **distance insurance**.

- **Near (store co-located with the engine — normal operation):** cutting round-trips saves ~nothing on the
  wire → the lever is a **no-op**. (It also cuts internal executor→loop marshaling crossings, so the near-case
  effect is expected **neutral-to-slightly-positive**, not negative — the baseline run confirms it.)
- **Far (DR failover — the secondary engine at the DR site reaches cross-site to the still-primary AOAG store;
  "the engine failed over, the store did not"):** each round-trip is expensive → cutting them is a
  **meaningful** win. This is the scenario the lever exists for. (If the AOAG *also* fails over so the store
  is local again, the lever is back to a near-case no-op — correct and self-adjusting.)

**A manual opt-in switch is the wrong design for a DR lever:** an automatic failover will not stop to flip a
throughput flag, so a switch that must be thrown mid-incident is one that never gets thrown. The **target is
therefore `batch_handoff_statements` default-ON**, with the flag retained **only as an emergency off-switch**
(for a hypothetical workload that ever regresses), not as an operational control operators normally touch.

**Revised promote criterion (supersedes the single-RTT ≥10% bar in §Gate and AC-6):** flip the default to ON
when the rig shows **both** — (1) **HARMLESS near** (no throughput regression at the co-located ~0.2 ms
baseline) **and** (2) **HELPS far** (a meaningful lift at a DR-representative RTT). Best characterized as an
**RTT sweep** (same-AZ → cross-AZ → cross-region) that finds the threshold RTT above which batching pays;
that threshold becomes the deployment note ("on for engines running more than ~X ms from their store").

**The hard gate before default-ON is CORRECTNESS, not the speed number:** the SS-gated tests
(`tests/test_adr0075_batch_sqlserver.py` — real-driver positioning, fail-closed on a real applock timeout,
serialization, ON/OFF disposition parity) must pass on the CI SQL-Server leg / the rig. That is the
precondition; the harmless-near + helps-far sweep is the promote decision.

---

## Context

ADR 0069 corrected the "store-write-bound" label: the SQL Server store absorbs ~27,000 commits/s while the pipeline feeds it only ~750 commits/s at its ~107 msg/s ceiling — a ~36× feed gap. It rejected every **durable-write-tier** lever (app-side group-commit, faster log, bigger pool — each ~0) and directed effort to the engine-side feed, naming three concrete levers to pursue: *"the executor split, batching SQL statements per executor hop, and free-threading (ADR 0053)."* ADR 0071 built the **executor split / thread-hop fusion** (B5) and free-threading is ADR 0053. **This ADR is the one remaining named lever: batching SQL statements per hop.**

The forcing measurement is the 2026-07-04 SQL Server profile behind ADR 0071 §2: the per-engine wall is **not** CPU and **not** the store (both idle at the ceiling) — it is the async machinery *around* each off-loop store statement on the single loop thread. On the SQL Server backend the store runs on **aioodbc**, which dispatches **each `pyodbc` statement to its own thread executor**, so every statement is *both* an executor→loop crossing *and* a network round-trip. A single handoff body issues **many** of each. ADR 0071's fusion attacked the *crossing* half (a synchronous handoff marshals back once: micro-bench 12→2 crossings/msg) but left the *round-trip* half untouched — even the fused sync path issues the body's statements as **serial round-trips**. The 2026-07-06 fusion NO-GO bench (ADR 0071 §8) named an **~11 ms inter-box store RTT** as a plausible dilutant fusion could not address because *"it cuts marshaling crossings, not network hops."* With ~4–5 store round-trips per message at ~11 ms each, per-hop serial round-trips are a genuine co-bottleneck that neither B5 fusion nor any durable-write lever touches.

The reliability fence any such lever must respect is quoted verbatim from CLAUDE.md §2:

> Every subsequent stage **handoff** (ingress→routed, routed→outbound) is a **single committed transaction** (claim → produce-next-stage rows → complete-this-stage), so a message is never lost or partially handed off … each handoff is idempotent against a re-run (the consumed row is gone, so a re-run is a no-op).

and ADR 0069's fence on *how far* commit-depth can be reduced:

> `route_only`/`transform_one` run *off the loop* between a claim and its handoff, so claims cannot fuse with handoffs, and the poison-guard claim must stay standalone … So ~7 [commits/msg] is close to a floor here.

The owner **HELD** the "SQL statement-batching per hop" build-go on the framing that per-hop batching is *invariant-blocked* by that same fence. This ADR settles that: it is not. Per-hop statement batching folds a multi-statement handoff **body** into 1–2 `pyodbc.execute()` batches — it cuts **round-trips, not transactions**. Each staged handoff still commits exactly once; no commit boundary moves; the logical `(sql, params)` sequence is preserved. Only **cross-lane** handoff batching (folding two hops' commits into one) would approach the ADR 0069 fence — that is a different lever, explicitly out of scope here.

There is precedent in the shipped code: the finalize `sp_getapplock` (`_SQL_APPLOCK`) is already a **4-statement T-SQL batch sent as one round-trip**. This lever extends that same technique from the applock to the rest of the handoff body.

## Decision

Add a `[pipeline].batch_handoff_statements` flag — **default-OFF, fail-closed, SQL Server only** — that, when enabled, generates a **batched form** of each per-hop handoff body: the same ordered `(sql, params)` sequence, grouped into the fewest `execute()` round-trips permitted by the client's own control flow, still committing exactly once per hop.

**What batching does and does not move:**

- **Round-trips down, transactions unchanged.** A batch groups consecutive statements between two *hard client-branch boundaries* — a statement whose result the client must read before it can build a later statement's SQL/params, or decide whether to run later statements at all (idempotency guard, finalize count, `mark_done`'s opening SELECT, the H2 ledger SELECTs, the PT lineage SELECT). Everything between two boundaries folds into one round-trip. The single per-hop `COMMIT` is untouched, so **`commits/msg` stays 2.000** (route_handoff + transform_handoff) — the covert-transaction-fusion identity guard. **No commit boundary moves; the ADR 0069 fence is not hit.**
- **Generated from the shared builders — the anti-drift seam.** The batched forms are assembled from the **same shared SQL constants + param-builders** (`_SQL_DELETE_GUARD`, `_SQL_APPLOCK`, `_SQL_UPDATE_MESSAGE_STATUS`, `_SQL_INSERT_EVENT`, `_insert_routed`/`_insert_outbound`, `_event`, `_maybe_finalize`, …) that already keep the async `route_handoff`/`transform_handoff`/`mark_done` and their shipped `*_sync` twins byte-identical. The batched form is a **third emission of the identical logical sequence**, not a re-authored one.
- **Claim stays standalone; ACK-on-receipt untouched.** The pooled claimer's `attempts+1` claim remains its own committed poison-guard transaction (ADR 0066 / ADR 0069). The ingress commit-before-ACK stays its own path. Batching only reshapes the *body* of the ingress→routed / routed→outbound / delivery-complete transactions, never their boundaries.
- **Composes with, but does not require, B5 fusion.** Batching works on the **default async (aioodbc) path** — which is where the engine runs, since fusion shipped default-OFF after its NO-GO — folding ~5–6 `execute()` per hop into 1–2 there cuts *both* network round-trips *and* aioodbc executor crossings. It also composes with a fused sync hop (cutting that hop's serial round-trips). It is the one lever that attacks **both** residuals — default-path crossings **and** the serial-RT co-bottleneck B5 could not — without moving a transaction boundary.
- **Content-vs-infra attribution preserved (load-bearing).** A batched `execute()` that fails must still attribute **which** statement failed and **why**, so an infrastructure fault (deadlock, timeout, connection drop) re-pends the message (never a content dead-letter for an infra cause) while a genuine content/constraint fault dead-letters. Where a fetch-bearing or gating statement's failure attribution — or the applock-rc-fold judgment (below) — demands it, that statement **stays its own `execute()`**; **partial batching still cuts most round-trips.**

**Reliability-core wiring.** The flag is read **once at engine construction** (a `/config/reload` does **not** re-read it — restart to change, exactly like `claim_mode` and `fuse_thread_hops`), fail-closes to the unbatched async path on any non-SQL-Server backend (logged "ignored"), and exposes a harness override `MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS` for the A/B.

## Evidence (honest, and conditional)

A microbench measured off the **real shipped store methods** (driving `route_handoff_sync` / `transform_handoff_sync` / `mark_done` against a recording fake cursor — the same offline harness style as the sync-handoff offline test) inventoried the exact ordered `(sql, params)` sequence each SQL Server hop issues, then modelled the batched round-trip count under an auditable batching model (round-trips = `execute()` + `commit()`; `fetch*` on a just-executed small result are buffered reads, not guaranteed extra round-trips). The inventory (`statement_rt_inventory.py`) and its living gate (`tests/test_adr0071_statement_rt_inventory.py`) were **adversarially re-reviewed and the counts VERIFIED honest.** *(Both currently live on the in-flight `throughput-microbench` branch — not yet merged; they land with, or ahead of, this ADR's build. The `b5_microbench.py` sibling and `tests/test_adr0071_crossing_count.py` — the crossing-count gate this ADR's RT-count gate mirrors — are already on `main`.)*

**The unconditional result** (interpretation-independent):
- **`commits/msg` stays 2.000 per handoff pair** — no commit boundary moves.
- **The logical `(sql, params)` sequence is preserved** — same statements, same order, same params.
- ⇒ **Per-hop batching is NOT invariant-blocked.** It moves no commit boundary; only *cross-lane* handoff batching approaches the ADR 0069 fence.

**The conditional result — the round-trip drop is a range, and the ≥40% figure is CONDITIONAL.** It hinges on one modelling choice: whether the finalize `sp_getapplock` **rc-check folds into the trailing batch**. The client only *validates* the rc (raise on rc<0 → rollback); it never changes which SQL/params come next, so folding is net-identical (an UPDATE/event that ran server-side before the client read rc<0 is rolled back with the whole transaction and is invisible to any other session). But it is the one judgment call, so both floors are reported and **neither may be quoted in isolation**:

| hop | round-trips (async) | `applock_soft` (rc folded) | `applock_hard` (rc gated) |
|---|---:|---:|---:|
| `route_handoff` | 6 | 3 (**50.0%**) | 4 (33.3%) |
| `transform_handoff` | 7 | 4 (**42.9%**) | 5 (28.6%) |
| route+transform pair | 13 | 7 (**46.2%**) | 9 (30.8%) |
| `mark_done` | 11 | 7 (36.4%) | 8 (27.3%) |

**CRITICAL HONESTY:** the ≥40% figures hold **only** under the applock-rc-fold assumption, and even then `mark_done` (36.4%) does not clear it. Under the **strict** interpretation (the applock rc kept as its own gating round-trip) the drops are **27–33% and NOTHING clears 40%.** The honest headline is: *"27–50% per-hop round-trip opportunity; ≥40% only under the applock-fold; strict interpretation 27–33%, clears nothing."*

**What the microbench does and does not deliver.** It proves the crossing/round-trip **arithmetic** and the **no-transaction-fusion identity** against the real statement sequences. It does **not** prove throughput lift (round-trip savings are one input to throughput, not throughput) and does **not** exercise the real-path invariants under crash/load. It is the **justification to run the rig A/B, not a substitute for it.**

## Gate (the honest core)

> **Superseded by the Amendment (2026-07-07) above.** The single-RTT ≥10% bar below reframes to
> _harmless-near + helps-far → default-ON_ (this lever is distance insurance, not a raw speed lever);
> correctness on real SQL Server is the hard precondition. The bar below is retained for context / as the
> per-RTT-cell throughput measurement used within the sweep.

**Build and promote are gated on a live-rig end-to-end A/B meeting the standard conjunctive bar** (the same bar ADR 0071 §6.4b and ADR 0066 §9 apply):

- **≥10% median throughput lift AND >2σ** across the concurrency cells (SQL Server, pooled, C ≥ 256, ≥3 trials/arm), on a real two-box rig with a representative inter-box store RTT;
- **zero-loss**, `delivered/offered ≥ 0.98`, **per-lane FIFO** intact, `in_pipeline` flat-or-lower — all cells, in every trial.

**The microbench alone does NOT clear this bar.** Its ≥40% is applock-fold-conditional and, being a round-trip inventory, says nothing about throughput. A sub-threshold or null rig result **banks nothing** — keep the flag default-OFF and record the outcome (as ADR 0071 did on its own NO-GO). Because the fusion NO-GO named the ~11 ms network RTT as its residual dilutant, this lever — which attacks exactly that network-RTT term — is the one with a live reason to expect a different sign; the A/B is how we find out, not assume.

**Anti-drift tripwire.** A **living statement/round-trip-count CI gate** — mirroring `tests/test_adr0071_crossing_count.py` and driving the same `statement_rt_inventory.py` — asserts, on every Windows `test` leg, that the batched and unbatched forms emit the **identical logical `(sql, params)` sequence** and that `commits/msg` stays exactly 2.000, and pins both the soft and strict round-trip floors so neither can silently regress or be quoted alone.

## Acceptance Criteria

> EARS form; each linked (`→`) to the test/fixture that verifies it. `messagefoundry adr-analyze` checks each `→` resolves.

- **AC-1** — WHEN `batch_handoff_statements=true` on a SQL Server store, THE SYSTEM SHALL emit, for each of `route_handoff` / `transform_handoff` / `mark_done`, the **identical logical `(sql, params)` sequence** as the unbatched path, grouped into fewer `execute()` round-trips, with **`commits/msg` unchanged (2.000 per handoff pair)**.
  → `tests/test_adr0075_batch_golden_sql.py::test_batched_matches_unbatched_sequence`
- **AC-2** — WHEN `batch_handoff_statements=true`, THE SYSTEM SHALL preserve per-handoff atomicity and idempotency: a crash after the claim commit / after the body but before the handoff commit / after the handoff commit SHALL, on restart + `reset_stale_inflight`, re-run in seq order with **zero loss and zero duplicate next-stage rows**.
  → `tests/test_staged_pipeline.py::test_batched_handoff_crash_replay` (SQLite skip; SS CI leg)
- **AC-3** — IF a batched `execute()` fails, THEN THE SYSTEM SHALL attribute the failure to the correct statement and classify it CONTENT vs INFRA — an **infrastructure fault re-pends** the message (never a content dead-letter), a content/constraint fault dead-letters — identically to the unbatched path.
  → `tests/test_adr0075_batch_error_attribution.py`
- **AC-4** — WHERE the store backend is not SQL Server (Postgres / SQLite) OR the flag is off, THE SYSTEM SHALL run the unbatched async path **byte-identically**, and a non-SQL-Server backend with the flag on SHALL log "ignored" and fail closed to the async path.
  → `tests/test_adr0075_batch_backend_gate.py`
- **AC-5** — THE SYSTEM SHALL keep the batched and unbatched forms in lockstep: the living statement/round-trip-count gate SHALL assert an identical logical sequence, `commits/msg == 2.000`, and pin BOTH the `applock_soft` (≥40%-only) and `applock_hard` (27–33%) round-trip floors so neither is quotable in isolation.
  → `tests/test_adr0071_statement_rt_inventory.py` (extended) · `tests/test_adr0075_rt_count_gate.py`
- **AC-6** — IF the live-rig A/B does not meet the conjunctive bar (≥10% median AND >2σ, zero-loss, `delivered/offered ≥ 0.98`, per-lane FIFO), THEN THE SYSTEM SHALL keep `batch_handoff_statements` default-OFF (build banks nothing; outcome recorded).
  → `docs/benchmarks/results/<date>-adr0075-batch-throughput/` (rig artifacts + verdict)

## Options considered

1. **Per-hop statement batching (`batch_handoff_statements`, default-OFF, SQL-Server-only), gated on a live-rig A/B.** **CHOSEN.** The one remaining ADR 0069-named lever; attacks both the default-path crossing residual and the serial-RT co-bottleneck (the ~11 ms × 4–5 RT/msg term the fusion NO-GO could not touch); moves no transaction boundary (commits/msg identity holds); generated from the shared builders (anti-drift). Honest about the conditional evidence: microbench justifies the A/B, does not substitute for it.
2. **Transaction fusion / cross-lane handoff batching** (fold two hops' commits into one). **Rejected** — folding commits crosses the ADR 0069 fence (standalone poison-guard + per-handoff atomicity + cross-lane atomicity). This is the lever the owner-HELD framing conflated with per-hop batching; the microbench's `commits/msg == 2.000` identity is precisely the line between them.
3. **B5 thread-hop fusion (ADR 0071).** **NO-GO 2026-07-06** (+6.5 / +9.3 / +10.0 %, below the ≥10% bar). Cut executor→loop crossings but not per-hop network round-trips — the residual this ADR targets. Complementary, not a substitute; batching can compose with a fused hop or stand on the default path.
4. **Free-threading (ADR 0053).** Parallelizes marshaling across cores but reduces no round-trips; ~+6–7% paper estimate is a NO-GO (#789); carries cp314t + python-hl7-refcount caveats. The escalation path if this lever also nulls, not a replacement for it.
5. **Durable-write-tier levers** (app-side group-commit / faster log / bigger pool). **Rejected (ADR 0069, measured ~0)** — the store is idle at the wall; these amortize an fsync that is ~6% of the round-trip. Batching cuts round-trips, not fsyncs.

## Consequences

**Positive** — attacks the network-round-trip half of the SS feed wall that B5 fusion and every durable-write lever leave untouched; works on the **default async path** (where the engine actually runs); moves no transaction boundary (durability + at-least-once + count-and-log untouched by construction); additive + behind a fail-closed flag; Postgres/SQLite provably unaffected; the anti-drift gate makes silent divergence a CI failure.

**Negative / risks** —
- **Reshapes reliability-core SQL text.** A **golden-SQL test asserting the batched and unbatched forms emit an identical logical statement sequence is mandatory** (AC-1/AC-5), not optional.
- **RCSI + `sp_getapplock` interaction under batching** must be re-confirmed: the finalize applock is transaction-scoped (`@LockOwner='Transaction'`), so folding it into a body batch keeps it in the same transaction — but the control-flow ordering (leading guard-DELETE opens the transaction so the applock is never a batch's first statement) must hold in the batched form too.
- **CONTENT/INFRA attribution is a load-bearing boundary** — a batched multi-statement `execute()` must not lose which statement failed; mis-attributing an infra fault as content would dead-letter a deliverable message (breaking count-and-log's "never accept-and-drop" intent). Where attribution needs it, a statement stays unbatched (partial batching still cuts most round-trips).
- **A third emission surface** of the handoff sequence (async + sync twin + batched) to keep in lockstep — mitigated by generating all three from the same shared constants/param-builders and the living inventory gate.
- **The magnitude is conditional and unproven for throughput.** ≥40% is applock-fold-only; strict is 27–33%; and neither round-trip number is a throughput number. If the rig A/B nulls, the honest outcome is to bank nothing and escalate to ADR 0053.

**Out of scope** — cross-lane handoff batching / any commit-boundary fusion (ADR 0069 fence); Postgres (asyncpg is loop-native and pipelines internally — no per-statement executor crossing to fold; a round-trip lever there is a separate question) and SQLite (loop-affine single-writer WAL); the delivery-send path (loop-native MLLP socket I/O, ADR 0067).

## To resolve on acceptance

> Open questions to settle before this flips to `Accepted`.

- [ ] **The applock-rc-fold behaviour question.** The re-review found folding technically sound (rc<0 raises → whole-transaction rollback, so any statement that ran server-side before the rc is read is never committed and is invisible to other sessions) — but **confirm it against the FINAL batched control flow** (the guard-DELETE-opens-the-transaction ordering and the finalize applock's position in the trailing batch), and decide whether v1 ships `applock_soft` (fold) or `applock_hard` (gate). This single choice is what separates a ≥40%-clearing model from the strict 27–33% one.
- [ ] **The live-rig A/B result** — the GO/NO-GO. Meets the conjunctive bar (≥10% median AND >2σ, zero-loss, `delivered/offered ≥ 0.98`, per-lane FIFO, `in_pipeline` flat-or-lower) at C ≥ 256 on a real two-box SQL Server rig, or it banks nothing and the flag stays default-OFF.
- [ ] **Statement-level error attribution under a batched `execute()`** — confirm pyodbc surfaces enough to attribute WHICH statement in a batch failed (or fix the batch boundaries so a fetch/gating statement that needs distinct attribution stays its own `execute()`).
- [ ] **`mark_done` inclusion** — the delivery-complete hop clears neither floor's ≥40% (36.4% soft / 27.3% strict); decide whether to batch it in v1 or defer it behind the route/transform pair.
