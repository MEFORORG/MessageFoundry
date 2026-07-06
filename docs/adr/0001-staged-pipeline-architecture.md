# ADR 0001 — Staged pipeline: per-stage durable queues

- **Status:** Accepted (2026-06-11) — ratified; Step A may begin. (Proposed → Accepted same day; the
  recommended answers below stand and the open questions are resolved as noted.)
- **Built:** Step A (ingress stage + ACK-on-receipt) and **Step B** (the full router/transform split —
  `ingress → routed → outbound`) are both built. The workload-conditional split (Q5) was taken as a
  forward investment in router-vs-transform isolation; its realized 3-stage cost (≈3 durable
  transactions/message single-handler, +1 per extra handler) is recorded in
  [`docs/benchmarks/step-b-write-amplification.md`](../benchmarks/step-b-write-amplification.md).
- **Supersedes:** the inline-pipeline model described in [`ARCHITECTURE.md`](../ARCHITECTURE.md) and
  `CLAUDE.md` §2 (to be revised on acceptance).
- **Related:** [`message-ordering-design.md`](../message-ordering-design.md) (Phase 1, now built),
  [`BACKLOG.md`](../BACKLOG.md) "Next up" + items 1 (SQL Server concurrency) and 3 (per-key ordering).

## Context

Today the pipeline is **inline**. An inbound listener runs each message straight through:

```
listen → decode → peek/parse → (opt. strict validate) → Router → Handler(s) → write outbox rows → commit → ACK
```

The **only durable queue is the per-outbound outbox**; routing and transformation run synchronously
on the inbound path. Two "do-not-break" invariants (CLAUDE.md §2) hold this together:

1. **Reliability:** the inbound is ACKed **only after** the message + its outbox rows are durably
   committed (at-least-once, broker-free, on SQLite WAL).
2. **Count-and-log:** every received message is persisted **with a disposition before the ACK**
   (`RECEIVED`/`PROCESSED`/`UNROUTED`/`FILTERED`/`ERROR`), so inbound counts reflect true volume.

Phase 1 (ordering) added FIFO-per-outbound, the failure-classification policy, and alerting — but
**only at the outbound stage**, because that is the only stage with a durable queue. The inline model
has structural limits this can't reach:

- A slow or failing **transform blocks the listener** — intake throughput is coupled to transform cost.
- There is **no durable buffer before the outbox**; a burst is bounded by how fast the listener can
  route+transform inline.
- **FIFO + the configurable error policy + alerting apply only to outbound** — a router or transformer
  failure has no queue, no retry lane, no per-stage replay.
- There is **no natural home for per-key lanes** (BACKLOG #3) — ordering is a property of the outbox only.

The decided target is a **staged, decoupled pipeline**: a durable queue between every stage, each
drained by its own worker, with FIFO + the Phase-1 error policy applied **uniformly at every stage**.

```
listen → [ingress queue] → ingress worker → [router queue] → router worker → [transform queue] → transform worker → [outbox] → delivery worker → partner
```

This is a **pipeline-core rewrite that revises both invariants**: it moves to **ACK-on-receipt** (ACK
once the raw message is durably persisted, before routing/transform) and **disposition-recorded-as-it-
flows** (the message's disposition is no longer fully known at ACK time). Because that changes
partner-visible behavior and the reliability/count-and-log guarantees, the decision is recorded here
**before any code**.

## Decision

Adopt the **staged pipeline with per-stage durable queues**, built **incrementally**, on the existing
single-file SQLite (WAL) store, reusing the Phase-1 queue machinery. The six design questions the
backlog flagged are resolved as follows.

### 1. ACK semantics — ACK-on-receipt, with an opt-in synchronous gate

The inbound listener persists the **raw message to the ingress queue**, commits, and ACKs — *before*
routing and transformation. An `AA` now means **"durably received and persisted,"** not "accepted and
routed." Routing/transform run asynchronously downstream; a transform/route failure therefore **no
longer NAKs the original sender** — it becomes an internal disposition (`ERROR`/dead-letter) + alert.

This matches mainstream interface-engine behavior (Mirth/Rhapsody ACK on receipt by default), but it
is a **partner-contract change** and some senders rely on a synchronous NAK for malformed input. So:

- The **ingress stage keeps the cheap synchronous work** that *can* legitimately reject at receive
  time — decode, `peek`/parse, and (when the connection sets `validation.strict`) hl7apy validation —
  and **NAKs `AE`/`AR` on those failures before enqueuing**, exactly as today. Only **routing and
  transformation** move downstream of the ACK.
- A per-connection `ack_mode`-adjacent setting (working name `ack_after = ingest` (default) `|`
  `delivered`) lets a connection that genuinely needs end-to-end confirmation defer its ACK to a later
  stage. Default is `ingest` (ACK-on-receipt). This preserves an escape hatch without making it the norm.

"ACK-on-receipt" therefore precisely means: **ACK after the ingress stage (decode + parse + optional
strict-validate) commits the raw message** — not "ACK before any parsing."

### 2. Transactional stage handoff — one transaction, pure transforms

Every stage worker performs **claim → produce-next → complete as a single store transaction**:

```
BEGIN
  UPDATE this_row     SET status='inflight', attempts=attempts+1   -- claim
  INSERT next_stage_row(s)                                         -- produce
  UPDATE this_row     SET status='done'                            -- complete
COMMIT
```

Crash semantics on one SQLite file:
- Crash **before commit** → the whole transaction rolls back; the row stays `pending` (or is reset
  from `inflight` by recovery) and the stage re-runs. No partial handoff.
- Crash **after commit** → the row is `done`; the next stage already has its input. No re-run.

**Idempotency rule:** transforms must be **pure** (message in → message out, no external side effects;
side effects belong only in connections — already a CLAUDE.md §8 rule). Given purity, a stage re-run
re-derives identical output, so the only at-least-once boundary that touches the outside world remains
the **outbound delivery stage** — which already requires idempotent receivers today. **Staging adds no
new idempotency burden** as long as transform purity is enforced (we should make it a checked
expectation, not just a convention).

> **Update (H2, 2026-06-24): MF-side outbound idempotency ledger.** The outbound stage stays
> at-least-once, but it no longer relies *solely* on the receiver to dedupe. A `delivered_keys` ledger
> row is written **in the same transaction** as `mark_done` / `complete_with_response`, keyed on the
> queue row's `outbox_id` and a SHA-256 of **non-PHI** ids + a replay-stable `delivery_seq` (the same
> counter shape as `response_seq`). The FIFO claim then **skips-and-completes in place** a re-claimed
> head whose `outbox_id` is already in the ledger (a crash-re-run recovered by `reset_stale_inflight`
> *after* `mark_done` committed, or a failover re-claim) — completing it `DONE` without a second send
> and returning `None`, so the lane advances with **no reorder**. A deliberate operator `replay`
> re-send DELETEs the affected ledger rows first, so an intentional re-transmit is **not** deduped
> (replay-distinguishing). The residual at-least-once window — a crash *before* `mark_done`/the ledger
> row commit — is unchanged (no ledger row exists to skip on, exactly as before), so idempotent
> receivers remain the contract for that window. The ledger carries **hashes + ids only, never a body
> or PHI**, so it is stored in the clear and is not part of the `_cipher` seam.

### 3. Revised invariants

- **Reliability (revised):** the inbound is ACKed only after the **raw message is durably committed to
  the ingress queue**; every subsequent stage handoff is a single committed transaction (§2), so a
  message is never lost between stages — **at-least-once end-to-end** is preserved, still broker-free.
- **Count-and-log (revised):** every received message is **persisted at ingress before the ACK** (so
  inbound counts still equal true received volume), and its **disposition is recorded as it flows** —
  `RECEIVED` at ingress → `ROUTED`/`UNROUTED`/`FILTERED` after the router → `PROCESSED` after the
  outbound drains, or `ERROR`/dead-letter at whichever stage failed. **The ACK no longer implies a
  final disposition** — only receipt-and-persistence. Both invariants' statements (CLAUDE.md §2) and
  their tests get rewritten as part of acceptance.

### 4. Per-stage queue schema + recovery — one generic table, reuse Phase-1 machinery

Use a **single generic staged-queue table** with a `stage` discriminator, mirroring the proven outbox
shape: `id, message_id, stage, payload, status, attempts, next_attempt_at, last_error, created_at,
updated_at`, indexed `(stage, status, next_attempt_at)` for the claim and ordered `(created_at, rowid)`
for FIFO. **(Superseded by [ADR 0059](0059-seq-only-fifo-ordering.md): per-lane FIFO now orders by
`seq` alone — SQLite `rowid`, SQL Server `BIGINT IDENTITY`, Postgres `BIGSERIAL` — dropping the
`_fifo_created_at` write-time clamp. `created_at` stays a real ingest-time/metrics timestamp but is no
longer the ordering key; one serial writer per lane makes seq order == receive order with zero
wall-clock dependence. The reliability invariant and the #285 no-skip / head-of-line-blocking lock
semantics below are unchanged.)** The current **outbox becomes "the outbound stage's rows"** of this model. The Phase-1 store
methods generalize to take a `stage`: `claim_next_fifo` / `claim_ready`, `mark_done` / `mark_failed` /
`dead_letter_now`, `reset_stale_inflight`, `pending_depth`. The Phase-1 worker (FIFO/unordered,
retry-policy, internal-error policy, buildup alert) becomes a **per-stage worker** parameterized by
stage — so ordering, failure policy, and alerting are uniform across stages by construction.

- **Recovery:** `reset_stale_inflight` runs **per stage** at startup.
- **DLQ / replay ("from which stage?"):** a dead row carries its `stage`; **replay re-enqueues at the
  failed stage** by default (re-run just the failed transform), with **replay-from-ingress** as an
  explicit option (re-run the whole pipeline). The Phase-1 DLQ/replay API generalizes with a `stage`
  filter.

### 5. Store strategy — build on SQLite, minimize stages, benchmark; SQL Server is the scale path

Staging multiplies durable writes per message: each stage adds a claim-update + a produce-insert + a
complete-update. A full 4-stage pipeline is roughly **3× the writes** of the inline model, on a
**single-writer** SQLite (WAL) store — real latency/contention under load.

Decision: **build on SQLite** (correctness first; typical HL7 volumes are not high-frequency), and
**minimize stages to those that deliver real isolation value**. Start with **ingress → processing →
outbound** (router+transform combined in one "processing" worker), splitting router and transformer
into separate stages **only if a workload needs independent router-vs-transform isolation**.
**Benchmark** the write amplification before committing to the full 4-stage split. The multi-writer
**SQL Server backend is the scale path**, but it is **gated on BACKLOG #1** (its concurrency bugs must
be fixed first) — staging would compound them.

> **Update (2026-06-20):** the SQL Server **and** Postgres staged backends have since shipped — each sets
> ``supports_ingest_stage = True`` and runs the full `ingress → routed → outbound` pipeline (see
> [FEATURE-MAP §5](../FEATURE-MAP.md)). This paragraph is retained as the original decision record.

### 6. Incremental build order — one boundary first

Do **not** restructure all at once. Prove the durable-queue + transactional-handoff pattern at a single
boundary, then extend:

- **Step A — ingress queue (one boundary).** Inbound listener: decode + parse + optional strict-validate
  → **persist raw to the ingress queue → commit → ACK** (ACK-on-receipt). An **ingress/processing worker**
  claims from the ingress queue and runs router + transform inline (as today), writing outbox rows via a
  transactional handoff, then completes the ingress row. This delivers ACK-on-receipt, decouples the
  listener from routing/transform latency, and exercises the revised invariants + one transactional
  handoff — **without** yet splitting router and transformer. Rewrite the invariant tests here.
- **Step B — full staging (built).** Split router and transformer into their own durable queues +
  workers: the combined ingress worker becomes a **router worker** (ingress → one `routed` row per
  selected handler, via `route_handoff`) and a **transform worker** (each `routed` row → outbound rows,
  via `transform_handoff`), so a slow/failing transform can no longer block routing and each handler's
  transform is independently observable/retryable. The `routed` stage carries the raw (consumed at its
  handoff, so no extra PHI at rest), keyed on `channel_id` like ingress; the store **finalizer** became
  the single disposition authority (it never finalizes while any earlier-stage row is in flight). Built
  three stages, **not** four — `ingress → routed → outbound` — matching the ~3-transaction target.

## Options considered

1. **Status quo — inline pipeline.** *Pros:* simplest, fewest writes, ACK carries full disposition,
   synchronous NAK on bad messages. *Cons:* transform cost blocks the listener; no durable buffer before
   the outbox; FIFO/error-policy/alerting only at the outbound stage; no per-stage isolation or replay;
   no home for per-key lanes. → The baseline we are deliberately moving past.
2. **Staged pipeline, per-stage durable queues (CHOSEN).** *Pros:* per-stage isolation; uniform FIFO +
   error policy + alerting (Phase 1 carries straight in); durable backpressure/buffering; natural home
   for per-key lanes; burst smoothing at ingress. *Cons:* write amplification on single-writer SQLite;
   ACK-semantics + invariant changes; ordering now matters at every stage; config/API/console surface
   multiplies per stage.
3. **External broker (Kafka / RabbitMQ / Redis Streams) between stages.** *Pros:* battle-tested
   durability/backpressure, horizontal scale. *Cons:* breaks the core "**no separate broker** —
   transactional inbox/outbox on SQLite" reliability model and the on-prem single-file deployment story;
   adds a broker to run/secure/back up; a cross-system handoff is a distributed transaction / dual-write,
   losing the single-transaction guarantee of §2. → **Rejected** — the reliability model is broker-free
   by design.
4. **In-memory staging (asyncio queues, no durability).** *Pros:* cheap, decouples the listener. *Cons:*
   a crash loses in-flight messages between stages → breaks at-least-once. Pinning the ACK to full
   completion to compensate just re-couples the ACK to transform cost (defeating the point). → **Rejected**
   — durability between stages is the whole point.

## Consequences

**Positive**
- True **per-stage isolation** — a wedged transformer can't block intake; each stage drains independently.
- **Uniform FIFO + failure policy + alerting** at every stage — the Phase-1 settings layer and failure
  semantics transfer unchanged; the per-stage worker is the Phase-1 worker parameterized by stage.
- **Durable backpressure / buffering**; ingress absorbs bursts.
- A **natural home for per-key lanes** (BACKLOG #3) — partitioning becomes a stage-queue property.

**Negative / risks**
- **Write amplification** (~3× durable writes/message) on single-writer SQLite — latency/contention under
  load; mitigated by minimizing stages (Q5) and must be **benchmarked** before the full split.
- **Partner-visible ACK change** — routing/transform failures no longer NAK; documented + the opt-in
  synchronous validation gate + `ack_after` setting preserve the escape hatch.
- **Count-and-log weakens** at the ACK boundary — disposition is no longer final at ACK; the invariant is
  re-specified as "received-and-persisted at ACK; disposition recorded as it flows," with rewritten tests.
- **Ordering now matters at every stage** — intertwines with per-key ordering (BACKLOG #3).
- **Config / API / console surface multiplies per stage** (per-stage depth, DLQ, replay, alerts).
- **SQL Server path is blocked on BACKLOG #1** (concurrency-safety fixes) before it can carry staging.

## Resolved on acceptance

The five sign-off questions were ratified to the recommended answers above:

1. **ACK-on-receipt is the default**, with the opt-in `ack_after = ingest | delivered` escape hatch.
2. **Step A starts with a combined `processing` stage** (ingress → processing → outbound); router and
   transformer are split into separate stages only in Step B, if a workload needs it.
3. **One generic staged-queue table** with a `stage` discriminator (not a table per stage).
4. **Replay re-enqueues at the failed stage** by default; replay-from-ingress is an explicit option.
5. **No fixed throughput number is set up front** — Step A is built first and its write amplification is
   **measured**, and that data (not a guess) decides whether the full 4-stage split is worth it and when
   to pursue the SQL Server scale path. This deferral-to-data is itself the decision.

---

*On acceptance: update CLAUDE.md §2 + `ARCHITECTURE.md` to the staged model and the revised invariants,
then build **Step A only**, with the invariant tests rewritten alongside it.*
