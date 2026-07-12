# ADR 0082 — Outbound batch aggregation (N messages into one BHS/BTS envelope)

*(final ADR number assigned at merge — placeholder to avoid multisession churn)*

**Status:** Accepted (2026-07-10) — owner ratified; **Built (2026-07-10)**, BACKLOG #134.

## Build notes (2026-07-10)

Implemented as a **shared delivery body** (`_process_delivery_batch`) reused by both the per_lane worker
and the pooled dispatcher (via the injected `_dispatch_delivery`) — so pooled-mode batching (the default
`claim_mode`) needed **zero changes to the `StageDispatcher` FIFO state machine**. The dispatcher claims
one head per lane as always; the delivery body coalesces its own tail by looping `claim_next_fifo` (the
existing H2 skip-and-complete single claim) up to `max_count` **or** `max_wait_ms` from the head's ingest
time **or** a graceful stop, then frames + sends once + completes all N in one transaction
(`mark_batch_done` / `mark_batch_failed` / `dead_letter_batch`). The lane's processing slot is held for
the bounded coalescing window (an opt-in trade; `max_count` is capped at 1000 so the slot-hold is
bounded). `BHS-11` is the **head member's control id** (MSH-10) rather than the raw DB seq: seq is not
projected onto `OutboxItem`, and the control id is equally FIFO-aligned (head = min seq), re-run-stable,
and more debuggable. `created_at` is now projected by **both** the single and the multi-lane
(`claim_fifo_heads`) SQL Server claims (it was previously omitted), so BHS-7 is populated and the window
is ingest-time-anchored in every mode/backend.

**Adversarial hardening (verified).** A 6-lens skeptic pass surfaced and drove fixes for: framing now runs
**inside** the send `try` (an unparseable/non-HL7 head dead-letters instead of stranding the batch
INFLIGHT forever); the head is carried **byte-verbatim** (parsed only for separators/control-id); the
coalescing loop is bounded (`max_count` cap) and stop-interruptible. **Crash-after-send scoping:** because
coalescing spans multiple commits, a crash *after* `send` but before completion re-sends the batch and may
absorb newly-arrived contiguous rows into a **larger** envelope — this is exactly the "whole batch re-sent
on crash-after-send, partner idempotent" consequence below; at-least-once holds under **per-message**
(MSH-10) idempotency (the standard HL7-batch partner), and framing is deterministic **given a member set**.
A future increment could pin membership durably (a batch-id stamp) for byte-identical membership across
such a crash — not required by the ratified contract.

## Context

The outbound stage delivers **one store row → one `connector.send(payload)` → one `mark_done`**: `_process_delivery_item` sends a single row's `item.payload` (`pipeline/wiring_runner.py:2822`) and completes that one row (`pipeline/wiring_runner.py:2913`), one delivery worker per outbound (`pipeline/wiring_runner.py:2685`). An `OutboxItem` carries a single message body (`store/store.py:356-368`).

Partners that ingest by **HL7 batch file** (BHS…BTS wrapping many MSH messages) need N messages framed into one envelope on send. Handlers cannot do this: they are **pure and per-message** — cross-message accumulation in a Handler would be non-idempotent state that a re-run cannot re-derive. `git grep BHS` finds only the **inverse** (`parsing/split.py:8` `split_batch` decomposes an inbound BHS/BTS); there is **no aggregation** anywhere. So aggregation must be a new seam at the **outbound/delivery** stage, downstream of the pure per-message transform.

The lever already present: `claim_next_fifo_batch` (ADR 0058, `store/base.py:377`) claims the **contiguous due head-prefix of one lane in a single commit**, processed strictly in `seq` order; `reset_stale_inflight` recovers an interrupted claim in order (a pure re-run). Per-lane order is **seq-only** (ADR 0059) — receive order, no wall-clock dependence. The outbound lane is keyed by `destination_name`.

## Decision

Add an opt-in per-outbound **batch delivery mode** (`[delivery] batch = { max_count, max_wait_ms }`, HL7v2 outbounds only). The delivery worker, when batching is on:

1. **Window/claim:** claim the contiguous FIFO head-prefix of the lane via `claim_next_fifo_batch(name, stage=outbound, limit=max_count)` in one commit — all N rows go in-flight together. If fewer than `max_count` are due **and** the head row's `created_at` age < `max_wait_ms`, **park the lane** (arm a timer at the head's age-out) rather than claim a short batch — this keeps the trigger a count-**or**-timeout on the *head*, never skipping ahead.
2. **Frame:** build **one** BHS…BTS envelope wrapping the N `item.payload` MSH messages, in claimed `seq` order, via a new `parsing` batch encoder (the encode-side counterpart to `split_batch`). **BHS-7 (timestamp) and BHS-11 (batch control ID) are derived deterministically** from the batch contents — head row's `created_at` (ADR 0009 re-run-stable ingest time) and a hash of member message-control-ids/seqs — **never `time.time()`** — so a re-run re-derives a byte-identical envelope.
3. **Send once, complete N atomically:** one `connector.send(envelope)`; on success, `mark_done` **all N rows in one transaction** (new `mark_batch_done([ids])`). On failure, `mark_failed` **all N** together (seq preserved → re-claimed as the same prefix).

## Options considered

- **A — Delivery-stage window over the FIFO head-prefix claim (chosen).** Reuses the committed, order-preserving batch-claim primitive; no new stage; accumulation lives in durable store rows, not memory. Trade-off: needs an atomic multi-row completion and a deterministic envelope.
- **B — New "aggregator" stage between routed and outbound.** Rejected: the accumulator is itself mutable cross-message state; a re-run cannot re-derive a partially-filled buffer, breaking purity/idempotency, and it adds a stage + finalizer complexity.
- **C — In-connector in-memory buffer flushed on count/timer.** Rejected: rows marked done before the buffer flushes ⇒ a crash loses the buffered messages — **breaks at-least-once**. Not crash-safe by construction.

## Consequences

- New store primitive `mark_batch_done` (single txn over N ids) + a `parsing` BHS/BTS encoder; delivery worker gains a batch path alongside the per-row one.
- Latency/throughput trade: `max_wait_ms` trades tail latency for envelope size. Partner must accept a batch ACK; the batch is the retry/dead-letter unit (see open questions).
- Duplicates on crash-after-send are the **whole batch** re-sent — the existing at-least-once contract (partner idempotent) already permits this.
- Non-HL7 content types are excluded initially (no BHS/BTS analogue).

## Invariant preservation

- **FIFO:** the batch is exactly the **contiguous seq-ordered head-prefix** of one lane, claimed in one commit and framed in that order; parking on the head's age never lets a later row jump ahead. Order within and across batches is unchanged.
- **At-least-once:** claim, send, and completion are the existing claim→produce→complete discipline widened from 1 to N rows in **single transactions**. A crash before `mark_batch_done` rolls all N back to PENDING (seq intact); `reset_stale_inflight` recovers them; the re-run re-claims the same prefix and re-sends. Nothing is lost or partially completed.
- **Purity / identical re-run:** routers/transforms are untouched and still pure per-message. The only new derivation is the envelope, made deterministic by sourcing BHS-7/BHS-11 from re-run-stable row data (ingest time + member ids), so a re-run yields the **byte-identical** envelope.
- **ACK:** unchanged — the sender ACK is still on ingress commit, entirely upstream of this outbound-only seam.

## Ratified decisions (2026-07-10)

The Proposed open questions are resolved as follows (owner-ratified), favouring the atomic-batch guarantee
and the sacred at-least-once / strict-FIFO invariants:

1. **Batch NAK → dead-letter all N (atomic).** A permanent partner rejection of the envelope dead-letters
   all N members together, preserving the atomic-batch guarantee; the operator replays the dead-lettered
   batch. Split-and-retry-per-message is rejected (it loses atomicity and complicates FIFO on retry).
2. **One BTS-level ACK.** Expect a single batch-level ACK for the envelope (standard HL7 batch semantics).
   Per-message ACKs inside the reply are out of scope; a partner requiring them is a future extension.
3. **BHS-11 from the head `seq`.** The batch control id is derived from the first member's sequence
   (monotonic, FIFO-aligned, debuggable) — not a member hash — unless a partner requires an opaque id.
4. **Graceful stop flushes a partial batch.** On a clean shutdown the current partial batch is delivered
   rather than parked (lower latency; FIFO-safe either way). A crash still recovers the un-flushed rows
   from the outbound stage on restart.
5. **Batch within the pooled claim.** The batch window operates inside the pooled dispatcher's per-lane
   claim (ADR 0066); it does **not** force `per_lane` mode. Pooled stays the default committed path — no
   regression of the claim-wall work.

## Acceptance Criteria

- With a batch window configured, N outbound rows to one connection are framed into one `BHS`…`BTS`
  envelope on a single `send`.
  → `tests/test_outbound_batch.py::test_n_rows_one_envelope`
- A crash mid-batch loses no message and reorders none (at-least-once + strict FIFO hold).
  → `tests/test_outbound_batch.py::test_crash_midbatch_no_loss_no_reorder`
- A re-run produces the identical envelope (deterministic BHS-11 from the head seq).
  → `tests/test_outbound_batch.py::test_rerun_identical_envelope`
- A permanent envelope rejection dead-letters all N; a graceful stop flushes the partial batch.
  → `tests/test_outbound_batch.py::test_permanent_reject_deadletters_all`
  → `tests/test_outbound_batch.py::test_graceful_stop_flushes_partial`
- Batching runs within the pooled claim; the default `claim_mode` is unchanged (no forced `per_lane`).
  → `tests/test_outbound_batch.py::test_batch_within_pooled_claim`
