# ADR 0059 — seq-only per-lane FIFO ordering (drop the `_fifo_created_at` write-time clamp)

- Status: **Proposed**
- Date: 2026-06-30
- Relates to: ADR 0001 (staged pipeline), ADR 0055 (group-committer), ADR 0058 (batch claim); issue #285 (per-lane FIFO no-skip); throughput roadmap (docs/throughput-roadmap.md, "collapse-commit-depth"); supersedes the `_fifo_created_at` mechanism introduced for clock-regression resilience.

## Context

The staged pipeline (ADR 0001) drains each (stage, lane-key) FIFO queue with a single serial worker per lane: the listener for the **ingress** lane (keyed by `channel_id`), the per-inbound **router worker** for the **routed** lane (keyed by `channel_id`), and the per-inbound **transform worker** for the **outbound** lane (keyed by `destination_name`, a documented fan-in of every inbound that targets that destination). Strict per-lane FIFO is a HARD conformance gate (#285): the claim BLOCKS on a producer-locked head and never skips it (no `READPAST`, no `SKIP LOCKED` of the true head).

The FIFO claim today orders by `created_at, seq` (SQLite uses the implicit `rowid` as `seq`). Because `created_at = time.time()` is wall-clock-derived, a backward clock step (NTP step-back, VM snapshot revert, a skewed standby after failover) could give a later-arriving row a smaller `created_at` and let it sort ahead of an earlier one. To prevent that, every stage handoff calls `_fifo_created_at(stage, lane, now)` — a `SELECT MAX(created_at)` round-trip per insert that clamps the new row's ordering timestamp up to the lane's current max (`max(now, lane_max)`), making `created_at` non-decreasing per lane.

That clamp is a **per-insert round-trip** inside the per-lane serial commit chain — the chain the throughput diagnosis (memory: pipeline-commit-bottleneck) identified as the primary wall (a single lane runs ~7 round-trips × ~2.84ms ≈ 20ms/msg). Each received message pays this clamp on **every** stage handoff that produces a row: ingress (1) + one routed row per selected handler + one outbound row per delivery (+ any PT-child / re-ingress / response rows). For the common single-handler/single-destination message that is **3 clamp round-trips** (ingress, routed, outbound); fan-out multiplies it.

The bet: the clamp is unnecessary for ordering because `seq` is already a per-store monotonic counter assigned by the DB at INSERT time (SQLite `rowid`, SQL Server `BIGINT IDENTITY`, Postgres `BIGSERIAL`), and within a single lane there is exactly one serial writer, so **seq-order == insert-order == FIFO**, independent of any wall clock. The clamp only ever existed to paper over `created_at`'s clock-dependence — a defect `seq` does not have.

## Decision

Remove `_fifo_created_at` and all its callers on all three backends, and change every per-lane FIFO claim/batch-claim from `ORDER BY created_at, seq` (SQLite: `created_at, rowid`) to `ORDER BY seq` (SQLite: `ORDER BY rowid`). `created_at` remains a column, still stamped with the true `time.time()` at enqueue (it is consumed as the ADR 0009 ingest-time and for the delivery-latency / oldest-pending metrics) — it is simply no longer consulted for ordering and no longer clamped. Re-key the FIFO covering indexes to trail in `seq` so the claim stays an index-ordered scan. The #285 no-skip / head-of-line-blocking lock semantics are untouched.

## FIFO proof (why seq-only preserves strict per-lane FIFO)

1. **seq == insert-commit order per lane, unconditionally.** The DB assigns `seq` at INSERT, monotonically, never recycling a value held by a live row (IDENTITY/SERIAL never reuse; SQLite without AUTOINCREMENT allocates `rowid = max(live rowid)+1`, so reuse only recycles already-deleted, gone rows). Among a lane's live pending rows, `ORDER BY seq` is strict insert order, with zero wall-clock dependence.

2. **The clamp already made `created_at`-order == `seq`-order.** `_fifo_created_at` reads the committed lane max and clamps `created_at` non-decreasing *in the same transaction that assigns `seq`*. So for one lane, `(created_at, seq)` is order-isomorphic to `(seq)`. The SQL Server batch claim already re-sorts OUTPUT rows by `seq` alone on exactly this equivalence. Therefore switching the authoritative ORDER BY to `seq` selects the **identical head and identical contiguous-due prefix** as today — it reorders nothing.

3. **The outbound fan-in lane is safe.** Multiple transform workers can insert into one `destination_name` lane on the server backends. The FIFO guarantee for a fan-in lane is insert-execution order (there is no cross-inbound "receive order" to honor). `seq` and clamped-`created_at` are **both** assigned by the same INSERT, so whichever transaction inserts first gets both the lower `seq` and a `created_at` ≤ the later inserter's. The two keys cannot diverge; seq-only delivers the lane in exactly the order `(created_at, seq)` did. An uncommitted lower-seq insert is invisible/locked, so a higher-seq row is never claimed ahead of it (unchanged from today). On SQLite the process-wide `self._lock` (ADR 0055) serializes all writers a fortiori.

4. **Clock skew & failover are strictly safer.** `seq` is a shared DB-side counter, monotone across a leader change with a skewed standby clock by construction — the case the clamp could only best-effort-detect. Backward NTP steps that could reorder `created_at` cannot reorder `seq`.

5. **Retry/recovery/replay preserve position.** `mark_failed`, `replay`, `replay_dead`, `reset_stale_inflight`, lease reclaim, and on-promotion recovery are in-place UPDATEs that never re-stamp `seq` (or `created_at`), so a retried/recovered/replayed row keeps its original lane position. The contiguous-due cutoff keys on `next_attempt_at` and breaks at the first not-due row in `seq` order, so a not-due lower-`seq` head still BLOCKS the lane.

## Consequences

- **Throughput:** removes one `SELECT MAX` round-trip from every stage handoff that produces a row — ≥3 per typical single-handler/single-destination message, more under fan-out — directly shortening the per-lane serial commit chain that is the throughput wall.
- **Resilience:** FIFO becomes *more* robust to clock anomalies (no wall-clock dependence in ordering), especially across failover.
- **Behavioral change (soft):** `current_ingest_time()` (ADR 0009) is no longer guaranteed non-decreasing per lane across a backward clock step; re-run stability is unaffected (created_at is persisted-once/immutable per message).
- **Lost signal:** the per-lane "clock regression … clamping" WARNING disappears; consider a node-level clock-regression monitor if that signal is valued.
- **Index change:** FIFO covering indexes re-key to trail in `seq`.
- **cancel_pending(top_only=True):** re-keyed to `next_attempt_at, seq` so "cancel the head" stays the true FIFO head.

## Reliability-invariant checklist

- [x] **At-least-once / crash re-run idempotent:** handoffs remain single committed transactions; seq/created_at immutable across re-runs. Unchanged.
- [x] **Strict per-lane / order-group FIFO (#285, no READPAST / no SKIP LOCKED of the true head):** ordering KEY changes, lock hints and head-of-line blocking do NOT. Proven equivalent to the prior ordering.
- [x] **Poison-guard (ADR 0055):** attempts still incremented durably before work. Unchanged.
- [x] **Finalizer = sole disposition authority:** finalizer scans are GROUP BY with no ORDER BY; order-independent. Unchanged.
- [x] **Count-and-log / ACK-on-receipt:** ingress row still committed before ACK; `created_at` still a real timestamp for ingest-time/metrics. Unchanged.

## Residual risks

- The per-lane "clock regression" operator WARNING is removed (re-emit elsewhere if valued).
- `current_ingest_time()` loses its implied per-lane monotonicity across a backward clock step (docstring update + changelog note).
- `oldest_pending_age` metric can briefly mis-report during an NTP regression (transient, non-reliability).
- Correctness now rests, with no created_at backstop, on **one serial writer per (stage, lane-key)** and SQLite's `rowid = max(live)+1` allocation; both are pinned by an explicit code comment and a churn regression test so a future second-writer or delete+reinsert-on-retry change cannot silently break FIFO.
