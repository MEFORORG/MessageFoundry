# Proposed backlog items from Fable review packet 5 (store core, SQLite)

**These are proposals, not items.** No number is allocated and nothing here is written into
`docs/BACKLOG.md`. The Manager allocates serially after the packets land (owner instruction relayed
2026-09-12) and files from this list. Each proposal is in the house format minus the heading number,
with the duplicate search recorded. The byte-level reproductions are in the vaulted findings document
`docs/reviews/FABLE-PACKET-5-STORECORE-2026-09-11-FINDINGS.md` (vault branch
`vault/fable-packet5-storecore`); this file names the subject, the mechanism and the fix only.

Engine ref measured: `2ffcf3347`. Every impact claim is conditional: there are zero deployments
(`CLAUDE.md` section 0).

---

## Proposal 1. SQLite store: the inline transaction path is not cancel-safe, so a cancelled stage handoff leaves the writer connection mid-transaction and the next writer commits the half-body

> Filed 2026-09-12 - not started. Found by Fable review packet 5 (finding P5-01) answering packet 2's
> "is the ingress commit cancel-safe" question at the store. `store/store.py` `_run_grouped` (the
> inline path every grouped writer takes when group commit is off, the shipped default) and every
> explicit-`BEGIN` writer in the file roll back on `except Exception`. `asyncio.CancelledError` derives
> from `BaseException`, so a cancel delivered inside the body releases `self._lock` with the transaction
> open and every statement up to the cancel applied. Measured on `2ffcf3347`: a `route_handoff`
> cancelled after its guarded ingress-row `DELETE` was committed by the next writer, leaving a
> `received` message with no queue row that no worker would ever see and `reset_stale_inflight`
> recovered 0; a `transform_handoff` cancelled after one of two outbound rows was inserted delivered to
> one destination and finalized `PROCESSED`; an `enqueue_ingress` cancelled between its two inserts left
> a phantom `received` row. On a keyed (AES-GCM) store `close()` alone commits the half-body, because
> its first act is the GCM invocation settlement write. Under group commit the same cancel is safe (the
> committer owns the transaction); group commit is off by default.

**Cluster:** Store & Reliability. **Priority:** P1. **Verdict:** build.
**Severity:** high. A first deployment stopping the service while a backlog drains would lose messages
from the pipeline with the store reporting them `received` or `processed`, no `ERROR`, no dead letter,
no alert, no NAK. Reachable with no fault injection: `RegistryRunner._teardown_body` cancels every
worker and pooled serializer, then the connection-event drainer flush and `Engine.stop()`'s
`store.close()` each write on the same connection before it closes; the H-2 shutdown grace and a
reload's quiesce cancel an MLLP handler blocked in `enqueue_ingress` the same way.

**Mechanism.** Python's `sqlite3` in its default transaction mode lets the next statement without an
explicit `BEGIN` join the open transaction, and that writer's `commit()` commits both. A writer that
does start with `BEGIN` fails once instead (`cannot start a transaction within a transaction`), and its
own rollback then discards the half-body, which is packet 3's P3-03 strand for that writer's row.

**Fix.** In `_run_grouped`'s inline path and in every explicit-`BEGIN` writer: `except BaseException:
await self._db.rollback(); raise`, keeping the `_AbortMember` arm first. aiosqlite serializes the
rollback behind the in-flight statement on its worker thread, so the ordering is safe. Add store-level
tests that cancel a task inside `route_handoff`, `transform_handoff` and `enqueue_ingress` and assert,
from a second connection, that the pre-cancel rows are intact after one further write and after
`close()`, with the keyed-store `close()` case explicit. Consider a debug assertion at lock
acquisition that the writer is not already `in_transaction`. Update ADR 0159's scope statement and the
comment at `stage_dispatcher.py` `stop()` ("leaves its claimed rows INFLIGHT"), which hold on SQLite
only when nothing writes before the connection closes.

**Duplicate search.** No open item. BACKLOG #348 (closed, ADR 0159) is the SQL Server twin of this
defect and scoped SQLite out with "one writer connection under an `asyncio.Lock` and no pool, so there
is no next borrower"; the next borrower is the next writer, and the measurement above refutes the
scoping. BACKLOG #1494 (closed) fixed the same exception-class mistake in `_release_leadership`.
Searched both ledgers for `CancelledError`, `cancel-safe`, `open transaction`, `BaseException`,
`_run_grouped`, `rollback`.

---

## Proposal 2. SQLite store: seventeen implicit-transaction writers still lack rollback-on-error (June M-1), so a mid-body statement failure is committed by the next writer

> Filed 2026-09-12 - not started. Fable review packet 5 (finding P5-02) re-measured June's M-1. June's
> fix shape (an explicit `BEGIN` with except-rollback) reached the grouped writers via `_run_grouped`
> and six standalone writers, and never reached the rest. An AST census over every `MessageStore`
> method that commits found seventeen with two or more statements and no rollback path:
> `claim_ready`, `claim_next_fifo`, `claim_next_fifo_batch`, `dead_letter_missing_destinations`,
> `dead_letter_missing_handlers`, `replay`, `cancel_queued`, `record_audit`, `upsert_alert_instance`,
> `_add_cipher_invocations_locked`, `reserve_upload_quota`, `consume_recovery_code_hash`,
> `consume_totp_step`, `purge_reference_snapshots`, `purge_state`, `prune_processed_files`, and the
> on-open cipher migration loops. Measured: `cancel_queued` with its event insert failing after the
> `UPDATE` was committed by the next writer as one row `cancelled` with no `cancelled` event and no
> finalize; `replay` with the status flip failing re-pended the dead row while the message stayed
> `error`; `claim_next_fifo` with its post-flip `SELECT` failing left the row `inflight` with no owner
> until a restart; a real `NOT NULL` failure in `record_audit` made the next `route_handoff` raise
> `cannot start a transaction within a transaction`.

**Cluster:** Store & Reliability. **Priority:** P2. **Verdict:** build.
**Severity:** medium. The triggers are ordinary (`SQLITE_FULL`, a busy timeout past 5 s, a constraint
violation); each would become either a silent half-write or one spurious failure of the next handoff.

**Fix.** One `_txn()` async context manager (`BEGIN`, commit on success, rollback on `BaseException`)
applied to every writer above, matching the writers that already carry it; the claim paths keep their
standalone commit. One test per multi-statement writer that injects a failure after its first mutation
and asserts, from a second connection and after one further write, that nothing was committed.

**Duplicate search.** No item covers the set. BACKLOG #1111 (open, ASVS 2.3.3 research) notes in
passing that `cancel_queued` lacks the rollback guard `replay_dead` has; cross-link it. Searched both
ledgers for `rollback-on-error`, `open transaction`, `implicit transaction`, `M-1`, `cancel_queued`,
`claim_next_fifo`, `record_audit`, `_txn`.

---

## Proposal 3. SQLite group commit: a poisoned member rejects every co-batched sibling, stranding up to `group_commit_max_batch` lanes in flight until a restart

> Filed 2026-09-12 - not started. Fable review packet 5 (finding P5-03) measured packet 3's handed-over
> "group commit as a P3-03 amplifier". `_GroupCommitter._flush` rolls the whole batch back when any
> member raises and rejects every other member's future with `RuntimeError("group commit rolled back
> (sibling member failed)")`; its docstring says each caller re-runs. The per-lane router and transform
> workers catch that under `except Exception`, log and back off, and never re-pend the claimed head
> (P3-03), and nothing in `pipeline/` matches the error. Measured with `window_ms=50`: three concurrent
> `route_handoff`s with one poisoned member left all three ingress rows `inflight` from a fresh
> connection; a re-run of the two healthy members succeeded, so the store's guard is idempotent and the
> re-run would have worked had anyone issued it.

**Cluster:** Store & Reliability. **Priority:** P3. **Verdict:** build.
**Severity:** medium, bounded by reach: group commit is off by default. A site that turns it on would
convert every transient store fault into a multi-lane stall invisible to `pending_depth` and the stall
alert.

**Fix.** Store half: on a group rollback, re-run the healthy members inline under the lock, each in
its own transaction, before rejecting anything, so only the member whose body raised sees an
exception. Runner half is packet 3's P3-03 fix (re-pend the head on any handoff exception). Add a test
with two healthy members and one poisoned one asserting the healthy rows commit.

**Duplicate search.** No match. Searched both ledgers for `group commit`, `group-commit`, `sibling`,
`poison`, `rolled back`, `P3-03`, `reschedule_claimed`.

---

## Proposal 4. Store-level guarantees that are asserted only by reading: the inline ACK gate, every-stage recovery, the read pool snapshot, and the no-row replay guard at the store

> Filed 2026-09-12 - not started. Fable review packet 5 (finding P5-04), from nine negative controls
> over the 24 SQLite store suites (342 tests). Four deliberate breaks stayed green: (B) `enqueue_ingress`
> on the inline path made to swallow a body failure and return the id anyway, the store half of
> packet 3's P3-01 (the grouped path is pinned by `test_ack_gate_rejected_on_group_rollback`; the
> shipped default path is not); (C) `reset_stale_inflight` made to skip one stage, because
> `test_reset_stale_inflight_recovers_all_stages` seeds only ingress and outbound rows and so pins two of
> the four stages its name claims; (E) `replay`'s rowcount guard removed (the June M-2 regression), which
> no store suite catches and only the API route test `test_replay_no_deliveries_is_409_and_preserves_error`
> reaches; (I) the read pool's deferred read transaction removed, so a multi-statement read no longer sees
> one snapshot. Five other controls turned the right tests red (rollback in `_run_grouped`, FIFO order,
> the audit chain link, dead-row precedence in the finalizer, the H2 ledger write), so the suites are
> live where they cover.

**Cluster:** Tests / Store. **Priority:** P2. **Verdict:** build (tests only).
**Severity:** no deployment axis; a test gap on the engine's most load-bearing claim. Ships nothing.

**Fix.** Four tests: `enqueue_ingress` with a body failure on the inline path raises and leaves zero
rows (from a second connection); `reset_stale_inflight` seeds one in-flight row at each of the four
`Stage` values and asserts all four recover; `replay` on an `ERROR`, a `FILTERED`, an `UNROUTED` and a
Step-B `FILTERED` message returns 0 with status and error untouched, at the store; a pooled multi-
statement read observes one snapshot while the writer commits between its statements.

**Duplicate search.** No match at the store. Packet 3's P3-01 (runner-side ACK test) is the runner
half and, if filed, should cross-link; packet 1's #1594 (on PR 1066) carries a runner guard, not a
store test. Searched both ledgers for `P3-01`, `ACK-after-commit`, `recovers all stages`,
`negative control`, `enqueue_ingress`, `read pool`, `query_only`.

---

## Proposal 5. `_secure_file` runs `icacls` synchronously on the event loop (June low-3 store half): about 21 ms per call at `open()` and once per DR backup in `snapshot_to`, plus four other engine callers

> Filed 2026-09-12 - not started. Fable review packet 5 (finding P5-06) re-measured June's low-3.
> `_secure_file` is `subprocess.run(["icacls", ...])` with no `to_thread`. `open()` calls it for the DB,
> WAL and SHM files (before the API serves and before any listener binds, so unobservable);
> `snapshot_to` calls it once per DR backup on the loop; `api/app.py` calls it in a request handler and
> the three `config/*_edit.py` writers call it on their write path. Measured at 21 to 28 ms per call.
> The closed BACKLOG #1 names "low-3 store half" in its title; the shipped call is still synchronous.

**Cluster:** Store / ops. **Priority:** P4. **Verdict:** build.
**Severity:** low. One 21 ms stall of every in-flight ACK and claim per backup, per config write and
per key-protect request.

**Fix.** `await asyncio.to_thread(_secure_file, path)` at every async call site, or an async wrapper
in `store.py` the callers share.

**Duplicate search.** BACKLOG #1 (closed) titles the store half but did not move the call; #1142 and
#1183 (open, ASVS research) mention `icacls` only as a trust-anchor mechanism. Searched both ledgers
for `icacls`, `_secure_file`, `to_thread`, `low-3`, `event loop`.

---

## Proposal 6. SQLite read pool: the deferred-read `BEGIN` sits outside its `try`, so one cancellation landing on it poisons a pooled read connection for the life of the process

> Filed 2026-09-12 - not started. Fable review packet 5 (finding P5-05). `store/store.py` `_read`
> issues `BEGIN` on a borrowed read connection before the `try` whose `except BaseException` issues
> `ROLLBACK`. aiosqlite completes the `BEGIN` on its worker thread whether or not the awaiting task
> survives, so a cancel on that await returns the connection to the pool inside an open transaction.
> Measured: the next borrower's `BEGIN` raised `cannot start a transaction within a transaction`, and
> so did every later one, because that failing `BEGIN` is also outside the `try` and the rollback never
> runs. With the shipped pool of four, one such cancel fails one read in four until restart, with an
> error text that names no cause.

**Cluster:** Store & Reliability. **Priority:** P3. **Verdict:** build.
**Severity:** medium, rare per event and permanent per process. Reachable from any cancel that lands
on a pooled read's `BEGIN`: the pooled dispatcher's `stop()` cancelling the sweep loop mid
`list_fifo_lanes`, a worker cancel while it sits in `pending_depth`, or a `wait_for` around a store
read; the exposure is the demote and reload paths, where the store keeps serving.

**Fix.** Move the `BEGIN` inside the `try`, or on any `BaseException` after `pool.get()` issue a
best-effort `ROLLBACK` before `put_nowait`. Add a test that cancels a read mid-`BEGIN` and asserts
the next borrower succeeds.

**Duplicate search.** No match. Searched both ledgers for `read pool`, `query_only`,
`lockfree-reads`, `_read()`, `cannot start a transaction`, `CancelledError`.

---

## Findings deliberately not proposed

- **The two-process-over-one-SQLite-file gap** (every lock-protected guarantee is process-local).
  Already carried by BACKLOG #1112 (open) as unallocated proposed work; not re-filed.
- **The false SQLite scoping in ADR 0159 / #348 and the `stage_dispatcher.py` `stop()` comment.**
  Documentation accuracy, handed to packet 18 by name; the correction is also part of Proposal 1's
  fix.
- **June M-3 (raw-body views never reach the hash-chained `audit_log`).** The store half is
  unchanged; the fix June named is in the API route. Packet 7's row.
- **Everything refuted** in part 7 of the findings document.
