<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors -->

# ADR 0159 — Cancellation-safe pooled-connection release: quarantine at the `_acquire` chokepoint

- **Status:** Accepted (2026-08-02)
- **Date:** 2026-08-02
- **Related:** [BACKLOG #348](../BACKLOG.md) · [ADR 0066](0066-pooled-stage-claimers.md) §9 (the `SET LOCK_TIMEOUT 0` never-block claim, whose 1222→EMPTY translation is what made this silent) · [ADR 0114](0114-phase-4-claim-path-call-complexity-reduction-driver-interface-redesign-ingress-routed-reset-fold.md) §2 (the shielded finally-guard — **explicitly not** a rollback guard; see §3 below) · [ADR 0001](0001-staged-pipeline-architecture.md) (the staged queue whose at-least-once contract bounds the damage)

---

## Context

`SqlServerStore`'s house idiom for a write is:

```python
async with self._acquire() as conn, self._cursor(conn) as cur:
    try:
        await cur.execute(...)
        await self._commit(conn)
    except Exception:
        await conn.rollback()
        raise
```

An AST census over `messagefoundry/store/sqlserver.py` finds **91** `self._acquire()` call sites, and in
**90** of them the `async with` body is a single top-level `try` whose only handler is `Exception`. This is
the dominant idiom of the file, not a slip at one or two sites.

`asyncio.CancelledError` derives from `BaseException`, not `Exception` (Python 3.8+). So on a cancellation
**none of those rollbacks run**. The body unwinds with its transaction still open and its row locks still
held, and nothing downstream compensates:

- `_cursor` (`sqlserver.py:2957`) closes only the cursor. Its docstring records that it *deliberately*
  bypasses aioodbc's own cursor context manager **because** that manager would commit/rollback and would
  "override each caller's own explicit `commit`/`rollback`".
- `_acquire` (`sqlserver.py:2891`) had no `try` at all — it applied the STORE-3 statement timeout and
  yielded.
- aioodbc's pool does not reset. `Pool.release()` (0.5.0 `pool.py:196-205`) is `self._used.remove(conn)`
  then, `if not conn.closed`, `self._free.append(conn)` — no commit, no rollback, no transaction-status
  check. `_ContextManager.__aexit__` (`utils.py:90-103`) calls `_release_on_exception`, which
  `Pool.acquire()` never supplies, so it defaults to the same `release` (`utils.py:60-62`): **the
  cancellation path and the success path release identically.** `create_pool` is called with no
  `pool_recycle` and no `after_created`, so the recycle branch is dead.

The pool is `autocommit=False` (`sqlserver.py:2244-2249`), so the transaction is real. The next borrower
inherits it: its own commit durably commits the stranger's statements, its rollback discards them.

### What was measured

Against a live SQL Server 2022 container, cancelling a call mid-body and then inspecting the server:

| Method | X/U row locks left on `queue` |
| --- | --- |
| `release_claimed` | **7** |
| `reschedule_claimed` | **7** |
| `mark_done` | **9** |
| `enqueue_ingress` | **11** |
| `claim_fifo_heads` (control) | **0** |

The connection was back on the pool's free list (`size=1 freesize=1`), a raw writer against the locked row
got **error 1222**, and a real second `claim_fifo_heads` returned **EMPTY-all**. Under ADR 0066 §9 that 1222
is translated to EMPTY-all by design — a *sanctioned* outcome — which is exactly why this never surfaced as
an error: **the failure mode is silence, not a stack trace.**

**`@@TRANCOUNT` is not a usable discriminator here** and was nearly mistaken for one. Under ODBC
manual-commit a connection sits at `@@TRANCOUNT=1` with **zero** locks as its normal resting state (a fresh
empty transaction opens after each commit). The clean control reports `@@TRANCOUNT=1` too. Only **held X/U
row locks** distinguish poisoned from clean; a guard keyed on `@@TRANCOUNT` would report a leak on every
healthy connection and prove nothing.

### Reachability

`StageDispatcher.stop()` cancels the lane tasks (`stage_dispatcher.py:509-511`); `_run_lane` is the body
that awaits `reschedule_claimed` (:739) and `release_claimed` (:751), and both call sites are themselves
guarded `except Exception`, so the `CancelledError` propagates. A third site is
`wiring_runner.py:4266`.

Two driving paths, and they differ in consequence:

- **Full shutdown** — `engine.stop()` closes the store shortly after, so the poisoned connection is closed
  at teardown. Bounded.
- **Loss of leadership** (`engine.py:1242-1252`, `_stop_graph`) — runs the identical cancel chain but
  **does not close the store**. The pool stays live and shared with the coordinator and convergence loops,
  so the poisoned connection sits in `_free` and is re-borrowed by unrelated callers. **This is the path
  that bites.**

## Decision

Contain the poison at the **`_acquire` chokepoint**, where all 91 sites funnel, rather than at individual
methods.

```python
try:
    yield conn
except BaseException as exc:
    if not isinstance(exc, Exception):
        await self._release_dirty(conn)
    raise
```

`_release_dirty` does two things, **in an order that is itself the guarantee**:

1. **Synchronously** drop the driver handle — `conn._conn = None` — with **no await in front of it**.
   aioodbc derives `Connection.closed` from `_conn` (`connection.py:89-93`) and `Pool.release()` re-adds a
   connection only `if not conn.closed`, so this one attribute write makes it unlendable. Because it cannot
   suspend, no cancellation can skip it.
2. **Then**, best-effort and time-boxed, close the raw handle off the event loop
   (`asyncio.to_thread(raw.close)` under `wait_for(shield(...), _DIRTY_CLOSE_TIMEOUT)`). pyodbc's `close()`
   rolls back uncommitted work per DBAPI, which is what actually frees the locks.

`isinstance(exc, Exception)` is the discriminator: an ordinary error has **already** been rolled back by the
caller's own handler, so that path is left byte-identical and the connection is recycled as before. Only the
cancellation path — the one no handler saw — quarantines.

### Why not a rollback in the same place

The obvious fix, `await conn.rollback()` on the cancellation path, was **built and rejected on measurement**.
`Connection.rollback()` is `run_in_executor(self._executor, ...)` with `_executor is None`, i.e. the loop's
default thread pool, whose threads may still be occupied by the abandoned statement — bounded only by
`command_timeout` (default 30s). Nothing upstream bounds the wait: `stage_dispatcher.py:514` gathers with no
timeout and `_stop_graph` awaits `runner.stop()` with no timeout. Measured: a cancel returned in **1.005s**
against a 1.0s rollback, serialized across lanes. That trades a bounded, contract-legal row-level bleed for a
multi-second-to-minutes stall **on the demotion path**, which is the one case that matters most.

A second defect killed the rollback draft outright: writing `await rb` on the `except CancelledError` arm
installs the rollback task as the outer task's `_fut_waiter`, so a **further** cancel cancels the rollback
itself — releasing the connection mid-transaction *and* with a rollback abandoned mid-flight, strictly worse
than today, while a single-cancel regression test stays green. The ordering rule in step 1 above exists
precisely to make that class of mistake unrepresentable, and the test suite pins it with an explicit
re-cancel arm.

### 3. `claim_fifo_heads` is not the precedent it appears to be

The lead that opened this investigation reasoned that `claim_fifo_heads` "already shields against precisely
this hazard". **It does not, and the record says so.** Its shielded finally is a `SET LOCK_TIMEOUT` *reset*
guard (the setting is session-scoped and would otherwise leak onto the next borrower). ADR 0114 §2 states
that on a cancellation at a body await "there is **no rollback**… This is **shipped** behavior", its
exit-path table row reads "**no rollback ran** on this path", and
`test_adr0114_claim_fold.py::test_ac3_cancellation_at_body_await_no_rollback_guard_runs` **freezes** it with
`assert "rollback" not in kinds`.

`claim_fifo_heads` ends on a clean boundary because the guard **commits**, not because it rolls back — which
is why it measures 0 locks in the table above while its siblings measure 7-11. Copying "what
`claim_fifo_heads` does" would therefore have copied a guard that does not roll back. This section exists so
the next reader does not re-derive the wrong precedent from the same comment.

## Consequences

- **All 91 `_acquire` sites** are covered, including `enqueue_ingress` — the pre-ACK ingress commit, the
  engine's hottest path — which the original two-method framing would have left leaking.
- **One reconnect per cancelled call.** The pool's `size` is derived (`freesize + len(_used) + _acquiring`),
  so a dropped connection simply shrinks it and `_fill_free_pool` reopens on demand. Paid only on a path
  that was previously corrupting the pool.
- **Shutdown/demotion stays bounded** by `_DIRTY_CLOSE_TIMEOUT` (5s), and on expiry the close completes
  detached — the connection is already out of the pool, so expiry costs a slower reclaim and nothing else.
- **No behaviour change on the success or ordinary-error paths**, pinned by two control tests that pass
  both before and after the change.
- **Not a data-integrity fix.** At-least-once was never at risk: a cancelled `release_claimed` leaves rows
  `INFLIGHT` and `reset_stale_inflight` re-pends them, which `stage_dispatcher.py:491-492` already declares
  the intended outcome. What is fixed is pool integrity and the silent EMPTY-all yield.
- **Backend scope: SQL Server only.** Postgres is structurally safe twice over — `async with
  conn.transaction()` rolls back on any `BaseException` (asyncpg's `__aexit__` tests `extype is not None`,
  with no `Exception` filter), and asyncpg's pool additionally resets under `asyncio.shield`.

  **CORRECTED 2026-09-14 (BACKLOG #1548).** This bullet used to end: *"SQLite shares the `except
  Exception` shape but has a single writer connection under an `asyncio.Lock` and no pool, so there is
  no next-borrower to inherit anything."* The first clause was right and the conclusion was wrong.
  **One connection does not remove the next borrower — it makes every later writer the next
  borrower**, because they all inherit that one connection as soon as the lock is released. A SQLite
  writer cancelled mid-transaction left it open; the next writer took the lock and its statements
  joined it. Most of the store's short writers issue no `BEGIN` of their own, so their `COMMIT` would
  make the abandoned statements durable too. On a stage handoff that is **work loss**, not pool
  damage: the ingress row's guarded `DELETE` would commit while the routed rows it should have
  produced never existed. What is genuinely SQL-Server-only is this ADR's **remedy** — quarantine-and-
  reopen presupposes a pool with spare connections, and SQLite has one writer it cannot throw away.
  It unwinds in place instead, through the single `_writer_txn` context manager in
  `messagefoundry/store/store.py`, which carries the mechanism and the reasoning.

  One difference there is worth naming here, because it looks like a copy of `_release_dirty` and is
  not: both shield the cleanup, but `_release_dirty` swallows a SECOND cancellation and returns at
  once, which is safe only because the connection is already out of the pool. SQLite's unwind keeps
  waiting out its bound instead — returning early would release the lock over a half-open
  transaction, which is the whole hazard.

  **That remedy was PARTIAL, recorded here because the paragraphs above read as though it were
  total.** `_writer_txn` first reached only the writers carrying a **stage handoff**: `_run_grouped`'s
  inline arm, the group committer's shared batch transaction, the fused `route_handoff`, and
  `dead_letter_now`'s standalone arm. The property it named for what was left is a writer that opens
  its own `BEGIN` directly under `self._lock` and unwinds on `except Exception`.

  **AMENDED 2026-09-15. Every writer matching that property is now converted, and a DIFFERENT residual
  remains, so the caveat below stays.** The population was re-derived from the property rather than
  carried from the count, and seventeen matched, which is the figure this paragraph already held:
  `enqueue_message`, `release_message_attachments`, `write_reference_snapshot`, `record_received`,
  `ingress_handoff`, `record_ack_sent`, `resend_to`, `reingress`, `delete_user`, `delete_custom_role`,
  `upsert_search_preset`, `set_user_roles`, `set_ad_group_role_map`, `set_ad_group_scope_map`,
  `purge_message_bodies`, `_apply_document_strips` and `purge_dead_letters`. All seventeen shared one
  shape exactly — a single `except Exception:` doing `rollback(); raise`, no `else`, no `finally` — so
  all seventeen took the existing helper and none needed a variant. Take that roster as the state at
  this commit rather than as a live index; what is kept live instead is the invariant, and it is now
  enforced rather than asserted. `tests/test_writer_txn_is_the_only_begin.py` AST-scans `store.py`
  and reds on any `execute("BEGIN")` outside two pinned carve-outs: `_writer_txn` itself, and
  `_read`'s pooled read snapshot, which runs on a borrowed connection and already unwinds in its own
  `except BaseException: ROLLBACK`. So **no writer opens a transaction on `self._db` outside
  `_writer_txn`**, and an eighteenth that tried would fail the build rather than quietly reopen the
  hole. The same scan covers the nested-transaction verbs. `SAVEPOINT` and `ROLLBACK TO` open and
  unwind a nested transaction, so they carry this ADR's shape exactly. `RELEASE` is scanned for the
  mirror-image hazard rather than the same one: it commits a savepoint and every savepoint opened
  after it, so a stray or mispaired one does not leak an open transaction, it makes durable what the
  caller still expected to be able to roll back. `store.py` holds none of the three today, so their
  carve-out table is empty and the first one added has to register itself with a count and a reason
  rather than arrive as grounds for deleting the check.

  **What remains is the SHORT writers: a different property, the same mechanism.** A short writer
  takes `self._lock`, issues its DML with no `BEGIN` of its own, and calls `_commit()`. The paragraph
  above casts those as the victims — the next borrower whose `COMMIT` would make an abandoned
  statement durable — and they are, but they are also exposed in their own right. sqlite3 auto-begins
  before DML, so a cancellation between the first DML and the `_commit()` would leave an implicit
  transaction open exactly as an abandoned explicit one would.

  **The population is SEVENTY-FOUR, not the seventy this paragraph first recorded (re-measured
  2026-09-15).** The original scan looked for DML issued *directly* inside the `self._lock` block, and
  that shape returns exactly 70 — which is why the wrong number looked right. Four further blocks
  reach their DML through a helper that takes no lock of its own, so a direct scan cannot see them:
  `attachment_decref` (via `_decref_attachment`, three statements), `record_view` and
  `record_message_event` (both via `_event`), and `add_cipher_invocations` (via
  `_add_cipher_invocations_locked`). Following one level of `self.`-helper call returns 74, and the
  set difference against the direct scan is exactly those four. The 74 include `claim_ready` and
  `claim_next_fifo`, so this residual is not confined to auxiliary writers.

  **The split that should drive priority is by BLAST RADIUS, not by which blocks already carry a
  handler.** Of the 74, **55** issue exactly one DML statement outside any loop: a cancellation there
  would risk one phantom write, committed by whichever writer next took the lock. The other **19** are
  multi-statement or loop-driven — among them `claim_next_fifo`, `claim_fifo_heads`, `release_claimed`,
  `reschedule_claimed`, `reset_stale_inflight`, `replay` and `cancel_queued` — where the same
  cancellation would risk a **torn multi-row write** finished and committed by a stranger. That is
  broken atomicity rather than broken isolation, and it is the harder failure to reason about after
  the fact. (Criterion for the split: more than one DML statement in the block, or any DML reachable
  from a loop, counting helper-mediated statements. State the criterion when re-running it — the
  count moves with it.)

  The handler tier is **nine**, not the eight first recorded, and the ninth is one of the four the
  direct scan missed. `put_attachment`, `attachment_incref`, `attachment_decref`,
  `sweep_orphan_attachments`, `claim_fifo_heads`, `release_claimed`, `reschedule_claimed`,
  `reset_stale_inflight` and `replay_dead` already carry the same `except Exception: rollback(); raise`
  handler the seventeen had. Those are not merely inheriting victims: they are the same
  cancellation-blind handler this work exists to delete, reached through the implicit begin instead of
  an explicit one. The remaining sixty-five have no handler at all.

  **The early exits are NOT an exposure today, and an earlier draft of this paragraph implied they
  were.** They are a blocker for one particular remedy, which is a different claim. All 52 `return`
  and `raise` sites inside the 74 blocks were classified (2026-09-15): every one either fires before
  the block's first DML — so nothing has auto-begun and there is no transaction to strand — or sits
  after a `_commit()`, or already rolls back itself, as `attachment_incref` does before its
  `raise KeyError`. Thirteen blocks hold an exit that falls before the block's last `_commit()`, by
  that criterion; a previous figure of fifteen was recorded without one and is not reproducible.
  What makes them matter is that `_writer_txn` opens its `BEGIN` **unconditionally**, so wrapping a
  read-only guard in it would convert a harmless exit into an open, empty transaction. That cost is
  created by the remedy; it is not a defect being carried.

  **The recommended remedy for this residual is NOT to give `_writer_txn` the `COMMIT`.** Doing that
  forces an abort sentinel for every no-op exit and drags in `_note_commit` accounting and the
  `_GroupCommitter` path. A second helper is the smaller change: a writer *guard* that takes the lock,
  issues **no** `BEGIN` and **no** `COMMIT`, unwinds on `BaseException` exactly as `_writer_txn` does,
  and on a clean exit checks `db.in_transaction` — rolling back and raising if the block wrote without
  committing. It leaves the auto-begin semantics alone, so a read-only early exit stays free, and it
  needs no sentinel: `in_transaction` already reports precisely what a sentinel would have to encode.
  It is filed as BACKLOG #1803. The 2026-09-18 amendment below records what this sentence said
  before that number existed. **So do not cite this ADR as evidence that a given SQLite writer
  unwinds on cancellation; check whether that writer goes through `_writer_txn`.**

  One property the whole residual rests on is worth stating once: **`isolation_level` is never set
  anywhere in the package.** `MessageStore.open` calls `aiosqlite.connect(str(path))` with no such
  argument, so all 74 sites inherit sqlite3's stock `''` — a future move to `autocommit=` would change
  every one of them at once. Measured 2026-09-15: auto-begin fires for DML only. `INSERT` and `UPDATE`
  leave `in_transaction` `True`; a bare `SELECT`, `CREATE TABLE`, `CREATE INDEX`, `ALTER TABLE` and
  `PRAGMA` all leave it `False`. That asymmetry is what makes the early exits safe today and what
  makes `in_transaction` a sound completion check for the guard above.

  **AMENDED 2026-09-18. The remedy above now has a number, and its hazard reaches further than this
  ADR framed it.** The decision stands. This amendment changes the pointer and records the reach.

  **The remedy is BACKLOG #1803, priority P1.** The remedy paragraph above first said: *"This is
  unfiled work, named by subject here rather than by a number, because none is allocated for it."*
  The number was issued on 2026-09-18. On that date a store manager session was building the guard
  on branch `b1803-writer-guard`. Read that as the state when this was written, not as a live index.

  **The trigger is any exception, not only a cancellation.** This ADR frames the short-writer hazard
  as cancellation. But a short writer without the rollback handler has nothing that unwinds on an
  ordinary `Exception` either, so that error leaves its implicit transaction open exactly as a
  cancellation would. Two instances were measured on 2026-09-18. In both, the error is the outcome
  the caller expects and catches:

  - `set_user_federated_subject` (BACKLOG #1801). The loser of the #1256 race hits the UNIQUE index
    on the federated subject.
  - `add_webauthn_credential` (BACKLOG #1804). Two concurrent enrolments of one label under ADR 0068,
    or a double submit, hit the UNIQUE index on `(user_id, label)`.

  An expected error is strictly more reachable than a cancellation. In both, the next `_writer_txn`
  writer then failed once with `cannot start a transaction within a transaction`. On first
  deployment that writer could be a stage handoff. The census behind #1803 found two more writers an
  ordinary path reaches, `create_user` and `create_session`, where no caller catches the error.

  **A third class needs no caller error at all.** Two faults in the environment reach the same
  mechanism:

  - A Vault outage. `TransitCipher` raises `CipherError` on any transport failure, and six writers
    encrypt after their first DML: `claim_next_fifo`, `replay`, `cancel_queued` and the three
    `dead_letter_missing_*` writers.
  - `SQLITE_BUSY`. The writer's `busy_timeout` is 5 s. With several engine-shard processes on one
    SQLite file, a first DML that waits past it raises `database is locked` and leaves an empty
    implicit transaction. That applies to every short writer. Whether it counts as an ordinary
    error is still open.

  **The measured consequence is a torn write against ADR 0001's reliability invariant.** The census
  drove `claim_next_fifo`'s skip-and-complete path with a cipher that raises `CipherError` after two
  UPDATEs. The next unrelated short writer then committed the half that had run: the queue row DONE,
  no `message_events` row, and the message stuck `ROUTED`. That is one writer, with the fault
  simulated. The census recorded the `SQLITE_BUSY` case as an empty transaction and did not drive it
  to a torn write. On first deployment a Vault outage would break the rule that a stage handoff
  commits whole or not at all.

  None of this reaches the SQL Server decision. Its discriminator rests on the pooled idiom's own
  `except Exception` rollback, which is exactly what these SQLite writers lack. The guard designed
  above unwinds on `BaseException`, so it covers the cancellation this ADR was written for and the
  wider triggers alike.

  **The census counts differ from this ADR's, and the difference is NOT reconciled.** The census ran
  at engine `origin/main` `909a38549`, where `store.py` is byte-identical to `363d79f49`, the commit
  that wrote this ADR's figures. The scanner behind this ADR's figures was never recorded, so nobody
  can re-run it.

  | Figure | This ADR | Census |
  | --- | --- | --- |
  | Lock blocks that write | 74 | 76, in 75 methods |
  | `return` and `raise` sites inside them | 52 | 55 |
  | Blocks with an exit before the last commit | 13 | 15 blocks, 18 exits |

  The census states its criterion for the last row. An exit is a `return` or `raise` inside a
  writing block, placed before the block's last direct `self._commit()`; a block with no direct
  commit counts every exit. That returns fifteen, the figure the early-exit paragraph above calls
  not reproducible. Whether it is the same fifteen is unknown, since that figure had no recorded
  criterion either.

  The census session offered two explanations. **They are its RECONSTRUCTIONS, not what this ADR
  says, and neither has been checked against this ADR's scan.**

  - For 74 against 76: `reserve_upload_quota` holds two lock blocks, which a scan keyed by method
    counts once. `revoke_user_sessions` passes its SQL through a variable, which a scan of literal
    arguments cannot see. Under that reading the blast-radius split reproduces: the same 19
    multi-statement blocks, and 57 single-statement blocks, which is this ADR's 55 plus those two.
  - For 13 against 15, starting from the census's 15: counting only `return` exits drops
    `attachment_incref` and gives 14. Also requiring a direct `_commit()` drops
    `add_cipher_invocations`, which commits inside its helper, and gives 13.

  Nobody has proposed an explanation for 52 against 55.

  **The early-exit safety claim above REPRODUCES.** The census drove all 18 exits on `origin/main`
  code and read `in_transaction` after each one. Seventeen pass silently, `attachment_incref`
  already rolls back, and none would raise where it used to return. So the guard changes nothing on
  any measured exit. That confirms this ADR rather than correcting it.

  One path outside that criterion is named so nobody reads it as a regression.
  `gcm_bound.checkpoint_invocations` swallows a failed upsert, and it runs inside
  `_encrypt_existing_rows` and `reencrypt_to_active`. A failure after the last batch commits would
  end the block cleanly with a transaction open. The guard would raise there. That is the guard
  doing its job, and only a failure outside the ordinary path reaches it.

  The census and its probes are recorded with BACKLOG #1803.
- **A new *source* for a 1222 that was assumed to come only from producer contention** (BACKLOG #344
  instance 2, found independently and concurrently). That work traced the other end of this same chain:
  a contended head raises 1222, the store swallows it as a normal EMPTY (the `_is_lock_timeout` branch),
  and the dispatcher's EMPTY branch goes to phase IDLE with **no timer armed**. It correctly concludes
  that this is a **test-rig gap, not an engine defect**, because production's periodic sweep re-readies
  exactly such a lane — the ADR 0070 tests disable that sweep on purpose, which is what makes IDLE
  terminal *there*. **Nothing in this ADR contradicts that**, and the severity above is deliberately not
  escalated on the strength of it.

  The connection worth recording is the **duration profile**. That analysis assumes the contention is
  momentary — a producer holding a head lock in flight. A connection poisoned by this defect holds its
  `queue` X locks for as long as it sits unclaimed in the pool's free deque, so the 1222 it manufactures
  can repeat across successive sweep ticks rather than clearing on the next one. Production still
  recovers, but the mechanism supplies a *persistent* contention source where a momentary one was
  assumed. Referenced by ledger number, not by SHA — that branch is unpushed and may be rebased.
- **Private-attribute coupling.** `conn._conn` is aioodbc-internal. This is pre-existing — `_acquire`
  already reaches through it to apply the STORE-3 timeout — and aioodbc is hash-locked at 0.5.0, but a
  version bump must re-check `Pool.release`'s `if not conn.closed` rule.

## Acceptance Criteria

- **AC-1** A cancellation delivered at any body await inside a pooled write leaves the connection
  **unlendable** — verified as "not on the pool's free list", against a fake pool that mirrors aioodbc's
  real `if not conn.closed` rule rather than an implementation detail.
- **AC-2** AC-1 holds under a **second** cancellation delivered during cleanup.
- **AC-3** An ordinary `Exception` still rolls back and **recycles** the connection (control: must pass
  before and after, so AC-1 cannot be satisfied by blanket-discarding).
- **AC-4** The success path still commits and recycles, untouched.
- **AC-5** AC-1..AC-4 hold for `release_claimed`, `reschedule_claimed` **and** `mark_done` — a method the
  original lead did not name — so the gate measures the chokepoint, not two patched call sites.
- **AC-6** ADR 0114's frozen no-rollback-on-cancellation test still passes unchanged.

Verified: the gate failed 6/12 against unpatched code (both cancellation properties × all three methods)
with the four controls already green, and passes 12/12 after. On the live server the same cancellation now
leaves **0** locks, no open-transaction session, an unblocked independent writer, and a pool that dropped
the connection rather than re-lending it.

## Options considered

| Option | Verdict |
| --- | --- |
| **Quarantine at `_acquire` (chosen)** | Covers all 91 sites; sync containment is cancellation-proof; bounded cleanup |
| Patch `release_claimed` + `reschedule_claimed` only | **Rejected** — arbitrary slice; `mark_done` and `enqueue_ingress` were measured leaking identically |
| `await conn.rollback()` on the cancellation path | **Rejected** — unbounded await on the demotion path (measured 1.005s, capped only by `command_timeout`); and the `await rb` arm is defeated by a second cancellation |
| Widen the 90 bodies to `except BaseException` | **Rejected** — 90-site edit, each needing its own rollback semantics, with the same unbounded-await problem |
| Document only, fix nothing | **Rejected** — at-least-once holds, but pool poisoning on the demotion path is real and its symptom is silent |
