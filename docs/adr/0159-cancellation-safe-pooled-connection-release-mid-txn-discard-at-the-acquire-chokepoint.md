<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

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
  with no `Exception` filter), and asyncpg's pool additionally resets under `asyncio.shield`. SQLite shares
  the `except Exception` shape but has a single writer connection under an `asyncio.Lock` and no pool, so
  there is no next-borrower to inherit anything.
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
