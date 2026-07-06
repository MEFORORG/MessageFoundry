# ADR 0058 — Batch-claim the contiguous due head-prefix on the INGRESS/ROUTED FIFO claim path

**Status:** Proposed · **Date:** 2026-06-30
**Relates-to:** ADR 0001 (staged pipeline), ADR 0055 (SQLite group committer / poison-guard AC-2),
ADR 0057 (B1 inline fast-path + G6 ingress-attempts ceiling), issue #285 (no-READPAST per-lane FIFO).

---

## 1. Context

Per-message throughput on the staged pipeline is bound by the per-lane **serial commit round-trip
chain**. A message that fans out to one handler costs ~7 durable commits; B1's inline fast-path already
cut eligible messages toward ~5. Of those, **three are standalone `claim_next_fifo` commits** — one each
at the ingress, routed, and outbound stages. On the measured remote-SQL profile (~66 msg/s,
round-trip-bound; see the pipeline-commit-bottleneck analysis) each claim is a full serial DB round-trip
on the critical path.

`claim_next_fifo` today is a TOP(1)/LIMIT 1 claim: one row, one commit, one handoff, repeat. A lane
draining K messages pays **K claim commits + K handoff commits**. The claim commit is pure overhead that
can be amortized: if a lane claims a *batch* of up to N rows in **one** commit and then processes each
row with its existing per-row off-loop work + per-row handoff, the same K messages cost
**ceil(K/N) claim commits + K handoff commits** — cutting the ingress and routed standalone-claim commits
toward 1/N each.

The outbound/delivery claim is **excluded**: its H2 skip-and-complete dedup branch
(`sqlserver.py` / `postgres.py` / `store.py`) completes an already-delivered re-pended head DONE *in
place* inside the single claim txn that returns `None`. Batching it would reorder the disposition
timeline. Ingress/routed rows carry `destination_name IS NULL` and never reach that branch, so they have
no in-claim-txn skip-and-complete to preserve.

## 2. Decision

Add a **new, pure-additive** store primitive
`claim_next_fifo_batch(name, now=None, *, stage, limit) -> list[OutboxItem]` to the `QueueStore`
protocol. It claims the **contiguous due head-prefix** — the N oldest rows of one lane in
`(created_at, seq | rowid)` order that are due (`next_attempt_at <= now`) and not blocked, **stopping at
the first not-due or producer-locked head** — bumping `attempts+1` on all claimed rows and flipping them
to `INFLIGHT` in **one** claim commit, then releasing all locks before returning the list.

`claim_next_fifo` is **unchanged**. The router/transform workers gate on a new
`[store].fifo_claim_batch` int (**default 1 = OFF**). At N=1 the workers call the **untouched**
`claim_next_fifo` verbatim (byte-identical). At N>1 they call the batch method and wrap the existing
per-row body in `for item in items:` — processing strictly in order, one off-loop
`route_only`/`transform_one` + one separate-commit handoff per row.

### The contiguous-due-prefix claim query, per backend

**Critical correctness rule (all backends):** the due-gate (`next_attempt_at <= now`) lives in the
**row-windowing predicate** so a not-due head **truncates the prefix to that point** — never deferred to
a stage that would let the window grab rows *past* a not-due head. A not-due head yields an **empty
batch** (lane blocks), exactly as today's single claim returns `None`.

This is non-negotiable because an **ingress head can be not-due**: the missing-inbound revert in
`_router_worker` calls `mark_failed(item.id, "inbound not in registry", RetryPolicy())`, and
`RetryPolicy()` defaults `backoff_seconds=5.0`, so `mark_failed` re-pends the ingress head with
`next_attempt_at = now + 5s`. **Ingress and routed both truncate at the first not-due row.**

#### SQLite (`store/store.py`)

Under the existing process-wide `async with self._lock` (the ADR 0055 group-committer serializer): no
row locks — the single writer **is** the no-skip guarantee, so there is no producer-locked head to block
on. SELECT the lane's oldest `limit` pending rows in `created_at, rowid` order, then truncate the prefix
at the first **not-due** row with a Python `break` (never reaching past it). One `UPDATE … id IN (…)`
bumps `attempts+1` + flips to `inflight`; then **re-SELECT** the claimed rows so each `OutboxItem` carries
the POST-increment `attempts` the G6 ceiling reads (mirrors the single claim's re-read). Decrypt after the
commit, off the lock; an undecryptable row is dead-lettered standalone and dropped.

#### SQL Server (`store/sqlserver.py`) — **a real batch claim (NOT a delegation)**

> **Correction over an earlier draft.** An earlier draft made the SQL Server batch a no-op delegation to
> the single claim on the premise that "SQL Server is outbound-only and never hosts ingress/routed lanes."
> **That premise is false.** `store/sqlserver.py` declares `supports_ingest_stage = True` and its module
> header states it "runs the full ADR-0001 staged pipeline (ingress → routed → outbound)". SQL Server is
> the **production scale-path store**, so a delegation would give B2 **zero benefit on the production
> store**. The stale `OutboxItem.created_at` docstring ("the SQL Server backend is outbound-only and runs
> no transforms") was a leftover from before the SQL Server store promotion and is **fixed by this ADR**:
> `created_at` is `None` on SQL Server only because the single claim's OUTPUT omits that column, *not*
> because SQL Server is outbound-only.

SQL Server uses **SELECT-then-UPDATE in ONE transaction** — the same shape the SQLite impl already uses,
with the single claim's `UPDLOCK, ROWLOCK` **no-READPAST** lock providing the head-of-line *blocking* that
SQLite gets from its global lock. Two statements in one `_acquire()`/`_cursor()` txn:

```sql
-- STEP 1 — lock the prefix candidates (plain SELECT: NO window function, NO re-join to queue)
SELECT TOP (@limit) id, next_attempt_at, seq
FROM queue WITH (UPDLOCK, ROWLOCK)            -- NO READPAST: block (not skip) on a producer-locked head (#285)
WHERE stage=@stage AND <lane_col>=@lane AND status=@pending
ORDER BY created_at, seq;
-- STEP 2 (in Python) — contiguous-due cutoff: sort by seq, break at the first next_attempt_at > @now,
--                       collect the due-prefix ids. Empty prefix ⇒ commit + return [] (lane blocks).
-- STEP 3 — claim exactly the due prefix (U-locks from STEP 1 still held in this txn)
UPDATE queue SET status=@inflight, attempts=attempts+1, updated_at=@now
OUTPUT inserted.id, inserted.message_id, inserted.channel_id, inserted.destination_name,
       inserted.handler_name, inserted.payload, inserted.attempts, inserted.seq
WHERE id IN (@id1, @id2, …) AND status=@pending <epoch_guard>;
```

Why this is correct:

* STEP 1's **plain** `SELECT TOP(@limit) … WITH (UPDLOCK, ROWLOCK)` **no-READPAST** — with **no window
  function and no re-join to `queue`** — takes its U-locks *as it scans the rows in `created_at, seq`
  order*, so it **BLOCKS** on a producer-locked interior head exactly like the single claim's `head`
  SELECT (no skip — #285 preserved). It cannot read past a locked head to a later seq. `queue` has
  `LOCK_ESCALATION=DISABLE` + the `ROWLOCK` hint, and `@limit <= 64`, so at most N row locks → **no
  escalation** to a TABLE lock. The U-locks are held until the txn commits (i.e. through STEP 3).
* STEP 2 truncates the prefix **in Python** at the first not-due row (`next_attempt_at > @now`), a `break`
  that never reaches past it — identical to the SQLite impl. A not-due *head* yields an empty prefix ⇒
  `commit()` + `return []` ⇒ the lane blocks (== the single claim's `None`).
* STEP 3's `UPDATE … WHERE id IN (…)` claims exactly that due prefix; the `AND status=@pending` is a
  belt-and-suspenders guard (the held U-locks already prevent another claimer). OUTPUT projects the **same
  fields as the single claim** (NO `created_at` — its OUTPUT omits it; the worker's ingest-time is
  therefore `None` on SQL Server, consistent with the single claim), **plus `inserted.seq`** — the
  plaintext FIFO tiebreak (never PHI) used only to re-establish the lane's oldest-first order in memory
  (the OUTPUT clause does not guarantee row order). The H1 `epoch_guard` is appended verbatim so a fenced
  ex-leader claims 0 rows.

**Why NOT the earlier single-statement window-CTE.** An earlier draft fused all three into one statement:
`WITH locked AS (SELECT TOP(N) …, SUM(…) OVER (ORDER BY created_at, seq …) AS notdue_through FROM queue
WITH (UPDLOCK, ROWLOCK) …), head AS (SELECT id FROM locked WHERE notdue_through = 0) UPDATE q … FROM queue
q INNER JOIN head h ON q.id = h.id`. On real SQL Server **T6 caught this not blocking on a locked head**:
the **window function** plus the **re-join to `queue q`** let the optimizer satisfy the read from a
version/index without holding the UPDLOCK *through the lock-wait* under the store's force-enabled RCSI, so
it read past a producer-locked head and could claim a later seq ahead of it (a #285 violation). The single
claim avoids this because its `WITH head AS (SELECT TOP(1) … WITH (UPDLOCK, ROWLOCK)) UPDATE head` operates
directly on the locked rows. The SELECT-then-UPDATE form restores that property: the lock-wait happens on
the candidate rows themselves in STEP 1, exactly as in the single claim.

Read the OUTPUT with `fetchall` under the EF-6 `_cursor()` close-before-release discipline (no-MARS),
like the single claim.

#### Postgres (`store/postgres.py`) — the careful one

Today's single claim uses `… LIMIT 1 FOR UPDATE SKIP LOCKED`. **`SKIP LOCKED` must be dropped for the
batch:** at `LIMIT N` it would *skip* a producer-locked interior head and pull a later row into the window
(the #285 reorder). The batch uses plain **`FOR UPDATE`** so a locked head **blocks** (matching the single
claim's documented intent).

Postgres rejects `FOR UPDATE` combined with window functions, so the lock and the prefix-cut are split:
an **inner `FOR UPDATE` subquery** that locks the lane's oldest `LIMIT N` pending rows in order (no
window), then an **outer non-locking** window that truncates at the first not-due row. The same-txn
stranded-head failover reclaim runs **first**, unchanged.

```sql
WITH locked AS (
    SELECT id, created_at, seq, next_attempt_at FROM queue
    WHERE stage=$1 AND <lane_col>=$2 AND status=$3
    ORDER BY created_at, seq LIMIT $8 FOR UPDATE          -- NO SKIP LOCKED: block on a producer-locked head
),
ordered AS (
    SELECT id, next_attempt_at, row_number() OVER (ORDER BY created_at, seq) AS rn FROM locked
),
head AS (
    SELECT id FROM ordered
    WHERE rn < COALESCE((SELECT min(rn) FROM ordered WHERE next_attempt_at > $5), 2147483647)
)
UPDATE queue q SET status=$4, attempts=attempts+1, updated_at=$5, owner=$6, lease_expires_at=$7
FROM head WHERE q.id=head.id <epoch_guard> RETURNING q.*;
```

`owner`/`lease_expires_at` are stamped on all claimed rows (failover-recovery parity); the H1
`epoch_guard` is appended exactly as the single claim. `RETURNING q.*` carries `created_at` (Postgres
surfaces it). The inner `FOR UPDATE` locks at most N rows (bounded by `LIMIT $8`), not the whole lane. The
result is re-sorted by `(created_at, seq)` in memory before decode (RETURNING does not guarantee order).

**All backends:** the worker processes the returned list **strictly in `(created_at, seq | rowid)`
order**; it never re-sorts.

## 3. Invariant preservation

- **INV-1 — strict per-lane/order-group FIFO, no skip past a not-due/locked head.** The batch is the
  *contiguous due prefix*: ORDER BY the lane total order, truncate at the first not-due row (SQLite and
  SQL Server in a Python `break`; Postgres `rn < first-not-due`), never reach past it. Locked head: SQL
  Server's STEP 1 SELECT uses `UPDLOCK, ROWLOCK` **no READPAST** (blocks — #285); Postgres uses plain
  **`FOR UPDATE`** (blocks — #285); SQLite's global lock means no producer holds a row mid-claim. A
  not-due head ⇒ empty batch ⇒ lane blocks, identical to single-claim `None`.
- **INV-2 — poison-guard durable-before-work, rollback-independent (ADR 0055 AC-2).** `attempts+1` is
  bumped on **all** N rows **inside the one claim commit**, before any route/transform. The per-row work +
  handoff are *separate later commits*, so a work rollback can't un-bump attempts. `reset_stale_inflight`
  never touches `attempts`, so a crash-loop is bounded by the existing G6 ingress-attempts ceiling.
- **INV-3 — at-least-once / crash-mid-batch.** Recovery is **status-based, not cardinality-based**. After
  the claim commit all N rows are `INFLIGHT`. The worker hands them off one at a time; each handoff is its
  **own** txn opening with the idempotent `DELETE … WHERE id=? AND stage=? AND status='inflight'` guard. A
  crash after K of N: rows 1..K were DELETEd by their committed handoffs (gone — `reset_stale_inflight`'s
  `WHERE status='inflight'` can't match them, no dup); rows K+1..N never reached handoff (still INFLIGHT)
  → `reset_stale_inflight` re-pends them with original `created_at` (order preserved) → re-claimed →
  **pure re-run** → handoff DELETE-guard inserts the next-stage rows exactly once. `{consumed} ∪
  {INFLIGHT-recovered} = all N`, no gap, no dup.
- **INV-4 — no txn/row-lock across off-loop work.** The batch claim commits and **releases all locks
  inside** `claim_next_fifo_batch` before returning (SQLite exits `self._lock`; Postgres closes
  `conn.transaction()`; SQL Server commits + `_cursor` closes the statement handle); rows sit `INFLIGHT`
  by status only. The N `to_thread` calls run with no held lock — the single-row contract, repeated N
  times.
- **INV-5 — byte-identity at N=1.** Default `fifo_claim_batch=1` ⇒ the worker takes the `<= 1` branch and
  calls the **unchanged** `claim_next_fifo`. The batch method is never invoked at N=1. `claim_next_fifo`,
  the handoffs, the OUTPUT/RETURNING shapes, and the outbound dedup path are all untouched.
- **INV-6 — finalizer = sole disposition authority.** Unchanged. The finalizer scans all of a message's
  rows across stages; it already tolerates N concurrent sibling INFLIGHT rows.
- **INV-7 — head-of-line within the batch.** The worker iterates the list strictly in lane order, one
  off-loop call + one handoff between each. A slow/failing row K is fully resolved (handed off,
  dead-lettered, or STOP-return) before row K+1's handoff, so K+1 can never hand off ahead of K. No
  in-batch concurrency.

## 4. Consequences

- Ingress and routed claim commits amortize from 1/msg toward 1/N. Per-message claim commits go from 3 to
  `1 + 2/N` (outbound stays 1). At N=8: ~1.25 (was 3); total durable commits/msg ~7 → ~5.25.
- N decrypted message bodies are resident per lane between the one claim and the N handoffs — bounded by
  `ge=1, le=64`; size the operational default (recommend 8–16) against worst-case message size, not the
  ~11.5 KB average.
- **SQL Server — the production scale-path store — gets the real win** (a genuine batched SELECT-then-
  UPDATE claim), not a no-op delegation. This is the central correction over the earlier draft. (The batch
  is 2 round-trips/claim — a locking SELECT then an UPDATE — vs the single claim's 1; it still amortizes
  the commit vs N single claims, and correctness, block-on-locked-head, is non-negotiable.)
- A STOP-policy abort mid-batch abandons the tail as INFLIGHT for recovery — slightly more worst-case
  re-run work, acceptable under existing STOP semantics.

## 5. Out of scope

- **Outbound/delivery claim** — never batched (the H2 skip-and-complete must stay atomic).
- **Batch handoff** — the N handoffs stay N separate commits; fusing them would break crash-mid-batch
  recovery and in-batch head-of-line. The N/msg handoff commits remain the floor — the structural lever
  for the large-org 10–20× target is inbound order-group lane sharding (parallel lanes), not this
  claim-commit cut.
- **A new row status** — rows stay `INFLIGHT` (else `reset_stale_inflight` can't recover them).

## 6. Residual risk

1. **Postgres two-level CTE** — `FOR UPDATE` + window functions don't combine, hence the inner-lock /
   outer-window split. The inner `FOR UPDATE … LIMIT $8` locks at most N rows (not the whole lane), and a
   producer-locked interior head **blocks** rather than letting a later row through. The `postgres` CI leg
   gates this (T6).
2. **SQL Server SELECT-then-UPDATE lock behavior** — STEP 1's plain `SELECT TOP(N) WITH (UPDLOCK,
   ROWLOCK)` no-READPAST (no window function, no re-join) must **block** (not skip) on a producer-locked
   interior head to preserve #285, then hold the U-locks through STEP 3's `UPDATE … id IN (…)`. The earlier
   single-statement window-CTE (`SUM(…) OVER (…)` + `JOIN queue q`) did **not** block under RCSI — T6 on
   real SQL Server caught it claiming a later seq ahead of a locked head — which is why the lock-wait now
   happens on the candidate rows directly, matching the single claim. `LOCK_ESCALATION=DISABLE` + bounded
   `@limit` keep it to N row locks. **T6 on the `sql-server` CI leg is the PR-blocking gate** that proves
   the locked head blocks rather than skips.
3. **SQLite re-SELECT cost** — one extra `SELECT … id IN (…)` per claim to read post-increment `attempts`;
   trivial under the single lock, but necessary (reusing the pre-UPDATE snapshot would shift the G6 poison
   ceiling by one pass).
4. **Memory under pathological N × many inbounds** — N decrypted bodies/lane resident between claim and
   handoff. The `le=64` clamp bounds it.
5. **STOP-policy mid-batch** abandons the tail to recovery — bounded, acceptable, slightly raises
   worst-case re-run work versus N=1.

All contained by: default OFF, byte-identical at N=1 (the safe rollout default), the
contiguous-due-prefix + block-on-locked-head rules (FIFO non-negotiable), and the per-row separate
handoffs + status-based `reset_stale_inflight` (crash recovery unchanged).
