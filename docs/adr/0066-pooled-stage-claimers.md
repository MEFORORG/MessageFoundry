# ADR 0066 — Pooled per-stage claimers with a FIFO-safe multi-lane head-claim primitive (`claim_mode = pooled`)

**Status:** Proposed · **Date:** 2026-07-02
**Relates-to:** ADR 0057 (inline Step-A fast path), ADR 0058 (batch-claim FIFO prefix), ADR 0059 (seq-only per-lane FIFO / one-serial-writer), ADR 0061 (per-lane wake events + the 2026-07-02 wake-or-backstop amendment), ADR 0063 (unified store for sharding), issue #285 (READPAST FIFO break) and its fix, the operator bench drop `claim-storm-finding-2026-07-02` (WS_C_CLAIM_STORM_REPORT / FIX_RECOMMENDATION / HANDOFF_for_dev — operator-local), docs/throughput-build-plan.md "WS-C RESULT" (2026-07-02).
**Code references** are `origin/main @ 0febba9`; line numbers are approximate — locate exactly at implementation time. This ADR supersedes nothing.

> **Default flipped to `pooled` — DONE (2026-07-03, issue #744).** `[pipeline].claim_mode` now defaults to **`pooled`** for every deployment; **`per_lane` stays fully selectable as the byte-identical opt-out** (`[pipeline].claim_mode = "per_lane"`). The flip was armed on: the **rate-walk resilience GO** (single-node — pooled collapses the claim storm and holds zero-loss at high fan-out where `per_lane` DROPS messages; lane isolation holds; store exonerated; engines scale), the **reinterpreted §8.12b** (the 525/s "FAIL" was a target-vs-capacity mismatch — 2 engines cap ~250–300/s and the ~120–150/s per-engine wall is engine-internal, not a pooled fault — not a resilience failure), and the **§8 row-1b fan-in soak PASS on live SQL Server + Postgres** (the §11-item-5 arming precondition, cited by name). Two operator caveats travel with the flip and are documented in `docs/CONNECTIONS.md` / `docs/SYSTEM-REQUIREMENTS.md`: (a) **exactly-once degrades under load** — no inbound de-dup, so throughput that pushes ACK latency past a partner's resend timeout yields duplicate delivery, contained by the "receivers must be idempotent" contract (NOT pooled-specific; `per_lane` is the same, it just surfaces at pooled-enabled scale); and (b) **single-node scope** — the evidence is single-node (`NullCoordinator`); failover duplicate/ordering paths are unmeasured (the T17 infra-fault known limitation is tracked by ADR 0070). See §11 items 9b / 10 below for the gate history.

---

## 1. Context

At connection scale (1,500 inbound MLLP lanes, 2 engines, 1 shared SQL Server store, 525 msg/s target) the staged pipeline runs **~4,500 per-(lane×stage) claim loops** — one router + one transform worker per inbound (`_ensure_inbound_workers`, wiring_runner.py:1194), one delivery worker per outbound (`_spawn_worker`, :1156) — each issuing `UPDLOCK, ROWLOCK` claims against the single shared `queue` table. Bench-proven (both boxes, adversarially cross-verified):

- **Idle:** ~18k empty UPDLOCK claim statements/s saturate the store at **zero messages** — 92% CPU, LCK_M_U convoy 40–70 ms, heavy PAGELATCH_EX. The claims are correct Index Seeks on `ix_queue_fifo_in_seq`/`ix_queue_fifo_out_seq` — this is **session-count-driven lock/latch contention, not a plan problem**. `poll_interval`, `pool_size`, and B12/`per_lane_wake` alone are inert against it.
- **Loaded:** the Phase-0 long-backstop patch (`wsC_fix.patch`) kills the idle storm (pool_wait_p95 5000 ms → 25 ms) but the **loaded claim convoy persists**: at 525/s, `in_pipeline` climbs unbounded, acks p95 ~28 s, delivered 58% ≪ 98%. Load-gen verdict: **Phase-1 (a) required.**

**The mandate** (FIX_RECOMMENDATION, operator-approved): collapse to **O(stages) pooled claimers** with a **new FIFO-safe head-per-lane store primitive** — at most one head (prefix) per lane, **EMPTY on a producer-locked head, never a READPAST skip to seq N+1 within a lane** (the #285 trap) — plus an in-process per-lane serializer/backpressure. **No schema migration.** Flag `[pipeline].claim_mode = pooled (default since #744) | per_lane (byte-identical opt-out)`.

**Hard invariants** (unchanged, restated as acceptance gates in §8): strict per-lane FIFO (#285/T6); at-least-once (claim+handoff single txn; crash re-runs idempotently); ACK-on-receipt; the finalizer (`sp_getapplock` / PG advisory lock / SQLite global lock) stays the **single disposition authority, untouched**; `reset_stale_inflight` recovery must reach a claimer; `mark_failed` retries must be re-claimed on schedule; count-and-log (never accept-and-drop).

### Why the existing primitives cannot be pooled as-is
- SQL Server `claim_next_fifo` (sqlserver.py:2717) deliberately takes `(UPDLOCK, ROWLOCK)` **without** READPAST and **blocks** on a producer-locked head (bounded by `command_timeout` ≈ 30 s). Correct for a dedicated per-lane worker; fatal for a shared claimer — one locked head pins a pooled connection and stalls hundreds of sibling lanes.
- Adding READPAST to a per-lane `ORDER BY seq` scan skips a locked head and claims seq N+1 — the literal #285 break, fixed once already by dropping READPAST (PR #285) and re-confirmed by the T6 window-CTE failure on real SQL Server (documented in `claim_next_fifo_batch`, sqlserver.py:2885–2891).
- The claim loops also carry the retry/recovery backstop: the 0.25 s `poll_interval` re-poll (`_wait_for_work`, :2540) is today the only path that re-claims a `mark_failed` backed-off head and `reset_stale_inflight`-recovered rows. Any pooled design must replace that job explicitly.

This ADR synthesizes two adversarially reviewed designs (store-first "A", runner-first "B") plus every required change from the three verification gates (FIFO/#285, at-least-once/recovery, interactions/performance). A traceability appendix (§10) maps each required change to its section.

---

## 2. Decision — overview

In `pooled` mode the engine runs **one `StageDispatcher` per stage** (INGRESS, ROUTED, OUTBOUND; RESPONSE only when a loopback inbound exists). Each dispatcher owns:

1. **K claimer task(s)** (`pooled_claimers_per_stage`, default 1; lanes hash-partitioned lane→claimer when K>1 so no two claimers ever claim the same lane) calling a **new multi-lane store primitive** `claim_fifo_heads(stage, lanes, per_lane_limit)` — one round trip, one transaction, at most the contiguous due head-prefix per lane, EMPTY (never N+1) on a locked or not-due head.
2. **A per-lane state machine** — `IDLE | READY | CLAIMING | PROCESSING | PARKED(until) | STOPPED` — that is the **one-logical-consumer-per-lane serializer** (the pooled analog of ADR 0059's one-task-per-lane), plus per-lane **ephemeral processor tasks** running the *existing* worker-loop bodies, mechanically extracted into shared per-item methods used verbatim by both modes.
3. **A clock-driven discovery sweep task** (default 0.25 s = `poll_interval` parity) calling the new read-only `list_fifo_lanes(stage)` — the bounded at-least-once backstop replacing ~18k locking round-trips/s with ≤16 read-only round-trips/s, and the source of **exact retry timers** for backed-off heads.
4. **Claim-gated backpressure** — a per-stage processing-slot budget gates chunk *assembly*, so unclaimable work stays PENDING **in the store** (queue depth stays visible to buildup/stall alerts and `/stats`; crash exposure bounded; memory bounded).

`per_lane` mode (the byte-identical opt-out since the #744 default flip) spawns exactly today's topology and claim SQL — byte-identical, enforced by a test sentinel. **No schema migration**: the existing `ix_queue_fifo_in_seq (stage, channel_id, status, seq)` and `ix_queue_fifo_out_seq (stage, destination_name, status, seq)` indexes (sqlserver.py:153–160 and the PG/SQLite equivalents) serve both new primitives.

---

## 3. The store primitive — one algorithm, three dialects

### 3.1 Protocol additions (`messagefoundry/store/base.py`, beside `claim_next_fifo` :342)

```python
@dataclass(frozen=True)
class ClaimedHeads:
    """Result of claim_fifo_heads. `by_lane` holds seq-ascending contiguous head-prefixes
    (post-increment attempts — the G6 ceiling reads them). `rearm` names lanes whose claimed
    head was consumed in-store this call (H2 skip-and-complete, or an undecryptable head
    dead-lettered post-commit) — the dispatcher re-queues them immediately so the lane
    advances to its next head without waiting for a wake or sweep."""
    by_lane: dict[str, list[OutboxItem]]
    rearm: frozenset[str]

async def claim_fifo_heads(
    self, stage: str, lanes: Sequence[str], now: float | None = None,
    *, per_lane_limit: int = 1,
) -> ClaimedHeads: ...

async def list_fifo_lanes(
    self, stage: str, now: float | None = None,
    *, limit: int = 4096, after: str | None = None,
) -> list[tuple[str, float]]: ...
    # Read-only: every lane with >=1 PENDING row at `stage`, paired with its HEAD row's
    # (seq-min pending row's) next_attempt_at — head-of-line-aware by construction: a lane
    # whose HEAD is backing off reports the head's due time, never a due tail row's.
    # limit + after (resume-after-lane cursor) bound pathological universes.

async def release_claimed(self, ids: Sequence[str], now: float | None = None) -> None: ...
    # inflight -> pending for never-dispatched rows: attempts = attempts - 1 (undo exactly
    # this claim's increment; floor 0 defensively), next_attempt_at UNCHANGED, owner/lease
    # cleared, updated_at = now. FIFO-neutral (seq never re-minted). Chunked <=500 ids/stmt.

async def mark_failed(self, ..., now: float | None = None) -> float | None: ...
    # ADDITIVE return: the computed next_attempt_at when the row re-pended, None when it
    # went DEAD. All 3 backends. per_lane-mode callers ignore it (byte-identical).
```

`claim_next_fifo`, `claim_next_fifo_batch`, and `claim_ready` are **untouched** — `per_lane` mode keeps calling them.

**Lane sets are always passed explicitly by the caller** (the dispatcher's ready-lane subset, registry-intersected). There is deliberately **no all-lanes-of-stage claim form**: the bench's own validation topology runs **2 engines with disjoint 750-lane sets on one shared store** (and ADR 0063 locks disjoint-inbound sharding on one unified store as the scaling model), so an unscoped claim would steal the sibling shard's heads — foreign ingress heads would churn the missing-inbound guard (wiring_runner.py:2012–2024) and foreign outbound heads would burn finite delivery `max_attempts` toward wrongful dead-letter. Shard safety is a **today** requirement, not an N-active future.

### 3.2 The uniform algorithm (probe-then-claim; the #285 inversion)

One store call, one transaction, one server round trip (SQL Server; PG/SQLite parity per below):

- **STEP 1 — DISCOVERY (non-locking snapshot read; never blocks, never lock-skips).** Per requested lane, read the `TOP(per_lane_limit)` min-seq **PENDING** rows ordered by `seq`, **regardless of due-ness**. RCSI committed snapshot on SQL Server; plain MVCC on Postgres; under the process-wide `_lock` on SQLite. The candidate is always the lane's min-seq pending row — never "min seq among due" (which would skip a backing-off head).
- **STEP 2 — CONTIGUOUS-DUE CUTOFF.** Within each lane's discovered list, truncate at the first row with `next_attempt_at > now`. A not-due **head** empties the lane (head-of-line blocking preserved — identical to ADR 0058 STEP 2 / the single claim's `None`).
- **STEP 3 — LOCK-PROBE, confined to the discovered ID set.** Attempt to lock exactly the cut candidates: `UPDLOCK, ROWLOCK, READPAST` on SQL Server (UPDLOCK forces real row locks even under forced RCSI — it cannot be satisfied from the version store — and this is `claim_ready`'s shipped, known-good hint set, :2645); `FOR UPDATE SKIP LOCKED` on Postgres; vacuous on SQLite (the global lock totally orders producers and claimers — a locked-head state is unobservable). **The lock-skip domain contains only discovered candidates**, so a skip can only *drop* a candidate — it is structurally incapable of reaching any row outside the set, let alone seq N+1 within a lane.
- **STEP 4 — HEAD-PINNED CONTIGUITY (the A1 fix; the PG "head-agreement pin", B1).** Per lane, keep the longest discovered prefix **anchored at the discovered head h0** whose every member survived the probe. If **h0 itself** was skipped (locked) or re-checked away, the lane yields **EMPTY** — never `[N+1, ...]`. A mid-prefix gap at rank j truncates at j−1. Because non-kept rows were never UPDATEd, **nothing needs releasing and `attempts` is never touched on them** (this closes the attempts-inflation and the release-atomicity findings by construction).
- **STEP 5 — CLAIM exactly the kept prefixes.** `UPDATE → status='inflight', attempts=attempts+1, updated_at=now` (+ PG: `owner`, `lease_expires_at`; SQL Server: `owner=NULL` single-active-node parity), with the **H1 `epoch_guard` appended verbatim** (`AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=?) <= ?`; NULL lease → fail-closed) and belt-and-suspenders `status='pending' AND next_attempt_at<=now` re-checks. Rows are already U-locked/row-locked from STEP 3, so per-row re-check failures are structurally impossible and the epoch guard is row-uniform (all-or-nothing) — **defensive rule:** if the claimed set differs from the kept set, roll back the whole call and return EMPTY-all (fail closed), log at WARNING.
- **STEP 6 — OUTBOUND H2 (same txn).** For each claimed outbound row with a `delivered_keys` hit, run the skip-and-complete **code-identical to `claim_next_fifo`'s** (sqlserver.py:2797–2823 / postgres.py:2058–2087 / store.py:2715–2740): DONE + `delivered` event + `_maybe_finalize`, drop from results, add the lane to `rearm`. This is the **only** `_maybe_finalize` call site in the primitive — the same caller class, txn discipline, and applock/advisory-lock ordering as today's single claim. **`per_lane_limit` is hard-1 for OUTBOUND and RESPONSE** (H2 atomicity + single-outstanding-head retry semantics, exactly as ADR 0058 excludes them from batching).
- **COMMIT; decrypt after commit.** Undecryptable payload → `dead_letter_now` standalone + drop (existing poison containment); if a lane's whole prefix was consumed (H2/poison), the lane joins `rearm`.

**Why this cannot violate #285 (the locking analysis).** The per-lane `ORDER BY seq` scan — the only place a lock-skip could move *within* a lane — happens exclusively in STEP 1's **non-locking snapshot read, where lock-skip semantics do not exist**. Lock-skips exist only in STEP 3, whose domain is the explicit discovered-ID set, and STEP 4 pins the kept set to the discovered head. Under the **true T6 schedule** (committed rows N, N+1, N+2; an external transaction X-locks N): discovery sees N as head (committed, snapshot-visible); the probe READPASTs/SKIP-LOCKEDs N; the head-pin sees h0 missing → **EMPTY** — not `[N+1, N+2]`. After the lock releases, the next pass claims N first. Under the **uncommitted-producer schedule** on a single-writer `channel_id` lane (ADR 0059: exactly one serial writer per (stage, lane), wiring_runner.py:1199–1210): an uncommitted row N implies **no committed N+1 exists in that lane** (the same writer hasn't inserted it; `route_handoff`/`transform_handoff` multi-row inserts commit atomically), so the snapshot head is always the lane's true committed head or nothing. Correctness lives in the explicit ID pin plus re-checks, **not in plan shape**, so the T6 window-CTE/RCSI failure mode (sqlserver.py:2885–2891) cannot recur.

**Documented semantic shift on SQL Server multi-writer fan-in lanes (`destination_name`)** — required disclosure, verdict A4: snapshot discovery adopts **Postgres visibility semantics**. Writer A's *uncommitted* seq-N row is invisible; writer B's *committed* N+1 is discovered and claimable — where today's UPDLOCK claim would block until A commits and then order N first. This is sanctioned by the codebase's own doctrine: cross-inbound interleavings on a fan-in lane carry **"no honored cross-inbound receive order"** (`_ensure_inbound_workers` docstring, :1207–1210), per-source order through the fan-in survives via the serial-writer argument, and it is byte-for-byte the justification the shipped Postgres `claim_next_fifo` already uses for SKIP LOCKED (postgres.py:1980–1986). Corollary: **T6 "uncommitted head → EMPTY" assertions are scoped** to single-writer lanes / the external-lock-on-committed-head schedule (§8 row 1). A second PG-parity disclosure: an admin replay/dead-letter re-pend transaction briefly holding a re-pended old-seq row while a claim runs can be passed over for **one cycle** (the re-pend is invisible or lock-skipped and head-pinned to EMPTY-or-current-head; the next cycle claims it first). This is an **ordering exposure bounded to one cycle**, identical to the shipped PG claim's exposure — documented, not new.

**Why EMPTY-on-locked-head is free here:** no statement in the pooled claim ever *waits* on a row lock (discovery snapshot-reads; the probe skips), so a shared claimer connection is never pinned in a lock-wait — the mandate's core reason for EMPTY, satisfied structurally with zero `command_timeout` dependence.

### 3.3 SQL Server dialect (one parameterized T-SQL batch, one `cursor.execute`, one commit)

The store already force-enables RCSI at open (`_ensure_database_options`, sqlserver.py:624–677) but **degrades to a warning** on locked-down DBs; **pooled mode adds a startup verify that FAILS CLOSED by default** (clear DBA remediation message) if `is_read_committed_snapshot_on = 0`, overridable via `[pipeline].require_rcsi_for_pooled=false` (which downgrades to a loud warning + a persistent `/stats` `rcsi_off_degraded` gauge and AlertSink event). **Note (corrected 2026-07-02):** the claim's non-blocking guarantee no longer *depends* on RCSI — both the claim and the `list_fifo_lanes` sweep prepend `SET LOCK_TIMEOUT 0` (a contended head raises native error 1222, mapped to the EMPTY-all contract), making the pooled path **structurally never-block independent of RCSI**. Fail-closed is retained on the correct grounds: the §3.2 correctness proofs and the §8 CI gates are scoped to RCSI-on snapshot visibility, and READ-COMMITTED discovery semantics are unverified. `{lane_col}` is the existing stage-aware code-controlled literal (`_lane_col`, :2635). `SET NOCOUNT ON` keeps the OUTPUT the sole result set (EF-6 `_cursor` close-before-release discipline unchanged; `fetchall` drains it).

```sql
SET NOCOUNT ON;
DECLARE @now FLOAT = ?, @stage NVARCHAR(16) = ?, @k INT = ?;

DECLARE @heads  TABLE (lane NVARCHAR(256) NOT NULL, id NVARCHAR(64) NOT NULL PRIMARY KEY,
                       seq BIGINT NOT NULL, rn INT NOT NULL, due BIT NOT NULL);
DECLARE @locked TABLE (id NVARCHAR(64) NOT NULL PRIMARY KEY);
DECLARE @keep   TABLE (id NVARCHAR(64) NOT NULL PRIMARY KEY);

-- STEP 1: snapshot discovery (plain RCSI read — no hints; non-blocking, never lock-skips).
-- One index seek per lane on ix_queue_fifo_in_seq / ix_queue_fifo_out_seq. The CI leg asserts
-- per-APPLY seeks; add FORCESEEK(ix_queue_fifo_..._seq) if the optimizer ever flattens (a
-- perf assertion only — correctness never depends on the plan).
INSERT INTO @heads (lane, id, seq, rn, due)
SELECT l.lane, h.id, h.seq,
       ROW_NUMBER() OVER (PARTITION BY l.lane ORDER BY h.seq),
       IIF(h.next_attempt_at <= @now, 1, 0)
FROM (VALUES (?), (?) /* ... <= pooled_claim_lane_chunk lane names ... */) AS l(lane)
CROSS APPLY (SELECT TOP (@k) id, seq, next_attempt_at FROM queue
             WHERE stage = @stage AND {lane_col} = l.lane AND status = 'pending'
             ORDER BY seq) AS h;

-- STEP 2: contiguous-DUE cutoff. A not-due row truncates AT itself; a not-due HEAD empties
-- the lane (head-of-line preserved — candidates were chosen min-seq REGARDLESS of due-ness).
DELETE h FROM @heads h
WHERE EXISTS (SELECT 1 FROM @heads p WHERE p.lane = h.lane AND p.rn <= h.rn AND p.due = 0);

-- STEP 3: lock-probe confined to the discovered ID set. UPDLOCK takes REAL row locks even
-- under forced RCSI; READPAST can only DROP a member of @heads — it structurally cannot
-- advance to any row outside the set. Epoch guard here decides the lockable set fail-closed.
INSERT INTO @locked (id)
SELECT q.id FROM queue q WITH (UPDLOCK, ROWLOCK, READPAST)
WHERE q.id IN (SELECT id FROM @heads)
  AND q.status = 'pending' AND q.next_attempt_at <= @now
  {epoch_guard: AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=?) <= ?};

-- STEP 4: head-pinned contiguity — keep, per lane, the longest prefix anchored at rn=1 whose
-- EVERY member is locked; rn=1 missing drops the whole lane => EMPTY, never seq N+1.
INSERT INTO @keep (id)
SELECT h.id FROM @heads h
WHERE NOT EXISTS (SELECT 1 FROM @heads p
                  WHERE p.lane = h.lane AND p.rn <= h.rn
                    AND NOT EXISTS (SELECT 1 FROM @locked k WHERE k.id = p.id));

-- STEP 5: claim exactly the kept prefixes (rows already U-locked; re-checks + the verbatim
-- epoch guard are belt-and-suspenders — plan-robust by the ID pin).
UPDATE q SET status = 'inflight', attempts = attempts + 1, updated_at = @now,
             owner = NULL, lease_expires_at = NULL
OUTPUT inserted.id, inserted.message_id, inserted.channel_id, inserted.destination_name,
       inserted.handler_name, inserted.payload, inserted.attempts, inserted.seq
FROM queue q JOIN @keep k ON q.id = k.id
WHERE q.status = 'pending'
  {epoch_guard};
```

Python then: group OUTPUT rows by lane, re-sort by `seq` (OUTPUT order is not guaranteed — same as the shipped batch, :2969–2975); assert kept==claimed per lane else rollback+EMPTY-all; run STEP 6 H2 statements for outbound rows in the same txn; `conn.commit()`; decrypt after commit. **Round trips:** 1 execute + 1 commit — the same wire-op count as today's single `claim_next_fifo` (H2 hits add statements only when a duplicate is actually detected, as today). **Parameters:** lane names + a handful of scalars only — row IDs live in table variables and never travel as parameters, so `pooled_claim_lane_chunk × per_lane_limit` can never brush pyodbc's ~2,100-parameter bound; the chunk is still clamped ≤ 500 defensively. Locks: ≤ chunk×k row U-locks (`LOCK_ESCALATION = DISABLE` already set, :161–167), zero lock waits, one commit. Deadlock-free: claimers never overlap lanes (partitioned) or stages (disjoint row sets); vs producers/admin ops the probe skips instead of waiting.

### 3.4 Postgres dialect (one chained-CTE statement inside the usual claim txn)

Statement count per claim **equals today's** (`BEGIN; lane-scoped stranded-lease reclaim; claim; [H2]; COMMIT` — postgres.py:2025–2087 generalized to the lane array). The reclaim **must stay a separate statement before the claim** (PG data-modifying-CTE snapshot rules: a later CTE cannot see an earlier CTE's writes through the table), and it runs FIRST exactly as today — failover FIFO preserved:

```sql
-- (i) multi-lane stranded-head lease reclaim, same txn, FIRST (the multi-lane twin of the
--     shipped per-lane reclaim): a crashed/fenced predecessor's expired-lease inflight rows
--     re-pend so the recovered oldest row is reconsidered as the (due) head and blocks the lane.
UPDATE queue SET status = $3, owner = NULL, lease_expires_at = NULL,
                 next_attempt_at = $4, updated_at = $4
WHERE stage = $1 AND {lane_col} = ANY($2::text[]) AND status = $5
  AND lease_expires_at IS NOT NULL AND lease_expires_at < $4;

-- (ii) discovery + probe + head-pin + claim, ONE statement (MATERIALIZED pins evaluation).
WITH cand AS MATERIALIZED (            -- STEP 1: plain MVCC snapshot read, non-locking
  SELECT l.lane, h.id, h.seq, h.next_attempt_at,
         row_number() OVER (PARTITION BY l.lane ORDER BY h.seq) AS rn
  FROM unnest($2::text[]) AS l(lane)
  CROSS JOIN LATERAL (
    SELECT id, seq, next_attempt_at FROM queue
    WHERE stage = $1 AND {lane_col} = l.lane AND status = $6
    ORDER BY seq LIMIT $7) AS h
), heads AS MATERIALIZED (             -- STEP 2: contiguous-due cutoff (not-due head => empty lane)
  SELECT c.* FROM cand c
  WHERE NOT EXISTS (SELECT 1 FROM cand p
                    WHERE p.lane = c.lane AND p.rn <= c.rn AND p.next_attempt_at > $4)
), locked AS MATERIALIZED (            -- STEP 3: lock-probe confined to the discovered ID set
  SELECT q.id FROM queue q
  WHERE q.id IN (SELECT id FROM heads)
    AND q.status = $6 AND q.next_attempt_at <= $4
  FOR UPDATE SKIP LOCKED
), keep AS MATERIALIZED (              -- STEP 4: head-pin — THE B1 head-agreement fix: a SKIP
  SELECT h.id FROM heads h             -- LOCKED drop of the visible head (rn=1) empties the
  WHERE NOT EXISTS (                   -- lane instead of letting LIMIT fill with N+1.
    SELECT 1 FROM heads p
    WHERE p.lane = h.lane AND p.rn <= h.rn
      AND NOT EXISTS (SELECT 1 FROM locked k WHERE k.id = p.id))
)
UPDATE queue q                         -- STEP 5: claim exactly the kept prefixes
SET status = $8, attempts = attempts + 1, updated_at = $4, owner = $9, lease_expires_at = $10
FROM keep WHERE q.id = keep.id
{epoch_guard: AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=$11) <= $12}
RETURNING q.*;
```

Then per-outbound-row H2 in the same txn (code-identical to :2058–2087), commit, decrypt after. All CTEs share one snapshot; `FOR UPDATE` uses EvalPlanQual re-checks post-lock; non-kept rows were locked-but-never-updated — locks release at commit, `attempts` untouched. Owner + row lease stamped per claimed row exactly as today (N-active-ready). The head-pin closes the reviewed hole where `ORDER BY seq LIMIT 1 FOR UPDATE SKIP LOCKED` alone advances past a *visible committed locked* head — and as a bonus closes the pre-existing admin-replay SKIP-LOCKED race to the same one-cycle EMPTY exposure documented in §3.2.

### 3.5 SQLite dialect

Under the process-wide `self._lock` (the ADR 0055 group-committer serializer), one transaction, one commit: loop the lane chunk (clamped ~200 to bound lock hold) → per lane `SELECT ... ORDER BY rowid LIMIT ?` → Python contiguous-due cutoff → `UPDATE ... WHERE id IN (...)` → re-`SELECT ... ORDER BY rowid` for **post-increment attempts** (the shipped batch pattern, store.py:2809–2821) → H2 per outbound claimed row (store.py:2722–2740) → single commit. The global lock makes a locked-head state unobservable — EMPTY-on-locked is vacuously satisfied and the lock **is** the no-skip guarantee (store.py:2767–2769). Decrypt off the lock; poison rows dead-lettered `_standalone=True` and dropped.

### 3.6 `list_fifo_lanes` — the read-only discovery

Loose index scan over `ix_queue_fifo_*_seq`: O(distinct lanes with pending rows) seeks, ~zero at idle, **no locks, no writes**.

- **SQL Server** (plain RCSI read — snapshot never blocks and never lock-skips; no hints needed):
```sql
WITH lanes AS (
  SELECT MIN({lane_col}) AS lane FROM queue WHERE stage = @stage AND status = 'pending'
  UNION ALL
  SELECT (SELECT MIN({lane_col}) FROM queue
          WHERE stage = @stage AND status = 'pending' AND {lane_col} > l.lane)
  FROM lanes l WHERE l.lane IS NOT NULL)
SELECT l.lane, h.next_attempt_at
FROM lanes l CROSS APPLY (SELECT TOP (1) next_attempt_at FROM queue
                          WHERE stage = @stage AND {lane_col} = l.lane AND status = 'pending'
                          ORDER BY seq) h
WHERE l.lane IS NOT NULL
OPTION (MAXRECURSION 0);
```
- **Postgres:** the recursive-CTE skip-scan analog + per-lane `LATERAL ... ORDER BY seq LIMIT 1`.
- **SQLite:** `SELECT DISTINCT {lane_col}` + per-lane head sub-select under the lock (registry-bounded universe).

Returning the **head row's** `next_attempt_at` (not `MIN(next_attempt_at)`) is load-bearing: it keeps the sweep head-of-line-aware (a lane with a backing-off head and due tail rows is *not* readied — no empty-claim churn) and lets the dispatcher arm **exact** retry timers for re-pends the runner did not perform (H2 re-pend, PG lease reclaim, replay, a sibling node's `mark_failed`).

---

## 4. The runner — `StageDispatcher`, claimers, sweep, lane serializer

### 4.1 Topology and state

In pooled mode `RegistryRunner.start()` constructs one `StageDispatcher` per stage instead of calling `_ensure_inbound_workers`/`_spawn_worker` (the RESPONSE dispatcher is created lazily when the registry holds a loopback inbound, re-checked on reload). Dispatcher state (all mutated **only on the event loop** — no locks): the per-lane state machine (`IDLE | READY | CLAIMING | PROCESSING | PARKED(until) | STOPPED` + a per-lane **dirty bit**), K claimer tasks with per-claimer ready-deques + `asyncio.Event`s, one sweep task, per-lane coalesced `loop.call_later` timer handles (earliest-wins), a processing-slot budget, and the live lane-task dict. Claimer/sweep/lane tasks get the same respawn-on-unexpected-exception supervision as today's workers (`_on_worker_done` pattern, :1162). Teardown mirrors the existing worker teardown (:1099–1152): stop event, wake all claimer events, cancel claimers + sweep + lane tasks + timers, gather, clear state post-gather.

### 4.2 Wake routing (`_wake_lane` pooled branch)

`dispatcher.mark_ready(key)` — **synchronous and await-free**, exactly like `Event.set()`, so every producer call site is unchanged in shape and cost, including the listener's wake-before-AA (ACK-on-receipt ordering untouched):

- **Unknown key → create-or-stick** (never silently drop), mirroring `_lane_event`'s strict get-or-create contract (:419–425) — covers the reload window and a loopback RESPONSE lane's first wake. (Wake call sites are all in-process handoffs naming this engine's own lanes; the shard filter applies to *sweep* results, which are store-wide — see 4.4.)
- `IDLE → READY` (push to the owning claimer's deque + set its Event). `READY` → no-op (coalesced). **`CLAIMING` → set dirty** — and an EMPTY claim outcome for a dirty lane transitions to `READY` (immediate re-claim), **not** IDLE. This closes the wake-during-claim race in both reviewed designs: a commit racing the in-flight claim statement re-claims immediately instead of waiting for the sweep — no steady tail-latency leak at 525/s. `PROCESSING` → set dirty (re-queue at `lane_done`). `PARKED` → set dirty only (new rows behind a backing-off head still head-of-line block; only the timer/sweep/`_wake_all` unpark). `STOPPED` → set dirty only (the reload re-arm drains it).
- `_wake_all` / `notify_work` (replay, DR failback, reload tail, post-recovery nudges): mark **all registry lanes** READY, **unpark PARKED lanes**, and request an immediate sweep — the recovery broadcast must override a park. The engine additionally calls `runner.notify_work()` after any mid-run reset/recovery (the Phase-0 wake-after-recovery nudge, adopted).
- In pooled mode `per_lane_wake` is **ignored** (logged once at start: subsumed by construction); `per_lane` mode keeps both ADR 0061 paths byte-identical.

### 4.3 Claimer loop

Drain up to `min(free_processing_slots, pooled_claim_lane_chunk)` lanes from my ready-deque (slots **reserved** at chunk assembly, unused reservations released after dispatch — exact under K>1); lanes → `CLAIMING`; `claim_fifo_heads(stage, lanes, per_lane_limit = clamp(fifo_claim_batch,1,64) for INGRESS/ROUTED else 1)`. Per lane: items → `PROCESSING` + spawn the lane serializer task; `rearm` lanes → `READY`; EMPTY → `READY` if dirty else `IDLE`, recorded into `EmptyClaimCounters` with the woken/sweep classification (B11 stays meaningful). No ready lanes → await my Event. A store error logs + returns the chunk's lanes to `READY` + `_stop_or_sleep(_WORKER_ERROR_BACKOFF_SECONDS = 1.0)` — chunk-scoped, so with K>1 only that claimer's partition pauses. The claimer **never awaits processing** — a slow lane cannot stall its siblings' claim service.

### 4.4 Sweep (the bounded at-least-once backstop) — an independent, clock-driven task

Every `pooled_sweep_interval` (default **0.25 s** = `poll_interval` parity — no silent worst-case regression, no connscale-SLO re-baseline), per stage: `list_fifo_lanes(stage, now)` → **intersect with this engine's registry lanes** (∪ the in-flight reload target set) — the shard filter, mandatory today (§3.1) → due heads: `mark_ready`; not-due heads: arm/refresh the lane's coalesced timer at `head_next_attempt_at` (which also unparks a PARKED lane when due). Because the sweep is its **own task**, it runs on the clock regardless of wake traffic — sustained wakes can never starve the backstop (the reviewed timeout-gated form is rejected). Cost: ≤ 4 stages × 4 read-only aggregate round-trips/s ≈ **16 RT/s total**, versus ~18,000 UPDLOCK claim RT/s today. On dispatcher start (engine `start()`, clustered promotion, reload re-arm) the dispatcher **seeds all registry lanes READY** and runs one immediate sweep — the claim-first parity that makes `reset_stale_inflight`-recovered rows (re-pended with `next_attempt_at = now`, sqlserver.py:3080–3112) reachable with **no wake at all**.

The retry/recovery re-claim paths — the per-lane poll's second job — are therefore **triply redundant**: (1) the lane task parks on `mark_failed`'s returned `next_attempt_at` and the dispatcher arms an exact `call_later`; (2) the sweep's head-due timers cover re-pends this runner never saw; (3) the sweep's due-scan floor bounds any lost timer/wake at ≤ `pooled_sweep_interval` — at or better than today's ≤ 0.25 s precision.

### 4.5 Lane serializer (strict order by construction)

The state machine permits **at most one outstanding claim-or-processing episode per lane** (claim only from READY; dispatch only on a claim result; next claim only after `lane_done`/park/stop). Per-lane processing is therefore serial → per-lane downstream handoffs commit serially → **ADR 0059's one-serial-writer-per-(stage,lane) invariant holds**: the pooled claimer is many lanes' single logical consumer, time-multiplexed — never a second concurrent writer into any lane.

`submit(lane, items)` spawns an **ephemeral per-lane task** (live task count = lanes with in-flight work) iterating the claimed prefix strictly oldest-first, fully resolving item K before K+1 (ADR 0058's in-batch head-of-line; no in-batch concurrency). Each item runs the **shared per-item body** extracted verbatim from today's loops (§5 "code motion"): `_process_ingress_item` (missing-inbound guard :2012–2024, G6 attempts ceiling :2025–2047, `run_contexts`, `route_only` via `to_thread`, the **full ADR 0057 fused branch** :2075–2138, split `route_handoff` + ROUTED wake :2171–2181, STOP/CONTINUE internal-error policy :2140–2169, the 1 s-rate-limited buildup depth check :2182–2189 — moved inside the lane task at the same rate limit, zero idle store traffic added), `_process_routed_item` (transform + lookup ExitStack, `transform_handoff`, OUTBOUND fan-out + PT cross-lane INGRESS wakes), `_process_delivery_item` (connector re-resolve, `is_leader` re-check, simulate suppression, send, NAK/DeliveryError policy branches, `complete_with_response` + RESPONSE cross-lane wake / `mark_done` / `mark_failed` / `dead_letter_now`), `_process_response_item` (`ingress_handoff` + INGRESS wake). `to_thread` hops and no-txn-across-the-hop (G4/G5) live inside the shared bodies, unchanged. Each body returns an `ItemOutcome` that the per_lane loops translate to today's `return`/`continue` control flow and the lane task translates to state transitions:

- **All items resolved** → `lane_done` → IDLE (+READY if dirty).
- **Retryable failure at item K** (`mark_failed` re-pended with future `next_attempt_at`) → `release_claimed(remaining tail ids)` (attempts restored — never processed out of order, never inflated) → `PARKED(until = returned next_attempt_at)` + exact timer. Restart semantics: a process restart discards PARKED state; seed-all-READY claims EMPTY on the not-due head → IDLE, and **the sweep's head-due timer is the sole re-claim path for previously-parked lanes after restart** (asserted in the crash-replay test).
- **Dead-letter CONTINUE** → row terminal, keep processing the tail (the lane legitimately advances, as today).
- **STOP policy / missing-inbound retry-forever** → `release_claimed(tail)` + `STOPPED` + `connection_stopped` alert — the pooled analog of "worker returns and stays down"; the reload/`start_inbound` re-arm flips STOPPED → READY. (Strictly safer than today's leave-tail-INFLIGHT-until-restart, ADR 0058 INV-3: an explicit attempts-neutral release is FIFO-neutral and immediately recoverable.)
- **Unexpected lane-task exception** → release tail, log, re-arm via a 1.0 s delayed timer (per-lane parity with `_WORKER_ERROR_BACKOFF_SECONDS`); the claimer and sibling lanes are untouched.

**Backpressure and bounded memory:** the slot budget (`pooled_max_processing_lanes`, default 256/stage) gates chunk **assembly** — the claimer never claims what it cannot dispatch, so excess work stays PENDING in the store: queue depth stays visible to buildup/stall alerts and `/stats` (count-and-log intact), crash exposure is bounded (fewer inflight rows), and a saturated stage degrades to store-buffered, never memory-buffered. Global decrypted-body bound = slots × per_lane_limit (≤ 64) per stage; READY/PARKED lanes hold zero bodies. Slot saturation surfaces as a `/stats` gauge + AlertSink event.

**Low-lane-count degradation** (the single-interface ~60 msg/s bound must not regress): a wake claims immediately (no sweep dependence on the hot path); the SQL Server pooled claim is **1 execute + 1 commit — the same wire-op count as `claim_next_fifo`** (§3.3) and the PG claim is statement-count parity (§3.4), so the serial 7-RT-per-message chain is structurally unchanged modulo one in-process `create_task` hop (µs); per-lane prefixes keep the B2 `fifo_claim_batch=8` commit amortization. Idle floor: ≤16 read RT/s total vs 4 locking claims/s per worker today — strictly cheaper even at N=1. The single-interface ladder is a **hard perf gate** (§8) rather than an assumption. **Unordered (`ordering=unordered`) outbound lanes** keep the existing per-lane `claim_ready` worker path in either mode (rare under FIFO-always; READPAST-skip is intended there; poolable in a follow-up — documented residual).

---

## 5. Flag, knobs, and the byte-identical default

`[pipeline].claim_mode: Literal["per_lane", "pooled"] = "per_lane"` (config/settings.py `PipelineSettings`, beside `per_lane_wake` :640), env `MEFOR_PIPELINE_CLAIM_MODE`, **reliability-core, read once at engine construction** — a `/config/reload` does not toggle it (restart to change; `per_lane_wake`'s exact contract), threaded through both Engine entrypoints to the `RegistryRunner` ctor.

Pooled-only knobs under `[pipeline]`: `pooled_claimers_per_stage` (default 1; hash-partitioned lane→claimer when >1), `pooled_sweep_interval` (default 0.25 s), `pooled_claim_lane_chunk` (default 256, hard cap 500; SQLite clamp 200), `pooled_max_processing_lanes` (default 256 per stage). `[store].fifo_claim_batch` keeps its meaning in both modes (pooled: the ingress/routed `per_lane_limit`). Startup logs: pooled+`per_lane_wake=true` → "subsumed"; pooled on SQL Server verifies RCSI and **fails closed** if off.

**Byte-identical default, enforced:** with `per_lane`, the runner spawns exactly today's worker topology, runs the same claim SQL (`claim_next_fifo`/`_batch`/`claim_ready` untouched), and constructs **zero pooled objects** — a test sentinel asserts no dispatcher/claimer/sweep/timer/slot attribute is instantiated when the flag is unset. The only default-path code changes: (a) extracting the four worker-loop bodies into the shared `_process_*_item` methods — pure code motion, called in place by the per_lane loops, guarded by the full suite as the identity proof; (b) `mark_failed`'s additive return value, ignored by per_lane callers (and independently useful to the Phase-0 retry-decouple).

---

## 6. Interaction matrix

- **B2 / ADR 0058 (batch claim):** **absorbed, not superseded.** `claim_fifo_heads`' per-lane contiguous-due prefix reproduces INV-1..7 (same `fifo_claim_batch` knob; empty-prefix-on-not-due-head == single-claim `None`; strictly-serial in-prefix iteration; post-increment attempts; poison-drop keeps tail order; outbound/response never batched). Pooled *additionally* amortizes the claim commit **across lanes** (one txn per ≤256 lanes) — the axis that matters at 1,500 lanes. The a7f2172 `fifo_claim_batch=8` guidance carries over unchanged in meaning; deep-backlog hot-few-lane regimes keep their amortization in **both** modes.
- **B12 / ADR 0061 (per-lane wake):** subsumed in pooled mode — `mark_ready` is per-lane precision by construction; the sticky-Event-never-replace law maps to sticky ready-set membership + create-or-stick unknown keys. ADR 0061's non-negotiable poll backstop survives as the 0.25 s clock-driven sweep — bounded, never removed. All producer call sites (listener pre-AA, `route_handoff`, fused fan-out, `transform_handoff` OUTBOUND + PT cross-lane, `complete_with_response`→RESPONSE, `ingress_handoff`→INGRESS) are signature-unchanged.
- **ADR 0057 (inline fast path):** intact — the fused route+transform+handoff body lives inside the shared `_process_ingress_item`; per-lane serialization holds across the fused body; G1 error routing maps to CONTINUE/STOPPED outcomes; G4/G5 preserved (the claim txn commits and releases before dispatch; handoff opens fresh); G6 reads the claim's post-increment attempts (OUTPUT/RETURNING/re-SELECT — spec'd per backend); fused per-destination OUTBOUND wakes fire through `_wake_lane` into the OUTBOUND dispatcher. `_recompute_inline_ok` and `store.handoff` untouched.
- **Finalizer:** **untouched** — `_maybe_finalize` only in the H2 twin, same txn, same caller class as today's claims; `sp_getapplock`/advisory/global-lock single-authority preserved. Acknowledged as the bench-predicted next wall on the rate-walk; explicitly out of scope.
- **`reset_stale_inflight` reachability:** store-side unchanged; engine `start()` still resets before `runner.start()`. Pooled: seed-all-READY at start + immediate first sweep; clustered promotion re-seeds; PG's in-claim stranded-head reclaim (now lane-array-scoped, same txn, FIRST) covers mid-life failover per lane; the sweep is the unconditional ≤0.25 s backstop; engine nudges `notify_work()` after mid-run recovery ops.
- **`mark_failed` retry re-claim:** the additive return feeds exact park timers; the sweep's head-due timers cover foreign re-pends; the due-scan floors everything at ≤0.25 s. Head-of-line preserved: a not-due head empties the lane at STEP 2 (candidates are min-seq regardless of due-ness).
- **N-active forward-compat:** the explicit lane set **is** the ownership seam (a coordinator assigns lane subsets; each node's dispatchers pass owned lanes to both `claim_fifo_heads` and `list_fifo_lanes` — a config/coordinator change, not a store-shape change). PG already stamps owner+lease per claimed row; SQL Server keeps `owner=NULL` parity with the columns present; the H1 epoch guard is appended verbatim to the probe **and** the UPDATE, so a fenced ex-leader claims 0 rows across all lanes in one shot.
- **Count-and-log + ACK-on-receipt:** untouched — listener commit/wake/AA ordering, NAK-before-ingress, and disposition recording live outside the claim/dispatch machinery; backpressure is claim-gated so true depth stays store-visible.

---

## 7. Consequences

**Positive:** claim sessions collapse ~4,500 → ≤ K×4 (default 4); idle claim RT ~18k/s → ≤16 read-only RT/s; loaded claims self-coalesce into multi-lane statements from a handful of sessions; zero claimer lock-waits (no pinned pool connections); claimer-vs-claimer conflict structurally zero; bounded memory + store-visible backpressure; recovery/retry latency at or better than today; the primitive is shard-scoped and N-active-ready.

**Negative / accepted:** (1) the one-consumer-per-lane invariant moves from "one task per lane" into the dispatcher state machine — a dispatcher bug re-opens FIFO breaks no SQL guard catches; mitigated by a small, exhaustively unit-tested state machine, T6-pooled tripwires, a debug assertion that a claimed lane had no in-process items, **and the §8 merge rider that the PR3 dispatcher tests + the T6/#285/fan-in pooled tests are green on the live SQL Server *and* Postgres CI legs (not SQLite-only) as the price of merging the PR that first builds the dispatcher**. (2) RCSI is **fail-closed by default** on SQL Server (overridable via `[pipeline].require_rcsi_for_pooled`) — retained not because the claim still needs it to avoid blocking (`SET LOCK_TIMEOUT 0` makes the claim *and* the sweep structurally never-block) but because the §3.2 correctness proofs + §8 CI gates are scoped to RCSI-on. (3) SQL Server fan-in lanes shift to PG visibility semantics (§3.2 disclosure; per-source order preserved; doctrine-sanctioned; **adjudicated accept, §11 item 5**). (4) With K=1 a claimer store-error backoff pauses a stage's claiming ~1 s (chunk-scoped handling + supervision + a starvation alert bound it; raise K to isolate). (5) Two claim architectures persist until a convergence decision — an **accepted, bounded, exit-defined cost, not a migration-in-progress**. **Update (2026-07-03, #744): the default was flipped to `pooled`** (rate-walk resilience GO + reinterpreted §8.12b + row-1b fan-in soak PASS; §11 item 10); `per_lane` is now the **byte-identical opt-out** (still enforced by the zero-pooled-construction sentinel), and pooled is documented + recommended to operators. Both code paths still ship until a convergence decision retires one — the double test surface is the remaining price. (6) The refactor touches the most reliability-critical file — contained by extract-only commits and the per_lane full-suite identity gate. (7) Known next walls, unblocked not caused: finalizer applock serialization; outbound connect-per-delivery TIME_WAIT — watched on the rate-walk so they are not misattributed. (8) A discovery/claim race with an admin op costs one wasted cycle (EMPTY), re-check-resolved — accepted, PG parity.

---

## 8. Acceptance criteria / test gates (all rows per-backend — SQLite in-proc, Postgres service leg, SQL Server CI leg — × claim_mode where meaningful; correctness gates run BEFORE any throughput leg, per FIX_RECOMMENDATION)

> **Merge rider (§11 item 9a, adjudicated 2026-07-02):** rows **1a / 1b / 1e / 1f** (T6/#285/fan-in
> locked-head) and row **5** (dispatcher state machine) are **MERGE-BLOCKING on the live SQL Server
> *and* Postgres legs — not SQLite-only** — for the PR that first constructs the `StageDispatcher`
> (PR3). Row **1b** must include the multi-writer fan-in soak (committed N+1 claimable; writer A's
> later-committed N claimed on the next pass; per-inbound order intact) — its PASS also gates the
> §11-item-10 default flip. The paid §8.12b bench is a **default-flip** gate, not a merge gate.

1. **#285/T6 under pool (the hard gate; real SQL Server RCSI on, and Postgres):**
   a. **True T6 schedule:** committed N, N+1, N+2 in one lane; an external txn X-locks N → `claim_fifo_heads` returns **EMPTY** for the lane (never `[N+1, N+2]`); claim completes in ms (no lock-wait; pool acquire-wait flat); after release, N is claimed first.
   b. **Uncommitted producer head** (single-writer lane / no committed successor): lane EMPTY-or-earlier-head while the insert txn is held; after commit the next claim returns N. Multi-writer fan-in variant asserts the **documented** semantics: committed N+1 claimable; writer A's later-committed N claimed on the next pass; per-source order end-to-end intact under a randomized soak.
   c. **Multi-lane isolation:** lane A's head locked, lane B free → one call returns B only.
   d. **Backing-off head:** head not-due + due N+1 behind it → lane yields nothing.
   e. **Mid-prefix gap:** lock held on a mid-prefix candidate → only the contiguous head prefix claimed; **gap-tail rows never updated** (status pending, `attempts` unchanged — probe-then-claim assertion).
   f. **Attempts-neutrality under a wedged head:** hold the head lock across 60 s of sweep cycles → tail `attempts` unchanged, nothing dead-letters (no G6 inflation).
   g. Existing T6 re-run in **both** claim modes.
2. **At-least-once / crash replay:** kill after claim-commit before handoff at **each** stage (inline + split paths) → restart → `reset_stale_inflight` → seed-all-READY → re-claimed in seq order and re-run idempotently (handoff DELETE-guard no-op); crash mid-prefix → tail INFLIGHT → re-pended → re-claimed in order; zero loss, zero duplicate next-stage rows, dispositions correct. Re-run the #283 two-node SIGKILL-under-load failover harness with `claim_mode=pooled`; per-lane FIFO stays the hard gate; PG variant proves the lane-array stranded-lease reclaim preserves failover FIFO (expired-lease mid-lane head re-pended before the head SELECT → N delivered before N+1).
3. **Retry schedule:** `mark_failed`(backoff) on an otherwise-idle lane → redelivered within backoff + timer slack; with the park timer fault-injected off, within backoff + sweep interval; the Phase-0 gate — a 30 s partner outage on an idle lane **still delivers**. H2: a delivered-then-re-pended outbound row is completed in-claim-txn, never re-sent, and its lane re-arms via `rearm`.
4. **Backstop under load (clock-driven sweep):** sustained cross-lane wake traffic at target rate + one claim-race-dropped ready entry → row re-claimed within `pooled_sweep_interval` + slack.
5. **Dispatcher state-machine unit tests:** no double dispatch; claim-only-from-READY; **wake-during-CLAIMING sets dirty and EMPTY+dirty → READY (immediate re-claim, no sweep dependence)**; **wake-before-lane-registration creates-or-sticks**; park/unpark; PARKED-discarded-on-restart (sweep-timer re-claim); STOPPED re-arm on reload; slot reservation/release exactness; teardown; a soak asserting the busy-violation counter == 0 across 200 randomized lanes.
6. **Sharding (mandatory today):** 2 runners, disjoint lane sets, one store → every claimed row's lane ∈ the claiming engine's set; neither engine's sweep readies the other shard's lanes; foreign-lane `attempts` untouched.
7. **H1 fencing pooled:** a paused ex-leader's pooled claim matches 0 rows across all lanes (probe and UPDATE guards).
8. **Fan-out finalize:** multi-handler skewed-speed graphs → PROCESSED/FILTERED/ERROR flip only after every sibling resolves (existing finalizer tests re-run pooled); the harness disposition-coverage graph × 3 backends × both modes (all dispositions reachable; loopback RESPONSE + PT re-ingress cross-lane wakes land in the pooled ready sets; depth-cap respected).
9. **Inline-under-pool:** inline=on graph through pooled — fused 5-commit chain taken; M-gate fallbacks; G1 STOP/CONTINUE; G6 dead-letters a poison-crash item at the ceiling using post-increment attempts (per backend).
10. **Byte-identical opt-out (post-#744):** the default is now `pooled`, so the full existing suite runs green under `pooled`; the byte-identical guarantee is re-anchored to the **explicit** `per_lane` opt-out — `test_explicit_per_lane_constructs_zero_pooled_objects` (the zero-pooled-construction sentinel, pinned to `claim_mode="per_lane"`) plus `test_default_mode_constructs_pooled_dispatchers` (the inverted default sentinel); `test_staged_pipeline.py` (the reliability suite) parametrized `claim_mode × backend`.
11. **Plan assertion (SQL Server leg, advisory):** discovery CROSS APPLY seeks `ix_queue_fifo_*_seq` per lane (attach FORCESEEK if it ever flattens — perf-only; correctness is plan-independent by the ID pin).
12. **Perf gates:** (a) single-interface ladder — **hard gate**: pooled within ±5% of per_lane's ~60 msg/s warm e2e; connscale monotonicity SLO stays green (0.25 s sweep = parity, no re-baseline). (b) Bench re-validation per HANDOFF: reset → 2-engine, 1,500 lanes, 525/s, 300 s hold → PASS = flat `in_pipeline`, delivered/offered ≥ 0.98, pool.idle recovered, bounded acks, idle+loaded store signals collapsed (CPU ≪ 92%, idle_poll ~0, PAGELATCH/LCK_M_U at noise); then rate-walk +100/s watching the finalizer applock and outbound TIME_WAIT (the named next walls).

---

## 9. Rejected alternatives

- **NOLOCK double-view head agreement (design B's SQL Server primitive):** every enumerated single-view anomaly fails closed, but the compound class (X-locked committed head + a simultaneous NOLOCK allocation-scan miss of the same row) yields agreement-on-N+1 — vanishingly rare, untestable-to-absence. The snapshot-discovery + ID-pin achieves the same EMPTY contract with zero dirty-read machinery. (If the probe-then-claim ever failed validation, a `SET LOCK_TIMEOUT 0` per-lane fallback behind the same signature is the documented swap.)
- **Claim-then-release contiguity (design A's original):** releasing post-gap rows inflates `attempts` on never-dispatched rows (G6 hazard under a wedged head + sweep) and needs an explicit txn per stage; probe-then-claim never updates non-kept rows.
- **All-lanes-of-stage server-side claim:** breaks disjoint-inbound sharding today and busy-lane exclusion (a busy lane's head claimed server-side = a second concurrent consumer + attempts churn).
- **Timeout-gated sweep inside the claimer loop:** starves the at-least-once backstop under sustained wakes; the clock-driven independent task is mandatory.
- **Removing the backstop entirely / event-only:** rejected by ADR 0061 and re-rejected here — `mark_failed`/recovery would have no bounded re-claim path.

## 10. Design-review traceability (adversarial-gate required changes → sections)

This ADR synthesizes two independently authored designs ("A" store-first, "B" runner-first) that were
each put through three adversarial verification gates (strict per-lane FIFO/#285; at-least-once +
crash recovery; interactions + performance). Every gate-required change is integrated above; the map
below records which finding landed where (labels are the review's own).

Gate 1 (FIFO/#285): A1 head-pin → §3.2 STEP 4 + test 1a; A2 attempts-restore → obsoleted stronger by probe-then-claim (§3.2 STEP 4, tests 1e/1f) + `release_claimed` attempts-undo (§3.1); A3 atomicity → single txn all stages (§3.2); A4 fan-in semantic disclosure + scoped tests → §3.2 + test 1b; A5 dirty-on-CLAIMING + head-due-aware discovery → §4.2/§3.6; B1 PG head-agreement pin → §3.4 `keep` CTE; B2 hardened validation/fallback → §9 + test 11; B3 mark_failed return → §3.1; B4 mid-claim wake re-add → §4.2 dirty bit.
Gate 2 (at-least-once/recovery): A1 → §4.2; A2 create-or-stick → §4.2 + test 5; A3 PARKED-restart semantics → §4.5 + test 5; B1 registry intersection today → §3.1/§4.4 + test 6; B2 clock-driven sweep → §4.4 + test 4; B3 → §3.1; B4 `rearm` in the return shape → §3.1/§3.2 STEP 6.
Gate 3 (interactions/perf): A1 → §4.2 + test 5; A2 single-round-trip fusion + hard ladder gate → §3.3/§3.4/§4 low-N + test 12a; A3 parameter bound → §3.3 (IDs never parameterized; chunk clamp); A4 sweep 0.25 s → §4.4; A5/A6 ADR disclosures → §3.2/§3.1; B1 → as gate-2 B1; B2 → §9/test 11; B3 hot-lane amortization → §6 B2 row (absorbed, both modes); B4 chunk-assembly wake semantics → §4.2/§4.3 + test 5.
## 11. To resolve on acceptance (recommended answers in bold)

> **Items 5, 6, 9, 10 were adversarially adjudicated 2026-07-02** (steelman-both-sides + independent judge, high/medium confidence, all reversible-easy) and are now **DECIDED** as recorded below — the rulings are folded into §3.3 / §7 / §8 above. Items 1–4, 7, 8 keep their recommended defaults.

1. **Claimers per stage (K):** default **K=1** (at 525 msg/s the claim traffic is ~12–50 RT/s — far
   below one task's capacity; a claimer store-error backoff pausing one stage's claiming for ~1 s is
   an acceptable, alert-surfaced blast radius). `pooled_claimers_per_stage` exists for the bench to
   A/B K=2.
2. **Sweep cadence:** default **0.25 s** (`poll_interval` parity — no worst-case latency regression,
   no connscale-SLO re-baseline). A 1 s near-zero-idle-floor variant would require re-baselining the
   connscale monotonicity SLO in the same PR — not worth coupling.
3. **Processing-slot sizing:** **one flat `pooled_max_processing_lanes = 256` per stage** for v1;
   per-stage character sizing (ingress/routed executor-bound vs outbound I/O-bound) is a follow-up
   knob only if the slot-saturation gauge shows a real skew.
4. **Unordered outbound lanes:** **stay on the existing per-lane `claim_ready` workers in v1**
   (rare under FIFO-always; documented residual per-lane claim loops). Folding them into the
   dispatcher is a follow-up.
5. **SQL Server fan-in visibility shift: DECIDED — accept documented** (§3.2). Postgres-parity
   snapshot semantics on multi-writer `destination_name` lanes; doctrine-sanctioned ("no honored
   cross-inbound receive order", `wiring_runner.py:1231–1233`), per-source order preserved by the
   one-serial-writer invariant; exact parity with the shipped Postgres `FOR UPDATE SKIP LOCKED`
   claim. Block-until-commit parity would reintroduce claimer lock-waits, defeating the mandate. The
   PR-blocking T6 gate is a single-writer INGRESS lane and encodes no cross-writer block-until-commit
   promise, so accepting this does **not** walk back #285. **Arming condition (gates the *default
   flip*, not this acceptance):** the §8 row 1b multi-writer fan-in soak must PASS on a real
   SQL Server RCSI-on leg (committed N+1 claimable while writer A's later-committed N is claimed on
   the next pass; per-inbound order end-to-end intact under a randomized producer/claimer soak). If a
   future adopter fan-in feed needs cross-inbound merge ordering, the answer is **source-side
   sequencing** (FIFO-always doctrine), never re-introducing a block-until-commit claim.
6. **RCSI fail-closed: DECIDED — keep fail-closed by default, overridable.** Pooled on SQL Server
   refuses to start if `is_read_committed_snapshot_on = 0` (DBA remediation text), overridable via
   `[pipeline].require_rcsi_for_pooled=false` (loud warning + a `/stats` `rcsi_off_degraded` gauge +
   AlertSink event). **Corrected rationale (§3.3):** the `SET LOCK_TIMEOUT 0` guard on the claim
   *and* the sweep already make the pooled path structurally never-block *independent of RCSI*, so
   fail-closed is **not** retained on non-blocking grounds; it is retained because the §3.2
   correctness proofs and the §8 CI gates are scoped to RCSI-on snapshot visibility and
   READ-COMMITTED discovery semantics are unverified. No-op on the SQL Server deploy target (RCSI is
   force-enabled at open where permitted).
7. **Phase-0 disposition:** **resolved** — the Phase-0 idle backstop + armed retry wake shipped as
   the ADR 0061 amendment (PR #732) ahead of this ADR; the two compose (Phase-0 relieves idle,
   pooled removes the loaded convoy).
8. **ADR number:** **0066** (this file).
9. **Bench gating: DECIDED — split into a merge gate and a default-flip gate** (the paid bench does
   *not* block the merges):
   - **9a — Merge gate:** PR2/PR3/PR4 land behind `claim_mode` default=`per_lane` once the §8 rows
     1–11 are **green on the SQLite in-proc + Postgres service + SQL Server CI legs**. The merge is a
     proven no-op for the shipped default (the zero-pooled-construction sentinel, §5). The paid
     2-engine / 1,500-lane bench is **NOT** a merge precondition. **Merge rider:** the §8 row 5
     dispatcher state-machine tests and the §8 rows 1a/1b/1e/1f T6/#285/fan-in pooled tests must be
     green on the **live SQL Server *and* Postgres** legs (not SQLite-only) for the PR that first
     constructs the `StageDispatcher` (PR3) — that is where the one-consumer-per-lane invariant leaves
     the SQL guard and becomes application code (the SS segfault proved gated tests hide real bugs).
   - **9b — Default-flip gate: DONE (2026-07-03, #744).** `claim_mode` default flipped to `pooled`
     and recommended in `CONNECTIONS.md` / `SYSTEM-REQUIREMENTS.md`. The gate cleared on the
     **reinterpreted** basis (§11 item 10): the paid §8.12b 525/s target was reconciled as a
     target-vs-capacity mismatch (not a pooled resilience FAIL), the rate-walk GO'd the flip on
     single-node resilience grounds, and the §8 row-1b fan-in soak PASSED on live SS+PG.
   Operator-coordinated on the instance-store rig (aws-bench ops notes); run while the rig is warm.
10. **Convergence: DECIDED — data-gated, and the flip is now DONE (2026-07-03, #744).** The
    flip-to-default decision was taken with data: the §8.12b bench was **reinterpreted** (its 525/s
    "FAIL" was a target-vs-capacity mismatch — 2 engines cap ~250–300/s, the ~120–150/s per-engine
    wall is engine-internal, not a pooled fault — so it is **not** a resilience failure), the
    **rate-walk** GO'd the flip on single-node resilience grounds (pooled collapses the claim storm
    and holds zero-loss at high fan-out where `per_lane` DROPS messages), and the decision **cites the
    §8 row-1b fan-in soak PASS on live SS+PG by name** (so the SQL Server fan-in visibility shift did
    not reach default silently). **`pooled` is now the default; `per_lane` becomes the byte-identical
    opt-out** (`[pipeline].claim_mode = "per_lane"`), still shipped and sentinel-guarded. Remaining
    scope caveat: the flip evidence is **single-node** (`NullCoordinator`) — failover
    duplicate/ordering paths are unmeasured, tracked as the T17 infra-fault limitation under ADR 0070;
    and exactly-once still degrades under load (no inbound de-dup; the idempotent-receiver contract
    contains it). A follow-up convergence decision may later retire `per_lane`, but that is a separate
    ticket — this item records only the default flip.
