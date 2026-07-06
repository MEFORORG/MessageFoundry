# ADR 0064 — Schema-init fast-path (content-hash marker) + index-seekable startup recovery

**Status:** Accepted · 2026-07-02
**Amends:** the open-path behavior described in [ADR 0060](0060-rename-based-fifo-index-migration.md)
(the on-open migration still applies to upgraded DBs — via the marker's *absence or mismatch* instead
of an unconditional re-run).

## Context

Every server-DB store open re-ran the **entire guarded schema DDL batch** (dozens of
check-then-create statements, including the ADR 0060 migration statements) under an **exclusive
schema lock** (`sp_getapplock` on SQL Server, the schema advisory lock on Postgres), and then ran
`reset_stale_inflight` with a **bare `status=?` predicate that matches no index** (Postgres
additionally used an `($n IS NULL OR stage=$n)` form that is unsargable under a generic plan) —
a full scan of the `queue` table on every startup.

The WS-B multi-engine bench (WS_B_REPORT.md REVISED 2026-07-02, Finding 2) measured the consequence:
N ≥ 4 engines cold-starting against one shared SQL Server store **convoy** on the schema applock +
the recovery scan (`LCK_M_IX`/`LCK_M_X` storms in the 330–690k ms range), a loser exceeds the 30 s
lock/command timeout, and startup fails (N=16 never started). Single-engine opens pay the same DDL
round-trips and the same scan on every restart — just without the convoy.

## Decision

1. **Content-hash schema marker.** A single-row `schema_meta(id=1, schema_hash, applied_at)` table
   records the sha256 of the shipped DDL batch (`_SCHEMA`; on Postgres the hash also folds in
   `_MIGRATION_REV`, the stand-in for the `_migrate_lease_columns` Python body the hash cannot see).
   At open: probe the marker (two cheap reads, no lock — existence via `OBJECT_ID`/`to_regclass`, so
   a virgin DB probes clean); on a match, **skip the batch and the exclusive lock entirely**; on a
   miss, take the schema lock, **re-check under the lock** (a queued peer may have just applied it),
   run the full idempotent batch + migrations, and upsert the marker in the same transaction.
   Content-addressing means there is no version constant to forget: **any** edit to `_SCHEMA`
   changes the hash and forces exactly one full run per database.
2. **Index-seekable startup recovery.** `reset_stale_inflight(stage=None)` now issues one UPDATE per
   `Stage` (single transaction) with a plain `(status, stage)` equality pair — seekable on the
   existing `ix_queue_ready(stage, status, next_attempt_at)` on all three backends — instead of one
   unindexed status-only scan. Iterating the `Stage` enum keeps a future stage automatically covered
   (count-and-log: an unrecovered inflight row hangs its message forever).
3. **SQLite keeps its existing open path** (local-file DDL is cheap and has no cross-process lock
   convoy); it gets the recovery-predicate fix only.

## Consequences

- Re-opening a current database does no DDL and takes no exclusive schema lock — cold restarts and
  HA failovers get faster, and concurrent opens against one store no longer convoy on schema-init.
  (Concurrent *N-active* engines on one store remain unsupported for other reasons — the ownerless
  startup reset steals live siblings' in-flight rows; see the engine's own cluster comments.)
- **Out-of-band schema drift is no longer healed on every open.** Previously, a hand-dropped index
  was silently recreated at the next restart; now the marker asserts "the shipped batch ran" and the
  fast-path trusts it. The remedy after any manual schema surgery is `DELETE FROM schema_meta`,
  which forces one full (idempotent) run at the next open. Tests that *simulate* an old database by
  hand-editing schema objects must delete the marker too (`test_fifo_index_migration.py` does).
- **Future on-open migrations must live in `_SCHEMA`** (where the hash sees them). On Postgres, a
  behavioral change to `_migrate_lease_columns` must bump `_MIGRATION_REV` — the constant sits
  directly above the hash with that instruction.
- Upgraded (pre-marker) databases behave exactly as before on their first open — no `schema_meta`
  probes as not-current, the full batch (including any pending ADR 0060-style migration) runs once,
  and the marker is written; every subsequent open fast-paths.
- **Version skew: all engines sharing one store should run the same build.** The marker stores one
  hash, so two *different* builds alternating opens against one store (an HA pair or a multishard
  fleet mid-rolling-upgrade) each see a mismatch, re-run the full batch under the exclusive lock,
  and stamp their own hash for the peer to invalidate again — the co-start convoy returns for the
  duration of the skew window, and an ADR 0060-style rename migration in the delta would rebuild
  its index on every alternation. Not a correctness issue (every statement is existence-guarded and
  the state converges with the fleet; a downgrade to a pre-marker build is also clean, since those
  builds ignore `schema_meta`) — but expect full-batch re-runs until the fleet converges, and don't
  leave a mixed-version fleet running against one store longer than the upgrade requires.
