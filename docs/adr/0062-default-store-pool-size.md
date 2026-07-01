# 0062 — Set the default server-DB store connection pool size to 40 (inverted-U optimum)

- **Status:** Accepted
- **Date:** 2026-07-01
- **Related:** [ADR 0037](0037-multi-process-sharding-l3.md) (sharding — the connection-scale regime) · [ADR 0063](0063-no-split-store-unified-store-for-sharding.md) (no split store — one unified store) · [ADR 0053](0053-free-threaded-multicore-engine.md) (multicore direction) · [ADR 0052](0052-enterprise-scale-target.md) (enterprise scale target) · B11 connection-scale harness (#675) · [docs/throughput-build-plan.md](../throughput-build-plan.md) (B13) · [docs/DEPLOY-SERVER-DB.md](../DEPLOY-SERVER-DB.md) §3 · CLAUDE.md §2 (staged pipeline, at-least-once)

---

## Context

The staged pipeline commits every stage handoff durably to the store, and the per-inbound router/transform
workers + per-outbound delivery workers run concurrently against **one shared connection pool per engine
process** (`[store].pool_size`, `messagefoundry/config/settings.py`). The default was **5** — sized for
*tens* of connections.

Three bench sweeps (SQL Server 2022, ephemeral NVMe, 8-vCPU box, cheap pass-through transform, 12–15 msg/s
per interface) established the shape of the pool lever:

1. **Single interface (B13 bracket): FLAT.** One strict-FIFO lane is a single serial delivery worker; it
   can't saturate even pool=5, so pool size does nothing. The lever's regime is **connection scale** (many
   interfaces on one engine), not single-interface throughput.
2. **Connection scale, N ≤ 32 × pool ≤ 20 (connscale): HELPS, monotone.** Acquire-wait first bites at N ≈ 8;
   5 → 10 → 20 cut acquire-wait + ACK latency.
3. **Higher N (16/32/48/64) × higher pool (20/40/80/160): an INVERTED-U — the definitive result.** The pool
   helps only up to ~40; **over-provisioning a single engine's pool is catastrophic.** ACK p99 (ms):

   | N  | pool 20 | pool 40 | pool 80 | pool 160 |
   |----|---------|---------|---------|----------|
   | 16 | 732     | **410** | 13,296  | 13,839   |
   | 32 | 4,606   | **2,967** | 24,227 | 51,806   |
   | 48 | 32,704  | **22,816** | 29,006 | 138,039 |
   | 64 | 46,876  | 63,276  | **30,799** | 140,828 |

   (N ≥ 48 is past the single-engine delivery knee — those cells fail zero-loss on *every* pool and partly
   reflect collapse dynamics, not sizing.)

**Why over-provisioning hurts (source-grounded, `sqlserver.py`):** past the useful concurrency (~one serial
writer per `(stage, lane)`), extra pooled connections add **zero** throughput and pile onto the **one shared
SQL instance** — every handoff/mark_done/ingress-ACK is a durable log flush that WRITELOG serializes; nearly
every closing commit takes an Exclusive `mefor:finalize:{id}` applock (an extra serialized round-trip); plus
page/row latches on the hot `queue` table + FIFO indexes. Engine **CPU drops** as the pool grows (29 → 12 %),
because the asyncio workers are `await`-suspended on slow SQL round-trips — a **latency/contention wall, not a
CPU wall** (B5 executor-split is therefore not indicated). At pool 160 the engine opens ~160 SQL sessions but
`idle_min` ≈ 160 — only ~15 are useful; the rest are pure contention. Concurrent connection demand ≈ 2.5 × N
interfaces.

This is a pure default change; it must **not** break the reliability invariants (CLAUDE.md §2 — at-least-once
/ per-lane FIFO / finalizer authority are untouched; the pool only governs concurrent in-flight store ops).

## Decision

**Set the default `[store].pool_size` to 40** (from 5) — the measured inverted-U optimum, **not higher**.

- **Server-DB only.** SQLite uses a fixed 4-connection read pool + a single writer and **never reads
  `pool_size`**, so this is a true no-op there.
- **Only the unset default moves.** Any explicit `[store].pool_size` / `MEFOR_STORE_POOL_SIZE` is unchanged;
  `pool_size` is a bare `int` (no `Field`/validator), so any value ≥ 1 still loads.
- **Cluster floor untouched** — the `[cluster].enabled` → `pool_size ≥ 2` validator is trivially satisfied.
- **Why 40 — and firmly NOT higher:** 40 is the measured optimum across the working N range (16–32) and a
  strict improvement over 20 (~1.5–1.8× lower ACK). Over-provisioning is **catastrophic** (the cliff is at
  80: ACK explodes 30–90×), so a larger default would actively harm. The risk is **asymmetric** —
  under-provisioning is a mild slope, over-provisioning falls off a cliff — so the default sits *at* the
  optimum with the cliff a full 2× above it. The common deployments fit the connection budget: a single node
  is 1 × 40; an active-passive pair is 2 × 40 = 80 (< the Postgres default `max_connections` ≈ 100).

## Acceptance Criteria

- **AC-1** — WHEN `[store].pool_size` is unset, THE SYSTEM SHALL default it to `40`.
  → `tests/test_settings.py::test_default_pool_size_is_40`
- **AC-2** — WHERE an explicit `[store].pool_size` (file) or `MEFOR_STORE_POOL_SIZE` (env) is set, THE SYSTEM
  SHALL use that value unchanged (env over file over default).
  → `tests/test_settings.py::test_explicit_pool_size_overrides_default`
- **AC-3** — WHERE `pool_size = 40` and `warm_pool_target` is unset, THE warm-target resolver
  `warm_pool_target(40, None)` SHALL return `20` (the startup pre-open count per server-DB engine).
  → `tests/test_settings.py::test_warm_target_at_new_default`
- **AC-4** — IF `[cluster].enabled` with `pool_size = 1`, THEN THE SYSTEM SHALL refuse to start; AND the
  default (40) SHALL satisfy the `≥ 2` floor.
  → `tests/test_settings.py::test_cluster_floor_and_default_pool`

## Options considered

1. **Default 40.** **CHOSEN** — the measured inverted-U optimum; strict improvement over 20 with a 2× margin
   below the catastrophic cliff.
2. **Default 20 (or 10).** Rejected — measurably below the optimum (~1.5–1.8× worse ACK at N=16–32) with no
   compensating safety benefit; the cliff is far above.
3. **Default 80 / 160 (match peak concurrent demand).** Rejected — **catastrophic**: extra connections thrash
   the one shared instance (WRITELOG + applock + latch contention), collapsing ACK latency 30–90×. "Bigger is
   better" is false here.
4. **Auto-scale the pool toward the connection/interface count.** Rejected — that drives *toward* the cliff;
   the useful concurrency (~40) is well below peak demand (~2.5 × N).
5. **Leave 5.** Rejected — provably undersized at connection scale.

## Consequences

**Positive** — the measured connection-scale optimum ships by default for Postgres/SQL Server; self-observing
via the existing B11 `/status` pool surface (`pool_status()` → `PoolInfo`/`PoolWaitInfo`).

**Negative / risks**
- **~8× steady-state DB sessions/backends per server-DB engine** (5 → 40).
- **Startup warm burst 2 → ~20 connections/engine** (`warm_pool_target(40, None) = 20`), bounded by
  `warm_pool_timeout`, background/off-intake, self-releasing, never raises. Pin `warm_pool_target` or set
  `warm_pool = false` on a connection-/license-constrained site.
- **Connection-budget ceiling (the #1 deployment caution):** `pool_size` is **per engine**. Under the
  no-split-store rule ([ADR 0063](0063-no-split-store-unified-store-for-sharding.md)) every engine that
  connects — multi-process shards (all on the *same* database) and the active-passive standby — counts against
  **one** `max_connections`. Budget peak ≈ engines × `pool_size`, so at 40 only ~2 co-located engines fit
  under a Postgres default of ~100 (vs ~5 at 20): a config that connected at 5 **can fail to connect at 40**.
  At real fan-out (the ~47-shard 1500-interface case) this needs a raised `max_connections` + a pooler
  (PgBouncer), or SQL Server (more sessions) — **not** a smaller default and **not** a split store. Documented
  in [DEPLOY-SERVER-DB.md](../DEPLOY-SERVER-DB.md) §3 + [CLOUD-DEPLOYMENT.md](../CLOUD-DEPLOYMENT.md).
- **Over-provisioning is a footgun** — setting `pool_size` far above ~40 (or above ~interfaces × 2.5) degrades
  a shared store. A soft startup warning is a recommended follow-up (not built here); the docs carry the
  guidance meanwhile.

**Refuted / re-scoped by the higher-N sweep**
- **"Raise the pool to reach ~1500 connections" is refuted.** One engine caps out well below it; 1500 is a
  **sharding** problem (ADR 0037: ~47 engines × ~32 interfaces, each with a *modest* pool ~40), not a
  pool-sizing one.
- **A residual per-engine wall at ≥ ~48 interfaces** that no pool size fixes — the per-lane serial commit/log
  throughput. Attack it separately (B2 `fifo_claim_batch`, `OrderingMode.UNORDERED`, cheaper per-message
  finalize-applock), never by enlarging the pool.
- **The unified store is the aggregate ceiling.** Because we do **not** split the store (ADR 0063), that
  ceiling is raised **vertically** (faster storage/box — B8: one NVMe store ≈ 23,600 commits/s) and by making
  each message **cheaper** on it (fewer commits/applocks) — never by fragmenting it. Validating the one store
  under real multi-shard load is the open pre-1500 risk (ADR 0063 §risks).

**Out of scope** — the soft over-provisioning warning; B5/B6 (executor split / ingest sub-pool); the
multi-shard runtime (ADR 0063).

## To resolve on acceptance

- [x] The higher-N sweep (N 16–64 × pool 20–160) **resolved** the sizing: an inverted-U with optimum ~40.
- [ ] The optimum is **workload/hardware-specific** (SQL Server 2022 / ephemeral NVMe / cheap transform /
      12–15 msg/s). It shifts with transform cost, message size, ACK mode, disk and SQL-box sizing — treat 40
      as a well-founded default, and **re-measure for a materially different deployment shape** (the prod-
      faithful "04" real-engine run remains the confirmation for real transform/message cost).
