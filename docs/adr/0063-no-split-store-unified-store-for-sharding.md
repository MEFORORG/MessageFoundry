# 0063 — No split data store: engine sharding requires ONE unified store

- **Status:** Accepted
- **Date:** 2026-07-01
- **Related:** **amends [ADR 0037](0037-multi-process-sharding-l3.md)** (multi-process sharding) · **declines [ADR 0039](0039-database-tier-sharding-l5.md)** (DB-tier store split — stays off) · [ADR 0053](0053-free-threaded-multicore-engine.md) (free-threading = the committed multicore-on-one-store path) · [ADR 0052](0052-enterprise-scale-target.md) (enterprise scale target) · CLAUDE.md §2 (staged pipeline, count-and-log) · project memory `mf-ha-vs-sharding-terminology`

---

## Context

Engine sharding ([ADR 0037](0037-multi-process-sharding-l3.md)) partitions **inbound** connections across
N engine subprocesses (a coordinator, `messagefoundry supervise`, spawns one `serve --shard <id>` per
shard) so routing/transform parallelizes across CPU cores. Its MVP gives **each shard its own SQLite db
file** (`<stem>_<shard>.db`, `supervisor._shard_db_path`) — a **split message store**.

A split/fragmented data store is a **no-go** (owner decision, 2026-07-01): it breaks unified **reporting and
monitoring** — search, dashboards, audit, dead-letter and replay all have to span K separate databases.
This is the same fragmentation ADR 0037 §Consequences and [ADR 0039](0039-database-tier-sharding-l5.md)
already name as the funding-tier (large-IDN) pain, and it is why ADR 0039's DB-tier store split stays **declined**. It
is **not** a throughput concern — B8 measured one store at ~23,600 commits/s (~83× the 45M/day target), so a
single store has ample headroom.

This must not be confused with **HA topologies**: *active-active* / *active-passive* describe hot-standby
availability (both nodes on one shared DB), NOT sharding. Engine sharding is a coordinator + disjoint-inbound
shards on **one** store — orthogonal to HA (see memory `mf-ha-vs-sharding-terminology`). The `#396` removal
of "active-active" (multi-node concurrent per-lane draining) does **not** bear on this decision.

## Decision

**A multi-shard deployment must share exactly ONE unified store; the per-shard store split is disallowed.**

- **Guard (built here):** `require_unified_store` (`pipeline/sharding.py`), called by
  `discover_shard_specs`/`supervise`, **refuses `>1` distinct shard when `[store].backend` is SQLite**
  (SQLite cannot be a shared multi-writer store across processes). It raises with a message pointing at a
  server-DB backend. Mirrors the existing `[cluster]` → server-DB rule (`_cluster_requires_server_db`).
- **Server DBs already unify:** `serve --shard` passes `--db <path>`, which only sets the *SQLite* path — a
  Postgres/SQL Server backend connects via `server`/`database`, so every shard already points at the **same**
  database. Multi-shard on a server DB is therefore permitted and store-unified by construction.
- **A single shard (or an untagged config) is unaffected** — one process, one store, byte-identical to plain
  `serve`. SQLite stays fully supported for the single-engine (non-sharded) case.
- **Amend, don't supersede, ADR 0037:** the store-agnostic sharding surface stays (the `shard=` tag,
  `serve --shard`, per-shard API ports, `filter_registry_for_shard`, the multi-shard console/fleet tier, the
  harness driver). Only the **SQLite-file-per-shard store split** is deprecated.

**Not built here (explicitly deferred):** the *unified server-DB multi-shard* runtime itself — N shard
processes actively sharing one server-DB store — needs a **single-delivery-consumer-per-outbound-lane**
ownership primitive (today every shard starts a delivery worker for every shared outbound; on a unified store
that is N consumers on one FIFO head, which `FOR UPDATE SKIP LOCKED` would reorder). That coordinator-assigned
outbound ownership is a separate reliability-core build, **gated** behind a measured CPU need and
free-threading-first (ADR 0053). This ADR only forbids the *split*; it does not certify multi-shard on a
server DB as production-ready.

> **Update — 2026-07-06 ([ADR 0073](0073-ownership-scoped-recovery-single-consumer-lanes.md)).** Both halves
> of the deferred runtime are now **BUILT**: the single-delivery-consumer-per-outbound-lane primitive
> (deterministic rendezvous ownership over the pinned shard universe, gated at the wake/claim boundary) and
> the ownership-scoped startup/DR crash recovery (`reset_stale_inflight(owned=...)`). The gating language
> above is stale in one respect: the ADR 0053 post-B5 re-scope (2026-07-06) inverted "free-threading-first" —
> engine sharding on one unified store is the committed 45M/day path and FT is an optional box-count reducer.
> N-active remains gated on the clean 4-engine no-loss bench before SYSTEM-REQUIREMENTS calls it a supported
> production topology (ADR 0073 §Consequences).

## Acceptance Criteria

- **AC-1** — IF a config declares `>1` distinct shard AND `[store].backend` is SQLite, THEN THE SYSTEM SHALL
  refuse to supervise (a `ValueError` naming the server-DB requirement), before spawning any subprocess.
  → `tests/test_sharding.py::test_require_unified_store_refuses_multi_shard_sqlite`
  → `tests/test_sharding.py::test_discover_shard_specs_runs_the_guard`
- **AC-2** — WHEN a config declares a single shard (or is untagged) on SQLite, THE SYSTEM SHALL run it
  unchanged (one process, one store).
  → `tests/test_sharding.py::test_require_unified_store_allows_single_or_no_shard_on_sqlite`
- **AC-3** — WHERE `[store].backend` is a server DB (Postgres/SQL Server), THE SYSTEM SHALL permit `>1` shard
  (all shards share the one database).
  → `tests/test_sharding.py::test_require_unified_store_allows_multi_shard_on_server_db`

## Options considered

1. **Refuse `>1` shard on SQLite; require a server DB (unified store).** **CHOSEN** — enforces the no-split
   rule with a cheap startup guard, mirrors the cluster precedent, keeps single-engine SQLite intact.
2. **Warn, don't refuse.** Rejected — leaves the fragmentation footgun armed; the owner's rule is a hard no-go.
3. **SQLite is `serve`-only (refuse `supervise` entirely on SQLite, even one shard).** Rejected — a single
   default shard is byte-identical to `serve` and harmless; no reason to forbid it.
4. **Supersede ADR 0037 wholesale.** Rejected — most of the sharded surface is store-agnostic and shipped; a
   wholesale supersede would wrongly refuse features (fleet console, harness driver). Amend instead.

## Consequences

**Positive** — the message store stays unified for every deployment; reporting/monitoring/audit/replay never
fragment; the rule is enforced at startup with a clear error, not discovered at query time.

**Negative / risks**
- **Breaking for any existing SQLite-sharded (`supervise` with `>1` shard) deployment.** Migration is
  drain-then-cutover: drain each per-shard SQLite store to empty (`in_pipeline → 0`), then re-point
  `supervise` at one server DB (Postgres/SQL Server) with the same per-shard inbound registries — **not** an
  offline K→1 store merge (cross-file message-id/seq/FIFO-state would collide). The single-engine SQLite path
  is unaffected. (No known production SQLite-sharded deployment today — engine run posture is single-process
  `serve` on one `.db`.)
- **Closes the store-split door — [ADR 0039](0039-database-tier-sharding-l5.md) (L5 DB-tier store split) stays
  DECLINED.** The rule is absolute across backends *and* tiers; there is **no** "split on a measured commit
  wall" exception. The aggregate store *is* a real ceiling (one WRITELOG / lock manager / finalize-applock
  namespace, shared by every engine — and it collapses on a *single* engine at ≥ ~48 interfaces, before any
  multi-shard aggregation), but it is raised **vertically** (faster storage/box — B8: one NVMe store
  ≈ 23,600 commits/s, ample headroom) and by making each message **cheaper** on it (fewer commits/applocks —
  B2 batch-claim, B3 seq-only, group-commit, a leaner finalizer), **never** by fragmenting it into multiple
  stores/instances or a partitioned queue/log. **Open pre-1500 risk:** the one unified store under real
  multi-shard load is UNMEASURED (the sweeps were single-engine) — validate it end-to-end at target N before
  promising 1500; sharding is necessary but not proven sufficient. Reversing the no-split rule needs a new ADR
  that supersedes *this* one, not a latent exception.

**Out of scope** — the unified server-DB multi-shard *runtime* (single-consumer-per-outbound-lane ownership +
per-shard liveness); free-threading (ADR 0053) as the primary multicore-on-one-store path.
