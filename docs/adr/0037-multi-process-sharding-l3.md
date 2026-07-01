# 0037 — Multi-process sharding (L3) — per-connection, N engine subprocesses

- **Status:** **Accepted (implemented, 2026-06-27).** Built in PR #584
  ([`pipeline/sharding.py`](../../messagefoundry/pipeline/sharding.py) +
  [`pipeline/supervisor.py`](../../messagefoundry/pipeline/supervisor.py), the `serve --shard` flag, the
  `supervise` CLI, and the `shard` tag on the inbound connection); the multi-shard console / IDE promote
  views landed alongside (PRs #582/#583).
- **Amended by [ADR 0063](0063-no-split-store-unified-store-for-sharding.md) (2026-07-01):** the
  **SQLite-file-per-shard store split** described below is **deprecated** — a split data store fragments
  reporting/monitoring/audit/replay, a no-go. A `>1`-shard deployment now **requires a server-DB backend**
  (one unified store; a `>1`-shard SQLite config is refused at startup by `require_unified_store`). The rest
  of this ADR — per-connection engine sharding, the `shard` tag, `serve --shard`, per-shard API ports, the
  fleet console — stands.
- **Date:** 2026-06-27
- **Related:** [docs/design/multiproc.md](../design/multiproc.md) (full design) · ADR 0001 (staged
  pipeline — each shard *is* the whole pipeline) · ADR 0039 (DB-tier sharding — L5, generalizes the
  per-shard store) · ADR 0040 (free-threading — the within-process alternative, not adopted) ·
  [CLAUDE.md](../../CLAUDE.md) §2 (asyncio concurrency; Windows/NSSM deployment), §1 (count-and-log,
  no grouping unit)

---

## Context

A single engine process is **GIL-bound**: routing and transform (pure Python — `python-hl7` peek,
routing predicates, `Message` transforms, `hl7apy` strict validation) all execute on **one CPU core**.
asyncio gives *concurrency* (overlapping I/O waits), not *parallelism*, so at high inbound volume the
CPU-bound router/transform path is the ceiling (the load numbers: the WIN2025 ~50 msg/s floor and the
E≈400 enterprise estimate are single-core Python ceilings). The forcing problem: scale past one core
**without a rewrite** and **without breaking** the reliability invariant —

> the transactional **staged queue on SQLite (WAL)** gives at-least-once delivery … the inbound
> connection is ACKed **only after** the raw message is durably committed to the **ingress** stage …

— or the per-channel FIFO and count-and-log invariants, and **without** introducing a "channel"/"route"
grouping element (CLAUDE.md §1, *no grouping unit*).

## Decision

**Run N engine subprocesses, each owning a disjoint subset of inbound connections — partition by
*connection*, never by message key.** An interface admin tags an inbound with a `shard` name
(code-first `inbound(..., shard="a")` or `connections.toml` `shard = "a"`); a supervisor
(`messagefoundry supervise`) spawns, monitors, restarts and stops one `serve --shard <id>` subprocess
per distinct shard.

- **Intake is partitioned; outbound + logic are shared.** A shard's `Registry` (via the pure,
  non-mutating `filter_registry_for_shard`) contains only its inbound connections but the **same**
  outbound connections, routers, handlers, code sets, references and lookups. Routers/handlers are pure
  (no per-process state) and outbound connections are independently re-bindable per process, so each
  shard builds its own delivery worker(s) for the outbounds its handlers actually send to.
- **One SQLite db file + one API port per shard.** Each subprocess owns an independent WAL store
  (`<stem>_<shard>.db`) — no cross-process write contention — and its own API port (`<base>+offset`,
  in sorted shard order, so the mapping is **stable across restarts**). A single default shard
  (`DEFAULT_SHARD = "default"`, every untagged inbound) keeps the bare db path + base port, so
  `supervise` on an untagged config is **byte-identical** to `serve`.
- **Each shard is the *whole* existing pipeline.** Per-channel FIFO is preserved *within* a shard
  exactly as today (a connection lives in one shard, one listener feeds one ordered pipeline); the
  staged-pipeline transactions, at-least-once, replay, dead-lettering and the single-finalizer all hold
  **per shard, unchanged** (each shard runs against its own store). Cross-shard ordering is neither
  provided nor required — shards own disjoint inbound *sources*.

This must **not** introduce a built "channel"/"route" object — a `shard` is a tag on a connection, not a
graph-bundling element — and must **not** weaken count-and-log or FIFO.

## Acceptance Criteria

- **AC-1** — WHEN a config tags inbound connections with distinct `shard` names, THE SYSTEM SHALL
  partition only the **inbound** connections into those shards while sharing outbound connections,
  routers and handlers across them.
  → `tests/test_sharding.py`
- **AC-2** — WHEN a config has no `shard` tags, THE SYSTEM SHALL run a single `"default"` shard whose
  behaviour is byte-identical to a plain `serve` (bare db path, base port).
  → `tests/test_sharding.py`
- **AC-3** — THE SUPERVISOR SHALL derive each shard's db file (`<stem>_<shard>.db`) and API port
  (`<base>+offset` in sorted order) deterministically, so a restart re-attaches the same store and
  re-binds the same port.
  → `tests/test_supervisor.py`
- **AC-4** — WHEN a shard subprocess exits unexpectedly, THE SUPERVISOR SHALL restart it; on a shutdown
  signal THE SUPERVISOR SHALL stop all children cleanly (terminate, then kill after a grace period).
  → `tests/test_supervisor.py`
- **AC-5** — WHILE running, EACH SHARD SHALL preserve per-channel FIFO and the staged-pipeline
  at-least-once guarantees against its own store (a connection lives in exactly one shard).
  → `tests/test_sharding.py`

## Options considered

1. **Per-connection multi-process sharding (this).** **CHOSEN.** Invisible-simple for the admin (tag a
   connection); reuses the whole reliable pipeline per shard; process isolation means no shared-memory
   races; FIFO and at-least-once are untouched.
2. **Per-message-key / per-facility sharding** (hash a message field to a shard). **Rejected** — too
   complex for an interface admin, and it would fan a single source across shards and **break
   per-channel FIFO** and the at-least-once invariants.
3. **Active-active (a second concurrently-writing copy of the data).** **Rejected / deleted** (#396) —
   each shard's store stays share-nothing active-passive; L3 adds intake *partitions*, never a second
   live writer of the same data.
4. **Free-threading (no-GIL) within one process.** A within-process alternative; **not adopted now**
   (see ADR 0040) — sharding stays the recommended multi-core path.

## Consequences

**Positive** — intake parallelizes across cores without a rewrite; share-nothing process isolation
(a shard crash/db-saturation is its own blast radius); FIFO, at-least-once and the single-finalizer are
preserved per shard; sharding is opt-in and byte-identical to `serve` until a connection is tagged.

**Negative / risks** — one db file + API port per shard (file/port sprawl); cross-shard reads (search,
aggregate dashboards) span K stores and are pushed to the Console/IDE control plane; an operator must
choose the shard assignment.

**Out of scope / deferred** — restart backoff / crash-loop breaker; per-shard structured-log
aggregation; graceful in-flight drain on restart; a shared single-db multi-shard mode (the MVP is one
SQLite file per shard); **DB-tier** sharding onto multiple clusters (that is L5 / ADR 0039, which
generalizes the per-shard store).
