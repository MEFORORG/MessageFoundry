# L3 multi-process sharding (per-connection)

Status: foundational slice (ADR-pending — owner to promote at merge).

## Problem

A single engine process is GIL-bound: routing + transform (pure Python) run on one CPU core. To
scale past that without a rewrite, run **N engine subprocesses**, each owning a **disjoint** subset
of inbound connections, so intake parallelizes across cores.

## Model

* **Per-connection, not per-key.** An interface admin tags an inbound connection with a `shard` name
  (`inbound(..., shard="a")` or `connections.toml` `shard = "a"`). The supervisor runs one engine
  subprocess per distinct shard. Per-message-key / per-facility sharding (hashing a message field to
  a shard) was **rejected** as too complex for an admin and because it would fan one source across
  shards and break per-channel FIFO. Per-connection keeps it invisible-simple: tag a connection.

* **Intake is partitioned; outbound + logic are shared.** A shard's `Registry` contains only its
  inbound connections, but the SAME outbound connections, routers, handlers, code sets, references
  and lookups. Routers/handlers are pure (no per-process state) and outbound connections are
  independently re-bindable per process, so each shard process builds its own delivery worker(s) for
  the outbounds its handlers actually send to. `filter_registry_for_shard` is a pure, non-mutating
  derivation that shares those sub-maps by reference.

* **One SQLite db file + one API port per shard.** Each subprocess owns an independent WAL store
  (`<stem>_<shard>.db`) — no cross-process write contention — and its own API port (`<base>+i` in
  sorted shard order, so the mapping is stable across restarts). A single default shard keeps the
  bare db path + base port, so `supervise` on an untagged config is byte-identical to `serve`.

* **Ordering.** Per-channel FIFO is preserved *within* a shard exactly as today (a connection lives
  in one shard with one listener feeding one ordered pipeline). Cross-shard ordering is neither
  provided nor required — shards own disjoint inbound *sources*, so there is no ordered relationship
  between messages on different connections in different shards.

* **Composition with the multi-shard console.** A separate lane unifies the per-shard APIs into one
  operator view. The supervisor only needs to publish the (deterministic) port it assigned each
  shard; the console fans out across them.

## Surfaces

* `inbound(..., shard=...)` / `connections.toml` `shard` — the tag (additive; `None` = default shard).
* `messagefoundry/pipeline/sharding.py` — pure core: `shard_ids`, `filter_registry_for_shard`.
* `serve --shard <id>` — filters the loaded graph to that shard before building the Engine; the
  filter is re-applied on every reload (via `Engine`'s `registry_filter`) so the shard ownership
  survives a config reload.
* `messagefoundry/pipeline/supervisor.py` + `supervise` CLI — spawn/monitor/restart/stop one
  subprocess per shard.

## Deferred (follow-up)

Restart backoff / crash-loop breaker; per-shard structured-log aggregation; graceful in-flight drain
on restart; a shared single-db multi-shard mode (the MVP is one SQLite file per shard).
