# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Coarse-grained, per-connection multi-process sharding (L3).

The GIL caps a single engine process at one CPU core for routing/transform. To scale past it
without a rewrite, an operator may run **N engine subprocesses**, each owning a **disjoint** subset
of inbound connections, so intake parallelizes across cores. Each subprocess is the *existing*
engine — same listener + router-worker + transform-worker + delivery-worker pipeline — loading only
its shard's inbounds, with its **own SQLite db file** and its **own API port**. A supervisor
(``messagefoundry supervise``) spawns, monitors, restarts and stops them.

Design rationale (captured here for a future ADR; see also ``docs/design/multiproc.md``):

* **Per-connection, not per-key.** The operator assigns whole inbound connections to a shard by
  tagging the connection with a ``shard`` name (code-first ``inbound(..., shard="a")`` or
  ``connections.toml``). Per-message-key / per-facility sharding (hash a message field to a shard)
  was rejected as too complex for an interface admin and for the at-least-once invariants — it would
  fan a single source across shards and break per-channel FIFO. Per-connection keeps it
  invisible-simple: tag a connection, done.

* **Intake is partitioned; outbound + logic are shared — but delivery is single-consumer.** A
  shard's registry contains ONLY its inbound connections, but the SAME outbound connections,
  routers, handlers, references and lookups as every other shard. Routers/handlers are pure
  functions (no per-process state), so sharing the definitions is sound. **Amended by ADR 0073:**
  each outbound *lane* is CLAIMED by exactly ONE shard — the deterministic rendezvous owner
  (:func:`owner_shard_of_destination`) — because on a unified store N concurrent head-claimers on
  one FIFO lane can invert per-lane delivery order, and crash recovery needs an unambiguous owner
  per lane. Every shard still *builds* every outbound connector (status/reload/dead-letter sweeps
  key off the full map); only claiming/delivering is gated to the owner. A shard's handlers may
  Send to any outbound — a non-owned lane's rows are drained by the owning shard.

* **One SQLite db file + one API port per shard.** Each subprocess owns an independent WAL store
  (``<stem>_<shard>.db``) so there is no cross-process write contention on the message store, and an
  independent API port (``<base>+offset``) so each shard's console/health endpoint is reachable.
  The multi-shard CONSOLE (a separate lane) unifies these per-shard APIs into one operator view; the
  supervisor only needs to know the ports it assigned. **Amended by ADR 0063:** the SQLite-file-per-shard
  split is **deprecated** (a split store fragments reporting/monitoring); a ``>1``-shard deployment now
  requires a **server-DB backend** — one unified store, every shard on the same database — enforced by
  :func:`require_unified_store`. A single shard keeps the bare path (byte-identical to ``serve``).

* **Ordering.** Per-channel FIFO is preserved *within* a shard exactly as today (a connection lives
  in one shard, and its single listener feeds one ordered pipeline). Cross-shard ordering is neither
  provided nor required: shards own disjoint inbound *sources*, so there is no ordered relationship
  between messages arriving on different connections in different shards.

This module is the **pure** core: a shard tag lives on :class:`InboundConnection`; the filtering and
discovery helpers here take a :class:`Registry` and return a derived one. They touch no I/O, no
event loop and no process state, so they are safe to call from the loader, the engine reload path,
``dryrun`` and tests alike. The subprocess supervisor lives in :mod:`messagefoundry.pipeline.supervisor`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from messagefoundry.config.settings import StoreBackend
from messagefoundry.config.wiring import Registry

#: The implicit shard every ``shard=None`` (untagged) inbound connection belongs to. A config with no
#: shard tags at all is therefore a single-shard deployment named ``"default"`` — ``supervise`` spawns
#: exactly one subprocess for it, byte-identical in behaviour to a plain ``serve``.
DEFAULT_SHARD = "default"


def shard_of(shard: str | None) -> str:
    """Normalize an inbound's ``shard`` tag to its effective shard id (``None`` → ``DEFAULT_SHARD``)."""
    return shard if shard is not None else DEFAULT_SHARD


def shard_ids(registry: Registry) -> list[str]:
    """The distinct shard ids present in ``registry``, sorted, with ``DEFAULT_SHARD`` for untagged.

    Discovery for the supervisor: one subprocess is spawned per id. A registry with no inbound
    connections yields ``[]`` (nothing to run); any untagged inbound contributes ``DEFAULT_SHARD``.
    """
    ids = {shard_of(conn.shard) for conn in registry.inbound.values()}
    return sorted(ids)


def require_unified_store(store_backend: StoreBackend, ids: Sequence[str]) -> None:
    """Enforce the no-split-store rule: a multi-shard deployment must share ONE unified store (ADR 0063).

    Engine sharding partitions inbound connections across N subprocesses for CPU parallelism, but the
    message **store must stay unified**. Splitting it — one ``<stem>_<shard>.db`` SQLite file per shard —
    fragments search / reporting / audit / dead-letter / replay across K databases, which is a no-go. And
    SQLite cannot be a shared multi-writer store across processes, so a **>1-shard** deployment requires a
    **server-DB backend** (Postgres / SQL Server), where every shard connects to the SAME database. A
    single shard (or an untagged config → the implicit ``DEFAULT_SHARD``) is unaffected — it is one
    process, one store, byte-identical to plain ``serve``. Mirrors the ``[cluster]`` → server-DB rule
    (``settings.py`` ``_cluster_requires_server_db``).

    Raises :class:`ValueError` when ``store_backend`` is not a server-DB backend (Postgres / SQL Server)
    and ``ids`` names more than one distinct shard; otherwise a no-op. **Fail-closed** for parity with
    ``_cluster_requires_server_db``: any non-server backend is refused for ``>1`` shard, not only SQLite,
    so a future single-file backend can't silently split the store.
    """
    distinct = sorted(set(ids))
    is_server_db = store_backend in (StoreBackend.POSTGRES, StoreBackend.SQLSERVER)
    if not is_server_db and len(distinct) > 1:
        raise ValueError(
            f"multi-process sharding ({len(distinct)} shards: {', '.join(distinct)}) requires a server-DB "
            "store (Postgres or SQL Server) so every shard shares ONE unified database — a single-file "
            f"store like {store_backend.value!r} would split the message store into one file per shard "
            "(fragmenting search / reporting / audit / replay), which is not allowed. Set [store].backend "
            "= 'postgres' or 'sqlserver' (all shards connect to the same database), or run a single "
            "un-sharded engine."
        )


def owner_shard_of_destination(dest: str, ids: Sequence[str]) -> str:
    """The single shard that owns CLAIMING/DELIVERY for outbound lane ``dest`` (ADR 0073).

    Rendezvous (highest-random-weight) hashing over the pinned shard universe ``ids``: every process
    that knows the same universe derives the same owner with **no runtime coordination**. Three
    properties the recovery design leans on:

    * **Restart-stable** — ``hashlib.sha256`` (never the salted builtin ``hash``), so the owner of a
      lane is identical across processes, restarts and machines.
    * **Total over any lane name** — a destination dropped from config but still draining its queued
      rows keeps exactly one owner (the universe, not the destination set, decides).
    * **Minimal disruption** — adding/removing a destination never moves another lane; adding or
      removing a shard id moves only ~1/N of lanes (why the universe must change only under a
      coordinated fleet restart — see the reload refusal in ``Engine.reload``).

    Ties are broken deterministically (candidates iterate sorted). Raises :class:`ValueError` on an
    empty universe — callers gate on a sharded registry, which always pins a non-empty one.
    """
    universe = sorted(set(ids))
    if not universe:
        raise ValueError("owner_shard_of_destination: empty shard universe")
    return max(universe, key=lambda s: hashlib.sha256(f"{dest}\x00{s}".encode()).digest())


def owned_destination_set(registry: Registry, shard: str, ids: Sequence[str]) -> frozenset[str]:
    """Every ``registry`` outbound lane owned by ``shard`` under the pinned universe ``ids``.

    The set form of :func:`owner_shard_of_destination` for callers that need concrete names — the
    ownership-scoped startup recovery (``OwnedLanes.destinations``) and the non-owned-lane watchdog.
    Claim-path gates should prefer the predicate: it stays total over names a reload has already
    dropped from ``registry.outbound``."""
    return frozenset(
        dest for dest in registry.outbound if owner_shard_of_destination(dest, ids) == shard
    )


def filter_registry_for_shard(registry: Registry, shard: str) -> Registry:
    """A :class:`Registry` exposing ONLY ``shard``'s inbound connections, sharing everything else.

    The returned registry keeps the SAME outbound connections, routers, handlers, code sets,
    references and lookups (delivery + logic are shared across shards — see the module docstring),
    but its ``inbound`` map contains only the connections whose effective shard equals ``shard``.
    Pure and non-mutating: the source registry is untouched and the shared sub-maps are reused by
    reference (they are read-only at run time), so this is cheap to call on every reload.

    When the (unfiltered) config names **more than one** shard, the result also carries the shard
    identity (``shard_id`` + the pinned ``all_shard_ids`` universe) that arms the ADR 0073
    sharded-mode behaviors: ownership-scoped startup recovery, the single-delivery-consumer-per-
    outbound-lane gates, and the shard-set reload refusal. A single-shard config attaches neither —
    it stays byte-identical to plain ``serve`` everywhere.

    Raising is intentionally avoided for an empty result — a shard id that matches no inbound yields
    an empty-intake registry; the caller (``serve --shard``) decides whether that is an error.
    """
    selected = {
        name: conn for name, conn in registry.inbound.items() if shard_of(conn.shard) == shard
    }
    ids = shard_ids(registry)
    sharded = len(ids) > 1
    return Registry(
        inbound=selected,
        outbound=registry.outbound,
        routers=registry.routers,
        handlers=registry.handlers,
        # Carry the `accepts=` predicates (ADR 0084) with the handlers they gate. Dropping them here
        # would leave each shard routing every selected handler — a silent cost + disposition
        # regression (the shard would materialize routed rows the unsharded engine declines).
        handler_accepts=registry.handler_accepts,
        code_sets=registry.code_sets,
        references=registry.references,
        lookups=registry.lookups,
        fhir_lookups=registry.fhir_lookups,
        shard_id=shard if sharded else None,
        all_shard_ids=tuple(ids) if sharded else None,
    )
