# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Synchronous, handler-callable **live** database lookup (the Corepoint real-time Data Point pattern).

Unlike :func:`~messagefoundry.config.reference.reference` / :func:`~messagefoundry.config.state.state_get`
(re-run-stable reads of engine-published *snapshots*), :func:`db_lookup` runs a **live, read-only query**
against an operator-declared database connection **each time the handler runs** — the pattern Corepoint
uses for provider-NPI / eligibility / "is-EIHC-provider" lookups that must reflect the database *now*.

**Deliberate exception to re-run stability (ADR 0009).** At-least-once re-runs a transform and normally
relies on identical output. A live lookup may re-query and return *different* data on a re-run — accepted
by design (owner decision): the value used is whatever the database returns on that pass. Because the
result is non-deterministic, ``db_lookup`` is **only** available inside a **Handler in the running
engine**; it is intentionally unavailable on a Router and in the **dry-run / Test Bench** path (no runner
is published there, so a call raises — a feed that needs it is previewed by stubbing its wrapper).

**Off the event loop.** Handlers are synchronous and run on the asyncio loop, and a live DB read must not
block it. So a handler that uses ``db_lookup`` runs **off the loop** (in a worker thread); the engine
publishes a *runner* that bridges the query back to the loop's async connection pool. This module owns
only the active-runner holder + the accessor; the runner (pool + loop bridge) is supplied by the
:class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner` via :func:`activated`, so ``config/`` stays
free of any transport / pool / event-loop import (one-way dependency, CLAUDE.md §4).

Declare a connection with :func:`~messagefoundry.config.wiring.DatabaseLookup`; read it in a Handler::

    npi = None
    rows = db_lookup("clarity", "SELECT npi FROM provider WHERE mrn = :mrn", {"mrn": msg["PID-3.1"]})
    if rows:
        npi = rows[0]["npi"]
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

__all__ = [
    "DbLookupError",
    "LookupRunner",
    "db_lookup",
    "set_active",
    "reset",
    "activated",
]


class DbLookupError(RuntimeError):
    """:func:`db_lookup` was called where it can't run — outside a live Handler (a Router, dry-run /
    Test Bench, or a graph with no ``DatabaseLookup`` connection) — or the connection/query failed.

    Raised at **handler run time**, so it surfaces as that message's ``ERROR`` / dead-letter disposition
    (fail loud, never a silent empty result). The message is kept PHI-free (it names the connection and,
    where available, the SQLSTATE — never the statement, parameters, or returned data)."""


#: The runner the engine publishes for the duration of one off-loop transform: it takes
#: ``(connection, statement, params)`` and returns the rows as a list of ``{column: value}`` dicts.
LookupRunner = Callable[[str, str, Mapping[str, Any] | None], list[dict[str, Any]]]

# Active runner as a ContextVar (mirrors reference._active / state._active): the runner is published
# around the off-loop transform run and copied into the worker thread by asyncio.to_thread, so a
# call-time db_lookup(...) inside the Handler resolves. Default None = "no active runner" → db_lookup
# raises (no Handler / Router / dry-run / no lookup connections), distinguishing it from "empty result".
_active: ContextVar[LookupRunner | None] = ContextVar("mefor_active_db_lookup", default=None)


def set_active(runner: LookupRunner | None) -> Any:
    """Publish ``runner`` as the active lookup runner and return a reset token (pass it to :func:`reset`).

    For callers that can't bracket the active span with a ``with`` (the transform worker publishes it
    around a single off-loop run). Prefer :func:`activated` where a ``with`` block fits."""
    return _active.set(runner)


def reset(token: Any) -> None:
    """Restore the active lookup runner to what it was before the matching :func:`set_active`."""
    _active.reset(token)


@contextmanager
def activated(runner: LookupRunner | None) -> Iterator[None]:
    """Make ``runner`` the active lookup runner for the duration of the ``with`` block, then restore.

    The transform worker brackets the off-loop ``transform_one`` run with it (only when the graph
    declares ≥1 ``DatabaseLookup``), so :func:`db_lookup` resolves at call time inside the worker thread
    and the prior runner is always restored — no leak across rows."""
    token = _active.set(runner)
    try:
        yield
    finally:
        _active.reset(token)


def db_lookup(
    connection: str, statement: str, params: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Run a live, read-only ``statement`` against the named ``DatabaseLookup`` ``connection`` and return
    its rows as a list of ``{column: value}`` dicts (empty list if it selected nothing).

    Call it inside a Handler at run time. ``statement`` uses ``:name`` placeholders bound from ``params``
    (always parameterized — a value can never inject SQL); a ``:name`` with no matching ``params`` key
    fails loud. The query runs **off the event loop** against a pooled connection.

    Raises :class:`DbLookupError` if there is no active runner (called on a Router, in dry-run / Test
    Bench, or in a graph with no ``DatabaseLookup``), if ``connection`` is unknown, if a parameter is
    missing, or if the connection/query fails — surfacing as that message's ``ERROR`` / dead-letter."""
    runner = _active.get()
    if runner is None:
        raise DbLookupError(
            f"db_lookup({connection!r}) is unavailable here — it runs a LIVE database read and resolves "
            "only inside a Handler in the running engine (a graph that declares a DatabaseLookup "
            "connection). It is intentionally unavailable on a Router and in dry-run / Test Bench, "
            "because its result is non-deterministic (re-run-divergent). See docs/adr/0010."
        )
    return runner(connection, statement, params)
