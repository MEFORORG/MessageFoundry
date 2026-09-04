# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Synchronous, handler-callable **live** FHIR read (the FHIR analog of :func:`db_lookup`, ADR 0043).

:func:`fhir_lookup` runs a **live, read-only** FHIR read — a read-by-id ``GET {base}/Patient/123`` or a
search ``GET {base}/Patient?identifier=...`` — against an operator-declared, allow-listed FHIR endpoint
**each time the handler runs**, the FHIR mirror of the SQL :func:`~messagefoundry.config.db_lookup.db_lookup`
carve-out (resolve a ``Patient``/``Coverage``/``Practitioner`` against an EHR FHIR API as the data stands
*now*, to enrich or gate a message). It extends the **one sanctioned non-pure input** to FHIR, not a
parallel mechanism: read-only, off the event loop, fail-closed egress-gated by ``[egress].allowed_http``,
and **unavailable on a Router and in dry-run / Test Bench**.

**Read-only is structural, not a convention.** The accessor builds **only** a GET — there is **no** verb
parameter, no body, no POST/PUT/DELETE path — so a Handler **cannot** mutate the FHIR server through it.
FHIR **writes** stay on the :func:`~messagefoundry.config.wiring.FHIR` outbound (past the staged-queue
boundary, idempotent, retried).

**Deliberate exception to re-run stability (ADR 0009).** At-least-once re-runs a transform and normally
relies on identical output. A live read may re-query and return *different* data on a re-run — accepted
by design (the value used is whatever the FHIR server returns on that pass). Because the result is
non-deterministic, ``fhir_lookup`` is **only** available inside a **Handler in the running engine**; it
is intentionally unavailable on a Router and in the **dry-run / Test Bench** path (no runner is published
there, so a call raises — a feed that needs it is previewed by stubbing its wrapper).

**Off the event loop.** Handlers are synchronous and run on the asyncio loop, and a live FHIR GET must not
block it. So a handler that uses ``fhir_lookup`` runs **off the loop** (in a worker thread); the engine
publishes a *runner* that bridges the GET back to the loop. This module owns only the active-runner holder
+ the accessor; the runner (HTTP opener + SMART bearer + loop bridge + codec) is supplied by the
:class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner` via :func:`activated`, so ``config/`` stays
free of any transport / pool / event-loop import (one-way dependency, CLAUDE.md §4).

Declare a connection with :func:`~messagefoundry.config.wiring.FhirLookup`; read it in a Handler::

    patient = fhir_lookup("epic", "Patient/123")                    # read-by-id → a resource dict
    bundle = fhir_lookup(                                           # search → a searchset Bundle
        "epic", "Patient", {"identifier": FhirToken("MRN", msg["PID-3.1"] or "")}
    )

**A search value states its own kind** (BACKLOG #1243) — see :func:`fhir_lookup` below, and
:mod:`messagefoundry.fhirsearch` for the vocabulary itself.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from messagefoundry.fhirsearch import FhirSearchParams

__all__ = [
    "FhirLookupError",
    "FhirLookupRunner",
    "fhir_lookup",
    "set_active",
    "reset",
    "activated",
]


class FhirLookupError(RuntimeError):
    """:func:`fhir_lookup` was called where it can't run — outside a live Handler (a Router, dry-run /
    Test Bench, or a graph with no ``FhirLookup`` connection) — or the connection/read failed.

    Raised at **handler run time**, so it surfaces as that message's ``ERROR`` / dead-letter disposition
    (fail loud, never a silent empty result). The message is kept **PHI- and secret-free**: it names the
    connection and, where available, a routing-safe identifier (resourceType, an ``OperationOutcome``
    issue code, an HTTP status, a redacted host) — **never** the query's parameter values, the returned
    resource body, or the SMART token."""


#: The runner the engine publishes for the duration of one off-loop transform: it takes
#: ``(connection, query, params)`` (``query`` is a read-by-id ``"Patient/123"`` or a path-only
#: ``"Patient"`` paired with structured ``params``) and returns the parsed read result as a plain dict
#: (a resource, or a searchset ``Bundle``). ``params`` (ADR 0043, BACKLOG #204) is the **safely-encoded**
#: search form and, since #1243, the only one: each value is percent-encoded by the engine, so an
#: attacker-influenced value can never inject an extra FHIR search parameter (CWE-88), and each value's
#: KIND settles the FHIR value layer above it (see :func:`fhir_lookup`). ``None`` means a read-by-id
#: (no search); a ``?``-query inside ``query`` is refused.
FhirLookupRunner = Callable[[str, str, FhirSearchParams | None], dict[str, Any]]

# Active runner as a ContextVar (mirrors db_lookup._active): the runner is published around the off-loop
# transform run and copied into the worker thread by asyncio.to_thread, so a call-time fhir_lookup(...)
# inside the Handler resolves. Default None = "no active runner" → fhir_lookup raises (no Handler / Router
# / dry-run / no lookup connections), distinguishing it from "empty/None result".
_active: ContextVar[FhirLookupRunner | None] = ContextVar("mefor_active_fhir_lookup", default=None)


def set_active(runner: FhirLookupRunner | None) -> Any:
    """Publish ``runner`` as the active FHIR-lookup runner and return a reset token (pass it to
    :func:`reset`).

    For callers that can't bracket the active span with a ``with`` (the transform worker publishes it
    around a single off-loop run). Prefer :func:`activated` where a ``with`` block fits."""
    return _active.set(runner)


def reset(token: Any) -> None:
    """Restore the active FHIR-lookup runner to what it was before the matching :func:`set_active`."""
    _active.reset(token)


@contextmanager
def activated(runner: FhirLookupRunner | None) -> Iterator[None]:
    """Make ``runner`` the active FHIR-lookup runner for the duration of the ``with`` block, then restore.

    The transform worker brackets the off-loop ``transform_one`` run with it (only when the graph declares
    ≥1 ``FhirLookup``), so :func:`fhir_lookup` resolves at call time inside the worker thread and the prior
    runner is always restored — no leak across rows."""
    token = _active.set(runner)
    try:
        yield
    finally:
        _active.reset(token)


def fhir_lookup(
    connection: str,
    query: str,
    params: FhirSearchParams | None = None,
) -> dict[str, Any]:
    """Run a live, read-only FHIR ``query`` against the named ``FhirLookup`` ``connection`` and return the
    parsed result as a dict — a single resource for a read-by-id, or a searchset ``Bundle`` for a search.

    Call it inside a Handler at run time. ``query`` is **one of two read shapes**, both read-only:

    * a **read-by-id**: ``fhir_lookup("epic", "Patient/123")`` → ``GET {base}/Patient/123``;
    * a **search**: the path in ``query`` plus the fields in ``params`` —
      ``fhir_lookup("epic", "Patient", {"identifier": FhirToken("MRN", mrn)})`` → ``GET
      {base}/Patient?...``.

    **Encoding of search values (ASVS 1.2.2, BACKLOG #204, #1243).** There is exactly **one** search
    form and it is encoded by construction, at both layers. At the **URL** layer the engine
    percent-encodes every value (``urlencode(quote_via=quote, safe="")``), so a value can **never**
    inject an extra search parameter, and a ``list`` value expands to repeated params (which FHIR ANDs).

    **At the FHIR value layer, percent-encoding does not help, so a value states its own kind:**

    * ``"literal"`` — a plain ``str`` is data. Carrying ``,`` ``|`` or ``$`` **raises**
      :class:`FhirLookupError`, naming the parameter key and the character but never the value.
    * :class:`~messagefoundry.fhirsearch.FhirToken` — ``FhirToken("MRN", msg["PID-3.1"] or "")``
      builds ``MRN|<code>``. The system half is your literal and passes through; the code half is
      data and screens.
    * :class:`~messagefoundry.fhirsearch.FhirRaw` — ``FhirRaw("status,-date")`` is FHIR syntax
      **you** wrote: percent-encoded, never screened. It is how you express an OR (a comma inside one
      value), a quantity or a composite; never build one out of message data.

    Import both from ``messagefoundry``. Why the engine refuses rather than backslash-escapes, and the
    normative FHIR citations for it, are stated once on :mod:`messagefoundry.fhirsearch` — read it
    before you pass message data into ``params``.

    **That is a URL-layer guarantee, and it is not the whole story: it does not neutralise FHIR's own
    value-layer separators, so a message-derived value can still change what a search MEANS.** Screen
    such a value in your Handler. The mechanism, the affected characters and the open item are stated
    once, on ``messagefoundry.transports.fhir._encode_search_params`` — read it before you pass message
    data into ``params``.

    A ``?``-query inside ``query`` is **refused** (:class:`FhirLookupError`). It used to be supported and
    rode the URL exactly as authored, which made per-value encoding the caller's duty — an
    ``f"Patient?identifier=MRN|{pid}"`` with ``pid="123&_count=99999"`` injected an extra FHIR search
    parameter. It was removed rather than gated behind a setting, because a setting leaves that sink one
    config edit away (BACKLOG #1243; supersedes ADR 0043 AC-2).

    The GET runs **off the event loop**. The result is read on demand by the Handler via the pure
    ``parsing/fhir/`` codec (``FhirPeek``/``FhirResource``) — never a typed object pushed through the
    pipeline.

    Raises :class:`FhirLookupError` if there is no active runner (called on a Router, in dry-run / Test
    Bench, or in a graph with no ``FhirLookup``), if ``connection`` is unknown, if the ``query`` is not a
    valid read-by-id / search path, if a search value is refused, or if the connection/read fails — surfacing as that message's
    ``ERROR`` / dead-letter. Its result **may differ on a re-run** (accepted by design, read-side only —
    the outbound stays idempotent, so at-least-once is not broken)."""
    runner = _active.get()
    if runner is None:
        raise FhirLookupError(
            f"fhir_lookup({connection!r}) is unavailable here — it runs a LIVE FHIR read and resolves "
            "only inside a Handler in the running engine (a graph that declares a FhirLookup "
            "connection). It is intentionally unavailable on a Router and in dry-run / Test Bench, "
            "because its result is non-deterministic (re-run-divergent). See docs/adr/0043."
        )
    return runner(connection, query, params)
