# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 14.2.2 — ``Cache-Control: no-store`` on every PHI-carrying API response, and a drift guard
that blocks the next uncovered one.

The engine writes ``Cache-Control`` in exactly one place, the ``_security_headers`` middleware, and it
writes it BY PATH PREFIX. That is why three PHI reads shipped header-free: ``GET /search/layered``,
``GET /logs/tail`` and ``GET /uploads/{file_id}/messages`` each arrived as a NEW member of a route
family whose prefix was not in the list, while their already-covered siblings under ``/messages`` and
``/dead-letters`` looked like proof the control was global. Lifting the test into
:data:`~messagefoundry.api.app._NO_STORE_PREFIXES` closes those three and their whole families.

**The guard is the half that matters, and it is written to be able to FAIL.** "Every route under the
prefixes has the header" is an identity confirmation — the middleware sets the header *by* prefix, so
that assertion cannot fail. The direction that catches the next defect is the inverse: **every PHI-read
route's path must be matched by a prefix**. A PHI read registered anywhere else reds this module.

**Predicate (binding correction: GET/HEAD-scoped).** A route is a PHI read when it declares
``require_phi_read``, or its handler charges the PHI-read hop/pacing budget by calling
``enforce_phi_read_hop`` (the bulk-PHI step-up GETs do this explicitly), or it is a GET/HEAD carrying
``require_step_up``. The GET/HEAD scoping on the step-up arm is load-bearing: anti-caching is a
property of cacheable reads, and an unscoped step-up-over-PHI predicate lands red on
``POST /connections/{name}/purge`` — a step-up route that returns cancellation counts, no PHI, from
outside every prefix. :func:`test_non_phi_step_up_write_is_not_selected` pins that exclusion. The first
two arms are deliberately method-agnostic so a bulk-PHI read later converted to a POST body-carrying
variant stays selected instead of silently dropping out of the coverage claim.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute

from messagefoundry.api import create_app
from messagefoundry.api.app import _NO_STORE_PREFIXES
from messagefoundry.pipeline import Engine

#: Qualname prefixes of the auth-dependency closures ``Depends(require_*(...))`` installs on a route.
_PHI_READ_DEP = "require_phi_read."
_STEP_UP_DEP = "require_step_up."
#: The explicit PHI-read declaration a step-up bulk-PHI handler makes in its own body.
_HOP_CALL = "enforce_phi_read_hop("

#: The PHI reads that must be selected by the predicate. Pinned literally so a refactor that makes the
#: predicate select NOTHING (a green, vacuous guard) fails here instead of passing silently.
_EXPECTED_PHI_READS = frozenset(
    {
        "/dead-letters",
        "/messages",
        "/messages/search",
        "/messages/export",
        "/messages/{message_id}",
        "/messages/{message_id}/attachments/{attachment_id}",
        "/messages/{message_id}/outbound",
        "/messages/{message_id}/responses",
        "/search/layered",
        "/logs/tail",
        "/uploads/{file_id}/messages",
    }
)

#: Every PHI response that emitted no ``Cache-Control`` at all before this. All GET.
_PREVIOUSLY_UNCOVERED = ("/search/layered", "/logs/tail", "/uploads/f1/messages")


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "no_store.db", poll_interval=0.02)
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


def _dependency_qualnames(route: APIRoute) -> set[str]:
    """Every dependency callable on the route, recursively (a gate closure can nest)."""
    found: set[str] = set()
    pending = [route.dependant]
    while pending:
        for sub in pending.pop().dependencies:
            call = getattr(sub, "call", None)
            if call is not None:
                found.add(getattr(call, "__qualname__", ""))
            pending.append(sub)
    return found


def _handler_charges_phi_hop(route: APIRoute) -> bool:
    try:
        return _HOP_CALL in inspect.getsource(route.endpoint)
    except (OSError, TypeError):  # source unavailable (zipped install) — fall back to the gate arms
        return False


def _is_phi_read(route: APIRoute) -> bool:
    """See the module docstring: PHI-read gate, or an explicit hop charge, or a GET/HEAD step-up."""
    quals = _dependency_qualnames(route)
    if any(q.startswith(_PHI_READ_DEP) for q in quals) or _handler_charges_phi_hop(route):
        return True
    cacheable = bool({"GET", "HEAD"} & (route.methods or set()))
    return cacheable and any(q.startswith(_STEP_UP_DEP) for q in quals)


def _phi_read_routes(app: FastAPI) -> list[APIRoute]:
    return [r for r in app.routes if isinstance(r, APIRoute) and _is_phi_read(r)]


# --- the drift guard ---------------------------------------------------------


async def test_every_phi_read_route_is_under_a_no_store_prefix(engine: Engine) -> None:
    """THE GUARD, in the direction that can fail: a PHI-read route registered outside every prefix in
    ``_NO_STORE_PREFIXES`` reds here — which is exactly how the three uncovered reads would have been
    caught the day they shipped."""
    app = create_app(engine, allow_no_auth=True, serve_ui=False)
    uncovered = [r.path for r in _phi_read_routes(app) if not r.path.startswith(_NO_STORE_PREFIXES)]
    assert uncovered == [], (
        "PHI-read route(s) outside _NO_STORE_PREFIXES — they will be served with no Cache-Control "
        f"and may be retained by an intermediary: {uncovered}"
    )


async def test_the_guard_selects_the_known_phi_reads(engine: Engine) -> None:
    """Non-vacuity: the predicate really selects the PHI surface. Without this a refactor that made
    ``_is_phi_read`` return False for everything would leave the guard above green and empty."""
    app = create_app(engine, allow_no_auth=True, serve_ui=False)
    selected = {r.path for r in _phi_read_routes(app)}
    assert selected >= _EXPECTED_PHI_READS, (
        f"guard stopped selecting: {_EXPECTED_PHI_READS - selected}"
    )


async def test_non_phi_step_up_write_is_not_selected(engine: Engine) -> None:
    """The binding correction, pinned. ``POST /connections/{name}/purge`` is step-up-gated over a
    MESSAGES_* permission but returns cancellation counts, not PHI, and sits outside every prefix — an
    unscoped step-up-over-PHI predicate would red the guard on it on day one."""
    app = create_app(engine, allow_no_auth=True, serve_ui=False)
    purge = [
        r for r in app.routes if isinstance(r, APIRoute) and r.path == "/connections/{name}/purge"
    ]
    assert len(purge) == 1
    assert "POST" in (purge[0].methods or set())
    assert any(q.startswith(_STEP_UP_DEP) for q in _dependency_qualnames(purge[0]))
    assert not _is_phi_read(purge[0])


# --- the served header -------------------------------------------------------


@pytest.mark.parametrize("path", _PREVIOUSLY_UNCOVERED)
async def test_previously_uncovered_phi_reads_are_no_store(
    client: httpx.AsyncClient, path: str
) -> None:
    """The three PHI responses that emitted no ``Cache-Control`` at all. Asserted on the SERVED
    response, and status-agnostic on purpose: the middleware must stamp the header whatever the route
    body does (an unconfigured upload store 503s, a missing preset 422s) — a header that only appears
    on the happy path is not a directive an intermediary can rely on."""
    r = await client.get(path)
    assert r.headers.get("cache-control") == "no-store"


@pytest.mark.parametrize(
    "path", ["/messages", "/dead-letters", "/search/presets", "/uploads", "/logs"]
)
async def test_no_store_families_stay_covered(client: httpx.AsyncClient, path: str) -> None:
    """One member per prefix family, so a future narrowing of ``_NO_STORE_PREFIXES`` (back to explicit
    route paths, say) is caught rather than silently shrinking the covered set."""
    r = await client.get(path)
    assert r.headers.get("cache-control") == "no-store"


async def test_no_store_is_not_blanket(client: httpx.AsyncClient) -> None:
    """The prefixes are scoped, not global: non-PHI operational reads are deliberately left cacheable-
    by-default, which is what keeps the header a meaningful signal where it IS set."""
    for path in ("/health", "/status"):
        assert (await client.get(path)).headers.get("cache-control") is None
