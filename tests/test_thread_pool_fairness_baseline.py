# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fairness baseline for the shared default thread pool (ASVS 15.4.4, BACKLOG #1195).

Sign-in's argon2 verify reaches the event loop's default executor through ``asyncio.to_thread``. At
least route and transform work share that executor too, unless ADR 0071 thread-hop fusion moves them
onto executors of their own. Nothing partitions the default executor, reserves a thread for sign-in,
or ranks work by priority. So when every thread is busy, a password verify waits behind all of it.
This file measures that, with no sleeps:

* ``_POOL`` workers form the default executor, reusing the connection-scale harness's instrumented
  pool so the queue depth is readable.
* ``parked`` tasks block on a ``threading.Event`` that only this test sets. Each one reports on the
  loop when its thread has started, so the test knows the threads are held before it goes on.
* One real argon2 verify then goes through :meth:`AuthService._argon2`, the seam every password
  verify uses. The stored hash uses the cheapest argon2 cost, because the cost is not under test.

The CONTROL parks one thread fewer than the pool holds, and the verify finishes. That shows the probe
can pass when one thread is free; its only bound is a backstop, so a slow runner cannot turn it red.
The BASELINE parks every thread, and the verify never starts. It is ``xfail(strict=True)`` and raises only :class:`Starved`, which requires
the verify to be still queued at the deadline. So a slow verify that did start is a real failure,
not an expected one. **The day a partition or reservation lets the verify through, the baseline
XPASSes, strict turns that red, and whoever built the partition must remove the marker** along with
the matching vault edit. Three limits bind whoever does that:

* An XPASS proves only that the verify got a thread. A local sign-in makes at least one more
  ``to_thread`` hop outside ``_argon2`` (the rehash check), and the directory and IdP paths make their
  own, so check those hops before closing the residual.
* The parkers submit straight to the default executor. A fix that caps the OTHER submitters will not
  XPASS until the parkers go through its cap.
* The test installs its own plain pool. A fix built as a partitioned default executor will not XPASS
  until the test installs that executor in place of the plain one.

This is a different pool from the one the ``async def`` request providers stopped using in the same
change. FastAPI runs a sync dependency through AnyIO's own worker threads, not the loop's default
executor, so that change does not touch the starvation measured here. The last tests in this file
guard that other pool: no route may declare a sync dependency (BACKLOG #2448).

Each starvation test runs on its own event loop through ``asyncio.run``. The suite shares one session
loop, and setting the default executor on it would leak a tiny pool into every later test. The route
guards set no executor, so they run on the shared loop.
"""

from __future__ import annotations

import ast
import asyncio
import functools
import inspect
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import fastapi
import pytest
from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, FastAPI, Request, WebSocket
from fastapi.dependencies import models as fastapi_models
from fastapi.dependencies.models import Dependant
from fastapi.responses import PlainTextResponse
from fastapi.routing import APIRoute, APIWebSocketRoute
from starlette.applications import Starlette
from starlette.routing import Mount, Route

from messagefoundry.api.app import _get_engine, _get_gate
from messagefoundry.api.auth_routes import _service as api_service
from messagefoundry.api.security import bearer_token_dependency
from messagefoundry.auth.passwords import verify_password
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline.connscale_shim import InstrumentedThreadPoolExecutor
from messagefoundry.store.store import MessageStore
from messagefoundry_webconsole._service import _service as console_service
from scripts.security import route_gates
from tests._ast_sites import call_sites, find_funcs, parse_source

_POOL = 4
# The baseline's budget. A verify with no free thread cannot finish at any budget, so the value only
# matters the day a fix lands: a verify at the cheapest cost takes about a millisecond, and one at the
# pinned cost measured 0.51 s on a loaded workstation. The baseline waits the whole budget every run.
_BUDGET_SECONDS = 1.0
# A backstop, not a measurement. It bounds parking and the control, so a parker that never starts
# fails one test instead of hanging until pytest-timeout kills the whole worker.
_BACKSTOP_SECONDS = 30.0
_PASSWORD = "fairness-baseline-password"


class Starved(AssertionError):
    """The verify was still waiting for a pool thread when the budget ran out."""


async def _verify_with_parked_threads(parked: int, budget: float) -> None:
    loop = asyncio.get_running_loop()
    pool = InstrumentedThreadPoolExecutor(max_workers=_POOL)
    loop.set_default_executor(pool)

    # Runs inline on the loop thread; it never touches the pool.
    stored_hash = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(_PASSWORD)
    release = threading.Event()
    all_parked = asyncio.Event()
    started = 0

    def _count_started() -> None:
        nonlocal started
        started += 1
        if started == parked:
            all_parked.set()

    def _park() -> None:
        loop.call_soon_threadsafe(_count_started)
        release.wait()

    verify_started = threading.Event()

    def _verify(stored: str, password: str) -> bool:
        verify_started.set()
        return verify_password(stored, password)

    parkers: list[asyncio.Future[None]] = []
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        for _ in range(parked):
            parkers.append(loop.run_in_executor(None, _park))
        async with asyncio.timeout(_BACKSTOP_SECONDS):
            await all_parked.wait()
        verify = asyncio.ensure_future(service._argon2(_verify, stored_hash, _PASSWORD))
        done, _ = await asyncio.wait({verify}, timeout=budget)
        if verify not in done and not verify_started.is_set():
            raise Starved(
                f"argon2 verify got no thread in {budget}s: {parked} of {_POOL} "
                f"threads parked, {pool.queue_depth} work item(s) still queued"
            )
        assert verify in done, f"argon2 verify started but ran past {budget}s"
        assert verify.result() is True
    finally:
        # A verify left pending is cancelled by ``asyncio.run`` on the way out.
        release.set()
        await asyncio.gather(*parkers)
        await store.close()


def test_control_verify_finishes_with_one_thread_free() -> None:
    asyncio.run(_verify_with_parked_threads(_POOL - 1, _BACKSTOP_SECONDS))


@pytest.mark.xfail(
    strict=True,
    raises=Starved,
    reason=(
        "ASVS 15.4.4 residual (BACKLOG #1195): the default pool has no partition or reservation, so "
        "a saturated pool starves sign-in. Remove this marker when that lands."
    ),
)
def test_baseline_verify_is_starved_when_every_thread_is_parked() -> None:
    asyncio.run(_verify_with_parked_threads(_POOL, _BUDGET_SECONDS))


def test_request_providers_do_not_take_a_worker_thread() -> None:
    """FastAPI runs a sync ``Depends`` provider on an AnyIO worker thread and an ``async`` one on the
    loop. This pins the four providers BACKLOG #1195 converted, which back most engine and console
    routes, and the wrapper BACKLOG #2448 put on ``POST /me/password``. The route-wide guard is
    :func:`test_no_route_declares_a_sync_dependency`; this one names the functions, so a provider
    made sync again fails here even while no route happens to declare it."""
    for provider in (_get_engine, _get_gate, api_service, console_service, bearer_token_dependency):
        assert inspect.iscoroutinefunction(provider), provider.__qualname__


#: Route types the walk below cannot see inside, each read and accepted. ``/ui/static`` is
#: Starlette's ``StaticFiles``, which reads files from disk; that I/O blocks, so its worker threads
#: are work a thread is for.
_UNREAD_ACCEPTED = {("Mount", "/ui/static")}

#: Sync calls the guard accepts, as ``module.qualname`` to the reason. Empty today. A dependency
#: whose work really blocks, such as file, directory or database I/O, needs a thread, so it belongs
#: here with its reason. Do not wrap it in an ``async def``: that runs the block on the event loop.
#: ``asyncio.to_thread`` is no better a home, because it uses the default executor this file shows
#: sign-in starving in.
_SYNC_ACCEPTED: dict[str, str] = {}


@dataclass
class _Walk:
    """What :func:`_walk` found. ``sync`` maps ``module.qualname`` to the paths that declare it.
    ``unread`` holds ``(type, path)`` for a route the walk could not look inside. ``paths`` is every
    path it visited, which the sentinels read."""

    sync: dict[str, set[str]] = field(default_factory=dict)
    unread: set[tuple[str, str]] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)


def _name(call: object) -> str:
    """``module.qualname``, so two functions sharing a qualname in different modules stay apart. A
    callable instance or a ``functools.partial`` has no qualname, so it is named by its type."""
    named = call if hasattr(call, "__qualname__") else type(call)
    return f"{getattr(named, '__module__', '?')}.{getattr(named, '__qualname__', '?')}"


def _fastapi_awaits(call: Callable[..., Any]) -> bool:
    """FastAPI's own rule for a dependency or endpoint: it awaits a coroutine function, enters an
    async generator on the loop, and sends anything else, such as a plain ``def``, a sync generator
    or a class, through ``run_in_threadpool`` (``fastapi.dependencies.utils.solve_dependencies``).

    The two helpers are private, and FastAPI has no public form of them: ``Dependant`` exposes no
    such predicate. Copying their logic here would let the guard drift from the rule FastAPI runs. So
    they are read at call time through ``route_gates.fastapi_symbol``, and a FastAPI that renames one
    fails these guards with the installed version and the missing name, leaving the starvation tests
    above standing (vault BACKLOG #3055)."""
    is_coroutine = route_gates.fastapi_symbol(fastapi_models, "_is_coroutine_callable")
    is_async_gen = route_gates.fastapi_symbol(fastapi_models, "_is_async_gen_callable")
    return bool(is_coroutine(call) or is_async_gen(call))


def _starlette_awaits(call: object) -> bool:
    """Starlette's rule for a plain ``Route`` endpoint or an exception handler, which differs from
    FastAPI's: it unwraps ``functools.partial`` but not ``__wrapped__``, and it checks the object or
    its ``__call__`` (``starlette._utils.is_async_callable``)."""
    while isinstance(call, functools.partial):
        call = call.func
    return inspect.iscoroutinefunction(call) or (
        callable(call) and inspect.iscoroutinefunction(getattr(call, "__call__", None))  # noqa: B004
    )


def _walk(
    owner: Starlette | APIRouter | Mount, prefix: str = "", found: _Walk | None = None
) -> _Walk:
    """The calls a request to ``owner``'s routes hands to a worker thread, as far as the walk can see.

    Routes come through ``route_gates._effective_routes``, the walk the gate inventory already uses.
    It opens every ``include_router`` and reads the include's own dependencies. A mount with routes
    is walked under its path. Any other route type lands in ``unread``, so it is named rather than
    skipped. A ``frontend`` group, which FastAPI keeps in a separate list, makes that call raise
    rather than pass unvisited.
    """
    found = _Walk() if found is None else found
    for route, effective in route_gates._effective_routes(owner):
        path = prefix + (getattr(effective, "path", None) or "")
        found.paths.add(path)
        dependant = getattr(effective, "dependant", None)
        if isinstance(route, APIRoute | APIWebSocketRoute) and isinstance(dependant, Dependant):
            # FastAPI awaits a WebSocket endpoint directly, so a sync one is broken rather than slow.
            # Only its dependencies can reach the pool.
            ws = isinstance(route, APIWebSocketRoute)
            pending = list(dependant.dependencies) if ws else [dependant]
            while pending:
                node = pending.pop()
                pending.extend(node.dependencies)
                if node.call is not None and not _fastapi_awaits(node.call):
                    found.sync.setdefault(_name(node.call), set()).add(path)
        elif isinstance(effective, Mount) and effective.routes:
            _walk(effective, path, found)
        elif isinstance(effective, Route) and (
            inspect.isfunction(effective.endpoint) or inspect.ismethod(effective.endpoint)
        ):
            # A plain Starlette route with a function endpoint, such as the docs pages. Starlette
            # runs a sync one on a worker thread. A class endpoint is an ASGI app, and lands below.
            if not _starlette_awaits(effective.endpoint):
                found.sync.setdefault(_name(effective.endpoint), set()).add(path)
        else:
            found.unread.add((type(effective).__name__, path))
    return found


def _walk_app(app: FastAPI) -> _Walk:
    """:func:`_walk` over the routes, plus two app-level places a sync call reaches the pool: an
    exception handler, which Starlette runs through ``run_in_threadpool``, and a dependency
    override, which FastAPI calls in place of the declared dependency."""
    found = _walk(app)
    for handler in app.exception_handlers.values():
        if not _starlette_awaits(handler):
            found.sync.setdefault(_name(handler), set()).add("<exception handler>")
    for override in app.dependency_overrides.values():
        if not _fastapi_awaits(override):
            found.sync.setdefault(_name(override), set()).add("<dependency override>")
    return found


def test_no_route_declares_a_sync_dependency() -> None:
    """THE GUARD BACKLOG #2448 asks for (ASVS 15.4.4). On the full surface, which is the JSON API,
    the web console, OIDC and the docs pages, no route declares a sync dependency or a sync endpoint,
    and no exception handler or dependency override is sync. A new one fails here, named with the
    paths that declare it.

    The fix depends on the work. Wrap a helper that never blocks in an ``async def``, the way
    :func:`bearer_token_dependency` wraps ``bearer_token``. A helper that does block goes in
    :data:`_SYNC_ACCEPTED` with its reason.

    WHAT IT DOES NOT COVER, at least: a sync background task, which Starlette also runs on a worker
    thread. The walk reads what is declared, not what an endpoint body does. A sync iterator handed
    to ``StreamingResponse`` is :func:`test_no_streaming_response_is_handed_a_sync_body`'s.
    """
    found = _walk_app(route_gates.full_surface_app())
    # Coverage beside the verdict: one sentinel per surface the full app adds, so a registrar that
    # stops registering cannot shrink the walk unseen.
    for sentinel in ("/me/password", "/ui/login", "/ui/oidc/start", "/ws/stats", "/docs"):
        assert sentinel in found.paths, (sentinel, len(found.paths))
    assert found.unread == _UNREAD_ACCEPTED
    assert {name: paths for name, paths in found.sync.items() if name not in _SYNC_ACCEPTED} == {}


def _planted_sync_dependency() -> None:
    return None


async def _planted_async_dependency() -> None:
    return None


def _planted_sync_endpoint(request: Request) -> PlainTextResponse:
    return PlainTextResponse("")  # pragma: no cover - never called


def _planted_sync_handler(request: Request, exc: Exception) -> PlainTextResponse:
    return PlainTextResponse("")  # pragma: no cover - never called


def test_the_guard_names_what_was_planted() -> None:
    """THE CONTROL. A guard nobody has made fail is not evidence. A bare app, so a real regression
    elsewhere cannot blur this one. One sync call is planted on each branch of the walk: under an
    async dependency, on an ``include_router`` call, on a WebSocket route, as an ``APIRoute``
    endpoint, as a plain Starlette endpoint, inside a mount, as an exception handler and as a
    dependency override. The walk names each of those and nothing else; the async dependency beside
    them is not named."""

    async def _outer(_inner: None = Depends(_planted_sync_dependency)) -> None:
        return None

    app = FastAPI()

    @app.get("/planted/nested")
    async def _nested(
        _a: None = Depends(_outer), _b: None = Depends(_planted_async_dependency)
    ) -> None:  # pragma: no cover - never called
        return None

    @app.get("/planted/sync-endpoint")
    def _sync_endpoint() -> None:  # pragma: no cover - never called
        return None

    @app.websocket("/planted/ws")
    async def _ws(
        websocket: WebSocket, _d: None = Depends(_planted_sync_dependency)
    ) -> None:  # pragma: no cover - never called
        return None

    router = APIRouter()

    @router.get("/included")
    async def _included() -> None:  # pragma: no cover - never called
        return None

    app.include_router(router, prefix="/planted", dependencies=[Depends(_planted_sync_dependency)])
    app.add_route("/planted/plain", _planted_sync_endpoint)
    app.mount("/planted/mount", Starlette(routes=[Route("/inner", _planted_sync_endpoint)]))
    app.add_exception_handler(LookupError, _planted_sync_handler)
    app.dependency_overrides[_planted_async_dependency] = _planted_sync_dependency

    found = _walk_app(app)
    assert found.sync == {
        _name(_planted_sync_dependency): {
            "/planted/nested",
            "/planted/included",
            "/planted/ws",
            "<dependency override>",
        },
        _name(_sync_endpoint): {"/planted/sync-endpoint"},
        _name(_planted_sync_endpoint): {"/planted/plain", "/planted/mount/inner"},
        _name(_planted_sync_handler): {"<exception handler>"},
    }
    assert _name(_planted_async_dependency) not in found.sync


@pytest.mark.parametrize("helper", ["_is_coroutine_callable", "_is_async_gen_callable"])
def test_a_renamed_fastapi_helper_fails_the_guard_by_name(
    helper: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard reads FastAPI's own private rule. A FastAPI that renames either helper must fail it
    with the installed version and the missing name, never let it classify with a guess (vault
    BACKLOG #3055)."""
    assert _fastapi_awaits(_planted_async_dependency)  # the control, before the rename
    monkeypatch.delattr(fastapi_models, helper)
    with pytest.raises(route_gates.MissingFastAPISymbol) as caught:
        _fastapi_awaits(_planted_async_dependency)
    assert f"fastapi.dependencies.models.{helper}" in str(caught.value)
    assert f"FastAPI {fastapi.__version__}" in str(caught.value)


#: The packages that build responses. ``harness`` and ``tee`` serve no HTTP.
_STREAMING_PACKAGES = ("messagefoundry", "messagefoundry_webconsole", "messagefoundry_toolkit")

#: ``StreamingResponse`` bodies the guard accepts, as ``path:line`` to the reason. Empty today. A
#: body that really blocks, such as a file read, needs a thread, so it belongs here with its reason.
_STREAMING_ACCEPTED: dict[str, str] = {}


def _is_async_generator(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether ``func`` is an ``async def`` that itself yields. A ``yield`` inside a nested
    function, lambda or class belongs to that scope, and ``route_gates._own_nodes`` does not enter
    one."""
    return isinstance(func, ast.AsyncFunctionDef) and any(
        isinstance(node, ast.Yield | ast.YieldFrom) for node in route_gates._own_nodes(func)
    )


def _names_streaming_response(expr: ast.expr) -> bool:
    """``StreamingResponse`` or ``<anything>.StreamingResponse``, the shapes ``callee_name`` reads."""
    return (isinstance(expr, ast.Name) and expr.id == "StreamingResponse") or (
        isinstance(expr, ast.Attribute) and expr.attr == "StreamingResponse"
    )


def _sync_streaming_bodies(source: str, where: str) -> dict[str, str]:
    """Every ``StreamingResponse`` body in ``source`` that cannot be shown to be async, as
    ``where:line`` to what was found.

    Starlette steps a body that is not an ``AsyncIterable`` through ``iterate_in_threadpool``, one
    worker-thread hop per chunk (``starlette.responses.StreamingResponse.__init__``). The one shape
    this reads as async is a call to a function whose every definition in the module is an
    ``async def`` that yields. Anything else it sees is named, including a body it cannot resolve:
    a list, a name bound earlier, a sync generator, a call through an attribute. An aliased import
    and a subclass are named too, because either would hide a call from the walk.

    It reads names, not bindings, so at least these pass unseen: ``StreamingResponse`` bound to
    another name by assignment and called through it, a body function rebound by assignment beside
    an ``async def`` of the same name, and a decorator that turns an async generator into a sync
    iterator.
    """
    tree = parse_source(source)
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom | ast.Import):
            for alias in node.names:
                if alias.name.rpartition(".")[2] == "StreamingResponse" and alias.asname:
                    found[f"{where}:{node.lineno}"] = f"imported as {alias.asname}"
        elif isinstance(node, ast.ClassDef) and any(map(_names_streaming_response, node.bases)):
            found[f"{where}:{node.lineno}"] = f"class {node.name} subclasses StreamingResponse"
    for call in call_sites(tree, "StreamingResponse"):
        at = f"{where}:{call.lineno}"
        content = call.args[0] if call.args else None
        for keyword in call.keywords:
            if keyword.arg == "content":
                content = keyword.value
        if content is None:
            found[at] = "no body argument"
            continue
        body = ast.unparse(content)
        if not (isinstance(content, ast.Call) and isinstance(content.func, ast.Name)):
            found[at] = f"body {body} is not a call to a named function"
            continue
        candidates = find_funcs(tree, content.func.id)
        if not candidates:
            found[at] = f"body {body} calls a function not defined in this module"
        elif not all(_is_async_generator(d) for d in candidates):
            found[at] = f"body {body} calls a function that is not an async generator"
    return found


def test_no_streaming_response_is_handed_a_sync_body() -> None:
    """THE GUARD BACKLOG #2918 asks for (ASVS 15.4.4). Starlette steps a sync body through a worker
    thread once per chunk, so a large export would share the pool every sync dependency above is
    kept out of. No ``StreamingResponse`` in the product packages is handed a body the guard cannot
    show is an async generator. A new one fails here, named by file and line.

    The fix is an ``async def`` generator, as ``_iter_csv`` in ``export_audit`` and
    ``_iter_ndjson`` in the message export are. A body that really blocks goes in
    :data:`_STREAMING_ACCEPTED` with its reason.

    A file whose text never spells ``StreamingResponse`` is not parsed: every shape the classifier
    names (a call, an aliased import, a subclass) spells it, and parsing the whole tree cost about
    8 s a run."""
    root = Path(__file__).resolve().parents[1]
    calls = 0
    found: dict[str, str] = {}
    for package in _STREAMING_PACKAGES:
        for path in sorted((root / package).rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            if "StreamingResponse" not in source:
                continue
            calls += len(call_sites(parse_source(source), "StreamingResponse"))
            found.update(_sync_streaming_bodies(source, path.relative_to(root).as_posix()))
    # Coverage beside the verdict: the audit export and the message export each make one call, and
    # this counts calls in code, not mentions, so a walk that stops finding them cannot pass.
    assert calls >= 2, calls
    assert {at: why for at, why in found.items() if at not in _STREAMING_ACCEPTED} == {}


_PLANTED_STREAMING = """
from fastapi.responses import StreamingResponse
from fastapi import responses
from starlette.responses import StreamingResponse as Aliased  # named

async def good():
    yield "a"

def sync_gen():
    yield "a"

async def no_yield():
    def nested():
        yield "the nested def's, not this one's"
    return nested()

async def twice():
    yield "a"

def twice():
    yield "a"

class Mine(StreamingResponse):  # named
    pass

def route(rows):
    StreamingResponse(good())
    StreamingResponse(content=good())
    StreamingResponse(sync_gen())  # named
    responses.StreamingResponse(sync_gen())  # named
    StreamingResponse(no_yield())  # named
    StreamingResponse(twice())  # named
    StreamingResponse(iter(rows))  # named
    StreamingResponse(rows)  # named
    StreamingResponse(elsewhere())  # named
    StreamingResponse(media_type="text/csv")  # named
"""


def test_the_streaming_guard_names_what_was_planted() -> None:
    """THE CONTROL for :func:`test_no_streaming_response_is_handed_a_sync_body`. One sync or
    unresolvable body is planted on each branch of the classifier, each line marked ``# named``,
    beside two async bodies, one positional and one by keyword. The guard names exactly the marked
    lines."""
    lines = _PLANTED_STREAMING.splitlines()
    marked = {f"planted.py:{n}" for n, line in enumerate(lines, 1) if line.endswith("# named")}
    found = _sync_streaming_bodies(_PLANTED_STREAMING, "planted.py")
    assert set(found) == marked, found
    assert len(marked) == 10
    reasons = sorted(found.values())
    assert sum("not an async generator" in why for why in reasons) == 4, reasons
    assert sum("not defined in this module" in why for why in reasons) == 2, reasons
