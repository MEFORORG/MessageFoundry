#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SINGLE derivation of a route's authorization gate, read from the LIVE app.

THE DEFECT THIS EXISTS FOR. A hand-kept route -> permission list goes stale the day a route lands, so
the only trustworthy expectation is one derived from the running application object. Worse, the
derivation itself is fragile in a way this repo has already MEASURED:
``messagefoundry/api/security.py`` (see the ``require()`` docstring) records a refactor that routed
``require()``'s body through a private helper, which renamed the returned closure's ``__qualname__`` —
and because the gate is recognised by exactly that qualname, EVERY route silently read as UNGATED. A
guard built on this walk therefore has a failure mode where it keeps passing while measuring nothing,
which is why every consumer must floor the number of gated rows it found rather than trusting a clean
result. There is deliberately ONE implementation of the walk (this module), consumed by both the
``docs/SECURITY.md`` drift guard and the DAST sweep: two copies would be free to disagree, and the
disagreement would be invisible.

A GATE IS RECOGNISED BY A MARK, NOT A NAME (vault BACKLOG #2604). The qualname is still what a row
reports, but whether a dependency IS a gate is now the mark its factory sets through
``messagefoundry.api.security.mark_route_gate``. The engine refuses at request time any route that
carries neither that mark nor a public declaration, and it reads the same mark, so the walk and the
refusal cannot disagree about what a gate is. The walk also descends into an included router and into
a mounted application with routes, and :func:`full_surface_app` builds the app with every
route-registering flag on.

WEBSOCKET ROUTES ARE READ, NOT ASSUMED (BACKLOG #2057). The HTTP walk reads the dependency closures
FastAPI attached to a route. ``/ws/stats`` has none: it authorizes inside its own endpoint body, first
through the web console's cookie hook (``app.state.ui_ws_authorize``, which ``mount_ui`` fills with
``authorize_ui_ws``) and then through the engine's header gate ``authorize_ws``. An earlier revision
wrote every WebSocket gate as ``authorize_ws`` and scraped permissions by substring, so the cookie gate
was invisible and a ``Permission`` named only in a comment counted. :func:`websocket_gates` now reads
the endpoint's AST: every call whose callee resolves, against the LIVE app, to a function named
``authorize`` or ``authorize_*`` is a gate, in the order written, and its permissions come from that
call's own ``Permission.X`` arguments. A hook slot the app leaves empty is skipped, because that gate
never runs there. A ``Permission`` the endpoint names that no gate read demands raises rather than
letting the route under-report. The row carries the first gate as ``gate`` and the whole chain as ``gates``.
The HTTP-only helpers still filter the WebSocket row out explicitly, and a consumer that probes over
HTTP must report it as excluded rather than let it vanish into the background.

NOTHING FALLS OFF THE END OF THE WALK. An earlier revision classified only ``APIRoute`` and
``APIWebSocketRoute`` and dropped everything else with no row and no report — so a plain Starlette
``Route`` (``/openapi.json``, ``/docs``, ``/redoc``, all anonymous 200s when ``expose_docs`` is on) or a
static ``Mount`` (``/ui/static`` when ``serve_ui`` is on) was invisible to the ungated-set invariant,
whose entire stated purpose is that an ungated route must red a run rather than join the background.
:func:`route_rows` now emits every remaining route as an UNGATED row (a mount, which has no methods,
under the synthetic method :data:`MOUNT_METHOD`), so a route class this walk does not understand lands
in :func:`ungated_http_rows` and must be reviewed into a consumer's allow-list to pass.

EACH ROW SAYS WHAT THE REFUSAL MAKES OF IT (vault BACKLOG #2846). "No gate" covered two routes that
mean opposite things: one public by design, and one the engine refuses to every caller. A row's
``kind`` now separates them (``KIND_GATED``, ``KIND_PUBLIC``, ``KIND_IN_BODY``, ``KIND_REFUSED`` or
``KIND_OUTSIDE``), decided by the engine's own ``route_is_declared``, and ``declaration`` carries the
reason a ``public_route`` or ``authorizes_in_body`` mark gives.

This is a LIBRARY: no argparse, no ``main()``. It imports cleanly with only the engine installed.
"""

from __future__ import annotations

import ast
import functools
import inspect
import linecache
import re
import types
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from fastapi import FastAPI
from fastapi import routing as fastapi_routing
from fastapi.routing import APIRoute, APIWebSocketRoute
from starlette.applications import Starlette
from starlette.routing import BaseRoute, Mount

from messagefoundry.api.app import create_app
from messagefoundry.api.security import (
    is_route_gate,
    refusal_runs_on,
    route_declaration_of,
    route_has_gate,
    route_is_declared,
)
from messagefoundry.auth.permissions import Permission

#: Substituted for every ``{path_param}`` when a template must become a concrete request target. It is
#: deliberately a recognisable, non-existent identifier: a probe must never name a real resource, and a
#: reader of an access log should be able to tell instantly that the request came from the sweep.
PATH_PARAM_PLACEHOLDER = "dast-probe"

#: HTTP methods FastAPI synthesises rather than the application declaring them. Excluded so a single
#: declared route does not inflate the row count with verbs nobody wrote a gate for.
_SYNTHETIC_METHODS = ("HEAD", "OPTIONS")

#: The synthetic method assigned to a WebSocket route (see the module blind-spot note).
WS_METHOD = "WS"

#: The synthetic method assigned to a route that declares no methods at all — a ``Mount``. It is a
#: real HTTP-reachable surface, so it is emitted as an UNGATED row rather than dropped.
MOUNT_METHOD = "MOUNT"

# What the engine's request-time refusal (``refuse_undeclared_route``) makes of a row, so a reader of
# the walk can tell a route public by design from one refused to every caller (vault BACKLOG #2846).
RouteKind = Literal["gated", "public", "in-body", "refused", "outside"]
#: A top-level dependency carries the gate mark.
KIND_GATED: Final[RouteKind] = "gated"
#: No gate; the endpoint is marked ``public_route``, and the row's ``declaration`` is its reason.
KIND_PUBLIC: Final[RouteKind] = "public"
#: A WebSocket with no gate dependency whose endpoint is marked ``authorizes_in_body``.
KIND_IN_BODY: Final[RouteKind] = "in-body"
#: Neither: the engine refuses this route to every caller.
KIND_REFUSED: Final[RouteKind] = "refused"
#: The refusal is not among the route's dependencies: a mount, a plain Starlette route, or a route of
#: an app that does not install the refusal, such as a mounted application. ``declaration`` is still
#: reported when the endpoint carries one, but nothing enforces it there.
KIND_OUTSIDE: Final[RouteKind] = "outside"


@dataclass(frozen=True)
class RouteRow:
    """One (method, path) operation of the live app, with the authorization gate found on it.

    ``gate`` is ``None`` when no gate was found (for HTTP, no ``require*()`` dependency; for a
    WebSocket, none of what :func:`websocket_gates` reads) — i.e. the operation is anonymous. ``permissions`` holds the WIRE strings (``Permission.value``), not the enum members, so
    a consumer can compare against a role's granted set without importing the enum.

    ``gates`` is every gate the operation runs, in order, and ``gate`` is its first entry. They differ
    only on a WebSocket route that tries more than one gate: ``/ws/stats`` on an app with the web
    console mounted reads ``("authorize_ui_ws", "authorize_ws")``, the cookie gate then the header
    fallback.

    ``kind`` is one of the ``KIND_*`` values: what the engine's refusal makes of the route, read with
    the engine's own ``route_is_declared``. ``declaration`` is the reason the endpoint's
    ``public_route`` or ``authorizes_in_body`` mark gives, or ``None`` when it carries neither.
    """

    method: str
    path: str
    permissions: tuple[str, ...]
    gates: tuple[str, ...]
    kind: RouteKind
    declaration: str | None = None

    @property
    def gate(self) -> str | None:
        """The first gate the operation runs, or ``None`` when it runs none."""
        return self.gates[0] if self.gates else None


def gate_of(call: object) -> tuple[str, tuple[str, ...], str | None] | None:
    """``(gate name, permission wire strings, action)`` for a route dependency built by one of the
    ``require*()`` factories, by reading the closure cells the factory captured. Recurses through the
    ``base`` cell, because require_paced / require_phi_read / require_step_up* wrap ``require``'s
    closure. Returns ``None`` for a dependency that is not one of those factories.

    A gate is recognised by the mark its factory sets (``mark_route_gate``), never by its name
    (vault BACKLOG #2604). A dependency merely NAMED ``require_*`` is no gate, and the engine's
    request-time refusal agrees, because it reads the same mark."""
    if not is_route_gate(call):
        return None
    closure = getattr(call, "__closure__", None)
    code = getattr(call, "__code__", None)
    if closure is None or code is None:
        return None
    qualname = getattr(call, "__qualname__", "") or ""
    name = qualname.split(".")[0]
    cells = dict(zip(code.co_freevars, closure, strict=False))
    perms: tuple[str, ...] = ()
    action: str | None = None
    base_info: tuple[str, tuple[str, ...], str | None] | None = None
    for var, cell in cells.items():
        try:
            value = cell.cell_contents
        except ValueError:  # pragma: no cover - an empty cell cannot occur on a built dependency
            continue
        if var == "permissions" and isinstance(value, tuple):
            perms = tuple(p.value for p in value if isinstance(p, Permission))
        elif var == "action" and isinstance(value, str):
            action = value
        elif var == "base":
            base_info = gate_of(value)
    if not perms and base_info is not None:
        perms = base_info[1]
    return (name, perms, action)


#: Returned when resolving a name in a WebSocket endpoint (see :func:`websocket_gates`) that the walk
#: cannot bind to one object: a local that is not a plain ``app.state`` hook fetch, or a name found
#: nowhere.
_UNRESOLVED = object()


def _local_names(code: types.CodeType) -> set[str]:
    """Every name bound locally in ``code`` or in a function nested inside it."""
    names = set(code.co_varnames) | set(code.co_cellvars)
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            names |= _local_names(const)
    return names


def _state_fetch_slot(value: ast.expr | None, socket: str) -> str | None:
    """``"slot"`` when ``value`` is ``getattr(<socket>.app.state, "slot"[, None])``, else ``None``.

    Any other default is refused: an empty slot would then run the default, which the walk would
    otherwise skip as a gate that never runs."""
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "getattr"
        and not value.keywords
        and len(value.args) in (2, 3)
        and ast.unparse(value.args[0]) == f"{socket}.app.state"
        and isinstance(value.args[1], ast.Constant)
        and isinstance(value.args[1].value, str)
        and (
            len(value.args) == 2
            or (isinstance(value.args[2], ast.Constant) and value.args[2].value is None)
        )
    ):
        return value.args[1].value
    return None


def _bound_names(node: ast.AST) -> list[str]:
    """The names ``node`` binds: a stored ``Name``, a ``def`` or ``class``, an ``except ... as``, an
    import alias, or a ``match`` capture."""
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
        return [node.id]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
        return [node.name]
    if isinstance(node, ast.alias):
        return [node.asname or node.name.split(".")[0]]
    return []


def _state_hook_slots(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str | None]:
    """``{local name: app.state slot}`` for each local bound by ``getattr(<socket>.app.state, "slot")``.

    ``<socket>`` is the endpoint's first parameter. A name that is ALSO bound any other way (see
    :func:`_bound_names`), including in a nested scope, or fetched from two slots, maps to ``None``:
    the walk cannot tell which binding a call sees, so it must not guess the hook."""
    socket = func.args.args[0].arg if func.args.args else ""
    fetched: dict[str, set[str]] = {}
    fetches: dict[str, int] = {}
    stores: dict[str, int] = {}
    for node in (n for stmt in func.body for n in ast.walk(stmt)):
        for bound in _bound_names(node):
            stores[bound] = stores.get(bound, 0) + 1
        value: ast.expr | None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        slot = _state_fetch_slot(value, socket)
        if slot is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                fetched.setdefault(target.id, set()).add(slot)
                fetches[target.id] = fetches.get(target.id, 0) + 1
    return {
        name: (next(iter(slots)) if len(slots) == 1 and stores[name] == fetches[name] else None)
        for name, slots in fetched.items()
    }


@functools.lru_cache(maxsize=8)
def _module_tree(filename: str) -> ast.Module:
    """The parsed module an endpoint was defined in. The whole module is parsed, never a dedented
    snippet: a nested endpoint whose body holds a multi-line string at column 0 does not dedent."""
    return ast.parse("".join(linecache.getlines(filename)), filename)


def _endpoint_node(endpoint: object) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """The definition of ``endpoint`` in its module's AST, matched by name and first line."""
    code = getattr(endpoint, "__code__", None)
    filename = inspect.getsourcefile(endpoint) if callable(endpoint) else None
    if not isinstance(code, types.CodeType) or filename is None:
        raise ValueError(f"no source file for {endpoint!r}")
    for node in ast.walk(_module_tree(filename)):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == code.co_name
            and min([node.lineno, *(d.lineno for d in node.decorator_list)]) == code.co_firstlineno
        ):
            return node
    raise ValueError(f"no definition of {code.co_name} at {filename}:{code.co_firstlineno}")


def _own_nodes(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    """Every node in ``func``'s body, not descending into nested functions, lambdas or classes.

    A nested function (``ws_stats``'s ``_reauthorize``, say) runs after the handshake, so a call in
    it is not a handshake gate."""
    nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    found: list[ast.AST] = []
    stack: list[ast.AST] = list(func.body)
    while stack:
        node = stack.pop()
        found.append(node)
        if not isinstance(node, nested):
            stack.extend(ast.iter_child_nodes(node))
    return found


def websocket_gates(
    route: APIWebSocketRoute, app: Starlette
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(gate names in the order they run, permission wire strings)`` for one WebSocket route.

    ``app`` is the application the socket sees as ``websocket.app``: for a route inside a mounted
    application, that application rather than the outer one.

    A ``require*()`` dependency counts first, read by :func:`gate_of` as for HTTP. Then the endpoint's
    own body, not its nested functions: every bare-name call whose callee resolves to a coroutine
    function named ``authorize`` or ``authorize_*`` is a gate, and its positional arguments after the
    socket must each be a literal ``Permission.X``. An empty hook slot is skipped, since that gate
    never runs on this app. Gates are listed in the order written, which is the order they run for
    sequential calls; a gate nested inside another gate's arguments would be listed out of run order.

    Raises ``ValueError`` where reading on would under-report: a gate argument that is not a
    ``Permission`` literal; two gates demanding different permissions, which one ``permissions`` field
    cannot state; a ``Permission`` literal in the endpoint's own body that is not a read gate's
    argument; or one in a nested function that no read gate demands. Those last two rules are what
    catch a gate the walk does not recognise, such as one called through an attribute, a wrapped hook,
    or a permission passed by keyword. A gate with NO ``Permission`` argument that the walk does not
    recognise is still invisible; the tests floor every shipped WebSocket route at one gate."""
    chain: list[tuple[str, tuple[str, ...]]] = []
    for dep in route.dependant.dependencies:
        found = gate_of(dep.call)
        if found is not None:
            chain.append((found[0], found[1]))

    endpoint = inspect.unwrap(route.endpoint)
    try:
        func = _endpoint_node(endpoint)
    except (OSError, TypeError, SyntaxError, ValueError) as exc:
        raise ValueError(f"cannot read the source of WebSocket route {route.path}: {exc}") from exc
    slots = _state_hook_slots(func)
    code = getattr(endpoint, "__code__", None)
    # A local or a closure variable cannot be read from the module globals, so it stays unresolved.
    shadowed = (
        _local_names(code) | set(code.co_freevars) if isinstance(code, types.CodeType) else set()
    )
    namespace: dict[str, object] = getattr(endpoint, "__globals__", {})

    def resolve(name: str) -> object:
        """What a bare ``name`` in the endpoint calls on the LIVE app. A hook local resolves to what
        its state slot holds now (``None`` when empty); any other local is unresolved."""
        if name in slots:
            slot = slots[name]
            return _UNRESOLVED if slot is None else getattr(app.state, slot, None)
        if name in shadowed:
            return _UNRESOLVED
        return namespace.get(name, _UNRESOLVED)

    def permission_of(node: ast.AST) -> str | None:
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and resolve(node.value.id) is Permission
            and node.attr in Permission.__members__
        ):
            return Permission[node.attr].value
        return None

    consumed: set[int] = set()  # id() of each Permission literal a gate read or a skipped hook took
    own = _own_nodes(func)
    calls = sorted(
        (n for n in own if isinstance(n, ast.Call)),
        key=lambda n: (n.lineno, n.col_offset),
    )
    for call in calls:
        if not isinstance(call.func, ast.Name):
            continue
        target = resolve(call.func.id)
        name = getattr(target, "__name__", None)
        if (
            inspect.iscoroutinefunction(target)
            and isinstance(name, str)
            and (name == "authorize" or name.startswith("authorize_"))
        ):
            read = [permission_of(a) for a in call.args[1:]]
            unread = [ast.unparse(a) for a, p in zip(call.args[1:], read, strict=True) if p is None]
            if unread:
                raise ValueError(
                    f"WebSocket route {route.path}: gate {name} at line {call.lineno} is passed "
                    f"{unread}, which is not a Permission.X literal, so its permissions cannot be read"
                )
            consumed.update(id(a) for a in call.args[1:])
            chain.append((name, tuple(p for p in read if p is not None)))
        elif target is None and call.func.id in slots:
            # An empty app.state hook slot: this gate never runs on this app.
            consumed.update(id(n) for n in ast.walk(call))

    names = tuple(dict.fromkeys(name for name, _perms in chain))
    demanded = {frozenset(perms) for _name, perms in chain}
    if len(demanded) > 1:
        raise ValueError(
            f"WebSocket route {route.path}: its gates {chain} demand different permissions, which "
            "one RouteRow cannot state"
        )
    permissions = chain[0][1] if chain else ()
    own_ids = {id(n) for n in own}
    for node in (n for stmt in func.body for n in ast.walk(stmt)):
        value = permission_of(node)
        if value is None or id(node) in consumed:
            continue
        # In the handshake body every Permission must be a gate's argument: one passed anywhere else
        # is a check the walk did not read, even when a read gate demands the same permission. A
        # nested function (a revalidation, say) may repeat a demanded permission.
        if id(node) in own_ids or value not in permissions:
            raise ValueError(
                f"WebSocket route {route.path}: {ast.unparse(node)} at line "
                f"{getattr(node, 'lineno', '?')} is not demanded by any gate the walk read "
                f"({names or 'none'}). Teach route_gates to read the check that uses it rather than "
                "let the route under-report."
            )
    return names, permissions


def _effective_routes(routes: Sequence[BaseRoute]) -> Iterator[tuple[BaseRoute, Any]]:
    """``(route, effective)`` for each route, with every ``include_router`` call unpacked.

    FastAPI 0.139 and later keep an included router as one opaque object on the app, and serve its
    routes through an effective context that carries the include's prefix and dependencies.
    ``effective`` is that context, read through FastAPI's ``iter_route_contexts``, or the route itself
    where there is no include. The walk takes the PATH and methods from it, and the gate from the
    route's own dependencies. An older FastAPI copied included routes onto the app, so there the
    plain list is already complete."""
    iterate = getattr(fastapi_routing, "iter_route_contexts", None)
    if iterate is None:  # pragma: no cover - only an older FastAPI than the lock pins
        for route in routes:
            yield route, route
        return
    for context in iterate(routes):
        original: BaseRoute = context.original_route
        if isinstance(original, APIRoute):
            yield original, context
        else:
            # A non-API route reached through an include is served by a rebuilt copy that carries
            # the include's prefix and, for a WebSocket, its dependencies.
            yield original, getattr(context, "starlette_route", None) or original


def _kind(declared_on: Any, effective: Any, *, websocket: bool) -> tuple[RouteKind, str | None]:
    """``(kind, declaration reason)`` for one API route, as the engine's refusal sees it.

    ``declared_on`` is the route object the refusal reads, and ``effective`` is the one FastAPI
    serves, whose dependencies say whether the refusal runs at all. The decision is the engine's own
    ``route_is_declared``, read through the same helpers the refusal uses.

    The walk reads no ``dependency_overrides``. That cuts both ways, at least: an app that overrides
    the refusal reads as refused here while it serves the route, and one that overrides a gate
    reads as gated here while it serves the route to anyone."""
    declaration = route_declaration_of(getattr(declared_on, "endpoint", None))
    reason = declaration.reason if declaration is not None else None
    if not refusal_runs_on(effective):
        return KIND_OUTSIDE, reason
    if not route_is_declared(declared_on, websocket=websocket):
        return KIND_REFUSED, reason
    if route_has_gate(declared_on):
        return KIND_GATED, reason
    assert declaration is not None  # route_is_declared found no gate, so a declaration passed it
    return (KIND_PUBLIC if declaration.public else KIND_IN_BODY), reason


def _state_owner(mount: Mount, outer: Starlette) -> Starlette:
    """The app whose ``state`` a socket under ``mount`` reads as ``websocket.app.state``.

    Every Starlette app sets ``scope["app"]`` to itself as a request enters it, so a socket inside a
    mounted application sees that application, not the outer one (vault BACKLOG #2846). A mount of
    bare routes has no app of its own, so its sockets still see ``outer``. The app is read from the
    same object ``Mount.routes`` reads, beneath any middleware the mount wraps around it."""
    # ``_base_app`` is private to Starlette; a test pins it, so a rename reds a run rather than
    # quietly reading a middleware-wrapped mount against ``outer`` again.
    base = getattr(mount, "_base_app", mount.app)
    return base if isinstance(base, Starlette) else outer


def _walk(routes: Sequence[BaseRoute], prefix: str, app: Starlette) -> Iterator[RouteRow]:
    for route, effective in _effective_routes(routes):
        path = prefix + (getattr(effective, "path", None) or "")
        if isinstance(route, APIRoute):
            kind, declaration = _kind(route, effective, websocket=False)
            methods = sorted(m for m in (effective.methods or set()) if m not in _SYNTHETIC_METHODS)
            gate: tuple[str, tuple[str, ...], str | None] | None = None
            # The route's OWN dependencies, never the include's: the engine's request-time refusal
            # reads only those, so a gate an include call adds is refused there and must read as
            # no gate here too.
            for dep in route.dependant.dependencies:
                found = gate_of(dep.call)
                if found is not None:
                    gate = found
                    break
            for method in methods:
                yield RouteRow(
                    method=method,
                    path=path,
                    permissions=gate[1] if gate else (),
                    gates=(gate[0],) if gate else (),
                    kind=kind,
                    declaration=declaration,
                )
        elif isinstance(effective, APIWebSocketRoute):
            # A WebSocket reached through an include is served by a rebuilt route that carries the
            # include's dependencies, and that rebuilt route is what the engine's refusal reads, so
            # the walk reads it too.
            names, perms = websocket_gates(effective, app)
            kind, declaration = _kind(effective, effective, websocket=True)
            yield RouteRow(
                method=WS_METHOD,
                path=path,
                permissions=perms,
                gates=names,
                kind=kind,
                declaration=declaration,
            )
        elif isinstance(effective, Mount) and effective.routes:
            # A mounted application with routes of its own. Its routes are walked under the mount's
            # path, so one the engine's refusal cannot reach still shows up here as ungated. Its
            # sockets read their hooks from the mounted app's state, so the walk reads that too.
            yield from _walk(effective.routes, path, _state_owner(effective, app))
        else:
            # Anything else Starlette mounted: a plain ``Route`` (the OpenAPI/docs endpoints) or a
            # ``Mount`` with no routes (the /ui static tree). It carries no FastAPI dependency
            # closure, so it can only be reported as UNGATED — which is honest, because that is
            # exactly what it is. Emitting it here is what stops it falling off the end of the walk
            # and out of the ungated-set invariant; see the module docstring.
            declared = sorted(
                m
                for m in (getattr(effective, "methods", None) or set())
                if m not in _SYNTHETIC_METHODS
            )
            marked = route_declaration_of(getattr(effective, "endpoint", None))
            for method in declared or [MOUNT_METHOD]:
                yield RouteRow(
                    method=method,
                    path=path,
                    permissions=(),
                    gates=(),
                    kind=KIND_OUTSIDE,
                    declaration=marked.reason if marked is not None else None,
                )


def route_rows(app: FastAPI | None = None) -> list[RouteRow]:
    """Every route operation of ``app`` (a default ``create_app()`` when ``None``).

    ``app`` is optional so a caller that has ALREADY configured a target — the DAST sweep brings up
    one app instance and probes that exact object — derives its expectation from the same application
    it is talking to, rather than from a second, differently-configured one.

    The walk descends into every included router and into every mounted application that has routes
    of its own (vault BACKLOG #2604). The default app is built with no flag on; use
    :func:`full_surface_app` for every route the engine can register.
    """
    target = create_app() if app is None else app
    return list(_walk(target.routes, "", target))


#: The ``create_app`` flags that register routes. ``oidc_enabled`` registers its routes only beside
#: ``serve_ui``; an ``auth`` service with OIDC on registers the same ones. A test flips every boolean
#: ``create_app`` takes, and tries a listed value for every other parameter, and checks that none adds
#: a route :func:`full_surface_app` lacks. A new flag that registers routes reds a run until it is
#: listed here, and a new non-boolean parameter reds one until the test lists it (vault BACKLOG #2846).
ROUTE_REGISTERING_FLAGS: tuple[str, ...] = ("expose_docs", "serve_ui", "oidc_enabled")


def full_surface_app(**kwargs: Any) -> FastAPI:
    """A ``create_app(**kwargs)`` with every flag in :data:`ROUTE_REGISTERING_FLAGS` on, so a route
    that only one flag registers is walked too."""
    flags: dict[str, Any] = dict.fromkeys(ROUTE_REGISTERING_FLAGS, True)
    return create_app(**{**flags, **kwargs})


def gated_http_rows(app: FastAPI | None = None) -> list[RouteRow]:
    """HTTP operations carrying a ``require*()`` gate. The WebSocket row is excluded because it cannot
    be probed with an HTTP request; a consumer must report that exclusion, not absorb it."""
    return [r for r in route_rows(app) if r.gate is not None and r.method != WS_METHOD]


def ungated_http_rows(app: FastAPI | None = None) -> list[RouteRow]:
    """HTTP operations with NO ``require*()`` gate — the anonymous surface. A consumer is expected to
    assert this set equals a reviewed allow-list, so a newly ungated route reds a run rather than
    quietly joining the background."""
    return [r for r in route_rows(app) if r.gate is None and r.method != WS_METHOD]


def concrete_path(path: str, placeholder: str = PATH_PARAM_PLACEHOLDER) -> str:
    """A route TEMPLATE rendered as a requestable path, e.g. ``/messages/{message_id}`` ->
    ``/messages/dast-probe``."""
    return re.sub(r"\{[^}]+\}", placeholder, path)
