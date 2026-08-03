#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

THE BLIND SPOT, stated rather than hidden. This walk reads the dependency closures FastAPI attached to
a route. A route that authorizes inside its own endpoint body is therefore invisible to it — the
``/ws/stats`` WebSocket is exactly that case. It is not silently dropped: :func:`route_rows` emits it
with the synthetic method ``"WS"`` and the gate name ``"authorize_ws"``, its permissions scraped from
the endpoint source, and the HTTP-only helpers filter it out explicitly. A consumer that probes over
HTTP must report the WebSocket row as excluded rather than let it vanish into the background.

NOTHING FALLS OFF THE END OF THE WALK. An earlier revision classified only ``APIRoute`` and
``APIWebSocketRoute`` and dropped everything else with no row and no report — so a plain Starlette
``Route`` (``/openapi.json``, ``/docs``, ``/redoc``, all anonymous 200s when ``expose_docs`` is on) or a
static ``Mount`` (``/ui/static`` when ``serve_ui`` is on) was invisible to the ungated-set invariant,
whose entire stated purpose is that an ungated route must red a run rather than join the background.
:func:`route_rows` now emits every remaining route as an UNGATED row (a mount, which has no methods,
under the synthetic method :data:`MOUNT_METHOD`), so a route class this walk does not understand lands
in :func:`ungated_http_rows` and must be reviewed into a consumer's allow-list to pass.

This is a LIBRARY: no argparse, no ``main()``. It imports cleanly with only the engine installed.
"""

from __future__ import annotations

import inspect
import re
from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.routing import APIRoute, APIWebSocketRoute

from messagefoundry.api.app import create_app
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


@dataclass(frozen=True)
class RouteRow:
    """One (method, path) operation of the live app, with the authorization gate found on it.

    ``gate`` is ``None`` when no ``require*()`` dependency was found — i.e. the operation is
    anonymous. ``permissions`` holds the WIRE strings (``Permission.value``), not the enum members, so
    a consumer can compare against a role's granted set without importing the enum.
    """

    method: str
    path: str
    permissions: tuple[str, ...]
    gate: str | None


def gate_of(call: object) -> tuple[str, tuple[str, ...], str | None] | None:
    """``(gate name, permission wire strings, action)`` for a route dependency built by one of the
    ``require*()`` factories, by reading the closure cells the factory captured. Recurses through the
    ``base`` cell, because require_paced / require_phi_read / require_step_up* wrap ``require``'s
    closure. Returns ``None`` for a dependency that is not one of those factories."""
    closure = getattr(call, "__closure__", None)
    code = getattr(call, "__code__", None)
    if closure is None or code is None:
        return None
    qualname = getattr(call, "__qualname__", "") or ""
    name = qualname.split(".")[0]
    if not name.startswith("require"):
        return None
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


def route_rows(app: FastAPI | None = None) -> list[RouteRow]:
    """Every route operation of ``app`` (a default ``create_app()`` when ``None``).

    ``app`` is optional so a caller that has ALREADY configured a target — the DAST sweep brings up
    one app instance and probes that exact object — derives its expectation from the same application
    it is talking to, rather than from a second, differently-configured one.
    """
    rows: list[RouteRow] = []
    target = create_app() if app is None else app
    for route in target.routes:
        if isinstance(route, APIRoute):
            methods = sorted(m for m in (route.methods or set()) if m not in _SYNTHETIC_METHODS)
            gate: tuple[str, tuple[str, ...], str | None] | None = None
            for dep in route.dependant.dependencies:
                found = gate_of(dep.call)
                if found is not None:
                    gate = found
                    break
            for method in methods:
                rows.append(
                    RouteRow(
                        method=method,
                        path=route.path,
                        permissions=gate[1] if gate else (),
                        gate=gate[0] if gate else None,
                    )
                )
        elif isinstance(route, APIWebSocketRoute):
            # The WS route authorizes inside the endpoint body, so read its source for the constant.
            source = inspect.getsource(route.endpoint)
            perms = tuple(p.value for p in Permission if f"Permission.{p.name}" in source)
            rows.append(
                RouteRow(method=WS_METHOD, path=route.path, permissions=perms, gate="authorize_ws")
            )
        else:
            # Anything else Starlette mounted: a plain ``Route`` (the OpenAPI/docs endpoints) or a
            # ``Mount`` (the /ui static tree). It carries no FastAPI dependency closure, so it can only
            # be reported as UNGATED — which is honest, because that is exactly what it is. Emitting it
            # here is what stops it falling off the end of the walk and out of the ungated-set
            # invariant; see the module docstring.
            declared = sorted(
                m for m in (getattr(route, "methods", None) or set()) if m not in _SYNTHETIC_METHODS
            )
            for method in declared or [MOUNT_METHOD]:
                rows.append(
                    RouteRow(
                        method=method, path=getattr(route, "path", ""), permissions=(), gate=None
                    )
                )
    return rows


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
