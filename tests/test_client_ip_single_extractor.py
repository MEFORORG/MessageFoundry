# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``api.security.client_ip`` is the only reader of the ASGI client address (BACKLOG #2289).

Login writes the session's address anchor and ``flag_new_client_ip`` compares a later request
against it. The audit rows and the per-IP rate limiters use the same address. If two of those read
the address two ways, a change to one (say, a new proxy rule) would split the anchor from the
comparison, and the new-IP signal would fire on every request or never. So every read goes through
``client_ip``, and this guard fails when a new raw read appears anywhere outside the allow-list.

It reads the SOURCE tree with ``ast``, never the imported modules, so it judges the files under
review even when a venv holds a frozen copy of the console package. Comments and docstrings never
reach the tree, so a mention of ``request.client.host`` in prose is not an offence.

What it counts as a raw read, at least:

- ``<x>.client.host`` and ``<x>.client.port``, on any object;
- ``<conn>.client`` on its own, where ``<conn>`` is a name a route uses for a connection, which is
  the aliased form ``c = request.client`` followed by ``c.host``;
- ``scope["client"]`` and ``scope.get("client")``, bare or as ``request.scope``.

A name heuristic, not type inference: a connection held under some other name, such as ``r``,
passes. The planted controls below pin the shapes it does catch.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

#: Every package that serves or handles an HTTP or WebSocket request. The harness is a CLIENT of the
#: engine and reads no peer address today; it is scanned so that stays true.
_SCANNED = ("messagefoundry", "messagefoundry_webconsole", "harness")

#: Names a route or dependency gives a Starlette connection.
_CONN_NAMES = frozenset({"request", "websocket", "conn", "connection", "ws", "req"})

#: ``(path, enclosing function) -> raw reads expected there``, each with the reason it stays raw.
#: The count is exact, so a site that moves or goes away reds here too and the list cannot go stale.
_ALLOWED: dict[tuple[str, str], int] = {
    # The extractor itself: ``conn.client.host if conn.client else None`` is three matching nodes.
    ("messagefoundry/api/security.py", "client_ip"): 3,
    # The [security].allowed_client_networks gate. It is raw ASGI middleware with a scope and no
    # Request, so it cannot call client_ip. It runs inside uvicorn's ProxyHeadersMiddleware and so
    # reads the same rewritten scope (ADR 0151, D-1).
    ("messagefoundry/api/client_networks.py", "ClientNetworkMiddleware.__call__"): 1,
    # /health's observed_client echo. It exists to tell a locked-out operator which address the
    # gate above matched, so it must read what the gate reads, whatever client_ip does.
    ("messagefoundry/api/app.py", "create_app.health"): 3,
}


def _is_scope(node: ast.expr) -> bool:
    """``scope`` or ``<anything>.scope``."""
    return (isinstance(node, ast.Name) and node.id == "scope") or (
        isinstance(node, ast.Attribute) and node.attr == "scope"
    )


def _is_raw_read(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        # <x>.client.host / <x>.client.port, whatever <x> is.
        if (
            node.attr in ("host", "port")
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "client"
        ):
            return True
        # request.client, websocket.client, conn.client: the aliasable form.
        return (
            node.attr == "client"
            and isinstance(node.value, ast.Name)
            and node.value.id in _CONN_NAMES
        )
    if isinstance(node, ast.Subscript):
        return (
            _is_scope(node.value)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == "client"
        )
    if isinstance(node, ast.Call):
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and _is_scope(node.func.value)
            and bool(node.args)
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "client"
        )
    return False


def _raw_reads(tree: ast.AST) -> list[tuple[str, int, str]]:
    """``(enclosing function qualname, line, source)`` for each raw read.

    ``<x>.client.host`` holds an inner ``<x>.client`` that matches too when ``<x>`` is a connection
    name, so one inline read counts once per node that matches. The allow-list counts are written
    against that rule."""
    found: list[tuple[str, int, str]] = []

    def visit(node: ast.AST, scope: tuple[str, ...]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = (*scope, node.name)
        if _is_raw_read(node):
            found.append((".".join(scope), getattr(node, "lineno", 0), ast.unparse(node)))
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(tree, ())
    return found


def _scan() -> dict[tuple[str, str], list[tuple[int, str]]]:
    sites: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for package in _SCANNED:
        for path in sorted((_ROOT / package).rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
            for func, line, text in _raw_reads(tree):
                sites.setdefault((rel, func), []).append((line, text))
    return sites


def test_only_client_ip_reads_the_client_address() -> None:
    """RED when: a raw client-address read appears outside the allow-list, or an allowed site's read
    count changes. Route the new read through ``api.security.client_ip``; if it truly needs the raw
    peer, add it to ``_ALLOWED`` with the reason."""
    sites = _scan()
    # The allowed sites are the positive control on the live tree: a walk that found nothing would
    # fail here before the absence check below could pass for the wrong reason.
    assert sites
    counts = {key: len(sites.get(key, [])) for key in _ALLOWED}
    assert counts == _ALLOWED, (
        f"an allowed site changed (expected {_ALLOWED}, found {counts}); re-check its reason"
    )
    extra = {key: sites[key] for key in sites if key not in _ALLOWED}
    assert extra == {}, (
        f"raw client-address reads outside client_ip; use api.security.client_ip(request): {extra}"
    )


def test_the_guard_finds_a_reverted_route_read() -> None:
    """Positive control on real code: put back one of the reads BACKLOG #2289 removed, into the real
    console login route's source, and the scan must see it. A walk that matched nothing would pass
    the guard above for the wrong reason."""
    path = _ROOT / "messagefoundry_webconsole" / "routes" / "core.py"
    source = path.read_text(encoding="utf-8")
    fixed = "client = client_ip(request)"
    assert fixed in source, "the control's anchor is gone; re-aim it at a live client_ip site"
    reverted = source.replace(fixed, "client = request.client.host if request.client else None", 1)
    after = _raw_reads(ast.parse(reverted))
    assert len(after) == 3, after  # request.client twice, request.client.host once
    assert _raw_reads(ast.parse(source)) == []


@pytest.mark.parametrize(
    ("source", "offending"),
    [
        pytest.param("c = request.client.host if request.client else None", True, id="inline"),
        pytest.param("c = websocket.client.host", True, id="websocket"),
        pytest.param("c = conn.client.port", True, id="port"),
        pytest.param("peer = request.client", True, id="aliased-object"),
        pytest.param("c = request.scope['client'][0]", True, id="aliased-scope"),
        pytest.param("c = scope.get('client')", True, id="scope-get"),
        pytest.param("c = request.scope.get('client')", True, id="request-scope-get"),
        pytest.param("c = anything.client.host", True, id="any-receiver"),
        pytest.param("c = client_ip(request)", False, id="through-client-ip"),
        pytest.param("c = row['client']", False, id="audit-row-field"),
        pytest.param("c = session.get('client')", False, id="session-dict"),
        pytest.param("c = self.client", False, id="own-attribute"),
        pytest.param("import http.client", False, id="stdlib-module"),
        pytest.param("c = ctx.client", False, id="harness-context"),
    ],
)
def test_the_raw_read_guard_discriminates(source: str, offending: bool) -> None:
    """The guard's own control: each planted shape it exists to catch reads as an offence, and the
    neighbouring shapes that are not an address read do not."""
    found = _raw_reads(ast.parse(f"def f():\n    {source}\n"))
    assert bool(found) is offending, found
