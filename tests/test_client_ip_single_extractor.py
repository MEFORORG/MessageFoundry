# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No code reads the ASGI client address except ``api.security.client_ip`` (BACKLOG #2289).

Login writes the session's address anchor and ``flag_new_client_ip`` compares a later request
against it. The audit rows, the per-IP rate limiters and the ``[security].allowed_client_networks``
gate use the same address. If two of those read the address two ways, a change to one (say, a new
proxy rule) would split the anchor from the comparison, and the new-IP signal would fire on every
request or never. So every read goes through ``client_ip``, and this guard fails when a new raw
read of a shape below appears outside it.

It reads the SOURCE tree with ``ast``, never the imported modules, so it judges the files under
review even when a venv holds a frozen copy of the console package. Comments and docstrings never
reach the tree, so a mention of ``request.client.host`` in prose is not an offence.

What it counts as a raw read:

- ``<x>.client.host`` and ``<x>.client.port``, on any object;
- on a connection name (``request``, ``websocket``, ``conn``, ``ws``): ``<conn>.client``, which is
  the aliased form ``c = request.client`` followed by ``c.host``; Starlette's mapping access
  ``<conn>["client"]`` and ``<conn>.get("client")``; and ``getattr(<conn>, "client")``;
- ``scope["client"]`` and ``scope.get("client")``, bare or as ``request.scope``.

It is a name heuristic, not type inference, so at least these pass unseen: a connection held under
another name, such as ``r``, and a scope aliased first, as in ``s = request.scope`` then
``s["client"]``. The planted controls below pin the shapes it catches and those two gaps.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

#: Every package that serves or handles an HTTP or WebSocket request. The harness is a CLIENT of the
#: engine and reads no peer address today; it is scanned so that stays true.
_SCANNED = ("messagefoundry", "messagefoundry_webconsole", "harness")

#: Names a route, dependency or middleware gives a Starlette connection. ``req`` and ``connection``
#: are left out: the engine uses them for request-body models and for connection config, where a
#: ``client`` field would be a false offence.
_CONN_NAMES = frozenset({"request", "websocket", "conn", "ws"})

#: ``(path, enclosing function) -> raw reads expected there``. The count is exact, so a site that
#: moves or goes away reds here too and the list cannot go stale. A new entry needs a stated reason
#: that the site wants the raw peer rather than the client address.
_ALLOWED: dict[tuple[str, str], int] = {
    # The extractor itself: ``conn.client.host if conn.client else None`` is three matching nodes.
    ("messagefoundry/api/security.py", "client_ip"): 3,
}


def _is_scope(node: ast.expr) -> bool:
    """``scope`` or ``<anything>.scope``."""
    return (isinstance(node, ast.Name) and node.id == "scope") or (
        isinstance(node, ast.Attribute) and node.attr == "scope"
    )


def _is_conn(node: ast.expr) -> bool:
    return isinstance(node, ast.Name) and node.id in _CONN_NAMES


def _is_client_key(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value == "client"


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
        return node.attr == "client" and _is_conn(node.value)
    if isinstance(node, ast.Subscript):
        # scope["client"], request.scope["client"], and Starlette's request["client"].
        return (_is_scope(node.value) or _is_conn(node.value)) and _is_client_key(node.slice)
    if isinstance(node, ast.Call) and node.args:
        func = node.func
        # scope.get("client"), request.scope.get("client"), request.get("client").
        if isinstance(func, ast.Attribute) and func.attr == "get":
            return (_is_scope(func.value) or _is_conn(func.value)) and _is_client_key(node.args[0])
        # getattr(request, "client"), with or without a default.
        if isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2:
            return _is_conn(node.args[0]) and _is_client_key(node.args[1])
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


def _parse(path: Path) -> ast.Module:
    # utf-8-sig: a byte-order mark would otherwise fail the parse for a reason that has nothing to
    # do with client addresses.
    return ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))


def _scan() -> dict[tuple[str, str], list[tuple[int, str]]]:
    sites: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for package in _SCANNED:
        for path in sorted((_ROOT / package).rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            for func, line, text in _raw_reads(_parse(path)):
                sites.setdefault((rel, func), []).append((line, text))
    return sites


def test_only_client_ip_reads_the_client_address() -> None:
    """RED when: a raw client-address read appears outside ``client_ip``, or ``client_ip``'s own read
    changes shape. Route the new read through ``api.security.client_ip``; if it truly needs the raw
    peer, add it to ``_ALLOWED`` with the reason."""
    sites = _scan()
    # client_ip's own read is the positive control on the live tree: a walk that found nothing
    # would fail here before the absence check below could pass for the wrong reason.
    assert sites
    counts = {key: len(sites.get(key, [])) for key in _ALLOWED}
    assert counts == _ALLOWED, (
        f"an allowed site changed (expected {_ALLOWED}, found {counts}); re-check its reason"
    )
    extra = {key: sites[key] for key in sites if key not in _ALLOWED}
    assert extra == {}, (
        f"raw client-address reads outside client_ip; use api.security.client_ip(request): {extra}"
    )


@pytest.mark.parametrize(
    ("relpath", "fixed", "reverted", "expected"),
    [
        pytest.param(
            "messagefoundry_webconsole/routes/core.py",
            "client = client_ip(request)",
            "client = request.client.host if request.client else None",
            3,  # request.client twice, request.client.host once
            id="console-login",
        ),
        pytest.param(
            "messagefoundry/api/client_networks.py",
            "host = client_ip(HTTPConnection(scope))",
            "host = scope.get('client')",
            1,
            id="network-gate",
        ),
    ],
)
def test_the_guard_finds_a_reverted_read(
    relpath: str, fixed: str, reverted: str, expected: int
) -> None:
    """Positive control on real code: put back a read BACKLOG #2289 removed, in its real file, and
    the scan must see it. A walk that matched nothing would pass the guard above for the wrong
    reason."""
    source = (_ROOT / relpath).read_text(encoding="utf-8-sig")
    assert fixed in source, "the control's anchor is gone; re-aim it at a live client_ip site"
    after = _raw_reads(ast.parse(source.replace(fixed, reverted, 1)))
    assert len(after) == expected, after
    assert _raw_reads(ast.parse(source)) == []


@pytest.mark.parametrize(
    ("source", "offending"),
    [
        pytest.param("c = request.client.host if request.client else None", True, id="inline"),
        pytest.param("c = websocket.client.host", True, id="websocket"),
        pytest.param("c = conn.client.port", True, id="port"),
        pytest.param("peer = request.client", True, id="aliased-object"),
        pytest.param("c = request.scope['client'][0]", True, id="request-scope-subscript"),
        pytest.param("c = scope.get('client')", True, id="scope-get"),
        pytest.param("c = request.scope.get('client')", True, id="request-scope-get"),
        pytest.param("c = anything.client.host", True, id="any-receiver"),
        pytest.param("c = request['client'][0]", True, id="mapping-subscript"),
        pytest.param("c = request.get('client')", True, id="mapping-get"),
        pytest.param("c = getattr(websocket, 'client', None)", True, id="getattr"),
        pytest.param("c = client_ip(request)", False, id="through-client-ip"),
        pytest.param("c = row['client']", False, id="audit-row-field"),
        pytest.param("c = session.get('client')", False, id="session-dict"),
        pytest.param("c = self.client", False, id="own-attribute"),
        pytest.param("import http.client", False, id="stdlib-module"),
        pytest.param("c = ctx.client", False, id="harness-context"),
        pytest.param("c = req.client", False, id="body-model-field"),
        pytest.param("c = connection.client", False, id="connection-config-field"),
        pytest.param("c = getattr(settings, 'client')", False, id="getattr-other"),
        # The two gaps the module docstring names. If one starts to read as an offence, the guard
        # got wider: move it up and correct the docstring.
        pytest.param("c = r['client']", False, id="gap-other-connection-name"),
        pytest.param("s = request.scope; c = s['client']", False, id="gap-aliased-scope"),
    ],
)
def test_the_raw_read_guard_discriminates(source: str, offending: bool) -> None:
    """The guard's own control: each planted shape it exists to catch reads as an offence, and the
    neighbouring shapes that are not an address read do not."""
    found = _raw_reads(ast.parse(f"def f():\n    {source}\n"))
    assert bool(found) is offending, found
