# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every first-party HTTP response emitter of a known shape is registered here (BACKLOG #1120).

The security header floor (:mod:`messagefoundry.api.header_floor`) is a property of the ASGI stack:
any response the app sends through it gets the baseline. What escapes it is an emitter that sends a
response some OTHER way. Three prior passes over ASVS 3.4.4 each missed a class of those. This gate
turns "we found them all" into something that fails when a new one lands unregistered.

**How it works.** It parses every module under ``messagefoundry/`` and ``messagefoundry_webconsole/``
and counts each site with one of the shapes below. The count it finds must equal :data:`_REGISTERED`
exactly, in both directions: a new site with no entry fails, and an entry whose site has gone fails
too, so the register cannot rot into a list of things that used to exist. Each entry says why that
site does not bypass the floor, or what covers it instead.

| Shape | What it catches |
| --- | --- |
| ``asgi-app`` | ``FastAPI(...)`` or ``Starlette(...)``: a second app would need its own floor. |
| ``asgi-server`` | ``uvicorn.run``, ``.Server`` or ``.Config``: a server without the floored protocols. |
| ``error-handler`` | A handler for ``Exception`` or ``500``: Starlette runs it OUTSIDE all user middleware. |
| ``asgi-response-start`` | A raw ASGI response-start or ``websocket.accept`` message literal. |
| ``ws-close`` | A ``websocket.close`` message or a ``.close(code=...)`` call: pre-accept, it is a refusal. |
| ``status-line`` | A literal that starts an HTTP status line: a raw writer below any ASGI stack. |
| ``protocol-override`` | A def of, or assignment to, ``send_400_response``, ``send_500_response`` or |
| | ``write_http_response``: the server's own responses. |

**Its bound, stated so it is not read as more.** This pins the FIRST-PARTY emitter population, and
only emitters of a shape listed above, in the literal spelling the table gives: an aliased import
(``import uvicorn as uv``) or a WebSocket bound to another name evades it. "Emits an HTTP response" has no total syntactic trigger, so a
new emitter of a shape nobody has named yet can still land. And it cannot pin uvicorn's own
population at all: the responses uvicorn writes below the app change with its version, and no scan
of this repository can see them. That is ``tests/test_header_floor_wire.py``'s job, which drives a
real, version-pinned uvicorn with a vacuity control in the same run.
"""

from __future__ import annotations

import ast
import functools
import re
from collections import Counter
from pathlib import Path
from typing import NamedTuple

import pytest
from _ast_sites import callee_name

_REPO = Path(__file__).resolve().parent.parent
_ROOTS = ("messagefoundry", "messagefoundry_webconsole")

_ASGI_RESPONSE_STARTS = frozenset(
    {"http.response.start", "websocket.http.response.start", "websocket.accept"}
)
_STATUS_LINE = re.compile(r"HTTP/\d\.\d \S")
_PROTOCOL_METHODS = frozenset({"send_400_response", "send_500_response", "write_http_response"})
_SERVER_CALLS = frozenset({"run", "Server", "Config"})
_WS_NAMES = frozenset({"ws", "websocket"})
_MESSAGE_KINDS = {
    **dict.fromkeys(_ASGI_RESPONSE_STARTS, "asgi-response-start"),
    "websocket.close": "ws-close",
}


class Site(NamedTuple):
    path: str
    scope: str
    kind: str


class _Collector(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.stack: list[str] = []
        self.sites: list[Site] = []

    def _add(self, kind: str) -> None:
        self.sites.append(Site(self.path, ".".join(self.stack) or "<module>", kind))

    def _scoped(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scoped(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node.name in _PROTOCOL_METHODS:
            self._add("protocol-override")
        self._scoped(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:
        # A per-instance override, `cycle.send_500_response = ...`, is as much an override as a def.
        for target in node.targets:
            if isinstance(target, ast.Attribute) and target.attr in _PROTOCOL_METHODS:
                self._add("protocol-override")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        name = callee_name(node) or ""
        if name in ("FastAPI", "Starlette"):
            self._add("asgi-app")
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "uvicorn"
            and func.attr in _SERVER_CALLS
        ):
            self._add("asgi-server")
        if name in ("exception_handler", "add_exception_handler") and node.args:
            first = node.args[0]
            if (isinstance(first, ast.Name) and first.id == "Exception") or (
                isinstance(first, ast.Constant) and first.value == 500
            ):
                self._add("error-handler")
        # Any close on a name that holds a WebSocket, however the code is passed or if it is not
        # passed at all (a bare close before accept is a refusal too), plus any close(code=...).
        receiver = func.value if isinstance(func, ast.Attribute) else None
        if name == "close" and (
            (isinstance(receiver, ast.Name) and receiver.id in _WS_NAMES)
            or any(kw.arg == "code" for kw in node.keywords)
        ):
            self._add("ws-close")
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values, strict=True):
            if (
                isinstance(key, ast.Constant)
                and key.value == "type"
                and isinstance(value, ast.Constant)
            ):
                kind = _MESSAGE_KINDS.get(str(value.value))
                if kind:
                    self._add(kind)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        if isinstance(value, str) and _STATUS_LINE.match(value):
            self._add("status-line")

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        head = node.values[0] if node.values else None
        if isinstance(head, ast.Constant) and str(head.value).startswith("HTTP/"):
            self._add("status-line")
            return  # the head constant is the same site; do not count it twice
        self.generic_visit(node)


def scan_source(source: str, path: str) -> Counter[Site]:
    """Every emitter site in one module, COUNTED: a second close in a function already registered
    for one is a new emitter, and a set would hide it."""
    collector = _Collector(path)
    collector.visit(ast.parse(source, filename=path))
    return Counter(collector.sites)


@functools.cache
def scan_tree() -> Counter[Site]:
    """Parsed once per run; callers combine it with ``+``/``-``, which return new counters."""
    found: Counter[Site] = Counter()
    for root in _ROOTS:
        for file in sorted((_REPO / root).rglob("*.py")):
            rel = file.relative_to(_REPO).as_posix()
            found += scan_source(file.read_text(encoding="utf-8"), rel)
    return found


_APP = "messagefoundry/api/app.py"
_FLOOR = "messagefoundry/api/header_floor.py"
_PROTOCOL = "messagefoundry/api/protocol_headers.py"

#: Every known emitter: site -> (how many, why it does not bypass the floor or what covers it).
_REGISTERED: dict[Site, tuple[int, str]] = {
    Site(_APP, "create_app", "asgi-app"): (
        1,
        "The one API app. SecurityHeaderFloorMiddleware is its LAST add_middleware, which makes it "
        "the outermost user middleware; tests/test_api_request_timeout.py pins that position.",
    ),
    Site("messagefoundry/__main__.py", "_serve", "asgi-server"): (
        1,
        "run_kwargs passes the floored http and ws protocols (api/protocol_headers.py); "
        "tests/test_api_tls.py pins both arms of the client-cert shim.",
    ),
    Site(_APP, "create_app._unhandled_exception", "error-handler"): (
        1,
        "Runs in ServerErrorMiddleware, outside every user middleware, so it sets "
        "BASELINE_SECURITY_HEADERS itself; tests/test_api_security_header_floor.py covers it.",
    ),
    Site(_APP, "create_app.ws_stats", "ws-close"): (
        2,
        "Both are AFTER accept, so each is a WebSocket frame, not an HTTP response. The route's "
        "pre-accept refusals go through refuse_websocket.",
    ),
    Site("messagefoundry/api/client_networks.py", "ClientNetworkMiddleware.__call__", "ws-close"): (
        1,
        "The fallback when the server offers no websocket.http.response extension, the only case "
        "where a bare close is possible at all. With it, the denial is a floored 403.",
    ),
    Site(_FLOOR, "refuse_websocket", "ws-close"): (1, "The same fallback, for routes."),
    Site(
        _FLOOR,
        "SecurityHeaderFloorMiddleware._serve_websocket.send_websocket",
        "asgi-response-start",
    ): (
        1,
        "The floor's own 403 for a bare pre-accept close; it applies the floor to it.",
    ),
    Site(
        "messagefoundry/api/request_timeout.py",
        "RequestTimeoutMiddleware.__call__",
        "asgi-response-start",
    ): (
        1,
        "Registered before the floor, so inside it: the floor setdefaults the baseline onto it.",
    ),
    Site(_PROTOCOL, "_floor_the_cycle_500", "protocol-override"): (
        1,
        "Adds the headers to uvicorn's own HTTP 500; tests/test_header_floor_wire.py.",
    ),
    Site(_PROTOCOL, "floored_http_protocol_class._FlooredHTTPProtocol", "protocol-override"): (
        1,
        "Adds the headers to uvicorn's own HTTP 400; tests/test_header_floor_wire.py.",
    ),
    Site(
        _PROTOCOL,
        "floored_ws_protocol_class._FlooredLegacyWebSocketProtocol",
        "protocol-override",
    ): (
        1,
        "Adds the headers, where absent, to every handshake answer the legacy websockets server "
        "writes; tests/test_header_floor_wire.py.",
    ),
    Site(_PROTOCOL, "floored_ws_protocol_class._FlooredWebSocketProtocol", "protocol-override"): (
        1,
        "Adds the headers to uvicorn's own WebSocket 500; tests/test_header_floor_wire.py.",
    ),
    Site("messagefoundry/transports/http_listener.py", "_status_line", "status-line"): (
        1,
        "The ADR 0023 listener's one status-line writer. Its caller, build_response, emits the "
        "baseline itself, because transports/ may not import api/.",
    ),
}


def _drift(found: Counter[Site]) -> list[str]:
    """Every difference between what the scan found and what is registered, in both directions."""
    problems = []
    for site in sorted(set(found) | set(_REGISTERED)):
        want = _REGISTERED.get(site, (0, ""))[0]
        if found[site] != want:
            problems.append(
                f"{site.kind} in {site.path} :: {site.scope}: found {found[site]}, registered {want}"
            )
    return problems


def test_every_first_party_emitter_is_registered() -> None:
    problems = _drift(scan_tree())
    assert not problems, (
        "The response-emitter inventory drifted. A NEW site must either send through the header "
        "floor or set the baseline itself, and then be registered here with the reason. A GONE "
        "site must be removed from the register.\n  " + "\n  ".join(problems)
    )


def test_the_scan_is_armed() -> None:
    """A scan that finds nothing agrees with an empty register, so pin that it finds every shape."""
    kinds = {site.kind for site in scan_tree()}
    assert kinds == {site.kind for site in _REGISTERED} == set(_PLANTED)


_PLANTED = {
    "asgi-app": "from fastapi import FastAPI\nshadow = FastAPI()\n",
    "asgi-server": "import uvicorn\ndef go(app):\n    uvicorn.run(app)\n",
    "error-handler": "def wire(app):\n    app.add_exception_handler(500, lambda r, e: None)\n",
    "asgi-response-start": (
        "async def mw(scope, receive, send):\n"
        "    await send({'type': 'http.response.start', 'status': 200, 'headers': []})\n"
    ),
    "ws-close": "async def route(websocket):\n    await websocket.close()\n",
    "status-line": "def raw(w, code):\n    w.write(f'HTTP/1.1 {code} OK'.encode())\n",
    "protocol-override": "class P:\n    def send_500_response(self):\n        pass\n",
}


@pytest.mark.parametrize("kind", sorted(_PLANTED))
def test_a_planted_emitter_of_every_shape_turns_the_gate_red(kind: str) -> None:
    """The positive control: each shape, planted in a module the register has never heard of, is
    found by the scan AND reported as drift by the same comparison the real gate runs."""
    planted = scan_source(_PLANTED[kind], "messagefoundry/api/planted.py")
    assert [site.kind for site in planted.elements()] == [kind]
    problems = _drift(scan_tree() + planted)
    assert len(problems) == 1 and "planted.py" in problems[0], problems


def test_a_second_emitter_in_a_registered_function_is_still_drift() -> None:
    """The count matters: a new pre-accept close beside ws_stats's two post-accept ones must not
    hide inside an entry that already names the function."""
    extra = Counter({Site(_APP, "create_app.ws_stats", "ws-close"): 1})
    assert _drift(scan_tree() + extra)


def test_a_registered_emitter_that_is_gone_is_drift() -> None:
    """The other direction: an entry whose site vanished must fail, or the register rots."""
    gone = Counter({Site(_APP, "create_app._unhandled_exception", "error-handler"): 1})
    assert _drift(scan_tree() - gone)


@pytest.mark.parametrize(
    "source",
    [
        "class P:\n    def write_http_response(self, status, headers, body=None):\n        pass\n",
        "def hook(cycle):\n    cycle.send_500_response = None\n",
    ],
    ids=["write_http_response-def", "send_500_response-assignment"],
)
def test_the_other_override_forms_turn_the_gate_red(source: str) -> None:
    """Positive controls for the override forms the shape table names beyond a plain def."""
    planted = scan_source(source, "messagefoundry/api/planted.py")
    assert [site.kind for site in planted.elements()] == ["protocol-override"]
    problems = _drift(scan_tree() + planted)
    assert len(problems) == 1 and "planted.py" in problems[0], problems
