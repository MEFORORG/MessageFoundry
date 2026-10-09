# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Security headers on the responses uvicorn writes itself, below the ASGI app (BACKLOG #1120).

The header floor in :mod:`messagefoundry.api.header_floor` sees every response the ASGI app sends. It
cannot see the ones the server writes on its own, because no app code runs for them. This module
adds ``X-Content-Type-Options: nosniff`` and ``Content-Security-Policy: frame-ancestors 'none';
base-uri 'none'`` (the floor's :data:`~messagefoundry.api.header_floor.FLOOR_CSP`) to at least these:

* the ``400`` for a request uvicorn cannot parse (``send_400_response`` on the HTTP protocol);
* the ``500`` when the app raised, or returned, without starting a response
  (``send_500_response`` on uvicorn's per-request cycle object, not on the protocol);
* the ``500`` when a WebSocket app fails before the handshake is answered;
* on the sans-I/O WebSocket protocol that ``ws="auto"`` resolves to from uvicorn 0.50, each
  handshake answer handed to ``send_response`` on its ``conn``, a websockets ``ServerProtocol``.
  At uvicorn 0.54.0 that is every one this module's author found, and at least these: the
  library's own rejection of a malformed handshake (a ``400`` for a missing
  ``Sec-WebSocket-Key``, a ``405`` for a method other than GET), uvicorn's ``500``, its ``403``
  for an app that closes before accepting, the app's own denial, the ``101``, and the ``414`` or
  ``431`` the library's parser queues for an over-long request line or header block; and
* on the legacy websockets server, which ``ws="auto"`` resolved to before uvicorn 0.50 and
  ``ws="websockets"`` still names, the pre-handshake ``500`` (``send_500_response``) and every
  handshake answer that library writes through ``write_http_response``: its own rejection of a
  malformed handshake, its ``503`` on shutdown, and its ``500``.

**Known gaps, not covered here.** wsproto writes its own ``400`` for a bad handshake straight to the
transport. It keeps a ``conn`` like the sans-I/O protocol, but its module has no websockets
``ServerProtocol`` for the floor to wrap, so the class build below refuses it. It is what
``ws="auto"`` resolves to only when websockets is not installed, and websockets is a declared
dependency. uvicorn
0.54 also ships a ``zttp`` HTTP protocol. ``http="auto"`` does not resolve to it and ``serve`` never
names it; handed to the class build, it is checked for the HTTP hooks like any other base.
uvicorn's interim ``100 Continue`` carries no header either.

**Two things this module does on the sans-I/O protocol beyond adding headers.** Both work around
uvicorn 0.54.0 behaviour that its legacy server did not have, and both are measured on the bare
class too.

*It writes what the websockets parser queued, and closes.* When that parser rejects a request
itself, uvicorn never writes the result. The peer gets no answer and the connection stays open.
The parser queues a ``414`` for an over-long request line and a ``431`` for an over-long or
over-numerous header block; for any other parse error it queues only an end-of-stream, with no
answer. :func:`_answer_a_parser_rejection` writes whatever was queued, which may be nothing, and
closes, the way uvicorn's own ``handle_connect`` does for a rejection it does see. It writes no
answer of its own making. ``tests/test_header_floor_wire.py`` pins the upstream behaviour on the
bare class, so a uvicorn that fixes it turns that test red and this step can go.

*It drops a second handshake answer on a conn that has already ended its stream.* At server stop
uvicorn sends its ``500`` to every connection whose handshake it has not marked complete. That
includes one it already answered and is still closing, such as a pre-handshake ``500`` to a TLS
peer that has not yet acknowledged the close, and one the parser rejected. websockets asserts on
the second end-of-stream, ``Server.shutdown`` raises, and the lifespan shutdown, which stops the
engine, never runs. Nothing more can be written on that conn, so
:func:`_send_floored_handshake_response` returns without calling the library.

**Never HSTS here.** Whether HSTS belongs on a response depends on the request's host and the served
chain (:func:`~messagefoundry.api.header_floor.hsts_notable`). On the default posture, a self-signed
pair on 127.0.0.1, it must stay absent. ``uvicorn.Config(headers=...)`` is the tempting shortcut and
it is wrong twice: it is unconditional, and it would stamp every app response a second time on top
of the floor.

**Adding, not rewriting.** Each override calls the server's own method and adds the headers on the
way out, so the status, body and framing stay the server's. The ``400`` and the legacy server's
WebSocket ``500`` are written straight to the transport, synchronously, and the FIRST ``write`` of
each carries the status line (for httptools and the WebSocket writer it is the only write; h11
writes head, body and end separately). So a transport proxy adds the header lines after that status
line, for the length of that one call. The HTTP ``500`` goes through the cycle's ``send``, which
prepends the cycle's ``default_headers``, so the override extends those for that one response. A
handshake answer, on either WebSocket protocol, is a headers object the library has not serialized
yet, so the override adds to that object.

**Refuse at startup.** Each hook this module overrides is checked when the class is built,
against the server class it is handed. The flags the two sans-I/O steps above read
(``handshake_initiated``, ``handshake_exc``, ``eof_sent``) are NOT checked at build: a rename
there turns those steps off silently, and only the startup self-test's parser-rejection drive would
notice the first. The checked hooks are: the HTTP protocol's ``send_400_response``, its
``cycle`` and ``transport`` attributes, uvicorn's ``RequestResponseCycle`` with its
``send_500_response`` and ``default_headers``, and the WebSocket protocol's hooks. For the legacy
server those are ``send_500_response``, ``transport`` and ``write_http_response``. For the sans-I/O
protocol they are ``data_received``, the ``conn`` attribute, and a synchronous ``send_response``
and ``data_to_send`` on the ``ServerProtocol`` its module imports. The methods the floor wraps synchronously must still be
synchronous. An attribute counts as present when a method of the server's own class for the hook
using it, or of a subclass, assigns it. A missing hook raises :class:`ProtocolFloorUnavailable`, naming the hook and the
installed uvicorn and websockets versions, and ``serve`` refuses to start on it. There is no
fallback to the server's own protocol and no opt-out: a server that would answer below the floor
without these headers does not start. So a WebSocket base that fits neither hook set (wsproto) is
refused rather than served with its handshake answers bare.

**Then measure, and refuse on that too.** The checks above read shape, and a hook can keep its shape
and stop adding the headers. So ``serve`` and ``supervise`` next run
:func:`messagefoundry.api.protocol_floor_selftest.selftest_protocol_floor` on the classes built here.
It drives each family's response in memory and raises the same
:class:`ProtocolFloorUnavailable` when one goes out without a header. That module says what it
drives and what it does not prove.

**Per-response steps degrade, and say so.** Once the class is built, a step this module adds to one
response (the transport swap and restore, the status-line injection, the 500 hook and its header
extension, the handshake header addition) catches ``Exception``, logs the type once per family and
step at WARNING, and lets the server's own response go out without the headers. Refusing that one
response would change its status, which the floor must never do. The overrides take
``*args, **kwargs`` so a changed server signature reaches the server's method unchanged.
``tests/test_header_floor_wire.py`` injects failures into those steps.

**This leans on uvicorn and websockets INTERNALS.** None of the hooks above is public API.
``pyproject.toml`` bounds uvicorn below the next minor and websockets below the next major.
``tests/test_header_floor_wire.py`` fails unless the installed versions are the ones it measured,
``_MEASURED_UVICORN`` and ``_MEASURED_WEBSOCKETS``, and drives every family on the wire against a
control. The two startup checks are what hold between those. An upgrade that removes a hook, or
leaves one in place that no longer adds the headers to the families the self-test drives, stops the
engine instead of shipping those responses without them.
"""

from __future__ import annotations

import asyncio
import dis
import inspect
import logging
import sys
import weakref
from collections.abc import Callable
from functools import partial
from importlib.metadata import PackageNotFoundError, version
from types import CodeType
from typing import Any

from messagefoundry.api.header_floor import (
    BASELINE_SECURITY_HEADERS,
    CSP_HEADER,
    FLOOR_CSP,
)

__all__ = [
    "PROTOCOL_SECURITY_HEADERS",
    "ProtocolFloorUnavailable",
    "floor_unavailable",
    "floored_http_protocol_class",
    "floored_ws_protocol_class",
]

_log = logging.getLogger(__name__)

_NOSNIFF = "X-Content-Type-Options"

#: The set the protocol layer adds. Values come from the floor's own constants so the two cannot
#: drift. Deliberately not the whole baseline: the brief for this layer is nosniff and the floor's CSP
#: (framing and base-uri, BACKLOG #2341). No app writer reaches these responses, so the floor's
#: writer-decides rule has nothing to defer to here.
PROTOCOL_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    (_NOSNIFF, dict(BASELINE_SECURITY_HEADERS)[_NOSNIFF]),
    (CSP_HEADER, FLOOR_CSP),
)

_HEADER_LINES = b"".join(
    f"{name}: {value}\r\n".encode("latin-1") for name, value in PROTOCOL_SECURITY_HEADERS
)
_HEADER_PAIRS = [
    (name.lower().encode("latin-1"), value.encode("latin-1"))
    for name, value in PROTOCOL_SECURITY_HEADERS
]

#: (family, step) pairs that have already logged a failure. A broken step warns once per response
#: family rather than per request, and one family's failure cannot silence another's.
_WARNED: set[tuple[str, str]] = set()


def _degraded(family: str, step: str, exc: BaseException) -> None:
    """Log one per-response header-path failure, once per (family, step). Only the exception TYPE is
    logged: the message could carry request bytes, and this runs on requests that may carry PHI."""
    if (family, step) in _WARNED:
        return
    _WARNED.add((family, step))
    _log.warning(
        "%s: %s failed (%s); the server's own behaviour took this step over, so responses of "
        "this family may lack the protocol-level security headers (BACKLOG #1120). Re-measure the "
        "uvicorn/websockets protocol layer.",
        family,
        step,
        type(exc).__name__,
    )


class ProtocolFloorUnavailable(RuntimeError):
    """The server class lacks a hook the protocol header floor needs, so the floor cannot be built.

    ``serve`` refuses to start on this. The message names the hook and the installed versions, and
    :attr:`hook` holds the hook alone. A refusal from the startup self-test names no single hook, so
    there it holds ``"startup self-test"`` and the message says what the test found."""

    hook: str = ""


def _refusal(base: type[Any], hook: str) -> ProtocolFloorUnavailable:
    return floor_unavailable(
        f"cannot be built on {base.__module__}.{base.__qualname__}: it has no {hook}", hook
    )


def floor_unavailable(problem: str, hook: str) -> ProtocolFloorUnavailable:
    """The one refusal both startup checks raise: the class build here, and the self-test in
    :mod:`messagefoundry.api.protocol_floor_selftest`. ``problem`` completes "the protocol header
    floor ...", and ``hook`` is what :attr:`ProtocolFloorUnavailable.hook` holds."""
    # Built here rather than in an __init__ override, so the exception keeps RuntimeError's own
    # (message,) args and pickles and copies like any other.
    refused = ProtocolFloorUnavailable(
        f"the protocol header floor (BACKLOG #1120) {problem} "
        f"(uvicorn {_installed('uvicorn')}, websockets {_installed('websockets')}). The responses "
        "the server writes below the app could go out without the floor's headers. Re-read the server's "
        "protocol modules and update messagefoundry/api/protocol_headers.py, or install the uvicorn "
        "and websockets the lock pins"
    )
    refused.hook = hook
    return refused


def _installed(name: str) -> str:
    """The version of the module actually imported, which is the code the check read. The
    distribution's metadata stands in only when the module is not imported yet."""
    loaded = getattr(sys.modules.get(name), "__version__", None)
    if isinstance(loaded, str):
        return loaded
    try:
        return version(name)
    except PackageNotFoundError:
        return "not installed"


#: The class uvicorn builds each HTTP request's cycle from, looked up in the protocol's own module.
_CYCLE_CLASS = "RequestResponseCycle"


def _stores(code: CodeType, attr: str) -> bool:
    """Whether ``code``, or a function nested in it, assigns ``<something>.<attr>``."""
    return any(
        ins.opname == "STORE_ATTR" and ins.argval == attr for ins in dis.get_instructions(code)
    ) or any(isinstance(const, CodeType) and _stores(const, attr) for const in code.co_consts)


def _root_definer(cls: type[Any], name: str) -> type[Any] | None:
    """The BASE-most class in ``cls``'s MRO that defines ``name`` itself: the server's own class, even
    when a subclass wraps the hook. None when no class dict holds it (a metaclass provides it)."""
    return next((klass for klass in reversed(cls.__mro__) if name in vars(klass)), None)


def _assigns(cls: type[Any], attr: str, *, upto: type[Any]) -> bool:
    """Whether a method of ``cls``, or of a base up to and including ``upto``, assigns ``attr``.

    uvicorn sets ``cycle``, ``transport`` and ``default_headers`` per instance, so a class-level
    ``hasattr`` cannot see them; the assignment in the class's own bytecode is what a rename or a
    removal changes. ``upto`` is the server's own class for the hook, so a THIRD-PARTY base further up
    (websockets' own protocol also assigns ``transport``) cannot satisfy the check for uvicorn's
    class, while a wrapper subclass below it still sees uvicorn's assignments."""
    for klass in cls.__mro__:
        for member in vars(klass).values():
            func = member.fset if isinstance(member, property) else member
            code = getattr(func, "__code__", None)
            if isinstance(code, CodeType) and _stores(code, attr):
                return True
        if klass is upto:
            break
    return False


def _require_sync_method(base: type[Any], name: str) -> None:
    """The floor calls these synchronously through ``partial(super().<name>)``. A hook that became a
    coroutine would build, then return an unawaited coroutine where the server awaits nothing."""
    method = getattr(base, name, None)
    if not callable(method) or inspect.iscoroutinefunction(method):
        raise _refusal(base, f"synchronous {name} method")


def _require_assigned(base: type[Any], attr: str, *, hook: str) -> None:
    owner = _root_definer(base, hook)
    if owner is None:
        raise _refusal(base, f"{hook} in any class body")
    if not _assigns(base, attr, upto=owner):
        raise _refusal(base, f"{attr} attribute")


#: The class the sans-I/O WebSocket protocol builds each connection's ``conn`` from, looked up in
#: the protocol's own module. It is websockets' ``ServerProtocol``, and every handshake answer that
#: protocol writes goes through its ``send_response``.
_CONN_CLASS = "ServerProtocol"


def _module_class(base: type[Any], name: str) -> type[Any] | None:
    """The class called ``name`` in the module of ``base`` or of one of its bases: what the server's
    own code builds when it spells that name."""
    for klass in base.__mro__:
        found = getattr(sys.modules.get(klass.__module__), name, None)
        if isinstance(found, type):
            return found
    return None


def _require_http_hooks(base: type[Any]) -> None:
    """Refuse, at class build, a base lacking any hook :func:`_build_floored_http` relies on."""
    _require_sync_method(base, "send_400_response")
    _require_assigned(base, "cycle", hook="send_400_response")
    _require_assigned(base, "transport", hook="send_400_response")
    cycle_cls = _module_class(base, _CYCLE_CLASS)
    if cycle_cls is None:
        raise _refusal(base, f"{_CYCLE_CLASS} in its module")
    if not inspect.iscoroutinefunction(getattr(cycle_cls, "send_500_response", None)):
        raise _refusal(cycle_cls, "send_500_response coroutine")
    _require_assigned(cycle_cls, "default_headers", hook="send_500_response")


def _answers_through_conn(base: type[Any]) -> bool:
    """Whether ``base`` keeps its handshake in a ``conn`` object and has no ``write_http_response``:
    the sans-I/O protocol's shape. wsproto's protocol has it too, and is then refused for the
    ``ServerProtocol`` its module lacks."""
    if callable(getattr(base, "write_http_response", None)):
        return False
    # Up to the class that first defines data_received, which is asyncio.Protocol: the whole of the
    # server's own class chain. Keyed on nothing the sans-I/O floor does not itself use.
    owner = _root_definer(base, "data_received")
    return owner is not None and _assigns(base, "conn", upto=owner)


def _require_ws_hooks(base: type[Any], *, through_conn: bool) -> None:
    """Refuse, at class build, a base lacking any hook its floored class relies on.
    ``through_conn`` is :func:`_answers_through_conn`'s reading of ``base``, which picks the set."""
    if through_conn:
        # Not send_500_response: on this protocol it goes through the conn, and the floor never
        # touches it, so its absence is no reason to refuse.
        _require_sync_method(base, "data_received")
        conn_cls = _module_class(base, _CONN_CLASS)
        if conn_cls is None:
            raise _refusal(base, f"{_CONN_CLASS} in its module")
        _require_sync_method(conn_cls, "send_response")
        _require_sync_method(conn_cls, "data_to_send")
    else:
        _require_sync_method(base, "send_500_response")
        _require_assigned(base, "transport", hook="send_500_response")
        _require_sync_method(base, "write_http_response")


def _after_status_line(data: bytes) -> bytes:
    """Insert the header lines right after the status line. Anything that does not start with one
    is left untouched, so a write this module did not expect cannot be corrupted."""
    end = data.find(b"\r\n")
    if not data.startswith(b"HTTP/") or end < 0:
        return data
    return data[: end + 2] + _HEADER_LINES + data[end + 2 :]


class _HeaderInjectingTransport:
    """Forwards everything to the real transport, adding the header lines to the FIRST write only."""

    def __init__(self, inner: Any, family: str) -> None:
        self._inner = inner
        self._family = family
        self._pending = True

    def write(self, data: bytes | bytearray | memoryview) -> None:
        if self._pending:
            self._pending = False
            try:
                data = _after_status_line(bytes(data))
            except Exception as exc:  # degrade: write what the server meant to write
                _degraded(self._family, "status-line header injection", exc)
        self._inner.write(data)

    def writelines(self, chunks: Any) -> None:
        if not self._pending:
            self._inner.writelines(chunks)
            return
        try:
            chunks = list(chunks)
            joined: bytes | None = b"".join(bytes(chunk) for chunk in chunks)
        except Exception as exc:
            _degraded(self._family, "writelines join", exc)
            joined = None
        if joined is None:
            self._pending = False
            self._inner.writelines(chunks)
            return
        self.write(joined)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _write_with_headers(protocol: Any, family: str, emit: Callable[[], None]) -> None:
    """Run one synchronous protocol-level response writer with the header lines added. Errors from
    ``emit`` itself are the server's and propagate as they would without this module: ``emit`` is
    never called inside an ``except`` block, so no header-path exception is chained onto them."""
    proxy: _HeaderInjectingTransport | None = None
    try:
        inner = protocol.transport
        proxy = _HeaderInjectingTransport(inner, family)
        protocol.transport = proxy
    except Exception as exc:
        _degraded(family, "transport swap", exc)
        proxy = None
    if proxy is None:
        emit()
        return
    try:
        emit()
    finally:
        try:
            protocol.transport = inner
        except Exception as exc:
            # The proxy stays in place. Stop it injecting, so a later write (a 101, say) goes out
            # exactly as the server wrote it; it forwards writes and attribute reads.
            proxy._pending = False
            _degraded(family, "transport restore", exc)


async def _send_floored_500(cycle_ref: weakref.ref[Any], *args: Any, **kwargs: Any) -> None:
    """A cycle's ``500`` with the headers. uvicorn prepends ``cycle.default_headers`` to every
    response start the cycle sends, so extending it only now puts the headers on this response
    alone. REBIND, never mutate: the list uvicorn passed in is the server-wide
    ``server_state.default_headers``."""
    # uvicorn calls this through the cycle it is about to answer for, so the referent is alive. If
    # it ever is not, there is no cycle left to send through, with or without this module.
    cycle: Any = cycle_ref()
    if cycle is None:
        _degraded("http-500", "cycle reference", ReferenceError("cycle already freed"))
        return
    try:
        cycle.default_headers = [*cycle.default_headers, *_HEADER_PAIRS]
    except Exception as exc:
        _degraded("http-500", "header extension", exc)
    await type(cycle).send_500_response(cycle, *args, **kwargs)


def _floor_the_cycle_500(cycle: Any) -> None:
    """Point this cycle's ``send_500_response`` at :func:`_send_floored_500`.

    A per-instance attribute holding a WEAK reference, so the cycle does not hold itself and is
    still freed by refcount. Measured on uvicorn 0.49.0's real cycles (h11 and httptools): about
    290 bytes more per in-flight request and no change to attribute-read speed. The per-request
    ``__class__`` swap this replaced cost about 240 bytes and made every attribute read on the
    cycle about 45 percent slower."""
    try:
        cycle.send_500_response = partial(_send_floored_500, weakref.ref(cycle))
    except Exception as exc:
        _degraded("http-500", "hook", exc)


def _add_where_absent(headers: Any) -> None:
    """Add each protocol header a handshake answer does not already carry. The 101 and an app's
    denial come through the ASGI floor first, so they are not stamped twice."""
    for name, value in PROTOCOL_SECURITY_HEADERS:
        if name not in headers:
            headers[name] = value


def _send_floored_handshake_response(conn_ref: weakref.ref[Any], *args: Any, **kwargs: Any) -> None:
    """A sans-I/O connection's ``send_response`` with the headers added to the response first."""
    # The protocol calls this through the conn it holds, so the referent is alive. If it ever is
    # not, there is no connection left to answer on, with or without this module.
    conn: Any = conn_ref()
    if conn is None:
        _degraded("ws-sansio", "conn reference", ReferenceError("conn already freed"))
        return
    if getattr(conn, "eof_sent", False) is True:
        # The conn has ended its stream: an answer already went out, or the parser gave up. The
        # library asserts on a second end-of-stream, and uvicorn makes this call at server stop
        # for a connection it answered and has not finished closing. See the module docstring.
        return
    try:
        # No named parameters, for the reason write_http_response below gives. At websockets 17.1
        # it is (response).
        response = kwargs["response"] if "response" in kwargs else args[0]
        _add_where_absent(response.headers)
    except Exception as exc:
        _degraded("ws-sansio", "header addition", exc)
    type(conn).send_response(conn, *args, **kwargs)


def _floor_the_conn_responses(conn: Any) -> None:
    """Point this conn's ``send_response`` at :func:`_send_floored_handshake_response`.

    Per instance, and holding a WEAK reference, for the reasons :func:`_floor_the_cycle_500` gives.
    websockets' own parser calls ``self.send_response`` for the answers it queues before uvicorn
    sees a request (an over-long request line, too many headers), so those get the headers too.
    :func:`_answer_a_parser_rejection` is what gets them written."""
    try:
        conn.send_response = partial(_send_floored_handshake_response, weakref.ref(conn))
    except Exception as exc:
        _degraded("ws-sansio", "hook", exc)


def _answer_a_parser_rejection(protocol: Any) -> None:
    """Write what the websockets parser queued for a request it rejected, and close. For a 414 or
    431 that is the answer; for any other parse error the parser queued no answer, and this only
    closes.

    See the module docstring: uvicorn 0.54.0 leaves the answer unwritten and the connection open.
    The parser sets ``handshake_exc`` and yields no request, so uvicorn's ``handle_connect`` never
    runs and ``handshake_initiated`` stays false. That pair is the whole test. The three flags are
    set the way ``handle_connect`` sets them for a rejection, so uvicorn's ``shutdown`` reads the
    connection as already answered."""
    try:
        conn = protocol.conn
        if getattr(protocol, "handshake_initiated", True):
            return
        if getattr(conn, "handshake_exc", None) is None:
            return
        queued = b"".join(conn.data_to_send())
        protocol.handshake_initiated = True
        protocol.handshake_complete = True
        protocol.close_sent = True
        if queued:
            protocol.transport.write(queued)
        protocol.transport.close()
    except Exception as exc:
        _degraded("ws-sansio", "parser rejection answer", exc)


def floored_http_protocol_class(base: type[Any] | None = None) -> type[asyncio.Protocol]:
    """uvicorn's HTTP protocol with the headers on its ``400`` and on each cycle's ``500``.

    ``base`` defaults to uvicorn's resolved ``AutoHTTPProtocol`` (httptools when installed, else h11).
    Compose, never replace: ``client_cert_http_protocol_class(base=<this>)`` stacks the mTLS shim on
    top, since the two override different methods.

    Raises :class:`ProtocolFloorUnavailable` when ``base`` lacks a hook; there is no fallback."""
    if base is None:
        from uvicorn.protocols.http.auto import AutoHTTPProtocol

        base = AutoHTTPProtocol

    _require_http_hooks(base)
    return _build_floored_http(base)


def _build_floored_http(base: type[Any]) -> type[asyncio.Protocol]:
    class _FlooredHTTPProtocol(base):  # type: ignore[misc]
        def send_400_response(self, *args: Any, **kwargs: Any) -> None:
            _write_with_headers(
                self, "http-400", partial(super().send_400_response, *args, **kwargs)
            )

        # Both implementations create each request's cycle with `self.cycle = RequestResponseCycle(...)`,
        # pipelined ones included, and before its task first runs. A property sees every one, once.
        @property
        def cycle(self) -> Any:
            return self._mf_cycle

        @cycle.setter
        def cycle(self, value: Any) -> None:
            self._mf_cycle = value  # first, so no failure below can lose the cycle
            if value is not None:
                _floor_the_cycle_500(value)

    return _FlooredHTTPProtocol


def floored_ws_protocol_class(base: type[Any] | None = None) -> type[asyncio.Protocol] | None:
    """uvicorn's WebSocket protocol with the headers on its pre-handshake ``500`` and on every
    handshake answer it writes, for the sans-I/O protocol and for the legacy websockets server. See
    the module docstring for what is NOT covered. Raises :class:`ProtocolFloorUnavailable` when
    ``base`` lacks a hook, which includes the wsproto protocol; there is no fallback.

    ``base`` defaults to uvicorn's resolved ``AutoWebSocketsProtocol``. That is ``None`` when no
    WebSocket library is installed, and then this returns ``None`` too, which uvicorn reads exactly
    as it reads ``ws="auto"`` in that environment: WebSockets off."""
    if base is None:
        from uvicorn.protocols.websockets.auto import AutoWebSocketsProtocol

        resolved: Any = AutoWebSocketsProtocol  # uvicorn types it as a callable, not a class
        if resolved is None:
            return None
        base = resolved

    # Read once: the same reading picks the hooks to require and the class to build.
    through_conn = _answers_through_conn(base)
    _require_ws_hooks(base, through_conn=through_conn)
    return _build_floored_sansio_ws(base) if through_conn else _build_floored_legacy_ws(base)


def _build_floored_sansio_ws(base: type[Any]) -> type[asyncio.Protocol]:
    class _FlooredWebSocketProtocol(base):  # type: ignore[misc]
        # The sans-I/O protocol writes a handshake answer by handing a response to
        # `self.conn.send_response` and then writing what the conn serialized; the module docstring
        # lists the answers found. So the conn is the one place to add the headers, and a property
        # sees it whenever it is assigned. send_500_response is NOT wrapped here: it goes through
        # the conn like the rest, and a second wrapper would stamp it twice.
        @property
        def conn(self) -> Any:
            return self._mf_conn

        @conn.setter
        def conn(self, value: Any) -> None:
            self._mf_conn = value  # first, so no failure below can lose the conn
            if value is not None:
                _floor_the_conn_responses(value)

        def data_received(self, *args: Any, **kwargs: Any) -> None:
            # Only until the handshake is under way: after that this is the frame path, and the
            # parser rejection can no longer happen.
            pending = not getattr(self, "handshake_initiated", True)
            super().data_received(*args, **kwargs)
            if pending:
                _answer_a_parser_rejection(self)

    return _FlooredWebSocketProtocol


def _build_floored_legacy_ws(base: type[Any]) -> type[asyncio.Protocol]:
    class _FlooredWebSocketProtocol(base):  # type: ignore[misc]
        def send_500_response(self, *args: Any, **kwargs: Any) -> None:
            _write_with_headers(self, "ws-500", partial(super().send_500_response, *args, **kwargs))

        # The legacy websockets server writes every handshake answer through this one method: the
        # 101, the app's denial, and its OWN answers to a bad handshake. Add the headers where
        # absent, so the 101 and the denial, which the floor already covered, are not stamped twice.
        def write_http_response(self, *args: Any, **kwargs: Any) -> None:
            # No named parameters, so a changed signature reaches the server's own method
            # unchanged instead of raising here. At 16.0 and at 17.1 it is
            # (status, headers, body=None).
            try:
                _add_where_absent(kwargs["headers"] if "headers" in kwargs else args[1])
            except Exception as exc:
                _degraded("ws-handshake", "header addition", exc)
            super().write_http_response(*args, **kwargs)

    return _FlooredWebSocketProtocol
