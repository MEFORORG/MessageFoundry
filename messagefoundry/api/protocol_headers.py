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
* the ``500`` when a WebSocket app fails before the handshake is answered (``send_500_response`` on
  the WebSocket protocol); and
* on the legacy websockets server that ``ws="auto"`` resolves to, every handshake answer that
  library writes through ``write_http_response``: its own rejection of a malformed handshake (for
  example a ``400`` for a missing ``Sec-WebSocket-Key``), its ``503`` on shutdown, and its ``500``.

**Known gaps, not covered here.** The sans-I/O WebSocket protocol builds its own handshake
rejections through ``ServerProtocol.reject``, and wsproto writes its own ``400`` for a bad handshake
straight to the transport. Neither is what ``ws="auto"`` resolves to at the locked versions, and
neither has ``write_http_response``, so the class build below refuses both. uvicorn's interim
``100 Continue`` carries no header either.

**Never HSTS here.** Whether HSTS belongs on a response depends on the request's host and the served
chain (:func:`~messagefoundry.api.header_floor.hsts_notable`). On the default posture, a self-signed
pair on 127.0.0.1, it must stay absent. ``uvicorn.Config(headers=...)`` is the tempting shortcut and
it is wrong twice: it is unconditional, and it would stamp every app response a second time on top
of the floor.

**Adding, not rewriting.** Each override calls the server's own method and adds the headers on the
way out, so the status, body and framing stay the server's. The ``400`` and the WebSocket ``500`` are
written straight to the transport, synchronously, and the FIRST ``write`` of each carries the status
line (for httptools and the WebSocket writers it is the only write; h11 writes head, body and end
separately). So a transport proxy adds the header lines after that status line, for the length of
that one call. The HTTP ``500`` goes through the cycle's ``send``, which prepends the cycle's
``default_headers``, so the override extends those for that one response.

**Refuse at startup.** Every hook this module overrides or reads is checked when the class is
built, against the server class it is handed: the HTTP protocol's ``send_400_response``, its
``cycle`` and ``transport`` attributes, uvicorn's ``RequestResponseCycle`` with its
``send_500_response`` and ``default_headers``, and the WebSocket protocol's ``send_500_response``,
``transport`` and ``write_http_response``. The methods the floor wraps synchronously must still be
synchronous. An attribute counts as present when a method of the server's own class for the hook
using it, or of a subclass, assigns it. A missing hook raises :class:`ProtocolFloorUnavailable`, naming the hook and the
installed uvicorn and websockets versions, and ``serve`` refuses to start on it. There is no
fallback to the server's own protocol and no opt-out: a server that would answer below the floor
without these headers does not start. So a WebSocket base without ``write_http_response`` (the
sans-I/O protocol, or wsproto) is refused rather than served with its handshake answers bare.

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
``pyproject.toml`` bounds uvicorn below the next minor and does not bound websockets.
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
    :attr:`hook` holds the hook alone. From the startup self-test it holds what the test found in
    place of a hook: each response and the header it lacked."""

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


def _cycle_class(base: type[Any]) -> type[Any] | None:
    for klass in base.__mro__:
        found = getattr(sys.modules.get(klass.__module__), _CYCLE_CLASS, None)
        if isinstance(found, type):
            return found
    return None


def _require_http_hooks(base: type[Any]) -> None:
    """Refuse, at class build, a base lacking any hook :func:`_build_floored_http` relies on."""
    _require_sync_method(base, "send_400_response")
    _require_assigned(base, "cycle", hook="send_400_response")
    _require_assigned(base, "transport", hook="send_400_response")
    cycle_cls = _cycle_class(base)
    if cycle_cls is None:
        raise _refusal(base, f"{_CYCLE_CLASS} in its module")
    if not inspect.iscoroutinefunction(getattr(cycle_cls, "send_500_response", None)):
        raise _refusal(cycle_cls, "send_500_response coroutine")
    _require_assigned(cycle_cls, "default_headers", hook="send_500_response")


def _require_ws_hooks(base: type[Any]) -> None:
    """Refuse, at class build, a base lacking any hook :func:`_build_floored_ws` relies on."""
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
    handshake answer the legacy websockets server writes. See the module docstring for what is NOT
    covered. Raises :class:`ProtocolFloorUnavailable` when ``base`` lacks a hook, which includes the
    sans-I/O and wsproto protocols; there is no fallback.

    ``base`` defaults to uvicorn's resolved ``AutoWebSocketsProtocol``. That is ``None`` when no
    WebSocket library is installed, and then this returns ``None`` too, which uvicorn reads exactly
    as it reads ``ws="auto"`` in that environment: WebSockets off."""
    if base is None:
        from uvicorn.protocols.websockets.auto import AutoWebSocketsProtocol

        resolved: Any = AutoWebSocketsProtocol  # uvicorn types it as a callable, not a class
        if resolved is None:
            return None
        base = resolved

    _require_ws_hooks(base)
    return _build_floored_ws(base)


def _build_floored_ws(base: type[Any]) -> type[asyncio.Protocol]:
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
                headers = kwargs["headers"] if "headers" in kwargs else args[1]
                for name, value in PROTOCOL_SECURITY_HEADERS:
                    if name not in headers:
                        headers[name] = value
            except Exception as exc:
                _degraded("ws-handshake", "header addition", exc)
            super().write_http_response(*args, **kwargs)

    return _FlooredWebSocketProtocol
