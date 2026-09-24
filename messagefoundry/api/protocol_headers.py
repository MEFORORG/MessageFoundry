# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Security headers on the responses uvicorn writes itself, below the ASGI app (BACKLOG #1120).

The header floor in :mod:`messagefoundry.api.header_floor` sees every response the ASGI app sends. It
cannot see the ones the server writes on its own, because no app code runs for them. This module
adds ``X-Content-Type-Options: nosniff`` and ``Content-Security-Policy: frame-ancestors 'none'`` to at
least these:

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
straight to the transport. Neither is what ``ws="auto"`` resolves to at the locked versions.

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

**Fail open, always.** A header is worth less than the response it rides on. Every step on the
header path catches ``Exception``, logs its type once at WARNING, and falls through to the server's
own behaviour, so no failure here can change a status or break a request.

**This leans on uvicorn and websockets INTERNALS**: the protocol's ``cycle`` attribute, the cycle's
``default_headers`` and ``send_500_response``, the protocols' ``transport``, and the legacy server's
``write_http_response``. None is public API. ``tests/test_header_floor_wire.py`` pins the versions it
measured, uvicorn 0.49.0 and websockets 16.0, and drives every family on the wire against a control,
so an upgrade that moves any of them goes red there. Fail-open is what keeps such an upgrade from
turning into an outage before the suite is re-run.
"""

from __future__ import annotations

import asyncio
import logging
import weakref
from collections.abc import Callable
from functools import partial
from typing import Any

from messagefoundry.api.header_floor import (
    BASELINE_SECURITY_HEADERS,
    CSP_HEADER,
    FRAME_ANCESTORS_CSP,
)

__all__ = [
    "PROTOCOL_SECURITY_HEADERS",
    "floored_http_protocol_class",
    "floored_ws_protocol_class",
]

_log = logging.getLogger(__name__)

_NOSNIFF = "X-Content-Type-Options"

#: The set the protocol layer adds. Values come from the floor's own constants so the two cannot
#: drift. Deliberately not the whole baseline: the brief for this layer is nosniff and framing.
PROTOCOL_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    (_NOSNIFF, dict(BASELINE_SECURITY_HEADERS)[_NOSNIFF]),
    (CSP_HEADER, FRAME_ANCESTORS_CSP),
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


def _fell_open(family: str, step: str, exc: BaseException) -> None:
    """Log one header-path failure, once per (family, step). Only the exception TYPE is logged: the
    message could carry request bytes, and this runs on requests that may carry PHI."""
    if (family, step) in _WARNED:
        return
    _WARNED.add((family, step))
    _log.warning(
        "%s: %s failed (%s); serving the server's own response without the protocol-level security "
        "headers (BACKLOG #1120). Re-measure the uvicorn/websockets protocol layer.",
        family,
        step,
        type(exc).__name__,
    )


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
            except Exception as exc:  # fail open: write what the server meant to write
                _fell_open(self._family, "status-line header injection", exc)
        self._inner.write(data)

    def writelines(self, chunks: Any) -> None:
        chunks = list(chunks)
        try:
            joined = b"".join(bytes(chunk) for chunk in chunks)
        except Exception as exc:
            _fell_open(self._family, "writelines join", exc)
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
        _fell_open(family, "transport swap", exc)
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
            _fell_open(family, "transport restore", exc)


async def _send_floored_500(cycle_ref: weakref.ref[Any], *args: Any, **kwargs: Any) -> None:
    """A cycle's ``500`` with the headers. uvicorn prepends ``cycle.default_headers`` to every
    response start the cycle sends, so extending it only now puts the headers on this response
    alone. REBIND, never mutate: the list uvicorn passed in is the server-wide
    ``server_state.default_headers``."""
    # uvicorn calls this through the cycle it is about to answer for, so the referent is alive.
    cycle: Any = cycle_ref()
    try:
        cycle.default_headers = [*cycle.default_headers, *_HEADER_PAIRS]
    except Exception as exc:
        _fell_open("http-500", "header extension", exc)
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
        _fell_open("http-500", "hook", exc)


def floored_http_protocol_class(base: type[Any] | None = None) -> type[asyncio.Protocol]:
    """uvicorn's HTTP protocol with the headers on its ``400`` and on each cycle's ``500``.

    ``base`` defaults to uvicorn's resolved ``AutoHTTPProtocol`` (httptools when installed, else h11).
    Compose, never replace: ``client_cert_http_protocol_class(base=<this>)`` stacks the mTLS shim on
    top, since the two override different methods."""
    if base is None:
        from uvicorn.protocols.http.auto import AutoHTTPProtocol

        base = AutoHTTPProtocol

    try:
        return _build_floored_http(base)
    except Exception as exc:  # fail open at startup too: serve uvicorn's own protocol
        _fell_open("http", "class build", exc)
        return base


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
    """uvicorn's WebSocket protocol with the headers on its pre-handshake ``500`` and, on the legacy
    websockets server, on every handshake answer that library writes. See the module docstring for
    what is NOT covered.

    ``base`` defaults to uvicorn's resolved ``AutoWebSocketsProtocol``. That is ``None`` when no
    WebSocket library is installed, and then this returns ``None`` too, which uvicorn reads exactly
    as it reads ``ws="auto"`` in that environment: WebSockets off."""
    if base is None:
        from uvicorn.protocols.websockets.auto import AutoWebSocketsProtocol

        resolved: Any = AutoWebSocketsProtocol  # uvicorn types it as a callable, not a class
        if resolved is None:
            return None
        base = resolved

    try:
        return _build_floored_ws(base)
    except Exception as exc:  # fail open at startup too: serve uvicorn's own protocol
        _fell_open("ws", "class build", exc)
        return base


def _build_floored_ws(base: type[Any]) -> type[asyncio.Protocol]:
    class _FlooredWebSocketProtocol(base):  # type: ignore[misc]
        def send_500_response(self, *args: Any, **kwargs: Any) -> None:
            _write_with_headers(self, "ws-500", partial(super().send_500_response, *args, **kwargs))

    if hasattr(base, "write_http_response"):
        # The legacy websockets server writes every handshake answer through this one method: the
        # 101, the app's denial, and its OWN answers to a bad handshake. Add the headers where
        # absent, so the 101 and the denial, which the floor already covered, are not stamped twice.

        class _FlooredLegacyWebSocketProtocol(_FlooredWebSocketProtocol):
            def write_http_response(
                self, status: Any, headers: Any, *args: Any, **kwargs: Any
            ) -> None:
                try:
                    for name, value in PROTOCOL_SECURITY_HEADERS:
                        if name not in headers:
                            headers[name] = value
                except Exception as exc:
                    _fell_open("ws-handshake", "header addition", exc)
                super().write_http_response(status, headers, *args, **kwargs)

        return _FlooredLegacyWebSocketProtocol
    return _FlooredWebSocketProtocol
