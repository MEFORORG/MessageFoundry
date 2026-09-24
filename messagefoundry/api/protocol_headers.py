# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Security headers on the responses uvicorn writes itself, below the ASGI app (BACKLOG #1120).

The header floor in :mod:`messagefoundry.api.header_floor` sees every response the ASGI app sends. It
cannot see the ones uvicorn's protocol layer writes on its own, because no app code runs for them:

* the ``400`` for a request uvicorn cannot parse (``send_400_response`` on the HTTP protocol);
* the ``500`` when the app raised, or returned, without starting a response
  (``send_500_response`` on uvicorn's per-request cycle object, not on the protocol); and
* the ``500`` when a WebSocket app fails before the handshake is answered (``send_500_response`` on
  the WebSocket protocol).

This module builds protocol subclasses that add ``X-Content-Type-Options: nosniff`` and
``Content-Security-Policy: frame-ancestors 'none'`` to exactly those responses.

**Never HSTS here.** Whether HSTS belongs on a response depends on the request's host and the served
chain (:func:`~messagefoundry.api.header_floor.hsts_notable`). On the default posture, a self-signed
pair on 127.0.0.1, it must stay absent. ``uvicorn.Config(headers=...)`` is the tempting shortcut and
it is wrong twice: it is unconditional, and it would stamp every app response a second time on top
of the floor.

**Adding, not rewriting.** Each override calls uvicorn's own method and adds the headers on the way
out, so the status, body and framing stay uvicorn's. The ``400`` and the WebSocket ``500`` are written
straight to the transport, synchronously, and the FIRST ``write`` of each carries the status line (for
httptools and the WebSocket writers it is the only write; h11 writes head, body and end separately).
So a transport proxy adds the header lines after that status line, for the length of that one call. The HTTP ``500``
goes through the cycle's ``send``, which prepends the cycle's ``default_headers``, so the override
extends those for that one response.

**Measured against one uvicorn.** Both overrides lean on uvicorn internals (the cycle attribute and
its ``default_headers``). ``tests/test_header_floor_wire.py`` pins the uvicorn version and drives every
family on the wire, so an upgrade that moves either goes red there rather than silently.
"""

from __future__ import annotations

import asyncio
import logging
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
_log = logging.getLogger(__name__)
#: One-shot latch for the warning in _floor_the_cycle_500.
_SWAP_FAILED: list[bool] = []
#: One floored subclass per uvicorn cycle class, built on first use.
_FLOORED_CYCLES: dict[type[Any], type[Any]] = {}

_HEADER_PAIRS = [
    (name.lower().encode("latin-1"), value.encode("latin-1"))
    for name, value in PROTOCOL_SECURITY_HEADERS
]


def _after_status_line(data: bytes) -> bytes:
    """Insert the header lines right after the status line. Anything that does not start with one
    is left untouched, so a write this module did not expect cannot be corrupted."""
    end = data.find(b"\r\n")
    if not data.startswith(b"HTTP/") or end < 0:
        return data
    return data[: end + 2] + _HEADER_LINES + data[end + 2 :]


class _HeaderInjectingTransport:
    """Forwards everything to the real transport, adding the header lines to the FIRST write only."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._pending = True

    def write(self, data: bytes | bytearray | memoryview) -> None:
        if self._pending:
            self._pending = False
            data = _after_status_line(bytes(data))
        self._inner.write(data)

    def writelines(self, chunks: Any) -> None:
        self.write(b"".join(bytes(chunk) for chunk in chunks))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _write_with_headers(protocol: Any, emit: Callable[[], None]) -> None:
    """Run one synchronous protocol-level response writer with the header lines added."""
    inner = protocol.transport
    protocol.transport = _HeaderInjectingTransport(inner)
    try:
        emit()
    finally:
        protocol.transport = inner


def _floored_cycle_class(cls: type[Any]) -> type[Any]:
    """A subclass of uvicorn's request cycle whose own ``500`` carries the headers, and nothing else.

    uvicorn prepends ``default_headers`` to every response start a cycle sends. Extending it only
    once the ``500`` is underway puts the headers on that response alone. REBIND, never mutate: the
    list uvicorn passed in is the server-wide ``server_state.default_headers``. A class, built once
    per cycle class, rather than a per-request closure: a closure stored on the cycle would hold the
    cycle, and a reference cycle keeps each request's scope and body alive until a GC pass."""

    floored = _FLOORED_CYCLES.get(cls)
    if floored is None:

        class _FlooredCycle(cls):  # type: ignore[misc]
            _mf_floored = True

            async def send_500_response(self) -> None:
                cycle: Any = self
                cycle.default_headers = [*cycle.default_headers, *_HEADER_PAIRS]
                await super().send_500_response()

        floored = _FLOORED_CYCLES[cls] = _FlooredCycle
    return floored


def _floor_the_cycle_500(cycle: Any) -> None:
    """Swap this cycle onto :func:`_floored_cycle_class`. If a future uvicorn makes that impossible,
    log once and serve the request anyway: a missing header on a 500 is not worth an outage."""
    cls = type(cycle)
    if getattr(cls, "_mf_floored", False):
        return
    try:
        cycle.__class__ = _floored_cycle_class(cls)
    except TypeError:
        if not _SWAP_FAILED:
            _SWAP_FAILED.append(True)
            _log.warning(
                "uvicorn's %s cannot be subclassed per request; its own 500 will not carry the "
                "security headers (BACKLOG #1120). Re-measure uvicorn's protocol layer.",
                cls.__name__,
            )


def floored_http_protocol_class(base: type[Any] | None = None) -> type[asyncio.Protocol]:
    """uvicorn's HTTP protocol with the headers on its ``400`` and on each cycle's ``500``.

    ``base`` defaults to uvicorn's resolved ``AutoHTTPProtocol`` (httptools when installed, else h11).
    Compose, never replace: ``client_cert_http_protocol_class(base=<this>)`` stacks the mTLS shim on
    top, since the two override different methods."""
    if base is None:
        from uvicorn.protocols.http.auto import AutoHTTPProtocol

        base = AutoHTTPProtocol

    class _FlooredHTTPProtocol(base):  # type: ignore[misc,valid-type]
        def send_400_response(self, msg: str) -> None:
            _write_with_headers(self, partial(super().send_400_response, msg))

        # Both implementations create each request's cycle with `self.cycle = RequestResponseCycle(...)`,
        # pipelined ones included, and before its task first runs. A property sees every one, once.
        @property
        def cycle(self) -> Any:
            return self._mf_cycle

        @cycle.setter
        def cycle(self, value: Any) -> None:
            if value is not None:
                _floor_the_cycle_500(value)
            self._mf_cycle = value

    return _FlooredHTTPProtocol


def floored_ws_protocol_class(base: type[Any] | None = None) -> type[asyncio.Protocol] | None:
    """uvicorn's WebSocket protocol with the headers on its pre-handshake ``500``, and, on the
    legacy websockets server, on the handshake rejections that library writes itself.

    NOT covered: the sans-I/O protocol's own handshake rejections, which it builds through
    ``ServerProtocol.reject``. It is not what ``ws="auto"`` resolves to at the locked versions.

    ``base`` defaults to uvicorn's resolved ``AutoWebSocketsProtocol``. That is ``None`` when no
    WebSocket library is installed, and then this returns ``None`` too, which uvicorn reads exactly
    as it reads ``ws="auto"`` in that environment: WebSockets off."""
    if base is None:
        from uvicorn.protocols.websockets.auto import AutoWebSocketsProtocol

        resolved: Any = AutoWebSocketsProtocol  # uvicorn types it as a callable, not a class
        if resolved is None:
            return None
        base = resolved

    class _FlooredWebSocketProtocol(base):  # type: ignore[misc,valid-type]
        def send_500_response(self) -> None:
            _write_with_headers(self, super().send_500_response)

    if hasattr(base, "write_http_response"):
        # The legacy websockets server writes every handshake answer through this one method: the
        # 101, the app's denial, and its OWN rejections of a bad handshake (400 for a missing key or
        # version, 426, 503 on shutdown, 500). Add the headers where absent, so the 101 and the
        # denial, which the floor already covered, are not stamped twice.

        class _FlooredLegacyWebSocketProtocol(_FlooredWebSocketProtocol):
            def write_http_response(self, status: Any, headers: Any, body: Any = None) -> None:
                for name, value in PROTOCOL_SECURITY_HEADERS:
                    if name not in headers:
                        headers[name] = value
                super().write_http_response(status, headers, body)

        return _FlooredLegacyWebSocketProtocol
    return _FlooredWebSocketProtocol
