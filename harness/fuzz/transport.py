# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How a fuzz case reaches the engine, and what came back.

Two shapes, both built on the ``harness/drivers`` family:

* ``mllp`` gets :class:`WireMLLPDriver`, the MLLP driver's wire-level twin. It sends the case's bytes
  verbatim -- framing included, so the ``frame`` layer can break the framing -- then half-closes
  its sending side, so an engine left holding an incomplete frame sees end-of-stream and can close
  cleanly instead of waiting out a timeout. It reads EVERY reply frame until the engine closes, so a
  two-frame case is answered and counted twice, and it tells a clean close from a timeout, a reset,
  a reply cut off mid-frame and bytes outside any frame, which the stock driver folds together.
* Any other kind is the stock driver for that kind (``harness.drivers.build``), sending the payload
  unframed. Those transports carry the byte and field layers only, and an absent reply reads as a
  clean close because the stock :class:`~harness.drivers.Injection` cannot say more.
"""

from __future__ import annotations

import abc
import socket
from collections.abc import Sequence
from dataclasses import dataclass

from harness import drivers
from harness.drivers import Injection
from harness.drivers.mllp import MLLPDriver
from harness.endpoints import Endpoints
from messagefoundry.mllpcodec import MLLPDecoder, MLLPFrameError

REPLY = "reply"
CLOSED = "closed"
TIMEOUT = "timeout"
RESET = "reset"
REFUSED = "refused"
MALFORMED = "malformed"

#: The ceiling on one reply frame. An ACK is a few hundred bytes; a reply past this is itself a defect.
_MAX_REPLY_BYTES = 1024 * 1024

#: Start block, end block and trailing CR: what MLLP adds around each payload.
_FRAME_OVERHEAD = 3


@dataclass(frozen=True)
class Exchange:
    """One case's round trip. ``outcome`` is one of the module constants; ``replies`` holds every
    reply frame received; ``detail`` names a transport error and never quotes a body."""

    outcome: str
    replies: tuple[bytes, ...] = ()
    detail: str = ""


class Transport(abc.ABC):
    """Sends one case's bytes and reports the exchange."""

    kind: str
    #: True when ``send`` takes framed wire bytes (and so can carry the ``frame`` layer).
    wire: bool

    @abc.abstractmethod
    def send(self, data: bytes) -> Exchange: ...

    def probe(self) -> str:
        """Empty when the inbound is there to fuzz; otherwise why not. Checked once, before the
        first case, so a wrong port is a setup error rather than an invariant failure."""
        return ""


class WireMLLPDriver(MLLPDriver):
    """An MLLP driver whose payloads are already-framed wire bytes, sent as they are."""

    def exchange(self, wire: bytes) -> Exchange:
        try:
            sock = socket.create_connection((self.host, self.port), self.timeout)
        except OSError as exc:
            return Exchange(REFUSED, detail=str(exc))
        with sock:
            sock.settimeout(self.timeout)
            try:
                sock.sendall(wire)
                sock.shutdown(socket.SHUT_WR)
            except OSError as exc:
                return Exchange(RESET, detail=f"send failed: {exc}")
            return _read_replies(sock)

    def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
        """The :class:`~harness.drivers.Driver` contract over :meth:`exchange`: each payload is wire
        bytes, the reply is the first reply frame, and anything but a reply or a clean close is an
        error."""
        out: list[Injection] = []
        for wire in payloads:
            ex = self.exchange(wire)
            error = "" if ex.outcome in (REPLY, CLOSED) else f"{ex.outcome}: {ex.detail}"
            out.append(Injection(error=error, reply=ex.replies[0] if ex.replies else None))
        return out


def _read_replies(sock: socket.socket) -> Exchange:
    decoder = MLLPDecoder(max_frame_bytes=_MAX_REPLY_BYTES)
    replies: list[bytes] = []
    received = 0
    try:
        while chunk := sock.recv(65536):
            received += len(chunk)
            replies.extend(decoder.feed(chunk))
    except MLLPFrameError as exc:
        return Exchange(MALFORMED, tuple(replies), f"reply framing: {exc}")
    except TimeoutError:
        return Exchange(TIMEOUT, tuple(replies), "the engine neither replied nor closed in time")
    except OSError as exc:
        return Exchange(RESET, tuple(replies), str(exc))
    if decoder.in_frame:
        return Exchange(MALFORMED, tuple(replies), "the engine closed inside a reply frame")
    framed = sum(len(r) + _FRAME_OVERHEAD for r in replies)
    if received != framed:
        # The decoder discards bytes outside a frame, so count them: an engine that writes
        # anything but whole SB..FS CR frames is answering in something other than MLLP.
        detail = f"{received - framed} reply byte(s) outside an MLLP frame"
        return Exchange(MALFORMED, tuple(replies), detail)
    return Exchange(REPLY if replies else CLOSED, tuple(replies))


class _WireTransport(Transport):
    kind = "mllp"
    wire = True

    def __init__(self, driver: WireMLLPDriver) -> None:
        self.driver = driver

    def send(self, data: bytes) -> Exchange:
        return self.driver.exchange(data)

    def probe(self) -> str:
        address = (self.driver.host, self.driver.port)
        try:
            socket.create_connection(address, self.driver.timeout).close()
        except OSError as exc:
            return f"cannot connect to MLLP {address[0]}:{address[1]}: {exc}"
        return ""


class _DriverTransport(Transport):
    wire = False

    def __init__(self, kind: str, driver: drivers.Driver) -> None:
        self.kind = kind
        self.driver = driver

    def send(self, data: bytes) -> Exchange:
        (injection,) = self.driver.inject([data])
        if injection.error:
            return Exchange(REFUSED, detail=injection.error)
        if injection.reply is None:
            return Exchange(CLOSED)
        return Exchange(REPLY, (injection.reply,))


#: The endpoint a driver kind fuzzes when none is named. Only MLLP has an obvious one.
DEFAULT_ENDPOINT = {"mllp": "mllp_in"}


def build_transport(
    kind: str, endpoints: Endpoints, key: str | None, *, timeout: float
) -> Transport:
    """The transport for driver ``kind`` aimed at endpoint ``key`` (the kind's default when None).
    Raises KeyError for a kind no harness driver serves, an endpoint no family declares, or a kind
    with no default endpoint and none named; ValueError for a bad port value. ``timeout`` bounds
    one MLLP reply; a stock driver keeps its own."""
    if key is None:
        try:
            key = DEFAULT_ENDPOINT[kind]
        except KeyError:
            raise KeyError(
                f"name the endpoint the {kind!r} driver sends to (--fuzz-endpoint)"
            ) from None
    if kind == "mllp":
        return _WireTransport(WireMLLPDriver(endpoints.host, endpoints.port(key), timeout=timeout))
    return _DriverTransport(kind, drivers.build(kind, endpoints, key))
