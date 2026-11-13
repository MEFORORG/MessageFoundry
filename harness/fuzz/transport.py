# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How a fuzz case reaches the engine, and what came back.

One shape: ``mllp`` gets :class:`WireMLLPDriver`, the MLLP driver's wire-level twin. It sends the
case's bytes verbatim -- framing included, so the ``frame`` layer can break the framing -- then
half-closes its sending side, so an engine left holding an incomplete frame sees end-of-stream and
can close cleanly instead of waiting out a timeout. It reads EVERY reply frame until the engine
closes, so a two-frame case is answered and counted twice, and it tells a clean close from a
timeout, a reset, a reply cut off mid-frame and bytes outside any frame, which the stock driver
folds together. Its probe connects to the inbound before the first case.

**Why only mllp.** Every other driver kind is refused as a setup error (BACKLOG #5638, #5639); this
paragraph is the one statement of why, which the invariants module and the harness README point
at. The invariants read every reply as an HL7 v2 ACK and match the store to the acknowledgements,
and a stock driver has neither an inbound probe nor a per-frame reply count. So an HTTP, DIMSE or
X12 reply would fail as not parsing as HL7, and a send that got no reply -- a file drop always, any other
kind whenever the engine stays silent -- would pass with nothing checked, even against an endpoint
no inbound polls. A kind joins only with its own probe and a reply invariant for its own shape.
"""

from __future__ import annotations

import abc
import socket
from collections.abc import Sequence
from dataclasses import dataclass

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
#: The ceiling on everything one case reads back, frames and stray bytes alike (BACKLOG #1127). A
#: case gets one ACK per message it carries, so 16 replies at the frame ceiling is far past any real
#: answer. Without it, an engine that kept writing would never hit the per-read timeout.
_MAX_EXCHANGE_BYTES = 16 * _MAX_REPLY_BYTES

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

    #: Names the replay files a campaign writes, so a replay is sent through the same kind.
    kind: str

    @abc.abstractmethod
    def send(self, data: bytes) -> Exchange: ...

    @abc.abstractmethod
    def probe(self) -> str:
        """Empty when the inbound is there to fuzz; otherwise why not. Checked once, before the
        first case, so a wrong port is a setup error rather than an invariant failure. Abstract, so
        a new transport cannot inherit a probe that reports every endpoint as there."""


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
            if received > _MAX_EXCHANGE_BYTES:
                detail = f"the engine sent over {_MAX_EXCHANGE_BYTES} reply bytes for one case"
                return Exchange(MALFORMED, tuple(replies), detail)
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


#: The endpoint the mllp driver fuzzes when none is named.
DEFAULT_ENDPOINT = "mllp_in"


def build_transport(
    kind: str, endpoints: Endpoints, key: str | None, *, timeout: float
) -> Transport:
    """The transport for driver ``kind`` aimed at endpoint ``key`` (``mllp_in`` when None).
    Raises ValueError for any kind but ``mllp`` (the module docstring says why) and for a bad port
    value; KeyError for an endpoint no family declares. ``timeout`` bounds one MLLP reply."""
    if kind != _WireTransport.kind:
        raise ValueError(
            f"--fuzz-driver accepts only {_WireTransport.kind}, not {kind!r} "
            "(the harness/fuzz/transport.py module docstring says why)"
        )
    port = endpoints.port(DEFAULT_ENDPOINT if key is None else key)
    return _WireTransport(WireMLLPDriver(endpoints.host, port, timeout=timeout))
