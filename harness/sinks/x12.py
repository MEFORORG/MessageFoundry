# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""X12 sink: a loopback listener that reassembles each ``ISA...IEA`` interchange and records it.

There is no sentinel to strip: the interchange is its own frame, so the sink reassembles with the
same pure :class:`~messagefoundry.parsing.x12.X12FrameReader` the engine's ``X12()`` connector uses
and records each interchange verbatim, capped at the engine's per-interchange cap.

``ta1`` picks the answer, the one reply the engine's X12 outbound classifies:

- ``"A"`` (the default) -- a TA1 interchange acknowledgement, TA104 ``A``: accepted;
- ``"E"`` -- accepted with errors (the engine delivers and does not retry);
- ``"R"`` -- rejected. The engine treats TA1*R as a permanent negative acknowledgement and
  dead-letters the delivery without retrying;
- None -- answer nothing (a fire-and-forget peer).

The TA1 names the received ISA13 in TA101 and carries a fresh ISA13 of its own. When the received
interchange has no readable ISA13 the sink answers nothing rather than invent one, and the same holds
for an ISA13 that is not nine digits. ISA13 is read by fixed offset, so it can hold the element or
segment separator; echoed into a reply written with fixed separators, ``1*0*0*R~Z`` would make an
accepting TA1 parse as TA1-04 ``R``, which the engine dead-letters (ASVS 1.1.2). A TA1 with a made-up
TA101 would acknowledge an interchange nobody sent, so silence is the answer. The interchange is
still recorded, with the value read, as everything received is.
"""

from __future__ import annotations

import socket

from harness.drivers._x12_interchange import is_control_number
from harness.drivers._x12_interchange import ta1 as build_ta1
from harness.endpoints import Endpoints
from harness.sinks import LOOPBACK, Record, Sink
from harness.sinks._tcp import LoopbackServer, recv_chunks
from messagefoundry.parsing.x12 import X12FrameError, X12FrameReader, X12Peek, X12PeekError
from messagefoundry.parsing.x12.delimiters import DEFAULT_MAX_INTERCHANGE_BYTES

KIND = "x12"


def isa13_of(interchange: str | bytes) -> str | None:
    """ISA13 (the interchange control number) of an X12 payload, or None when it does not peek."""
    try:
        return X12Peek.parse(interchange).control_number or None
    except X12PeekError:
        return None


class X12Sink(Sink):
    kind = KIND

    def __init__(self, host: str = LOOPBACK, port: int = 0, *, ta1: str | None = "A") -> None:
        super().__init__()
        if ta1 not in (None, "A", "E", "R"):
            raise ValueError(f"ta1 must be A, E, R or None, got {ta1!r}")
        self.ta1 = ta1
        self._server = LoopbackServer(host, port, self._handle)

    @property
    def port(self) -> int:
        return self._server.port

    def start(self) -> None:
        self._server.start()

    def stop(self) -> None:
        self._server.stop()

    def _handle(self, conn: socket.socket, peer: str) -> None:
        reader = X12FrameReader(max_interchange_bytes=DEFAULT_MAX_INTERCHANGE_BYTES)
        read = recv_chunks(conn, self._server.stopping)
        while (chunk := read()) is not None:
            try:
                for interchange in reader.feed(chunk):
                    control = isa13_of(interchange)
                    self._add(Record(interchange, {"peer": peer, "isa13": control or ""}))
                    # Never echo an ISA13 that is not nine digits: see the module docstring.
                    if self.ta1 is not None and control is not None and is_control_number(control):
                        conn.sendall(build_ta1(control, self.ta1))
            except X12FrameError:
                return  # over the cap: drop the connection, as the engine's own listener does
            except OSError:
                return


def build(endpoints: Endpoints, key: str) -> Sink:
    return X12Sink(LOOPBACK, endpoints.port(key))  # never endpoints.host: a sink binds loopback
