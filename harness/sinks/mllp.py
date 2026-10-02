# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""MLLP sink: a loopback MLLP listener that records every frame and answers with an ACK.

``reply`` picks the answer: ``"AA"`` (the default), ``"AE"`` or ``"AR"`` to drive the engine's
retry and dead-letter path, or None to answer nothing (a NONE-ack peer). The frame size is capped
at the engine's own per-message cap, so a runaway delivery is refused rather than buffered.
"""

from __future__ import annotations

import socket

from harness.endpoints import Endpoints
from harness.sinks import LOOPBACK, Record, Sink
from harness.sinks._tcp import LoopbackServer, recv_chunks
from messagefoundry.mllpcodec import MLLPDecoder, MLLPFrameError, build_ack, frame
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

KIND = "mllp"


class MLLPSink(Sink):
    kind = KIND

    def __init__(self, host: str = LOOPBACK, port: int = 0, *, reply: str | None = "AA") -> None:
        super().__init__()
        if reply not in (None, "AA", "AE", "AR"):
            raise ValueError(f"reply must be AA, AE, AR or None, got {reply!r}")
        self.reply = reply
        self._server = LoopbackServer(host, port, self._handle)

    @property
    def port(self) -> int:
        return self._server.port

    def start(self) -> None:
        self._server.start()

    def stop(self) -> None:
        self._server.stop()

    def _handle(self, conn: socket.socket, peer: str) -> None:
        decoder = MLLPDecoder(max_frame_bytes=DEFAULT_MAX_MESSAGE_BYTES)
        read = recv_chunks(conn, self._server.stopping)
        while (chunk := read()) is not None:
            try:
                for payload in decoder.feed(chunk):
                    self._add(Record(payload, {"peer": peer}))
                    if self.reply is not None:
                        conn.sendall(frame(build_ack(payload, code=self.reply)))
            except MLLPFrameError:
                return  # over the cap: drop the connection, as the engine's own listener does
            except OSError:
                return


def build(endpoints: Endpoints, key: str) -> Sink:
    return MLLPSink(LOOPBACK, endpoints.port(key))
