# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Raw-TCP sink: a loopback listener that deframes (STX/ETX by default) and records each frame.

The framing is :mod:`messagefoundry.framing`, the codec the engine's ``Tcp()`` outbound frames
with. The engine does not parse a raw-TCP reply: with ``expect_reply`` it waits for one frame and
treats any frame as confirmation. So the sink's answer is a choice of behaviour, not of content:

- ``reply`` (default ``b"ACK"``) -- answer each frame with that payload, framed;
- ``reply=None`` -- answer nothing and keep the connection open (a fire-and-forget peer);
- ``refuse=True`` -- record the frame, then close without answering. An outbound that expects a
  reply fails that delivery and retries, which is how a scenario drives retry and dead-letter.

The frame is capped at the engine's per-message cap, so a runaway delivery is refused rather than
buffered.
"""

from __future__ import annotations

import socket

from harness.endpoints import Endpoints
from harness.sinks import LOOPBACK, Record, Sink
from harness.sinks._tcp import LoopbackServer, recv_chunks
from messagefoundry.framing import STX_ETX_CODEC, FrameCodec, FrameError
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

KIND = "tcp"


class TcpSink(Sink):
    kind = KIND

    def __init__(
        self,
        host: str = LOOPBACK,
        port: int = 0,
        *,
        codec: FrameCodec = STX_ETX_CODEC,
        reply: bytes | None = b"ACK",
        refuse: bool = False,
    ) -> None:
        super().__init__()
        self.codec = codec
        self.reply = reply
        self.refuse = refuse
        self._server = LoopbackServer(host, port, self._handle)

    @property
    def port(self) -> int:
        return self._server.port

    def start(self) -> None:
        self._server.start()

    def stop(self) -> None:
        self._server.stop()

    def _handle(self, conn: socket.socket, peer: str) -> None:
        decoder = self.codec.decoder(max_frame_bytes=DEFAULT_MAX_MESSAGE_BYTES)
        read = recv_chunks(conn, self._server.stopping)
        while (chunk := read()) is not None:
            try:
                for payload in decoder.feed(chunk):
                    self._add(Record(payload, {"peer": peer}))
                    if self.refuse:
                        return  # the server closes the connection; no reply was sent
                    if self.reply is not None:
                        conn.sendall(self.codec.frame(self.reply))
            except FrameError:
                return  # over the cap: drop the connection, as the engine's own listener does
            except OSError:
                return


def build(endpoints: Endpoints, key: str) -> Sink:
    return TcpSink(LOOPBACK, endpoints.port(key))  # never endpoints.host: a sink binds loopback
