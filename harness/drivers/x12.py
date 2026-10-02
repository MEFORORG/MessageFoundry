# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""X12 driver: each interchange written verbatim on its own connection.

X12-over-TCP has no transport sentinel -- the ``ISA...IEA`` interchange is its own frame, and the
engine's ``X12()`` inbound reassembles it with the pure
:class:`~messagefoundry.parsing.x12.X12FrameReader`. So the driver adds no framing at all. It
half-closes after the write and reads until the engine closes, for the synchronisation reason
:mod:`harness.drivers.tcp` gives; anything written back is reassembled with the same reader and the
first interchange kept as the reply (the engine's X12 inbound is an opaque relay and answers
nothing today).
"""

from __future__ import annotations

from collections.abc import Sequence

from harness.drivers import Driver, Injection
from harness.drivers.tcp import send_and_drain
from harness.endpoints import Endpoints
from messagefoundry.parsing.x12 import X12FrameError, X12FrameReader
from messagefoundry.parsing.x12.delimiters import DEFAULT_MAX_INTERCHANGE_BYTES

KIND = "x12"


class X12Driver(Driver):
    kind = KIND

    def __init__(self, host: str, port: int, *, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
        return [self._send_one(payload) for payload in payloads]

    def _send_one(self, payload: bytes) -> Injection:
        try:
            back = send_and_drain(
                self.host, self.port, payload, self.timeout, DEFAULT_MAX_INTERCHANGE_BYTES
            )
        except OSError as exc:
            return Injection(error=str(exc))
        reader = X12FrameReader(max_interchange_bytes=DEFAULT_MAX_INTERCHANGE_BYTES)
        try:
            for interchange in reader.feed(back):
                return Injection(reply=interchange)
        except X12FrameError:
            pass
        return Injection()


def build(endpoints: Endpoints, key: str) -> Driver:
    return X12Driver(endpoints.host, endpoints.port(key))
