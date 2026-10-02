# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""HTTP driver: POST each payload to an engine ``Http`` inbound, one request per connection.

The ``Http`` inbound answers ``202 Accepted`` with a JSON receipt carrying the engine
``message_id`` once the body is durably committed, and ``422`` for a body it read, recorded as
``ERROR`` and refused. Any non-2xx answer is reported as a failed send (``error`` names the status,
never the body), with the answer kept in ``reply``: unlike an MLLP NAK, which is an application
answer on a delivered frame, a non-2xx HTTP status is the request itself failing.

Plain HTTP on loopback, which is what the ``Http`` inbound serves without ``tls=True``. The reply
read is capped: the inbound's answers are a few dozen bytes, and a driver must not buffer an
unbounded body from a peer that misbehaves.
"""

from __future__ import annotations

import http.client
import json
from collections.abc import Sequence

from harness.drivers import Driver, Injection
from harness.endpoints import Endpoints

KIND = "http"

#: The ``Content-Type`` an HL7 v2 POST carries (the inbound does not read it; a partner sends one).
HL7_CONTENT_TYPE = "application/hl7-v2"

#: How an ``error`` names a request the inbound ANSWERED with a non-2xx status (``"HTTP 422"``), as
#: opposed to one that never reached it: a scenario tells the two apart by this prefix.
ANSWERED_PREFIX = "HTTP "

#: The most of an inbound's answer a driver reads.
MAX_REPLY_BYTES = 64 * 1024


class HttpDriver(Driver):
    kind = KIND

    def __init__(
        self,
        host: str,
        port: int,
        *,
        path: str = "/",
        method: str = "POST",
        content_type: str = HL7_CONTENT_TYPE,
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.path = path
        self.method = method
        self.content_type = content_type
        self.timeout = timeout

    def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
        return [self._send_one(payload) for payload in payloads]

    def post(self, payload: bytes) -> tuple[int, bytes]:
        """Send one request; return the answer's status and (capped) body. Raises :class:`OSError`
        or :class:`http.client.HTTPException` when there is no answer."""
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            conn.request(
                self.method, self.path, body=payload, headers={"Content-Type": self.content_type}
            )
            response = conn.getresponse()
            return response.status, response.read(MAX_REPLY_BYTES)
        finally:
            conn.close()

    def _send_one(self, payload: bytes) -> Injection:
        try:
            status, body = self.post(payload)
        except (OSError, http.client.HTTPException) as exc:
            return Injection(error=f"{type(exc).__name__}: {exc}")
        if 200 <= status < 300:
            return Injection(reply=body)
        return Injection(error=f"{ANSWERED_PREFIX}{status}", reply=body)


def message_id_of(reply: bytes | None) -> str | None:
    """The engine ``message_id`` in an ``Http`` inbound's ``202`` receipt, or None."""
    if not reply:
        return None
    try:
        receipt = json.loads(reply)
    except (ValueError, RecursionError):  # a deeply nested reply must read as "no receipt"
        return None
    value = receipt.get("message_id") if isinstance(receipt, dict) else None
    return value if isinstance(value, str) and value else None


def build(endpoints: Endpoints, key: str) -> Driver:
    return HttpDriver(endpoints.host, endpoints.port(key))
