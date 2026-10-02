# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Hostile-content pass-through graph: every message in, unchanged, to an MLLP and a File outbound.

The hostile-content scenarios (``harness/scenarios/hostile.py``) send WELL-FORMED HL7 whose field
values are hostile to a downstream sink -- path traversal, SQL and spreadsheet metacharacters,
markup, HL7 escapes, redefined delimiters, MLLP framing bytes, an oversize field, non-ASCII text.
They need a path that changes nothing, so that what a sink receives can be compared byte for byte
with what was sent. The coverage graph's fan-out sets MSH-6, so it cannot serve.

| Inbound          | Router -> Handler                 | Outbounds                                 |
|------------------|-----------------------------------|-------------------------------------------|
| IB_Hostile_MLLP  | hostile_router -> hostile_handler | OB_Hostile_Echo (MLLP) + FILE-OUT_Hostile |
| FILE-IN_Hostile  | the same                          | the same                                  |

``FILE-OUT_Hostile`` names each file ``{MSH-10}.hl7``, the same template the coverage archive uses,
so a control id carrying path separators reaches the engine's filename rendering. Only these two
inbounds name ``hostile_router``, so no other family's traffic reaches it, and the router and
handler read no field: a hostile value is data this graph is never steered by.

Ports and directories are the engine's own ``env()`` values, keyed ``harness_`` plus the endpoint
key in ``harness/endpoints/hostile.py``, with the same defaults (2628/2629 and
``./harness_io/hostile_*``); ``MEFOR_VALUE_HARNESS_<KEY>`` overrides one. The graph imports nothing
from ``harness``, so an engine running from its own wheel can load it.

All data is synthetic; never point a real PHI feed at a sample config.
"""

from __future__ import annotations

from messagefoundry import MLLP, File, Send, env, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy
from messagefoundry.parsing.message import Message, RawMessage

inbound(
    "IB_Hostile_MLLP",
    MLLP(port=env("harness_hostile_mllp_in", default=2628, cast=int)),
    router="hostile_router",
)
inbound(
    "FILE-IN_Hostile",
    File(
        directory=env("harness_hostile_file_in", default="./harness_io/hostile_in"),
        pattern="*.hl7",
        poll_seconds=0.5,
    ),
    router="hostile_router",
)

# A fast retry, so a run with no sink listening dead-letters quickly instead of holding the queue.
outbound(
    "OB_Hostile_Echo",
    MLLP(
        host=env("harness_host", default="127.0.0.1"),
        port=env("harness_hostile_mllp_echo", default=2629, cast=int),
        connect_timeout=3.0,
        timeout_seconds=5.0,
    ),
    retry=RetryPolicy(
        max_attempts=3, backoff_seconds=1.0, backoff_multiplier=2.0, max_backoff_seconds=5.0
    ),
)
outbound(
    "FILE-OUT_Hostile",
    File(
        directory=env("harness_hostile_file_out", default="./harness_io/hostile_out"),
        filename="{MSH-10}.hl7",
    ),
)


@router("hostile_router")
def route_hostile(msg: Message | RawMessage) -> list[str]:
    return ["hostile_handler"]


@handler("hostile_handler")
def pass_through(msg: Message | RawMessage) -> list[Send]:
    # Unchanged on purpose: the scenarios compare each sink's bytes with what was sent.
    return [Send("OB_Hostile_Echo", msg), Send("FILE-OUT_Hostile", msg)]
