# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Raw-TCP and X12 graph the harness drives (vault BACKLOG #2674). Loaded with every other
top-level module here by ``python -m messagefoundry serve --config harness/config``.

Ports are read with the engine's own ``env()``, each under ``harness_<endpoint key>`` with the same
default as its entry in ``harness/endpoints/tcp.py`` or ``harness/endpoints/x12.py`` (2580 to 2583),
so a ``MEFOR_VALUE_HARNESS_<KEY>`` variable moves the graph and the scenarios together (the engine
applies it only with an environment active, e.g. ``serve --env dev``). This module imports nothing
from ``harness``: an engine serving it from its own install need not have the harness importable.
Two independent paths, neither of which routes another family's messages:

| Path | Send this                                  | Decision                    | Disposition |
|------|--------------------------------------------|-----------------------------|-------------|
| TCP  | ADT, any trigger but A03 (STX/ETX framed)  | relayed unchanged to OB TCP | PROCESSED   |
| TCP  | ADT^A03                                    | handler raises              | ERROR       |
| TCP  | anything that is not HL7                   | inbound NAKs (framed AR)    | ERROR       |
| TCP  | any non-ADT HL7                            | router returns []           | UNROUTED    |
| X12  | an interchange whose envelope ties out     | relayed verbatim to OB X12  | PROCESSED   |
| X12  | an interchange whose envelope does not     | handler raises              | ERROR       |

The TCP inbound carries the default ``hl7v2`` content type, so each frame is parsed as HL7 and the
engine answers it with a framed HL7 ACK; that is what lets a scenario match its messages by MSH-10.
The TCP outbound expects a reply frame, so a peer that closes without one fails the delivery,
which retries on a fast policy and then dead-letters. The X12 inbound is ``content_type="x12"``, an
opaque relay that answers nothing; its outbound requires a TA1, and a TA1*R is a permanent reject
that dead-letters at once.

All data is synthetic; never point a real PHI or claims feed at a sample config.
"""

from messagefoundry import X12, Send, Tcp, env, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy
from messagefoundry.parsing.x12 import check_integrity

_HOST = env("harness_host", default="127.0.0.1")

#: Fast enough that a refused delivery dead-letters inside a scenario's timeout.
_FAST_RETRY = RetryPolicy(
    max_attempts=3, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=2.0
)

# --- raw TCP -------------------------------------------------------------------------------------

inbound(
    "IB_Harness_TCP",
    Tcp(port=env("harness_tcp_in", default=2580, cast=int), framing="stx_etx"),
    router="harness_tcp_router",
)
outbound(
    "OB_Harness_TCP",
    Tcp(
        host=_HOST,
        port=env("harness_tcp_out", default=2581, cast=int),
        framing="stx_etx",
        expect_reply=True,
        connect_timeout=3.0,
        timeout_seconds=5.0,
    ),
    retry=_FAST_RETRY,
)


@router("harness_tcp_router")
def route_tcp(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.1"] != "ADT":
        return []  # logged UNROUTED, never silently dropped
    return ["harness_tcp_handler"]


@handler("harness_tcp_handler")
def handle_tcp(msg):  # type: ignore[no-untyped-def]
    if msg["MSH-9.2"] == "A03":
        raise RuntimeError("simulated handler failure (A03) on the raw-TCP path")
    return Send("OB_Harness_TCP", msg)  # unchanged, so the sink can compare bytes


# --- X12 -----------------------------------------------------------------------------------------

inbound(
    "IB_Harness_X12",
    X12(port=env("harness_x12_in", default=2582, cast=int)),
    router="harness_x12_router",
    content_type="x12",
)
outbound(
    "OB_Harness_X12",
    X12(
        host=_HOST,
        port=env("harness_x12_out", default=2583, cast=int),
        ta1_required=True,
        connect_timeout=3.0,
        timeout_seconds=5.0,
    ),
    retry=_FAST_RETRY,
)


@router("harness_x12_router")
def route_x12(msg):  # type: ignore[no-untyped-def]
    return ["harness_x12_handler"]


@handler("harness_x12_handler")
def handle_x12(msg):  # type: ignore[no-untyped-def]
    if check_integrity(msg.raw):
        # A fixed message: the problem list quotes envelope values, which stay out of the error.
        raise ValueError("X12 envelope does not tie out (control numbers or counts disagree)")
    return Send("OB_Harness_X12", msg.raw)  # verbatim, so the sink can compare bytes
