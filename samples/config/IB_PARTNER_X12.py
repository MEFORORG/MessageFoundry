# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sample route: receive ASC X12 EDI over raw TCP (ISA/IEA framed), route by transaction set, relay.

The inbound declares ``content_type="x12"`` so each interchange routes as a ``RawMessage`` (ADR 0004);
the Router and Handler parse it on demand with the pure ``messagefoundry.parsing.x12`` codec — a cheap
ISA + GS/ST *peek* for routing, never a full parse on the hot path. The interchange is the frame, so
``X12()`` takes no delimiter knobs (they're discovered from each ISA header, ADR 0012). The outbound
peer is environment-specific, so it's authored with ``env()`` (resolved from ``environments/<env>.toml``).

    python -m messagefoundry serve --config samples/config --env dev --db ./messagefoundry.db

See ``samples/messages/x12_270_eligibility.edi`` for a synthetic interchange to send.
"""

from messagefoundry import X12, ContentType, Send, env, handler, inbound, outbound, router
from messagefoundry.parsing.x12 import X12Peek

inbound(
    "IB_PARTNER_X12",
    X12(port=2710),
    router="partner_x12_router",
    content_type=ContentType.X12,
)
outbound("OB_PAYER_X12", X12(host=env("payer_x12_host"), port=env("payer_x12_port", cast=int)))


@router("partner_x12_router")
def route(msg):
    # Anything that isn't an X12 interchange at all (e.g. mis-delivered to this port) is UNROUTED —
    # still counted + logged, never an error. A genuinely malformed X12 header (starts with ISA but
    # bad) instead lets X12Peek.parse raise below → ERROR/dead-letter (the count-and-log invariant).
    if not msg.raw.lstrip().startswith("ISA"):
        return []
    # Peek the ISA + GS/ST headers (cheap, no full parse) to decide where the interchange goes. One
    # interchange may carry several transaction sets, so route on the full list.
    peek = X12Peek.parse(msg.raw)
    if "270" in peek.transaction_ids():  # eligibility inquiry → forward
        return ["partner_x12_handler"]
    return []  # other X12 transaction sets are UNROUTED here (still counted + logged)


@handler("partner_x12_handler")
def handle(msg):
    # Relay the interchange verbatim. A real handler could edit fields via
    # ``messagefoundry.parsing.x12.X12Message`` and re-encode before sending.
    return Send("OB_PAYER_X12", msg)
