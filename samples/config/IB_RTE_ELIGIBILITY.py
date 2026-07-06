# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Sample feed: real-time eligibility (X12 270 → 271) as synchronous request/response (ADR 0016).

A trigger 270 (eligibility inquiry) arrives, is forwarded to the payer over a raw-TCP X12 connection
that **blocks for the 271 on the same socket**, and the captured 271 is **re-ingressed** into a
``Loopback()`` inbound where a pure ``@router`` routes it onward — the ADR-0013 capture-then-re-ingress
machinery wired onto the X12 capture path.

- ``OB_PAYER_RTE`` sets ``expect_reply=True`` + ``reingress_to=`` (which implies capture) + a
  ``ta1_required`` knob: a **TA1** interchange ack is classified by the transport (TA1*A → accepted;
  TA1*R → permanent dead-letter; TA1*E → accepted-with-warning, not retried); a business 271 returned
  instead of a TA1 is itself the confirmation. The captured body rides re-ingress.
- ``IB_RTE_RESPONSE`` is a no-source ``Loopback()`` (the 271 arrives via the internal re-ingress, not a
  socket); ``content_type="x12"`` so the 271 routes as a ``RawMessage`` peeked via ``parsing.x12``.

Peers are environment-specific → ``env()`` (resolved from ``environments/<env>.toml``).

    python -m messagefoundry serve --config samples/config --env dev --db ./messagefoundry.db
"""

from messagefoundry import (
    AckMode,
    ContentType,
    Loopback,
    Send,
    X12,
    env,
    handler,
    inbound,
    outbound,
    router,
)
from messagefoundry.parsing.x12 import X12Peek

# Trigger: an internal requester sends a 270 to this raw-TCP X12 listener.
inbound("IB_RTE_REQUEST", X12(port=2730), router="rte_request_router", content_type=ContentType.X12)

# Synchronous request/response to the payer: send the 270, capture the 271/TA1, re-ingress the reply.
outbound(
    "OB_PAYER_RTE",
    X12(
        host=env("payer_rte_host"),
        port=env("payer_rte_port", cast=int),
        expect_reply=True,  # block for the returned interchange on the same socket
        reingress_to="IB_RTE_RESPONSE",  # route the captured 271 back in (implies capture_response)
        ta1_required=True,  # a no-reply within timeout_seconds is a retry (RTE partners always TA1)
    ),
)

# The captured 271 re-enters here as a RawMessage (no source — re-ingress only); a pure router routes it.
inbound(
    "IB_RTE_RESPONSE",
    Loopback(),
    router="rte_response_router",
    content_type=ContentType.X12,
    ack_mode=AckMode.NONE,  # no external peer to ACK (forced by Loopback)
)

# Where the routed 271 result goes (e.g. back to the requesting system).
outbound("OB_RTE_RESULT", X12(host=env("rte_result_host"), port=env("rte_result_port", cast=int)))


@router("rte_request_router")
def route_request(msg):
    if not msg.raw.lstrip().startswith("ISA"):
        return []  # not an X12 interchange → UNROUTED (counted + logged)
    return ["rte_query_handler"] if "270" in X12Peek.parse(msg.raw).transaction_ids() else []


@handler("rte_query_handler")
def query(msg):
    # Forward the 270 verbatim; OB_PAYER_RTE captures the 271 reply and re-ingresses it (ADR 0016).
    return Send("OB_PAYER_RTE", msg)


@router("rte_response_router")
def route_response(msg):
    # The captured 271 re-ingressed as a RawMessage(content_type="x12").
    if not msg.raw.lstrip().startswith("ISA"):
        return []
    return ["rte_result_handler"] if "271" in X12Peek.parse(msg.raw).transaction_ids() else []


@handler("rte_result_handler")
def result(msg):
    return Send("OB_RTE_RESULT", msg)
