# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Cross-registry validation for ``reply_from`` (ADR 0154 D4) — the facts one ``Http()`` call cannot
know, because they are about the *other* connection.

The load-bearing pair is ``ordering`` / ``max_attempts``, and they are load-bearing precisely because
the naive test passes. ``OutboundConnection.ordering`` defaults to ``None`` meaning *inherit* and
``retry`` defaults to no policy object at all, so a literal ``ordering == FIFO`` check passes cleanly
for the overwhelmingly common shape — which is the exact shape the refusal exists to catch. These
tests therefore assert against the shape that declares **nothing**.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.models import ContentType, OrderingMode, RetryPolicy
from messagefoundry.config.settings import DeliverySettings
from messagefoundry.config.wiring import (
    Http,
    Registry,
    Rest,
    WiringError,
    apply_sync_reply_capture_implication,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import check_http_sync_reply

# The shape that makes the feature work: an unordered lane that dead-letters rather than retrying
# forever. Everything else in this module is a departure from it.
SERVICEABLE = DeliverySettings(ordering=OrderingMode.UNORDERED, retry_max_attempts=3)


def _graph(
    *,
    reply_from: str | None = "OB_PARTNER",
    reply_content_type: str = "passthrough",
    capture_response: bool = True,
    capture_headers: list[str] | None = None,
    deployed: bool = True,
    ordering: OrderingMode | None = None,
    retry: RetryPolicy | None = None,
    outbound_name: str = "OB_PARTNER",
) -> tuple[Registry, object]:
    reg = Registry()
    ic = build_inbound_connection(
        "IB_HTTP",
        Http(port=0, reply_from=reply_from, reply_content_type=reply_content_type)
        if reply_from
        else Http(port=0),
        router="r",
        content_type=ContentType.JSON,
    )
    reg.add_inbound(ic)
    reg.add_outbound(
        build_outbound_connection(
            outbound_name,
            Rest(
                url="https://partner.example/ingest",
                capture_response=capture_response,
                capture_response_headers=capture_headers,
            ),
            deployed=deployed,
            ordering=ordering,
            retry=retry,
        )
    )
    return reg, ic


def test_a_serviceable_graph_passes() -> None:
    reg, ic = _graph(ordering=OrderingMode.UNORDERED, retry=RetryPolicy(max_attempts=3))
    apply_sync_reply_capture_implication(reg)
    check_http_sync_reply(ic, reg, delivery=SERVICEABLE)


def test_an_inbound_without_reply_from_is_untouched() -> None:
    reg, ic = _graph(reply_from=None)
    check_http_sync_reply(ic, reg, delivery=DeliverySettings())  # returns before any arm: fine


def test_an_unknown_or_undeployed_target_is_refused() -> None:
    reg, ic = _graph(outbound_name="OB_SOMETHING_ELSE")
    with pytest.raises(WiringError, match="unknown outbound"):
        check_http_sync_reply(ic, reg, delivery=SERVICEABLE)

    reg, ic = _graph(deployed=False)
    with pytest.raises(WiringError, match="deployed=False"):
        check_http_sync_reply(ic, reg, delivery=SERVICEABLE)


def test_a_target_that_does_not_capture_is_refused() -> None:
    # Without capture_response there is no reply to return, so every call would block to timeout.
    reg, ic = _graph(capture_response=False)
    with pytest.raises(WiringError, match="capture_response=True"):
        check_http_sync_reply(ic, reg, delivery=SERVICEABLE)


def test_reply_from_implies_capturing_the_content_type() -> None:
    # The ADR contradicts itself here: reply_content_type defaults to "passthrough", which D4 says
    # requires content-type in capture_response_headers — a setting that defaults to None. So the
    # ADR's own headline shape would refuse. The implication resolves it.
    reg, ic = _graph(ordering=OrderingMode.UNORDERED, retry=RetryPolicy(max_attempts=3))
    assert not reg.outbound["OB_PARTNER"].spec.settings["capture_response_headers"]

    apply_sync_reply_capture_implication(reg)

    headers = reg.outbound["OB_PARTNER"].spec.settings["capture_response_headers"]
    assert [h.lower() for h in headers] == ["content-type"]
    check_http_sync_reply(ic, reg, delivery=SERVICEABLE)


def test_the_implication_is_idempotent_and_preserves_operator_headers() -> None:
    reg, _ = _graph(capture_headers=["X-Request-Id", "Content-Type"])
    apply_sync_reply_capture_implication(reg)
    apply_sync_reply_capture_implication(reg)
    headers = reg.outbound["OB_PARTNER"].spec.settings["capture_response_headers"]
    assert headers == ["X-Request-Id", "Content-Type"], "the operator's own list was disturbed"

    # Case-insensitively already present, so nothing is appended a second time.
    reg, _ = _graph(capture_headers=["content-type"])
    apply_sync_reply_capture_implication(reg)
    assert reg.outbound["OB_PARTNER"].spec.settings["capture_response_headers"] == ["content-type"]


def test_the_implication_leaves_a_literal_mime_type_alone() -> None:
    # Only passthrough needs the partner's own content type; a pinned MIME type does not.
    reg, _ = _graph(reply_content_type="application/json")
    apply_sync_reply_capture_implication(reg)
    assert not reg.outbound["OB_PARTNER"].spec.settings["capture_response_headers"]


def test_an_effective_fifo_lane_is_refused_even_when_nothing_is_declared() -> None:
    # THE landmine. ordering is unset, so a literal `== FIFO` test passes — while the lane really
    # does resolve to FIFO and serialises every concurrent caller behind one partner round-trip.
    reg, ic = _graph(retry=RetryPolicy(max_attempts=3))  # ordering left unset
    assert reg.outbound["OB_PARTNER"].ordering is None, "the test lost its own premise"

    with pytest.raises(WiringError, match="EFFECTIVE ordering is FIFO"):
        check_http_sync_reply(ic, reg, delivery=DeliverySettings(retry_max_attempts=3))

    # An explicit FIFO is refused too, and the message distinguishes the two cases.
    reg, ic = _graph(ordering=OrderingMode.FIFO, retry=RetryPolicy(max_attempts=3))
    with pytest.raises(WiringError, match="declared: fifo"):
        check_http_sync_reply(ic, reg, delivery=SERVICEABLE)


def test_effective_retry_forever_is_refused_even_when_nothing_is_declared() -> None:
    # Same shape: no RetryPolicy object at all, so the declared value is None and the naive test
    # passes, while the lane really does resolve to whatever [delivery] says.
    # `retry_max_attempts=None` is EXPLICIT since #1051 — the shipped [delivery] default is the
    # finite 100, so `DeliverySettings()` no longer reaches this refusal. Leaving it implicit here
    # would have made the arm unreachable and this test green for the wrong reason.
    reg, ic = _graph(ordering=OrderingMode.UNORDERED)  # retry left unset
    assert reg.outbound["OB_PARTNER"].retry is None, "the test lost its own premise"

    with pytest.raises(WiringError, match="EFFECTIVE max_attempts"):
        check_http_sync_reply(
            ic,
            reg,
            delivery=DeliverySettings(ordering=OrderingMode.UNORDERED, retry_max_attempts=None),
        )

    # ... and inheriting a FINITE global default is fine.
    check_http_sync_reply(ic, reg, delivery=SERVICEABLE)


def test_the_effective_arm_is_skipped_rather_than_guessed_without_delivery() -> None:
    # A caller that could not resolve [delivery] must not have the refusal guessed for it — the
    # runner re-checks at start where the resolved values always exist.
    reg, ic = _graph()  # nothing declared: would be refused if delivery were known
    check_http_sync_reply(ic, reg, delivery=None)
