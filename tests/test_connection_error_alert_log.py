# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3210: ``LoggingAlertSink.connection_error`` logs a stand-in, not the detail. The planted
token stands in for payload content that no redaction pattern matches.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, OutboundConnection, Registry
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.redaction import safe_exc, safe_text
from messagefoundry.store import MessageStore
from messagefoundry.transports.base import DeliveryError
from tests._refusal_log_capture import TOKEN, assert_no_token

OUT = "OB_PARTNER_ADT"
_TRANSPORT_TEXT = f"connection reset sending {TOKEN}"


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_the_sink_logs_the_class_and_not_the_detail(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    detail = safe_exc(DeliveryError(_TRANSPORT_TEXT))
    assert TOKEN in detail  # the premise: safe_exc keeps this text, so the sink must drop it
    LoggingAlertSink().connection_error(OUT, kind="connection_lost", detail=detail)
    (line,) = _warnings(caplog)
    assert line.getMessage() == (
        f"ALERT connection_error: outbound {OUT!r} connection_lost (DeliveryError); "
        "the reason is not logged"
    )
    assert_no_token(caplog.records)


@pytest.mark.parametrize(
    ("detail", "stand_in"),
    [
        (f"{TOKEN} refused", "unnamed error"),
        (f"not a class: {TOKEN}", "unnamed error"),
        (f"Ünïcode{TOKEN}: x", "unnamed error"),
        ("", "unnamed error"),
        (None, "unnamed error"),
        ("DeliveryError", "DeliveryError"),
        ("SYN900002", "SYN900002"),
    ],
    ids=["spaced", "spaced-head", "non-ascii-head", "empty", "none", "bare-class", "bare-token"],
)
def test_the_stand_in_for_each_detail_shape(
    caplog: pytest.LogCaptureFixture, detail: str | None, stand_in: str
) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    LoggingAlertSink().connection_error(OUT, kind="connection_lost", detail=detail)
    (line,) = _warnings(caplog)
    assert f"({stand_in})" in line.getMessage()
    assert_no_token(caplog.records)


@pytest.mark.parametrize(
    ("transport_text", "stored_whole"),
    [(_TRANSPORT_TEXT, True), (f"{_TRANSPORT_TEXT}{' x' * 200}", False)],
    ids=["short", "long"],
)
async def test_the_stored_event_reason_is_the_detail_bounded_again_and_no_log_has_it(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, transport_text: str, stored_whole: bool
) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    store = await MessageStore.open(tmp_path / "engine.db")
    try:
        reg = Registry()
        reg.add_outbound(
            OutboundConnection(
                OUT, ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 1})
            )
        )
        runner = RegistryRunner(
            reg,
            store,
            alert_sink=LoggingAlertSink(),
            egress=EgressSettings(deny_by_default=False),
        )
        runner._conn_event_q = asyncio.Queue(maxsize=10)  # normally created in start()
        exc = DeliveryError(transport_text)
        runner._note_lane_unhealthy(OUT, "m1", exc)
        await store.record_connection_events([runner._conn_event_q.get_nowait()])
        (event,) = await store.list_connection_events(connection=OUT, allowed_channels=None)
    finally:
        await store.close()
    detail = safe_exc(exc)
    assert event.kind == "connection_lost" and event.reason == safe_text(detail, limit=200)
    assert TOKEN in event.reason
    assert (event.reason == detail) is stored_whole
    (line,) = [r for r in _warnings(caplog) if "ALERT connection_error" in r.getMessage()]
    assert "(DeliveryError)" in line.getMessage()
    assert_no_token(caplog.records)
