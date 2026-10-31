# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3210: the default alert sink's ``connection_error`` line names the connection and the
exception class, never the transport's error text.

Why the detail is withheld is stated once, in ``LoggingAlertSink.connection_error``. The stored
``connection_lost`` reason keeps the full text, which the runner test pins. The planted token stands
in for payload content that no redaction pattern matches.
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
from messagefoundry.redaction import safe_exc
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
    "detail",
    [f"{TOKEN} refused", f"not a class: {TOKEN}", f"Ünïcode{TOKEN}: x", "", None],
    ids=["no-colon", "spaced-head", "non-ascii-head", "empty", "none"],
)
def test_a_head_that_is_no_class_name_is_not_logged(
    caplog: pytest.LogCaptureFixture, detail: str | None
) -> None:
    caplog.set_level(logging.DEBUG, logger="messagefoundry")
    LoggingAlertSink().connection_error(OUT, kind="connection_lost", detail=detail)
    (line,) = _warnings(caplog)
    assert "(unnamed error)" in line.getMessage()
    assert_no_token(caplog.records)


async def test_the_runner_keeps_the_stored_reason_and_logs_none_of_it(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The real emit site with the real default sink. Engine loggers at DEBUG, so every record they
    # write is scanned, with no message skipped.
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
        exc = DeliveryError(_TRANSPORT_TEXT)
        runner._note_lane_unhealthy(OUT, "m1", exc)
        event = runner._conn_event_q.get_nowait()
    finally:
        await store.close()
    # The stored reason is unchanged: the full safe_exc text, masked later by the read routes.
    assert event["kind"] == "connection_lost" and event["reason"] == safe_exc(exc)
    (line,) = [r for r in _warnings(caplog) if "ALERT connection_error" in r.getMessage()]
    assert "(DeliveryError)" in line.getMessage()
    assert_no_token(caplog.records)
