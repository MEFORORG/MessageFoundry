# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""P2b — outbound lane connection_lost/restored edge-trigger + the connection_error alert lockstep (#46)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AlertRule
from messagefoundry.config.wiring import ConnectionSpec, OutboundConnection, Registry
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports import DeliveryError


class _RecordingSink:
    def __init__(self) -> None:
        self.errors: list[tuple[str, str, str | None]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None: ...
    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None: ...
    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None: ...
    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None: ...

    def connection_restored(self, name: str) -> None: ...

    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None:
        self.errors.append((name, kind, detail))


def _runner_with_outbound(
    store: MessageStore, sink: _RecordingSink, **kw: object
) -> RegistryRunner:
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "OB_PARTNER_ADT",
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 1}),
        )
    )
    return RegistryRunner(reg, store, alert_sink=sink, **kw)  # type: ignore[arg-type]


def _drain(runner: RegistryRunner) -> list[dict]:
    q = runner._conn_event_q
    assert q is not None
    out: list[dict] = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


async def test_outbound_edge_trigger_is_once_per_transition(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "ob.db")
    try:
        sink = _RecordingSink()
        runner = _runner_with_outbound(store, sink)
        runner._conn_event_q = asyncio.Queue(maxsize=100)  # normally created in start()

        runner._note_lane_unhealthy("OB_PARTNER_ADT", "m1", DeliveryError("connect refused"))
        runner._note_lane_unhealthy(
            "OB_PARTNER_ADT", "m2", DeliveryError("still down")
        )  # no re-emit
        runner._note_lane_healthy("OB_PARTNER_ADT")  # recovery
        runner._note_lane_healthy("OB_PARTNER_ADT")  # already healthy → no re-emit

        events = _drain(runner)
        assert [e["kind"] for e in events] == ["connection_lost", "connection_restored"]
        lost = events[0]
        assert lost["direction"] == "outbound" and lost["transport"] == "mllp"
        assert lost["message_id"] == "m1" and lost["peer_host"] is None
        assert events[1]["message_id"] is None  # restored carries no message id
        # the throttled operator alert fires on the DOWN edge only (recovery is store-row-only)
        assert [(n, k) for n, k, _ in sink.errors] == [("OB_PARTNER_ADT", "connection_lost")]
    finally:
        await store.close()


async def test_capture_off_emits_nothing(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "off.db")
    try:
        sink = _RecordingSink()
        runner = _runner_with_outbound(store, sink, connection_events=False)
        # No queue created (start() skips it when off); the helper must be a pure no-op.
        runner._note_lane_unhealthy("OB_PARTNER_ADT", "m1", DeliveryError("x"))
        runner._note_lane_healthy("OB_PARTNER_ADT")
        assert runner._conn_event_q is None
        assert sink.errors == []
        assert "OB_PARTNER_ADT" not in runner._lane_healthy  # lane state untouched when off
    finally:
        await store.close()


def test_connection_error_alert_rule_round_trips() -> None:
    rule = AlertRule(event_type="connection_error", connection="OB_*")
    assert rule.event_type == "connection_error"
    with pytest.raises(ValueError):
        AlertRule(event_type="not_a_real_event")
