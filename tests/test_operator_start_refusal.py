# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3063 item 4: an operator start that a start gate refuses answers 409 and is audited.

An ``auto_start = false`` listener first meets the inbound exposure gates when an operator starts
it. The gate's ``WiringError`` escaped ``_dual_role_control`` as a 500 and wrote no
``connection_control`` row.

BACKLOG #3859: a refused start or restart records the listener failed, with one alert."""

from __future__ import annotations

import errno
import json
import logging
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, time
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.models import ActiveWindow, ConnectorType, Schedule
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, InsecureHopRefused
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    PortConflictError,
    Registry,
    WiringError,
)
from messagefoundry.pipeline import Engine, wiring_runner
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import NotDeployedError, RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports.base import SourceStartupError


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


def _down_cleartext_listener() -> Registry:
    """One MLLP listener, left down at start, that the exposure gate refuses when it binds."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_DOWN",
            ConnectionSpec(ConnectorType.MLLP, {"port": 0}),
            router="r",
            auto_start=False,
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


def _down_ftps_poll() -> Registry:
    """One FTPS poll, left down at start, whose revocation-hop guard refuses it when it is built:
    off-box, with no CRL and no attestation (BACKLOG #2193). The guard raises
    ``InsecureHopRefused``, a ``ValueError`` and not a ``WiringError``."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_DOWN",
            ConnectionSpec(
                ConnectorType.REMOTEFILE,
                {"host": "10.0.0.5", "remote_dir": "/in", "protocol": "ftps"},
            ),
            router="r",
            auto_start=False,
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


#: Each down inbound, with a phrase only its refusal's own text carries.
_REFUSED = [
    pytest.param(_down_cleartext_listener, "without TLS", id="exposure-gate"),
    pytest.param(_down_ftps_poll, "revocation", id="ftps-poll-revocation"),
]


@pytest.mark.parametrize(("build", "gate_text"), _REFUSED)
@pytest.mark.parametrize("action", ["start", "restart"])
async def test_a_gate_refused_operator_start_answers_409_and_is_audited(
    store: MessageStore,
    caplog: pytest.LogCaptureFixture,
    action: str,
    build: Callable[[], Registry],
    gate_text: str,
) -> None:
    engine = Engine(
        store,
        inbound_bind_host="0.0.0.0",
        hop_posture=HopPosture(enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(build())
    await engine.start()
    try:
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                r = await client.post(f"/connections/IB_DOWN/{action}")
        assert r.status_code == 409, r.text
        detail = r.json()["detail"]
        assert "IB_DOWN" in detail and "see the server log" in detail
        # The answer names only the listener; the gate's own text goes to the operator log.
        assert gate_text not in detail
        assert any(
            rec.name == "messagefoundry.api.app" and gate_text in rec.getMessage()
            for rec in caplog.records
        )
        rows = await store.list_audit(action="connection_control", limit=10)
        assert len(rows) == 1
        assert json.loads(rows[0]["detail"] or "{}") == {
            "connection": "IB_DOWN",
            "action": action,
            "role": "source",
            "running": False,
        }
        rr = engine.registry_runner
        assert rr is not None and not rr.inbound_running("IB_DOWN")
        # BACKLOG #3859: a refused plain start is recorded failed too, as boot start() records one.
        assert rr.inbound_failed("IB_DOWN") is not None
    finally:
        await engine.stop()


# --- BACKLOG #3859: a refused restart of a RUNNING listener --------------------------------------


class _RecordingSink(LoggingAlertSink):
    """Records each ``connection_stopped`` alert; every other alert only logs."""

    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))


#: The refusal the stand-in gate raises, worded as the real exposure gate words its own.
_TLS_REFUSAL = "inbound connection 'IB_LIVE': refused without TLS"


def _live_listener(schedule: Schedule | None = None) -> Registry:
    """One loopback MLLP listener that binds at start."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_LIVE",
            ConnectionSpec(ConnectorType.MLLP, {"port": 0}),
            router="r",
            schedule=schedule,
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


class _Gate:
    """Stands in for the inbound exposure gate: passes until ``refusal`` is set, then raises it.

    A running loopback listener passes the real gate, so the test arms a refusal only after it is
    up, the way a restart meets a gate the first start did not. Every refusal the start path can
    raise reaches the record through the same ``except``, so one seam covers each type."""

    def __init__(self) -> None:
        self.refusal: Exception | None = None

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        if self.refusal is not None:
            raise self.refusal


@pytest.fixture
def gate(monkeypatch: pytest.MonkeyPatch) -> _Gate:
    g = _Gate()
    monkeypatch.setattr(wiring_runner, "check_inbound_tls_exposure", g)
    return g


def _runner(reg: Registry, store: MessageStore, **kw: Any) -> tuple[RegistryRunner, _RecordingSink]:
    """A runner over ``reg`` whose alerts land on a fresh recording sink."""
    sink = _RecordingSink()
    runner = RegistryRunner(
        reg, store, egress=EgressSettings(deny_by_default=False), alert_sink=sink, **kw
    )
    return runner, sink


def _source_status(rows: list[dict[str, Any]], name: str) -> str:
    """The dashboard status of ``name``'s inbound row."""
    (row,) = [r for r in rows if r["role"] == "source" and r["channel_id"] == name]
    return str(row["status"])


async def test_a_gate_refused_restart_of_a_running_listener_reads_failed_and_alerts_once(
    store: MessageStore, gate: _Gate
) -> None:
    """The restart unbinds the listener, then the gate refuses its start. Before the fix the
    listener sat down reading ``stopped``, with no failed record and no alert. It reads ``failed``
    now, with one ``connection_stopped``. A second refused restart pages no more: an alert rule
    whose control action restarts the inbound would otherwise loop, one page per restart. A
    restart that binds clears the record, so the next refusal pages afresh."""
    sink = _RecordingSink()
    engine = Engine(store, egress_settings=EgressSettings(deny_by_default=False), alert_sink=sink)
    engine.add_registry(_live_listener())
    await engine.start()
    try:
        rr = engine.registry_runner
        assert rr is not None and rr.inbound_running("IB_LIVE")
        assert sink.stopped == []
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            gate.refusal = WiringError(_TLS_REFUSAL)
            r = await client.post("/connections/IB_LIVE/restart")
            assert r.status_code == 409, r.text
            assert not rr.inbound_running("IB_LIVE")
            failed = rr.inbound_failed("IB_LIVE")
            assert failed is not None and "without TLS" in failed
            rows = (await client.get("/connections")).json()
            assert _source_status(rows, "IB_LIVE") == "failed"
            assert [name for name, _ in sink.stopped] == ["IB_LIVE"]
            assert "without TLS" in sink.stopped[0][1]

            r = await client.post("/connections/IB_LIVE/restart")
            assert r.status_code == 409, r.text
            assert len(sink.stopped) == 1, sink.stopped
            assert rr.inbound_failed("IB_LIVE") is not None

            gate.refusal = None
            r = await client.post("/connections/IB_LIVE/restart")
            assert r.status_code == 200, r.text
            assert rr.inbound_running("IB_LIVE") and rr.inbound_failed("IB_LIVE") is None
            assert _source_status((await client.get("/connections")).json(), "IB_LIVE") == (
                "running"
            )

            gate.refusal = WiringError(_TLS_REFUSAL)
            r = await client.post("/connections/IB_LIVE/restart")
            assert r.status_code == 409, r.text
            assert len(sink.stopped) == 2, sink.stopped
    finally:
        await engine.stop()


@pytest.mark.parametrize(
    "refusal",
    [
        pytest.param(PortConflictError("cannot bind 127.0.0.1:2575"), id="bind-race"),
        pytest.param(InsecureHopRefused("revocation hop refused"), id="hop-guard"),
        pytest.param(SourceStartupError("directory missing"), id="startup-validation"),
        pytest.param(OSError(errno.ENETDOWN, "network is down"), id="os-error"),
        # A constructor's own refusal, such as a CRL past nextUpdate or a key-wrap check, is a
        # ValueError, and none of the named types above. A narrower catch left it unrecorded.
        pytest.param(ValueError("CRL is past its nextUpdate"), id="constructor-value-error"),
        pytest.param(RuntimeError("connector failed to start"), id="runtime-error"),
    ],
)
async def test_each_refused_restart_type_records_the_listener_failed_once(
    store: MessageStore, gate: _Gate, refusal: Exception
) -> None:
    """Each other type a failed start raises records the restarted listener failed with one
    alert, and a second refused restart adds none."""
    runner, sink = _runner(_live_listener(), store)
    await runner.start()
    try:
        assert runner.inbound_running("IB_LIVE")
        gate.refusal = refusal
        for _ in range(2):
            with pytest.raises(type(refusal)):
                await runner.restart_inbound("IB_LIVE", operator=True)
        assert not runner.inbound_running("IB_LIVE")
        assert runner.inbound_failed("IB_LIVE") is not None
        assert [name for name, _ in sink.stopped] == ["IB_LIVE"], sink.stopped
    finally:
        await runner.stop()


async def test_a_raise_after_the_bind_leaves_a_serving_listener_unrecorded(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A restart that binds and then raises, here from ``_ensure_inbound_workers``, leaves the
    listener serving. Recording it failed would page for a feed that is up, and a later start
    returns early on the bound source, so the false record would stick. It records nothing, as
    before #3859, and the raise still reaches the caller."""
    runner, sink = _runner(_live_listener(), store)
    await runner.start()
    try:
        assert runner.inbound_running("IB_LIVE")

        def boom(name: str) -> None:
            raise RuntimeError("worker spawn failed")

        monkeypatch.setattr(runner, "_ensure_inbound_workers", boom)
        with pytest.raises(RuntimeError, match="worker spawn failed"):
            await runner.restart_inbound("IB_LIVE", operator=True)
        assert runner.inbound_running("IB_LIVE")
        assert runner.inbound_failed("IB_LIVE") is None
        assert sink.stopped == []
    finally:
        monkeypatch.undo()
        await runner.stop()


async def test_a_not_deployed_or_unknown_start_is_not_recorded_failed(store: MessageStore) -> None:
    """NotDeployedError is a refused request, not a failed start: the inbound stays not_deployed,
    with no failed record and no alert. A name the graph does not declare is the caller's
    KeyError, and it records nothing either."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_OFF", ConnectionSpec(ConnectorType.MLLP, {"port": 0}), router="r", deployed=False
        )
    )
    reg.add_router("r", lambda m: [])
    runner, sink = _runner(reg, store)
    await runner.start()
    try:
        with pytest.raises(NotDeployedError):
            await runner.start_inbound("IB_OFF", operator=True)
        assert runner.inbound_failed("IB_OFF") is None
        with pytest.raises(KeyError):
            await runner.restart_inbound("IB_NOPE", operator=True)
        assert runner.inbound_failed("IB_NOPE") is None
        assert sink.stopped == []
    finally:
        await runner.stop()


async def test_a_gate_refused_window_open_alerts_once_over_three_ticks(
    store: MessageStore, gate: _Gate
) -> None:
    """A regression guard, green before the fix too: the scheduler path already recorded a
    refused window open once, through ``_record_window_open_failure``. With the start path now
    recording first, the two must not page twice: three in-window ticks give one
    ``connection_stopped``."""
    schedule = Schedule(
        windows=[
            ActiveWindow(
                days=frozenset(range(7)), start=time(8, 0), end=time(17, 0), timezone="UTC"
            )
        ]
    )
    clock = {"now": datetime(2026, 7, 13, 20, tzinfo=UTC)}  # outside the window
    runner, sink = _runner(_live_listener(schedule), store, schedule_clock=lambda: clock["now"])
    await runner.start()
    try:
        await runner._reconcile_schedule("IB_LIVE", "inbound", schedule)  # parks it
        assert not runner.inbound_running("IB_LIVE")
        gate.refusal = WiringError(_TLS_REFUSAL)
        clock["now"] = datetime(2026, 7, 13, 12, tzinfo=UTC)  # inside the window
        for _ in range(3):
            await runner._reconcile_schedule("IB_LIVE", "inbound", schedule)
        assert runner.inbound_failed("IB_LIVE") is not None
        assert [name for name, _ in sink.stopped] == ["IB_LIVE"], sink.stopped
    finally:
        await runner.stop()
