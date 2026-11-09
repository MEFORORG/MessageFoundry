# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3063 item 4: an operator start that a start gate refuses answers 409 and is audited.

An ``auto_start = false`` listener first meets the inbound exposure gates when an operator starts
it. The gate's ``WiringError`` escaped ``_dual_role_control`` as a 500 and wrote no
``connection_control`` row.

BACKLOG #3859: a refused start or restart records the listener failed, with one alert."""

from __future__ import annotations

import asyncio
import errno
import json
import logging
import threading
from collections.abc import AsyncIterator, Callable
from concurrent.futures.thread import BrokenThreadPool
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
            "refused": True,
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


# --- Lander hold 6730392844, item 3: a build the executor never began runs on the loop ----------


@pytest.mark.parametrize("fault", ["cancelled", "broken", "shut-down"])
@pytest.mark.parametrize("action", ["start", "restart"])
async def test_an_executor_fault_on_an_operator_start_builds_on_the_loop_and_starts(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    action: str,
    fault: str,
) -> None:
    """The executor cancels the inbound's build, fails it as a broken pool, or refuses it because
    it was shut down. The build never began, so it runs on the loop instead, as every build did
    before builds left the loop, and the start succeeds, with a WARNING naming the cause. Red
    (Lander hold 6730392844, item 3): the start raised an executor fault and answered 409, so an
    executor fault left the inbound down where main started it. Before that (Lander hold
    6703229134, item 2), a bare RuntimeError or BrokenThreadPool escaped as a 500."""
    engine = Engine(
        store,
        inbound_bind_host="127.0.0.1",
        hop_posture=HopPosture(enforcing=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    # Bound to loopback, so every start gate passes and the start reaches the connector build.
    engine.add_registry(_down_cleartext_listener())
    await engine.start()
    loop = asyncio.get_running_loop()
    real = loop.run_in_executor

    def faulty(executor: Any, fn: Any, *args: Any) -> asyncio.Future[Any]:
        if "_build_off_loop" not in getattr(fn, "__qualname__", ""):
            return real(executor, fn, *args)
        if fault == "shut-down":
            raise RuntimeError("Executor shutdown has been called")
        queued: asyncio.Future[Any] = loop.create_future()
        if fault == "cancelled":
            queued.cancel()
        else:
            queued.set_exception(BrokenThreadPool("a thread initializer failed"))
        return queued

    try:
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        monkeypatch.setattr(loop, "run_in_executor", faulty)
        with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                r = await client.post(f"/connections/IB_DOWN/{action}")
        monkeypatch.setattr(loop, "run_in_executor", real)
        assert r.status_code == 200, r.text
        cause = {
            "cancelled": "the executor cancelled the connector build",
            "broken": "a thread initializer failed",
            "shut-down": "Executor shutdown has been called",
        }[fault]
        assert any(
            "runs on the event loop" in rec.getMessage() and cause in rec.getMessage()
            for rec in caplog.records
            if rec.levelno == logging.WARNING
        ), [rec.getMessage() for rec in caplog.records]
        rows = await store.list_audit(action="connection_control", limit=10)
        assert len(rows) == 1
        assert json.loads(rows[0]["detail"] or "{}") == {
            "connection": "IB_DOWN",
            "action": action,
            "role": "source",
            "running": True,
        }
        rr = engine.registry_runner
        assert rr is not None and rr.inbound_running("IB_DOWN")
        assert rr.inbound_failed("IB_DOWN") is None
    finally:
        await engine.stop()


async def test_an_engine_restart_whose_build_submit_is_refused_leaves_the_inbound_running(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """An engine-driven restart, as an alert rule drives one, meets a pool that refuses a new
    thread at submit. The build never began, so it runs on the loop, and the inbound is running
    again after the restart, as on main, which built on the loop. Red (Lander hold 6730392844,
    item 3): the restart raised an executor fault and left the inbound down, recorded failed."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection("IB_UP", ConnectionSpec(ConnectorType.MLLP, {"port": 0}), router="r")
    )
    reg.add_router("r", lambda m: [])
    engine = Engine(
        store,
        inbound_bind_host="127.0.0.1",
        hop_posture=HopPosture(enforcing=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(reg)
    await engine.start()
    loop = asyncio.get_running_loop()
    real = loop.run_in_executor

    def refusing(executor: Any, fn: Any, *args: Any) -> asyncio.Future[Any]:
        if "_build_off_loop" in getattr(fn, "__qualname__", ""):
            raise RuntimeError("can't start new thread")
        return real(executor, fn, *args)

    try:
        rr = engine.registry_runner
        assert rr is not None and rr.inbound_running("IB_UP")
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(loop, "run_in_executor", refusing)
            with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
                await rr.restart_inbound("IB_UP")
        assert rr.inbound_running("IB_UP")
        assert rr.inbound_failed("IB_UP") is None
        assert any(
            "runs on the event loop" in rec.getMessage()
            and "can't start new thread" in rec.getMessage()
            for rec in caplog.records
        )
    finally:
        await engine.stop()


async def test_a_build_the_pool_queued_before_it_failed_to_start_a_thread_is_built_once() -> None:
    """A pool can queue the work item and then raise from its thread start. The build is made on
    the loop, so a later dequeue must build nothing, or the build would run twice and one
    connector would be built that no caller would close."""
    loop = asyncio.get_running_loop()
    runs: list[object] = []
    queued_items: list[Callable[[], object]] = []

    def build() -> object:
        built = object()
        runs.append(built)
        return built

    def queue_then_raise(_executor: Any, fn: Callable[[], object], *_args: Any) -> Any:
        queued_items.append(fn)
        raise RuntimeError("can't start new thread")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(loop, "run_in_executor", queue_then_raise)
        answer = await wiring_runner._build_off_loop(None, build)
    assert len(queued_items) == 1
    queued_items[0]()  # the late dequeue
    assert runs == [answer]


async def test_a_refusal_the_on_loop_build_raises_does_not_chain_the_executor_fault() -> None:
    """A build made on the loop after a refused submit raises its own refusal with no context, so
    its traceback never reads as if the executor caused the config refusal."""
    loop = asyncio.get_running_loop()

    def refuse_submit(_executor: Any, _fn: Callable[[], object], *_args: Any) -> Any:
        raise RuntimeError("can't start new thread")

    def build() -> object:
        raise WiringError("the build's own refusal")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(loop, "run_in_executor", refuse_submit)
        with pytest.raises(WiringError) as raised:
            await wiring_runner._build_off_loop(None, build)
    assert raised.value.__context__ is None


@pytest.mark.parametrize("outcome", ["built", "refused"])
async def test_a_build_a_worker_took_before_the_pool_failed_to_start_a_thread_is_its_own_answer(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, outcome: str
) -> None:
    """The other order: a busy worker takes the queued build before the pool's thread start
    raises. The build's own outcome is the answer: a good build is returned, and a refusal is
    raised as itself, not as an executor fault, and nothing goes to the abandoned-build close.
    Red (Lander hold 6704342060, item 2): an executor fault was raised either way."""
    loop = asyncio.get_running_loop()
    handed: list[object] = []

    def record(_loop: object, work: Any) -> None:
        handed.append(work)

    monkeypatch.setattr(wiring_runner, "_close_abandoned_build", record)

    def run_then_raise(_executor: Any, fn: Callable[[], object], *_args: Any) -> Any:
        worker = threading.Thread(target=fn)
        worker.start()
        worker.join()
        raise RuntimeError("can't start new thread")

    built = object()

    def build() -> object:
        if outcome == "refused":
            raise WiringError("the build's own refusal")
        return built

    monkeypatch.setattr(loop, "run_in_executor", run_then_raise)
    if outcome == "built":
        assert await wiring_runner._build_off_loop(None, build) is built
    else:
        with pytest.raises(WiringError) as raised:
            await wiring_runner._build_off_loop(None, build)
        assert type(raised.value) is WiringError
        assert str(raised.value) == "the build's own refusal"
    monkeypatch.undo()
    assert handed == []
    # The executor's own fault is not lost: it is logged.
    assert any("can't start new thread" in r.getMessage() for r in caplog.records)


# --- Lander hold 6733221092, item 1: a fault in the WARNING never strands the build -------------


class _RaisingFilter(logging.Filter):
    """A log filter that raises, so any record the runner's logger is handed raises from the
    logging call itself."""

    def filter(self, record: logging.LogRecord) -> bool:
        raise RuntimeError("a log filter failed")


@pytest.mark.parametrize("outcome", ["built", "refused"])
@pytest.mark.parametrize("fault", ["cancelled", "broken", "refused", "worker-took"])
async def test_a_raising_log_filter_never_strands_a_build_the_executor_never_began(
    fault: str, outcome: str
) -> None:
    """The executor cancels the queued build, fails it as a broken pool, refuses it at submit,
    or fails after a worker took it, and the WARNING that says so raises, from a log filter. The
    build still runs once and its caller gets it, or its own refusal with no context, and the
    filter's fault reaches the loop's exception handler, naming the executor's fault by type,
    rather than being swallowed. Red (Lander hold 6733221092, item 1): for a
    cancelled or broken item, settle() logged before run() with no finally, so the build was
    never made and the caller waited forever, holding the reload lock in a reload; for a refusal
    at submit, or a worker that took it, the filter's fault escaped in place of the build."""
    loop = asyncio.get_running_loop()
    runs: list[object] = []

    def build() -> object:
        built = object()
        runs.append(built)
        if outcome == "refused":
            raise WiringError("the build's own refusal")
        return built

    def faulty(_executor: Any, fn: Callable[[], None], *_args: Any) -> Any:
        if fault == "refused":
            raise RuntimeError("can't start new thread")
        if fault == "worker-took":
            worker = threading.Thread(target=fn)
            worker.start()
            worker.join()
            raise RuntimeError("can't start new thread")
        queued: asyncio.Future[None] = loop.create_future()
        if fault == "cancelled":
            queued.cancel()
        else:
            queued.set_exception(BrokenThreadPool("a thread initializer failed"))
        return queued

    handled: list[dict[str, Any]] = []
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: handled.append(context))
    raising = _RaisingFilter()
    wiring_runner.log.addFilter(raising)
    answer: object = None
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(loop, "run_in_executor", faulty)
            if outcome == "built":
                answer = await asyncio.wait_for(wiring_runner._build_off_loop(None, build), 5)
            else:
                with pytest.raises(WiringError) as raised:
                    await asyncio.wait_for(wiring_runner._build_off_loop(None, build), 5)
                assert raised.value.__context__ is None
        await asyncio.sleep(0)  # a done callback's fault reaches the handler on a later pass
    finally:
        wiring_runner.log.removeFilter(raising)
        loop.set_exception_handler(previous)
    assert len(runs) == 1
    if outcome == "built":
        assert runs == [answer]
    cause = {
        "cancelled": "a cancellation",
        "broken": "BrokenThreadPool",
        "refused": "RuntimeError",
        "worker-took": "RuntimeError",
    }[fault]
    assert any(
        isinstance(context.get("exception"), RuntimeError)
        and str(context["exception"]) == "a log filter failed"
        and context["message"].endswith(f"the executor's fault: {cause}")
        for context in handled
    ), handled


@pytest.mark.parametrize("fault", ["cancelled", "refused"])
async def test_a_raising_handler_filter_that_also_breaks_the_loop_handler_never_strands_a_build(
    fault: str,
) -> None:
    """A raising filter sits on a root handler, so the loop's default exception handler, which
    logs through the same handler, fails too when it is handed the WARNING's fault. The build
    still runs once and its caller gets it, and the loop keeps running. Red (Lander hold
    6733221092, item 1, round two of its repair): the handler's own fault escaped, raising in
    place of the build on a refused submit and killing the loop from a cancelled item's done
    callback."""
    loop = asyncio.get_running_loop()
    runs: list[object] = []

    def build() -> object:
        built = object()
        runs.append(built)
        return built

    def faulty(_executor: Any, _fn: Callable[[], None], *_args: Any) -> Any:
        if fault == "refused":
            raise RuntimeError("can't start new thread")
        queued: asyncio.Future[None] = loop.create_future()
        queued.cancel()
        return queued

    handler = logging.Handler()
    handler.addFilter(_RaisingFilter())
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(loop, "run_in_executor", faulty)
            answer = await asyncio.wait_for(wiring_runner._build_off_loop(None, build), 5)
        await asyncio.sleep(0)  # the loop is still running after the done callback's pass
    finally:
        root.removeHandler(handler)
    assert runs == [answer]
