# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Passive DR standby follow-ups (vault BACKLOG #3263; ADR 0048, the #3263 amendment).

Each test names the reading it gave before the repair. They cover four things: what a passive
box learns about its activation set at start; what an activation does with a lane it builds for
the first time; a release or an activation that is cut short; and an activation under a log halt.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.auth.trust_anchors as ta
from messagefoundry.config.models import ConnectorType, Priority
from messagefoundry.config.settings import DrSettings, EgressSettings, StoreSettings
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    Rest,
    Send,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
    env,
)
from messagefoundry.logging_guard import LogSinkEvent
from messagefoundry.pipeline import Engine, wiring_runner
from messagefoundry.pipeline.wiring_runner import DrParkedError, RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports.file import FileDestination
from tests.test_connection_scheduler import _DeadLogGuard, _LogPageSink, _wait_until
from tests.test_dr_running_config_dir import _free_ports
from tests.test_outbound_ca_anchors import _ca, _CountingSink, _ftps_poller_registry, _sha
from tests.test_trust_anchors import _block, _path_ok

_IB = "IB_CRIT"
_OB_CA = "OB_CA"
_OB_FILE = "OB_FILE"
_PASSIVE_REFUSED = "its tls_ca_file was refused on this passive DR standby"
_PASSIVE_UNCHECKED = "its tls_ca_file could not be checked on this passive DR standby"

_ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|PF1|P|2.5.1\rEVN|A01|20260604\rPID|1||100^^^H^MR||DOE^JANE\r"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "followups.db")
    yield s
    await s.close()


@pytest.fixture
def judged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ACL and path read as owner-only, so a test varies only the pin."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)


def _graph(tmp_path: Path, ca: Path, pin: str, **file_settings: object) -> Registry:
    """A critical MLLP inbound, a Rest outbound with a pinned CA and a File outbound."""
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            _IB, MLLP(port=_free_ports(1)[0]), router="r", priority=Priority.CRITICAL
        )
    )
    rest = Rest(url="https://partner.example.org/api", tls_ca_file=str(ca), tls_ca_pin=pin)
    reg.add_outbound(build_outbound_connection(_OB_CA, rest, priority=Priority.CRITICAL))
    out = tmp_path / _OB_FILE
    if "directory" not in file_settings:
        out.mkdir(exist_ok=True)
    spec = ConnectionSpec(ConnectorType.FILE, {"directory": str(out), **file_settings})
    reg.add_outbound(build_outbound_connection(_OB_FILE, spec, priority=Priority.CRITICAL))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send(_OB_FILE, m))
    return reg


def _runner(store: MessageStore, reg: Registry, **kw: Any) -> RegistryRunner:
    return RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
        lane_anchor_check=ta.make_lane_anchor_check(store, enforcing=True),
        **kw,
    )


def _swapped_ca(tmp_path: Path) -> tuple[Path, str]:
    """A CA whose bytes no longer match the pin its connection carries."""
    ca = _ca(tmp_path)
    pin = _sha(ca)
    ca.write_bytes(_block(b"substitute"))
    return ca, pin


# --- what a passive box learns at start ---------------------------------------------------


async def test_a_passive_start_shows_an_activation_set_outbound_whose_ca_is_refused(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Before: the lane read ``filtered`` only, and the bad CA first showed at the activation.
    No connector is built to find it, and the lane stays parked."""
    ca, pin = _swapped_ca(tmp_path)
    sink = _CountingSink()
    runner = _runner(
        store, _graph(tmp_path, ca, pin), dr_standby=Priority.CRITICAL, alert_sink=sink
    )
    await runner.start()
    try:
        assert _PASSIVE_REFUSED in (runner.outbound_failed(_OB_CA) or "")
        assert runner.outbound_failed(_OB_FILE) is None  # the control: a good lane is not failed
        assert sink.stopped == [_OB_CA]
        assert runner._destinations == {}  # nothing was built to find it
        assert set(runner.filtered_outbound()) == {_OB_CA, _OB_FILE}
        with pytest.raises(DrParkedError):
            await runner.start_outbound(_OB_CA)

        # A reload while passive reads the same CA. Once the file is right it clears the record.
        with pytest.raises(WiringError):
            await runner.reload()
        assert _PASSIVE_REFUSED in (runner.outbound_failed(_OB_CA) or "")
        ca.write_bytes(_block(b"partner-ca"))
        await runner.reload()
        assert runner.outbound_failed(_OB_CA) is None
    finally:
        await runner.stop()


async def test_a_passive_start_shows_an_ftps_poller_whose_ca_is_refused(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The inbound that dials out is read too. Before: ``filtered`` only."""
    reg = _ftps_poller_registry(_ca(tmp_path), pin="00" * 32)
    runner = _runner(store, reg, dr_standby=Priority.NORMAL)
    await runner.start()
    try:
        assert _PASSIVE_REFUSED in (runner.inbound_failed("IB_FTPS") or "")
        assert not runner.inbound_running("IB_FTPS")
    finally:
        await runner.stop()


async def test_the_passive_preflight_leaves_a_lane_another_engine_shard_owns(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the owning engine shard reports a lane (ADR 0073). The first test is the control."""
    ca, pin = _swapped_ca(tmp_path)
    runner = _runner(store, _graph(tmp_path, ca, pin), dr_standby=Priority.CRITICAL)
    monkeypatch.setattr(runner, "_owns_destination", lambda name: name != _OB_CA)
    await runner.start()
    try:
        assert runner.outbound_failed(_OB_CA) is None
    finally:
        await runner.stop()


async def test_a_passive_start_is_not_stopped_by_a_check_that_cannot_run(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The check reports and never refuses the start. One that raises something other than a
    refusal, such as a store error on its audit row, fails that lane and the start goes on."""
    ca = _ca(tmp_path)

    async def broken(direction: str, name: str, settings: object) -> None:
        raise RuntimeError("the audit row could not be written")

    runner = RegistryRunner(
        _graph(tmp_path, ca, _sha(ca)),
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
        lane_anchor_check=broken,
        dr_standby=Priority.CRITICAL,
    )
    await runner.start()
    try:
        assert _PASSIVE_UNCHECKED in (runner.outbound_failed(_OB_CA) or "")
        assert set(runner.filtered_outbound()) == {_OB_CA, _OB_FILE}
    finally:
        await runner.stop()


async def test_a_passive_start_runs_no_outbound_startup_check(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``validate_startup`` writes a probe file into a File outbound's directory and lists a
    remote one over a session to the partner, so a passive box does not run it. The activation
    does: before, its reconcile built the connector without it, and the lane read as healthy
    over a directory that is not there."""
    calls: list[str] = []
    real = FileDestination.validate_startup

    async def counting(self: FileDestination) -> None:
        calls.append(self.directory.name)
        await real(self)

    monkeypatch.setattr(FileDestination, "validate_startup", counting)
    ca = _ca(tmp_path)
    reg = _graph(
        tmp_path, ca, _sha(ca), directory=str(tmp_path / "not-there"), validate_directory=True
    )
    runner = _runner(store, reg, dr_standby=Priority.CRITICAL)
    await runner.start()
    try:
        assert calls == []
        assert runner.outbound_failed(_OB_FILE) is None

        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()
        assert calls == ["not-there"]
        assert "failed startup validation" in (runner.outbound_failed(_OB_FILE) or "")
        assert _OB_FILE not in runner._destinations
        assert _OB_CA in runner._destinations  # the other lane came up
    finally:
        await runner.stop()


# --- what an activation does with a lane it builds for the first time ---------------------


async def test_an_activation_fails_one_lane_on_a_refused_ca_and_starts_the_rest(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Before: the activation's reload read the CA in its pre-check and refused the whole
    activation, so no listener bound and no lane delivered."""
    ca, pin = _swapped_ca(tmp_path)
    reg = _graph(tmp_path, ca, pin)
    runner = _runner(store, reg, dr_standby=Priority.CRITICAL)
    await runner.start()
    try:
        await store.enqueue_message(channel_id=_IB, raw=_ADT, deliveries=[(_OB_FILE, _ADT)])
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()

        assert runner.inbound_running(_IB)
        assert "its tls_ca_file was refused" in (runner.outbound_failed(_OB_CA) or "")
        assert _OB_CA not in runner._destinations
        assert runner.outbound_failed(_OB_FILE) is None and _OB_FILE in runner._destinations
        await _wait_until(lambda: any((tmp_path / _OB_FILE).iterdir()))  # the good lane delivers
        assert set(runner.filtered_outbound()) == set()

        # Released with the CA still refused: a reload on the passive box reads it again. Red
        # when the lane's kept failure left it out and the park then cleared its record.
        runner.set_dr_threshold(None, standby=Priority.CRITICAL)
        with pytest.raises(WiringError):
            await runner.reload()
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # and activated again
        await runner.reload()
        assert "its tls_ca_file was refused" in (runner.outbound_failed(_OB_CA) or "")

        # Recovery is the ordinary one for a lane its CA failed: fix the file, start the lane.
        ca.write_bytes(_block(b"partner-ca"))
        await runner.start_outbound(_OB_CA)
        assert _OB_CA in runner._destinations and runner.outbound_failed(_OB_CA) is None
        assert runner.outbound_running(_OB_CA)
    finally:
        await runner.stop()


async def test_a_lane_that_fails_at_an_activation_keeps_its_rows_held(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The failed lane stays parked. Red when it was unparked anyway: the row was claimed with
    no connector and charged an attempt, and a finite ``max_attempts`` dead-lettered it."""
    ca, pin = _swapped_ca(tmp_path)
    runner = _runner(store, _graph(tmp_path, ca, pin), dr_standby=Priority.CRITICAL)
    await runner.start()
    try:
        row_id = await store.enqueue_message(
            channel_id=_IB, raw=_ADT, deliveries=[(_OB_CA, _ADT), (_OB_FILE, _ADT)]
        )
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()
        await _wait_until(lambda: any((tmp_path / _OB_FILE).iterdir()))  # the control lane sent
        await asyncio.sleep(0.3)
        held = [r for r in await store.outbox_for(row_id) if r["destination_name"] == _OB_CA]
        assert [(r["status"], r["attempts"]) for r in held] == [("pending", 0)]
        assert not runner.outbound_running(_OB_CA)
    finally:
        await runner.stop()


async def test_an_activation_charges_no_attempt_to_a_row_held_on_a_lane_it_is_building(
    store: MessageStore, tmp_path: Path
) -> None:
    """The first build awaits its CA check. The lane is unparked only after it, so the held row
    is not claimed while there is no connector. Red when the unpark came first: the row was
    charged a failed attempt with ``last_error`` ``outbound reloading``."""
    ca = _ca(tmp_path)

    async def slow(direction: str, name: str, settings: object) -> None:
        await asyncio.sleep(0.3)

    runner = RegistryRunner(
        _graph(tmp_path, ca, _sha(ca)),
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
        lane_anchor_check=slow,
        dr_standby=Priority.CRITICAL,
    )
    await runner.start()
    try:
        row_id = await store.enqueue_message(
            channel_id=_IB, raw=_ADT, deliveries=[(_OB_FILE, _ADT)]
        )
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()
        await _wait_until(lambda: any((tmp_path / _OB_FILE).iterdir()))
        (row,) = await store.outbox_for(row_id)
        # One attempt, the delivery itself. The control is the unpark-first order, which gave 2.
        assert (row["status"], row["attempts"], row["last_error"]) == ("done", 1, None)
    finally:
        await runner.stop()


async def test_a_passive_start_reads_the_other_lanes_when_one_does_not_resolve(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """One lane's settings name an ``env()`` value this instance lacks. That lane is recorded
    failed, and the lane with the refused CA is still read. Red when one fault skipped them all."""
    ca, pin = _swapped_ca(tmp_path)
    reg = _graph(tmp_path, ca, pin, directory=env("not_defined_here"))
    runner = _runner(store, reg, dr_standby=Priority.CRITICAL)
    await runner.start()
    try:
        assert _PASSIVE_REFUSED in (runner.outbound_failed(_OB_CA) or "")
        assert runner.outbound_failed(_OB_FILE) is not None
    finally:
        await runner.stop()


# --- an activation under a log halt -------------------------------------------------------


async def test_an_activation_under_a_log_halt_drops_the_passive_marker(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: the halt's refusal skipped the lane before its DR marker was judged again, so on
    an active box the documented recovery, starting the connection, answered "activate DR
    first"."""
    ca = _ca(tmp_path)
    guard = _DeadLogGuard()
    runner = _runner(
        store,
        _graph(tmp_path, ca, _sha(ca)),
        dr_standby=Priority.CRITICAL,
        alert_sink=_LogPageSink(),
    )
    await runner.start()
    try:
        await store.enqueue_message(channel_id=_IB, raw=_ADT, deliveries=[(_OB_FILE, _ADT)])
        monkeypatch.setattr(wiring_runner, "active_log_guard", lambda: guard)
        await runner._respond_to_log_sink_event(
            LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=True)
        )
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()

        assert runner.outbound_filtered(_OB_FILE) is None
        assert not runner.outbound_running(_OB_FILE)  # the halt still holds it
        assert not any((tmp_path / _OB_FILE).iterdir())

        guard.writable = True  # the disk is repaired
        await runner.start_outbound(_OB_FILE)  # raised DrParkedError before
        await _wait_until(lambda: any((tmp_path / _OB_FILE).iterdir()))
    finally:
        await runner.stop()


# --- a release or an activation that is cut short -----------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    db = tmp_path / "engine.db"
    eng = Engine(
        await MessageStore.open(db),
        poll_interval=0.02,
        config_dir=None,
        store_settings=StoreSettings(path=str(db)),
        dr_settings=DrSettings(enabled=True, activate=False),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


def _engine_graph(tmp_path: Path) -> Registry:
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            _IB, MLLP(port=_free_ports(1)[0]), router="r", priority=Priority.CRITICAL
        )
    )
    out = tmp_path / _OB_FILE
    out.mkdir(exist_ok=True)
    spec = ConnectionSpec(ConnectorType.FILE, {"directory": str(out)})
    reg.add_outbound(build_outbound_connection(_OB_FILE, spec, priority=Priority.CRITICAL))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send(_OB_FILE, m))
    return reg


async def _started(engine: Engine, tmp_path: Path) -> RegistryRunner:
    engine.add_registry(_engine_graph(tmp_path))
    await engine.start()
    rr = engine.registry_runner
    assert rr is not None
    return rr


async def _audit_actions(engine: Engine) -> list[str]:
    rows = await engine.store.list_audit(limit=50)
    return [str(row["action"]) for row in rows]


async def test_a_release_cancelled_while_it_closes_connectors_has_still_handed_back(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: the engine was passive by then, and the coordinator recorded a failed release
    and stayed active. The two now agree, and the ``dr.release`` row is written."""
    rr = await _started(engine, tmp_path)
    coordinator = engine.dr_coordinator
    assert coordinator is not None
    await engine._dr_activate_profile()
    coordinator._active = True  # as POST /dr/activate leaves it once its seed gates pass
    closing = asyncio.Event()

    async def hang() -> None:
        closing.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(rr, "close_passive_connectors", hang)
    release = asyncio.create_task(coordinator.release(actor="operator"))
    await asyncio.wait_for(closing.wait(), timeout=10)
    release.cancel()
    with pytest.raises(asyncio.CancelledError):
        await release

    assert engine.dr_active is False
    assert coordinator.active is False
    actions = await _audit_actions(engine)
    assert "dr.release" in actions and "dr_release_failed" not in actions
    assert not rr.inbound_running(_IB) and set(rr.filtered_outbound()) == {_OB_FILE}

    # The cut-short cleanup is owed. A retried release runs it and writes no second row.
    closed: list[bool] = []

    async def close() -> None:
        closed.append(True)

    monkeypatch.setattr(rr, "close_passive_connectors", close)
    again = await coordinator.release(actor="operator")
    assert again.active is False and closed == [True]
    assert (await _audit_actions(engine)).count("dr.release") == 1


async def test_a_release_that_cannot_close_a_connector_has_still_handed_back(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same split by an error: before, a raise from the close read as a failed drain."""
    rr = await _started(engine, tmp_path)
    coordinator = engine.dr_coordinator
    assert coordinator is not None
    await engine._dr_activate_profile()
    coordinator._active = True

    async def refuse() -> None:
        raise OSError("the session would not close")

    monkeypatch.setattr(rr, "close_passive_connectors", refuse)
    result = await coordinator.release(actor="operator")

    assert result.active is False and engine.dr_active is False and coordinator.active is False
    assert "dr_release_failed" not in await _audit_actions(engine)


async def test_an_activation_cancelled_after_its_reload_commits_leaves_no_listener_bound(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: the reload had bound the critical listener, the cancellation put the latch back,
    and the box read passive while it answered on the port."""
    rr = await _started(engine, tmp_path)

    async def cancelled() -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(rr, "_reconcile_schedulers", cancelled)  # the first await past the commit
    with pytest.raises(asyncio.CancelledError):
        await engine._dr_activate_profile()

    assert engine.dr_active is False
    assert not rr.inbound_running(_IB)
    assert set(rr.filtered_inbound()) == {_IB} and set(rr.filtered_outbound()) == {_OB_FILE}
    assert rr._destinations == {}  # and the session the attempt opened is closed


async def test_a_refused_activation_unbinds_what_a_concurrent_reload_bound_under_it(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operator reload is partway through when the activation flips the threshold, so that
    reload binds the critical listener. The activation's own reload is then refused. Before: the
    latch went back and the listener stayed bound."""
    rr = await _started(engine, tmp_path)
    in_reload, go = asyncio.Event(), asyncio.Event()
    real_close = rr._close_sandbox_sessions

    async def held_close() -> None:
        in_reload.set()
        await go.wait()
        await real_close()

    checks = 0
    real_check = rr._check_reload_lane_anchors

    async def second_refuses(*args: Any) -> list[tuple[Any, str]]:
        nonlocal checks
        checks += 1
        if checks == 2:
            raise WiringError("a trust anchor this graph names is not readable")
        return await real_check(*args)

    monkeypatch.setattr(rr, "_close_sandbox_sessions", held_close)
    monkeypatch.setattr(rr, "_check_reload_lane_anchors", second_refuses)
    operator_reload = asyncio.create_task(rr.reload())
    await asyncio.wait_for(in_reload.wait(), timeout=10)
    activation = asyncio.create_task(engine._dr_activate_profile())
    await _wait_until(lambda: rr.dr_threshold is Priority.CRITICAL)
    go.set()
    await operator_reload
    with pytest.raises(WiringError):
        await activation

    assert engine.dr_active is False
    assert not rr.inbound_running(_IB)
    assert set(rr.filtered_inbound()) == {_IB}


async def test_a_refused_activation_keeps_a_listener_an_operator_had_started(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the two above: a refused activation changes nothing, so an operator's
    start of an inbound, which overrides the passive park, survives it."""
    rr = await _started(engine, tmp_path)
    await rr.start_inbound(_IB, operator=True)

    async def refuse(*_args: object) -> list[tuple[Any, str]]:
        raise WiringError("a trust anchor this graph names is not readable")

    monkeypatch.setattr(rr, "_check_reload_lane_anchors", refuse)
    with pytest.raises(WiringError):
        await engine._dr_activate_profile()
    assert engine.dr_active is False and rr.inbound_running(_IB)
