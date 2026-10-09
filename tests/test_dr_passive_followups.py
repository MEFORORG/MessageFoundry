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
from contextlib import asynccontextmanager
from datetime import UTC, datetime, time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import messagefoundry.auth.trust_anchors as ta
from messagefoundry.api.app import _alert_control_action
from messagefoundry.config.models import (
    ActiveWindow,
    BuildupThreshold,
    ConnectorType,
    Priority,
    Schedule,
)
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
from messagefoundry.pipeline.dr import DrActivationError
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


def _graph(
    tmp_path: Path,
    ca: Path,
    pin: str,
    *,
    ca_schedule: Schedule | None = None,
    **file_settings: object,
) -> Registry:
    """A critical MLLP inbound, a Rest outbound with a pinned CA and a File outbound."""
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            _IB, MLLP(port=_free_ports(1)[0]), router="r", priority=Priority.CRITICAL
        )
    )
    rest = Rest(url="https://partner.example.org/api", tls_ca_file=str(ca), tls_ca_pin=pin)
    reg.add_outbound(
        build_outbound_connection(_OB_CA, rest, priority=Priority.CRITICAL, schedule=ca_schedule)
    )
    out = tmp_path / _OB_FILE
    if "directory" not in file_settings:
        out.mkdir(exist_ok=True)
    spec = ConnectionSpec(ConnectorType.FILE, {"directory": str(out), **file_settings})
    reg.add_outbound(build_outbound_connection(_OB_FILE, spec, priority=Priority.CRITICAL))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send(_OB_FILE, m))
    return reg


def _runner(store: MessageStore, reg: Registry, **kw: Any) -> RegistryRunner:
    kw.setdefault("lane_anchor_check", ta.make_lane_anchor_check(store, enforcing=True))
    return RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False), **kw
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


async def test_an_activation_on_an_engine_shard_that_does_not_own_a_lane_fails_that_lane_only(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every engine shard builds every lane at a start, so each one takes the start's checks at
    an activation too (ADR 0073). Red when only the owning engine shard did: the engine shard that
    does not own the lane sent it to the reload's CA pre-check, and one refused CA refused its
    whole takeover."""
    ca, pin = _swapped_ca(tmp_path)
    runner = _runner(store, _graph(tmp_path, ca, pin), dr_standby=Priority.CRITICAL)
    monkeypatch.setattr(runner, "_owns_destination", lambda name: name != _OB_CA)
    await runner.start()
    try:
        await store.enqueue_message(channel_id=_IB, raw=_ADT, deliveries=[(_OB_FILE, _ADT)])
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()

        assert runner.inbound_running(_IB)
        assert "its tls_ca_file was refused" in (runner.outbound_failed(_OB_CA) or "")
        await _wait_until(lambda: any((tmp_path / _OB_FILE).iterdir()))
    finally:
        await runner.stop()


# --- a lane that failed at an activation --------------------------------------------------

_ALWAYS = Schedule(
    windows=[
        ActiveWindow(days=frozenset(range(7)), start=time(0, 0), end=time(23, 59), timezone="UTC")
    ]
)
_NOON = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
_LATE = datetime(2026, 6, 1, 23, 59, 30, tzinfo=UTC)  # outside _ALWAYS


class _PageSink(_CountingSink):
    """Records ``queue_buildup`` pages as well."""

    def __init__(self) -> None:
        super().__init__()
        self.buildup: list[str] = []

    def queue_buildup(self, name: str, **_kw: object) -> None:
        self.buildup.append(name)


@asynccontextmanager
async def _after_a_failed_activation(
    store: MessageStore, tmp_path: Path, *, ca_schedule: Schedule | None = None, **kw: Any
) -> AsyncIterator[tuple[RegistryRunner, Path, str]]:
    """A passive box with a row held on each outbound, activated with the CA lane refused. The
    File lane has delivered its row when this yields."""
    ca, pin = _swapped_ca(tmp_path)
    reg = _graph(tmp_path, ca, pin, ca_schedule=ca_schedule)
    runner = _runner(store, reg, dr_standby=Priority.CRITICAL, **kw)
    await runner.start()
    try:
        row_id = await store.enqueue_message(
            channel_id=_IB, raw=_ADT, deliveries=[(_OB_CA, _ADT), (_OB_FILE, _ADT)]
        )
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()
        await _wait_until(lambda: any((tmp_path / _OB_FILE).iterdir()))
        assert _OB_CA not in runner._destinations
        yield runner, ca, row_id
    finally:
        await runner.stop()


async def _ca_row(store: MessageStore, row_id: str) -> tuple[str, int]:
    """The status and attempts of the row held on the CA lane."""
    (row,) = [r for r in await store.outbox_for(row_id) if r["destination_name"] == _OB_CA]
    return row["status"], row["attempts"]


async def test_the_scheduler_leaves_a_lane_that_failed_at_an_activation_held(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Red when the lane had no DR marker the scheduler read: the reload's new scheduler task
    found it in its window and not running, started it with no connector, and charged the held
    row an attempt (ADR 0048: a parked row is never charged). Nor does a tick read the CA again."""
    check = ta.make_lane_anchor_check(store, enforcing=True)
    reads: list[str] = []

    async def counting(direction: str, name: str, settings: Any) -> None:
        reads.append(name)
        await check(direction, name, settings)

    async with _after_a_failed_activation(
        store,
        tmp_path,
        ca_schedule=_ALWAYS,
        schedule_tick=0.02,
        schedule_clock=lambda: _NOON,
        lane_anchor_check=counting,
    ) as (runner, _ca, row_id):
        before = reads.count(_OB_CA)
        await asyncio.sleep(0.3)
        assert await _ca_row(store, row_id) == ("pending", 0)
        assert not runner.outbound_running(_OB_CA)
        assert reads.count(_OB_CA) == before


async def test_a_start_or_restart_of_a_lane_that_failed_at_an_activation_charges_nothing(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The CA is still refused. Red when the doors resumed the lane once its build failed again:
    the held row was claimed with no connector and charged an attempt."""
    async with _after_a_failed_activation(store, tmp_path) as (runner, _ca, row_id):
        await runner.restart_outbound(_OB_CA)
        await runner.start_outbound(_OB_CA)
        await asyncio.sleep(0.3)
        assert await _ca_row(store, row_id) == ("pending", 0)
        assert not runner.outbound_running(_OB_CA)
        assert "its tls_ca_file was refused" in (runner.outbound_failed(_OB_CA) or "")


async def test_an_alert_rule_does_not_restart_a_lane_that_failed_at_an_activation(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An alert rule is the engine, as the scheduler is. Red when its restart reached the lane:
    each fire read the CA again and could alert again, which can fire the rule again."""
    async with _after_a_failed_activation(store, tmp_path) as (runner, _ca, _row_id):
        restarted: list[str] = []

        async def record(name: str) -> None:
            restarted.append(name)

        monkeypatch.setattr(runner, "restart_outbound", record)
        engine = cast(Engine, SimpleNamespace(registry_runner=runner))
        await _alert_control_action(engine, "restart_outbound", _OB_CA, default_target=False)
        await _alert_control_action(engine, "restart_outbound", _OB_FILE, default_target=False)
        assert restarted == [_OB_FILE]  # the control: a healthy lane is restarted


async def test_a_lane_that_failed_at_an_activation_still_pages_its_buildup(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR 0031 paging holds for the held lane. Red when its park silenced it: a paused lane's
    buildup page is suppressed, so a critical feed held at the takeover never paged."""
    monkeypatch.setattr(wiring_runner, "_INFLIGHT_WATCH_INTERVAL_SECONDS", 0.05)
    sink = _PageSink()
    async with _after_a_failed_activation(
        store, tmp_path, alert_sink=sink, buildup_default=BuildupThreshold(max_depth=1)
    ):
        await _wait_until(lambda: _OB_CA in sink.buildup)


async def test_a_lane_that_failed_outside_its_window_still_pages_its_buildup(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The activation falls outside the lane's schedule window, so the reload hands its park to
    the calendar before the build. Red when the failed lane stayed the calendar's: the calendar
    leaves a failed lane alone, and the paging check passed it over, so it never paged."""
    monkeypatch.setattr(wiring_runner, "_INFLIGHT_WATCH_INTERVAL_SECONDS", 0.05)
    sink = _PageSink()
    async with _after_a_failed_activation(
        store,
        tmp_path,
        ca_schedule=_ALWAYS,
        schedule_clock=lambda: _LATE,
        alert_sink=sink,
        buildup_default=BuildupThreshold(max_depth=1),
    ):
        await _wait_until(lambda: _OB_CA in sink.buildup)


async def test_a_passive_box_does_not_page_the_rows_it_holds(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the page above: on a passive box the park is the design, not a fault."""
    monkeypatch.setattr(wiring_runner, "_INFLIGHT_WATCH_INTERVAL_SECONDS", 0.05)
    sink = _PageSink()
    ca, pin = _swapped_ca(tmp_path)
    runner = _runner(
        store,
        _graph(tmp_path, ca, pin),
        dr_standby=Priority.CRITICAL,
        alert_sink=sink,
        buildup_default=BuildupThreshold(max_depth=1),
    )
    await runner.start()
    try:
        await store.enqueue_message(channel_id=_IB, raw=_ADT, deliveries=[(_OB_CA, _ADT)])
        await asyncio.sleep(0.3)
        assert sink.buildup == []
    finally:
        await runner.stop()


async def test_a_reload_builds_a_lane_that_failed_at_an_activation_once_its_ca_is_fixed(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """Red when a reload lifted the park and built nothing: with the CA still refused the held
    row was charged attempts, and with it fixed the lane stayed down until an operator start."""
    async with _after_a_failed_activation(store, tmp_path) as (runner, ca, row_id):
        await runner.reload()  # the CA is still refused
        await asyncio.sleep(0.3)
        assert await _ca_row(store, row_id) == ("pending", 0)
        assert not runner.outbound_running(_OB_CA)

        ca.write_bytes(_block(b"partner-ca"))
        await runner.reload()
        assert _OB_CA in runner._destinations and runner.outbound_failed(_OB_CA) is None
        assert runner.outbound_running(_OB_CA)


async def test_a_lane_built_while_the_box_turns_passive_again_stays_parked(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A failed activation hands the threshold back without the reload lock, so the box can turn
    passive while a lane's first build awaits. Red when the unpark did not look again: the lane
    delivered its held row on a passive box."""
    ca = _ca(tmp_path)
    armed, building, go = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def held(direction: str, name: str, settings: object) -> None:
        if name == _OB_FILE and armed.is_set():
            building.set()
            await go.wait()

    runner = _runner(
        store, _graph(tmp_path, ca, _sha(ca)), lane_anchor_check=held, dr_standby=Priority.CRITICAL
    )
    await runner.start()
    try:
        await store.enqueue_message(channel_id=_IB, raw=_ADT, deliveries=[(_OB_FILE, _ADT)])
        armed.set()
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        reload = asyncio.create_task(runner.reload())
        await asyncio.wait_for(building.wait(), timeout=10)
        runner.set_dr_threshold(None, standby=Priority.CRITICAL)  # and its rollback
        go.set()
        await reload
        await asyncio.sleep(0.3)

        assert not runner.outbound_running(_OB_FILE)
        assert (runner.outbound_filtered(_OB_FILE) or "").startswith("DR standby is passive")
        assert not any((tmp_path / _OB_FILE).iterdir())
    finally:
        await runner.stop()


async def test_a_reload_cancelled_in_a_first_build_leaves_the_lane_on_that_path(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The reload drops the lane's passive marker, then is cancelled while the build awaits. Red
    when the lane was marked unbuilt only after the build: it then had neither mark, so the next
    reload sent it to the CA pre-check and one refused CA refused that reload whole."""
    ca, pin = _swapped_ca(tmp_path)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    armed, building = asyncio.Event(), asyncio.Event()

    async def held(direction: str, name: str, settings: Any) -> None:
        if name == _OB_CA and armed.is_set():
            building.set()
            await asyncio.Event().wait()
        await check(direction, name, settings)

    runner = _runner(
        store, _graph(tmp_path, ca, pin), lane_anchor_check=held, dr_standby=Priority.CRITICAL
    )
    await runner.start()
    try:
        row_id = await store.enqueue_message(channel_id=_IB, raw=_ADT, deliveries=[(_OB_CA, _ADT)])
        armed.set()
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        reload = asyncio.create_task(runner.reload())
        await asyncio.wait_for(building.wait(), timeout=10)
        reload.cancel()
        with pytest.raises(asyncio.CancelledError):
            await reload
        armed.clear()

        await runner.reload()  # raised WiringError before
        assert "its tls_ca_file was refused" in (runner.outbound_failed(_OB_CA) or "")
        await asyncio.sleep(0.3)
        assert await _ca_row(store, row_id) == ("pending", 0)
    finally:
        await runner.stop()


async def test_a_cancelled_first_build_closes_the_connector_it_built(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red when the cancellation skipped the close: the built connector was dropped open."""
    closed: list[str] = []
    entered = asyncio.Event()

    async def hang(self: FileDestination) -> None:
        entered.set()
        await asyncio.Event().wait()

    async def aclose(self: FileDestination) -> None:
        closed.append(self.directory.name)

    monkeypatch.setattr(FileDestination, "validate_startup", hang)
    monkeypatch.setattr(FileDestination, "aclose", aclose)
    ca = _ca(tmp_path)
    runner = _runner(store, _graph(tmp_path, ca, _sha(ca)), dr_standby=Priority.CRITICAL)
    await runner.start()
    try:
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)
        runner._filtered.pop(("outbound", _OB_FILE), None)  # as the reconcile does first
        build = asyncio.create_task(runner._ensure_destination_built(_OB_FILE))
        await asyncio.wait_for(entered.wait(), timeout=10)
        build.cancel()
        with pytest.raises(asyncio.CancelledError):
            await build
        assert closed == [_OB_FILE] and _OB_FILE not in runner._destinations
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


async def test_a_lane_an_activation_under_a_log_halt_left_unbuilt_keeps_its_isolation(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The halt holds the lane at the activation, so its first build has not run, and its CA is
    refused. Red when the halt branch dropped the passive marker and kept no other record: once
    the log was repaired, a reload sent the lane to its CA pre-check and was refused whole, and
    a start resumed the lane with no connector and charged its held row an attempt."""
    monkeypatch.setattr(wiring_runner, "_INFLIGHT_WATCH_INTERVAL_SECONDS", 0.05)
    ca, pin = _swapped_ca(tmp_path)
    guard = _DeadLogGuard()
    sink = _PageSink()
    runner = _runner(
        store,
        _graph(tmp_path, ca, pin),
        dr_standby=Priority.CRITICAL,
        alert_sink=sink,
        buildup_default=BuildupThreshold(max_depth=1),
    )
    await runner.start()
    try:
        row_id = await store.enqueue_message(channel_id=_IB, raw=_ADT, deliveries=[(_OB_CA, _ADT)])
        monkeypatch.setattr(wiring_runner, "active_log_guard", lambda: guard)
        await runner._respond_to_log_sink_event(
            LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=True)
        )
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()
        assert runner.outbound_filtered(_OB_CA) is None
        # Still shown as failed, in words that fit an active box, and not yet a failed build: the
        # halt kept the build from running. Red when the passive start's record stood unchanged:
        # it asked for an activation that had run, and the lane read as failed at its build, so
        # the scheduler and an alert rule's restart passed it over and it paged during the halt.
        held = runner.outbound_failed(_OB_CA) or ""
        assert "passive start" in held and "POST /dr/activate needs it" not in held
        assert not runner.outbound_dr_failed(_OB_CA)
        # An alert rule's restart reaches it now, and the halt refuses the start half.
        engine = cast(Engine, SimpleNamespace(registry_runner=runner))
        await _alert_control_action(engine, "restart_outbound", _OB_CA, default_target=False)
        await asyncio.sleep(0.3)
        # Not a control for the restart: a lane the halt holds is silent with or without it.
        # It shows the page below is the build's, not the halt's.
        assert sink.buildup == []

        guard.writable = True  # the disk is repaired
        await runner.reload()  # raised WiringError before
        built = runner.outbound_failed(_OB_CA) or ""
        assert "its tls_ca_file was refused" in built and "passive" not in built
        assert runner.outbound_dr_failed(_OB_CA)
        # The failed lane pages, as the engine holds it. Red when the restart's stop half left
        # the park an operator pause: a paused lane is silent, so it never paged.
        await _wait_until(lambda: _OB_CA in sink.buildup)
        await runner.start_outbound(_OB_CA)
        await asyncio.sleep(0.3)
        assert await _ca_row(store, row_id) == ("pending", 0)
        assert not runner.outbound_running(_OB_CA)
    finally:
        await runner.stop()


async def test_a_refused_restart_keeps_an_operator_stop_of_a_lane_a_log_halt_left_unbuilt(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator stops the lane, an alert rule's restart reaches it, and the halt refuses the
    start half. Red when that refusal made the lane the engine's park: once the log was repaired,
    the reload that built the lane resumed it and delivered its held row, undoing the stop."""
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
        await runner.stop_outbound(_OB_FILE)  # the operator's stop
        engine = cast(Engine, SimpleNamespace(registry_runner=runner))
        await _alert_control_action(engine, "restart_outbound", _OB_FILE, default_target=False)

        guard.writable = True  # the disk is repaired
        await runner.reload()
        assert _OB_FILE in runner._destinations  # the reload built it
        # The halt has lifted, so what holds the lane below is the pause and not the halt.
        assert not runner._delivery_halted
        await asyncio.sleep(0.3)
        assert not runner.outbound_running(_OB_FILE)
        assert not any((tmp_path / _OB_FILE).iterdir())

        await runner.start_outbound(_OB_FILE)  # the control: the operator's start delivers
        await _wait_until(lambda: any((tmp_path / _OB_FILE).iterdir()))
    finally:
        await runner.stop()


async def test_a_restart_whose_build_fails_keeps_an_operator_stop(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator stops a lane a log halt kept from its first build, and its CA is refused.
    Once the log is repaired an alert rule's restart builds it, and the build fails. Red when
    that failure made the lane the engine's park: the reload after the CA was fixed resumed it,
    undoing the stop, and its held row was claimed."""
    ca, pin = _swapped_ca(tmp_path)
    guard = _DeadLogGuard()
    runner = _runner(
        store, _graph(tmp_path, ca, pin), dr_standby=Priority.CRITICAL, alert_sink=_LogPageSink()
    )
    await runner.start()
    try:
        row_id = await store.enqueue_message(channel_id=_IB, raw=_ADT, deliveries=[(_OB_CA, _ADT)])
        monkeypatch.setattr(wiring_runner, "active_log_guard", lambda: guard)
        await runner._respond_to_log_sink_event(
            LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=True)
        )
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()
        await runner.stop_outbound(_OB_CA)  # the operator's stop

        guard.writable = True  # the disk is repaired
        engine = cast(Engine, SimpleNamespace(registry_runner=runner))
        await _alert_control_action(engine, "restart_outbound", _OB_CA, default_target=False)
        assert runner.outbound_dr_failed(_OB_CA)  # the restart's build ran and failed

        ca.write_bytes(_block(b"partner-ca"))
        await runner.reload()
        assert _OB_CA in runner._destinations  # the reload built it
        await asyncio.sleep(0.3)
        assert not runner.outbound_running(_OB_CA)
        assert await _ca_row(store, row_id) == ("pending", 0)
    finally:
        await runner.stop()


async def test_a_restart_cancelled_in_its_build_leaves_the_engine_park_a_reload_lifts(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The lane failed at the activation, so the engine holds it. A restart is cancelled while
    its start half builds the lane. Red when the stop half's operator pause stood: the reload
    after the CA was fixed built the lane and left it paused."""
    check = ta.make_lane_anchor_check(store, enforcing=True)
    armed, building = asyncio.Event(), asyncio.Event()

    async def held(direction: str, name: str, settings: Any) -> None:
        if name == _OB_CA and armed.is_set():
            building.set()
            await asyncio.Event().wait()
        await check(direction, name, settings)

    async with _after_a_failed_activation(store, tmp_path, lane_anchor_check=held) as (
        runner,
        ca,
        row_id,
    ):
        armed.set()
        restart = asyncio.create_task(runner.restart_outbound(_OB_CA))
        await asyncio.wait_for(building.wait(), timeout=10)
        restart.cancel()
        with pytest.raises(asyncio.CancelledError):
            await restart
        armed.clear()
        await asyncio.sleep(0.3)
        assert await _ca_row(store, row_id) == ("pending", 0)

        ca.write_bytes(_block(b"partner-ca"))
        await runner.reload()
        assert _OB_CA in runner._destinations
        assert runner.outbound_running(_OB_CA)


async def test_the_calendar_starts_a_lane_a_log_halt_kept_unbuilt_once_the_halt_lifts(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The halt kept the lane from its first build, and nothing about it failed. Red when the
    scheduler left every unbuilt lane alone: the window open passed it over, and it stayed down
    with its rows held and no page until a reload or a start by hand."""
    ca = _ca(tmp_path)
    guard = _DeadLogGuard()
    runner = _runner(
        store,
        _graph(tmp_path, ca, _sha(ca), ca_schedule=_ALWAYS),
        dr_standby=Priority.CRITICAL,
        alert_sink=_LogPageSink(),
        schedule_clock=lambda: _NOON,
    )
    await runner.start()
    try:
        monkeypatch.setattr(wiring_runner, "active_log_guard", lambda: guard)
        await runner._respond_to_log_sink_event(
            LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=True)
        )
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()
        guard.writable = True  # the disk is repaired
        await runner.start_outbound(_OB_FILE)  # the halt's recovery, which clears the latch

        await runner._reconcile_schedule(_OB_CA, "outbound", _ALWAYS)  # a window-open tick
        assert runner.outbound_running(_OB_CA) and _OB_CA in runner._destinations
    finally:
        await runner.stop()


async def test_a_lane_a_reload_adds_under_a_log_halt_takes_its_dr_marker(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An active box, under a halt, reloads a graph that adds a feed below the threshold. The
    halt pauses that lane now. Red when only a lane already paused was judged: the new lane had no
    marker, so a start of it once the log was repaired built a feed the profile parks."""
    ca = _ca(tmp_path)
    guard = _DeadLogGuard()
    runner = _runner(
        store,
        _graph(tmp_path, ca, _sha(ca)),
        dr_threshold=Priority.CRITICAL,
        alert_sink=_LogPageSink(),
    )
    await runner.start()
    try:
        monkeypatch.setattr(wiring_runner, "active_log_guard", lambda: guard)
        await runner._respond_to_log_sink_event(
            LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=True)
        )
        reg = _graph(tmp_path, ca, _sha(ca))
        low = ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / _OB_FILE)})
        reg.add_outbound(build_outbound_connection("OB_LOW", low, priority=Priority.NORMAL))
        await runner.reload(reg)

        assert runner.outbound_filtered("OB_LOW") is not None
        guard.writable = True  # the disk is repaired
        with pytest.raises(DrParkedError):
            await runner.start_outbound("OB_LOW")
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


async def test_a_release_whose_row_cannot_be_written_still_closes_its_sessions(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The box has handed back when the ``dr.release`` row is written, so a released box holds
    no partner session whether that write lands or not (vault BACKLOG #3262). Red when the
    cleanup ran only after the row: an audit store that refused the write left every session
    open, and each retry refused at the same write before it reached the cleanup."""
    rr = await _started(engine, tmp_path)
    coordinator = engine.dr_coordinator
    assert coordinator is not None
    await engine._dr_activate_profile()
    coordinator._active = True
    store = coordinator._store
    real_record = store.record_audit

    async def refuse_release_row(action: str, *args: Any, **kwargs: Any) -> Any:
        if action == "dr.release":
            raise OSError("the audit store refused the write")
        return await real_record(action, *args, **kwargs)

    closed: list[bool] = []

    async def close() -> None:
        closed.append(True)

    monkeypatch.setattr(store, "record_audit", refuse_release_row)
    monkeypatch.setattr(rr, "close_passive_connectors", close)
    with pytest.raises(DrActivationError):
        await coordinator.release(actor="operator")
    assert closed == [True] and engine.dr_active is False

    with pytest.raises(DrActivationError):  # the row is still owed, and the retry closes again
        await coordinator.release(actor="operator")
    assert closed == [True, True]


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


async def test_a_refused_activation_closes_sessions_when_its_unbind_fails(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The unbind and the close are separate steps. Red when one try held both: an unbind error
    skipped the close, and the outbound sessions the attempt opened stayed open."""
    rr = await _started(engine, tmp_path)

    async def refuse(*_args: object) -> list[tuple[Any, str]]:
        raise WiringError("a trust anchor this graph names is not readable")

    async def unbind_fails(*_args: object, **_kw: object) -> None:
        raise OSError("the listener would not close")

    closed: list[bool] = []

    async def close() -> None:
        closed.append(True)

    monkeypatch.setattr(rr, "_check_reload_lane_anchors", refuse)
    monkeypatch.setattr(rr, "park_intake", unbind_fails)
    monkeypatch.setattr(rr, "close_passive_connectors", close)
    with pytest.raises(WiringError):
        await engine._dr_activate_profile()
    assert closed == [True] and engine.dr_active is False
