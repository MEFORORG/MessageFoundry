# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Passive DR standby follow-ups (vault BACKLOG #3263; ADR 0048, the #3263 amendment).

Each test names the reading it gave before the repair. They cover four things: what a passive
box learns about its activation set at start; what an activation does with a lane it builds for
the first time; a release or an activation that is cut short; and an activation under a log halt.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
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
from messagefoundry.transports.base import DestinationConnector
from messagefoundry.transports.file import FileDestination
from tests.test_connection_scheduler import (
    _WAIT_BOUND_SECONDS,
    _DeadLogGuard,
    _LogPageSink,
    _wait_until,
)
from tests.test_dr_running_config_dir import _free_ports, _until
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


async def _delivered_on_first_claim(
    store: MessageStore, row_id: str, directory: Path, lane: str = _OB_FILE
) -> None:
    """Wait for the row on ``lane`` to settle, then require it delivered on its first claim with
    no error, and a published file in ``directory``.

    A file in the directory does not mean the row is delivered. The File outbound writes a
    ``.part`` temp first, and the row reads ``inflight`` until the delivery returns, so a wait on
    the directory then a read of the row gave ('inflight', 1, None) on a slow runner. The store
    adds one to ``attempts`` at each claim and takes it back when a claim is released unsent, so
    1 here is the delivery itself. The wait stops early on any other ending, such as a second
    attempt, an error or a dead row, so a charge fails the assert rather than the deadline."""
    last: dict[str, Any] = {}

    async def settled() -> bool:
        nonlocal last
        (last,) = [r for r in await store.outbox_for(row_id) if r["destination_name"] == lane]
        return (
            last["status"] not in ("pending", "inflight")
            or last["attempts"] > 1
            or bool(last["last_error"])
        )

    def state() -> tuple[object, ...]:
        return (last.get("status"), last.get("attempts"), last.get("last_error"))

    try:
        await _until(settled, timeout=_WAIT_BOUND_SECONDS)
    except AssertionError:
        pytest.fail(f"the {lane} row did not settle; it last read {state()}")
    assert state() == ("done", 1, None)
    # A claim that finds the row's delivery already recorded marks it done without sending, so
    # the published file is checked too. A ``.part`` temp is not one.
    assert [p for p in directory.iterdir() if p.suffix != ".part"]


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
        row_id = await store.enqueue_message(
            channel_id=_IB, raw=_ADT, deliveries=[(_OB_FILE, _ADT)]
        )
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()

        assert runner.inbound_running(_IB)
        assert "its tls_ca_file was refused" in (runner.outbound_failed(_OB_CA) or "")
        assert _OB_CA not in runner._destinations
        assert runner.outbound_failed(_OB_FILE) is None and _OB_FILE in runner._destinations
        await _delivered_on_first_claim(store, row_id, tmp_path / _OB_FILE)  # the good lane
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
        await _delivered_on_first_claim(store, row_id, tmp_path / _OB_FILE)  # the control lane
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
        # The control is the unpark-first order. Its row stops the wait at
        # ('pending', 1, 'outbound reloading'), the charged attempt.
        await _delivered_on_first_claim(store, row_id, tmp_path / _OB_FILE)
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
        row_id = await store.enqueue_message(
            channel_id=_IB, raw=_ADT, deliveries=[(_OB_FILE, _ADT)]
        )
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()

        assert runner.inbound_running(_IB)
        assert "its tls_ca_file was refused" in (runner.outbound_failed(_OB_CA) or "")
        await _delivered_on_first_claim(store, row_id, tmp_path / _OB_FILE)
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
    File lane has delivered its row on its first claim when this yields."""
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
        await _delivered_on_first_claim(store, row_id, tmp_path / _OB_FILE)
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


async def test_a_hung_startup_check_at_an_activation_fails_its_lane_and_binds_the_inbounds(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Owner ruling 2026-11-16: a lane leaving the DR park whose ``validate_startup`` hangs, as a
    check on a partner file share that does not answer does, is bounded. The lane fails, recorded
    and alerted as a failed build, the connector the build made is closed, and the activation
    binds its inbounds. Red before the bound: the prepare runs before the quiesce, so the
    activation's reload never returned and no listener bound."""
    closed: list[str] = []
    real_validate = FileDestination.validate_startup

    async def hang(self: FileDestination) -> None:
        if self.directory.name == _OB_FILE:
            await asyncio.Event().wait()
        await real_validate(self)

    async def aclose(self: FileDestination) -> None:
        closed.append(self.directory.name)

    monkeypatch.setattr(FileDestination, "validate_startup", hang)
    monkeypatch.setattr(FileDestination, "aclose", aclose)
    # Long enough that the healthy _OB_CA build on a busy runner is not cancelled with it.
    monkeypatch.setattr(wiring_runner, "_DR_PARK_BUILD_TIMEOUT_SECONDS", 5.0)
    sink = _CountingSink()
    ca = _ca(tmp_path)
    runner = _runner(
        store, _graph(tmp_path, ca, _sha(ca)), dr_standby=Priority.CRITICAL, alert_sink=sink
    )
    await runner.start()
    try:
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await asyncio.wait_for(runner.reload(), timeout=_WAIT_BOUND_SECONDS)

        assert runner.inbound_running(_IB)
        assert "within 5s as it left the DR park" in (runner.outbound_failed(_OB_FILE) or "")
        assert sink.stopped.count(_OB_FILE) == 1
        assert _OB_FILE not in runner._destinations
        assert runner._dr_unbuilt.get(_OB_FILE) is True  # held parked, as a failed build is
        assert not runner.outbound_running(_OB_FILE)
        assert _OB_CA in runner._destinations  # the other lane came up
        await _wait_until(lambda: closed == [_OB_FILE])
    finally:
        await runner.stop()


def _with_file_lanes(tmp_path: Path, reg: Registry, *names: str) -> Registry:
    """``reg`` with a critical File outbound added per name, each in its own directory."""
    for name in names:
        out = tmp_path / name
        out.mkdir(exist_ok=True)
        spec = ConnectionSpec(ConnectorType.FILE, {"directory": str(out)})
        reg.add_outbound(build_outbound_connection(name, spec, priority=Priority.CRITICAL))
    return reg


async def test_hung_startup_checks_on_three_lanes_hold_an_activation_for_one_bound(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Owner ruling 2026-11-16: the bound is on the activation's inbound binds, not on each
    lane. Three lanes leaving the DR park whose ``validate_startup`` all hang delay the binds by
    about one bound. Red when the prepare built them one after another: the reload took about
    three bounds and missed the deadline."""
    bound = 3.0
    hung = (_OB_FILE, "OB_FILE_2", "OB_FILE_3")
    closed: list[str] = []
    real_validate = FileDestination.validate_startup

    async def hang(self: FileDestination) -> None:
        if self.directory.name in hung:
            await asyncio.Event().wait()
        await real_validate(self)

    async def aclose(self: FileDestination) -> None:
        closed.append(self.directory.name)

    monkeypatch.setattr(FileDestination, "validate_startup", hang)
    monkeypatch.setattr(FileDestination, "aclose", aclose)
    monkeypatch.setattr(wiring_runner, "_DR_PARK_BUILD_TIMEOUT_SECONDS", bound)
    sink = _CountingSink()
    ca = _ca(tmp_path)
    reg = _with_file_lanes(tmp_path, _graph(tmp_path, ca, _sha(ca)), *hung[1:])
    runner = _runner(store, reg, dr_standby=Priority.CRITICAL, alert_sink=sink)
    await runner.start()
    try:
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        # One bound plus a margin, well short of the three bounds a sequential prepare takes.
        await asyncio.wait_for(runner.reload(), timeout=2.5 * bound)

        assert runner.inbound_running(_IB)
        for name in hung:
            assert "as it left the DR park" in (runner.outbound_failed(name) or ""), name
            assert sink.stopped.count(name) == 1, name
            assert name not in runner._destinations
            assert runner._dr_unbuilt.get(name) is True  # held parked, as a failed build is
        await _wait_until(lambda: sorted(closed) == sorted(hung))
    finally:
        await runner.stop()


async def test_a_hung_lane_at_an_activation_leaves_a_healthy_lane_to_go_live(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The concurrent builds share one bound, and a healthy lane among them is not failed with
    the hung one: it builds, goes live and delivers its held row."""
    healthy = "OB_FILE_OK"
    real_validate = FileDestination.validate_startup

    async def hang(self: FileDestination) -> None:
        if self.directory.name == _OB_FILE:
            await asyncio.Event().wait()
        await real_validate(self)

    monkeypatch.setattr(FileDestination, "validate_startup", hang)
    # Long enough that a healthy build on a busy runner is not cancelled with the hung one.
    monkeypatch.setattr(wiring_runner, "_DR_PARK_BUILD_TIMEOUT_SECONDS", 5.0)
    ca = _ca(tmp_path)
    reg = _with_file_lanes(tmp_path, _graph(tmp_path, ca, _sha(ca)), healthy)
    runner = _runner(store, reg, dr_standby=Priority.CRITICAL)
    await runner.start()
    try:
        row_id = await store.enqueue_message(channel_id=_IB, raw=_ADT, deliveries=[(healthy, _ADT)])
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await asyncio.wait_for(runner.reload(), timeout=_WAIT_BOUND_SECONDS)

        assert "as it left the DR park" in (runner.outbound_failed(_OB_FILE) or "")
        assert runner.outbound_failed(healthy) is None
        assert healthy in runner._destinations
        assert runner.outbound_running(healthy)
        await _delivered_on_first_claim(store, row_id, tmp_path / healthy, lane=healthy)
    finally:
        await runner.stop()


async def test_the_dr_park_build_bound_leaves_an_ordinary_reload_build_alone(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bound is the DR park's only. A reload that rebuilds a lane on a box with no DR
    profile builds it unbounded: a build slower than the bound still lands."""
    real_build = wiring_runner._build_off_loop

    async def slow(*args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(0.3)
        return await real_build(*args, **kwargs)

    ca = _ca(tmp_path)
    reg = _graph(tmp_path, ca, _sha(ca))
    runner = _runner(store, reg)
    await runner.start()
    try:
        monkeypatch.setattr(wiring_runner, "_DR_PARK_BUILD_TIMEOUT_SECONDS", 0.05)
        monkeypatch.setattr(wiring_runner, "_build_off_loop", slow)
        moved = tmp_path / "moved"
        moved.mkdir()
        await runner.reload(_graph(tmp_path, ca, _sha(ca), directory=str(moved)))
        assert runner.outbound_failed(_OB_FILE) is None
        assert Path(runner._destinations[_OB_FILE].directory) == moved  # type: ignore[attr-defined]
    finally:
        await runner.stop()


class _FakeConnector(DestinationConnector):
    """A connector a fake DR-park build returns, recording its close."""

    def __init__(self, name: str, closed: list[str]) -> None:
        self.name, self._closed = name, closed

    async def send(self, payload: str, *, metadata: Mapping[str, str] | None = None) -> None:
        raise AssertionError("never sent")

    async def aclose(self) -> None:
        self._closed.append(self.name)


class _Boom(BaseException):
    """A build's raise that is not an ``Exception``, which the build does not turn into a
    failed lane. Not ``KeyboardInterrupt``, which the event loop re-raises out of a task."""


async def _cancel_tracked(runner: RegistryRunner, *more: asyncio.Task[Any]) -> None:
    """Cancel the test's hung builds, a second cancel ending their hung cancel handlers, and
    wait for them to end."""
    tasks = [*more, *runner._lookup_close_tasks]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.wait(tasks, timeout=10)


def _bare_runner(store: MessageStore, tmp_path: Path) -> RegistryRunner:
    ca = _ca(tmp_path)
    return _runner(store, _graph(tmp_path, ca, _sha(ca)))


async def test_a_cancelled_dr_park_build_whose_cancel_handler_hangs_releases_the_reload(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cancelled reload waits for its DR-park builds at most one bound. Red when it waited
    with no limit: a build whose cancel handler hangs held the call, and so the reload lock,
    for ever. The build still running is tracked with the detached closes."""
    monkeypatch.setattr(wiring_runner, "_DR_PARK_BUILD_TIMEOUT_SECONDS", 0.3)
    runner = _bare_runner(store, tmp_path)
    started = asyncio.Event()

    async def build(name: str, oc: Any) -> Any:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.Event().wait()  # the cancel handler hangs
        raise AssertionError("unreachable")

    monkeypatch.setattr(runner, "_build_lane_destination", build)
    into: dict[str, Any] = {}
    lanes: Any = [("A", object())]
    call = asyncio.create_task(runner._build_lane_destinations_bounded(lanes, into))
    await asyncio.wait_for(started.wait(), timeout=10)
    call.cancel()
    try:
        done, _ = await asyncio.wait([call], timeout=5)
        assert call in done, "the cancelled call is still waiting on the hung build"
        assert call.cancelled()
        # The hung build, and the close waiting on it, are tracked.
        assert len([t for t in runner._lookup_close_tasks if not t.done()]) == 2
    finally:
        await _cancel_tracked(runner, call)


async def test_a_second_cancel_of_dr_park_builds_still_closes_and_tracks_them(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red when a second cancellation, landing while the call waited for its cancelled builds,
    skipped the close: the finished build's connector was dropped open and the running one
    was tracked by nothing."""
    monkeypatch.setattr(wiring_runner, "_DR_PARK_BUILD_TIMEOUT_SECONDS", 5.0)
    runner = _bare_runner(store, tmp_path)
    closed: list[str] = []
    hanging = asyncio.Event()

    async def build(name: str, oc: Any) -> Any:
        if name == "DONE":
            return wiring_runner._LaneBuild(
                _FakeConnector(name, closed), wiring_runner._AnchorVerdict()
            )
        hanging.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.Event().wait()  # the cancel handler hangs
        raise AssertionError("unreachable")

    monkeypatch.setattr(runner, "_build_lane_destination", build)
    into: dict[str, Any] = {}
    lanes: Any = [("DONE", object()), ("HUNG", object())]
    call = asyncio.create_task(runner._build_lane_destinations_bounded(lanes, into))
    await asyncio.wait_for(hanging.wait(), timeout=10)
    call.cancel()
    await asyncio.sleep(0.05)  # into the wait for the cancelled builds
    call.cancel()
    try:
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(call, timeout=10)  # a timeout is red, not a hung suite
        assert into == {}
        await _wait_until(lambda: closed == ["DONE"], timeout=5)
        # The hung build, and the close waiting on it, are tracked.
        assert len([t for t in runner._lookup_close_tasks if not t.done()]) == 2
    finally:
        await _cancel_tracked(runner)


async def test_a_dr_park_build_that_raises_leaves_every_other_result_with_the_caller(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red when one done build's raise skipped the done builds after it: their connectors went
    into nothing, so nothing closed them."""
    runner = _bare_runner(store, tmp_path)
    closed: list[str] = []

    async def build(name: str, oc: Any) -> Any:
        if name == "RAISES":
            raise _Boom
        return wiring_runner._LaneBuild(
            _FakeConnector(name, closed), wiring_runner._AnchorVerdict()
        )

    monkeypatch.setattr(runner, "_build_lane_destination", build)
    into: dict[str, Any] = {}
    lanes: Any = [("FIRST", object()), ("RAISES", object()), ("LAST", object())]
    with pytest.raises(_Boom):
        await runner._build_lane_destinations_bounded(lanes, into)
    assert sorted(into) == ["FIRST", "LAST"]
    await asyncio.sleep(0.05)  # any close a wrong abandon started gets its loop passes
    if runner._lookup_close_tasks:
        await asyncio.wait(runner._lookup_close_tasks, timeout=10)
    assert closed == []  # each result is the caller's to close, not abandoned


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
        assert sink.buildup == []  # the control: a lane the halt holds is silent

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


def _repair_the_log_after_the_prepare(
    runner: RegistryRunner, guard: _DeadLogGuard, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The disk is repaired once the reload's last prepare has read the #122 halt, so the
    prepare leaves the lanes it holds unbuilt and the apply's probe then lifts the halt (BACKLOG
    #5755). The apply awaits nothing, so the repair lands between the two."""
    real_apply = runner._apply_outbound_reconcile

    def repair_then_apply(*args: Any) -> None:
        guard.writable = True
        real_apply(*args)

    monkeypatch.setattr(runner, "_apply_outbound_reconcile", repair_then_apply)


async def _halt(runner: RegistryRunner, guard: _DeadLogGuard, monkeypatch: Any) -> None:
    monkeypatch.setattr(wiring_runner, "active_log_guard", lambda: guard)
    await runner._respond_to_log_sink_event(
        LogSinkEvent(sink="file", stage="unwritable", reason="disk full", stop_requested=True)
    )


async def test_a_halt_lifted_inside_an_activation_keeps_the_passive_starts_ca_record(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The prepare left the lane unbuilt under the halt, and the apply's probe lifted it. Red
    before the fix: the first-build block dropped the passive start's CA failure record before
    the lane was found held, so the lane read healthy with no connector."""
    ca, pin = _swapped_ca(tmp_path)
    guard = _DeadLogGuard()
    runner = _runner(
        store, _graph(tmp_path, ca, pin), dr_standby=Priority.CRITICAL, alert_sink=_LogPageSink()
    )
    await runner.start()
    try:
        assert _PASSIVE_REFUSED in (runner.outbound_failed(_OB_CA) or "")
        await _halt(runner, guard, monkeypatch)
        _repair_the_log_after_the_prepare(runner, guard, monkeypatch)
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()

        assert not runner._delivery_halted  # the apply's probe lifted it
        assert _OB_CA not in runner._destinations
        assert runner.outbound_filtered(_OB_CA) is None
        held = runner.outbound_failed(_OB_CA) or ""
        assert "passive start" in held and "POST /dr/activate needs it" not in held
        assert not runner.outbound_dr_failed(_OB_CA)  # no build ran, so none failed
    finally:
        await runner.stop()


async def test_a_halt_lifted_inside_a_reload_keeps_an_earlier_failed_build_mark(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lane's build failed at the activation, then a reload found it held by the halt the
    apply's probe lifted. Red before the fix: that path wrote the lane's mark False, so it no
    longer read as a failed build and its pages went silent."""
    ca, pin = _swapped_ca(tmp_path)
    guard = _DeadLogGuard()
    runner = _runner(
        store, _graph(tmp_path, ca, pin), dr_standby=Priority.CRITICAL, alert_sink=_LogPageSink()
    )
    await runner.start()
    try:
        runner.set_dr_threshold(Priority.CRITICAL, standby=None)  # the activation
        await runner.reload()
        assert runner.outbound_dr_failed(_OB_CA)
        failed = runner.outbound_failed(_OB_CA)

        await _halt(runner, guard, monkeypatch)
        _repair_the_log_after_the_prepare(runner, guard, monkeypatch)
        await runner.reload()

        assert not runner._delivery_halted  # the apply's probe lifted it
        assert _OB_CA not in runner._destinations
        assert runner.outbound_dr_failed(_OB_CA)
        assert runner.outbound_failed(_OB_CA) == failed
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
        await asyncio.sleep(0.3)
        assert not runner.outbound_running(_OB_FILE)
        assert not any((tmp_path / _OB_FILE).iterdir())

        await runner.start_outbound(_OB_FILE)  # the control: the operator's start delivers
        await _wait_until(lambda: any((tmp_path / _OB_FILE).iterdir()))
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
        dr_settings=DrSettings(enabled=True, seed_archive="seed.mfbak"),
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
