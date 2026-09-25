# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connscale reload probe's accounting window (BACKLOG #1292).

The engine's reload closes every inbound connection, so the probe strands whatever is in flight. On a
loaded windows-2025 runner on 2026-09-25 that was most of a 36-send step, and the no-loss reconcile
reported it as intake loss. ``_reload_mid_hold`` now counts what the reload strands, waits for every
connection to come back, and keeps traffic flowing after it. These tests pin that window:

* only the ``timeouts`` that move between the probe firing and every connection returning are
  attributed to the reload -- not those before it, not those after it;
* more hold is offered only when a slow reload left too little of it, or no send, behind;
* the reconnect wait runs unless dual-control held the reload, including when the request timed out;
* the reconnect wait is real: a connection the engine drops opens a new socket, and one that cannot
  reconnect is reported rather than waited on forever.

ORDERING, NOT WALL CLOCK. The hold's late timeouts wait on the window closing, and the time left in
the hold is set through ``hold_started``, so a stalled event loop on a loaded runner cannot move a
send across the window's edge.
"""

from __future__ import annotations

import asyncio

import pytest

from harness.load.connscale import runner
from harness.load.connscale.driver import ConnScaleDriver
from harness.load.connscale.report import ConnScaleRecord
from harness.load.correlator import Correlator
from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.metrics import Counters, Histogram, LiveMetrics

_HOLD = 0.2  # the probe sleeps half of this before it fires; nothing below races against it


class _FakeDriver:
    """The three members ``_reload_mid_hold`` reads, over N fake connection generations."""

    def __init__(self, count: int) -> None:
        self.gens = [1] * count
        self.waited_with: list[int] | None = None
        self.window_closed = asyncio.Event()
        self.emitted_count = 0

    @property
    def emitted(self) -> int:
        # The probe reads this right after its snapshot, so reading it marks the window closed.
        self.window_closed.set()
        return self.emitted_count

    def generations(self) -> list[int]:
        return list(self.gens)

    async def await_reconnected(self, since: list[int], *, timeout: float) -> int:
        self.waited_with = list(since)
        return sum(1 for g, s in zip(self.gens, since, strict=True) if g <= s)


async def _window(
    *,
    counters: Counters,
    driver: _FakeDriver,
    strands: int,
    returns: tuple[float | None, bool] = (0.01, False),
    reconnect: bool = True,
    hold_left_after: float,
    emits_after: int = 1,
    during_hold: int = 0,
) -> tuple[runner._ReloadAccount, list[float]]:
    """Run ``_reload_mid_hold`` with a reload that strands ``strands`` sends.

    ``hold_left_after`` is how much of the hold remains once the connections are back, set by
    placing ``hold_started`` rather than by sleeping. ``emits_after`` sends are offered in that
    remainder, and ``during_hold`` timeouts land in it: the stop-grace or unrelated close that must
    NOT be attributed to the reload.
    """
    extra_holds: list[float] = []

    async def reload() -> tuple[float | None, bool]:
        counters.timeouts += strands
        counters.sent += strands
        if reconnect:
            driver.gens = [g + 1 for g in driver.gens]
        return returns

    async def run_hold(seconds: float) -> None:
        extra_holds.append(seconds)

    async def hold() -> None:
        # Runs on only once the probe has taken its snapshot (see `_FakeDriver.emitted`).
        await driver.window_closed.wait()
        driver.emitted_count += emits_after
        counters.timeouts += during_hold

    loop = asyncio.get_running_loop()
    # The probe fires at `_HOLD / 2`; place the hold's end `hold_left_after` past the moment the
    # connections come back, which is at most a few ms after that.
    started = loop.time() + hold_left_after - _HOLD / 2
    hold_task = asyncio.create_task(hold())
    account = await runner._reload_mid_hold(
        driver=driver,  # type: ignore[arg-type]
        counters=counters,
        reload=reload,
        run_hold=run_hold,
        hold_task=hold_task,
        hold_seconds=_HOLD,
        hold_started=started,
    )
    return account, extra_holds


async def test_only_the_timeouts_inside_the_window_are_the_reloads() -> None:
    # 4 timeouts before the probe fired, 7 stranded by the reload, 5 after every connection was back.
    # Only the 7 are the reload's.
    counters = Counters(sent=10, timeouts=4)
    account, _ = await _window(
        counters=counters, driver=_FakeDriver(3), strands=7, during_hold=5, hold_left_after=10.0
    )
    assert account.stranded == 7
    assert counters.timeouts == 16  # the control: all three batches really did land
    assert account.after.timeouts == 11  # the snapshot sits between the reload and the late 5


async def test_a_quick_reload_adds_no_hold() -> None:
    # Plenty of hold left after the connections came back, and a send offered in it: nothing added.
    account, extra = await _window(
        counters=Counters(), driver=_FakeDriver(2), strands=1, hold_left_after=10.0
    )
    assert extra == []
    assert account.extra_hold_s == 0.0
    assert account.not_reconnected == 0


async def test_a_slow_reload_is_followed_by_traffic() -> None:
    # The hold ended before the connections came back, so a quarter hold is added. This is the step
    # shape CI produced, with nothing offered after the reload.
    account, extra = await _window(
        counters=Counters(), driver=_FakeDriver(2), strands=5, hold_left_after=-10.0
    )
    assert extra == [account.extra_hold_s]
    assert account.extra_hold_s == pytest.approx(_HOLD * runner._POST_RELOAD_HOLD_FRACTION)


async def test_time_left_but_no_send_offered_still_adds_hold() -> None:
    # A low rate: time remained after the reload, but no token fell due in it. The floor is offered
    # anyway, and `run_hold` sends at once, so the step has a send the reload did not touch.
    account, extra = await _window(
        counters=Counters(), driver=_FakeDriver(2), strands=1, hold_left_after=10.0, emits_after=0
    )
    assert extra == [_HOLD * runner._POST_RELOAD_HOLD_FRACTION]
    assert account.extra_hold_s == extra[0]


async def test_connections_that_never_came_back_are_counted() -> None:
    driver = _FakeDriver(4)
    account, _ = await _window(
        counters=Counters(), driver=driver, strands=2, reconnect=False, hold_left_after=10.0
    )
    assert driver.waited_with == [1, 1, 1, 1]
    assert account.not_reconnected == 4


async def test_a_reload_with_no_reading_is_still_waited_for() -> None:
    # The request timed out (no reading) but was not held. The engine may still be restarting its
    # listeners, which is the slow reload this exists for, so the wait runs.
    driver = _FakeDriver(2)
    account, _ = await _window(
        counters=Counters(), driver=driver, strands=3, returns=(None, False), hold_left_after=10.0
    )
    assert driver.waited_with == [1, 1]
    assert account.seconds is None
    assert account.stranded == 3


async def test_a_held_reload_is_not_waited_for() -> None:
    # Dual-control held it: nothing was swapped or closed, so waiting would only burn the timeout.
    driver = _FakeDriver(2)
    account, _ = await _window(
        counters=Counters(),
        driver=driver,
        strands=0,
        returns=(None, True),
        reconnect=False,
        hold_left_after=10.0,
    )
    assert driver.waited_with is None
    assert account.held
    assert account.not_reconnected == 0


async def test_a_failed_probe_cancels_the_hold() -> None:
    # A reload that raises something other than ApiError must not leave the token bucket running.
    hold_task = asyncio.create_task(asyncio.sleep(30))

    async def reload() -> tuple[float | None, bool]:
        raise RuntimeError("decode failed")

    async def run_hold(seconds: float) -> None:
        raise AssertionError("no extra hold after a failed probe")

    with pytest.raises(RuntimeError, match="decode failed"):
        await runner._reload_mid_hold(
            driver=_FakeDriver(1),  # type: ignore[arg-type]
            counters=Counters(),
            reload=reload,
            run_hold=run_hold,
            hold_task=hold_task,
            hold_seconds=0.02,
            hold_started=asyncio.get_running_loop().time(),
        )
    with pytest.raises(asyncio.CancelledError):
        await hold_task


def _real_driver(port: int) -> ConnScaleDriver:
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    return ConnScaleDriver(
        host="127.0.0.1",
        base_port=port,
        count=1,
        correlator=Correlator(1000, metrics),
        metrics=metrics,
    )


async def test_a_dropped_connection_opens_a_new_socket_and_the_driver_sees_it() -> None:
    # The real sender against a real listener that closes each client once, as the engine's reload
    # does. The generation moves and the new socket is up, so the wait returns 0.
    closed = asyncio.Event()

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not closed.is_set():
            closed.set()
            writer.close()
            return
        await reader.read()  # hold the second connection open until the client leaves
        writer.close()

    server = await asyncio.start_server(on_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    driver = _real_driver(port)
    try:
        await driver.open(connect_batch=1, batch_pause_s=0.0)
        await asyncio.wait_for(closed.wait(), timeout=5.0)
        before = [1]  # the first socket, which the listener has just closed
        assert await driver.await_reconnected(before, timeout=5.0) == 0
        assert driver.generations()[0] >= 2
    finally:
        await driver.stop(0.1)
        server.close()


async def test_a_connection_that_cannot_reconnect_is_reported_not_awaited_forever() -> None:
    # THE CONTROL for the test above: the listener is gone, so the generation never moves and the
    # bounded wait returns the connection as still down.
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    driver = _real_driver(port)
    try:
        await driver.open(connect_batch=1, batch_pause_s=0.0)
        assert await driver.await_reconnected(driver.generations(), timeout=0.3) == 1
    finally:
        await driver.stop(0.1)


def _engine_sample(read: int) -> EngineSample:
    return EngineSample(
        elapsed_s=1.0,
        pending=0,
        inflight=0,
        done=read,
        dead=0,
        read=read,
        written=read,
        out_dead=0,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=1.0,
    )


def _record(counters: Counters, reload: runner._ReloadAccount | None) -> ConnScaleRecord:
    poller = EnginePoller("http://127.0.0.1:1", token=None, origin=0.0)
    poller._samples = [_engine_sample(0), _engine_sample(counters.sink_received)]
    return runner._build_record(
        claim_mode="per_lane",
        fuse_mode=False,
        batch_mode=False,
        mode="fixed_aggregate",
        count=12,
        aggregate_rate=24.0,
        metrics_counters=counters,
        ack_hist=Histogram(),
        poller=poller,
        samples=[],
        in_hold_samples=0,
        in_hold_floor_ticks=0,
        proc_readings=[],
        drain_seconds=1.0,
        reload_seconds=None if reload is None else reload.seconds,
        reload_account=reload,
    )


def test_the_record_carries_the_same_clamped_count_the_reconcile_prints() -> None:
    # An account claiming 50 stranded against 6 unconfirmed. The detail says 6, and so must the
    # record, the JSON and the diagnostics table: one count, never two.
    counters = Counters(sent=36, acked=30, timeouts=6, sink_received=36)
    account = runner._ReloadAccount(
        seconds=0.5,
        stranded=50,
        not_reconnected=0,
        extra_hold_s=0.0,
        after=Counters(sent=10, acked=4, timeouts=6),
    )
    rec = _record(counters, account)
    assert rec.reload_stranded == 6
    assert rec.no_loss.detail.startswith("6 send(s) stranded by the reload probe")
    assert rec.to_json_dict()["wall5_reload"] == {
        "seconds": 0.5,
        "stranded": 6,
        "not_reconnected": 0,
        "extra_hold_s": 0.0,
    }


def test_no_reload_probe_records_not_measured_rather_than_zero() -> None:
    # "stranded nothing" is a reading; "the probe did not run" is not. The two must not both be 0.
    rec = _record(Counters(sent=36, acked=36, sink_received=36), None)
    assert rec.reload_stranded is None
    assert rec.reload_not_reconnected is None
    assert rec.post_reload_extra_hold_s is None
    assert rec.to_json_dict()["wall5_reload"]["stranded"] is None


class _Conn:
    def __init__(self, generation: int, up: bool) -> None:
        self.generation = generation
        self.up = up


async def test_a_connection_that_reconnected_and_dropped_again_is_still_behind() -> None:
    # The reload reached this connection late: it opened a new socket, then that socket was closed
    # too. A new generation alone is not "back"; the socket must still be up.
    driver = _real_driver(1)
    driver._conns = [_Conn(2, up=False)]  # type: ignore[list-item]
    assert await driver.await_reconnected([1], timeout=0.05) == 1
    driver._conns = [_Conn(2, up=True)]  # type: ignore[list-item]
    assert await driver.await_reconnected([1], timeout=0.05) == 0
