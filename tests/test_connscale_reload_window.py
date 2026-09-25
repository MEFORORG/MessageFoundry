# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connscale reload probe's accounting window (BACKLOG #1292).

The engine's reload closes every inbound connection, so the probe strands whatever is in flight. On a
loaded windows-2025 runner on 2026-09-25 that was most of a 36-send step, and the no-loss reconcile
reported it as intake loss. ``_reload_mid_hold`` now counts what the reload strands, waits for every
connection to come back, and keeps traffic flowing after it. These tests pin that window:

* only the sends a close strands between the probe firing and every connection returning are
  attributed to the reload -- not those before it, not those after it -- and of those only the ones
  WRITTEN inside the window. A send that had already waited longer than any ACK is a no-ACK fault,
  and the budget judges it (the planted 28-of-36 fault below);
* more hold is offered only when a slow reload left too little of it, or no send, behind;
* the reconnect wait always runs, and scales with N. After a reload that was held or refused it
  waits only for every connection to be UP, since a refusal can follow a rollback that closed them;
* the reconnect wait is real: a connection the engine drops opens a new socket, and one that cannot
  reconnect is reported rather than waited on forever.

ORDERING, NOT WALL CLOCK. The hold's late timeouts wait on the window closing, and the time left in
the hold is set through ``hold_started``, so a stalled event loop on a loaded runner cannot move a
send across the window's edge.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

import pytest

from harness.load.connscale import probe, runner
from harness.load.connscale.driver import ConnScaleDriver
from harness.load.connscale.report import ConnScaleRecord, NoLoss
from harness.load.corpus import Outgoing
from harness.load.correlator import Correlator
from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.metrics import Counters, Histogram, LiveMetrics
from messagefoundry.apiclient.client import ApiError
from messagefoundry.transports.mllp import MLLPDecoder, frame

_HOLD = 0.2  # the probe sleeps half of this before it fires; nothing below races against it


class _FakeDriver:
    """The members ``_reload_mid_hold`` reads, over N fake connection generations."""

    def __init__(self, count: int) -> None:
        self.count = count
        self.gens = [1] * count
        self.waited_with: list[int] | None = None
        self.waited_for: float | None = None
        self.window_closed = asyncio.Event()
        self.emitted_count = 0
        self.slowest_ack_s = 0.0
        self.strand_log: list[int] | None = None
        self.up = [True] * count
        self.required_new: bool | None = None
        self.drops = 0

    def strand(self, send_ns: int) -> None:
        """A close left a send written at ``send_ns`` unconfirmed, as the sender reports it."""
        if self.strand_log is not None:
            self.strand_log.append(send_ns)

    def watch_strands(self) -> None:
        self.strand_log = []

    def end_strand_watch(self) -> list[int]:
        log, self.strand_log = self.strand_log or [], None
        return log

    @property
    def emitted(self) -> int:
        # The probe reads this right after its snapshot, so reading it marks the window closed.
        self.window_closed.set()
        return self.emitted_count

    def generations(self) -> list[int]:
        return list(self.gens)

    async def await_reconnected(
        self, since: list[int], *, timeout: float, require_new: bool = True
    ) -> int:
        self.waited_with = list(since)
        self.waited_for = timeout
        self.required_new = require_new
        return sum(
            1
            for g, s, up in zip(self.gens, since, self.up, strict=True)
            if (require_new and g <= s) or not up
        )


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
    aged: int = 0,
    reply_wait_s: float = 0.0,
) -> tuple[runner._ReloadAccount, list[float]]:
    """Run ``_reload_mid_hold`` with a reload that strands ``strands`` sends.

    ``hold_left_after`` is how much of the hold remains once the connections are back, set by
    placing ``hold_started`` rather than by sleeping. ``emits_after`` sends are offered in that
    remainder, and ``during_hold`` timeouts land in it: the stop-grace or unrelated close that must
    NOT be attributed to the reload. ``aged`` more sends are stranded by the same close, but were
    written ten seconds before it, far past any lookback.

    ``reply_wait_s`` is 0 here: this fake offers sends that no writer ever sends or answers, so the
    real wait would always run out. The wait has its own tests, against a real sender, below.
    """
    extra_holds: list[float] = []

    async def reload() -> tuple[float | None, bool]:
        now = time.perf_counter_ns()
        counters.timeouts += strands + aged
        counters.sent += strands + aged
        for _ in range(strands):
            driver.strand(now)
        for _ in range(aged):
            driver.strand(now - 10_000_000_000)
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
        for _ in range(during_hold):
            driver.strand(time.perf_counter_ns())  # the watch has ended, so this must not count

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
        reply_wait_s=reply_wait_s,
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
    assert account.aged == 0
    assert counters.timeouts == 16  # the control: all three batches really did land
    assert account.after.timeouts == 11  # the snapshot sits between the reload and the late 5


async def test_a_send_the_close_found_already_waiting_too_long_is_not_the_reloads() -> None:
    # The same close strands 7 sends written inside the window and 3 written ten seconds before
    # the request. Only the 7 are excused; the 3 are a no-ACK fault the budget must judge.
    account, _ = await _window(
        counters=Counters(), driver=_FakeDriver(3), strands=7, aged=3, hold_left_after=10.0
    )
    assert account.stranded == 7
    assert account.aged == 3
    assert account.lookback_s <= runner._RELOAD_LOOKBACK_FLOOR_S  # no ACK seen: at most the floor


def test_the_lookback_is_the_slowest_ack_between_its_floor_and_its_two_caps() -> None:
    floor = runner._RELOAD_LOOKBACK_FLOOR_S
    long_hold = 60.0  # the operator profile's hold, so the half-hold cap is 15 s
    assert runner._reload_lookback(0.0, long_hold) == floor  # no ACK recorded yet
    assert runner._reload_lookback(floor / 10, long_hold) == floor  # a fast host
    assert runner._reload_lookback(0.8, long_hold) == 0.8  # a loaded runner: its own slowest ACK
    assert runner._reload_lookback(60.0, long_hold) == runner._STOP_GRACE  # the step's ACK wait
    # The smoke fires at 0.75 s into its hold. One slow ACK of 0.75 s must not reach back to the
    # start of the hold: the window stops at half of it, so the first half is always judged.
    assert runner._reload_lookback(0.75, 0.75) == pytest.approx(0.375)
    assert runner._reload_lookback(0.0, 0.2) == pytest.approx(
        0.1
    )  # the half-hold cap beats the floor


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


async def test_a_reload_that_was_not_applied_waits_only_for_every_connection_to_be_up() -> None:
    # Dual-control held it, or the engine refused it, and no connection dropped. Waiting for a NEW
    # socket would burn the whole timeout and fail the step as "never came back". The wait asks only
    # that every connection be up, which is true at once.
    driver = _FakeDriver(2)
    account, _ = await _window(
        counters=Counters(),
        driver=driver,
        strands=0,
        returns=(None, True),
        reconnect=False,
        hold_left_after=10.0,
    )
    assert driver.required_new is False
    assert account.not_applied
    assert account.not_reconnected == 0


async def test_a_refusal_after_a_rollback_that_left_a_listener_down_is_still_caught() -> None:
    # THE CONTROL for the test above. A 404 or 422 can follow a swap that closed every client and
    # then rolled back; if a listener did not restart, its connection stays down and must count.
    driver = _FakeDriver(3)
    driver.up = [True, False, True]
    account, _ = await _window(
        counters=Counters(),
        driver=driver,
        strands=2,
        returns=(None, True),
        reconnect=False,
        hold_left_after=10.0,
    )
    assert account.not_reconnected == 1
    assert account.stranded == 2  # what the rollback's close stranded is still the reload's


class _RefusingClient:
    def __init__(self, status: int | None) -> None:
        self.status = status

    def reload_config(self, config_dir: str | None) -> object:
        raise ApiError("refused", status=self.status)


@pytest.mark.parametrize("status", [403, 404, 422])
def test_a_refused_reload_was_not_applied(status: int) -> None:
    # Outside the allowed reload roots, not found, does not validate: the reload was not applied.
    assert status in probe.RELOAD_REFUSED_STATUSES
    assert probe.time_reload_outcome(_RefusingClient(status), None) == (None, True)  # type: ignore[arg-type]


@pytest.mark.parametrize("status", [None, 500, 503])
def test_a_reload_that_failed_otherwise_may_have_closed_everything(status: int | None) -> None:
    # THE CONTROL: a timeout (no status) or a server error may have swapped, so it is waited for.
    assert probe.time_reload_outcome(_RefusingClient(status), None) == (None, False)  # type: ignore[arg-type]


def test_a_refused_reload_does_not_fail_the_step() -> None:
    # The CI shape of a refusal: no reading, nothing closed, every connection up, the step's sends
    # all ACKed. It must reconcile, with no reading for wall #5, exactly as before BACKLOG #1292.
    account = runner._ReloadAccount(
        seconds=None,
        stranded=0,
        not_reconnected=0,
        extra_hold_s=0.0,
        after=Counters(sent=18, acked=18),
        not_applied=True,
    )
    rec = _record(Counters(sent=36, acked=36, sink_received=36), account)
    assert rec.no_loss.ok, rec.no_loss.detail
    assert "never came back" not in rec.no_loss.detail
    assert rec.reload_seconds is None
    assert rec.reload_not_reconnected == 0


def test_the_reconnect_wait_scales_with_n_and_with_the_measured_reload() -> None:
    floor = runner._RECONNECT_TIMEOUT
    assert runner._reconnect_timeout(12, 0.5) == floor  # the smoke's quick reload keeps 10 s
    assert runner._reconnect_timeout(500, 0.5) == floor  # where the per-connection term meets it
    assert runner._reconnect_timeout(1000, 0.5) == pytest.approx(20.0)
    assert runner._reconnect_timeout(1500, 0.5) == pytest.approx(30.0)  # the operator rig's top N
    # A measured reload of 4 s at N=12: twice it plus one full reconnect backoff.
    assert runner._reconnect_timeout(12, 4.0) == pytest.approx(13.0)
    assert runner._reconnect_timeout(1500, 4.0) == pytest.approx(30.0)  # N still governs
    # No reading: the request hit its own 5 s timeout, so the reload took at least that. It must not
    # get a shorter wait than the measured 4 s reload above.
    assert runner._reconnect_timeout(12, None) == pytest.approx(15.0)
    assert runner._reconnect_timeout(12, None) > runner._reconnect_timeout(12, 4.0)


async def test_the_probe_waits_the_scaled_timeout() -> None:
    driver = _FakeDriver(1500)
    account, _ = await _window(counters=Counters(), driver=driver, strands=1, hold_left_after=10.0)
    assert driver.waited_for == pytest.approx(30.0)
    assert account.reconnect_timeout_s == driver.waited_for


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
        await server.wait_closed()


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
        "reply_s": None,
        "drops_after": 0,
    }


def test_no_reload_probe_records_not_measured_rather_than_zero() -> None:
    # "stranded nothing" is a reading; "the probe did not run" is not. The two must not both be 0.
    rec = _record(Counters(sent=36, acked=36, sink_received=36), None)
    assert rec.reload_stranded is None
    assert rec.reload_not_reconnected is None
    assert rec.post_reload_extra_hold_s is None
    assert rec.post_reload_reply_s is None
    assert rec.post_reload_drops is None
    assert rec.to_json_dict()["wall5_reload"]["stranded"] is None
    assert rec.to_json_dict()["wall5_reload"] == {
        "seconds": None,
        "stranded": None,
        "not_reconnected": None,
        "extra_hold_s": None,
        "reply_s": None,
        "drops_after": None,
    }


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


async def test_without_require_new_an_old_socket_still_up_counts_as_back() -> None:
    # After a held or refused reload: the old socket, never dropped, is back. A dropped one is not.
    driver = _real_driver(1)
    driver._conns = [_Conn(1, up=True)]  # type: ignore[list-item]
    assert await driver.await_reconnected([1], timeout=0.05) == 1  # the control: default needs new
    assert await driver.await_reconnected([1], timeout=0.05, require_new=False) == 0
    driver._conns = [_Conn(1, up=False)]  # type: ignore[list-item]
    assert await driver.await_reconnected([1], timeout=0.05, require_new=False) == 1


# --- the planted control: a no-ACK fault the reload must not excuse (BACKLOG #1292) ---------------

_ACK = "MSH|^~\\&|ENG|F|H|F|20260925000000||ACK|1|P|2.5\rMSA|AA|1\r"


class _NoAckEngine:
    """An MLLP listener with a no-ACK fault, and a reload that closes every client.

    It reads every frame. It ACKs the first ``ack_first``, then ACKs nothing more on those sockets:
    the engine took the bytes and never answered. ``reload`` closes every client, as the engine's
    reload does, and a socket opened after it is ACKed normally.
    """

    def __init__(self, ack_first: int) -> None:
        self.ack_first = ack_first
        self.read = 0
        self.reloaded = False
        self._writers: list[asyncio.StreamWriter] = []

    async def on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.append(writer)
        healthy = self.reloaded
        decoder = MLLPDecoder()
        try:
            while chunk := await reader.read(65536):
                for _payload in decoder.feed(chunk):
                    self.read += 1
                    if healthy or self.read <= self.ack_first:
                        writer.write(frame(_ACK))
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    def reload(self) -> None:
        self.reloaded = True
        for writer in self._writers:
            writer.close()
        self._writers.clear()


def _outgoing(seq: int) -> Outgoing:
    payload = f"MSH|^~\\&|H|F|ENG|F|20260925000000||ADT^A01|C{seq}|P|2.5\rPID|1||{seq}\r"
    return Outgoing(seq=seq, code="ADT", control_id=f"C{seq}", payload=payload)


async def _no_ack_fault_step(*, unacked_just_before_reload: bool) -> runner.NoLoss:
    """One connection, a 1.2 s hold, the probe at 0.6 s. 2 sends are ACKed, then 28 go unACKed
    until the reload closes the socket, then 6 more after it are ACKed: 28 of 36 unconfirmed, 78%.

    ``unacked_just_before_reload`` places the 28 at 0.55 s, inside the window. Otherwise they go
    out at 0 s with the 2, and have waited 0.6 s for an ACK when the reload fires. The lookback is
    at most half of that 0.6 s whatever the ACKs took, so they are outside the window.
    """
    engine = _NoAckEngine(ack_first=2)
    server = await asyncio.start_server(engine.on_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    driver = _real_driver(port)
    counters = driver._m.counters
    loop = asyncio.get_running_loop()
    hold = 1.2
    try:
        await driver.open(connect_batch=1, batch_pause_s=0.0)
        while driver.generations()[0] < 1:
            await asyncio.sleep(0.01)
        started = loop.time()

        async def run_hold() -> None:
            for seq in range(2):
                driver._emit_one(_outgoing(seq))
            if unacked_just_before_reload:
                await asyncio.sleep(max(0.0, started + 0.55 - loop.time()))
            for seq in range(2, 30):
                driver._emit_one(_outgoing(seq))
            await asyncio.sleep(max(0.0, started + hold - loop.time()))

        async def reload() -> tuple[float | None, bool]:
            # ORDERING, NOT WALL CLOCK: close only once the engine has read all 30 frames, so the 28
            # are in flight on the old socket whatever a loaded runner does to the two timers.
            deadline = loop.time() + 5.0
            while engine.read < 30 and loop.time() < deadline:
                await asyncio.sleep(0.005)
            engine.reload()
            return 0.01, False

        async def after_reload(seconds: float) -> None:
            for seq in range(30, 36):
                driver._emit_one(_outgoing(seq))
            deadline = loop.time() + 5.0
            while counters.acked + counters.nak < 8 and loop.time() < deadline:
                await asyncio.sleep(0.01)

        hold_task = asyncio.create_task(run_hold())
        account = await runner._reload_mid_hold(
            driver=driver,
            counters=counters,
            reload=reload,
            run_hold=after_reload,
            hold_task=hold_task,
            hold_seconds=hold,
            hold_started=started,
        )
    finally:
        await driver.stop(0.5)
        server.close()
        await server.wait_closed()
    # The control on the fault itself: the shape really is 28 of 36 unconfirmed.
    assert (counters.sent, counters.acked, counters.timeouts) == (36, 8, 28), counters
    counters.sink_received = engine.read  # every read frame delivered: only the ACKs are missing
    return runner._reconcile(
        counters,
        _engine_sample(0),
        _engine_sample(engine.read),
        unconfirmed_budget=1,
        reload=account,
    )


async def test_a_no_ack_fault_before_the_reload_is_not_excused_as_its_stranding() -> None:
    # PLANTED CONTROL. At a6a6d7586 the excusal counted every timeout the close produced, so these
    # 28 sends, unACKed for 0.6 s before the reload fired, were excused and the step PASSED.
    # SCOPE: the budget still forgives up to three quarters of the sends it judges, so the window
    # changes the verdict only where the aged sends pass that line. 28 of 36 is one over it. The
    # third assertion pins the window's own classification, which does not depend on the budget.
    result = await _no_ack_fault_step(unacked_just_before_reload=False)
    assert not result.ok, result.detail
    assert "28 unconfirmed sends exceed the stranding budget" in result.detail
    assert "28 send(s) the reload's close found already waiting" in result.detail


async def test_the_same_sends_made_just_before_the_reload_are_excused() -> None:
    # THE OTHER HALF: the same 28 sends, written 50 ms before the request, are what the reload
    # strands on a healthy engine. They are excused, so the window is what separates the two.
    result = await _no_ack_fault_step(unacked_just_before_reload=True)
    assert result.ok, result.detail
    assert "28 send(s) stranded by the reload probe" in result.detail


# --- after the reload: a slow engine is waited for, a silent one still fails (BACKLOG #1292) -------
#
# Merge-group run 36166728739 (windows-2025, 2026-09-25) failed N=24 on "9 send(s) after the reload
# probe drew no reply". The post-mortem audit found a stored row for all 45 sends: the engine had
# read and committed every post-reload frame, and no reply reached the sender inside the 5 s stop
# grace. The probe now waits for the first post-reload reply before the step stops, and counts the
# engine's closes over that wait. These pin both halves with a real sender on a real socket.


class _AfterReloadEngine:
    """An MLLP listener that ACKs at once until ``reload``, which closes every client. On a socket
    opened after it, ``mode`` decides what the engine does with each frame it reads:

    * ``slow``: ACKs it after ``delay`` seconds, one frame at a time -- a loaded engine;
    * ``silent``: never ACKs, and keeps the socket open -- an engine that stopped answering;
    * ``close``: closes the socket without an ACK -- a second close that takes the reply.
    """

    def __init__(self, mode: str, *, delay: float = 0.0) -> None:
        self.mode = mode
        self.delay = delay
        self.read = 0
        self.reloaded = False
        self._writers: list[asyncio.StreamWriter] = []

    async def on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.append(writer)
        after = self.reloaded
        decoder = MLLPDecoder()
        try:
            while chunk := await reader.read(65536):
                for _payload in decoder.feed(chunk):
                    self.read += 1
                    if not after:
                        writer.write(frame(_ACK))
                    elif self.mode == "slow":
                        await asyncio.sleep(self.delay)
                        writer.write(frame(_ACK))
                    elif self.mode == "close":
                        return
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    def reload(self) -> None:
        self.reloaded = True
        for writer in self._writers:
            writer.close()
        self._writers.clear()


async def _post_reload_step(
    engine: _AfterReloadEngine, *, reply_wait_s: float
) -> tuple[runner._ReloadAccount, NoLoss]:
    """One connection: 2 sends ACKed before the reload, the reload closes the socket, and 3 sends go
    out on the new one. The step then stops with a 0.05 s grace, far shorter than the slow engine's
    delay, so only the probe's own wait can see a slow reply."""
    server = await asyncio.start_server(engine.on_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    driver = _real_driver(port)
    counters = driver._m.counters
    loop = asyncio.get_running_loop()
    hold = 0.4
    try:
        await driver.open(connect_batch=1, batch_pause_s=0.0)
        while driver.generations()[0] < 1:
            await asyncio.sleep(0.01)
        started = loop.time()

        async def run_hold() -> None:
            for seq in range(2):
                driver._emit_one(_outgoing(seq))
            await asyncio.sleep(max(0.0, started + hold - loop.time()))

        async def reload() -> tuple[float | None, bool]:
            # ORDERING: close only once both pre-reload sends are ACKed, so nothing is stranded.
            deadline = loop.time() + 5.0
            while counters.acked < 2 and loop.time() < deadline:
                await asyncio.sleep(0.005)
            engine.reload()
            return 0.01, False

        async def after_reload(seconds: float) -> None:
            for seq in range(2, 5):
                driver._emit_one(_outgoing(seq))

        hold_task = asyncio.create_task(run_hold())
        account = await runner._reload_mid_hold(
            driver=driver,
            counters=counters,
            reload=reload,
            run_hold=after_reload,
            hold_task=hold_task,
            hold_seconds=hold,
            hold_started=started,
            reply_wait_s=reply_wait_s,
        )
    finally:
        await driver.stop(0.05)
        server.close()
        await server.wait_closed()
    # The control on the shape itself: 5 written, the 2 before the reload ACKed, none stranded.
    assert counters.sent == 5, counters
    assert account.stranded == 0 and account.not_reconnected == 0, account
    counters.sink_received = engine.read  # every read frame delivered: only replies can be missing
    return account, runner._reconcile(
        counters,
        _engine_sample(0),
        _engine_sample(engine.read),
        unconfirmed_budget=1,
        reload=account,
    )


async def test_a_slow_engine_after_the_reload_is_waited_for() -> None:
    # The CI shape: every post-reload frame is read, and the reply comes later than the stop grace.
    # The probe waits for it, so the step passes and records how long the engine took.
    account, result = await _post_reload_step(
        _AfterReloadEngine("slow", delay=0.5), reply_wait_s=5.0
    )
    assert result.ok, result.detail
    assert account.reply_s is not None and account.reply_s >= 0.5, account
    assert account.drops_after == 0


async def test_the_same_slow_engine_fails_without_the_wait() -> None:
    # THE CONTROL for the test above, and the 2026-09-25 failure reproduced: the same engine judged
    # at the stop grace alone reads as one that never answered.
    account, result = await _post_reload_step(
        _AfterReloadEngine("slow", delay=0.5), reply_wait_s=0.0
    )
    assert not result.ok
    assert "drew no reply" in result.detail
    assert account.reply_s is None


async def test_an_engine_silent_after_the_reload_still_fails() -> None:
    # PLANTED FAULT. The engine reads every post-reload frame and never answers. The wait runs out,
    # and the step fails and says it held its sockets open.
    account, result = await _post_reload_step(_AfterReloadEngine("silent"), reply_wait_s=0.3)
    assert not result.ok
    assert "drew no reply at all (no ACK, no NAK) in 0.3s of waiting" in result.detail
    assert "the engine closed no socket after every connection was back" in result.detail
    assert account.reply_s is None
    assert account.drops_after == 0


async def test_a_second_close_after_the_reload_is_named() -> None:
    # PLANTED FAULT. The engine closes each post-reload socket on its first frame, so the replies go
    # with it. The step fails, and names the closes rather than calling the engine silent.
    account, result = await _post_reload_step(_AfterReloadEngine("close"), reply_wait_s=0.3)
    assert not result.ok
    assert "drew no reply" in result.detail
    assert account.drops_after >= 1, account
    assert f"the engine closed {account.drops_after} socket(s)" in result.detail


async def _reply_wait(
    counters: Counters, *, offered: bool, timeout: float
) -> tuple[float | None, float]:
    """Run the probe's reply wait from a snapshot of ``counters``; return its reading and how long
    it took."""
    loop = asyncio.get_running_loop()
    began = loop.time()
    after = counters.snapshot()
    watcher = asyncio.create_task(runner._first_reply_after(counters, after, began))
    try:
        got = await runner._await_post_reload_reply(
            watcher, counters, after, offered=lambda: offered, timeout=timeout
        )
    finally:
        watcher.cancel()
    return got, loop.time() - began


async def test_the_reply_wait_returns_at_once_when_nothing_was_offered() -> None:
    # A zero-rate lane offers nothing after the reload. There is no reply to wait for, so a long
    # timeout must not be spent; the reconcile's "nothing was sent" guard judges that step.
    got, took = await _reply_wait(Counters(), offered=False, timeout=30.0)
    assert got is None
    assert took < 1.0


async def test_the_reply_wait_waits_for_a_send_still_queued() -> None:
    # THE CONTROL for the test above: offered but not yet written is still waited for, until the
    # timeout, so a writer that is merely behind does not end the wait early.
    got, took = await _reply_wait(Counters(), offered=True, timeout=0.2)
    assert got is None
    assert took >= 0.2


async def test_the_reply_wait_times_the_first_reply_from_the_snapshot() -> None:
    # The reading is when the reply came, not when the wait began: a reply counted 0.15 s after the
    # snapshot reads as about 0.15 s, however long the wait was allowed to run.
    counters = Counters(sent=1)

    async def answer() -> None:
        await asyncio.sleep(0.15)
        counters.acked += 1

    task = asyncio.create_task(answer())
    got, _ = await _reply_wait(counters, offered=True, timeout=5.0)
    await task
    assert got is not None
    assert 0.15 <= got < 1.0


async def test_the_runner_waits_the_shipped_reply_wait_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The runner's own call passes no wait, so the constant is what CI gets. Pin that wiring: with no
    # argument the probe allows `_POST_RELOAD_REPLY_WAIT_S`, here shrunk so the fake's unanswered
    # send runs it out quickly.
    monkeypatch.setattr(runner, "_POST_RELOAD_REPLY_WAIT_S", 0.05)
    driver = _FakeDriver(1)
    counters = Counters()
    hold_task = asyncio.create_task(_emit_after_snapshot(driver))
    account = await runner._reload_mid_hold(
        driver=driver,  # type: ignore[arg-type]
        counters=counters,
        reload=_reconnecting_reload(driver),
        run_hold=_no_extra_hold,
        hold_task=hold_task,
        hold_seconds=_HOLD,
        hold_started=asyncio.get_running_loop().time(),
    )
    assert account.reply_wait_s == 0.05
    assert account.reply_s is None


def test_the_shipped_reply_wait_fits_the_smokes_module_timeout() -> None:
    # The constant's own comment sizes it: the fixture's setup took 40.8 s on the failing runner, and
    # four steps each waiting in full must still finish inside the module's 120 s timeout.
    assert 40.8 + 4 * runner._POST_RELOAD_REPLY_WAIT_S < 120.0
    assert runner._POST_RELOAD_REPLY_WAIT_S > runner._STOP_GRACE  # it must add to the grace


async def _emit_after_snapshot(driver: _FakeDriver) -> None:
    await driver.window_closed.wait()
    driver.emitted_count += 1  # offered after every connection was back, never written or answered


def _reconnecting_reload(
    driver: _FakeDriver,
) -> Callable[[], Awaitable[tuple[float | None, bool]]]:
    async def reload() -> tuple[float | None, bool]:
        driver.gens = [g + 1 for g in driver.gens]
        return 0.01, False

    return reload


async def _no_extra_hold(seconds: float) -> None:
    return None
