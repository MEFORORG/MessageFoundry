# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connscale reload probe's accounting window (BACKLOG #1292).

The engine's reload closes every inbound connection, so the probe strands whatever is in flight. On a
loaded windows-2025 runner on 2026-09-25 that was most of a 36-send step, and the no-loss reconcile
reported it as intake loss. ``_reload_mid_hold`` now counts what the reload strands, waits for every
connection to come back, and keeps traffic flowing after it. These tests pin that window:

* only the ``timeouts`` that move between the probe firing and every connection returning are
  attributed to the reload -- not those before it, not those after it;
* the hold is extended only when a slow reload left too little of it behind;
* the reconnect wait is real: a connection the engine drops opens a new socket, and one that cannot
  reconnect is reported rather than waited on forever.
"""

from __future__ import annotations

import asyncio

from harness.load.connscale import runner
from harness.load.connscale.driver import ConnScaleDriver
from harness.load.correlator import Correlator
from harness.load.metrics import Counters, Histogram, LiveMetrics


class _FakeDriver:
    """Just the two methods ``_reload_mid_hold`` reads, over N fake connection generations."""

    def __init__(self, count: int) -> None:
        self.gens = [1] * count
        self.waited_with: list[int] | None = None

    def generations(self) -> list[int]:
        return list(self.gens)

    async def await_reconnected(self, since: list[int], *, timeout: float) -> int:
        self.waited_with = list(since)
        return sum(1 for g, s in zip(self.gens, since, strict=True) if g <= s)


async def _window(
    *,
    counters: Counters,
    driver: _FakeDriver,
    reload_s: float,
    strands: int,
    returns: float | None = 0.01,
    reconnect: bool = True,
    hold_seconds: float = 0.4,
    during_hold: int = 0,
) -> tuple[runner._ReloadAccount, list[float]]:
    """Run ``_reload_mid_hold`` with a reload that takes ``reload_s`` and strands ``strands`` sends.

    ``during_hold`` more timeouts land AFTER the window closes but before the hold ends, which is
    what a stop-grace or an unrelated close would look like. They must not be attributed.
    """
    extra_holds: list[float] = []

    async def reload() -> float | None:
        await asyncio.sleep(reload_s)
        counters.timeouts += strands
        counters.sent += strands
        if reconnect:
            driver.gens = [g + 1 for g in driver.gens]
        return returns

    async def run_hold(seconds: float) -> None:
        extra_holds.append(seconds)

    async def hold() -> None:
        await asyncio.sleep(hold_seconds)
        counters.timeouts += during_hold

    loop = asyncio.get_running_loop()
    started = loop.time()
    hold_task = asyncio.create_task(hold())
    account = await runner._reload_mid_hold(
        driver=driver,  # type: ignore[arg-type]
        counters=counters,
        reload=reload,
        run_hold=run_hold,
        hold_task=hold_task,
        hold_seconds=hold_seconds,
        hold_started=started,
    )
    return account, extra_holds


async def test_only_the_timeouts_inside_the_window_are_the_reloads() -> None:
    # 4 timeouts before the probe fired, 7 stranded by the reload, 5 after every connection was back.
    # Only the 7 are the reload's.
    counters = Counters(sent=10, timeouts=4)
    account, _ = await _window(
        counters=counters, driver=_FakeDriver(3), reload_s=0.01, strands=7, during_hold=5
    )
    assert account.stranded == 7
    assert counters.timeouts == 16  # the control: all three batches really did land
    assert account.after.timeouts == 11  # the snapshot sits between the reload and the late 5


async def test_a_quick_reload_adds_no_hold() -> None:
    # The probe fires at half the hold; a reload of 0.01 s leaves about 0.19 s of a 0.4 s hold, more
    # than the quarter-hold floor of 0.1 s, so nothing is added.
    account, extra = await _window(
        counters=Counters(), driver=_FakeDriver(2), reload_s=0.01, strands=1
    )
    assert extra == []
    assert account.extra_hold_s == 0.0
    assert account.not_reconnected == 0


async def test_a_slow_reload_is_followed_by_traffic() -> None:
    # A reload that outlasts the hold leaves no offered time after the connections come back, so a
    # quarter hold is added. This is the step shape CI produced with nothing after the reload.
    account, extra = await _window(
        counters=Counters(), driver=_FakeDriver(2), reload_s=0.5, strands=5
    )
    assert extra == [account.extra_hold_s]
    assert abs(account.extra_hold_s - 0.4 * runner._POST_RELOAD_HOLD_FRACTION) < 1e-9


async def test_connections_that_never_came_back_are_counted() -> None:
    driver = _FakeDriver(4)
    account, _ = await _window(
        counters=Counters(), driver=driver, reload_s=0.01, strands=2, reconnect=False
    )
    assert driver.waited_with == [1, 1, 1, 1]
    assert account.not_reconnected == 4


async def test_no_reading_means_no_reconnect_wait() -> None:
    # A reload that returned no reading may not have swapped, so nothing need have dropped. Waiting
    # would spend the whole timeout on connections that are still up.
    driver = _FakeDriver(2)
    account, _ = await _window(
        counters=Counters(), driver=driver, reload_s=0.01, strands=0, returns=None
    )
    assert driver.waited_with is None
    assert account.seconds is None
    assert account.not_reconnected == 0


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
    # does. The generation moves, so the wait returns 0 well inside its timeout.
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
