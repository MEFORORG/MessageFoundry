# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Timer / scheduled source (ADR 0011).

A timer reads no external resource — it fires a configured ``body`` on a schedule and hands it to the
pipeline handler. These tests cover the firing cadence (interval + run_once), the leader-gate
(``polls_shared_resource``), at-least-once on a failing fire, cooperative stop, encoding, settings
validation, and the ``Timer(...)`` factory / wiring.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Source
from messagefoundry.config.wiring import Timer, build_inbound_connection
from messagefoundry.transports import build_source
from messagefoundry.transports.timer import TimerSource, _CronSchedule


class _FastCron:
    """A stand-in schedule whose next fire is always ~20 ms out, so the cron loop can be exercised
    end-to-end in a test without waiting a real wall-clock minute."""

    def next_after(self, dt: datetime) -> datetime:
        return dt + timedelta(milliseconds=20)


def _timer(**settings: object) -> TimerSource:
    src = build_source(Source(type=ConnectorType.TIMER, settings=dict(settings)))
    assert isinstance(src, TimerSource)  # registry resolved a TIMER source
    return src


# --- firing cadence ----------------------------------------------------------


async def test_timer_source_declares_polls_shared_resource() -> None:
    # A schedule is a shared trigger — the runner reads this flag to know intake is leader-gated
    # (only the cluster leader fires it, else every node would emit the message).
    assert TimerSource.polls_shared_resource is True


async def test_timer_interval_fires_repeatedly() -> None:
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="MSH|^~\\&|TIMER\r", interval_seconds=0.01)
    await src.start(handler)  # no gate → single-node path, fires every tick
    try:
        await _until(lambda: len(fired) >= 3)
    finally:
        await src.stop()
    assert len(fired) >= 3
    assert fired[0] == b"MSH|^~\\&|TIMER\r"  # body emitted verbatim, first fire at t=0


async def test_timer_run_once_fires_exactly_once() -> None:
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="PING", run_once=True)
    await src.start(handler)
    try:
        await _until(lambda: len(fired) == 1)
        await asyncio.sleep(0.05)  # idles after firing — no second emission
    finally:
        await src.stop()
    assert len(fired) == 1


async def test_timer_run_once_restart_fires_again() -> None:
    # "Once per leadership term", not once-ever: start() re-arms (resets _fired), so a stop->start
    # cycle fires again. (The engine builds a fresh source per start/reload, so this reset is
    # defensive idempotency — but it pins the documented contract against an accidental refactor.)
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="PING", run_once=True)
    await src.start(handler)
    await _until(lambda: len(fired) == 1)
    await src.stop()
    await src.start(handler)  # restart → re-arms and fires once more
    await _until(lambda: len(fired) == 2)
    await src.stop()
    assert len(fired) == 2


async def test_timer_body_honors_encoding() -> None:
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="PID|café", interval_seconds=0.01, encoding="latin-1")
    await src.start(handler)
    try:
        await _until(lambda: bool(fired))
    finally:
        await src.stop()
    assert fired[0] == "PID|café".encode("latin-1")


# --- at-least-once on a failing fire -----------------------------------------


async def test_timer_handler_failure_keeps_firing() -> None:
    # A fire that raises is an infrastructure error (the durable ingress write failed) — it must NOT
    # kill the source; the loop logs and retries on the next tick.
    attempts = {"n": 0}

    async def handler(raw: bytes) -> None:
        attempts["n"] += 1
        raise RuntimeError("store unavailable")  # never recovers

    src = _timer(body="X", interval_seconds=0.01)
    await src.start(handler)
    try:
        await _until(
            lambda: attempts["n"] >= 3
        )  # retried across multiple ticks, source still alive
    finally:
        await src.stop()
    assert attempts["n"] >= 3


async def test_timer_run_once_retries_until_it_lands() -> None:
    # run_once whose first fire fails must retry the next tick, then fire exactly once (at-least-once).
    calls = {"n": 0}
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("store down")  # first fire fails
        fired.append(raw)

    src = _timer(body="X", interval_seconds=0.01, run_once=True)
    await src.start(handler)
    try:
        await _until(lambda: len(fired) == 1)
        await asyncio.sleep(0.05)  # then idles — no further fires
    finally:
        await src.stop()
    assert len(fired) == 1
    assert calls["n"] == 2  # first failed, second landed


# --- leader-gating (Track B Step 4b) -----------------------------------------


async def test_timer_skips_fire_when_gate_false() -> None:
    # A follower (leader_gate() -> False) must NOT fire across many ticks: the schedule is shared, so a
    # non-leader emitting would duplicate the message.
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="X", interval_seconds=0.01)
    await src.start(handler, leader_gate=lambda: False)
    try:
        await asyncio.sleep(0.1)  # several tick intervals
        assert fired == []  # never fired
    finally:
        await src.stop()


async def test_timer_fires_when_gate_true() -> None:
    # A leader (leader_gate() -> True) fires exactly as the un-gated default does.
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="X", interval_seconds=0.01)
    await src.start(handler, leader_gate=lambda: True)
    try:
        await _until(lambda: bool(fired))
    finally:
        await src.stop()
    assert fired


async def test_timer_resumes_when_gate_flips_to_true() -> None:
    # Reactive-by-polling: a follower fires nothing; once the gate flips True (this node became leader)
    # the next tick fires — no restart needed.
    fired: list[bytes] = []
    leader = {"on": False}

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="X", interval_seconds=0.01)
    await src.start(handler, leader_gate=lambda: leader["on"])
    try:
        await asyncio.sleep(0.05)
        assert fired == []  # still a follower
        leader["on"] = True  # this node wins leadership
        await _until(lambda: bool(fired))  # the next tick fires
    finally:
        await src.stop()
    assert fired


# --- cooperative stop --------------------------------------------------------


async def test_timer_stop_joins_promptly() -> None:
    async def handler(raw: bytes) -> None:
        return None

    src = _timer(body="X", interval_seconds=0.01)
    await src.start(handler)
    await _until(lambda: src._task is not None)
    await asyncio.wait_for(src.stop(), timeout=2.0)  # must not hang on the firing loop
    assert src._task is None


# --- settings validation -----------------------------------------------------


def test_timer_requires_body() -> None:
    with pytest.raises(ValueError, match="requires a 'body'"):
        TimerSource(Source(type=ConnectorType.TIMER, settings={"interval_seconds": 1}))


def test_timer_requires_a_schedule() -> None:
    with pytest.raises(ValueError, match="interval_seconds.*run_once"):
        TimerSource(Source(type=ConnectorType.TIMER, settings={"body": "X"}))


def test_timer_rejects_nonpositive_interval() -> None:
    with pytest.raises(ValueError, match="must be > 0"):
        TimerSource(Source(type=ConnectorType.TIMER, settings={"body": "X", "interval_seconds": 0}))


# --- cron / calendar schedule (ADR 0011 amendment, BACKLOG #160) --------------


def test_cron_next_after_is_strictly_future_never_t0() -> None:
    # Unlike the interval heartbeat, cron does NOT fire at t=0: next_after is always strictly after the
    # given time (so a fire is never scheduled "now" or in the past — no busy-loop).
    sched = _CronSchedule.parse("* * * * *")  # every minute
    base = datetime(2026, 7, 17, 10, 30, 15)
    assert sched.next_after(base) == datetime(2026, 7, 17, 10, 31, 0)
    # On an exact minute boundary it advances to the NEXT minute (never re-fires the same minute).
    assert sched.next_after(datetime(2026, 7, 17, 10, 31, 0)) == datetime(2026, 7, 17, 10, 32, 0)


def test_cron_calendar_schedule() -> None:
    # 08:00 on weekdays. From Fri 2026-07-17 the next fire is Mon 2026-07-20 08:00.
    sched = _CronSchedule.parse("0 8 * * 1-5")
    assert sched.next_after(datetime(2026, 7, 17, 10, 0, 0)) == datetime(2026, 7, 20, 8, 0, 0)


def test_cron_step_and_list_and_range() -> None:
    assert _CronSchedule.parse("*/15 * * * *").next_after(datetime(2026, 7, 17, 10, 7)) == datetime(
        2026, 7, 17, 10, 15
    )
    sched = _CronSchedule.parse("0,30 9-17 * * *")  # top & half hour, 9am-5pm
    assert sched.matches(datetime(2026, 7, 17, 9, 30))
    assert sched.matches(datetime(2026, 7, 17, 17, 0))
    assert not sched.matches(datetime(2026, 7, 17, 18, 0))
    assert not sched.matches(datetime(2026, 7, 17, 9, 15))


def test_cron_dom_dow_or_semantics() -> None:
    # Vixie rule: when BOTH day-of-month and day-of-week are restricted, a match on EITHER fires.
    sched = _CronSchedule.parse("0 0 1 * 1")  # midnight on the 1st OR any Monday
    assert sched.matches(datetime(2026, 7, 1, 0, 0))  # the 1st (a Wednesday)
    assert sched.matches(datetime(2026, 7, 6, 0, 0))  # a Monday (not the 1st) → OR fires
    assert not sched.matches(datetime(2026, 7, 7, 0, 0))  # neither


def test_cron_sunday_is_zero_or_seven() -> None:
    zero = _CronSchedule.parse("0 0 * * 0")  # Sunday = 0
    seven = _CronSchedule.parse("0 0 * * 7")  # Sunday = 7 (accepted)
    sunday = datetime(2026, 7, 19, 0, 0)  # a Sunday
    assert zero.matches(sunday)
    assert seven.matches(sunday)


def test_cron_next_after_is_dst_aware() -> None:
    # With an explicit IANA zone the schedule is DST-aware: the same wall-clock cron resolves to a
    # different UTC offset in winter (EST -05:00) vs summer (EDT -04:00).
    ny = ZoneInfo("America/New_York")
    sched = _CronSchedule.parse("0 12 * * *")  # noon daily
    winter = sched.next_after(datetime(2026, 1, 15, 0, 0, tzinfo=ny))
    summer = sched.next_after(datetime(2026, 7, 15, 0, 0, tzinfo=ny))
    assert winter.utcoffset() == timedelta(hours=-5)
    assert summer.utcoffset() == timedelta(hours=-4)


def test_cron_rejects_unsatisfiable_expression() -> None:
    with pytest.raises(ValueError, match="no fire time|unsatisfiable"):
        _CronSchedule.parse("* * 30 2 *")  # Feb 30 never exists


@pytest.mark.parametrize(
    "bad",
    ["* * * *", "* * * * * *", "61 * * * *", "* 24 * * *", "* * * * 8", "x * * * *", "*/0 * * * *"],
)
def test_cron_rejects_invalid_fields(bad: str) -> None:
    with pytest.raises(ValueError):
        _CronSchedule.parse(bad)


def test_timer_cron_exclusive_with_interval() -> None:
    with pytest.raises(ValueError, match="exclusive"):
        TimerSource(
            Source(
                type=ConnectorType.TIMER,
                settings={"body": "X", "cron_expression": "* * * * *", "interval_seconds": 5},
            )
        )


def test_timer_cron_exclusive_with_run_once() -> None:
    with pytest.raises(ValueError, match="exclusive"):
        TimerSource(
            Source(
                type=ConnectorType.TIMER,
                settings={"body": "X", "cron_expression": "* * * * *", "run_once": True},
            )
        )


def test_timer_rejects_unknown_timezone() -> None:
    with pytest.raises(ValueError, match="IANA zone"):
        TimerSource(
            Source(
                type=ConnectorType.TIMER,
                settings={"body": "X", "cron_expression": "0 8 * * *", "timezone": "Nowhere/Bad"},
            )
        )


def test_timer_timezone_requires_cron() -> None:
    with pytest.raises(ValueError, match="only applies"):
        TimerSource(
            Source(
                type=ConnectorType.TIMER,
                settings={"body": "X", "interval_seconds": 5, "timezone": "America/New_York"},
            )
        )


def test_cron_next_fire_is_always_strictly_future() -> None:
    """The actual invariant, asserted purely: ``next_after`` never returns its own input.

    This is what "a cron does not fire at t=0" MEANS, and it needs no clock and no sleeping. The
    boundary offsets are the point — at :59.999 the next fire is a millisecond away, and that is
    correct behaviour, not a bug to sleep through.
    """
    sched = _CronSchedule.parse("* * * * *")
    base = datetime(2026, 7, 27, 12, 0)
    for offset in (0.0, 0.001, 1.0, 30.0, 59.0, 59.999):
        t = base + timedelta(seconds=offset)
        nxt = sched.next_after(t)
        assert nxt > t, f"next_after({t}) must be strictly future, got {nxt}"
        assert (nxt.second, nxt.microsecond) == (0, 0), (
            f"a minute cron fires on the minute, got {nxt}"
        )


async def test_timer_cron_does_not_fire_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    """The running loop must not fire at t=0 either — on a clock ANCHORED mid-minute.

    This used to start a real ``* * * * *`` source, sleep 0.1s, and assert nothing had fired. That is
    only reliable mid-minute: a minute cron fires ON the minute, so a run beginning within 100ms of the
    boundary saw a fire that was entirely CORRECT and the test failed for being right — ~0.17% per run
    per leg (a 0.1s window out of every 60s). It duly red-X'd a comments-only PR. Its own comment gave
    it away: "its next fire is up to ~60s away". Up to. It can also be 50ms away.

    THE CLOCK ADVANCES; ONLY ITS ORIGIN IS PINNED. A frozen clock was tried first and is WRONG: with
    ``_now()`` constant, ``remaining`` never decreases, so ``_run_cron`` waits forever and cannot fire
    at ANY pinned time — including :59.95, where firing is exactly what should happen. That version was
    deterministic because it could not fail, which is worse than the flake it replaced. Anchoring the
    origin at :30 and letting it advance in real time keeps the failure mode reachable (the sibling test
    below pins that) while removing the dependence on where the wall clock happened to be.

    The source is naive-clocked here (no ``timezone`` setting), so a naive datetime is the right shape.
    """
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="X", cron_expression="* * * * *")
    origin, t0 = datetime(2026, 7, 27, 12, 0, 30), time.monotonic()  # :30 — 30s short of a fire
    monkeypatch.setattr(
        type(src), "_now", lambda _self: origin + timedelta(seconds=time.monotonic() - t0)
    )
    await src.start(handler)
    try:
        await asyncio.sleep(0.1)
        assert fired == []  # never fires at t=0
    finally:
        await src.stop()


async def test_the_cron_no_fire_probe_can_actually_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guards the guard: anchored just BEFORE a fire, the same setup must fire.

    Without this, the test above passes whether the loop is correct, broken, or wedged — and the first
    attempt at fixing it (a frozen clock) was exactly that: unfalsifiable. Anchoring at :59.90 puts a
    scheduled fire 100ms out, inside the window, so a fire is the CORRECT outcome and its absence means
    the probe has stopped observing anything.
    """
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="X", cron_expression="* * * * *")
    origin, t0 = datetime(2026, 7, 27, 12, 0, 59, 900_000), time.monotonic()
    monkeypatch.setattr(
        type(src), "_now", lambda _self: origin + timedelta(seconds=time.monotonic() - t0)
    )
    await src.start(handler)
    try:
        await asyncio.sleep(0.6)  # generous: the fire is ~100ms in, the slack absorbs a slow runner
        assert fired, "the no-fire probe above cannot fail — it would pass on a wedged loop too"
    finally:
        await src.stop()


async def test_timer_cron_fires_when_due() -> None:
    # Exercise the cron loop end-to-end without waiting a real minute by injecting a fast schedule.
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="TICK", cron_expression="* * * * *")
    src._cron = _FastCron()  # next fire is always ~20 ms out
    await src.start(handler)
    try:
        await _until(lambda: len(fired) >= 2)
    finally:
        await src.stop()
    assert fired[0] == b"TICK"


async def test_timer_cron_respects_leader_gate() -> None:
    # A follower advances the schedule without emitting (the fire is leader-gated like the interval path).
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    src = _timer(body="X", cron_expression="* * * * *")
    src._cron = _FastCron()
    await src.start(handler, leader_gate=lambda: False)
    try:
        await asyncio.sleep(0.15)  # many fast ticks
        assert fired == []  # never fired as a follower
    finally:
        await src.stop()


async def test_timer_cron_stop_joins_promptly() -> None:
    async def handler(raw: bytes) -> None:
        return None

    src = _timer(body="X", cron_expression="* * * * *")
    src._cron = _FastCron()
    await src.start(handler)
    await _until(lambda: src._task is not None)
    await asyncio.wait_for(src.stop(), timeout=2.0)
    assert src._task is None


def test_timer_cron_factory_wiring() -> None:
    spec = Timer(body="PING", cron_expression="0 8 * * 1-5", timezone="America/New_York")
    assert spec.settings["cron_expression"] == "0 8 * * 1-5"
    assert spec.settings["timezone"] == "America/New_York"


# --- factory + wiring --------------------------------------------------------


def test_timer_factory_builds_connection_spec() -> None:
    spec = Timer(body="PING", interval_seconds=5.0)
    assert spec.type is ConnectorType.TIMER
    assert spec.settings["body"] == "PING"
    assert spec.settings["interval_seconds"] == 5.0
    assert spec.settings["run_once"] is False
    assert spec.settings["encoding"] == "utf-8"


def test_build_source_returns_timer_source() -> None:
    src = build_source(Source(type=ConnectorType.TIMER, settings={"body": "X", "run_once": True}))
    assert isinstance(src, TimerSource)


def test_timer_inbound_wiring_accepts_text_content_type() -> None:
    # A timer emitting a non-HL7 body declares its format on inbound(); the connector never forces it.
    ic = build_inbound_connection(
        "IB_TIMER_HB",
        Timer(body="ping", interval_seconds=30.0),
        router="r",
        content_type=ContentType.TEXT,
    )
    assert ic.spec.type is ConnectorType.TIMER
    assert ic.content_type is ContentType.TEXT
    assert ic.router == "r"


# --- helpers -----------------------------------------------------------------


async def _until(cond, timeout: float = 2.0) -> None:
    """Poll ``cond`` until true or timeout (avoids fixed sleeps in async tests)."""
    elapsed = 0.0
    while not cond():
        await asyncio.sleep(0.01)
        elapsed += 0.01
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")
