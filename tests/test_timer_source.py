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

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Source
from messagefoundry.config.wiring import Timer, build_inbound_connection
from messagefoundry.transports import build_source
from messagefoundry.transports.timer import TimerSource


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
    assert fired[0] == "MSH|^~\\&|TIMER\r".encode()  # body emitted verbatim, first fire at t=0


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


def test_timer_cron_is_not_yet_implemented() -> None:
    with pytest.raises(ValueError, match="cron_expression' is not yet implemented"):
        TimerSource(
            Source(type=ConnectorType.TIMER, settings={"body": "X", "cron_expression": "* * * * *"})
        )


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
