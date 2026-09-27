# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 2.4.1 / 15.2.2 — message-rate pacing on the inbound MLLP data plane.

The engine had no bound on messages per second from an accepted peer in any configuration, so a
sender able to reach the NIC-bound data plane could submit unbounded messages, each durably
persisted before its ACK.

**The control had to be a pacer rather than a limiter, and that is what these tests pin.** The
count-and-log invariant forbids accept-and-drop, so discarding was never available; NAKing would
mean refusing clinical messages the engine can process; closing the connection moves the loss
outside the boundary where it cannot be counted. Pacing the READ satisfies the invariant by
construction — the excess is never framed, so it never becomes a received message.

The load-bearing test here is therefore NOT that pacing happens. It is
:func:`test_pacing_never_drops_a_message` — every message a paced sender sends still arrives.
"""

from __future__ import annotations

import asyncio
import logging
import time

import pytest
from _ingress_pace_probe import install_ingress_pace_probe, stream_debt_seconds

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports import mllp
from messagefoundry.transports.mllp import (
    DEFAULT_MAX_MESSAGES_PER_SECOND,
    MLLPSource,
    _MessagePacer,
    frame,
)

_ADT = "MSH|^~\\&|A|B|C|D|202601011200||ADT^A01|{mid}|P|2.5\rPID|1||MRN1||DOE^JOHN\r"


def _source(**settings: object) -> MLLPSource:
    return MLLPSource(
        Source(name="IB_TEST", type=ConnectorType.MLLP, settings={"port": 0, **settings})
    )


# --- the pacer itself, pure and clock-injected -------------------------------------------------


def test_a_pacer_under_budget_asks_for_no_wait() -> None:
    pacer = _MessagePacer(10.0, 10.0, now=0.0)
    assert pacer.charge(5, now=0.0) == 0.0


def test_a_pacer_over_budget_asks_for_exactly_the_deficit() -> None:
    """The wait is the time for the bucket to return to non-negative -- so it is bounded by
    messages/rate and cannot grow without limit, which is what stops a pacer becoming a stall."""
    pacer = _MessagePacer(10.0, 10.0, now=0.0)
    assert pacer.charge(10, now=0.0) == 0.0  # burst absorbed
    # 5 more with an empty bucket at 10/s -> 0.5s of debt.
    assert pacer.charge(5, now=0.0) == pytest.approx(0.5)


def test_tokens_refill_with_elapsed_time_and_never_exceed_burst() -> None:
    pacer = _MessagePacer(10.0, 10.0, now=0.0)
    pacer.charge(10, now=0.0)
    # A full second later the bucket has refilled to its cap, not beyond it.
    assert pacer.charge(10, now=1.0) == 0.0
    assert pacer.charge(1, now=100.0) == 0.0  # long idle does not bank unlimited credit
    assert pacer.charge(10, now=100.0) == pytest.approx(0.1)


def test_burst_floor_is_one_so_a_pacer_can_always_make_progress() -> None:
    """A zero/negative burst would leave the bucket permanently empty and stall the connection."""
    pacer = _MessagePacer(1.0, 0.0, now=0.0)
    assert pacer.charge(1, now=0.0) == 0.0


# --- the shipped default ------------------------------------------------------------------------


def test_pacing_ships_off() -> None:
    """Ruled 2026-08-11: absent -> OFF, deliberately against this module's usual
    "key absent -> secure default" convention, because a guessed rate on a clinical interface
    throttles real traffic. Pinned so the deviation cannot be 'tidied' into the convention."""
    assert DEFAULT_MAX_MESSAGES_PER_SECOND is None
    assert _source().max_messages_per_second is None


def test_burst_defaults_to_one_seconds_worth() -> None:
    src = _source(max_messages_per_second=25)
    assert src.max_messages_per_second == 25.0
    assert src.message_burst == 25.0


def test_an_explicit_burst_is_honoured() -> None:
    assert _source(max_messages_per_second=25, message_burst=100).message_burst == 100.0


# --- end to end, on a real socket ---------------------------------------------------------------

#: The paced scenario, named once so the timing arms can derive their bounds from it instead of
#: restating a number the bucket arithmetic already fixes -- and so nobody can move the burst on the
#: connector while those arms keep checking a scenario it is no longer running.
_PACED: dict[str, float] = {"max_messages_per_second": 20.0, "message_burst": 2.0}
_RATE, _BURST = _PACED["max_messages_per_second"], _PACED["message_burst"]
_MESSAGES = 12


async def _run_against(src: MLLPSource, count: int) -> list[bytes]:
    """Send ``count`` framed messages down ONE connection and return what the handler received."""
    seen: list[bytes] = []

    async def handler(message: bytes) -> str | None:
        seen.append(message)
        return "MSA|AA|x"

    await src.start(handler)
    assert src._server is not None
    port = src._server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        for i in range(count):
            writer.write(frame(_ADT.format(mid=i), "utf-8"))
        await writer.drain()
        # Read one ACK per message: the sender is told AA for every one, paced or not.
        for _ in range(count):
            await asyncio.wait_for(reader.readuntil(b"\x1c\r"), timeout=10.0)
    finally:
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)
        await src.stop()
    return seen


async def test_pacing_never_drops_a_message() -> None:
    """THE test for this control. A paced sender is SLOWED, never truncated.

    Rate 20/s with burst 2 against 12 messages guarantees the pacer engages several times. Every
    message must still reach the handler and every one must still be ACKed -- accept-and-drop is
    what the count-and-log invariant forbids, and a limiter that discarded would pass a
    'rate is bounded' test while breaking the thing that actually matters.
    """
    seen = await _run_against(_source(**_PACED), _MESSAGES)
    assert len(seen) == 12
    # And in order: pacing must not reorder either, since FIFO is the project's ordering model.
    ids = [m.decode().split("|")[9] for m in seen]
    assert ids == [str(i) for i in range(12)]


async def test_pacing_off_delivers_everything_unchanged() -> None:
    seen = await _run_against(_source(), 12)
    assert len(seen) == 12


async def test_pacing_actually_delays_the_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    """Watched fail: with the pre-read wait removed, both arms below go to zero.

    **Neither arm is a constant, and that is the fix for BACKLOG #1538.** This asserted
    ``elapsed >= 0.3``, which is pacing plus the runner's own work with nothing to separate them --
    a box slow enough to spend 0.3s framing twelve messages passed it with the pacer deleted.
    Raising the number does not help: the pacer's debt SHRINKS as the runner slows, because the
    bucket refills on the same wall clock the work is spent on. ``tests/_ingress_pace_probe.py``
    puts the bucket on a clock this test owns, so the DECISION arm reads exact bucket arithmetic
    that no runner can influence, and the WALL-CLOCK arm is bounded by what this run decided rather
    than by a guess -- it is what still catches a pacer that decides a wait and never takes it.
    """
    probe = install_ingress_pace_probe(monkeypatch, mllp)
    loop = asyncio.get_running_loop()
    start = loop.time()
    seen = await _run_against(_source(**_PACED), _MESSAGES)
    elapsed = loop.time() - start
    assert len(seen) == _MESSAGES
    assert probe.built == 1, "the probe never replaced the pacer this intake builds"
    # 12 messages, burst 2, 20/s -> exactly (12-2)/20 = 0.5s of debt, paid before the next read.
    assert sum(probe.decided) == pytest.approx(stream_debt_seconds(_MESSAGES, _BURST, _RATE))
    assert elapsed >= sum(probe.taken)


# --- REACHABILITY: the factory surface that could not populate the pacer (BACKLOG #1249) ----------
#
# Everything above builds an MLLPSource from a raw settings dict, which is how a control with tests
# stayed unreachable in every shipped configuration: the tests proved the PACER worked by injecting
# settings the only authoring surface could not produce. `mllp.py` read both keys; `MLLP()` had no
# parameter for either, and `connections.toml` desugars through that same factory, so neither the
# code-first nor the data surface could express them. The doc row said so; the code now matches it.
#
# These tests go THROUGH the factory on purpose. That is the whole point of them.


def _from_factory(**kwargs: object) -> MLLPSource:
    """Build the source the way an author actually would -- via the public factory."""
    from messagefoundry.config.wiring import MLLP

    spec = MLLP(port=2575, **kwargs)  # type: ignore[arg-type]
    return MLLPSource(
        Source(name="IB_FACTORY", type=ConnectorType.MLLP, settings=dict(spec.settings))
    )


def test_the_factory_can_now_reach_the_pacer() -> None:
    """The defect, stated as a test: before #1249 no argument to MLLP() could set either key."""
    src = _from_factory(max_messages_per_second=9.5, message_burst=30.0)
    assert src.max_messages_per_second == 9.5
    assert src.message_burst == 30.0


def test_the_ruled_off_default_is_preserved() -> None:
    """Exposing the keys must NOT turn pacing on. The off default was ruled, not accidental -- a rate
    on a clinical interface is only safe at a number from a real feed profile."""
    src = _from_factory()
    assert src.max_messages_per_second is None, "a default install must still have NO rate bound"


def test_burst_defaults_to_one_seconds_worth_through_the_factory() -> None:
    """Setting only the rate must not leave the burst at zero, which would pace the first message."""
    src = _from_factory(max_messages_per_second=4.0)
    assert src.message_burst == 4.0


def test_the_toml_surface_reaches_it_too() -> None:
    """`connections.toml` desugars through the SAME factory -- `return factory(**settings)`, with the
    factory as the schema and no second source of truth. So the data surface is covered by the same
    change, and this test is what makes that claim checkable rather than asserted in a docstring."""
    from messagefoundry.config.connections_file import _TRANSPORTS

    spec = _TRANSPORTS["mllp"](port=2575, max_messages_per_second=7.0, message_burst=21.0)
    assert spec.settings["max_messages_per_second"] == 7.0
    assert spec.settings["message_burst"] == 21.0


def test_the_factory_still_rejects_an_unknown_key() -> None:
    """Positive control on the two tests above. If MLLP() swallowed arbitrary keyword arguments, every
    assertion here would pass without the parameters existing at all."""
    from messagefoundry.config.wiring import MLLP

    with pytest.raises(TypeError):
        MLLP(port=2575, mefor_no_such_pacing_key_1249=1.0)  # type: ignore[call-arg]


def test_the_shipped_default_constant_is_still_off() -> None:
    """`DEFAULT_MAX_MESSAGES_PER_SECOND` is what the connector falls back to when the key is absent.
    If it ever becomes non-None, exposing the keys would have silently turned pacing on for everyone."""
    assert DEFAULT_MAX_MESSAGES_PER_SECOND is None


# --- BACKLOG #290: pacing has to be observable, or its opt-in posture cannot be tuned -------------
#
# The 2026-08-11 ruling ships DEFAULT_MAX_MESSAGES_PER_SECOND OFF because a safe number can only come
# from a site's own feed profile. That posture only works if an operator who sets a number can watch
# it engage -- and pacing is silent by construction (it never drops, NAKs, refuses or errors), so a
# paced interface is indistinguishable from a slow one. These pin the report, not the pacing.


def test_pacing_reports_itself_on_a_stream_intake(caplog: pytest.LogCaptureFixture) -> None:
    """The pace()/settle() pair -- MLLP, raw TCP and X12 -- reports the delay it applies.

    Fails without the change: `_note_paced` does not exist, so `pace()` sleeps in silence and nothing
    reaches the log at any level.
    """
    pacer = _MessagePacer(1000.0, 1.0, now=time.monotonic(), name="IB_ACME_ADT")
    pacer.settle(5)  # 5 messages against a burst of 1 -> 4 tokens of debt, 4ms at 1000/s
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.mllp"):
        asyncio.run(pacer.pace())
    assert "IB_ACME_ADT" in caplog.text
    assert "pacing engaged" in caplog.text
    # The operator has to be told this is a hold, not a loss -- the whole point of the control.
    assert "not refused" in caplog.text


def test_pacing_reports_itself_on_a_listener_scoped_intake(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The deficit()/charge() pair -- the HTTP intake's one listener-wide bucket -- reports too.

    Driven on a fully synthetic clock, so it pins the report rather than any wall-clock timing.
    """
    pacer = _MessagePacer(1.0, 1.0, now=0.0, name="IB_ACME_HTTP")
    pacer.charge(5, now=0.0)  # 5 messages against a burst of 1 -> 4s of debt at 1/s
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.mllp"):
        owed = pacer.deficit(now=0.0)
    assert owed > 0.0
    assert "IB_ACME_HTTP" in caplog.text


def test_a_pacer_that_is_not_engaging_says_nothing(caplog: pytest.LogCaptureFixture) -> None:
    """NEGATIVE CONTROL for the two tests above. Without this, a report emitted unconditionally --
    on every read of every paced connection, whether or not the bucket is in deficit -- would pass
    both of them while flooding the log of a connection that is under its rate and fine."""
    pacer = _MessagePacer(1000.0, 1000.0, now=0.0, name="IB_QUIET")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.mllp"):
        assert pacer.deficit(now=0.0) == 0.0  # well inside the burst -> nothing owed
        asyncio.run(pacer.pace())  # no debt held -> no sleep, no report
    assert caplog.text == ""


def test_the_report_is_throttled_to_one_line_per_window(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A pacer in deficit is consulted on EVERY read, so an unthrottled line would restate one fact
    thousands of times and bury the log. Two applied delays inside one window produce one line."""
    pacer = _MessagePacer(1.0, 1.0, now=0.0, name="IB_BUSY")
    pacer.charge(5, now=0.0)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.mllp"):
        first = pacer.deficit(now=0.0)  # stamp == _report_at -> reports
        second = pacer.deficit(now=1.0)  # inside the window -> tallied, silent
    assert first > 0.0 and second > 0.0
    assert len([r for r in caplog.records if "pacing engaged" in r.getMessage()]) == 1


def test_the_report_names_the_connection_the_source_was_wired_with() -> None:
    """The name is not decoration: a pacing report an operator cannot trace to a connection tells
    them a feed somewhere is being held back and nothing about which one. Pins the wiring from
    `Source.name` through the source to the pacer, which is the half a pacer-only test cannot see."""
    src = _source(max_messages_per_second=5.0)
    assert src._pacing_name == "IB_TEST"
    pacer = _MessagePacer.for_rate(
        src.max_messages_per_second, src.message_burst, name=src._pacing_name
    )
    assert pacer is not None
    assert pacer._name == "IB_TEST"


def test_for_rate_still_returns_none_when_pacing_is_off() -> None:
    """POSITIVE CONTROL on the test above. If `for_rate` had stopped honouring the off-default while
    gaining its `name` argument, every pacing test in this file would still pass and pacing would
    have been silently turned on for every inbound."""
    assert _MessagePacer.for_rate(None, 1.0, name="IB_TEST") is None
    assert _MessagePacer.for_rate(0, 1.0, name="IB_TEST") is None
