# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

import pytest

from messagefoundry.config.models import ConnectorType, Source
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


async def _run_against(src: MLLPSource, count: int) -> list[str]:
    """Send ``count`` framed messages down ONE connection and return what the handler received."""
    seen: list[str] = []

    async def handler(message: str) -> str | None:
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
    seen = await _run_against(_source(max_messages_per_second=20, message_burst=2), 12)
    assert len(seen) == 12
    # And in order: pacing must not reorder either, since FIFO is the project's ordering model.
    ids = [(m.decode() if isinstance(m, bytes) else m).split("|")[9] for m in seen]
    assert ids == [str(i) for i in range(12)]


async def test_pacing_off_delivers_everything_unchanged() -> None:
    seen = await _run_against(_source(), 12)
    assert len(seen) == 12


async def test_pacing_actually_delays_the_reads() -> None:
    """Watched fail: with the pacer removed this elapsed time collapses to near zero.

    Deliberately a LOWER bound only. Asserting an upper bound would pin scheduler timing and make
    this the flaky test that gets deleted; the claim under test is that a wait occurs at all.
    """
    loop = asyncio.get_running_loop()
    start = loop.time()
    seen = await _run_against(_source(max_messages_per_second=20, message_burst=2), 12)
    elapsed = loop.time() - start
    assert len(seen) == 12
    # 12 messages, burst 2, 20/s -> at least (12-2)/20 = 0.5s of debt must be paid somewhere.
    assert elapsed >= 0.3


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
