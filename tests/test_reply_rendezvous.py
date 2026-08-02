# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The in-process reply rendezvous (ADR 0154 D3) — the race matrix, tested where it is deterministic.

The rendezvous carries no information: every signal is a latency hint and the woken turn re-reads the
store. So these tests are not about *what* a wake means — they are about the two properties whose
absence produces silent, load-dependent failure in production and nothing at all in a functional test:

* **a hint is consumed, never sticky** — an ``asyncio.Event`` stays set once set, so a waiter looping
  on an unconsumed one stops sleeping and spins at full CPU for the rest of ``reply_timeout``,
  precisely in the legitimate multi-handler case that drives repeated wakes; and
* **an armed entry never outlives its turn** — a leak accumulates until the cap, after which *every*
  caller resolves ``degraded`` with a perfectly healthy store and no error anywhere.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from messagefoundry.pipeline.reply_wait import RendezvousFull, ReplyRendezvous

KEY = ("m1", "OB_PARTNER")


async def test_a_hint_wakes_the_waiter_early() -> None:
    rv = ReplyRendezvous()
    with rv.arm(*KEY) as waiter:
        rv.signal(*KEY)
        started = time.monotonic()
        await waiter.hint(5.0)
        assert time.monotonic() - started < 0.5, "the hint did not wake the waiter"


async def test_a_hint_is_consumed_not_sticky() -> None:
    # THE spin guard. One signal buys exactly one early wake; the next tick must sleep normally.
    # Without the consume, every subsequent hint() would return instantly forever.
    rv = ReplyRendezvous()
    with rv.arm(*KEY) as waiter:
        rv.fail(*KEY)

        started = time.monotonic()
        await waiter.hint(5.0)
        assert time.monotonic() - started < 0.5  # consumed the hint

        started = time.monotonic()
        await waiter.hint(0.15)
        elapsed = time.monotonic() - started
    assert elapsed >= 0.10, (
        f"the second hint returned after {elapsed:.3f}s — the Event stayed set, so a waiter would "
        "spin at full CPU for the rest of reply_timeout"
    )


async def test_repeated_hints_coalesce_rather_than_queue() -> None:
    # A sibling handler firing repeatedly must not bank wakes that skip future sleeps for free.
    rv = ReplyRendezvous()
    with rv.arm(*KEY) as waiter:
        for _ in range(50):
            rv.fail(*KEY)
        await waiter.hint(5.0)  # consumes all 50

        started = time.monotonic()
        await waiter.hint(0.15)
        elapsed = time.monotonic() - started
    assert elapsed >= 0.10, f"banked wakes survived: second hint returned in {elapsed:.3f}s"


async def test_a_signal_before_any_arm_is_a_silent_no_op() -> None:
    # The normal case, not an error: every delivery signals, almost none is awaited.
    rv = ReplyRendezvous()
    rv.signal(*KEY)
    rv.fail("unknown", "OB_NOBODY")
    assert rv.waiters == 0

    # ... and it does not leave a latent wake for a later turn on the same key.
    with rv.arm(*KEY) as waiter:
        started = time.monotonic()
        await waiter.hint(0.15)
        assert time.monotonic() - started >= 0.10, "a pre-arm signal leaked into a later turn"


async def test_a_foreign_key_never_wakes_this_waiter() -> None:
    rv = ReplyRendezvous()
    with rv.arm(*KEY) as waiter:
        rv.signal("m1", "OB_OTHER")  # same message, different destination
        rv.signal("m2", "OB_PARTNER")  # same destination, different message
        started = time.monotonic()
        await waiter.hint(0.15)
        assert time.monotonic() - started >= 0.10, "a foreign key woke the waiter"


@pytest.mark.parametrize("failure", ["normal", "timeout", "exception", "cancel"])
async def test_the_entry_count_returns_to_zero(failure: str) -> None:
    # The leak guard, across every exit path a turn can take.
    rv = ReplyRendezvous()

    async def turn() -> None:
        with rv.arm(*KEY) as waiter:
            assert rv.waiters == 1
            if failure == "timeout":
                await waiter.hint(0.02)
            elif failure == "exception":
                raise RuntimeError("handler blew up mid-wait")
            elif failure == "cancel":
                await waiter.hint(30.0)  # cancelled from outside

    if failure == "exception":
        with pytest.raises(RuntimeError):
            await turn()
    elif failure == "cancel":
        task = asyncio.create_task(turn())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await turn()

    assert rv.waiters == 0, f"an armed entry survived the {failure!r} path — this is the leak"


async def test_many_sequential_turns_leave_nothing_behind() -> None:
    rv = ReplyRendezvous()
    for i in range(200):
        with rv.arm(f"m{i}", "OB_PARTNER") as waiter:
            rv.signal(f"m{i}", "OB_PARTNER")
            await waiter.hint(1.0)
    assert rv.waiters == 0


async def test_the_cap_refuses_rather_than_queues() -> None:
    rv = ReplyRendezvous(max_waiters=2)
    with rv.arm("m1", "OB") as _a, rv.arm("m2", "OB") as _b:
        assert rv.waiters == 2
        with pytest.raises(RendezvousFull, match="at capacity"), rv.arm("m3", "OB"):
            pass
    # ... and the cap is a live count, not a high-water mark: capacity returns on release.
    assert rv.waiters == 0
    with rv.arm("m4", "OB"):
        assert rv.waiters == 1


async def test_drain_wakes_everyone_and_names_the_reason() -> None:
    rv = ReplyRendezvous()
    with rv.arm("m1", "OB") as first, rv.arm("m2", "OB") as second:
        assert first.drain_reason is None
        rv.drain("shutting_down")

        started = time.monotonic()
        await first.hint(5.0)
        await second.hint(5.0)
        assert time.monotonic() - started < 0.5, "drain did not wake a blocked waiter"
        assert first.drain_reason == "shutting_down"
        assert second.drain_reason == "shutting_down"

        # A drained waiter never blocks again — stop() must not be paced by the poll period.
        started = time.monotonic()
        await first.hint(5.0)
        assert time.monotonic() - started < 0.5


async def test_arming_during_drain_is_refused() -> None:
    # A request arriving mid-shutdown must resolve degraded immediately rather than arm a waiter
    # nothing will ever wake.
    rv = ReplyRendezvous()
    rv.drain("shutting_down")
    with pytest.raises(RendezvousFull, match="draining"), rv.arm("m1", "OB"):
        pass


async def test_drain_is_idempotent() -> None:
    rv = ReplyRendezvous()
    with rv.arm("m1", "OB") as waiter:
        rv.drain("shutting_down")
        rv.drain("shutting_down")
        assert waiter.drain_reason == "shutting_down"
    assert rv.waiters == 0


async def test_two_waiters_on_one_key_are_both_woken() -> None:
    # Not expected in production (one HTTP turn per committed message), but a collision must not
    # silently drop one waiter — that would be a turn that hangs to full timeout for no reason.
    rv = ReplyRendezvous()
    with rv.arm(*KEY) as first, rv.arm(*KEY) as second:
        assert rv.waiters == 2
        rv.signal(*KEY)
        started = time.monotonic()
        await first.hint(5.0)
        await second.hint(5.0)
        assert time.monotonic() - started < 0.5
