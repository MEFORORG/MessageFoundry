# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Deterministic observation of the egress send pacer (BACKLOG #82).

**The flake this replaces.** ``_pace_outbound`` stamps the lane's send clock and returns; the delivery
body -- frame, send, complete every row -- runs AFTER that stamp. A test that starts its own stopwatch
once the first delivery has RETURNED is therefore already part-way into the interval, so what it
measures is ``interval - W1 + W2``, where ``W1`` is the first delivery's post-stamp work and ``W2`` is
the second's. Whenever the first delivery is the slower of the two -- routine on a loaded Windows
runner paying cold SQLite/WAL costs on its first write -- the measured value falls BELOW the interval
while the pacer behaved perfectly. Measured 2026-09-05 in merge-group run 33953850543: 0.0306 s
against a 0.05 s interval, which ejected a pull request from the merge queue. Reproduced locally by
stalling only the FIRST delivery by 25 ms, which lands on 0.0300 s with the pacing code untouched.

A multiplicative tolerance cannot fix that. ``W1`` is a property of the runner, not a fraction of the
interval, so any factor loose enough to pass on a slow box is also loose enough to pass a pacer that
has stopped waiting altogether.

**It is not timer granularity.** Windows' coarse timer makes ``asyncio.sleep`` return LATE, never
early: measured 0/240 early returns across four requested intervals on ProactorEventLoop, worst
deficit 0.000000 s. Widening the bound to absorb quantisation would be padding against a mechanism
that is not present, and would cost the assertion its remaining power.

**What this does instead.** ``_pace_outbound`` reads the clock as ``time.monotonic()`` and waits as
``asyncio.sleep()``, both resolved through the ``wiring_runner`` module namespace at call time.
Swapping those two names for the duration of each call -- the same surgical module swap
``_totp_clock.pin_totp_clock`` uses on ``totp`` -- puts the pacer on a clock the test owns and turns
its wait into a recorded number. The test then asserts what the seam DECIDED, which no runner can
influence, instead of how long the box took to obey.

The swap is scoped to the call, and that scope is load-bearing rather than cautious. The delivery
body AROUND the pacer reads ``time.time()`` and awaits ``asyncio.wait_for`` for its own batch
coalescing window (``_process_delivery_batch``), neither of which the stand-ins below expose: a
test-wide swap would break that body outright, and widening the stand-ins to cover it would fold the
coalescing window's own waits into what the pacer is recorded as asking for. Within the call the swap
is invisible, because the stand-in ``sleep`` never awaits -- ``_pace_outbound`` is left with no yield
point, so no other coroutine can run while the two names are swapped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Never

import pytest

from messagefoundry.pipeline import wiring_runner

__all__ = ["PaceProbe", "install_pace_probe"]


@dataclass
class PaceProbe:
    """What one lane's pacer did: every call it received, and every wait it asked for.

    ``slept`` is the assertion that matters. It holds the delay of each ``asyncio.sleep`` the pacer
    requested, in order, and it is empty when the pacer decided no wait was owed -- so it separates
    "held the interval" from "returned immediately" with no reference to elapsed wall-clock time.
    """

    #: The pacer's clock. Any instant will do; a monotonic clock has no defined epoch.
    now: float = 1000.0
    #: One entry per ``_pace_outbound`` call, in order -- the lane name it was called for.
    calls: list[str] = field(default_factory=list)
    #: One entry per wait the pacer requested, in order, in seconds.
    slept: list[float] = field(default_factory=list)

    def advance(self, seconds: float) -> None:
        """Model ``seconds`` of delivery work between two sends, on the pacer's own clock.

        This is the ``W1`` the old wall-clock assertion could neither see nor control. Setting it
        explicitly is what makes the next requested wait an exact, known number.
        """
        self.now += seconds


def _unmodelled(module: str, name: str) -> Never:
    """Fail with a message that names the probe, because the traceback will not.

    The stand-ins model exactly the two attributes ``_pace_outbound`` reads today. Give it a third --
    most likely by making the wait cancellable, which is the refactor this code is closest to -- and
    the swap stops being invisible: the missing attribute surfaces in whatever coroutine happens to
    run next, as an AttributeError naming neither pacing nor this file. Say so here instead.
    """
    raise AttributeError(
        f"tests/_pace_probe.py models only time.monotonic and asyncio.sleep, but the code under the"
        f" probe read {module}.{name}. If _pace_outbound gained a yield point, the module swap is no"
        f" longer invisible and this probe needs rethinking, not just a wider stand-in."
    )


class _FrozenClock:
    """Stand-in for the ``time`` module exposing only ``monotonic()`` -- the pacer's sole clock read."""

    def __init__(self, probe: PaceProbe) -> None:
        self._probe = probe

    def monotonic(self) -> float:
        return self._probe.now

    def __getattr__(self, name: str) -> Never:
        _unmodelled("time", name)


class _RecordingSleep:
    """Stand-in for the ``asyncio`` module exposing only ``sleep()`` -- the pacer's sole asyncio use.

    Records the requested delay and advances the frozen clock by exactly that much instead of
    suspending, so the wait becomes an observable number and the test spends no real time on it.
    """

    def __init__(self, probe: PaceProbe) -> None:
        self._probe = probe

    async def sleep(self, delay: float) -> None:
        self._probe.slept.append(delay)
        self._probe.now += delay

    def __getattr__(self, name: str) -> Never:
        _unmodelled("asyncio", name)


def install_pace_probe(
    monkeypatch: pytest.MonkeyPatch, runner: wiring_runner.RegistryRunner
) -> PaceProbe:
    """Put ``runner``'s pacer on a clock the test owns; return the record of what it decides.

    The real ``_pace_outbound`` still runs -- this wraps it, it does not reimplement it -- so a seam
    that stops calling the pacer records no call, and a pacer that stops waiting records no sleep.
    """
    probe = PaceProbe()
    # Bound BEFORE the patch, so the wrapper delegates to the genuine method rather than to itself.
    real = runner._pace_outbound
    clock = _FrozenClock(probe)
    sleeper = _RecordingSleep(probe)

    async def _probed(name: str) -> None:
        probe.calls.append(name)
        with monkeypatch.context() as swap:
            swap.setattr(wiring_runner, "time", clock)
            swap.setattr(wiring_runner, "asyncio", sleeper)
            await real(name)

    monkeypatch.setattr(runner, "_pace_outbound", _probed)
    return probe
