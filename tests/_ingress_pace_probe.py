# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Deterministic observation of the ingress message pacer (BACKLOG #1538).

**The defect this closes.** Four paced ingress tests -- raw TCP, X12, HTTP and MLLP -- bounded a
single arm against a fixed ``elapsed >= 0.3``. Elapsed seconds are the sum of the pacer's waits and
the runner's own work, and nothing in those assertions told the two apart, so a box slow enough to
spend 0.3 s framing twelve messages passed every one of them with the pacer deleted. The constant
could not be raised out of that reach either: the pacer's debt SHRINKS as the runner slows, because
the bucket refills on the same wall clock the work is being spent on, so a higher floor turns into a
false red on exactly the hosts a lower one is vacuous on.

**What this does instead.** ``_MessagePacer`` reads the clock at exactly two places -- ``__init__``
stamps ``_last``, and ``charge`` refills from ``now``; ``settle``, ``deficit`` and
``for_rate`` all reach the clock THROUGH those two. Overriding both in a recording subclass puts the
whole bucket on a clock this file owns, advanced only by the waits the pacer itself decides. The
runner then drops out of the arithmetic completely and the schedule becomes exact, which is what lets
a test assert what the pacer DECIDED rather than how long the box took.

This is the ``tests/_pace_probe.py`` rule (BACKLOG #82) applied to the ingress side, and the same
rule ``tests/test_dicom_association_intake_bound.py`` applies to the DICOM association intake
(BACKLOG #1536). Recording rather than substituting is why both arms are readable from one run: the
real ``asyncio.sleep`` still happens, so a test can still ask whether the box actually slept.

**Cost.** Nothing is added to the suite's wall time. The paced runs sleep off the same debt they
always did; only the clock the debt is computed on has moved.

**The seam is two methods, and a third clock read would break it silently.** Nothing here raises if
``_MessagePacer`` grows one. What catches it is the exact schedule each caller asserts: a read this
subclass does not intercept sees real monotonic seconds against a probe clock near zero, and the
decisions stop matching the bucket arithmetic the test spells out. Read a mismatch there as this
probe needing rethinking, not as a tolerance needing widening.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import ModuleType

import pytest

from messagefoundry.transports.mllp import _MessagePacer

__all__ = [
    "IngressPaceProbe",
    "install_ingress_pace_probe",
    "listener_waits",
    "stream_debt_seconds",
]


@dataclass
class IngressPaceProbe:
    """What one intake's pacer did: how many pacers it built, and every wait each one decided.

    ``built`` is the positive control and is not optional. A swap that failed to take records zero,
    and every assertion about ``decided`` would then be a claim about an empty list -- which is
    exactly the shape of a search that finds nothing being read as a clean result.
    """

    #: Pacers constructed through the swapped name. Zero means the swap never took.
    built: int = 0
    #: Every positive wait the pacer decided, in order, in seconds.
    decided: list[float] = field(default_factory=list)
    #: The subset of ``decided`` whose sleep ran to completion inside the pacer. A stream intake is
    #: usually cancelled part-way through its final wait, when the test tears the connection down
    #: with the debt already decided, so this is the honest floor for a wall-clock arm.
    taken: list[float] = field(default_factory=list)
    #: The pacer's clock. Any origin will do; a monotonic clock has no defined epoch.
    now: float = 0.0


def stream_debt_seconds(messages: int, burst: float, rate: float) -> float:
    """Seconds a stream intake must wait in total to admit ``messages`` at ``rate``.

    Exact rather than approximate, and invariant to how the peer's bytes happen to be chunked. The
    bucket starts full, the probe clock advances only by the waits the pacer decides, and each wait
    is sized to bring the bucket back to exactly zero -- so refill over the run equals
    ``rate * total_wait`` and the clamp at capacity is never reached once the burst is spent.
    Rearranged, the tokens charged beyond the burst are paid for at ``rate``, whatever order they
    arrived in.
    """
    return (messages - max(burst, 1.0)) / rate


def listener_waits(requests: int, burst: float, rate: float) -> list[float]:
    """Every wait a listener-wide bucket decides while serving ``requests``, one per request.

    A listener reads the debt BEFORE charging, which is what makes this schedule different from the
    stream one rather than a rounding of it. The first ``capacity`` requests spend the burst, one
    more is served on a zero balance -- ``deficit`` owes nothing until the bucket is actually
    negative -- and every request after that finds it one token short and waits exactly ``1 / rate``
    for that token to refill. The result is a flat run of identical waits, not a single debt.

    Measured against the HTTP intake at 12 requests, burst 2, 20/s: nine waits of 0.05 s. An earlier
    draft of the DICOM twin guessed ``N - burst`` for the same shape and was wrong by exactly the
    one request served on a zero balance, so the ``- 1`` here is the whole point of writing it down.
    """
    return [1.0 / rate] * int(requests - max(burst, 1.0) - 1)


def install_ingress_pace_probe(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType
) -> IngressPaceProbe:
    """Swap ``module``'s ``_MessagePacer`` for a recording subclass; return the record.

    Every intake that paces imports the class into its own namespace, so the swap is per module and
    the recorder is not: one definition serves the raw-TCP, X12, HTTP and MLLP sites. The real
    ``_MessagePacer`` still runs -- this subclasses it, it does not reimplement it -- so an intake
    that stops building a pacer records no construction, and a pacer that stops waiting records no
    decision.

    Install it BEFORE the source is constructed. The HTTP listener builds its one listener-wide
    pacer in ``__init__``; the three stream intakes build one per connection inside the accept
    handler, which a later swap would still reach, but there is no reason to have two rules.
    """
    probe = IngressPaceProbe()

    class _RecordingPacer(_MessagePacer):
        """``_MessagePacer`` on the probe's clock, recording what it decides.

        ``for_rate`` is inherited unchanged: it builds ``cls(...)``, so it yields this subclass
        without an override, and it still returns ``None`` when no rate is configured -- the
        shipped-off default is not something a test probe should be able to move.
        """

        __slots__ = ()

        def __init__(self, rate: float, burst: float, *, now: float) -> None:
            # The caller's `now` is the runner's monotonic clock. Dropping it here is what puts
            # `_last` and every later refill on one clock, since a bucket stamped from one clock and
            # refilled from another reads a nonsense first interval.
            super().__init__(rate, burst, now=probe.now)
            probe.built += 1

        def charge(self, messages: int, *, now: float) -> float:
            return super().charge(messages, now=probe.now)

        async def pace(self) -> None:
            # Read the debt before delegating, and advance the clock by it BEFORE the sleep: the
            # schedule is then the pacer's own arithmetic, and whether the box really slept stays a
            # question for the caller's wall-clock arm rather than an input to this one.
            wait = self._pending_wait
            if wait > 0.0:
                probe.decided.append(wait)
                probe.now += wait
            await super().pace()
            if wait > 0.0:
                probe.taken.append(wait)

        def deficit(self, *, now: float) -> float:
            # The listener-scoped read. Its caller sleeps the returned value immediately, so the
            # clock advances here for the same reason it advances in pace(). It cannot record a
            # `taken`: the sleep happens in the listener, out of this object's sight.
            owed = super().deficit(now=now)
            if owed > 0.0:
                probe.decided.append(owed)
                probe.now += owed
            return owed

    monkeypatch.setattr(module, "_MessagePacer", _RecordingPacer)
    return probe
