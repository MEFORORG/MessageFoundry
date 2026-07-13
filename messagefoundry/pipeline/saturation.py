# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Saturation detection — the DERIVATIVE signal for "a lane is *becoming* overloaded" (BACKLOG #93).

Every shipped operational alert (``queue_buildup`` / ``message_stall`` / ADR 0014 rules) keys on an
**absolute snapshot**: a pending-depth ceiling or an oldest-message-age ceiling. On that axis a
bursty-but-DRAINING lane (a spike that the worker is clearing) and a genuinely OVERLOADED one look
identical until the ceiling trips — and by then the operator is already behind. Nothing fires on the
**rate of change**.

:class:`SaturationDetector` closes that gap with a small, bounded per-lane depth-sample history. Its
trigger is *sustained rising backlog*, which — by conservation of the queue — is exactly *ingest >
drain sustained over the window*: for a lane whose depth goes ``d0 → … → dN``, ``dN > d0`` iff
arrivals exceeded departures across the window. So a lane that spikes then drains (its depth falls
back) never trips, while a lane whose depth climbs monotonically does. That is the whole point of the
signal, and it needs **only depth samples** — no second rate sampler, no extra per-lane store read
beyond the one the buildup check already performs.

Pure and synchronous (no I/O, no ``await``), so it is trivially unit-testable off the async runner —
the "fires on rising / does NOT fire on bursty-but-draining" property is a table test over
:meth:`SaturationDetector.observe`.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

__all__ = ["SaturationSignal", "SaturationDetector"]


@dataclass(frozen=True)
class SaturationSignal:
    """A fired saturation observation — the queue-shape DERIVATIVE for one lane. Carries only
    counts/rates (no message content — no PHI): the window's start/end pending depth, the net growth
    rate, the wall span it was measured over, and how many samples the window spans."""

    depth: int  # current (window-end) pending depth
    depth_start: int  # pending depth at the window start
    growth_per_second: float  # net rise rate across the window ((depth - depth_start) / span)
    span_seconds: float  # wall-clock span the window covers
    samples: int  # number of samples in the decision window (== sustain_samples + 1)


class SaturationDetector:
    """A bounded per-lane depth-sample history that fires when the backlog is RISING SUSTAINED.

    ``sustain_samples`` is how many consecutive non-decreasing steps (with a net rise end-to-end) must
    be observed before :meth:`observe` returns a :class:`SaturationSignal`. The history is capped at
    ``sustain_samples + 1`` samples (constant memory), so an old spike ages out of the window and a
    lane that has since drained stops firing on its own.

    The decision (evaluated over the full window once it is primed):

    * **net rise** — the newest depth is strictly greater than the oldest in the window (``dN > d0``),
      i.e. arrivals exceeded departures over the window (ingest > drain); and
    * **sustained** — no step in the window *decreased* (every ``d[i+1] >= d[i]``). A single drop means
      the worker drained at some point in the window, so the growth is a burst being cleared, not
      saturation — and it does **not** fire.

    A flat window (``dN == d0``) or a window with any decrease returns ``None``.
    """

    __slots__ = ("_sustain", "_samples")

    def __init__(self, sustain_samples: int) -> None:
        if sustain_samples < 2:
            # Fewer than two rising steps can't distinguish a burst from sustained growth.
            raise ValueError(f"sustain_samples must be >= 2, got {sustain_samples}")
        self._sustain = sustain_samples
        self._samples: deque[tuple[float, int]] = deque(maxlen=sustain_samples + 1)

    def observe(self, now: float, depth: int) -> SaturationSignal | None:
        """Record one ``(timestamp, pending_depth)`` sample and, if the window now shows sustained
        rising backlog, return the :class:`SaturationSignal`; otherwise ``None``. Cheap and pure."""
        self._samples.append((now, depth))
        if len(self._samples) < self._sustain + 1:
            return None  # window not yet primed — need sustain_samples + 1 observations
        window = list(self._samples)
        depths = [d for _, d in window]
        if depths[-1] <= depths[0]:
            return None  # no net rise across the window → not becoming overloaded
        for prev, cur in zip(depths, depths[1:]):
            if cur < prev:
                # A decrease anywhere in the window = the lane drained during it. That is a
                # bursty-but-DRAINING lane, not saturation — do not fire (the key property).
                return None
        span = window[-1][0] - window[0][0]
        growth = (depths[-1] - depths[0]) / span if span > 0 else 0.0
        return SaturationSignal(
            depth=depths[-1],
            depth_start=depths[0],
            growth_per_second=growth,
            span_seconds=span,
            samples=len(depths),
        )

    def reset(self) -> None:
        """Drop the sample history (called on connection teardown/reload so a fresh lane starts clean)."""
        self._samples.clear()
