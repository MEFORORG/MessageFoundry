# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Bench-gated per-delivery phase timing (default OFF) — shared by the delivery body
(:mod:`messagefoundry.pipeline.wiring_runner`) and the pooled claimer
(:mod:`messagefoundry.pipeline.stage_dispatcher`).

**Why this module exists.** PR #842 timed two sub-phases of a delivery — ``send_ack`` (the connector
send->ACK round-trip) and ``mark_done`` (the store completion round-trip) — on the premise that the
per-delivery wall "is either" one or the other. The 2026-07-09 rig ladder falsified that premise: at
``dests=8`` the per-lane delivery cycle ran 62-190 ms while ``send_ack + mark_done`` accounted for
only 9-18 ms of it. **81-91% of every delivery was time neither timer could see** — because the
CLAIM round-trip (``claim_fifo_heads`` in pooled mode, ``claim_next_fifo`` in per_lane) sits outside
both timed regions. SQL Server's own ``dm_os_waiting_tasks`` capture named the claim batch as the top
``PAGELATCH_EX/SH`` waiter on tempdb's metadata catalog. This module closes that blind spot: the
claim is now timed as a first-class phase, so the residual is measured rather than inferred.

**Why the claim can bound aggregate throughput.** In pooled mode a stage runs ``K =
pooled_claimers_per_stage`` claimer tasks (ADR 0066 §3.3, default **K=1**). A claimer's loop is
serial — assemble a lane chunk, ``await claim_fifo_heads`` for the whole chunk, dispatch, repeat —
and it never awaits delivery. So a stage's lanes are re-fed at most once per claim round-trip per
claimer, and with hard-1 OUTBOUND (``per_lane_limit`` forced to 1) the aggregate outbound rate is
bounded by ``K x lanes / T_claim``. ADR 0066 chose K=1 on the estimate that "claim traffic is
~12-50 RT/s — far below one task's capacity"; a ``T_claim`` of 62-190 ms puts one claimer at 5-16
RT/s, so that estimate wants re-measuring, not assuming. ``lanes_per_claim`` / ``rows_per_claim``
below make the bound directly observable.

Metrics ONLY — count / mean / max / ratios. This module never records or logs a payload, a control
id, a lane name, or any message content (PHI rule, CLAUDE.md §9). Default OFF: when the lever is off
every call site is a single bool check — no ``perf_counter``, no allocation.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)

#: Truthy spellings for the bench lever (shared by both phase accumulators).
DELIVERY_PHASE_TIMING_ENV = "MEFOR_DELIVERY_PHASE_TIMING"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: How often (monotonic seconds) each process emits a rolling phase summary, then resets the window.
#: Bounded — a per-process INFO line every ~5 s, never a line per delivery or per claim.
_DELIVERY_PHASE_EMIT_INTERVAL = 5.0


def delivery_phase_timing_enabled() -> bool:
    """Whether the bench-only phase-timing lever is on (``MEFOR_DELIVERY_PHASE_TIMING`` truthy).

    Default OFF — read ONCE per runner/dispatcher at construction, never per delivery or per claim.
    """
    return os.environ.get(DELIVERY_PHASE_TIMING_ENV, "").strip().lower() in _TRUTHY


@dataclass
class _PhaseWindow:
    """One phase's rolling window: bounded aggregates only (count + sum + max nanoseconds), never a
    per-sample list — so the accumulator can't grow with delivery volume. Reset each emit window."""

    count: int = 0
    sum_ns: int = 0
    max_ns: int = 0

    def add(self, ns: int) -> None:
        self.count += 1
        self.sum_ns += ns
        if ns > self.max_ns:
            self.max_ns = ns

    def reset(self) -> None:
        self.count = 0
        self.sum_ns = 0
        self.max_ns = 0

    def mean_ms(self) -> float:
        return (self.sum_ns / self.count) / 1e6 if self.count else 0.0

    def max_ms(self) -> float:
        return self.max_ns / 1e6


class DeliveryPhaseTiming:
    """Bench-gated accumulator for the two per-delivery sub-phases INSIDE the delivery body:
    ``send_ack`` (the ``await connector.send`` round-trip to the partner) and ``mark_done`` (the store
    completion round-trip — ``mark_done`` / ``complete_with_response``).

    These two do NOT sum to the per-delivery cycle — the claim round-trip that re-feeds the lane is
    timed separately by :class:`ClaimPhaseTiming`. Read them together or the residual is invisible
    (that was the #842 blind spot; see the module docstring).

    Mutated only on the engine event loop — ``_process_delivery_item`` records synchronously (no await
    between reading and writing the counters) so pooled claimers can't interleave a partial update; no
    lock needed (same discipline as ``EmptyClaimCounters``). Never records or logs a payload /
    control-id (PHI rule).

    ``logger`` lets the caller keep the emitting logger's NAME stable across this module extraction —
    ``wiring_runner`` passes its own module logger so the shipped INFO line (which the rig's node-log
    parser and ``tests/test_delivery_phase_timing.py`` both key on) is byte-identical to #842's."""

    def __init__(self, *, logger: logging.Logger | None = None) -> None:
        self.send_ack = _PhaseWindow()
        self.mark_done = _PhaseWindow()
        self._log = logger if logger is not None else log
        # 0.0 (not now) so the FIRST recorded delivery emits immediately, then throttles — one prompt
        # datapoint per process on the rig, without waiting a full window for the first line.
        self._last_emit = 0.0

    def record_send_ack(self, ns: int) -> None:
        self.send_ack.add(ns)

    def record_mark_done(self, ns: int) -> None:
        self.mark_done.add(ns)

    def maybe_emit(self, *, stage: str = "outbound") -> None:
        """Emit the throttled summary + reset the window when the interval has elapsed. Called after
        each recorded delivery; a no-op between windows (one monotonic subtraction)."""
        now = time.monotonic()
        if now - self._last_emit < _DELIVERY_PHASE_EMIT_INTERVAL:
            return
        self._last_emit = now
        # Metrics only — count/mean/max in ms, never a message body or control-id.
        self._log.info(
            "delivery phase timing (stage=%s): send_ack n=%d mean=%.2fms max=%.2fms | "
            "mark_done n=%d mean=%.2fms max=%.2fms",
            stage,
            self.send_ack.count,
            self.send_ack.mean_ms(),
            self.send_ack.max_ms(),
            self.mark_done.count,
            self.mark_done.mean_ms(),
            self.mark_done.max_ms(),
        )
        self.send_ack.reset()
        self.mark_done.reset()


class ClaimPhaseTiming:
    """Bench-gated accumulator for the CLAIM round-trip — the phase #842 could not see.

    One ``record_claim`` per store claim call: pooled mode times ``claim_fifo_heads`` (one round-trip
    covering a whole lane chunk), per_lane mode times ``claim_next_fifo`` / ``claim_ready`` (one
    round-trip per lane worker). ``lanes`` and ``rows`` make the two modes comparable and expose the
    pooled bound ``aggregate <= K x rows_per_claim / T_claim``:

    * ``lanes_per_claim`` — mean lanes offered per round-trip. Pooled: the chunk size (grows with the
      destination count, and so does ``T_claim`` — the ``CROSS APPLY`` does one index seek per lane).
      per_lane: always 1.
    * ``rows_per_claim`` — mean rows actually returned. Under hard-1 OUTBOUND this is bounded by
      ``lanes``, so ``rows_per_claim / claim_mean_ms`` IS the stage's re-feed rate per claimer.
    * ``rearm`` — lanes the claim fully consumed via the H2 skip-and-complete (an already-delivered
      head completed in place). Those did real work and returned no row, so they must NOT be booked as
      empty overhead — during a dedup/failover pass that would be exactly backwards.
    * ``empty`` — claims that returned zero rows AND rearmed nothing: pure overhead, yet the fixed
      per-claim tempdb churn is paid anyway. **Caveat (per_lane only):** ``claim_next_fifo`` returns
      ``None`` both for "nothing pending" and for an H2 in-place completion / poison dead-letter, which
      DID write. per_lane cannot tell them apart, so its ``empty`` is an upper bound. Pooled can (it
      gets ``rearm`` back) and does.

    **Failed claims are excluded by design.** A claim that raises is logged with a traceback and takes
    the backoff path; its timeout-capped duration never enters this window. Folding it in would distort
    the very 62-190 ms figure this accumulator exists to measure, and a raised claim has no ``rows`` —
    it would be mis-booked as empty. The tempdb signature shows up as slow-but-SUCCESSFUL claims, which
    ARE recorded (the tail lands in ``claim.max_ms``).

    Same concurrency discipline as :class:`DeliveryPhaseTiming`: recorded synchronously on the event
    loop, never a lock. Metrics only — a lane is a ``destination_name``, so lane NAMES are never
    logged, only counts (PHI rule)."""

    def __init__(self, *, logger: logging.Logger | None = None) -> None:
        self.claim = _PhaseWindow()
        self.lanes_offered = 0
        self.rows_returned = 0
        self.rearm_lanes = 0
        self.empty_claims = 0
        self._log = logger if logger is not None else log
        self._last_emit = 0.0

    def record_claim(self, ns: int, *, lanes: int, rows: int, rearm: int = 0) -> None:
        self.claim.add(ns)
        self.lanes_offered += lanes
        self.rows_returned += rows
        self.rearm_lanes += rearm
        # A rearm-only claim consumed heads in place (H2) — real work, not overhead. Only a claim that
        # returned nothing AND rearmed nothing is the pure-overhead poll the churn metric cares about.
        if rows == 0 and rearm == 0:
            self.empty_claims += 1

    def _reset(self) -> None:
        self.claim.reset()
        self.lanes_offered = 0
        self.rows_returned = 0
        self.rearm_lanes = 0
        self.empty_claims = 0

    def maybe_emit(self, *, stage: str, claimers: int) -> None:
        """Emit the throttled claim summary + reset the window. ``claimers`` is the stage's K so a
        reader can compute the theoretical re-feed bound without knowing the config."""
        now = time.monotonic()
        if now - self._last_emit < _DELIVERY_PHASE_EMIT_INTERVAL:
            return
        self._last_emit = now
        n = self.claim.count
        lanes_per = self.lanes_offered / n if n else 0.0
        rows_per = self.rows_returned / n if n else 0.0
        # Metrics only — counts + ratios; never a lane name (destination_name) or payload.
        self._log.info(
            "claim phase timing (stage=%s): claim n=%d mean=%.2fms max=%.2fms | "
            "lanes/claim=%.2f rows/claim=%.2f rearm=%d empty=%d claimers=%d",
            stage,
            n,
            self.claim.mean_ms(),
            self.claim.max_ms(),
            lanes_per,
            rows_per,
            self.rearm_lanes,
            self.empty_claims,
            claimers,
        )
        self._reset()
