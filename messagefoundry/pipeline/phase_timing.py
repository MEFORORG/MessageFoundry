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

#: The LANE EPISODE lever is DELIBERATELY SEPARATE from ``MEFOR_DELIVERY_PHASE_TIMING``.
#:
#: The bench rig sets ``MEFOR_DELIVERY_PHASE_TIMING=1`` on EVERY arm — it is a hard prerequisite of the
#: harness's claim/delivery parsing. Riding that flag would therefore pin ``S_lane`` ON for every arm and
#: make the one control that matters IMPOSSIBLE: an instrument-OFF rung at the same offered rate, proving
#: the instrument did not perturb the very ceiling it exists to explain. ``S_lane`` is measured on the
#: dispatcher's hot path, so "it is only a clock read" is an assertion, not evidence — and ADR 0101 does
#: not accept assertions. A separate flag buys a same-session inertness control for one env var.
LANE_EPISODE_TIMING_ENV = "MEFOR_PIPELINE_LANE_EPISODE_TIMING"

#: How often (monotonic seconds) each process emits a rolling phase summary, then resets the window.
#: Bounded — a per-process INFO line every ~5 s, never a line per delivery or per claim.
_DELIVERY_PHASE_EMIT_INTERVAL = 5.0


def delivery_phase_timing_enabled() -> bool:
    """Whether the bench-only phase-timing lever is on (``MEFOR_DELIVERY_PHASE_TIMING`` truthy).

    Default OFF — read ONCE per runner/dispatcher at construction, never per delivery or per claim.
    """
    return os.environ.get(DELIVERY_PHASE_TIMING_ENV, "").strip().lower() in _TRUTHY


def lane_episode_timing_enabled() -> bool:
    """Whether the LANE EPISODE lever is on (``MEFOR_PIPELINE_LANE_EPISODE_TIMING`` truthy).

    Deliberately NOT ``MEFOR_DELIVERY_PHASE_TIMING`` — see :data:`LANE_EPISODE_TIMING_ENV`. The rig sets
    that one on every arm, which would make an instrument-OFF control rung impossible.

    Default OFF — read ONCE per dispatcher at construction, never per episode.
    """
    return os.environ.get(LANE_EPISODE_TIMING_ENV, "").strip().lower() in _TRUTHY


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


class LaneEpisodeTiming:
    """Bench-gated accumulator for the LANE EPISODE — ``S_lane``, the pooled dispatcher's per-lane
    **service time**, plus the lane's non-service OCCUPANCY (STEP 4 ARM 1).

    **What it measures.** One episode = the interval from a lane's processing slot being **RESERVED**
    (the lane enters ``_LanePhase.CLAIMING`` and ``_slots_free`` decrements) to that slot being
    **RELEASED**. It therefore spans the whole serialized per-lane cycle — claim round-trip + prefix
    drain (``send_ack`` + ``mark_done`` + everything between) — which is exactly the quantity that
    neither :class:`DeliveryPhaseTiming` (inside the body only) nor :class:`ClaimPhaseTiming` (the claim
    only) can see, and which the accounted phases do not sum to. TWO windows are kept:

    * ``episode`` — **BOOKED**: the slot was reserved, a prefix was claimed, every item RESOLVED and the
      lane quiesced. A COMPLETED SERVICE. This is ``S_lane``.
    * ``dropped`` — **NOT a service**: the same reserve→release interval for a release via an empty /
      rearm-only claim, a claim error, an operator pause, or a RETRY/STOP outcome. These render no
      delivery, so folding them into ``S_lane`` would poison the mean (empty/rearm releases are frequent
      and sub-millisecond — they would drag ``S_lane`` toward the bare claim time and MANUFACTURE the
      "lanes do not bind" verdict on the load-bearing question). But they still **OCCUPY the lane**: an
      empty-claim lane sits RESERVED across the whole shared ``claim_fifo_heads`` round-trip and cannot
      serve a delivery meanwhile. Discarding them entirely would make the negative branch of the ARM 1
      test UNFALSIFIABLE, so they are counted separately rather than thrown away.

    **How to read it (do NOT misread this as Little's law).** A lane is a single-server queue: it holds
    at most one outstanding claim-or-processing episode at a time (ADR 0066 §4.5). So its maximum
    service rate is the RECIPROCAL OF ITS SERVICE TIME — a definition, measured directly, with no
    ``N = lambda x W`` identity anywhere::

        lambda_max_per_lane ~= rows / S_lane_total            # one lane's ceiling, MESSAGES/s
        aggregate_ceiling   ~= min(lanes, slots) / S_lane     # fan-out-to-all: every lane serves every msg
        utilization         ~= (episode_sum + dropped_sum) / (window x lanes)

    ``min(lanes, slots)`` — **not** ``lanes``. Concurrent episodes are capped by the dispatcher's slot
    pool (``max_processing_lanes``, default **256**), so at the programme's 1,500-connection target a
    reader applying ``lanes / S_lane`` would over-state the ceiling ~5.9x. Both terms are printed
    (``lanes=`` and ``slots=``) so the line stays self-contained and cannot be misapplied.

    ``lambda_max_per_lane`` is derived from **rows**, not from ``1 / mean``. On OUTBOUND/RESPONSE
    ``per_lane_limit`` is hard-clamped to 1, so one episode == one delivery and the two coincide; on
    INGRESS/ROUTED an episode drains a PREFIX of up to ``fifo_claim_batch`` rows, and ``1 / mean`` would
    under-state that stage's message rate by the batch factor while looking identical in shape. The line
    also prints ``rows/episode``, which is SELF-CHECKING: it must read ``1.00`` on ``stage=outbound``, so
    a broken hard-1 assumption surfaces instead of silently skewing ``S_lane``.

    **``utilization`` is what makes the negative branch falsifiable.** ``lambda_max = rows / S_lane``
    is the ceiling of a lane that is back-to-back busy with COMPLETED SERVICES. A lane that burns real
    slot time on empty claims has an actual ceiling BELOW that, and ``S_lane`` alone cannot see the
    difference. So before quoting ``lambda_max``, read ``utilization`` (and cross-check ``empty=`` /
    ``rearm=`` on the CLAIM line of the same 5 s window): a utilization near **1.0** means the lanes
    BIND regardless of what ``S_lane`` reads, and a non-trivial ``dropped``/``empty`` count means the
    reciprocal is an upper bound on an upper bound.

    **stage=outbound is the line to read.** The engine runs ONE dispatcher (and so emits ONE of these
    lines) PER STAGE — ingress / routed / outbound / response. ARM 1's arithmetic is about the OUTBOUND
    stage only. Blending the four is a live, already-committed error on the claim line (the harness
    n-weighted all four into one ``claim_mean`` — see ``shardcert_ladder._CLAIM_RE``); do not repeat it
    here. ``shardcert_ladder.aggregate_episode_timing`` splits ``by_stage`` for exactly that reason.

    **The ARM 1 test, stated so the result cannot be motivated.** TWO priors are live, and they point
    OPPOSITE ways — which is the whole reason to measure rather than assert:

    * **(a) accounted-service arithmetic.** The phases we can already see sum to ``S_acc ~= 24.4 ms``
      (claim 13.37 + send_ack 0.53 + mark_done 10.52), or ~28.8 ms once the claim SLOT WAIT is added
      (STEP 4 §1). Either way the lane-bound ceiling is ``lambda_max = 1 / S_acc ~= 34.7-41.0 msg/s``
      (28.8 ms => **34.7/s**, the figure STEP 4 §1 registers; 24.4 ms => 41.0/s) — ~2.2-2.6x **ABOVE**
      the ~16/s per-lane rate actually observed. On this prior the lanes would **NOT** explain the wall.
    * **(b) the direct cycle prior.** The 2026-07-09 rig ladder put the per-lane delivery cycle at
      **62-190 ms** (module docstring, lines 9-10), i.e. ``lambda_max ~= 5.3-16.1 msg/s`` — which
      **BRACKETS** the ~16/s ceiling. On this prior the lanes **MIGHT** explain it. Caveat: that figure
      is from an OLDER build and was **INFERRED** from the residual, not measured as an episode.

    So do NOT read a particular ``S_lane`` as "the expected one": (a) and (b) cannot both be right, and
    ``S_lane`` exists to DECIDE between them, not to confirm either. Whatever it reads, pair it with
    ``utilization``: a value near 1.0 means the lanes BIND regardless of the mean (the slot time went to
    empty claims — ``dropped`` says so), and a value well below 1.0 with a small mean means the lanes do
    not bind and the cap is elsewhere. **Every outcome is informative.**

    **``1 / S_lane`` is an UPPER BOUND on the per-lane rate, not the rate.** The episode is measured from
    slot RESERVATION (``_LanePhase.CLAIMING``) to release, so it excludes the lane's idle **DWELL** —
    the time before CLAIMING: waiting in the ready deque, and waiting UNDISCOVERED for a producer wake or
    the 0.25 s sweep to notice work. Real per-lane throughput is ``1 / (S_lane + dwell)``, which is lower.
    A measured ``S_lane`` can therefore REFUTE "the lanes bind" (if even the bound sits above the
    ceiling) but cannot by itself PROVE it; that is what ``utilization`` is for.

    Same discipline as its siblings: recorded synchronously on the event loop, never a lock; bounded
    aggregates (count / sum_ns / max_ns) only.

    **PHI (and the policy, stated so the next reader does not "fix" the wrong thing).** A lane key IS a
    ``destination_name`` — a partner identifier — so no lane name and no per-lane structure EVER reaches
    this class or its log line: counts only. That rule is about THIS metrics surface. It is *not* a
    module-wide absolute: the dispatcher's own WARN/ERROR paths and its ``AlertSink`` deliberately name
    the lane (an operator cannot action "some connection crashed"), and that is accepted. Metrics
    aggregate; alerts identify."""

    def __init__(self, *, logger: logging.Logger | None = None) -> None:
        self.episode = _PhaseWindow()  # BOOKED — completed services (S_lane)
        self.dropped = (
            _PhaseWindow()
        )  # NOT a service, but still lane OCCUPANCY (empty/rearm/pause/...)
        self.rows = 0  # Σ items drained across the booked episodes (rows/episode; the λ numerator)
        self._log = logger if logger is not None else log
        # 0.0 (not now) so the FIRST sample emits promptly — same as the sibling accumulators, and the
        # rig's per-rung teardown would otherwise lose a short stage's only window.
        self._last_emit = 0.0
        # Window ORIGIN (monotonic): the instant the PREVIOUS window closed, so ``window=`` is a true
        # since-last-emit wall-clock span and ``utilization`` has a denominator. **A process's FIRST window
        # is a partial RAMP window** — it opens at construction and closes at the first sample, so its
        # span is near-zero and its utilization is not meaningful. That is precisely why
        # ``shardcert_ladder.aggregate_episode_timing`` DROPS each STAGE's first window (per stage, per
        # log — one dispatcher, and so one ramp window, per stage), exactly as the claim/delivery
        # aggregators already do.
        self._window_start = time.monotonic()

    def record_episode(self, ns: int, *, rows: int = 1) -> None:
        """Book ONE completed service. ``rows`` is the number of items the episode drained (always 1 on
        the hard-1 OUTBOUND/RESPONSE stages; up to ``fifo_claim_batch`` on INGRESS/ROUTED)."""
        self.episode.add(ns)
        self.rows += rows

    def record_dropped(self, ns: int) -> None:
        """Book ONE non-service release — the lane WAS reserved for ``ns`` and rendered no delivery. Kept
        out of ``S_lane`` (it is not a service) but counted, because it is real lane occupancy."""
        self.dropped.add(ns)

    def _reset(self, now: float) -> None:
        self.episode.reset()
        self.dropped.reset()
        self.rows = 0
        self._window_start = now
        self._last_emit = now

    def maybe_emit(self, *, stage: str, lanes: int, slots: int, force: bool = False) -> None:
        """Emit the throttled episode summary + reset the window.

        Called from BOTH the booking site AND the claimer loop (and once with ``force`` at dispatcher
        stop): booking alone would never flush the FINAL partial window of a stage that goes quiet —
        which is exactly what every bench rung does once the offer stops and the backlog drains, i.e. the
        tail where ``S_lane`` is most interesting. The claimer keeps ticking (empty claims) while idle, so
        routing the emit through it too guarantees the window lands.

        ``lanes`` is the dispatcher's SERVABLE lane COUNT and ``slots`` its ``max_processing_lanes``
        (never a name) — the ceiling bound is ``min(lanes, slots) / S_lane``, printed so the arithmetic is
        readable straight off the node log without knowing the config."""
        now = time.monotonic()
        if not force and now - self._last_emit < _DELIVERY_PHASE_EMIT_INTERVAL:
            return
        if self.episode.count == 0 and self.dropped.count == 0:
            # Nothing to say: return WITHOUT touching the window or the throttle clock. An all-zero line
            # every 5 s on an idle stage would be noise; but advancing ``_last_emit`` here would be worse —
            # this runs on every claim round-trip, so an empty tick would silently THROTTLE the next real
            # sample for a full window, and a short-lived stage's only window would never be emitted at all.
            # The window simply stays open until it has something in it.
            return
        elapsed = now - self._window_start
        mean_ms = self.episode.mean_ms()
        rows_per = self.rows / self.episode.count if self.episode.count else 0.0
        # λ from ROWS/second, not 1/mean — correct on the batching prefix stages too (see the docstring).
        # Guarded: this runs inside the lane serializer's terminal transition, and a raise there would
        # wedge the lane in PROCESSING (the transition sits outside a try).
        busy_s = self.episode.sum_ns / 1e9
        lambda_max = self.rows / busy_s if busy_s > 0.0 else 0.0
        # Lane occupancy over the window: BOTH the booked services and the non-service reservations, over
        # (window x lanes) lane-seconds. ~1.0 ⇒ the lanes bind REGARDLESS of what S_lane reads.
        occupied_s = (self.episode.sum_ns + self.dropped.sum_ns) / 1e9
        denom = elapsed * lanes
        utilization = occupied_s / denom if denom > 0.0 else 0.0
        # Metrics only — counts + ms + rates; never a lane name (destination_name) or payload.
        self._log.info(
            "lane episode timing (stage=%s): episode n=%d mean=%.2fms max=%.2fms | "
            "rows/episode=%.2f lambda_max_per_lane=%.2f/s | dropped n=%d sum=%.2fms | "
            "lanes=%d slots=%d window=%.2fs utilization=%.3f",
            stage,
            self.episode.count,
            mean_ms,
            self.episode.max_ms(),
            rows_per,
            lambda_max,
            self.dropped.count,
            self.dropped.sum_ns / 1e6,
            lanes,
            slots,
            elapsed,
            utilization,
        )
        self._reset(now)
