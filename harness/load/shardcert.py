# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
r"""N-active engine-shard CERTIFICATION bench (ADR 0073).

Drives N **real** ``serve --shard`` engine processes against ONE unified server store, with the
``harness/config/shardcert`` graph whose shards deliver to OVERLAPPING outbound destinations, and
certifies the ADR 0073 invariants from the **sink/drain** signal (never a ``/stats``-poller peak):

* **No acknowledged loss** — every accept-ACKed message reaches the sink (``acked ⊆ delivered``).
* **Per-lane FIFO** — within each (source-shard, destination) lane the first-arrival order is
  monotonic (``lane_inversions == 0``), non-vacuously (``lanes_observed >= 2``).
* **No duplicate delivery** — no message delivered to the same lane twice on a clean run
  (``lane_repeats``); bounded at-least-once re-delivery is allowed only across a kill.
* **Single delivery consumer per outbound lane** — proven indirectly-but-robustly by no-loss +
  no-duplicate + no-stranded-INFLIGHT together: a mis-owned lane with no consumer would strand, and a
  double-consumed lane would duplicate.
* **Ownership-scoped crash recovery** (kill leg) — SIGKILL one shard mid-load; on its supervisor-style
  restart it recovers ONLY its owned lanes (``reset_stale_inflight(owned=...)``) while siblings are
  untouched, and the whole fleet drains with the invariants above intact.

This is the **local correctness** half of the throughput plan's clean-4-engine-no-loss bench: it
proves N-active is *safe* at a modest rate on one box. It does NOT establish the throughput/sizing
number — that needs the isolated AWS two-box rig (per-process CPU, client isolation). See
``OneDrive\...\aws-bench\n-active-4engine-certification-*``.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import socket
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from harness.config.shardcert._shape import (
    BROADCAST,
    PARTITIONED_FANOUT,
    load_routing,
    reported_shape,
)
from harness.load.coord import (
    DRIVE_COMPLETE,
    DRIVE_GO,
    DRIVE_START,
    DRIVER_ARMED,
    DRIVER_DONE,
    ENGINE_DRAINED,
    SHARDS_READY,
    SINK_BOUND,
    SINK_DONE,
    CoordTimeout,
    FileDropCoord,
)
from harness.load.corpus import SEQ_BASE_STRIDE, build_corpus
from harness.load.correlator import Correlator
from harness.load.enginepoll import EMPTY_POOL_STATS, EnginePoller, PoolStats
from harness.load.failover import EngineNode, _insecure_bind_args
from harness.load.failover_track import FailoverTracker
from harness.load.ids import SHARDCERT_IDS
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import TypeMix, load_profile_text
from harness.load.sender import PersistentConnection
from harness.load.sink import CorrelationSink
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.sharding import (
    owned_destination_set,
    shard_ids,
)

_CONFIG_DIR = "harness/config/shardcert"

# A minimal corpus profile: one ADT^A01 mix (the graph routes every type identically, so the type is
# immaterial), a small template pool, one nominal phase/target to satisfy the profile schema. We drive
# with our own token bucket, not the profile's phases.
_CORPUS_PROFILE = """
[load]
name = "shardcert-corpus"
pool_size = 1
corpus_count_per_trigger = 10
[[load.target]]
name = "s"
host = "127.0.0.1"
port = 3600
types = ["ADT"]
[load.mix]
"ADT^A01" = 1.0
[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 40.0
duration_s = 10.0
"""

_TOKEN_BATCH_CAP = 4096
_MAX_TICK_SLEEP = 0.05

#: The DRIVE half awaits every sender child's DRIVER_DONE BEFORE draining, and a child posts DRIVER_DONE only
#: AFTER it finishes its full hold — so the await necessarily spans the whole hold. A FIXED timeout under-
#: shoots any hold approaching it: a soak whose hold nears this many seconds would abort mid-send, reaping the
#: sinks while the engine still holds backlog and manufacturing a fake collapse in the engine's store-truth
#: (B1 -> B3). So the timeout is DERIVED from the hold (+ drain + this margin), not fixed.
_DRIVER_DONE_MARGIN = 60.0


def _derive_driver_done_timeout(
    hold_seconds: float, drain_timeout: float, override: float | None
) -> float:
    """The DRIVER_DONE await timeout (B1): an explicit ``override`` if given, else ``hold + drain + margin``.
    DRIVER_DONE precedes the drain, so strictly only ``hold + margin`` is needed; ``+ drain`` is a harmless-
    conservative bound. A fixed default (the old 600s) caps long soaks and is the observed B3 trigger."""
    if override is not None:
        return override
    return hold_seconds + drain_timeout + _DRIVER_DONE_MARGIN


#: B6: slack added on top of the SUM of the coordinator's own step timeouts, to absorb coord-file polling
#: jitter and child spawn cost. The sink budget is a bound, never a wait — a sink returns the instant
#: DRIVE_COMPLETE lands — so over-shooting costs nothing, while under-shooting fabricates a collapse.
_DRIVE_COMPLETE_MARGIN = 60.0

#: B7: the ENGINE_DRAINED gate wait must cover the ENGINE's own drain (bounded by the SAME ``drain_timeout``
#: we were given) plus its ``_queue_breakdown`` store read plus coord jitter. A fixed 300.0 silently
#: under-shoots once ``--drain-timeout``/``--soak-drain-timeout`` is raised past ~300 — and there was no CLI
#: flag to raise it with, so lengthening the drain window quietly disarmed the gate.
_ENGINE_DRAINED_MARGIN = 150.0


def _derive_engine_drained_timeout(drain_timeout: float, override: float | None) -> float:
    """The ENGINE_DRAINED gate wait (B7): an explicit ``override`` if given, else ``drain + margin``.

    The drive opens this await AFTER its own advisory ``/stats`` drain returns — which "zeroes under load on
    a unified store", so it can return early — and the engine posts ENGINE_DRAINED only once ITS real
    store-truth drain (bounded by the same ``drain_timeout``) plus ``_queue_breakdown`` completes. So the
    wait scales with ``drain_timeout``, and the old fixed ``300.0`` was safe only while the drain stayed
    under ~150s. At ``drain_timeout=150`` this derives 300.0 — byte-identical to the old default.

    NOTE on severity, against the obvious reading: missing this gate does **not** fabricate a collapse.
    :func:`classify_rung` never consumes the advisory poller, and :func:`build_rung_outcome` falls back to
    ENGINE_RUNG_REPORT for store-truth, so ``engine_ok`` is unaffected. A missed gate only lets the sinks
    tally BEFORE the engine finished delivering, which lands on FROZEN_TAIL (engine drained clean, sink tally
    short) — explicitly benign, excluded from the ceiling, and non-climb-stopping. The real cost is a FALSE
    NEGATIVE: a soak that genuinely held renders FROZEN_TAIL, and ``soak_ok`` (== verdict is SUSTAINED)
    reads False. Conservative direction, still wrong. Hence: derive it, don't re-classify on it."""
    if override is not None:
        return override
    return drain_timeout + _ENGINE_DRAINED_MARGIN


def _derive_drive_complete_timeout(
    hold_seconds: float,
    drain_timeout: float,
    *,
    child_ready_timeout: float,
    engine_drained_timeout: float,
    await_engine_drained: bool,
    driver_done_timeout: float | None = None,
    override: float | None = None,
) -> float:
    """The sink's DRIVE_COMPLETE await timeout (B6): an explicit ``override`` if given, else a bound that
    strictly DOMINATES every coordinator step between the sink's ``SINK_BOUND`` post and the coordinator's
    ``DRIVE_COMPLETE`` post.

    B6 is B1's sibling, and nastier. ``_derive_driver_done_timeout`` fixed only the COORDINATOR's wait; the
    SINK ran a separate hardcoded 600s. The sink's window strictly CONTAINS the driver's — it opens EARLIER
    (at ``SINK_BOUND``, before the remaining sinks bind, before the senders arm, before ``DRIVE_GO``) and
    closes LATER (``DRIVE_COMPLETE`` trails ``DRIVER_DONE`` by the /stats drain poll AND the ENGINE_DRAINED
    gate). So reusing ``hold + drain + margin`` here would still under-shoot. The interval the sink must
    survive, in coordinator order:

    1. ``child_ready_timeout``  — the remaining ``M-1`` sinks spawn and post SINK_BOUND (this sink is already
       waiting; the FIRST sink to bind waits longest).
    2. ``child_ready_timeout``  — the ``K`` sender children spawn and post DRIVER_ARMED.
    3. ``driver_done_wait``     — DRIVE_GO → every DRIVER_DONE (spans the full hold; == the B1 derivation).
    4. ``drain_timeout``        — the advisory remote ``/stats`` drain poll.
    5. ``engine_drained_timeout`` — the PR-C2 store-truth drain gate, when ``await_engine_drained``.

    Each term is the coordinator's OWN timeout for that step, so the sum is the longest run the coordinator
    can have before it gives up and reaps us anyway. A sink that fires earlier records a partial tally and
    drops its socket while the engine is still delivering — and because a sink self-timeout posts no
    ``RUNG_ABORTED`` marker, B3's abort-invalidation never fires and the engine reads a REAL ``stranded>0``
    from store-truth. The result is indistinguishable from a genuine product collapse. Hence: dominate."""
    if override is not None:
        return override
    driver_done_wait = _derive_driver_done_timeout(hold_seconds, drain_timeout, driver_done_timeout)
    return (
        2.0 * child_ready_timeout
        + driver_done_wait
        + drain_timeout
        + (engine_drained_timeout if await_engine_drained else 0.0)
        + _DRIVE_COMPLETE_MARGIN
    )


#: B3: how long the engine waits, ONLY after a FAILED drain, for the drive's RUNG_ABORTED marker before
#: concluding the failure was a genuine collapse rather than a drive-abort artifact. The drive posts the
#: marker the instant it aborts (well before our drain times out), so this only absorbs coord timing jitter;
#: a genuine collapse pays it once as a small tail. Small on purpose.
_ABORT_MARKER_GRACE = 15.0

# Intake-shortfall tolerance for the rate-ladder ceiling test. The token-bucket drive does NOT emit
# exactly ``offered`` messages: above ~200 msg/s it drops a handful of boundary tokens even in a
# perfectly HEALTHY run, so ``achieved_intake`` lands a few short of the theoretical ``offered``. This
# band absorbs that boundary-token noise so a healthy step is not mis-read as a throughput ceiling; a
# real intake shortfall (the fleet cannot ingest the offered rate) is far larger than this.
_INTAKE_TOL = 0.05


# ======================================================================================================
# ARTIFACT 2 — THE STORE POOL (2026-07-14)
# ======================================================================================================
# The bench used to pin ``MEFOR_STORE_POOL_SIZE=8`` with a bare ``setdefault``, one fifth of the PRODUCT
# default, at two sites, recorded nowhere. The pool is per Store instance per PROCESS, so a 4-shard fleet
# ran on 32 concurrent store connections against a product posture of 4 x 40 = 160. At a ~12 ms store
# round-trip and 7 committed txns/message (partitioned), 32 connections cap ingress at ~380 msg/s — AND
# THAT CAP IS FLAT IN L. A pool bind is INDISTINGUISHABLE from the pooled-claim wall in every column we
# have looked at (strands at outbound, claim_mean grows, immune to drive and to the drive box's disk), so
# it would have commissioned the tempdb claim-query rewrite against a HARNESS ARTIFACT.
#
# It does NOT invalidate the banked broadcast runs: at 16 msg/s x 35 txn/msg = 560 txn/s the pool sat at
# ~21% utilisation and the measured acquire_wait mean was 0.0135 ms — no queueing. It is a FUTURE trap.
#
# The fix is NOT a silent bump to 40. It is to make the pool an EXPLICIT, RECORDED, SWEEPABLE variable
# that DEFAULTS TO THE PRODUCT DEFAULT, and to emit the pool's own saturation evidence per rung
# (harness/load/enginepoll.py: PoolStats + the pre-registered tripwire) so a pool bind can never again
# masquerade as a claim wall.


def _product_store_pool_size() -> int:
    """The PRODUCT default pool size (``StoreSettings.pool_size``), read from the engine's own settings
    model rather than copied — a literal here would be a second source for the same constant, which is
    this harness's signature defect class (a stale constant sitting beside the parameter it shadows).

    Falls back to 40 only if the field cannot be introspected (a pydantic-internals change), which keeps a
    bench run alive but is a bug worth noticing."""
    from messagefoundry.config.settings import StoreSettings

    default = StoreSettings.model_fields["pool_size"].default
    return int(default) if isinstance(default, int) else 40


#: The product's ``MEFOR_STORE_POOL_SIZE`` — what a real deployment runs with, and therefore what the bench
#: must run with unless an operator DELIBERATELY sweeps it.
PRODUCT_STORE_POOL_SIZE = _product_store_pool_size()


def _pool_size_bounds() -> tuple[int, int]:
    """ADR 0062's MEASURED inverted-U for the store pool: ``(optimum, cliff)``. IMPORTED, never re-stated —
    a copied constant beside the parameter it shadows is this harness's signature defect."""
    from messagefoundry.store.base import POOL_SIZE_CLIFF, POOL_SIZE_OPTIMUM

    return int(POOL_SIZE_OPTIMUM), int(POOL_SIZE_CLIFF)


#: ADR 0062 (``messagefoundry/store/base.py``) records a MEASURED inverted-U: throughput peaks at ~40
#: connections per engine process and COLLAPSES past ~80 (ACK p99 explodes 30-90x as the extra connections
#: thrash a shared instance). The knob this PR adds is SWEEPABLE — so without a bound it can manufacture a
#: BRAND-NEW fake wall (a catastrophic pool thrash) that looks, column for column, exactly like the claim wall
#: this PR exists to stop being blamed. Sweeping ABOVE the cliff therefore needs an explicit force flag.
POOL_SIZE_OPTIMUM, POOL_SIZE_CLIFF = _pool_size_bounds()


class StorePoolOverCliff(ValueError):
    """Raised when ``--store-pool-size`` is at/over ADR 0062's measured collapse cliff without
    ``--force-store-pool-size``. Not a style objection: past the cliff the pool ITSELF becomes the wall."""


def store_pool_warning(pool_size: int, shard_count: int) -> str | None:
    """The ADR 0062 note for a swept pool, or ``None`` when the size is at/below the measured optimum.

    Pure, so the CLI validators, the fleet launcher and the report all read ONE predicate (the ``filling``
    gate shipped live on one path and dead on the other; that is not repeated here)."""
    if pool_size < POOL_SIZE_OPTIMUM:
        return None
    fleet = pool_size * max(1, shard_count)
    if pool_size >= POOL_SIZE_CLIFF:
        return (
            f"STORE POOL AT/OVER THE ADR 0062 CLIFF: --store-pool-size {pool_size} >= {POOL_SIZE_CLIFF} "
            f"({fleet} connections fleet-wide against ONE unified store). ADR 0062 MEASURED throughput "
            f"COLLAPSING past this point (ACK p99 30-90x) as the extra connections thrash a shared instance. "
            "A ceiling measured here is a POOL-THRASH ceiling and is column-for-column identical to the claim "
            f"wall it would be blamed on. The measured optimum is {POOL_SIZE_OPTIMUM}"
        )
    return (
        f"store pool {pool_size} is AT the ADR 0062 measured optimum ({POOL_SIZE_OPTIMUM}); {fleet} "
        f"connections fleet-wide against ONE unified store. Throughput COLLAPSES past ~{POOL_SIZE_CLIFF} "
        "(the cliff) — do not sweep upward without reading ADR 0062"
    )


def check_store_pool_size(pool_size: int, shard_count: int, *, force: bool = False) -> str | None:
    """Emit the ADR 0062 pool bound: return the note (also printed to stderr) or ``None``. At/over the CLIFF
    it RAISES :class:`StorePoolOverCliff` unless ``force`` — because a run above the cliff cannot produce an
    engine ceiling, only a pool-thrash one, and would be indistinguishable from the wall under investigation."""
    note = store_pool_warning(pool_size, shard_count)
    if note is None:
        return None
    if pool_size >= POOL_SIZE_CLIFF and not force:
        raise StorePoolOverCliff(
            note + " — pass --force-store-pool-size to run above the cliff anyway"
        )
    print(f"WARNING: {note}", file=sys.stderr)
    return note


def resolve_store_pool_size(
    store_env: Mapping[str, str], override: int | None, *, environ: Mapping[str, str] | None = None
) -> int:
    """The EFFECTIVE ``MEFOR_STORE_POOL_SIZE`` for this run, by precedence: an explicit ``override`` (the
    ``--store-pool-size`` flag — a deliberate sweep) > an ambient ``MEFOR_STORE_POOL_SIZE`` already in
    ``store_env``/``environ`` (an operator pinning it out-of-band, which the old ``setdefault`` honoured
    and must keep honouring) > :data:`PRODUCT_STORE_POOL_SIZE`.

    The point is not the number — it is that the number is now CHOSEN in one place and RECORDED, so a run's
    pool size is recoverable from its own artifact. A run whose configuration cannot be reconstructed from
    its report is unauditable."""
    if override is not None:
        if override < 1:
            raise ValueError(f"--store-pool-size must be >= 1, got {override}")
        return override
    import os

    env = os.environ if environ is None else environ
    for source in (store_env, env):
        raw = source.get("MEFOR_STORE_POOL_SIZE")
        if raw is None or not raw.strip():
            continue
        try:
            ambient = int(raw)
        except ValueError as exc:  # a garbage ambient value must be LOUD, not silently the default
            raise ValueError(f"MEFOR_STORE_POOL_SIZE={raw!r} is not an integer") from exc
        if ambient < 1:
            raise ValueError(f"MEFOR_STORE_POOL_SIZE={ambient} must be >= 1")
        return ambient
    return PRODUCT_STORE_POOL_SIZE


def announce_store_pool(pool_size: int, shard_count: int) -> None:
    """Print the RESOLVED pool to stderr at fleet launch, beside the ``G < L`` band warning.

    The default MOVED (a silent 8 → the product 40), and until now the only place that said so was the final
    report — so an operator running the documented command line got a fleet with 5x the store concurrency of
    every banked run with no announcement at the moment it happened, and nothing told them a fresh run and a
    banked one were not config-comparable. A behaviour change must be LOUD AT RUN TIME, not only in the
    artifact."""
    fleet = pool_size * max(1, shard_count)
    delta = (
        ""
        if pool_size == PRODUCT_STORE_POOL_SIZE
        else f"  [SWEPT — the product default is {PRODUCT_STORE_POOL_SIZE}]"
    )
    print(
        f"store pool: MEFOR_STORE_POOL_SIZE={pool_size} per shard process x {shard_count} shards = "
        f"{fleet} concurrent store connections fleet-wide{delta}. ADR 0062 measured optimum="
        f"{POOL_SIZE_OPTIMUM}/process, COLLAPSE CLIFF={POOL_SIZE_CLIFF}/process (past it the extra "
        "connections thrash the shared instance and throughput collapses — a pool-thrash wall reads exactly "
        "like a claim wall). Runs banked before 2026-07-14 ran at 8 (a silent, unrecorded pin) and are NOT "
        "config-comparable with this one.",
        file=sys.stderr,
    )


# ======================================================================================================
# ARTIFACT 5 — THE INBOUND POOL (G) vs THE OUTBOUND POOL (L) (2026-07-14)
# ======================================================================================================
# The ingress and routed stages are ALSO hard-1 per-lane pools, keyed on the INBOUND CONNECTION. The engine
# exposes exactly ``G = shards x lanes_per_shard`` inbound MLLP bands, so the lane-scaling law applies to
# THREE pools, not one:
#
#     ingress ~= G / cycle      routed ~= G / cycle      outbound ~= L / cycle
#
# At the SHIPPED defaults (--shards a,b,c,d --lanes-per-shard 1 --dests 8) that is G = 4 against L = 8: the
# INBOUND pool is already the narrow one. A destination sweep that raises L while G stays at 4 therefore
# PLATEAUS on the inbound side and manufactures a fake pooled-claim wall out of the ingress stage.
#
# G < L is TRUE AT THE DOCUMENTED COMMAND LINE, so this CANNOT be a hard refusal by default — it would red
# every existing invocation and every existing test. It is a loud WARNING + a RECORDED report field
# (`topology.inbound_bands`), with refusal available behind an explicit opt-in for a lane sweep that must
# not silently measure the wrong pool.


class InboundBandTooNarrow(RuntimeError):
    """Raised (only under ``strict_bands``) when the inbound band count ``G`` is below the outbound lane
    count ``L`` — a lane sweep run in this shape measures the INGRESS pool, not the outbound one."""


def inbound_band_count(shard_count: int, lanes_per_shard: int) -> int:
    """``G`` — the number of inbound MLLP bands the fleet exposes: one per (shard, lane). This is the width
    of the INGRESS and ROUTED per-lane pools, exactly as ``dests`` (L) is the width of the OUTBOUND one."""
    return shard_count * lanes_per_shard


#: ⚠️ WHAT A CLEAN ``G >= L`` VERDICT DOES **NOT** SAY. The three-pool law (``ingress ≈ G/cycle``,
#: ``routed ≈ G/cycle``, ``outbound ≈ L/cycle``) assumes ONE ``cycle``, and it is not one: the ingress cycle
#: (decode + parse + strict-validate + commit) is strictly HEAVIER than the outbound one. So the counts can
#: be equal — G == L — while the INBOUND pool is still the narrower one in capacity terms. This check compares
#: lane COUNTS, not cycle TIMES, so a clean bill of health here EXCLUDES a count asymmetry and nothing more.
#: It is carried in the warning text AND recorded in the report (``topology.inbound_band_check_basis``) so the
#: absence of a warning can never be read as "the ingress pool is not the constraint".
INBOUND_BAND_CHECK_BASIS = (
    "compares lane COUNTS (G vs L), NOT cycle times — and the INGRESS cycle (decode + parse + "
    "strict-validate + commit) is HEAVIER than the outbound one, so at G == L the inbound pool is STILL the "
    "narrower one in capacity. A clean G >= L verdict does NOT exclude an ingress bind."
)


def inbound_band_warning(shard_count: int, lanes_per_shard: int, dests: int) -> str | None:
    """The pre-flight note when ``G < L``, or ``None`` when the inbound side is at least as wide as the
    outbound one. Pure, so both the co-located and the two-box halves call the SAME predicate (the
    ``filling`` gate shipped live on one path and dead on the other; that is not repeated here).

    ``None`` is NOT a clean bill of health for the ingress pool — see :data:`INBOUND_BAND_CHECK_BASIS`. The
    trigger stays at ``G < L`` (a strict COUNT asymmetry, which is the only thing this predicate can actually
    prove) rather than ``G <= L``; the cycle-time caveat is carried explicitly in the text and the report
    instead, so nothing is silently assumed either way."""
    g = inbound_band_count(shard_count, lanes_per_shard)
    if g >= dests:
        return None
    return (
        f"INBOUND BAND NARROWER THAN THE OUTBOUND LANES: G = shards({shard_count}) x "
        f"lanes_per_shard({lanes_per_shard}) = {g} inbound bands vs L = dests({dests}) outbound lanes. "
        "The ingress and routed stages are hard-1 per-lane pools keyed on the INBOUND connection, so this "
        f"run's intake is capped by G ({g} lanes), not by L. A lane/destination sweep in this shape "
        "PLATEAUS on the ingress pool and reads as a fake outbound/claim wall. Raise --lanes-per-shard "
        f"(>= {-(-dests // max(1, shard_count))}) or lower --dests before attributing any plateau. "
        f"NOTE: this check {INBOUND_BAND_CHECK_BASIS}"
    )


#: THE LOUDNESS BAR for the ``G < L`` pre-flight. ``G < L`` is TRUE AT THE SHIPPED DEFAULTS (4 bands vs 8
#: dests = 2x), so an unconditional stderr WARNING fires on 100% of invocations — and a warning that ALWAYS
#: fires carries no information and is tuned out by the second rig session, which is the failure mode every
#: constant alarm has. The NOTE is still RECORDED on every run (the report field is unconditional — the run
#: must stay auditable), but the SHOUT is reserved for the shape where the inbound pool is so much narrower
#: that the run cannot possibly be measuring the outbound one: a destination/lane SWEEP (L >= 4G, e.g.
#: --dests 64 against G=4), where silently measuring the ingress pool wastes the whole experiment.
_INBOUND_BAND_SHOUT_RATIO = 4.0


def check_inbound_bands(
    shard_count: int, lanes_per_shard: int, dests: int, *, strict: bool = False
) -> str | None:
    """Emit the ``G < L`` pre-flight: return the note (also printed to stderr) or ``None``. Under ``strict``
    (the opt-in ``--strict-inbound-bands``) it RAISES instead — for a lane sweep, where silently measuring
    the ingress pool would be the whole experiment wasted.

    The note is returned (⇒ RECORDED in the report) on EVERY ``G < L`` run. Only the stderr line is graded:
    a loud ``WARNING`` at ``L >= 4G`` (a sweep — see :data:`_INBOUND_BAND_SHOUT_RATIO`), a quiet ``note`` at
    the shipped-default 2x, where the condition holds on every single run and shouting about it teaches the
    operator to ignore it."""
    note = inbound_band_warning(shard_count, lanes_per_shard, dests)
    if note is None:
        return None
    if strict:
        raise InboundBandTooNarrow(note)
    g = inbound_band_count(shard_count, lanes_per_shard)
    sweep = g > 0 and dests >= g * _INBOUND_BAND_SHOUT_RATIO
    prefix = "WARNING" if sweep else "note"
    print(f"{prefix}: {note}", file=sys.stderr)
    return note


class FanoutLaneHeadroomTooLow(RuntimeError):
    """Raised (only under ``strict_bands``) when a partitioned-FANOUT run's outbound lanes are too few for
    the fan-out D: each accepted message occupies D of the ``dests`` strict-FIFO lanes, so the effective
    outbound width is ``dests / D`` — below the inbound band count ``G`` the outbound cycle re-caps ingress
    and the run measures the BENCH lane cycle, not the engine."""


def fanout_lane_warning(
    shard_count: int, lanes_per_shard: int, dests: int, delivering: int
) -> str | None:
    """The pre-flight note when a fan-out run's effective outbound width ``dests / D`` is narrower than the
    inbound band count ``G`` (⇒ the OUTBOUND fan-out lanes, not the engine, cap ingress), else ``None``.

    D-AWARE where :func:`check_inbound_bands` is not: that check compares ``G`` to the RAW ``dests``, but
    under fan-out D each message delivers to D distinct lanes, so the outbound pool serves only ``dests / D``
    messages-worth of ingress per cycle. Neither ``check_inbound_bands`` (G vs raw dests) nor the
    ``RungFidelity`` under-driven gate can catch this: a fan-out lane-saturated run is genuinely driven and
    sustains the scale-free ``S == A*D`` no-loss identity losslessly, so it serialises as ADMISSIBLE/
    SUSTAINED — a manufactured sub-engine plateau published as an engine wall (the B-defect class this
    harness exists to prevent). The balance condition ``dests >= D * G`` needs no ceiling/rate constant
    (``per_lane_rate`` cancels): it says the effective outbound width ``dests/D`` must be at least ``G``."""
    g = inbound_band_count(shard_count, lanes_per_shard)
    if dests >= delivering * g:
        return None
    return (
        f"FAN-OUT LANES NARROWER THAN THE INBOUND BAND: at D = DELIVERING({delivering}) each message "
        f"occupies D of DESTS({dests}) strict-FIFO outbound lanes, so the effective outbound width "
        f"dests/D = {dests // delivering} is below G = shards({shard_count}) x "
        f"lanes_per_shard({lanes_per_shard}) = {g} inbound bands. The OUTBOUND fan-out pool then caps "
        f"ingress (~dests/(D*cycle)), so this run PLATEAUS on the bench lane cycle and reads as a fake "
        f"engine wall — losslessly, so no drive/fidelity gate catches it. Raise --dests to >= D*G "
        f"({delivering * g}) or lower --delivering before attributing any plateau to the engine."
    )


def check_fanout_lane_headroom(
    shard_count: int,
    lanes_per_shard: int,
    dests: int,
    delivering: int,
    routing: str,
    *,
    strict: bool = False,
) -> str | None:
    """Emit the fan-out lane-headroom pre-flight: return the note (also printed to stderr) or ``None``.
    A NO-OP unless ``routing`` is partitioned-fanout (broadcast/partitioned have fan-out 1, whose balance is
    exactly :func:`check_inbound_bands`'s G vs dests). Under ``strict`` it RAISES instead — a mis-sized D>1
    certification soak silently measures the bench lane cycle, so refusing is correct there. The note is
    always a WARNING (unlike the quiet G<L note): a fan-out headroom breach fabricates a plateau, so it must
    never be tuned out."""
    if routing != PARTITIONED_FANOUT:
        return None
    note = fanout_lane_warning(shard_count, lanes_per_shard, dests, delivering)
    if note is None:
        return None
    if strict:
        raise FanoutLaneHeadroomTooLow(note)
    print(f"WARNING: {note}", file=sys.stderr)
    return note


# ======================================================================================================
# ARTIFACT 4 — THE PER-RUNG FIDELITY GATE (2026-07-14)
# ======================================================================================================
# ``classify_rung`` never compares ``acked`` to ``offered``, and never sees ``sent`` at all. Its SUSTAINED
# arm is ``no_loss`` — the identity ``S == A x D``, which is SCALE-FREE: a rung that offered 520/s, pushed
# 16/s, and delivered all 16 losslessly is SUSTAINED. So a DRIVE SHORTFALL (the load generator could not
# push the plan) and an ENGINE INTAKE BIND (the engine would not take it) both serialise as SUSTAINED, and
# the ceiling that comes out is a pure function of the PLAN.
#
# THAT DISTINCTION IS THE WHOLE POINT: "my load generator is too small" and "the engine bound" are opposite
# findings, and the ladder could not tell them apart. Partitioned needs ~520 msg/s of drive against the ~16
# the rig pushes today, so an UNDER-DRIVEN rung is the DEFAULT expectation, not an edge case.
#
# The predicate lives HERE, beside :func:`_is_ceiling`, and is called from BOTH rung record types
# (``ShardCertStepRecord`` co-located, ``shardcert_ladder.RungOutcome`` two-box). The precedent is explicit:
# the ``filling`` gate shipped LIVE on the co-located path and DEAD on the two-box one — the only path
# STEP 5 runs — and nobody noticed for a day. One predicate, two callers, both pinned by tests.


class RungFidelity(enum.Enum):
    """Whether a rung is ADMISSIBLE EVIDENCE ABOUT THE ENGINE, and if not, WHOSE fault it was.

    ⚠️ **A ``sent`` SHORTFALL DOES NOT, ON ITS OWN, NAME A CULPRIT.** ``sent`` is incremented only after a job
    is popped from a BOUNDED queue (``sender.py:185``), and the write loop ``await writer.drain()``s before
    popping the next. When the engine stops reading its socket the TCP window fills, ``drain()`` blocks, the
    queue fills, ``submit_nowait()`` refuses, and the message is NEVER SENT. So ``offered - sent`` is
    **ENGINE-PACED**, and the gate needs the ``deferred_*`` cause split (:class:`~harness.load.metrics.
    Counters`) to say who caused it. The verdicts below are grouped by WHETHER THE RATE REACHED THE WIRE."""

    #: The drive pushed the plan and the engine took it — the rung measures the ENGINE.
    ADMISSIBLE = "admissible"
    #: ``sent`` short, and the deferrals are dominated by the GENERATOR's own tick-lag / no-target (it never
    #: reached a connection). A genuine RIG limit: void the rung and add sender workers / drive boxes.
    DRIVE_SHORTFALL = "drive_shortfall"
    #: ``sent`` short, and the deferrals are dominated by FULL SEND BUFFERS — i.e. the ENGINE stopped reading
    #: the socket and TCP backpressure throttled the drive. A REAL ENGINE FINDING (the intake would not
    #: absorb the offered rate), and the single most likely signature of the ARTIFACT-5 ingress-pool bind.
    #: It KEEPS its rate label and may bracket the ceiling; it is NOT a rig failure.
    BACKPRESSURE_BIND = "backpressure_bind"
    #: ``sent`` short and the cause is **NOT ATTRIBUTED** (the ``deferred_*`` split was not recorded — an
    #: older drive half or a synthetic record). Cause-neutral by construction: the plan was not put on the
    #: wire and we CANNOT say whose fault it was. VOID (fail-closed), but it must never print "fix the rig".
    OFFER_SHORTFALL = "offer_shortfall"
    #: The drive DID push it and the ENGINE would not accept it (``acked`` short of a ``sent`` that was
    #: fine). A REAL finding — and a DIFFERENT one from a lane/claim wall: the bind is at INTAKE.
    ENGINE_INTAKE_BIND = "engine_intake_bind"
    #: The inputs to the gate were not recorded (an older report / a synthetic record). FAIL-CLOSED: the
    #: rung is VOID for the ceiling, because "we did not measure it" must never read as "it passed".
    UNKNOWN = "unknown"

    @property
    def admissible(self) -> bool:
        """The rung may PIN a ceiling: driven to plan AND accepted to plan."""
        return self is RungFidelity.ADMISSIBLE

    @property
    def driven(self) -> bool:
        """THE OFFERED RATE REACHED THE ENGINE (or the engine itself refused to let it) — so the rung's RATE
        LABEL is real and it may BRACKET the ceiling.

        This is the predicate that separates "we measured the engine at rate R" from "no rate was ever
        established". :attr:`ENGINE_INTAKE_BIND` and :attr:`BACKPRESSURE_BIND` are both ENGINE findings: the
        drive offered R and the engine would not absorb it. Excluding them from the bracket would throw away
        the one result a saturation climb exists to produce (an engine saturating at R is EXACTLY
        ``acked < offered``), and would print "no ceiling reached — raise the ladder" on a real collapse."""
        return self in (
            RungFidelity.ADMISSIBLE,
            RungFidelity.ENGINE_INTAKE_BIND,
            RungFidelity.BACKPRESSURE_BIND,
        )

    @property
    def not_driven(self) -> bool:
        """The rate was NOT established on the wire, or we cannot say it was. Such a rung can neither pin nor
        bracket: a bracket is a RATE, and no rate was proven here. Folds into ``setup_degraded``."""
        return not self.driven


#: The gate VERSION stamped into the JSON beside every fidelity verdict, so a reader cannot silently compare
#: a run scored under one set of bars against a run scored under another.
#:
#: v2 (2026-07-14): the ``sent``-shortfall arm is CAUSE-SPLIT. v1 returned DRIVE_SHORTFALL for ANY ``sent``
#: shortfall — but ``sent`` is engine-paced (see :class:`RungFidelity`), so v1 classified a real engine
#: backpressure bind as a rig failure, voided the rung, and told the operator to go buy drive boxes. v2 reads
#: the ``deferred_backpressure`` / ``deferred_schedule`` split and returns BACKPRESSURE_BIND, DRIVE_SHORTFALL
#: or (unattributed) OFFER_SHORTFALL. A v1 ``drive_shortfall`` verdict is NOT comparable to a v2 one.
FIDELITY_GATE_VERSION = 2

#: PRE-REGISTERED FIDELITY BARS. ``sent`` is counted at WRITE-BUFFER time (see the accounting note on
#: ``harness/load/connscale/runner.py``), so ``sent >= 0.98 x offered`` is emphatically NOT proof the bytes
#: reached the engine — it is proof the LOAD GENERATOR was able to OFFER the plan, which is exactly what a
#: DRIVE SHORTFALL test needs and all it claims. The 2% band absorbs the token-bucket's boundary drops.
#:
#: ⚠️ THE BUCKET'S ACTUAL SHORTFALL HAS NEVER BEEN MEASURED, and this bar is TIGHTER than :data:`_INTAKE_TOL`
#: (5%), the band the sustain bar has always given the same physical phenomenon. A dropped token is a message
#: never SENT, so if the bucket really drops >2% of tokens at high rates, a HEALTHY rung would be voided as a
#: DRIVE SHORTFALL — discarding real engine evidence as a rig failure. Two reasons it stays at 0.98 anyway:
#: (1) it is the PRE-REGISTERED bar, and loosening a pre-registered gate on an UNMEASURED argument is the
#: same move this whole exercise exists to stop; (2) ``_INTAKE_TOL``'s own comment calls the drop "a handful
#: of boundary tokens" — a handful out of 12,000 offered is ~0.1%, not 2%, so 5% is a generous tolerance band,
#: NOT a measurement of the bucket, and aligning to it would be anchoring to nothing.
#: DERIVE IT FROM THE BANKED RUNS BEFORE THE FIRST PARTITIONED CLIMB. Both rung records emit the three keys
#: needed, but THEY ARE NOT SPELLED THE SAME and an operator told to read one name will not find it on the
#: other path — so, exactly:
#:   * co-located (``shardcert_ladder`` v2, per record): ``offered``, ``sent``, ``sent_ratio``
#:   * two-box    (``shardcert_ladder_two_box`` v6, per climb rung): ``offered_ingress``, ``sent``,
#:     ``sent_ratio``  ← the offered key is ``offered_ingress``, NOT ``offered``
#: (This comment previously named ``offered`` for both, and ``sent_ratio`` did not exist on the two-box
#: record at all — the remediation plan for the one UNMEASURED pre-registered bar pointed at a missing key,
#: on the only path STEP 5 runs. Both are now emitted and both are pinned by tests.)
#: If the measured shortfall exceeds 2%, restate this constant FROM that measurement and bump
#: :data:`FIDELITY_GATE_VERSION`.
#: The error direction is conservative meanwhile: a mis-void REFUSES to publish a ceiling, never inflates one.
_FIDELITY_SENT_FLOOR = 0.98
#: ``acked`` is a wire-confirmed accept-ACK, so this bar IS an engine statement. It matches ``_INTAKE_TOL``
#: (5%) on purpose: the SAME shortfall the shared ``_is_ceiling`` bar has always called an intake failure.
_FIDELITY_ACKED_FLOOR = 0.95

#: Public aliases. The two-box ladder REPORTS these bars (a run scored under an un-named bar is unauditable),
#: and a cross-module read of a private name is how a constant ends up duplicated and then stale.
FIDELITY_SENT_FLOOR = _FIDELITY_SENT_FLOOR
FIDELITY_ACKED_FLOOR = _FIDELITY_ACKED_FLOOR


def rung_fidelity(
    *,
    sent: int,
    acked: int,
    offered: int,
    deferred_backpressure: int = -1,
    deferred_schedule: int = -1,
) -> RungFidelity:
    """Classify a rung's FIDELITY TO ITS OWN PLAN — the gate ``classify_rung`` never had.

    ``FIDELITY := (sent >= 0.98 x offered) AND (acked >= 0.95 x offered)``. The ``sent`` arm is checked
    FIRST, because when the plan never went on the wire the engine's low ``acked`` is a CONSEQUENCE, not a
    finding.

    ⚠️ **BUT A ``sent`` SHORTFALL DOES NOT NAME A CULPRIT, AND v1 PRETENDED IT DID.** ``sent`` is incremented
    only after a job is popped from a BOUNDED queue and the writer ``drain()``s before popping the next
    (``sender.py``), so ENGINE BACKPRESSURE — the engine refusing to read its socket — stalls the write loop,
    fills the queue, and makes ``submit_nowait()`` refuse. The refused offers land in ``deferred``, and
    ``sent`` never advances. The governor's own docstring has always said so ("if the pool can't accept a
    send (ENGINE LAGGING) it's counted as *deferred*"). v1 read that exact signature as DRIVE_SHORTFALL and
    told the operator "this rung says NOTHING about the engine; go add drive boxes" — discarding the single
    most likely signature of a REAL ingress bind (ARTIFACT 5's own hypothesis) as a rig failure.

    So the shortfall is attributed from the counters that already existed and were merged:

    * ``deferred_backpressure`` dominant ⇒ :attr:`RungFidelity.BACKPRESSURE_BIND` — the ENGINE would not take
      the bytes. A real engine finding; it KEEPS its rate and may bracket the ceiling.
    * ``deferred_schedule`` dominant ⇒ :attr:`RungFidelity.DRIVE_SHORTFALL` — the generator could not even
      schedule the sends. A real rig limit.
    * neither recorded (``-1``) ⇒ :attr:`RungFidelity.OFFER_SHORTFALL` — cause-neutral. VOID (fail-closed),
      but it must NOT be reported as a rig failure, because we did not measure that.

    Unrecorded ``sent``/``acked`` (the ``-1`` sentinel) or a non-positive ``offered`` are
    :attr:`RungFidelity.UNKNOWN`, which is VOID for the ceiling. FAIL-CLOSED, never a silent skip: a gate
    that abstains into "pass" is a dead gate that reads exactly like a live one."""
    if offered <= 0 or sent < 0 or acked < 0:
        return RungFidelity.UNKNOWN
    if sent < offered * _FIDELITY_SENT_FLOOR:
        # WHOSE shortfall? The counters, not the shortfall itself, arbitrate.
        if deferred_backpressure < 0 or deferred_schedule < 0:
            return (
                RungFidelity.OFFER_SHORTFALL
            )  # not attributed — say exactly that, and nothing more
        if deferred_backpressure > deferred_schedule:
            return RungFidelity.BACKPRESSURE_BIND
        if deferred_schedule > deferred_backpressure:
            return RungFidelity.DRIVE_SHORTFALL
        # A dead heat (including 0 == 0: the offers vanished with neither cause counted) attributes to
        # NEITHER side. Naming a culprit on a tie would be a coin-flip dressed as a measurement.
        return RungFidelity.OFFER_SHORTFALL
    if acked < offered * _FIDELITY_ACKED_FLOOR:
        return RungFidelity.ENGINE_INTAKE_BIND
    return RungFidelity.ADMISSIBLE


def fidelity_note(
    fidelity: RungFidelity,
    *,
    sent: int,
    acked: int,
    offered: int,
    deferred_backpressure: int = -1,
    deferred_schedule: int = -1,
) -> str | None:
    """The operator-facing reason a rung is VOID for the ceiling, or ``None`` when it is admissible. Says
    WHOSE fault it was in words — and, where the cause was NOT measured, says THAT instead of guessing."""
    if fidelity is RungFidelity.ADMISSIBLE:
        return None
    short = f"sent {sent} of {offered} offered ({sent / offered:.1%} < {_FIDELITY_SENT_FLOOR:.0%})"
    causes = f"deferred: backpressure={deferred_backpressure} schedule={deferred_schedule}"
    if fidelity is RungFidelity.DRIVE_SHORTFALL:
        return (
            f"FIDELITY VOID — DRIVE SHORTFALL: the load generator {short}, and the deferrals are dominated "
            f"by the GENERATOR's own tick-lag / no-target ({causes}) — the sends never reached a connection, "
            "so the engine never saw them. This rung says NOTHING about the engine; it measures the RIG. "
            "Add sender workers / drive boxes and re-run — do NOT quote it as a ceiling"
        )
    if fidelity is RungFidelity.BACKPRESSURE_BIND:
        return (
            f"ENGINE BACKPRESSURE BIND (a REAL engine finding, NOT a rig failure): the load generator {short}"
            f" — but the deferrals are dominated by FULL SEND BUFFERS ({causes}), i.e. the ENGINE STOPPED "
            "READING ITS SOCKET and TCP backpressure throttled the drive. The offered rate WAS established "
            "against the engine and the engine would not absorb it. The bind is at INTAKE (ingress/routed "
            "are hard-1 per-lane pools keyed on the INBOUND connection — check G, not L). This rung KEEPS "
            "its rate label and MAY bracket the ceiling; it is NOT admissible to PIN one"
        )
    if fidelity is RungFidelity.OFFER_SHORTFALL:
        return (
            f"FIDELITY VOID — OFFER SHORTFALL (CAUSE NOT ATTRIBUTED): the load generator {short}. The "
            f"deferral cause split was NOT RECORDED for this rung ({causes}), so we CANNOT say whether the "
            "rig ran out or the ENGINE applied backpressure — those are opposite findings and this rung "
            "distinguishes neither. VOID for the ceiling (fail-closed). Re-run on a drive half that records "
            "deferred_backpressure/deferred_schedule before attributing this to anything"
        )
    if fidelity is RungFidelity.ENGINE_INTAKE_BIND:
        return (
            f"FIDELITY VOID — ENGINE INTAKE BIND: the drive offered it (sent={sent} of {offered}) and the "
            f"ENGINE accepted only {acked} ({acked / offered:.1%} < {_FIDELITY_ACKED_FLOOR:.0%}). A REAL "
            "finding, and a DIFFERENT one from a lane/claim wall: the bind is at INTAKE (ingress/routed are "
            "hard-1 per-lane pools keyed on the INBOUND connection — check G, not L)"
        )
    return (
        f"FIDELITY UNKNOWN — the gate's inputs were not recorded (sent={sent} acked={acked} "
        f"offered={offered}); the rung is VOID for the ceiling. An unmeasured gate is never a pass"
    )


#: WHY a ceiling was suppressed, keyed by the NOT-DRIVEN fidelity that suppressed it. Only the not-driven
#: verdicts appear: a rung the ENGINE bound (intake/backpressure) is a real finding at a real rate and KEEPS
#: its ceiling. ``offer_shortfall`` is deliberately its own reason and NOT folded into ``drive_shortfall`` —
#: "the plan did not reach the wire and we did not measure why" is a different (weaker) claim than "the rig
#: ran out", and collapsing them would re-introduce the fabrication in the report instead of the gate.
_CEILING_VOID_REASONS: dict[RungFidelity, str] = {
    RungFidelity.DRIVE_SHORTFALL: "drive_shortfall",
    RungFidelity.OFFER_SHORTFALL: "offer_shortfall",
    RungFidelity.UNKNOWN: "fidelity_unknown",
}


# ======================================================================================================
# FILLING DETECTOR (``fill_ratio``) — SCOPE FIRST, because the scope is the whole story (2026-07-13).
# ======================================================================================================
# **This gate applies to the CO-LOCATED ladder ONLY** — ``run_shardcert_ladder`` (CLI: ``harness shardcert
# --rate-ladder``), the single-process path where ONE process both sends and sinks, so a ``Correlator`` can
# join send↔receive timestamps and produce a real E2E stream.
#
# **It does NOT apply to the TWO-BOX ladder** (``shardcert-engine-ladder`` / ``shardcert-drive-ladder``) —
# the path STEP 4 actually runs. There, senders and sinks are SEPARATE PROCESSES on the load-gen box and the
# coordinator is metadata-only: a sink's ``Correlator`` never sees ``on_send``, so ``metrics.e2e`` is empty
# by construction and ``ShardCertDriveReport`` carries no E2E fields at all. The two-box per-rung verdict is
# ``shardcert_ladder.classify_rung`` (drained ∧ no_loss ∧ cross-observer agreement), which has NO filling
# term. So:
#
#   *** EVERY TWO-BOX CEILING — INCLUDING THE ~16 msg/s STEP-4 PLATEAU — IS MEASURED WITHOUT THIS GATE. ***
#
# ``ShardCertDriveReport.ceiling`` therefore ABSTAINS from the filling term EXPLICITLY (it passes
# ``filling=False`` to :func:`_is_ceiling` rather than letting four unset fields default to a 0 sentinel —
# a silent abstain is how a dead gate reads as a live one). Plumbing a real filling signal into the two-box
# tier needs a cross-process E2E correlation that does not exist yet; until it does, do NOT claim the rig's
# ceiling is filling-corrected. See ``docs/benchmarks/shardcert-ceiling-ladder.md``.
#
# **NOT the STEP-4 §7 "M2" validity check.** An earlier draft called this "M2" and it is a DIFFERENT quantity:
# STEP-4's M2 splits a rung's steady cohort by ENGINE received-ts, compares the STORE's ``E2E_complete``
# median (``scripts/bench/stage_residency.py``), bars a SYMMETRIC relative difference at 0.10, and its
# purpose is to EXCLUDE a rung from a regression — the doc explicitly says a near-ceiling rung legitimately
# fails it and "BRACKETS; it does not regress". This gate splits by SINK RECEIPT time, compares the drive's
# SOCKET-observed latency, bars a RATIO at 1.5, and LOWERS a reported ceiling. Two bars under one name in
# one programme is a live confusion hazard, so the name "M2" is not used here.
#
# **What it does.** A rung can be lossless-and-eventually-drained (``no_loss``) yet still be FILLING — its
# in-flight backlog growing while the offered load holds, so the (generous) drain window merely clears a
# backlog that was still climbing. Such a rung is NOT a sustainable operating point. We detect it WITHOUT a
# store-gauge slope (which the two-box path found sign-unstable across rates, B5): the HOLD's E2E stream is
# split in half and the SECOND half's median latency is compared to the FIRST's. At a truly sustained rung
# the two halves are ~equal (ratio ~ 1.0); at a filling rung E2E climbs monotonically.
#
# **Calibration provenance (stated, because it is NOT this instrument's).** The "1.37-3.06 on run s4-climbA"
# figures quoted for this bar were measured STORE-SIDE (``E2E_complete`` out of ``message_events``, via
# ``scripts/bench/stage_residency.py``) on the two-box run — which, per the scope above, this code cannot
# see. So 1.5 is an INHERITED, PROVISIONAL bar for a related-but-not-identical quantity, chosen well above
# the ~1.0 steady value so a clearly-steady rung never false-fails. Re-calibrate it against a co-located
# ladder run before quoting a ``fill_ratio``-gated ceiling as precise.
_FILLING_RATIO = 1.5
# Minimum correlated E2E samples IN EACH half before the ratio is trusted; below it the ratio is too noisy
# to gate on, so the filling criterion ABSTAINS (the rung is judged on the pre-existing no_loss/intake bars
# alone). The gate only ever ADDS a ceiling when it has clear evidence — it never false-fails on thin data.
_FILLING_MIN_SAMPLES = 30
# Fraction of the hold discarded as WARM-UP before the two comparable halves begin. The cold-start transient
# (an empty pipeline ⇒ artificially LOW latency) would otherwise sit entirely in the first half and inflate
# the ratio — biasing the gate toward declaring a rung FILLING, i.e. toward the very ceiling-lowering it is
# built to produce. A motivated instrument is worse than no instrument, so the ramp is dropped and the two
# halves are EQUAL-LENGTH steady cohorts: ramp = [0, R*H), first = [R*H, (R+(1-R)/2)*H), second = [.., H).
_FILLING_RAMP_FRACTION = 0.2


class ShardCertNode(EngineNode):
    """An :class:`EngineNode` that serves ONE shard: injects ``--shard <id>`` into the argv (and keeps
    per-PID :meth:`kill` for the crash leg, which ``supervise()`` does not expose). Everything else —
    the store, the graph shape, and the sink target — comes from the shared ``MEFOR_*`` env."""

    def __init__(
        self, shard: str, api_port: int, *, env: Mapping[str, str], config_dir: str, cwd: Path
    ) -> None:
        super().__init__(f"shard-{shard}", api_port, env=env, config_dir=config_dir, cwd=cwd)
        self.shard = shard

    async def start(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "messagefoundry",
            "serve",
            "--config",
            self._config_dir,
            "--shard",
            self.shard,
            "--port",
            str(self.api_port),
            "--env",
            "dev",
            # A non-loopback shard bind (the two-box cert binds 0.0.0.0 for off-box reach) needs the dev
            # override so serve's off-loopback plaintext-MLLP gate warns instead of refusing; a co-located
            # loopback bind adds nothing (byte-identical argv — the single-box path is unchanged).
            *_insecure_bind_args(self._env),
            env=self._env,
            cwd=str(self._cwd),
            stdout=self._log,
            stderr=asyncio.subprocess.STDOUT,
        )


@dataclass
class ShardCertReport:
    """The certification outcome — sink/drain-derived, plus store diagnostics."""

    shards: tuple[str, ...]
    owned: dict[str, list[str]]  # shard -> owned destination lanes (rendezvous)
    killed_shard: str | None
    sent: int
    acked: int
    delivered_distinct: int
    sink_received: int
    acked_not_delivered: int
    lane_inversions: int
    lanes_observed: int
    lane_repeats: int
    engine_done: int
    engine_dead: int
    in_pipeline_final: int
    drained: bool
    drain_seconds: float | None
    stranded_nonterminal: int
    queue_breakdown: str
    # --- sizing-bench extras (default sentinels ⇒ the correctness/kill path is unchanged) ---
    offered: int = 0  # intended load over the hold (round(aggregate_rate * hold_seconds))
    achieved_intake: int = 0  # messages the fleet accept-ACKed (== acked; the intake number)
    in_pipeline_peak: int = -1  # peak NOT-DONE rows during the hold; -1 = not sampled (default)
    #: END-TO-END message latency (2026-07-13). The correlator has been recording into `metrics.e2e`
    #: (`correlator.py:67`) all along and the report summarised `ack` ONLY — so the single measurement of
    #: a FULL message's life (send -> sink arrival) was built and thrown away on every run ever done.
    #: VALID ONLY where the sender and the correlating sink share one process and one clock (this
    #: single-box report and the two-box DRIVER half). In the multi-process drive the sinks are separate
    #: processes and every arrival is a `correlation_miss` — it is NOT surfaced there, deliberately.
    #: `e2e_count == 0` means "not measured", never "zero latency".
    e2e_count: int = 0
    e2e_p50_ms: float = 0.0
    e2e_p99_ms: float = 0.0
    #: The HOLD's two EQUAL-LENGTH steady cohorts — the ladder's ``fill_ratio`` filling detector reads
    #: these (2026-07-13). ``metrics.e2e`` is swapped per phase (ramp → first → second → drain), so the two
    #: halves' medians are separable while the aggregate (``e2e_p50_ms`` etc.) stays the merge of ALL FOUR
    #: phases and is byte-identical to the pre-split value. The warm-up ramp and the post-hold DRAIN are
    #: deliberately EXCLUDED from both halves (see the ``_FILLING_RATIO`` block).
    #:
    #: Populated ONLY on the SIZING path (``capture_peak=True``). On the correctness/kill path NO swap ever
    #: happens, so BOTH halves stay at the 0 sentinel ("not measured") and :attr:`ShardCertStepRecord.
    #: fill_ratio` ABSTAINS. (It is not the case that the first half then holds the full-run aggregate — the
    #: unswapped run lives in the ramp histogram, which is not reported. An earlier docstring claimed
    #: otherwise; a reader who trusted it would divide by a full-run denominator.)
    e2e_first_half_p50_ms: float = 0.0
    e2e_first_half_count: int = 0
    e2e_second_half_p50_ms: float = 0.0
    e2e_second_half_count: int = 0
    ack_p50_ms: float = 0.0  # ACK-on-receipt latency (across every shard lane)
    ack_p99_ms: float = 0.0
    recovery_seconds: float | None = None
    notes: list[str] = field(default_factory=list)
    # BACKLOG #209 topology: the shape this run SERVED. `dests` is the destination-CONNECTION count
    # (topology), `handlers` (H) is the router's selection width, `delivering` (D) is the fan-out. Default
    # sentinels (-1) so a caller that doesn't supply them is byte-identical; the CLI always does. The
    # verdict here is a per-message-id set difference (`acked_not_delivered`), so it is fan-out-agnostic —
    # these are RECORDED so a reader can tell an H!=D run from a default-shape one (schema_version 2).
    dests: int = -1
    handlers: int = -1
    delivering: int = -1
    #: WHICH SHAPE produced this run (schema_version 3). Without it the artifact is AMBIGUOUS: a PARTITIONED
    #: run reports the DERIVED accounting pair (handlers=1, delivering=1) alongside `dests=64`, which is
    #: byte-identical to a perfectly legal BROADCAST run `--dests 64 --handlers 1 --delivering 1` (load_shape
    #: accepts it: D <= dests, D <= H) — an utterly different shape that funnels ALL traffic onto destination
    #: 0, one FIFO lane, ~16 msg/s. Two wildly different numbers, one indistinguishable artifact. This key is
    #: what tells them apart, so it is emitted, not merely posted into an ephemeral coord drop.
    routing: str = BROADCAST
    #: ARTIFACT 2: the store pool this run actually ran on — the EFFECTIVE ``MEFOR_STORE_POOL_SIZE`` handed to
    #: every shard PROCESS (``pool.requested``, which now defaults to the PRODUCT 40, not the 8 a bare
    #: `setdefault` used to pin), the engine's OWN reported maximum, and the acquire_wait saturation evidence
    #: + pre-registered tripwire. ONE field, because a pool bind is column-for-column identical to the
    #: pooled-claim wall and the two were previously told apart by nothing at all.
    pool: PoolStats = EMPTY_POOL_STATS
    #: ARTIFACT 5: lanes-per-shard, so ``G = len(shards) x lanes_per_shard`` (the INGRESS/ROUTED pool width)
    #: is recoverable from the artifact and any plateau can be attributed to the right pool.
    lanes_per_shard: int = 1
    #: THE DEFERRAL CAUSE SPLIT (gate v2). ``offered - sent`` is ENGINE-PACED (a full send buffer means the
    #: engine stopped reading), so ``sent`` alone cannot say whose fault a shortfall was. These two say.
    #: ``-1`` = NOT RECORDED ⇒ a ``sent`` shortfall is OFFER_SHORTFALL (cause-neutral), never DRIVE_SHORTFALL.
    deferred_backpressure: int = -1  # full send buffers ⇒ THE ENGINE would not take the bytes
    deferred_schedule: int = -1  # tick-lag / no target ⇒ THE RIG could not schedule the sends

    @property
    def inbound_bands(self) -> int:
        """``G`` — the inbound MLLP band count (the INGRESS/ROUTED per-lane pool width). Compare against
        ``dests`` (L, the OUTBOUND pool width): at ``G < L`` the intake, not the outbound, is the narrow pool."""
        return inbound_band_count(len(self.shards), self.lanes_per_shard)

    @property
    def ok(self) -> bool:
        """Pass bar: zero acknowledged loss, drained pipeline, per-lane FIFO (non-vacuous), no
        dead-letters, no stranded non-terminal rows. Duplicates are allowed only across a kill."""
        dup_ok = self.lane_repeats == 0 if self.killed_shard is None else True
        return (
            self.acked > 0
            and self.acked_not_delivered == 0
            and self.drained
            and self.in_pipeline_final == 0
            and self.engine_dead == 0
            and self.lane_inversions == 0
            and self.lanes_observed >= 2
            and self.stranded_nonterminal == 0
            and dup_ok
        )

    def render(self) -> str:
        lines = [
            f"ShardCert {'/'.join(self.shards)}  verdict={'PASS' if self.ok else 'FAIL'}"
            + (f"  killed={self.killed_shard}" if self.killed_shard else "  (baseline, no kill)"),
            f"  sent={self.sent} acked={self.acked} delivered_distinct={self.delivered_distinct} "
            f"sink_received={self.sink_received}",
            f"  acked_not_delivered={self.acked_not_delivered} (0 = no acknowledged loss)",
            f"  lane_inversions={self.lane_inversions} lanes_observed={self.lanes_observed} "
            f"lane_repeats(dups)={self.lane_repeats}",
            f"  engine done={self.engine_done} dead={self.engine_dead} "
            f"in_pipeline_final={self.in_pipeline_final} drained={self.drained} "
            f"drain_s={self.drain_seconds}",
            f"  stranded_nonterminal_rows={self.stranded_nonterminal}",
            "  ownership: "
            + " ".join(f"{s}->[{','.join(self.owned[s]) or '-'}]" for s in self.shards),
            f"  {self.queue_breakdown}",
        ]
        if self.recovery_seconds is not None:
            lines.append(f"  recovery_seconds(reported, not gated)={self.recovery_seconds:.2f}")
        lines.append(f"  {self.pool.render()}")
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)

    def to_json_dict(self) -> dict[str, object]:
        """Metrics + metadata only (never message bodies or control-id lists — PHI rule)."""
        return {
            # v2 (BACKLOG #209): adds the `topology` block. The `--handlers`/`--delivering` CLI knobs let
            # this report describe an H!=D run, so a reader can no longer assume H = D = dests; the shape
            # is now RECORDED. (The PASS/FAIL verdict itself is a fan-out-agnostic set difference, unchanged.)
            #
            # v3 (PARTITIONED routing): `topology.routing` is new, and the MEANING of `handlers`/`delivering`
            # is now MODE-DEPENDENT — under `partitioned` they are the DERIVED accounting pair (1, 1) while
            # the graph BUILT H = D = dests. Under `broadcast` they are the build pair, exactly as in v2. A
            # v2 consumer reading `{dests: 64, handlers: 1, delivering: 1}` would conclude the fleet used ONE
            # of its 64 lanes; the version bump is the only thing that tells it the key's meaning moved.
            #
            # v4 (ARTIFACTS 2 + 5, 2026-07-14) — purely ADDITIVE; nothing removed or redefined:
            #  * `store_pool` — the EFFECTIVE MEFOR_STORE_POOL_SIZE (which now DEFAULTS TO THE PRODUCT 40,
            #    not the 8 a bare `setdefault` used to pin) + the pool's acquire_wait saturation evidence and
            #    the pre-registered tripwire. A run whose pool size is not recoverable from its own artifact
            #    is unauditable — and a pool bind is column-for-column identical to a pooled-claim wall.
            #  * `topology.lanes_per_shard` / `topology.inbound_bands` — G, the INGRESS/ROUTED pool width.
            #    At G < dests the INBOUND pool is the narrow one and any plateau is an ingress plateau.
            "schema_version": 4,
            "kind": "shardcert",
            "verdict": "PASS" if self.ok else "FAIL",
            "shards": list(self.shards),
            "killed_shard": self.killed_shard,
            "owned": {s: list(self.owned[s]) for s in self.shards},
            "topology": {
                "dests": self.dests,  # destination CONNECTIONS (port-band width) — NOT the fan-out
                "handlers": self.handlers,  # H: router SELECTION width (cost model only; 1 if partitioned)
                "delivering": self.delivering,  # D: the FAN-OUT (deliveries/message; 1 if partitioned)
                # broadcast | partitioned — WITHOUT THIS the two shapes above are indistinguishable.
                "routing": self.routing,
                # v4 (ARTIFACT 5): G — the INBOUND band count = the ingress/routed per-lane pool width.
                # `dests` (L) is the OUTBOUND one. At G < L the INTAKE is the narrow pool and a destination
                # sweep plateaus on ingress, which looks exactly like an outbound/claim wall.
                "lanes_per_shard": self.lanes_per_shard,
                "inbound_bands": self.inbound_bands,
                "inbound_bands_narrower_than_dests": (
                    self.dests > 0 and self.inbound_bands < self.dests
                ),
            },
            "traffic": {
                "sent": self.sent,
                "acked": self.acked,
                "offered": self.offered,
                "achieved_intake": self.achieved_intake,
                "delivered_distinct": self.delivered_distinct,
                "sink_received": self.sink_received,
            },
            # v4 (ARTIFACT 2): the EFFECTIVE pool size + its saturation evidence. Recoverable from the
            # artifact alone — the old `setdefault("8")` was recorded nowhere at all.
            "store_pool": self.pool.to_json_dict(),
            "correctness": {
                "acked_not_delivered": self.acked_not_delivered,
                "lane_inversions": self.lane_inversions,
                "lanes_observed": self.lanes_observed,
                "lane_repeats": self.lane_repeats,
                "stranded_nonterminal": self.stranded_nonterminal,
                "engine_dead": self.engine_dead,
            },
            "throughput": {
                "in_pipeline_peak": self.in_pipeline_peak,
                "in_pipeline_final": self.in_pipeline_final,
                "drained": self.drained,
                "drain_seconds": self.drain_seconds,
            },
            "ack_ms": {"p50": round(self.ack_p50_ms, 3), "p99": round(self.ack_p99_ms, 3)},
            "recovery_seconds": self.recovery_seconds,
            "queue_breakdown": self.queue_breakdown,
            "notes": self.notes,
        }


# --- port helpers ------------------------------------------------------------


def _reserve_ports(n: int) -> list[int]:
    """Reserve ``n`` free loopback ports (bind :0 then close — the small close→bind race is the same
    pattern the failover harness uses; the engine binds moments later)."""
    socks = []
    try:
        for _ in range(n):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        return [int(s.getsockname()[1]) for s in socks]
    finally:
        for s in socks:
            s.close()


def _free_contiguous(n: int, start: int = 3600, tries: int = 60) -> int:
    """A base port ``B`` such that ``B..B+n-1`` are all bindable — the graph needs the N shard inbound
    ports contiguous (``inbound_base + i``)."""
    base = start
    for _ in range(tries):
        socks = []
        ok = True
        try:
            for i in range(n):
                s = socket.socket()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("127.0.0.1", base + i))
                    socks.append(s)
                except OSError:
                    ok = False
                    break
        finally:
            for s in socks:
                s.close()
        if ok:
            return base
        base += n + 7
    raise RuntimeError(f"could not find {n} contiguous free ports from {start}")


async def _await_health(url: str, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    async with httpx.AsyncClient(timeout=2.0) as client:
        while time.monotonic() < deadline:
            with contextlib.suppress(Exception):
                r = await client.get(f"{url}/health")
                if r.status_code == 200:
                    return True
            await asyncio.sleep(0.3)
    return False


async def _await_port(host: str, port: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return True
        except OSError:
            await asyncio.sleep(0.2)
    return False


# --- store helpers (SQL Server) ----------------------------------------------


async def _reset_store(env: Mapping[str, str]) -> None:
    """DELETE the pipeline tables so a re-run starts clean (mirrors test_load_failover_sqlserver)."""
    import os

    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    # The TLS-escape guard (insecure_tls_allowed) reads os.environ DIRECTLY, so the parent-process
    # store open needs the escape + creds in os.environ, not just the load_settings `environ=` arg.
    with _env_scope(dict(env)):
        settings = load_settings(environ=os.environ).store
        store = await SqlServerStore.open(settings)
    try:
        async with store._pool.acquire() as conn:
            cur = await conn.cursor()
            for table in (
                "queue",
                "response",
                "delivered_keys",
                "state",
                "leader_lease",
                "nodes",
                "cluster_config",
                "messages",
            ):
                with contextlib.suppress(Exception):
                    await cur.execute(f"DELETE FROM {table}")
            await conn.commit()
    finally:
        await store.close()


@dataclass(frozen=True)
class QueueBreakdown:
    """The PURE summary of a ``GROUP BY stage, status`` scan of the ``queue`` table — the store-truth
    signals the outbound-scoped ``store.stats()`` cannot give.

    ``nonterminal`` (``status NOT IN ('done','dead')``) and ``dead_total`` are the ALL-STAGE totals the
    engine's self-contained store-truth verdict gates on. The three ``*_stranded`` fields SPLIT the
    delivery-blocking rows — non-terminal **and** dead, jointly, since the A4b permit charges them
    identically — by the STAGE they are stuck at, which is exactly what the cross-observer permit needs to
    charge each strand the RIGHT number of blocked deliveries (BACKLOG #229): an INGRESS strand blocks all
    ``D`` copies (the message never routed), an OUTBOUND strand blocks exactly one delivery, a ROUTED
    strand blocks in ``[0, 1]`` (a delivering handler's row blocks one, a non-delivering handler's blocks
    zero) — rather than the stage-blind flat one the opaque ``stranded + dead`` total forced. The per-stage
    split sums to ``nonterminal + dead_total`` (every ``queue`` row sits at exactly one of the three
    stages: ``ingress`` → ``routed`` → ``outbound``)."""

    nonterminal: int
    dead_total: int
    ingress_stranded: int  # ingress rows non-terminal OR dead — each blocks ALL D copies
    routed_stranded: int  # routed rows non-terminal OR dead — each blocks [0, 1] (the permit)
    outbound_stranded: int  # outbound rows non-terminal OR dead — each blocks exactly 1
    summary: str


#: The three persisted pipeline stages (ADR 0001 Step B), lower-cased for a case-insensitive match against
#: the stored ``stage`` discriminator. Every ``queue`` row sits at exactly one of these.
_PIPELINE_STAGES = ("ingress", "routed", "outbound")


def _summarize_queue_rows(rows: Sequence[Sequence[Any]]) -> QueueBreakdown:
    """Reduce a ``GROUP BY stage, status`` result (``[(stage, status, count), ...]``) to a
    :class:`QueueBreakdown` — PURE, no DB, so it is unit-tested directly with synthetic rows.

    A row is DELIVERY-BLOCKING when it is either NON-TERMINAL (``status`` not ``done`` / ``dead`` — a stuck
    row) or DEAD (an acked-on-receipt row that will never deliver); the A4b permit charges both identically,
    so each ``*_stranded`` field is (non-terminal + dead) at that stage. ``nonterminal`` == the count of
    ``status NOT IN ('done','dead')`` rows and ``dead_total`` == the count of ``dead`` rows, both across all
    stages — computed from the SAME scan so there is one source of truth (statuses are stored lower-case, and
    the compare here lower-cases to stay collation-agnostic). The ``summary`` string preserves the exact
    ``stage/status=n`` render every prior caller emitted."""
    nonterminal = 0
    dead_total = 0
    per_stage_blocked = dict.fromkeys(_PIPELINE_STAGES, 0)
    for row in rows:
        stage = str(row[0]).lower()
        status = str(row[1]).lower()
        count = int(row[2])
        is_dead = status == "dead"
        is_nonterminal = status not in ("done", "dead")
        if is_dead:
            dead_total += count
        if is_nonterminal:
            nonterminal += count
        if (is_dead or is_nonterminal) and stage in per_stage_blocked:
            per_stage_blocked[stage] += count
    summary = "QUEUE " + (" ".join(f"{r[0]}/{r[1]}={r[2]}" for r in rows) or "<empty>")
    return QueueBreakdown(
        nonterminal=nonterminal,
        dead_total=dead_total,
        ingress_stranded=per_stage_blocked["ingress"],
        routed_stranded=per_stage_blocked["routed"],
        outbound_stranded=per_stage_blocked["outbound"],
        summary=summary,
    )


async def _queue_breakdown(env: Mapping[str, str]) -> QueueBreakdown:
    """The store-truth :class:`QueueBreakdown` read DIRECTLY from the store — signals the outbound-scoped
    ``store.stats()`` can't give: the stranded-INFLIGHT count (``stats()`` would miss a stuck ingress/routed
    row), the all-stage dead total, AND the per-stage strand split the A4b permit needs (BACKLOG #229). A
    router/handler regression dead-letters at the INGRESS or ROUTED stage (``dead_letter_now`` sets
    ``status=DEAD`` WITHOUT touching ``stage``), and ``stats().dead`` counts only ``stage=outbound`` — so
    those acked-on-receipt rows are acknowledged loss the engine's own store-truth verdict must catch without
    leaning on the driver half's sink-truth. Every figure is derived from the single ``GROUP BY stage,
    status`` scan below (via :func:`_summarize_queue_rows`) — no extra round trip."""
    import os

    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    with _env_scope(dict(env)):  # escape reads os.environ directly — see _reset_store
        settings = load_settings(environ=os.environ).store
        store = await SqlServerStore.open(settings)
    try:
        async with store._pool.acquire() as conn:
            cur = await conn.cursor()
            await cur.execute(
                "SELECT stage, status, COUNT(*) FROM queue GROUP BY stage, status "
                "ORDER BY stage, status"
            )
            rows = await cur.fetchall()
    finally:
        await store.close()
    return _summarize_queue_rows(rows)


# --- the bench ---------------------------------------------------------------


async def _sample_in_pipeline_peak(
    urls: list[str], stop: asyncio.Event, out: list[int], *, interval: float = 0.5
) -> None:
    """Poll the fleet's aggregate in-pipeline gauge every ``interval`` until ``stop``, keeping the
    high-water in ``out[0]``. A dedicated short-lived poller so the SIZING bench can report the
    steady-state backlog peak; the correctness path never starts it (``capture_peak=False``), so its
    drive stays byte-identical."""
    poller = EnginePoller(urls, None, origin=time.perf_counter())
    await poller.open()
    # De-dup the unified-store gauge: each shard's /stats in_pipeline counts the WHOLE store and the poller
    # SUMS across the N shard URLs, so the aggregate is N× the true fleet backlog (#841). Divide by the
    # distinct-shard count to record a SINGLE store view as the high-water.
    n_shards = max(1, len(set(urls)))
    try:
        while not stop.is_set():
            sample = await poller.sample_once()
            if sample is not None:
                depth = sample.in_pipeline // n_shards
                if depth > out[0]:
                    out[0] = depth
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=interval)
    finally:
        await poller.close()


async def _sample_in_pipeline_trace(
    urls: list[str],
    stop: asyncio.Event,
    out: list[list[float]],
    *,
    interval: float = 2.0,
    origin: float | None = None,
) -> None:
    """Poll the fleet's aggregate in-pipeline gauge every ``interval`` until ``stop``, APPENDING each
    ``[elapsed_s, in_pipeline]`` reading to ``out`` (the full bounded trace, not just the peak). The PR-C2
    soak uses the trace SLOPE (flat/draining vs monotonic growth) to tell a sustainable plateau from a
    slow-saturation one; a short-lived poller so the correctness/climb path (``sample_in_pipeline=False``)
    adds no concurrent poller during the hold."""
    t0 = origin if origin is not None else time.perf_counter()
    poller = EnginePoller(urls, None, origin=t0)
    await poller.open()
    # De-inflate the unified-store in_pipeline: each shard's gauge counts the whole store and the poller
    # sums the N shard URLs (#841). Divide by the distinct-shard count so the recorded trace is a SINGLE
    # store view — which ALSO de-inflates the least-squares SLOPE by the same N, removing the accidental
    # N× slope sensitivity the soak's flat-or-draining gate would otherwise apply (paired with the tightened
    # _SLOPE_FLAT_TOL in shardcert_ladder.py and the bounded soak drain, D2).
    n_shards = max(1, len(set(urls)))
    try:
        while not stop.is_set():
            sample = await poller.sample_once()
            if sample is not None:
                out.append([round(time.perf_counter() - t0, 3), sample.in_pipeline / n_shards])
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=interval)
    finally:
        await poller.close()


def _resolve_shape(dests: int, handlers: int | None, delivering: int | None) -> tuple[int, int]:
    """Resolve ``(H, D)`` from the ``dests`` topology + the optional overrides (BACKLOG #209).

    BOTH default to ``dests``, which reproduces the pre-#209 graph exactly (``H = D = dests`` ⇒
    ``routed == delivered``), so every existing caller and every published run is byte-identical. The
    graph's :func:`load_shape` is the authority that VALIDATES the pair (``1 <= D <= dests``, ``D <= H``)
    and raises — this only resolves the defaults, so there is ONE place the invariants live."""
    return (dests if handlers is None else handlers), (dests if delivering is None else delivering)


async def run_shardcert(
    *,
    dests: int = 8,
    handlers: int | None = None,
    delivering: int | None = None,
    aggregate_rate: float = 40.0,
    hold_seconds: float = 20.0,
    kill: bool = False,
    kill_shard: str | None = None,
    kill_at_fraction: float = 0.4,
    drain_timeout: float = 90.0,
    store_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    sink_host: str = "127.0.0.1",
    sink_port: int | None = None,
    capture_peak: bool = False,
    store_pool_size: int | None = None,
    strict_bands: bool = False,
) -> ShardCertReport:
    """Run the 4-shard certification bench once. ``store_env`` must point every serve process at the
    ONE unified server store (``MEFOR_STORE_*``) — see the module doc + the AWS handoff for the exact
    set; ``run_shardcert`` adds the graph shape (``MEFOR_SHARDCERT_*``) and the auth/insecure escapes.

    ``sink_port`` pins the correlation-sink port (default ``None`` ⇒ an ephemeral reserved port, the
    original behavior); ``sink_host`` is the sink bind host. ``capture_peak`` samples the fleet's
    aggregate in-pipeline gauge during the hold and reports ``in_pipeline_peak`` — the sizing bench
    turns it on; **off by default so the correctness/kill path drives byte-identically** (no extra
    poller during the hold, ``in_pipeline_peak`` stays ``-1``).

    ``handlers`` (H) / ``delivering`` (D) are the BACKLOG #209 shape split; both default to ``dests``
    (⇒ the pre-#209 ``H = D = dests`` graph). ``dests`` remains TOPOLOGY only. This single-box path's
    verdict is a per-message-id set difference (``acked_not_delivered``), so it is fan-out-agnostic by
    construction and needs no D-keyed arithmetic — it only has to SERVE the requested shape.
    """
    import os

    cwd = cwd or Path.cwd()
    store_env = dict(store_env or {})
    routing = load_routing()
    handlers, delivering = _resolve_shape(dests, handlers, delivering)
    # The ACCOUNTING pair (see reported_shape): under `partitioned` the graph builds H = D = dests but the
    # router selects ONE handler ⇒ the fan-out is 1. The graph-build pair below stays (handlers, delivering).
    r_handlers, r_delivering = reported_shape(handlers, delivering, routing)

    # Discover the shard set + ownership from the graph (with the FULL shape applied) BEFORE serving. The
    # scope must carry H/D/routing too, not just dests: discovery and the served fleet have to build the SAME
    # graph.
    with _env_scope(
        {
            "MEFOR_SHARDCERT_DESTS": str(dests),
            "MEFOR_SHARDCERT_HANDLERS": str(handlers),
            "MEFOR_SHARDCERT_DELIVERING": str(delivering),
            "MEFOR_SHARDCERT_ROUTING": routing,
        }
    ):
        reg = load_config(_CONFIG_DIR)
    ids_list = shard_ids(reg)
    owned = {s: sorted(owned_destination_set(reg, s, ids_list)) for s in ids_list}
    n = len(ids_list)
    # Lanes per shard (many-thin-lanes): the built graph has N*lanes inbound rows, so derive it from the
    # registry rather than re-reading the env (keeps the driver and the served graph in lock-step).
    lanes = (len(reg.inbound) // n) if n else 1
    # ARTIFACT 5: the G < L pre-flight, on the SAME predicate the two-box `_discover` calls. A check that
    # lives on only one of the two paths is the `filling`-gate failure repeated.
    setup_notes: list[str] = []
    # Under partitioned-fanout the D-aware check_fanout_lane_headroom SUPERSEDES the raw G<dests check —
    # which false-positives there: a well-sized fanout run always has dests >= D*G > G, so the raw check
    # would strict-ABORT EVERY fanout run. Let it record its note but not strict-raise under fanout.
    band_note = check_inbound_bands(
        n, lanes, dests, strict=strict_bands and routing != PARTITIONED_FANOUT
    )
    if band_note is not None:
        setup_notes.append(band_note)
    # D-aware fan-out lane-headroom pre-flight (no-op unless partitioned-fanout): the outbound pool serves
    # dests/D messages-worth of ingress under fan-out, which neither the G<L nor the RungFidelity gate models.
    fanout_note = check_fanout_lane_headroom(
        n, lanes, dests, delivering, routing, strict=strict_bands
    )
    if fanout_note is not None:
        setup_notes.append(fanout_note)

    # Ports: N*lanes contiguous inbound (lane l of shard i binds base + i*lanes + l), 1 sink (pinned or
    # ephemeral), N API. lanes == 1 ⇒ N contiguous inbound at base + i, byte-identical to today.
    inbound_base = _free_contiguous(n * lanes)
    if sink_port is None:
        sink_port, *api_ports = _reserve_ports(1 + n)
    else:
        api_ports = _reserve_ports(n)

    # The shape env every serve process (and the config discovery) shares.
    shape_env = {
        "MEFOR_SHARDCERT_SHARDS": ",".join(ids_list),
        "MEFOR_SHARDCERT_INBOUND_BASE": str(inbound_base),
        "MEFOR_SHARDCERT_DESTS": str(dests),
        "MEFOR_SHARDCERT_HANDLERS": str(handlers),
        "MEFOR_SHARDCERT_DELIVERING": str(delivering),
        "MEFOR_SHARDCERT_ROUTING": routing,
        "MEFOR_SHARDCERT_SINK_HOST": sink_host,
        "MEFOR_SHARDCERT_SINK_PORT": str(sink_port),
        "MEFOR_SHARDCERT_TRANSFORM": "edit",
    }
    escapes = {
        "MEFOR_ALLOW_INSECURE_TLS": "1",
        "MEFOR_ALLOW_INSECURE_CONFIG_SOURCE": "1",
        "MEFOR_SECURITY_REQUIRE_SIGN_IN": "false",
        "MEFOR_INBOUND_BIND_HOST": "127.0.0.1",
    }
    # ARTIFACT 2: the pool is now RESOLVED (flag > ambient env > PRODUCT default 40) and ASSIGNED, not
    # `setdefault`-pinned at 8 and forgotten. `resolve_store_pool_size` still honours an ambient
    # MEFOR_STORE_POOL_SIZE exactly as the old setdefault did, so an operator's out-of-band pin is unchanged
    # — what changed is the DEFAULT (8 -> 40, the product's) and the fact that the value is now RECORDED.
    pool_size = resolve_store_pool_size(store_env, store_pool_size)
    store_env["MEFOR_STORE_POOL_SIZE"] = str(pool_size)
    announce_store_pool(pool_size, n)
    node_env = {**os.environ, **store_env, **shape_env, **escapes}

    await _reset_store(node_env)

    # Sink + correlation + tracker (span all shards).
    ids = SHARDCERT_IDS
    metrics = LiveMetrics(counters=Counters(), ack=Histogram(), e2e=Histogram())
    correlator = Correlator(capacity=1 << 20, metrics=metrics)
    tracker = FailoverTracker()
    corpus = build_corpus(load_profile_text(_CORPUS_PROFILE, where="<shardcert>"), ids)
    mix = TypeMix({"ADT^A01": 1.0})
    sink = CorrelationSink(
        ids, correlator, metrics, host=sink_host, ports=(sink_port,), tracker=tracker
    )
    await sink.start()

    nodes: dict[str, ShardCertNode] = {}
    conns: list[PersistentConnection] = []
    poller: EnginePoller | None = None
    peak_holder = [0]  # in_pipeline high-water during the hold (capture_peak only)
    peak_stop = asyncio.Event()
    peak_task: asyncio.Task[None] | None = None
    report_notes: list[str] = []
    # E2E filling detector (`fill_ratio`), sizing path only. The single `metrics.e2e` histogram is swapped
    # per PHASE (the LiveMetrics "swap per phase" pattern) so the hold's two steady halves are separable:
    #
    #   ramp  [0, R*H)          -> e2e_ramp_hist   (cold start: empty pipeline, artificially LOW latency)
    #   first [R*H, M)          -> e2e_first_hist  \ the two EQUAL-LENGTH comparable steady cohorts
    #   second[M, H)            -> e2e_second_hist /
    #   drain [H, drained)      -> e2e_drain_hist  (post-hold tail: the LONGEST samples in the run)
    #
    # Every phase is MERGED back into the aggregate, so `e2e_p50/p99/count` stay byte-identical to the
    # pre-split value. Only `first` and `second` feed `fill_ratio` — the ramp and the DRAIN are excluded by
    # construction. That exclusion is load-bearing, not tidiness: the drive loop breaks at the hold, but the
    # CorrelationSink keeps recording through the ACK grace, the kill/restart leg and the whole
    # `await_drain` window (default 150 s per rung). Leaving `metrics.e2e` pointed at the second half would
    # dump every drain-tail sample — by construction the most-delayed in the run — into the very half the
    # gate divides BY, so a longer `--drain-timeout` would mean a higher ratio would mean a lower reported
    # ceiling. A knob must not move the ceiling.
    e2e_ramp_hist = metrics.e2e
    e2e_first_hist: Histogram | None = None
    e2e_second_hist: Histogram | None = None
    e2e_drain_hist: Histogram | None = None
    killed = kill_shard if kill else None
    if kill and killed is None:
        # Kill the shard that owns the MOST lanes (maximizes recovery coverage).
        killed = max(ids_list, key=lambda s: len(owned[s]))
    recovery_seconds: float | None = None

    try:
        # Start shards STRICTLY one-at-a-time behind a health gate — the SS schema-init applock convoys
        # at N>=4 simultaneous opens (multishard.py:426 documents the 30s-timeout blowout).
        for i, s in enumerate(ids_list):
            node = ShardCertNode(s, api_ports[i], env=node_env, config_dir=_CONFIG_DIR, cwd=cwd)
            await node.start()
            nodes[s] = node
            if not await _await_health(node.url, timeout=60.0):
                raise RuntimeError(f"shard {s} did not become healthy\n{node.log_tail()}")
            # Each shard binds `lanes` inbound ports (base + i*lanes + l); wait for every one.
            for lane in range(lanes):
                port = inbound_base + i * lanes + lane
                if not await _await_port("127.0.0.1", port, timeout=30.0):
                    raise RuntimeError(f"shard {s} inbound lane port {port} never bound")

        # One persistent connection per (shard, lane) inbound (tracker wired for on_ack) — N*lanes now.
        for i, _s in enumerate(ids_list):
            for lane in range(lanes):
                pc = PersistentConnection(
                    "127.0.0.1",
                    inbound_base + i * lanes + lane,
                    correlator,
                    metrics,
                    expect_ack=True,
                    tracker=tracker,
                )
                pc.start()
                conns.append(pc)

        # Sizing bench only: sample the fleet's in-pipeline high-water across the hold (off by default
        # ⇒ the correctness/kill path adds no concurrent poller during the drive).
        if capture_peak:
            peak_task = asyncio.create_task(
                _sample_in_pipeline_peak([nodes[s].url for s in ids_list], peak_stop, peak_holder)
            )

        # Drive load at an aggregate rate, round-robin across the N*lanes shard-lane connections;
        # optionally SIGKILL one shard `kill_at_fraction` into the hold and keep driving the survivors.
        kill_deadline = time.monotonic() + hold_seconds * kill_at_fraction if kill else None
        did_kill = False
        kill_at: float | None = None
        loop = asyncio.get_running_loop()
        start = loop.time()
        next_due = start
        interval = 1.0 / aggregate_rate if aggregate_rate > 0 else 0.0
        sampler = corpus.sampler(mix)
        rr = 0
        # Sizing/ladder path only (capture_peak): the phase boundaries of the `fill_ratio` split. The
        # correctness/kill path never swaps (single histogram) so that drive stays byte-identical.
        ramp_end = hold_seconds * _FILLING_RAMP_FRACTION
        half_end = ramp_end + (hold_seconds - ramp_end) / 2.0  # the two halves are EQUAL length
        while True:
            now = loop.time()
            elapsed = now - start
            if elapsed >= hold_seconds:
                break
            if capture_peak:
                if e2e_first_hist is None and elapsed >= ramp_end:
                    e2e_first_hist = Histogram()  # warm-up over: the first comparable cohort starts
                    metrics.e2e = e2e_first_hist
                elif e2e_first_hist is not None and e2e_second_hist is None and elapsed >= half_end:
                    e2e_second_hist = Histogram()  # the second comparable cohort
                    metrics.e2e = e2e_second_hist
            if kill and not did_kill and time.monotonic() >= (kill_deadline or 0):
                nodes[killed].kill()  # type: ignore[index]
                kill_at = time.monotonic()
                did_kill = True
                report_notes.append(f"SIGKILLed shard {killed} at ~{kill_at_fraction:.0%} of hold")
            emitted = 0
            while next_due <= now and emitted < _TOKEN_BATCH_CAP:
                out = corpus.next(sampler)
                conn = conns[rr % len(conns)]
                rr += 1
                if not conn.submit_nowait(out):
                    # BUFFER FULL ⇒ the ENGINE stopped reading its socket (see Counters.deferred_*). This
                    # is an engine signal, and it SUPPRESSES `sent` — so it must never be read as "the rig
                    # was too small".
                    metrics.counters.deferred += 1
                    metrics.counters.deferred_backpressure += 1
                next_due += interval
                emitted += 1
            if next_due <= now:
                behind = int((now - next_due) / max(interval, 1e-6)) + 1
                metrics.counters.deferred += behind  # THE RIG could not schedule these at all
                metrics.counters.deferred_schedule += behind
                next_due = now + interval
            await asyncio.sleep(max(0.0, min(next_due - loop.time(), _MAX_TICK_SLEEP)))

        # HOLD OVER — FREEZE the second half HERE, before anything post-hold can land in it. Everything
        # from this instant on (the 2 s ACK grace, the kill/restart leg, the whole `await_drain` window) is
        # DRAIN: the most-delayed samples in the run, and `metrics.e2e` is still live for all of it. Point
        # it at a drain histogram so those samples still reach the AGGREGATE (e2e_p50/p99/count stay
        # byte-identical) but CANNOT move `fill_ratio`. Without this swap a longer --drain-timeout would
        # silently lower the reported ceiling.
        if capture_peak:
            e2e_drain_hist = Histogram()
            metrics.e2e = e2e_drain_hist
        # Stop the peak sampler (if any), then stop offering; grace in-flight ACKs.
        if peak_task is not None:
            peak_stop.set()
            with contextlib.suppress(Exception):
                await peak_task
        await asyncio.gather(*(c.stop(2.0) for c in conns))

        # Kill leg: restart the killed shard (supervisor-style) so its startup runs the
        # ownership-scoped reset over ITS lanes; time functional recovery.
        if kill and killed is not None:
            idx = ids_list.index(killed)
            restart = ShardCertNode(
                killed, api_ports[idx], env=node_env, config_dir=_CONFIG_DIR, cwd=cwd
            )
            await restart.start()
            nodes[killed] = restart
            if not await _await_health(restart.url, timeout=60.0):
                raise RuntimeError(f"shard {killed} did not restart\n{restart.log_tail()}")
            if kill_at is not None:
                recovery_seconds = time.monotonic() - kill_at

        # Aggregate drain over ALL shards (every shard back up): in_pipeline==0 across the fleet, read
        # from /stats — the authoritative drain signal, NOT a poller peak.
        urls = [nodes[s].url for s in ids_list]
        poller = EnginePoller(urls, None, origin=time.perf_counter())
        await poller.open()
        drain_s = await poller.await_drain(timeout=drain_timeout, interval=0.5)
        final = poller.final

        # Store-truth: stranded non-terminal rows + stage/status breakdown. (Single-box gates no-loss
        # on the SINK-truth `acked_not_delivered==0`, so the all-stage dead total is surfaced in the
        # breakdown but not separately gated here — see ShardCertEngineReport for the two-box rationale.)
        _qb = await _queue_breakdown(node_env)
        stranded, breakdown = _qb.nonterminal, _qb.summary

    finally:
        if peak_task is not None and not peak_task.done():
            peak_stop.set()
            peak_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await peak_task
        if poller is not None:
            await poller.close()
        for pc in conns:
            with contextlib.suppress(Exception):
                await pc.stop(0.5)
        for node in nodes.values():
            with contextlib.suppress(Exception):
                await node.stop()
        with contextlib.suppress(Exception):
            await sink.stop()

    ctr = metrics.counters
    ack = metrics.ack.summary()
    # The full-message-life histogram the report used to discard. The aggregate is the MERGE of EVERY phase
    # (ramp + first + second + drain), so `e2e_p50/p99/count` are byte-identical to the pre-split value. Only
    # `first` and `second` — the two equal-length steady cohorts — feed `fill_ratio`. On the correctness/kill
    # path nothing is ever swapped, so `e2e_ramp_hist` IS the whole run and both halves stay unmeasured (0),
    # which makes `fill_ratio` abstain.
    e2e_agg = Histogram()
    for _h in (e2e_ramp_hist, e2e_first_hist, e2e_second_hist, e2e_drain_hist):
        if _h is not None:
            e2e_agg.merge(_h)
    e2e = e2e_agg.summary()
    e2e_first = e2e_first_hist.summary() if e2e_first_hist is not None else None
    e2e_second = e2e_second_hist.summary() if e2e_second_hist is not None else None
    return ShardCertReport(
        shards=tuple(ids_list),
        owned=owned,
        killed_shard=killed,
        sent=ctr.sent,
        # The fidelity gate's CAUSE SPLIT: without these, a `sent` shortfall caused by ENGINE BACKPRESSURE
        # is indistinguishable from one caused by the rig running out — and the gate would blame the rig.
        deferred_backpressure=ctr.deferred_backpressure,
        deferred_schedule=ctr.deferred_schedule,
        acked=ctr.acked,
        delivered_distinct=tracker.delivered_count,
        sink_received=ctr.sink_received,
        acked_not_delivered=tracker.acked_not_delivered(),
        lane_inversions=tracker.lane_inversions,
        lanes_observed=tracker.lanes_observed,
        lane_repeats=tracker.lane_repeats,
        engine_done=(final.done if final else 0),
        engine_dead=(final.dead if final else 0),
        # D4: de-dup the N×-summed unified-store poller aggregate to a single store view (#841). This value
        # feeds ShardCertReport.ok/drained, unlike the advisory drive-side poller cross-checks (left as N×).
        in_pipeline_final=(final.in_pipeline // max(1, len(ids_list)) if final else -1),
        drained=drain_s is not None,
        drain_seconds=drain_s,
        stranded_nonterminal=stranded,
        queue_breakdown=breakdown,
        offered=round(aggregate_rate * hold_seconds),
        achieved_intake=ctr.acked,
        in_pipeline_peak=(peak_holder[0] if capture_peak else -1),
        e2e_count=e2e.count,
        e2e_p50_ms=e2e.p50_ms,
        e2e_p99_ms=e2e.p99_ms,
        e2e_first_half_p50_ms=(e2e_first.p50_ms if e2e_first is not None else 0.0),
        e2e_first_half_count=(e2e_first.count if e2e_first is not None else 0),
        e2e_second_half_p50_ms=(e2e_second.p50_ms if e2e_second is not None else 0.0),
        e2e_second_half_count=(e2e_second.count if e2e_second is not None else 0),
        ack_p50_ms=ack.p50_ms,
        ack_p99_ms=ack.p99_ms,
        recovery_seconds=recovery_seconds,
        # The G < L pre-flight note (ARTIFACT 5) rides FIRST: it is a setup condition that shapes how every
        # number below must be read, so it belongs above the run's own notes, not appended after them.
        notes=[*setup_notes, *report_notes],
        dests=dests,
        # The ACCOUNTING pair, never the graph-build pair: these feed txn_per_message / events_per_message.
        # Under `partitioned` the router selects ONE handler ⇒ (1, 1), so txn/msg reads its true 7 and not
        # the build shape's 3 + 2*dests + 2*dests. `routing` rides WITH them: the derived pair is ambiguous
        # without it (see ShardCertReport.routing).
        handlers=r_handlers,
        delivering=r_delivering,
        routing=routing,
        # ARTIFACT 2 / 5: the pool the fleet actually ran on (requested + engine-observed + acquire_wait
        # evidence) and G's other half. `final` is the drain-time sample; acquire_wait is a CUMULATIVE
        # histogram and each rung spawns a FRESH fleet, so the cumulative read IS this rung's read.
        pool=PoolStats.from_sample(final, requested=pool_size),
        lanes_per_shard=lanes,
    )


# --- ascending rate-ladder (ceiling hunt) ------------------------------------

#: The gate VERSION stamped into the ladder JSON. Bumped whenever the sustain bar changes, so a reader
#: cannot silently compare a ceiling measured under one gate against one measured under another. v2 added
#: the `filling` term (2026-07-13) — see the `_FILLING_RATIO` block for its SCOPE (co-located ladder only).
CEILING_GATE_VERSION = 2


def _is_ceiling(*, no_loss: bool, achieved_intake: int, offered: int, filling: bool) -> bool:
    """The ladder's SUSTAIN bar, as ONE pure function with every term EXPLICIT — the single definition both
    :attr:`ShardCertStepRecord.ceiling` and :attr:`ShardCertDriveReport.ceiling` call.

    A **throughput** ceiling, kept distinct from a **correctness** break (loss/inversion/dup still FAILs the
    ladder verdict — see :attr:`ShardCertLadderReport.ok`). Three ways to fail sustain:

    * ``not no_loss`` — real acknowledged loss, or a backlog that never drained inside the drain window.
    * ``achieved_intake < offered * (1 - _INTAKE_TOL)`` — the engines could not even INGEST that fast.
      (Deliberately **not** ``delivered < offered``, a MEASURED quantity that false-trips on the healthy
      token-bucket boundary-drop above ~200 msg/s and stopped the ladder early.)
    * ``filling`` — the in-flight backlog was still GROWING at the hold's end, so the rung drained only
      *after* the offer stopped: lossless and eventually-drained, but NOT a sustainable operating point.

    ``filling`` is a REQUIRED keyword with no default ON PURPOSE. It used to be four optional dataclass
    fields, and the two-box drive report simply did not set them — so they took the 0 sentinel, the ratio
    abstained, and a caller could not tell an ABSTAIN from a STEADY read. A caller that cannot compute the
    term must now say ``filling=False`` in the source and explain why (as
    :attr:`ShardCertDriveReport.ceiling` does)."""
    return (not no_loss) or (achieved_intake < offered * (1 - _INTAKE_TOL)) or filling


@dataclass(frozen=True)
class ShardCertStepRecord:
    """One hold step of the ascending rate ladder — the sizing bench's per-rate view. Metrics +
    metadata only (never message bodies / control-id lists — PHI rule)."""

    aggregate_rate: float
    offered: int
    achieved_intake: int
    delivered: int
    in_pipeline_peak: int
    ack_p50_ms: float
    ack_p99_ms: float
    drain_seconds: float | None
    no_loss: bool
    lane_inversions: int
    lane_repeats: int
    stranded_nonterminal: int
    #: Filling detector (``fill_ratio``): the hold's two EQUAL-LENGTH steady cohorts — first-/second-half
    #: median E2E + per-half sample counts (from :class:`ShardCertReport`). Default sentinels ⇒ "not
    #: measured" (a synthetic record, the correctness/kill path, or ANY two-box run — see the
    #: ``_FILLING_RATIO`` block for the scope), which makes :attr:`fill_ratio` ``None`` and ABSTAINS from
    #: the filling gate. The criterion never false-fails on absent data.
    e2e_first_half_p50_ms: float = 0.0
    e2e_first_half_count: int = 0
    e2e_second_half_p50_ms: float = 0.0
    e2e_second_half_count: int = 0
    #: ARTIFACT 4: Σ sender-worker ``sent`` — the DRIVE-side half of the fidelity gate. -1 = NOT RECORDED
    #: (a synthetic record), which makes :attr:`fidelity` UNKNOWN and the rung VOID for the ceiling.
    #: FAIL-CLOSED by design: this field is exactly the kind that took a 0 sentinel and silently killed the
    #: ``filling`` gate (see the warning in :meth:`from_report`).
    sent: int = -1
    #: THE DEFERRAL CAUSE SPLIT (gate v2) — the OTHER half of the ``sent`` shortfall arm. ``-1`` = not
    #: recorded ⇒ the shortfall is OFFER_SHORTFALL (cause NOT attributed), never DRIVE_SHORTFALL. Without
    #: these the gate reads ENGINE BACKPRESSURE (which suppresses ``sent``) as a rig failure and sends the
    #: operator away to buy drive boxes on the one finding the ladder exists to produce.
    deferred_backpressure: int = -1
    deferred_schedule: int = -1
    #: The rung's HOLD, so the accepted-derived rate (``acked / (hold + drain)``) has an honest span. 0 =
    #: not recorded ⇒ :attr:`accepted_rate` is ``None`` (an unmeasured span cannot denominate a rate).
    hold_seconds: float = 0.0
    #: ARTIFACTS 2 + 5: the CONFIGURATION this rung ran on, measured by ``run_shardcert`` and — until now —
    #: dropped on the floor by :meth:`from_report`, so the LADDER artifact could not name the pool, the
    #: routing shape, or the inbound band count its own ceiling was measured under. A run whose configuration
    #: cannot be reconstructed from its own artifact is unauditable.
    dests: int = -1
    handlers: int = -1
    delivering: int = -1
    routing: str = BROADCAST
    lanes_per_shard: int = 1
    shard_count: int = 0
    pool: PoolStats = EMPTY_POOL_STATS

    @property
    def inbound_bands(self) -> int:
        """``G`` — the INGRESS/ROUTED per-lane pool width (``shards x lanes_per_shard``), beside ``dests``
        (``L``, the OUTBOUND one)."""
        return inbound_band_count(self.shard_count, self.lanes_per_shard)

    @property
    def inbound_band_narrower(self) -> bool:
        """``G < L`` — the inbound pool is the narrow one, so any plateau here may be an INGRESS plateau.
        (Count-only; see :data:`INBOUND_BAND_CHECK_BASIS` — a clean verdict does not exclude an ingress bind.)"""
        return self.dests > 0 and self.shard_count > 0 and self.inbound_bands < self.dests

    @property
    def sent_ratio(self) -> float | None:
        """``sent / offered`` — the DRIVE's fidelity to its own plan, emitted so :data:`_FIDELITY_SENT_FLOOR`
        can be RE-DERIVED from banked runs (the bar's own comment asks for exactly this)."""
        if self.offered <= 0 or self.sent < 0:
            return None
        return self.sent / self.offered

    @property
    def accepted_rate(self) -> float | None:
        """The ACCEPTED-derived rate this rung actually proves: ``achieved_intake / (hold + drain)`` — built
        from what the ENGINE TOOK over the REAL span, not from the ``aggregate_rate`` we ASKED for. The
        offered figure is a readback of the plan (ARTIFACT 3); this one cannot be. ``None`` when the hold or
        the drain was not recorded (an unmeasured span cannot denominate a rate)."""
        if self.hold_seconds <= 0 or self.drain_seconds is None:
            return None
        span = self.hold_seconds + self.drain_seconds
        if span <= 0:
            return None
        return self.achieved_intake / span

    @property
    def fidelity(self) -> RungFidelity:
        """Whether this rung is admissible EVIDENCE ABOUT THE ENGINE — and if not, whose fault it was
        (:func:`rung_fidelity`). The SAME predicate the two-box ``RungOutcome`` calls: one definition, two
        record types, both pinned by tests. A ``ceiling`` without a fidelity read is a statement about the
        PLAN, not about the fleet."""
        return rung_fidelity(
            sent=self.sent,
            acked=self.achieved_intake,
            offered=self.offered,
            deferred_backpressure=self.deferred_backpressure,
            deferred_schedule=self.deferred_schedule,
        )

    @property
    def fidelity_reason(self) -> str | None:
        """The operator-facing VOID reason (``None`` when admissible) — derived from the SAME inputs as
        :attr:`fidelity`, so the note and the verdict can never disagree."""
        return fidelity_note(
            self.fidelity,
            sent=self.sent,
            acked=self.achieved_intake,
            offered=self.offered,
            deferred_backpressure=self.deferred_backpressure,
            deferred_schedule=self.deferred_schedule,
        )

    @property
    def fill_ratio(self) -> float | None:
        """The ratio of the hold's SECOND-half median E2E to its FIRST-half median: the "still filling"
        discriminator. ``> 1`` means typical latency GREW across the hold (in-flight backlog not yet
        relaxed); ``~ 1`` means a steady plateau. Both halves are equal-length STEADY cohorts — the warm-up
        ramp and the post-hold drain are excluded by construction (see ``_FILLING_RATIO``).

        **NOT the STEP-4 §7 "M2" validity check** (different source, different split key, different bar,
        opposite purpose — that one EXCLUDES a rung from a regression at a 0.10 symmetric bar; this one
        LOWERS a ceiling at a 1.5 ratio bar). Do not conflate them.

        ``None`` when either half carries fewer than ``_FILLING_MIN_SAMPLES`` samples or the first-half
        median is zero — too little signal to judge, so the filling gate ABSTAINS (mirrors the soak
        slope's "None ⇒ not proven")."""
        if (
            self.e2e_first_half_count < _FILLING_MIN_SAMPLES
            or self.e2e_second_half_count < _FILLING_MIN_SAMPLES
            or self.e2e_first_half_p50_ms <= 0.0
        ):
            return None
        return self.e2e_second_half_p50_ms / self.e2e_first_half_p50_ms

    @property
    def filling(self) -> bool:
        """The rung's in-flight backlog was still GROWING at the hold's end — its second-half E2E ran
        materially longer than its first half (``fill_ratio > _FILLING_RATIO``). Such a rung has NOT
        reached a steady state; it only *looks* lossless-and-drained because the (generous) drain window
        eventually cleared a backlog that was still climbing while offered load held. It counts as a
        ceiling even when ``no_loss`` + ``drained`` both pass.

        ``fill_ratio is None`` (too few samples / not measured — which includes EVERY two-box run) ⇒ NOT
        filling. The gate abstains rather than guessing."""
        ratio = self.fill_ratio
        return ratio is not None and ratio > _FILLING_RATIO

    @property
    def ceiling(self) -> bool:
        """The fleet could not SUSTAIN the offered load at this rate — the ladder stops climbing. The bar
        is :func:`_is_ceiling` (loss/drain, intake shortfall, or :attr:`filling`)."""
        return _is_ceiling(
            no_loss=self.no_loss,
            achieved_intake=self.achieved_intake,
            offered=self.offered,
            filling=self.filling,
        )

    @classmethod
    def from_report(
        cls, aggregate_rate: float, report: ShardCertReport, *, hold_seconds: float = 0.0
    ) -> ShardCertStepRecord:
        return cls(
            aggregate_rate=aggregate_rate,
            hold_seconds=hold_seconds,
            offered=report.offered,
            achieved_intake=report.achieved_intake,
            delivered=report.delivered_distinct,
            in_pipeline_peak=report.in_pipeline_peak,
            ack_p50_ms=report.ack_p50_ms,
            ack_p99_ms=report.ack_p99_ms,
            drain_seconds=report.drain_seconds,
            no_loss=report.acked_not_delivered == 0 and report.drained,
            lane_inversions=report.lane_inversions,
            lane_repeats=report.lane_repeats,
            stranded_nonterminal=report.stranded_nonterminal,
            # The filling terms MUST be carried across: they are the ONLY input to `fill_ratio`, and
            # omitting them silently pins every half-count at the 0 sentinel ⇒ `fill_ratio is None` ⇒ the
            # filling gate abstains on EVERY rung, i.e. the detector is dead code that reads as "steady".
            e2e_first_half_p50_ms=report.e2e_first_half_p50_ms,
            e2e_first_half_count=report.e2e_first_half_count,
            e2e_second_half_p50_ms=report.e2e_second_half_p50_ms,
            e2e_second_half_count=report.e2e_second_half_count,
            # ARTIFACT 4 — the SAME carry-across, for the same reason. `sent` lives on ShardCertReport and
            # NOT carrying it here would pin `fidelity` at UNKNOWN on every co-located rung: a gate that is
            # structurally incapable of firing. That is precisely how `fill_ratio` died. The deferral CAUSE
            # SPLIT rides with it — without the causes the gate cannot tell an engine backpressure bind from
            # a rig shortfall, and v1 resolved that ambiguity by blaming the rig.
            sent=report.sent,
            deferred_backpressure=report.deferred_backpressure,
            deferred_schedule=report.deferred_schedule,
            # ARTIFACTS 2 + 5 — the SAME carry-across, a THIRD time. `run_shardcert` MEASURES the pool, the
            # routing shape and the lane count; this record dropped all of them, so the ladder artifact could
            # not name the configuration its own ceiling was pinned under. Measured-then-discarded is
            # indistinguishable, in the artifact, from never-measured.
            dests=report.dests,
            handlers=report.handlers,
            delivering=report.delivering,
            routing=report.routing,
            lanes_per_shard=report.lanes_per_shard,
            shard_count=len(report.shards),
            pool=report.pool,
        )

    def to_json_dict(self) -> dict[str, object]:
        ratio = self.fill_ratio
        fid = self.fidelity
        return {
            "aggregate_rate": round(self.aggregate_rate, 3),
            "hold_seconds": self.hold_seconds,
            "offered": self.offered,
            "sent": self.sent,  # ARTIFACT 4: the drive-side half of the fidelity gate (-1 = not recorded)
            # ARTIFACT 4: the drive's fidelity to its own plan, so `_FIDELITY_SENT_FLOOR` (0.98) can be
            # RE-DERIVED from banked runs rather than taken on trust — the bar is not yet anchored to a
            # measurement of the token bucket's real boundary-drop rate.
            "sent_ratio": None if self.sent_ratio is None else round(self.sent_ratio, 4),
            "achieved_intake": self.achieved_intake,
            "delivered": self.delivered,
            # ARTIFACT 3: the ACCEPTED-derived rate (intake / (hold + measured drain)) BESIDE the offered
            # `aggregate_rate` above. The offered figure cannot disagree with the plan; this one can.
            "accepted_rate": None if self.accepted_rate is None else round(self.accepted_rate, 3),
            # ARTIFACT 4: WAS THIS RUNG EVIDENCE ABOUT THE ENGINE AT ALL? `ceiling` above/below is scored on
            # loss + intake + filling, none of which compare `sent` to `offered` — so an under-driven rung
            # (the DEFAULT expectation: partitioned needs ~520/s of drive against the ~16 the rig pushes)
            # reads as a clean ceiling that is a pure function of the PLAN. `admissible` false ⇒ VOID.
            "fidelity": fid.value,
            "fidelity_admissible": fid.admissible,
            # Whether the rung's RATE LABEL is real (the offer reached the engine, or the engine refused to
            # read it) — the predicate that decides whether it may BRACKET the ceiling, as distinct from
            # PIN one. An ENGINE/BACKPRESSURE bind is driven; a drive/offer shortfall is not.
            "fidelity_driven": fid.driven,
            "fidelity_reason": self.fidelity_reason,
            "fidelity_gate_version": FIDELITY_GATE_VERSION,
            # ⭐ THE DEFERRAL CAUSE SPLIT (gate v2) — WHY `sent` fell short, which `sent` itself cannot say.
            # A full send buffer means the ENGINE stopped reading its socket (backpressure); a tick-lag
            # means the RIG could not schedule. These are OPPOSITE findings and were ONE counter.
            # -1 = not recorded ⇒ a shortfall is scored OFFER_SHORTFALL (cause-neutral), never "fix the rig".
            "deferred_backpressure": self.deferred_backpressure,
            "deferred_schedule": self.deferred_schedule,
            "in_pipeline_peak": self.in_pipeline_peak,
            "ack_ms": {"p50": round(self.ack_p50_ms, 3), "p99": round(self.ack_p99_ms, 3)},
            "drain_seconds": self.drain_seconds,
            "no_loss": self.no_loss,
            "lane_inversions": self.lane_inversions,
            "lane_repeats": self.lane_repeats,
            "stranded_nonterminal": self.stranded_nonterminal,
            # Filling (2026-07-13): surfaced so a rung stopped by FILLING is distinguishable from one
            # stopped by loss/intake. Without it a filling ceiling reads as `no_loss=true, ceiling=true` —
            # inexplicable. `e2e_fill_ratio: null` = ABSTAINED (thin data / not measured), NOT "steady".
            # `ceiling_gate_version` pins WHICH sustain bar produced `ceiling`, so a reader cannot silently
            # compare a v2 (filling-gated) ceiling against a v1 one.
            "e2e_fill_ratio": None if ratio is None else round(ratio, 3),
            "filling": self.filling,
            "ceiling": self.ceiling,
            "ceiling_gate_version": CEILING_GATE_VERSION,
            # ARTIFACTS 2 + 5: the CONFIGURATION this rung ran on — the pool (its acquire_wait evidence and
            # the pre-registered tripwire) and the three-pool topology (G vs L, and the routing shape that
            # makes handlers/delivering readable). Without these the ladder's ceiling is unattributable.
            "topology": {
                "dests": self.dests,  # L (outbound lane pool width)
                "handlers": self.handlers,
                "delivering": self.delivering,
                "routing": self.routing,
                "lanes_per_shard": self.lanes_per_shard,
                "shards": self.shard_count,
                "inbound_bands": self.inbound_bands,  # G (ingress/routed lane pool width)
                "inbound_bands_narrower_than_dests": self.inbound_band_narrower,
            },
            "store_pool": self.pool.to_json_dict(),
        }

    def render(self) -> str:
        loss = "OK" if self.no_loss else "LOSS"
        drain = "n/a" if self.drain_seconds is None else f"{self.drain_seconds:.1f}s"
        ratio = self.fill_ratio
        fill = "n/a" if ratio is None else f"{ratio:.2f}"  # n/a = ABSTAINED, never "steady"
        fid = self.fidelity
        return (
            f"rate={self.aggregate_rate:g}/s offered={self.offered} sent={self.sent} "
            f"intake={self.achieved_intake} "
            f"delivered={self.delivered} | in_pipeline_peak={self.in_pipeline_peak} "
            f"ack p50/p99={self.ack_p50_ms:.1f}/{self.ack_p99_ms:.1f}ms drain={drain} | "
            f"no_loss={loss} inversions={self.lane_inversions} repeats={self.lane_repeats} "
            f"stranded={self.stranded_nonterminal} fill={fill}"
            + ("  <= FILLING" if self.filling else "")
            + ("  <= CEILING" if self.ceiling else "")
            # A rung the ENGINE bound (intake/backpressure) is NOT the same animal as one the rig never
            # drove: it is a REAL engine finding at a REAL rate, and printing "FIDELITY VOID" over it is how
            # an operator ends up "fixing the rig" in response to the result the ladder exists to produce.
            # Both are inadmissible to PIN a ceiling; only the not-driven ones are void of a RATE.
            + (
                ""
                if fid.admissible
                else f"  <= ENGINE BIND ({fid.value.upper()})"
                if fid.driven
                else f"  <= FIDELITY VOID ({fid.value.upper()})"
            )
        )


@dataclass
class ShardCertLadderReport:
    """The ascending rate-ladder sweep — one :class:`ShardCertStepRecord` per hold step, stopping at
    the first step that fails to SUSTAIN the offered load (:attr:`ShardCertStepRecord.ceiling` — a
    non-draining/lossy step or a materially-short intake).

    ARTIFACT 4: ``ceiling_rate`` is now ADMISSIBILITY-GATED, exactly as the two-box ladder's pinned ceiling
    is. :func:`_is_ceiling` fires on ``achieved_intake < offered * 0.95`` — which is EXACTLY what a DRIVE
    SHORTFALL produces (the engine can only ACK what the rig SENT) — so a rung the load generator could not
    push used to set the headline ceiling and stop the climb. The intake term CANNOT tell "the engine would
    not take it" from "the rig never offered it"; only the fidelity gate can, and that distinction is the
    entire point. A DRIVE_SHORTFALL ceiling now publishes NO ``ceiling_rate`` and exits 2."""

    records: list[ShardCertStepRecord] = field(default_factory=list)
    ceiling_rate: float | None = None
    #: WHY there is no ``ceiling_rate`` despite the climb stopping (see :data:`_CEILING_VOID_REASONS`):
    #: ``"drive_shortfall"`` (the rig ran out), ``"offer_shortfall"`` (the plan never reached the wire and
    #: the CAUSE WAS NOT MEASURED) or ``"fidelity_unknown"`` (the gate's inputs were not recorded). All three
    #: exit 2 — nothing was established about the engine at the stopping rung. ``None`` when the ceiling is
    #: admissible (or engine-bound, which KEEPS its rate) or the climb never stopped.
    ceiling_void_reason: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Every step held the correctness invariants WHILE climbing (no acknowledged loss, per-lane
        FIFO, no stranded rows). The ceiling itself is a MEASUREMENT, not a failure."""
        return bool(self.records) and all(
            r.no_loss and r.lane_inversions == 0 and r.stranded_nonterminal == 0
            for r in self.records
        )

    @property
    def ceiling_pool_bound(self) -> bool:
        """ARTIFACT 2 — **THE PUBLISHED CEILING IS A STORE-POOL BIND, NOT AN ENGINE ONE.** The rung the
        ``ceiling_rate`` came from (or, absent one, the pinned rung) TRIPPED the pre-registered pool tripwire.

        The tripwire used to be ADVISORY ONLY: it appended a string to ``notes`` and a number to
        ``store_pool.tripped_at_rates``, and entered NO verdict, NO bracket, NO result token and NO exit code.
        So a pool-bound ceiling still shipped as a confident PASS — which is verbatim the failure this
        artifact exists to prevent, since a pool bind is column-for-column identical to the pooled-claim wall
        it would have been blamed on (and would have commissioned an engine rewrite against a BENCH
        ARTIFACT). A ceiling whose own rung tripped the pool tripwire must not publish a rate."""
        # SAME PREDICATE AS THE TWO-BOX LADDER (ConsolidatedLadderReport.ceiling_pool_bound): ANY measured
        # rung that tripped taints the ceiling. The two callers previously disagreed on PRECEDENCE — this one
        # keyed on the collapse rung, the two-box one on the pinned rung — and the two-box reading was inert
        # on the case that matters (the pool announces itself on the rung it BREAKS, not the one it lets
        # through). One predicate, fail-safe in both. A false taint costs a re-run; a missed one costs an
        # engine rewrite against a bench artifact.
        return any(r.pool.tripped for r in self.records)

    @property
    def setup_degraded(self) -> bool:
        """The climb stopped on a rung that established NOTHING about the engine — the rig ran out
        (``drive_shortfall``), the offer never reached the wire and we cannot say why (``offer_shortfall``),
        or the gate's inputs were unrecorded (``fidelity_unknown``). None of those is a load-generator-
        independent measurement, so none may read as a clean PASS with a confident ceiling: exit 2,
        ``ceiling_rate`` null (see :attr:`ceiling_void_reason`).

        ARTIFACT 2 adds the POOL: a ceiling measured on a rung that tripped the pre-registered store-pool
        tripwire is a POOL BIND, not an engine ceiling, and must not publish a rate either."""
        return self.ceiling_void_reason is not None or self.ceiling_pool_bound

    @property
    def exit_code(self) -> int:
        """0 (correctness held) / 1 (a correctness break) / 2 (a SETUP degradation — nothing was measured
        about the engine at the rung that stopped the climb, or the STORE POOL was the constraint there)."""
        if not self.ok:
            return 1
        return 2 if self.setup_degraded else 0

    @property
    def result_label(self) -> str:
        if not self.ok:
            return "FAIL"
        # POOL_BOUND is called out by name, not folded into SETUP_DEGRADED: "the pool was the wall" is a
        # specific, actionable finding (raise --store-pool-size and re-run), and the whole point of ARTIFACT
        # 2 is that it must never again be indistinguishable from a claim wall in the headline.
        if self.ceiling_pool_bound:
            return "POOL_BOUND"
        return "SETUP_DEGRADED" if self.setup_degraded else "PASS"

    @property
    def ceiling_admissible(self) -> bool:
        """The published ``ceiling_rate`` came from a rung that was EVIDENCE ABOUT THE ENGINE — the offer
        reached the wire AND the store pool was not the constraint. False when the climb stopped on a
        not-driven rung (then ``ceiling_rate`` is ``None``) or on a POOL-BOUND one (ARTIFACT 2)."""
        return (
            self.ceiling_rate is not None
            and self.ceiling_void_reason is None
            and not self.ceiling_pool_bound
        )

    @property
    def admissible_records(self) -> list[ShardCertStepRecord]:
        """The rungs that are evidence about the ENGINE — the only ones a rate may be pinned from."""
        return [r for r in self.records if r.fidelity.admissible]

    @property
    def pinned_record(self) -> ShardCertStepRecord | None:
        """The highest-rate rung that both SUSTAINED (not a ceiling) and was actually DRIVEN — the honest
        FLOOR this climb proved. ``None`` when nothing sustained admissibly."""
        held = [r for r in self.admissible_records if not r.ceiling]
        return max(held, key=lambda r: r.aggregate_rate) if held else None

    @property
    def pinned_rate(self) -> float | None:
        """The pinned (offered) rate of :attr:`pinned_record` — a FLOOR, and still OFFERED-derived."""
        p = self.pinned_record
        return None if p is None else p.aggregate_rate

    @property
    def pinned_accepted_rate(self) -> float | None:
        """ARTIFACT 3: the pinned rung's ACCEPTED-derived rate (``intake / (hold + drain)``) — built from
        what the engine TOOK, not from what we ASKED for. ``None`` when nothing pinned / no measured span."""
        p = self.pinned_record
        return None if p is None else p.accepted_rate

    @property
    def fidelity_void_rates(self) -> list[float]:
        """The rates whose rung was NOT admissible evidence about the engine (ARTIFACT 4) — a drive
        shortfall, an engine intake bind, or an unrecorded gate. Reported so an operator reading
        ``ceiling_rate`` can see at a glance whether the climb it came from was actually driven."""
        return [r.aggregate_rate for r in self.records if r.fidelity is not RungFidelity.ADMISSIBLE]

    @property
    def store_pool(self) -> PoolStats:
        """ARTIFACT 2: the pool this ladder ran on — the pinned rung's when there is one, else the first
        rung that measured a pool at all. A ladder whose pool size is not recoverable from its own artifact
        is unauditable, and a POOL BIND is column-for-column identical to the pooled-claim wall."""
        pinned = self.pinned_record
        if pinned is not None and pinned.pool.measured:
            return pinned.pool
        for r in self.records:
            if r.pool.measured:
                return r.pool
        return self.records[0].pool if self.records else EMPTY_POOL_STATS

    @property
    def pool_tripped_rates(self) -> list[float]:
        """The rates whose rung TRIPPED the pre-registered pool tripwire — i.e. where the STORE POOL, not
        the claim query and not a lane, was the constraint."""
        return [r.aggregate_rate for r in self.records if r.pool.tripped]

    def _topology(self) -> dict[str, object]:
        """ARTIFACT 5: the three-pool topology (G vs L) + the routing shape, taken from the LAST rung (every
        rung of a ladder runs the same shape; the last one is the one the ceiling came from)."""
        r = self.records[-1] if self.records else None
        if r is None:
            return {"recorded": False, "inbound_band_check_basis": INBOUND_BAND_CHECK_BASIS}
        return {
            "recorded": True,
            "dests": r.dests,  # L — the OUTBOUND per-lane pool width
            "handlers": r.handlers,
            "delivering": r.delivering,
            "routing": r.routing,  # broadcast | partitioned — REQUIRED to read handlers/delivering
            "lanes_per_shard": r.lanes_per_shard,
            "shards": r.shard_count,
            "inbound_bands": r.inbound_bands,  # G — the INGRESS/ROUTED per-lane pool width
            "inbound_bands_narrower_than_dests": r.inbound_band_narrower,
            # A clean G >= L verdict does NOT exclude an ingress bind — the check compares COUNTS, not cycles.
            "inbound_band_check_basis": INBOUND_BAND_CHECK_BASIS,
        }

    def to_json_dict(self) -> dict[str, object]:
        return {
            # v2 (THE BENCH ARTIFACTS, 2026-07-14) — kind=shardcert_ladder was v1 at HEAD and this is ONE
            # unreleased change, so it is ONE bump. (An earlier draft narrated a "v2" and a "v3" as separate
            # historical steps and emitted 3: a version number that NO artifact can ever carry, which sends a
            # consumer hunting for a v2 that does not exist. Exactly the class of trap this PR is about.)
            #
            # ⚠️ ONE DELIBERATE REDEFINITION, plus additions:
            #  * ⚠️ REDEFINED: `ceiling_rate` is now NULL when the climb stopped on a rung whose OFFER NEVER
            #    REACHED THE ENGINE (`drive_shortfall` / `offer_shortfall` / `fidelity_unknown`) or on one
            #    that TRIPPED THE STORE-POOL TRIPWIRE. `_is_ceiling` fires on the intake shortfall a drive
            #    shortfall ITSELF CAUSES, so a v1 `ceiling_rate` may be a pure function of the PLAN — or of
            #    the POOL. `ceiling_void_reason` / `ceiling_pool_bound` say which, `ceiling_admissible` is
            #    the boolean, and both cases now exit 2 (`result` gained SETUP_DEGRADED and POOL_BOUND).
            #    An ENGINE INTAKE BIND / BACKPRESSURE BIND ceiling is a REAL finding and KEEPS its rate.
            #  * ADDED: `topology` (G/L/lanes_per_shard/routing — ARTIFACT 5) and `store_pool` (+ per-rung),
            #    so the pool size and the three-pool shape a ceiling was measured under are recoverable from
            #    the artifact. They were MEASURED by `run_shardcert` and DISCARDED by the record.
            #  * ADDED: `pinned_rate` / `pinned_accepted_rate` — the accepted-derived floor (ARTIFACT 3).
            #  * ADDED per record: `hold_seconds`, `sent`, `sent_ratio`, `accepted_rate`, the FIDELITY block
            #    (incl. the `deferred_backpressure`/`deferred_schedule` CAUSE SPLIT), `topology`,
            #    `store_pool`.
            "schema_version": 2,
            "kind": "shardcert_ladder",
            "result": self.result_label,
            "exit_code": self.exit_code,
            "ceiling_rate": self.ceiling_rate,
            "ceiling_admissible": self.ceiling_admissible,
            "ceiling_void_reason": self.ceiling_void_reason,
            # ARTIFACT 2: the ceiling's own rung tripped the pre-registered pool tripwire ⇒ the wall is the
            # STORE POOL, not the engine. Gated (exit 2 / result POOL_BOUND), not merely noted.
            "ceiling_pool_bound": self.ceiling_pool_bound,
            # ARTIFACT 3: the honest FLOOR the climb actually proved, in both currencies. `pinned_rate` is
            # still OFFERED-derived; `pinned_accepted_rate` is built from what the engine ACCEPTED over the
            # real span (hold + measured drain) and cannot agree with the plan by construction.
            "pinned_rate": self.pinned_rate,
            "pinned_accepted_rate": (
                None if self.pinned_accepted_rate is None else round(self.pinned_accepted_rate, 3)
            ),
            "topology": self._topology(),
            "store_pool": {
                **self.store_pool.to_json_dict(),
                "product_default": PRODUCT_STORE_POOL_SIZE,
                "tripped_at_rates": self.pool_tripped_rates,
            },
            "fidelity": {
                "gate_version": FIDELITY_GATE_VERSION,
                "sent_floor": _FIDELITY_SENT_FLOOR,
                "acked_floor": _FIDELITY_ACKED_FLOOR,
                "void_rates": self.fidelity_void_rates,
                "all_admissible": not self.fidelity_void_rates,
                # The FOUR non-admissible outcomes, called by name, because conflating any two of them is the
                # whole defect. The first two are ENGINE findings (the offer reached the engine and it would
                # not absorb it); the third is a RIG finding; the fourth is an HONEST NON-FINDING.
                "any_engine_intake_bind": any(
                    r.fidelity is RungFidelity.ENGINE_INTAKE_BIND for r in self.records
                ),
                "any_backpressure_bind": any(
                    r.fidelity is RungFidelity.BACKPRESSURE_BIND for r in self.records
                ),
                "any_drive_shortfall": any(
                    r.fidelity is RungFidelity.DRIVE_SHORTFALL for r in self.records
                ),
                # `sent` fell short and the deferral CAUSE was not recorded — we cannot say whether the rig
                # ran out or the engine applied backpressure. NOT a rig failure; an unattributed one.
                "any_offer_shortfall": any(
                    r.fidelity is RungFidelity.OFFER_SHORTFALL for r in self.records
                ),
            },
            "records": [r.to_json_dict() for r in self.records],
            "notes": self.notes,
        }

    def render(self) -> str:
        lines = [
            "ShardCert rate-ladder (ascending; stops when the offered rate is not sustained)",
            "",
        ]
        for r in self.records:
            lines.append("  " + r.render())
        lines.append("")
        lines.append(f"  {self.store_pool.render()}")
        topo = self._topology()
        if topo.get("recorded"):
            narrow = (
                "   <= INBOUND IS THE NARROW POOL"
                if topo["inbound_bands_narrower_than_dests"]
                else ""
            )
            lines.append(
                f"  pools: G={topo['inbound_bands']} inbound bands vs L={topo['dests']} outbound "
                f"lanes  routing={topo['routing']}{narrow}"
            )
        lines.append("")
        if self.ceiling_rate is not None and self.ceiling_pool_bound:
            # ARTIFACT 2: the rate EXISTS but it is the POOL's, not the engine's. Say so where the number is
            # read, not only in a note nobody scrolls to.
            lines.append(
                f"  ceiling ~ {self.ceiling_rate:g} msg/s (aggregate)  <= ⚠ POOL BOUND: this rung TRIPPED "
                f"the pre-registered store-pool tripwire (requested={self.store_pool.requested}). This is a "
                "STORE-POOL ceiling, NOT an engine ceiling — it is column-for-column identical to a claim "
                "wall. Raise --store-pool-size and re-run before attributing it to the engine."
            )
        elif self.ceiling_rate is not None:
            lines.append(f"  ceiling ~ {self.ceiling_rate:g} msg/s (aggregate)")
        elif self.ceiling_void_reason is not None:
            # NEVER print a rate here: the rung that stopped the climb was not evidence about the engine.
            lines.append(
                f"  ceiling: NONE PUBLISHED — the climb stopped on a rung that FAILED FIDELITY "
                f"({self.ceiling_void_reason}). It is not an engine ceiling; fix the rig and re-run."
            )
        else:
            lines.append("  no ceiling reached across the ladder (raise the top rate)")
        pin = self.pinned_rate
        if pin is not None:
            acc = self.pinned_accepted_rate
            acc_txt = "n/a (no measured span)" if acc is None else f"{acc:g} msg/s"
            lines.append(
                f"  highest DRIVEN sustained rung: {pin:g} msg/s offered | accepted {acc_txt}"
            )
        for note in self.notes:
            lines.append(f"  note: {note}")
        lines.append("")
        lines.append(f"RESULT: {self.result_label} -> exit {self.exit_code}")
        return "\n".join(lines)


def parse_rate_ladder(spec: str) -> list[float]:
    """Parse the ``--rate-ladder`` spec into an ascending list of aggregate rates. Two forms:
    ``"40,80,120"`` (explicit comma list) or ``"start:stop:step"`` (``"40:200:40"`` ⇒ 40,80,…,200)."""
    spec = spec.strip()
    if ":" in spec:
        parts = spec.split(":")
        if len(parts) != 3:
            raise ValueError(f"rate-ladder range must be start:stop:step, got {spec!r}")
        start, stop, step = (float(p) for p in parts)
        if step <= 0:
            raise ValueError(f"rate-ladder step must be > 0, got {step}")
        rates: list[float] = []
        r = start
        while r <= stop + 1e-9:
            rates.append(round(r, 6))
            r += step
        if not rates:
            raise ValueError(f"rate-ladder range {spec!r} produced no rates")
        return rates
    rates = [float(x) for x in spec.split(",") if x.strip()]
    if not rates:
        raise ValueError(f"rate-ladder list {spec!r} named no rates")
    return rates


async def _run_ladder_step(
    *,
    rate: float,
    dests: int,
    handlers: int | None,
    delivering: int | None,
    hold_seconds: float,
    drain_timeout: float,
    store_env: Mapping[str, str] | None,
    cwd: Path | None,
    sink_host: str,
    sink_port: int | None,
    store_pool_size: int | None = None,
    strict_bands: bool = False,
) -> ShardCertStepRecord:
    """Drive ONE ladder hold step at ``rate`` (a full fresh-fleet ``run_shardcert``, no kill, peak
    sampled) and fold it into a :class:`ShardCertStepRecord`. A module-level seam so a unit test can
    substitute a synthetic step and exercise the climb/stop logic without a live SQL Server."""
    report = await run_shardcert(
        dests=dests,
        handlers=handlers,
        delivering=delivering,
        aggregate_rate=rate,
        hold_seconds=hold_seconds,
        kill=False,
        drain_timeout=drain_timeout,
        store_env=store_env,
        cwd=cwd,
        sink_host=sink_host,
        sink_port=sink_port,
        capture_peak=True,
        store_pool_size=store_pool_size,
        strict_bands=strict_bands,
    )
    return ShardCertStepRecord.from_report(rate, report, hold_seconds=hold_seconds)


async def run_shardcert_ladder(
    *,
    rates: Sequence[float],
    dests: int = 8,
    handlers: int | None = None,
    delivering: int | None = None,
    hold_seconds: float = 60.0,
    drain_timeout: float = 120.0,
    store_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    sink_host: str = "127.0.0.1",
    sink_port: int | None = None,
    store_pool_size: int | None = None,
    strict_bands: bool = False,
) -> ShardCertLadderReport:
    """Run the ascending rate-ladder ceiling hunt: for each aggregate rate (sorted ascending), drive one
    hold step and record it; STOP at the first step that fails to SUSTAIN the offered load
    (:attr:`ShardCertStepRecord.ceiling` — a non-draining/lossy step, or an intake that fell materially
    short of offered). Each step is a fresh fleet + fresh store (mirrors ``multishard``'s per-step
    isolation), so the recorded intake/delivered/backlog are clean per rate. Correctness is asserted per
    step via :attr:`ShardCertLadderReport.ok` — the ceiling is a measurement, not a failure."""
    report = ShardCertLadderReport()
    ordered = sorted(dict.fromkeys(float(r) for r in rates))  # ascending, de-duplicated
    if not ordered:
        raise ValueError("run_shardcert_ladder needs at least one rate")
    for rate in ordered:
        rec = await _run_ladder_step(
            rate=rate,
            dests=dests,
            handlers=handlers,
            delivering=delivering,
            hold_seconds=hold_seconds,
            drain_timeout=drain_timeout,
            store_env=store_env,
            cwd=cwd,
            sink_host=sink_host,
            sink_port=sink_port,
            store_pool_size=store_pool_size,
            strict_bands=strict_bands,
        )
        report.records.append(rec)
        # ARTIFACT 4: a rung that was not DRIVEN at its own plan is not a ceiling — say so at the moment it
        # is recorded, so a `ceiling_rate` read out of this report is never quoted without the caveat.
        if not rec.fidelity.admissible:
            note = rec.fidelity_reason
            if note is not None:
                report.notes.append(f"{rate:g} msg/s: {note}")
        # ARTIFACT 2: the pool tripwire, RECORDED at the rung that tripped it (it gates `ceiling_pool_bound`).
        if rec.pool.tripped and rec.pool.trip_reason is not None:
            report.notes.append(f"{rate:g} msg/s: {rec.pool.trip_reason}")
        if rec.ceiling:
            # ARTIFACT 4 — THE CEILING IS ADMISSIBILITY-GATED. `_is_ceiling` fires on
            # `achieved_intake < offered * (1 - _INTAKE_TOL)`, and that is EXACTLY what a DRIVE SHORTFALL
            # produces: the engine can only ACK what the rig SENT, so a rig that pushed 30% of the plan
            # forces a 70% intake shortfall and trips the bar. The intake term is structurally INCAPABLE of
            # telling "the engine would not take it" from "the rig never offered it" — that conflation is
            # the whole reason this gate exists. So the split is on `fidelity.driven` (did the offered rate
            # actually reach the engine?), NOT on `admissible`:
            #
            #   * NOT DRIVEN (DRIVE_SHORTFALL / OFFER_SHORTFALL / UNKNOWN) -> publish NO ceiling_rate (it
            #     would be a pure function of the PLAN), STOP the climb anyway (the offer is not reaching the
            #     engine; every higher rung is more meaningless, not less), and exit 2 — a rig failure, or an
            #     UNATTRIBUTED one, must never read as a clean PASS with a confident number.
            #   * DRIVEN (ENGINE_INTAKE_BIND / BACKPRESSURE_BIND) -> a REAL engine finding: the drive offered
            #     the rate and the ENGINE would not absorb it. It KEEPS its ceiling_rate, and it is NAMED.
            fid = rec.fidelity
            if fid.not_driven:
                report.ceiling_void_reason = _CEILING_VOID_REASONS[fid]
                report.notes.append(
                    f"NO CEILING PUBLISHED at {rate:g} msg/s: the rung tripped the intake bar "
                    f"(intake {rec.achieved_intake} of offered {rec.offered}) — but the OFFER NEVER REACHED "
                    f"THE ENGINE ({fid.value}: sent {rec.sent} of {rec.offered}), so the intake shortfall is "
                    "a CONSEQUENCE of that, not an engine result. ceiling_rate is null. "
                    + (
                        "The cause was NOT ATTRIBUTED (the deferral split was not recorded) — do NOT read "
                        "this as either a rig failure or an engine bind."
                        if fid is RungFidelity.OFFER_SHORTFALL
                        else "The climb stops here because THE RIG is exhausted; fix the rig and re-run."
                        if fid is RungFidelity.DRIVE_SHORTFALL
                        else "The gate's inputs were not recorded; an unmeasured gate is never a pass."
                    )
                )
                break
            report.ceiling_rate = rate
            report.notes.append(
                f"ceiling at {rate:g} msg/s ({fid.value}): intake {rec.achieved_intake} of offered "
                f"{rec.offered} (no_loss={rec.no_loss}; sustain bar = offered*(1-{_INTAKE_TOL:g}))"
            )
            break
    return report


class _env_scope:
    """Temporarily set env vars (so ``load_config`` reads the intended graph shape), restore on exit."""

    def __init__(self, env: Mapping[str, str]) -> None:
        self._env = dict(env)
        self._saved: dict[str, str | None] = {}

    def __enter__(self) -> None:
        import os

        for k, v in self._env.items():
            self._saved[k] = os.environ.get(k)
            os.environ[k] = v

    def __exit__(self, *exc: object) -> None:
        import os

        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# =====================================================================================================
# WS-C two-box split — the engine-launcher half + the driver half, coordinated by the file-drop
# handshake. The co-located `run_shardcert` above stays byte-identical (single process, no coord); these
# two run as SEPARATE processes (one per box). See harness/load/coord.py for the two-message protocol.
#
# Reconciled onto the #836 LANES-AWARE base: the engine reserves N*lanes contiguous inbound ports and the
# driver opens one persistent connection per (shard, lane) — `lanes` is discovered from the built graph
# (`len(reg.inbound) // n`, exactly as the single-box `run_shardcert` derives it) and advertised in
# SHARDS_READY so the two halves stay in lock-step across the box boundary.
# =====================================================================================================


# --- shared setup helpers (used by the split engine/driver halves) ---------------------------------


def _discover(
    dests: int, handlers: int, delivering: int, routing: str, *, strict_bands: bool = False
) -> tuple[list[str], dict[str, list[str]], int, int, str | None]:
    """Discover the shard set, per-shard owned destination lanes, shard count ``n``, lanes-per-shard, and
    the ``G < L`` band warning (``None`` when the inbound side is wide enough) from the ``shardcert`` graph
    (with the FULL ``dests``/``handlers``/``delivering`` shape applied + the ambient
    ``MEFOR_SHARDCERT_LANES_PER_SHARD``) BEFORE serving. ``lanes`` is derived from the built graph
    (``len(reg.inbound) // n``) — the SAME derivation the single-box :func:`run_shardcert` uses — so the
    driver and the served graph stay in lock-step. Pure read of the config; no engine/store side effects.

    H/D/routing are scoped here, not left ambient: discovery and :func:`_shape_env` (which shapes the SERVED
    fleet) must build the same graph, and this is also where ``load_shape``'s invariant checks (``D <= dests``,
    ``D <= H``, and under ``partitioned`` the ``H == D == dests`` pin) fire — BEFORE any process is spawned.

    ARTIFACT 5: the ``G < L`` pre-flight (:func:`check_inbound_bands`) fires HERE for the same reason — this
    is the existing fail-loud shape-invariant choke point that BOTH two-box entry points already funnel
    through, so a programmatic/test caller cannot bypass it the way a CLI-only check would let it."""
    with _env_scope(
        {
            "MEFOR_SHARDCERT_DESTS": str(dests),
            "MEFOR_SHARDCERT_HANDLERS": str(handlers),
            "MEFOR_SHARDCERT_DELIVERING": str(delivering),
            "MEFOR_SHARDCERT_ROUTING": routing,
        }
    ):
        reg = load_config(_CONFIG_DIR)
    ids_list = shard_ids(reg)
    owned = {s: sorted(owned_destination_set(reg, s, ids_list)) for s in ids_list}
    n = len(ids_list)
    lanes = (len(reg.inbound) // n) if n else 1
    # Under partitioned-fanout the D-aware fanout check supersedes the raw G<dests check (which else
    # strict-aborts EVERY fanout run: dests >= D*G > G always). Record its note; don't strict-raise there.
    band_note = check_inbound_bands(
        n, lanes, dests, strict=strict_bands and routing != PARTITIONED_FANOUT
    )
    fanout_note = check_fanout_lane_headroom(
        n, lanes, dests, delivering, routing, strict=strict_bands
    )
    notes = [x for x in (band_note, fanout_note) if x]
    return ids_list, owned, n, lanes, ("\n".join(notes) or None)


def _shape_env(
    ids_list: list[str],
    inbound_base: int,
    dests: int,
    handlers: int,
    delivering: int,
    sink_host: str,
    sink_port: int,
    sink_ports: int = 1,
    *,
    # KEYWORD-ONLY, and the pre-existing positional order above is left untouched: inserting a `str`
    # positionally between `sink_port: int` and `sink_ports: int` would let a future caller (or a merge that
    # restores the old argument order) silently bind an int into `routing` and a str into `sink_ports`.
    # harness is not mypy-gated in CI, so nothing would catch the swap at review time.
    routing: str,
) -> dict[str, str]:
    """The ``MEFOR_SHARDCERT_*`` graph-shape env every ``serve --shard`` process shares. ``sink_host`` is
    where the shards deliver their outbound fan-out (the load-gen box on a two-box run; loopback
    co-located); ``sink_port``/``sink_ports`` are the base + width of the sink port band the driver binds
    (a SINGLE sink for the correctness cert — the fan-out width is exercised in a later PR). The
    lanes-per-shard + persistent knobs ride ambiently on ``os.environ`` (the CLI/caller sets them before
    config load), so the discovered graph and the served graph agree.

    This is what SHAPES THE SERVED FLEET, so ``handlers``/``delivering`` (BACKLOG #209) and ``routing`` must be
    pinned here explicitly — the same values :func:`_discover` scoped. Leaving them to ride ambiently would let
    a caller discover one graph and serve another, and the mismatch would surface only as a fabricated
    ``S != A*D``.

    NOTE the values pinned here are the GRAPH-BUILD pair (under ``partitioned``, ``H = D = dests`` — every
    handler owns a destination). The ACCOUNTING pair the drive box is told is the DERIVED ``(1, 1)`` — see
    :func:`reported_shape` and the SHARDS_READY post. Do not conflate them.

    ``transform`` is pinned to ``edit`` and that is LOAD-BEARING: it stamps the MSH-6 FIFO lane key the sink
    derives every per-lane ordering verdict from. Under ``cheap`` MSH-6 is never written, every delivery
    collapses onto the lane key ``""``, ``lanes_observed`` reads 1, and the per-lane FIFO check goes VACUOUS
    while still reporting PASS."""
    return {
        "MEFOR_SHARDCERT_SHARDS": ",".join(ids_list),
        "MEFOR_SHARDCERT_INBOUND_BASE": str(inbound_base),
        "MEFOR_SHARDCERT_DESTS": str(dests),
        "MEFOR_SHARDCERT_HANDLERS": str(handlers),
        "MEFOR_SHARDCERT_DELIVERING": str(delivering),
        "MEFOR_SHARDCERT_ROUTING": routing,
        "MEFOR_SHARDCERT_SINK_HOST": sink_host,
        "MEFOR_SHARDCERT_SINK_PORT": str(sink_port),
        "MEFOR_SHARDCERT_SINK_PORTS": str(sink_ports),
        "MEFOR_SHARDCERT_TRANSFORM": "edit",
    }


def _escapes(inbound_bind_host: str) -> dict[str, str]:
    """The auth/insecure-TLS test escapes + the inbound bind interface every shard binds (``0.0.0.0`` on
    a two-box run so the off-box load-gen senders can reach it; loopback co-located)."""
    return {
        "MEFOR_ALLOW_INSECURE_TLS": "1",
        "MEFOR_ALLOW_INSECURE_CONFIG_SOURCE": "1",
        "MEFOR_SECURITY_REQUIRE_SIGN_IN": "false",
        "MEFOR_INBOUND_BIND_HOST": inbound_bind_host,
    }


def _choose_killed(
    kill: bool, kill_shard: str | None, ids_list: list[str], owned: dict[str, list[str]]
) -> str | None:
    """The shard the kill leg SIGKILLs: the pinned ``kill_shard`` if given, else the shard owning the
    MOST lanes (maximizes ownership-scoped recovery coverage). ``None`` when the run has no kill leg."""
    if not kill:
        return None
    if kill_shard is not None:
        return kill_shard
    return max(ids_list, key=lambda s: len(owned[s]))


async def _start_shards(
    ids_list: list[str],
    api_ports: list[int],
    *,
    node_env: Mapping[str, str],
    cwd: Path,
    inbound_base: int,
    lanes: int,
    preflight_host: str,
    nodes: dict[str, ShardCertNode],
) -> None:
    """Start each ``serve --shard`` STRICTLY one-at-a-time behind a health gate + inbound-port preflight
    (the SS schema-init applock convoys at N>=4 simultaneous opens). Each shard binds ``lanes`` inbound
    ports (lane ``l`` of shard ``i`` on ``inbound_base + i*lanes + l``); EVERY one is readiness-gated at
    ``preflight_host``. Populates ``nodes`` as it goes — a partially-started fleet is left in ``nodes`` so
    the caller's ``finally`` still tears it down."""
    for i, s in enumerate(ids_list):
        node = ShardCertNode(s, api_ports[i], env=node_env, config_dir=_CONFIG_DIR, cwd=cwd)
        await node.start()
        nodes[s] = node
        if not await _await_health(node.url, timeout=60.0):
            raise RuntimeError(f"shard {s} did not become healthy\n{node.log_tail()}")
        for lane in range(lanes):
            port = inbound_base + i * lanes + lane
            if not await _await_port(preflight_host, port, timeout=30.0):
                raise RuntimeError(f"shard {s} inbound lane port {port} never bound")


async def _drive_load(
    conns: list[PersistentConnection],
    corpus: Any,
    mix: TypeMix,
    metrics: LiveMetrics,
    *,
    aggregate_rate: float,
    hold_seconds: float,
) -> None:
    """Drive an aggregate token-bucket load round-robin across the N*lanes shard-lane connections for
    ``hold_seconds`` — the DRIVER-half loop with NO kill (the SIGKILL stays engine-box-local on a timer).
    Same schedule/deferral accounting as the co-located bench's inline loop, minus the kill check."""
    loop = asyncio.get_running_loop()
    start = loop.time()
    next_due = start
    interval = 1.0 / aggregate_rate if aggregate_rate > 0 else 0.0
    sampler = corpus.sampler(mix)
    rr = 0
    while True:
        now = loop.time()
        if now - start >= hold_seconds:
            break
        emitted = 0
        while next_due <= now and emitted < _TOKEN_BATCH_CAP:
            out = corpus.next(sampler)
            conn = conns[rr % len(conns)]
            rr += 1
            if not conn.submit_nowait(out):
                # BUFFER FULL ⇒ ENGINE BACKPRESSURE (the write loop drains before it pops the next job, so
                # a full queue means the engine stopped reading). Counted apart from the schedule-side
                # deferral below, because `sent` is suppressed by THIS one and by the engine — attributing
                # the resulting shortfall to "the rig" is the fabrication the fidelity gate exists to stop.
                metrics.counters.deferred += 1
                metrics.counters.deferred_backpressure += 1
            next_due += interval
            emitted += 1
        if next_due <= now:
            behind = int((now - next_due) / max(interval, 1e-6)) + 1
            metrics.counters.deferred += behind  # THE RIG never got these onto a connection at all
            metrics.counters.deferred_schedule += behind
            next_due = now + interval
        await asyncio.sleep(max(0.0, min(next_due - loop.time(), _MAX_TICK_SLEEP)))


def _kill_delay(kill_at_fraction: float, hold_seconds: float) -> float:
    """How long after the driver's ``DRIVE_START`` the engine-local SIGKILL fires: ``fraction × hold``.
    Anchoring on the engine's OBSERVATION of ``DRIVE_START`` (not a shared wall clock) means the two
    boxes never compare monotonic clocks — the sub-poll-interval handshake latency is negligible."""
    return max(0.0, kill_at_fraction * hold_seconds)


async def _kill_after(node: ShardCertNode, delay: float) -> float:
    """Sleep ``delay`` seconds then SIGKILL ``node`` (a LOCAL PID — never remoted). Returns the monotonic
    kill instant so the engine half can time functional recovery from it."""
    await asyncio.sleep(delay)
    node.kill()
    return time.monotonic()


@dataclass
class ShardCertEngineReport:
    """The ENGINE half's outcome — the store-truth signals that need direct store access (stranded
    non-terminal rows + the stage/status breakdown) plus its OWN ``/stats`` drain gauge, the ownership
    map, and recovery timing. The sink/tracker VERDICT (no-loss, per-lane FIFO, duplicates) is the DRIVER
    half's report — the engine box never sees the sink."""

    shards: tuple[str, ...]
    owned: dict[str, list[str]]
    killed_shard: str | None
    stranded_nonterminal: int
    queue_breakdown: str
    # The engine drains its OWN /stats before the store-truth read, so it carries a self-contained
    # store-truth verdict (`ok`). Defaulted so an older report / a partial run deserializes unchanged.
    drained: bool = False
    engine_dead: int = 0
    # All-stage dead-letter count (store-truth). `engine_dead` above is `stats().dead`, which is
    # OUTBOUND-stage-scoped; a router/handler regression dead-letters at the INGRESS or ROUTED stage
    # (`dead_letter_now` leaves `stage` unchanged), which `engine_dead` misses. Those rows were
    # ACK-on-receipt'd, so they are acknowledged loss the engine's OWN store-truth verdict must catch
    # without leaning on the driver half's sink-truth. Defaulted so an older report deserializes unchanged.
    dead_total: int = 0
    # BACKLOG #229: the delivery-blocking rows (non-terminal + dead) SPLIT by pipeline stage — what the A4b
    # cross-observer permit needs to charge each strand the right number of blocked deliveries (ingress
    # blocks D, outbound 1, routed [0,1]) instead of the stage-blind opaque total. `-1` = NOT READ (an
    # aborted rung, or an older report), which tells the permit to fall back to the stage-blind arithmetic.
    ingress_stranded: int = -1
    routed_stranded: int = -1
    outbound_stranded: int = -1
    in_pipeline_final: int = -1
    recovery_seconds: float | None = None
    #: D1: the engine-side drain duration (this box's own await_drain elapsed) — the RELIABLE drain the drive
    #: uses for the honest sustainable rate (its own remote drain misses under load). Guaranteed non-None
    #: whenever the fleet drained (drained ⇒ drain_s is not None). Defaulted so an older report deserializes
    #: unchanged.
    drain_seconds: float | None = None
    # Per-shard subprocess identity for the operator's EXTERNAL per-PID CPU capture (Get-Process
    # TotalProcessorTime deltas): shard id -> (node_id, live PID). The SAME map is advertised in
    # SHARDS_READY, so a per-PID CPU sample maps unambiguously to a node identity. On the kill leg the
    # killed shard's PID is its RESTARTED subprocess's (the one that survives to drain) — the pre-kill PID
    # is gone. Defaulted so an older report / a partial run deserializes unchanged.
    node_pids: dict[str, tuple[str, int | None]] = field(default_factory=dict)
    # Soak-only (default empty ⇒ the correctness/climb path is unchanged): a bounded in-HOLD trace of the
    # fleet's OWN /stats in_pipeline gauge, ``[[elapsed_s, in_pipeline], ...]``, sampled when
    # ``sample_in_pipeline=True``. Each shard's /stats in_pipeline counts the WHOLE unified store and the
    # poller sums the N shard URLs, so the sampler DE-DUPS by dividing each reading by the distinct-shard
    # count (#841) — the recorded absolute value AND the derived slope are a single store view, not N×. The
    # TREND (flat/draining vs monotonic growth) is the sustainable-vs-slow-saturation discriminator the
    # PR-C2 soak needs — a slow-saturation plateau looks lossless for ~60s but its backlog slope is
    # positive. Metadata only (a gauge count over time — never a payload / control-id).
    in_pipeline_trace: list[list[float]] = field(default_factory=list)
    #: B3: this rung's store-truth was INVALIDATED — the drive aborted mid-delivery (a broken rendezvous) and
    #: reaped its sinks, so the fleet's stranded/dead are a teardown ARTIFACT, not a product collapse. When
    #: True the render + the ENGINE_DRAINED gate report INVALID(abort), never FAIL — an abort must NEVER read
    #: as a fabricated collapse. Defaulted so an older report deserializes unchanged.
    aborted: bool = False
    #: ARTIFACT 2: the store pool this rung's fleet ran on — the EFFECTIVE requested size (now the PRODUCT 40
    #: by default, not the old `setdefault` 8), the engine's OWN reported maximum, and the acquire_wait
    #: saturation evidence + pre-registered tripwire. Rides the ENGINE_RUNG_REPORT to the drive box, which is
    #: the ONLY half that writes a report — so without this wire the pool evidence exists on the engine box
    #: and dies there (which is exactly what happened: STEP 2 hand-scraped it from /status).
    pool: PoolStats = EMPTY_POOL_STATS
    #: ARTIFACT 5: lanes-per-shard, so ``G = shards x lanes_per_shard`` — the INGRESS/ROUTED pool width — is
    #: recorded. It was computed on BOTH boxes and recorded on NEITHER.
    lanes_per_shard: int = 1
    notes: list[str] = field(default_factory=list)

    @property
    def inbound_bands(self) -> int:
        """``G`` — the inbound MLLP band count (= the ingress/routed per-lane pool width)."""
        return inbound_band_count(len(self.shards), self.lanes_per_shard)

    @property
    def ok(self) -> bool:
        """Engine-side store-truth pass bar: the fleet drained, no stranded non-terminal rows, and no
        dead-letters at ANY stage (`dead_total`, not just the outbound-scoped `engine_dead`) — an
        ingress/routed dead-letter is acked-on-receipt loss, so a self-contained store-truth verdict must
        fail on it. The no-loss / per-lane-FIFO / duplicate VERDICT is the DRIVER report's (it holds the
        sink/tracker); the engine owns the store-truth reconcile."""
        return (
            self.drained
            and self.stranded_nonterminal == 0
            and self.engine_dead == 0
            and self.dead_total == 0
        )

    def render(self) -> str:
        verdict = "INVALID(abort)" if self.aborted else ("PASS" if self.ok else "FAIL")
        lines = [
            f"ShardCert ENGINE {'/'.join(self.shards)}  verdict={verdict}"
            + (f"  killed={self.killed_shard}" if self.killed_shard else "  (baseline, no kill)"),
            f"  stranded_nonterminal_rows={self.stranded_nonterminal} "
            f"drained={self.drained} engine_dead={self.engine_dead} "
            f"dead_total={self.dead_total} "
            f"in_pipeline_final={self.in_pipeline_final}",
            "  ownership: "
            + " ".join(f"{s}->[{','.join(self.owned[s]) or '-'}]" for s in self.shards),
            f"  {self.queue_breakdown}",
            f"  {self.pool.render()}",  # ARTIFACT 2: the pool bind's own evidence, per rung
        ]
        if self.aborted:
            lines.append(
                "  store-truth INVALID: drive aborted mid-delivery (sinks reaped) — NOT a product collapse"
            )
        if self.node_pids:
            lines.append(
                "  node PIDs (for per-PID CPU correlation): "
                + " ".join(
                    f"{s}:{self.node_pids[s][0]}=pid{self.node_pids[s][1]}"
                    for s in self.shards
                    if s in self.node_pids
                )
            )
        if self.recovery_seconds is not None:
            lines.append(f"  recovery_seconds(reported, not gated)={self.recovery_seconds:.2f}")
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


@dataclass
class ShardCertDriverReport:
    """The DRIVER half's outcome — the sink/tracker-derived verdict signals (identical to the co-located
    ``ShardCertReport``'s), plus the engine done/dead/in_pipeline read from the REMOTE ``/stats`` at
    drain. The store-truth stranded/queue-breakdown is the ENGINE half's report."""

    shards: tuple[str, ...]
    killed_shard: str | None
    sent: int
    acked: int
    delivered_distinct: int
    sink_received: int
    acked_not_delivered: int
    lane_inversions: int
    lanes_observed: int
    lane_repeats: int
    engine_done: int
    engine_dead: int
    in_pipeline_final: int
    drained: bool
    drain_seconds: float | None
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Driver-side pass bar: zero acknowledged loss, drained pipeline (remote ``/stats``), per-lane
        FIFO (non-vacuous), no dead-letters. Duplicates are allowed only across a kill. The stranded-row
        check lives on the ENGINE report (it needs direct store access)."""
        dup_ok = self.lane_repeats == 0 if self.killed_shard is None else True
        return (
            self.acked > 0
            and self.acked_not_delivered == 0
            and self.drained
            and self.in_pipeline_final == 0
            and self.engine_dead == 0
            and self.lane_inversions == 0
            and self.lanes_observed >= 2
            and dup_ok
        )

    def render(self) -> str:
        lines = [
            f"ShardCert DRIVER {'/'.join(self.shards)}  verdict={'PASS' if self.ok else 'FAIL'}"
            + (f"  killed={self.killed_shard}" if self.killed_shard else "  (baseline, no kill)"),
            f"  sent={self.sent} acked={self.acked} delivered_distinct={self.delivered_distinct} "
            f"sink_received={self.sink_received}",
            f"  acked_not_delivered={self.acked_not_delivered} (0 = no acknowledged loss)",
            f"  lane_inversions={self.lane_inversions} lanes_observed={self.lanes_observed} "
            f"lane_repeats(dups)={self.lane_repeats}",
            f"  engine done={self.engine_done} dead={self.engine_dead} "
            f"in_pipeline_final={self.in_pipeline_final} drained={self.drained} "
            f"drain_s={self.drain_seconds}",
        ]
        for note in self.notes:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


async def run_shardcert_engine(
    *,
    dests: int = 8,
    handlers: int | None = None,
    delivering: int | None = None,
    hold_seconds: float = 20.0,
    kill: bool = False,
    kill_shard: str | None = None,
    kill_at_fraction: float = 0.4,
    drain_timeout: float = 90.0,
    sink_port: int,
    sink_ports: int = 1,
    store_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    coord: FileDropCoord,
    inbound_bind_host: str = "0.0.0.0",
    sink_host: str = "127.0.0.1",
    claim_mode: str = "pooled",
    drive_start_timeout: float = 300.0,
    post_drain_grace: float = 3.0,
    signal_drained: bool = False,
    #: B3: the per-rung coord signal (RUNG_ABORTED) the drive posts when it aborts this rung. When set and the
    #: drain fails, the engine marks the rung's store-truth INVALID instead of posting a fabricated collapse.
    #: None (the default) keeps the standalone shardcert-engine path byte-identical (the marker never arrives).
    abort_signal: str | None = None,
    sample_in_pipeline: bool = False,
    sample_interval: float = 2.0,
    store_pool_size: int | None = None,
    strict_bands: bool = False,
) -> ShardCertEngineReport:
    """The ENGINE-box half (WS-C option #2). Brings the ``serve --shard`` fleet up against the ONE
    unified store, posts :data:`SHARDS_READY` with the topology, waits for the driver's
    :data:`DRIVE_START`, arms a LOCAL SIGKILL timer for the kill leg, restarts the killed shard, drains
    its OWN ``/stats``, reads the store-truth queue breakdown, and tears the fleet down. It NEVER drives
    load and NEVER binds the sink — those are the driver box's job (the client-isolation the
    attribution policy requires).

    Reconciled onto the #836 lanes-aware base: ``lanes`` per shard is discovered from the built graph and
    the fleet reserves + preflights ``N*lanes`` contiguous inbound ports (lane ``l`` of shard ``i`` on
    ``inbound_base + i*lanes + l``); the lanes-per-shard + persistent knobs are read ambiently from
    ``os.environ`` (the CLI sets them before config load, as the single-box path does). ``sink_host`` is
    the load-gen box (where the shards deliver); ``sink_port``/``sink_ports`` are the sink port band the
    driver binds (single sink for the correctness cert; the band is advertised now for the PR-C fan-out).
    ``store_env`` must point every ``serve`` at the unified store (``MEFOR_STORE_*``).

    ``claim_mode`` (``pooled`` | ``per_lane``, ADR 0066 §8.2) is set first-class on EVERY ``serve --shard``
    subprocess via ``MEFOR_PIPELINE_CLAIM_MODE`` so the pooled-vs-per_lane A/B arm is unambiguous in the
    run record, not left to whatever happened to be in the parent env.

    ``signal_drained`` (default OFF ⇒ the standalone C1 cert path is byte-identical) posts the
    :data:`ENGINE_DRAINED` message once the DIRECT store-truth read confirms the pipeline drained — the
    reliable drain gate the PR-C2 ladder's DRIVE half waits on before tallying its sinks, so a
    teardown-frozen in-flight tail is absorbed BEFORE the tally rather than mis-read as loss. It is posted
    with the store-truth (``drained``/``stranded``/``dead_total``/``in_pipeline_final``), never the remote
    poller's gauges.

    ``handlers`` (H) / ``delivering`` (D) are the BACKLOG #209 shape split (both default to ``dests`` ⇒ the
    pre-#209 graph). This box OWNS the shape — the DRIVE box has no shape flag and learns H/D/dests from the
    :data:`SHARDS_READY` post below, so there is exactly ONE source of truth across the box boundary. That
    includes the ROUTING MODE (``MEFOR_SHARDCERT_ROUTING``, read ambiently here from the env the CLI set): it
    is resolved on THIS box, and the DERIVED accounting pair — not the graph-build pair — is what gets posted.
    """
    import os

    cwd = cwd or Path.cwd()
    store_env = dict(store_env or {})
    routing = load_routing()
    handlers, delivering = _resolve_shape(dests, handlers, delivering)
    ids_list, owned, n, lanes, band_note = _discover(
        dests, handlers, delivering, routing, strict_bands=strict_bands
    )
    # The ACCOUNTING pair the DRIVE box must gate on. Under `partitioned` the graph BUILDS H = D = dests
    # (every handler owns a destination) but the router selects ONE, so the fan-out per message is 1 and the
    # reported pair is (1, 1). Posting the BUILD pair instead would make the drive expect S == A*dests against
    # a truth of S == A*1 and read FALSE LOSS on every healthy rung.
    r_handlers, r_delivering = reported_shape(handlers, delivering, routing)
    # Ports: N*lanes contiguous inbound (lane l of shard i on base + i*lanes + l), N API. The DRIVER binds
    # the sink — the ENGINE only advertises the port band.
    inbound_base = _free_contiguous(n * lanes)
    api_ports = _reserve_ports(n)
    shape_env = _shape_env(
        ids_list,
        inbound_base,
        dests,
        handlers,
        delivering,
        sink_host,
        sink_port,
        sink_ports,
        routing=routing,
    )
    escapes = _escapes(inbound_bind_host)
    # ARTIFACT 2 — see run_shardcert for the full argument. The pool is RESOLVED (flag > ambient > PRODUCT
    # default 40) and ASSIGNED, so its value is CHOSEN in one place and RECORDED in the rung's report; it
    # used to be `setdefault`-pinned at 8 (1/5 of product, 32 connections fleet-wide) and recorded nowhere.
    pool_size = resolve_store_pool_size(store_env, store_pool_size)
    store_env["MEFOR_STORE_POOL_SIZE"] = str(pool_size)
    announce_store_pool(pool_size, n)
    node_env = {**os.environ, **store_env, **shape_env, **escapes}
    # First-class claim-mode pin (ADR 0066 §8.2): set explicitly so the A/B arm is unambiguous in the run
    # record, not left to whatever MEFOR_PIPELINE_CLAIM_MODE happened to be in the parent env.
    node_env["MEFOR_PIPELINE_CLAIM_MODE"] = claim_mode

    await _reset_store(node_env)

    killed = _choose_killed(kill, kill_shard, ids_list, owned)
    nodes: dict[str, ShardCertNode] = {}
    # ARTIFACT 5: the G < L pre-flight note leads the rung's notes — it is a setup condition that governs how
    # every number in this report must be read, and it rides the ENGINE_RUNG_REPORT to the drive box.
    notes: list[str] = [] if band_note is None else [band_note]
    recovery_seconds: float | None = None
    stranded = -1
    breakdown = "QUEUE <not-read>"
    drained = False
    engine_dead = 0
    in_pipeline_final = -1
    node_pids: dict[str, tuple[str, int | None]] = {}
    in_pipeline_trace: list[list[float]] = []
    try:
        # Bring the fleet up. Preflight the engine's OWN inbound bind on loopback (127.0.0.1 reaches a
        # 0.0.0.0 listener) — the DRIVER separately proves off-box reachability from its side.
        await _start_shards(
            ids_list,
            api_ports,
            node_env=node_env,
            cwd=cwd,
            inbound_base=inbound_base,
            lanes=lanes,
            preflight_host="127.0.0.1",
            nodes=nodes,
        )
        # Per-PID CPU-correlation map: each live shard subprocess's (node_id, PID). Captured right after
        # the fleet is up (before any kill) so the operator's EXTERNAL per-PID CPU capture maps each
        # reading to a shard/node identity. Advertised in SHARDS_READY AND returned in the report.
        node_pids = {s: (nodes[s].node_id, getattr(nodes[s], "pid", None)) for s in ids_list}
        # Message 1: advertise the topology the driver needs — the inbound base + lanes-per-shard (so the
        # driver opens N*lanes connections at base + i*lanes + l), the destination-CONNECTION count, the
        # sink port BAND to bind (base + width), the API ports to poll, the shard set, which shard gets
        # killed — plus the per-shard subprocess identity (PID + node id + role) for external per-PID CPU
        # attribution. Metadata only — no PHI.
        #
        # BACKLOG #209: `handlers` (H) and `delivering` (D) ride here too, and this post is the ONLY channel
        # by which the drive box learns the FAN-OUT. The drive has no shape flag on purpose — a flag on both
        # CLIs is a two-place constant that WILL drift invisibly, and a drive that assumed `dests` was the
        # fan-out would compute `S == A*dests` and read every healthy H!=D rung as LOSS.
        #
        # These are the DERIVED (ACCOUNTING) values, NOT the graph-build pair: under `partitioned` the graph
        # builds H = D = dests handlers/connections but the router selects exactly ONE handler, which delivers
        # to exactly ONE destination — so the fan-out is 1 and `(H, D) = (1, 1)`. `dests` stays the LANE count
        # (the sink port-band width) in BOTH modes, which is why the whole sink/port-partition layer below
        # needs no change.
        #
        # `routing` is a REQUIRED read on the drive side and is THREADED INTO THE REPORTS (drive v3, ladder
        # v5) — not merely dropped here. This coord file is ephemeral: were the mode to die in it, the BANKED
        # artifact would record `{dests: 64, handlers: 1, delivering: 1}` for a partitioned run, which is
        # byte-identical to what a LEGAL broadcast `--handlers 1 --delivering 1` run writes — a different
        # shape by ~50x in throughput. Provenance lives in the report, or it does not exist.
        coord.post(
            SHARDS_READY,
            {
                "shards": list(ids_list),
                "inbound_base": inbound_base,
                "lanes": lanes,
                "dests": dests,
                "handlers": r_handlers,
                "delivering": r_delivering,
                "routing": routing,
                "api_ports": list(api_ports),
                "sink_port": sink_port,
                "sink_base": sink_port,
                "sink_ports": sink_ports,
                "killed": killed,
                "hold_seconds": hold_seconds,
                "kill_at_fraction": kill_at_fraction,
                "claim_mode": claim_mode,
                # ARTIFACT 2: the RESOLVED pool size, so the DRIVE box (the only half that writes a report)
                # can record the configuration this fleet actually ran on. Without this wire, `shardcert-
                # engine --store-pool-size N` + `shardcert-drive --report-json` yields an artifact from which
                # N is unrecoverable — it lived only on the engine box's stderr.
                "store_pool_size": pool_size,
                "nodes": [
                    {
                        "shard": s,
                        "node_id": node_pids[s][0],
                        "pid": node_pids[s][1],
                        "role": "engine-shard",
                    }
                    for s in ids_list
                ],
            },
        )
        # Message 2 (inbound): the driver has bound its sink + opened its senders and is now driving.
        drive = await coord.await_message(DRIVE_START, timeout=drive_start_timeout)
        notes.append(f"observed DRIVE_START (driver t0={drive.get('t0')})")
        t0_local = time.monotonic()

        # Arm the LOCAL SIGKILL timer relative to WHEN WE OBSERVED DRIVE_START (no cross-box clock
        # compare). The kill is a local PID op on a timer — WS-C has no remote-kill leg.
        kill_task: asyncio.Task[float] | None = None
        if kill and killed is not None:
            delay = _kill_delay(kill_at_fraction, hold_seconds)
            kill_task = asyncio.create_task(_kill_after(nodes[killed], delay))
            notes.append(
                f"armed local SIGKILL of {killed} at +{delay:.2f}s (~{kill_at_fraction:.0%} of hold)"
            )

        # Hold locally so the killed shard is restarted AFTER the hold (mirrors the co-located sequence).
        # Soak-only: sample the fleet's OWN in_pipeline gauge across the hold so the PR-C2 soak can report
        # the backlog SLOPE (flat/draining vs a slow-saturation positive slope). Off by default ⇒ the
        # correctness/climb path adds no concurrent poller during the hold.
        trace_stop = asyncio.Event()
        trace_task: asyncio.Task[None] | None = None
        if sample_in_pipeline:
            trace_task = asyncio.create_task(
                _sample_in_pipeline_trace(
                    [nodes[s].url for s in ids_list],
                    trace_stop,
                    in_pipeline_trace,
                    interval=sample_interval,
                )
            )
        try:
            await asyncio.sleep(max(0.0, hold_seconds - (time.monotonic() - t0_local)))
        finally:
            if trace_task is not None:
                trace_stop.set()
                with contextlib.suppress(Exception):
                    await trace_task
        kill_at: float | None = None
        if kill_task is not None:
            kill_at = await kill_task

        # Kill leg: restart the killed shard (supervisor-style) so its startup runs the ownership-scoped
        # reset over ITS lanes; time functional recovery from the kill instant.
        if kill and killed is not None:
            idx = ids_list.index(killed)
            restart = ShardCertNode(
                killed, api_ports[idx], env=node_env, config_dir=_CONFIG_DIR, cwd=cwd
            )
            await restart.start()
            nodes[killed] = restart
            # The restarted shard is a NEW subprocess (new PID) — refresh the correlation map so a
            # post-kill CPU sample attributes to the survivor process, not the reaped pre-kill one.
            node_pids[killed] = (restart.node_id, getattr(restart, "pid", None))
            if not await _await_health(restart.url, timeout=60.0):
                raise RuntimeError(f"shard {killed} did not restart\n{restart.log_tail()}")
            if kill_at is not None:
                recovery_seconds = time.monotonic() - kill_at

        # Drain the fleet's OWN /stats (keep the shards up until the store empties), then read the
        # store-truth stranded/breakdown before tearing down. The drain gauge + dead count give the engine
        # its self-contained store-truth verdict. A short post-drain grace so the driver's own REMOTE
        # drain poll doesn't race the shard teardown (both read the same store).
        urls = [nodes[s].url for s in ids_list]
        poller = EnginePoller(urls, None, origin=time.perf_counter())
        await poller.open()
        try:
            drain_s = await poller.await_drain(timeout=drain_timeout, interval=0.5)
            final = poller.final
        finally:
            await poller.close()
        drained = drain_s is not None
        # B3: distinguish a REAL congestion collapse from a drive-abort ARTIFACT. Only on a FAILED drain: if
        # the drive reaped its sinks mid-delivery (a broken rendezvous), our still-in-flight rows strand with
        # nowhere to go — manufacturing stranded/dead in our OWN store-truth that looks exactly like a product
        # collapse. A RUNG_ABORTED marker from the drive means the latter → mark this rung INVALID. The clean
        # (drained) path is byte-identical: the check is skipped.
        rung_aborted = False
        if not drained and abort_signal is not None:
            with contextlib.suppress(CoordTimeout):
                await coord.await_message(abort_signal, timeout=_ABORT_MARKER_GRACE)
                rung_aborted = True
        engine_dead = final.dead if final else 0
        # D4: de-dup the N×-summed unified-store poller aggregate to a single store view (#841). This is
        # stored on ShardCertEngineReport AND posted in the ENGINE_DRAINED gate, so the two-box report's
        # engine_in_pipeline_final is the TRUE fleet backlog, not N× it.
        in_pipeline_final = final.in_pipeline // max(1, len(ids_list)) if final else -1
        # On an abort the store's stranded/dead are a teardown artifact, not a measurement — do not read them
        # (they would only re-confirm the fabricated collapse). A genuine failed drain still reads them.
        if rung_aborted:
            stranded, dead_total, breakdown = -1, -1, "(rung aborted — store-truth not read)"
            # BACKLOG #229: the per-stage strand split rides the store-truth read; on an abort it is
            # unread, so the sentinel (-1) tells the A4b permit to fall back to the stage-blind total.
            ingress_stranded, routed_stranded, outbound_stranded = -1, -1, -1
        else:
            _qb = await _queue_breakdown(node_env)
            stranded, dead_total, breakdown = _qb.nonterminal, _qb.dead_total, _qb.summary
            ingress_stranded = _qb.ingress_stranded
            routed_stranded = _qb.routed_stranded
            outbound_stranded = _qb.outbound_stranded
        # PR-C2 ladder drain gate (default OFF): once the DIRECT store read above confirms drain, tell the
        # DRIVE half it is safe to tally its sinks — the reliable authority (stranded/dead), never the
        # remote poller. Posted BEFORE the grace/teardown, but by construction stranded==0 means every
        # delivery already landed on the sink sockets, so there is no tail left to lose at teardown.
        if signal_drained and rung_aborted:
            # B3: the drive tore its sinks down mid-delivery — our drain failure is a HARNESS artifact, not a
            # product collapse. Post the rung's store-truth as INVALID so the drive/operator can never read it
            # as a fabricated collapse (the drive independently marks the run setup-degraded, B2).
            coord.post(
                ENGINE_DRAINED,
                {
                    "valid": False,
                    "aborted": True,
                    "engine_ok": False,
                    "drained": False,
                    "note": (
                        "drive aborted mid-delivery — sinks torn down; store-truth INVALID, not a collapse"
                    ),
                },
            )
        elif signal_drained:
            coord.post(
                ENGINE_DRAINED,
                {
                    "drained": drained,
                    "stranded": stranded,
                    "dead_total": dead_total,
                    # BACKLOG #229: the per-stage strand split (non-terminal + dead, by stage) rides the
                    # RELIABLE gate too — a gate-only fix would leave build_rung_outcome's report-fallback
                    # path stage-blind. A sentinel (-1) on an older payload keeps the opaque-total fallback.
                    "ingress_stranded": ingress_stranded,
                    "routed_stranded": routed_stranded,
                    "outbound_stranded": outbound_stranded,
                    "in_pipeline_final": in_pipeline_final,
                    # ARTIFACT 2: THE POOL EVIDENCE RIDES THE RELIABLE GATE, not only the later, more fragile
                    # ENGINE_RUNG_REPORT. The code explicitly designs for a lost/late rung report (store-truth
                    # deliberately falls back to THIS gate so a lost report is not read as a collapse) — but
                    # the pool was read ONLY from the report. So a rung whose report went missing had NO pool
                    # evidence, the tripwire was structurally incapable of firing, and the rung STILL pinned
                    # and STILL bracketed the ceiling: an unmeasured pool treated as an innocent one. The same
                    # box posts both messages, so this is where it belongs.
                    "store_pool": PoolStats.from_sample(final, requested=pool_size).to_json_dict(),
                    # The RELIABLE engine-side drain time (this box's own await_drain). Guaranteed non-None
                    # whenever engine_ok (drained ⇒ drain_s is not None), so the drive uses it for the honest
                    # sustainable rate (D1) instead of its advisory remote drain, which misses under load.
                    "drain_seconds": drain_s,
                    # engine-side store-truth pass bar for THIS rung (drive folds it into the classifier)
                    "engine_ok": bool(
                        drained and stranded == 0 and engine_dead == 0 and dead_total == 0
                    ),
                },
            )
        await asyncio.sleep(post_drain_grace)
    finally:
        for node in nodes.values():
            with contextlib.suppress(Exception):
                await node.stop()

    return ShardCertEngineReport(
        shards=tuple(ids_list),
        owned=owned,
        killed_shard=killed,
        stranded_nonterminal=stranded,
        ingress_stranded=ingress_stranded,
        routed_stranded=routed_stranded,
        outbound_stranded=outbound_stranded,
        queue_breakdown=breakdown,
        drained=drained,
        engine_dead=engine_dead,
        dead_total=dead_total,
        in_pipeline_final=in_pipeline_final,
        recovery_seconds=recovery_seconds,
        drain_seconds=drain_s,
        node_pids=node_pids,
        in_pipeline_trace=in_pipeline_trace,
        aborted=rung_aborted,
        # ARTIFACT 2: `final` is the drain-time poller sample — already in hand here and, until now, thrown
        # away. acquire_wait is a CUMULATIVE histogram and every rung spawns a FRESH fleet, so a cumulative
        # read at drain IS this rung's read.
        pool=PoolStats.from_sample(final, requested=pool_size),
        lanes_per_shard=lanes,
        notes=notes,
    )


async def run_shardcert_driver(
    *,
    engine_host: str,
    aggregate_rate: float = 40.0,
    hold_seconds: float = 20.0,
    drain_timeout: float = 90.0,
    coord: FileDropCoord,
    sink_host: str = "127.0.0.1",
    shards_ready_timeout: float = 300.0,
    inbound_ready_timeout: float = 60.0,
    allow_insecure: bool = False,
) -> ShardCertDriverReport:
    """The LOAD-GEN-box half (WS-C option #2). Waits for :data:`SHARDS_READY`, binds the correlation
    sink LOCALLY (``sink_host`` — the load-gen box) over the advertised port band, opens one persistent
    MLLP connection per (shard, lane) inbound against the ENGINE box
    (``engine_host:inbound_base + i*lanes + l`` — the lanes-aware many-thin-lane shape), posts
    :data:`DRIVE_START`, drives the aggregate load (NO kill — the engine owns that), then drains against
    the engine's REMOTE ``/stats`` and computes the sink/tracker verdict. It NEVER spawns an engine and
    NEVER touches the store — the whole point is CPU isolation from the engine box.

    The lanes-per-shard + sink port band are learned from SHARDS_READY (default ``lanes=1`` /
    ``sink_ports=1`` so an older engine's payload still drives), so the driver's connection set matches
    the served graph exactly."""
    ready = await coord.await_message(SHARDS_READY, timeout=shards_ready_timeout)
    ids_list = [str(s) for s in ready["shards"]]
    inbound_base = int(ready["inbound_base"])
    lanes = int(ready.get("lanes", 1))
    api_ports = [int(p) for p in ready["api_ports"]]
    sink_base = int(ready.get("sink_base", ready["sink_port"]))
    sink_ports = int(ready.get("sink_ports", 1))
    killed_raw = ready.get("killed")
    killed = str(killed_raw) if killed_raw is not None else None
    n = len(ids_list)

    ids = SHARDCERT_IDS
    metrics = LiveMetrics(counters=Counters(), ack=Histogram(), e2e=Histogram())
    correlator = Correlator(capacity=1 << 20, metrics=metrics)
    tracker = FailoverTracker()
    corpus = build_corpus(load_profile_text(_CORPUS_PROFILE, where="<shardcert>"), ids)
    mix = TypeMix({"ADT^A01": 1.0})
    # The sink binds on the LOAD-GEN box (`sink_host`) over the advertised port band — it IS the engine's
    # outbound destination and holds the verdict signal (tracker/correlator), so it lives with the drive
    # side. A single port for the correctness cert; the band is wider only for the PR-C sink fan-out.
    sink_bind_ports = tuple(sink_base + k for k in range(sink_ports))
    sink = CorrelationSink(
        ids, correlator, metrics, host=sink_host, ports=sink_bind_ports, tracker=tracker
    )
    conns: list[PersistentConnection] = []
    poller: EnginePoller | None = None
    notes: list[str] = []
    try:
        await sink.start()
        # One persistent connection per (shard, lane) inbound (N*lanes total), dialing the ENGINE box's
        # inbound IP at base + i*lanes + l — the lanes-aware many-thin-lane shape.
        for i in range(n):
            for lane in range(lanes):
                pc = PersistentConnection(
                    engine_host,
                    inbound_base + i * lanes + lane,
                    correlator,
                    metrics,
                    expect_ack=True,
                    tracker=tracker,
                )
                pc.start()
                conns.append(pc)
        # Prove the exact off-box reachability the drive will use before posting DRIVE_START — every
        # (shard, lane) inbound port.
        for i in range(n):
            for lane in range(lanes):
                port = inbound_base + i * lanes + lane
                if not await _await_port(engine_host, port, timeout=inbound_ready_timeout):
                    raise RuntimeError(
                        f"engine inbound {engine_host}:{port} not reachable from the load-gen box"
                    )
        # Message 2: tell the engine we're driving now (t0 informational — the engine anchors its kill
        # timer on ITS observation of this message, not on a cross-box clock).
        coord.post(DRIVE_START, {"t0": time.time()})
        await _drive_load(
            conns, corpus, mix, metrics, aggregate_rate=aggregate_rate, hold_seconds=hold_seconds
        )
        await asyncio.gather(*(c.stop(2.0) for c in conns))

        # Drain against the engines' REMOTE /stats — the authoritative drain signal, polled off-box.
        # allow_insecure: the remote engine API is plaintext http, so the poller needs it (loopback
        # never does) — else poller.open() fail-closes on the non-loopback http URL.
        urls = [f"http://{engine_host}:{p}" for p in api_ports]
        poller = EnginePoller(urls, None, origin=time.perf_counter(), allow_insecure=allow_insecure)
        await poller.open()
        drain_s = await poller.await_drain(timeout=drain_timeout, interval=0.5)
        final = poller.final
    finally:
        if poller is not None:
            with contextlib.suppress(Exception):
                await poller.close()
        for pc in conns:
            with contextlib.suppress(Exception):
                await pc.stop(0.5)
        with contextlib.suppress(Exception):
            await sink.stop()

    ctr = metrics.counters
    return ShardCertDriverReport(
        shards=tuple(ids_list),
        killed_shard=killed,
        sent=ctr.sent,
        acked=ctr.acked,
        delivered_distinct=tracker.delivered_count,
        sink_received=ctr.sink_received,
        acked_not_delivered=tracker.acked_not_delivered(),
        lane_inversions=tracker.lane_inversions,
        lanes_observed=tracker.lanes_observed,
        lane_repeats=tracker.lane_repeats,
        engine_done=(final.done if final else 0),
        engine_dead=(final.dead if final else 0),
        in_pipeline_final=(final.in_pipeline if final else -1),
        drained=drain_s is not None,
        drain_seconds=drain_s,
        notes=notes,
    )


# =====================================================================================================
# WS-C multi-process SIZING drive (PR-C1) — over-provision the CLIENT tier into K sender processes + M
# sink processes, all on the load-gen box (NEVER co-located with the engine fleet — the attribution
# isolation), so a plateau reflects the ENGINE/STORE ceiling rather than a single sender's ~457/s ACK
# ceiling or a single sink's ~100-140/s. The coord channel is metadata-only, so splitting senders from
# sinks across processes forbids per-message acked↔delivered correlation (PR-B's FailoverTracker saw both
# sides in ONE proc); the reconcile becomes COUNT-BALANCE + engine store-truth, NOT per-message. See the
# PR-C spec + coord.py for the message protocol. The single-box run_shardcert + the PR-B two-box halves +
# the #836 ladder are UNCHANGED — this is purely additive, reusing their helpers.
# =====================================================================================================


# --- port/band partition helpers (fail loud — a silent gap understates delivered → false PASS) -------


def _partition_band(base: int, width: int, count: int) -> list[list[int]]:
    """Partition the contiguous port band ``[base, base+width)`` into ``count`` CONTIGUOUS, non-empty,
    non-overlapping chunks that EXACTLY tile the band (chunk ``k`` is the sink ``k`` binds).

    **Fail loud** (:class:`ValueError`) on ``count > width`` (some sink would bind no ports),
    ``count < 1`` / ``width < 1``, or any gap/overlap/empty chunk — a silently-unbound destination port
    would drop deliveries the reconcile never counts, understating ``S`` and FALSE-PASSing no-loss. The
    first ``width % count`` chunks are one port wider so the tiling is exact."""
    if count < 1:
        raise ValueError(f"sink_count must be >= 1, got {count}")
    if width < 1:
        raise ValueError(f"sink_ports must be >= 1, got {width}")
    if count > width:
        raise ValueError(
            f"sink_count ({count}) > sink_ports ({width}): a sink would bind no ports — give each sink "
            "at least one destination port (set sink_ports == dests and sink_count <= dests)"
        )
    q, r = divmod(width, count)
    chunks: list[list[int]] = []
    port = base
    for k in range(count):
        size = q + (1 if k < r else 0)
        chunks.append(list(range(port, port + size)))
        port += size
    # Belt-and-suspenders: the chunks must EXACTLY tile [base, base+width) with no gap/overlap/empty
    # chunk — fail loud if the arithmetic above ever failed to (defends against a future edit).
    flat = [p for chunk in chunks for p in chunk]
    if flat != list(range(base, base + width)) or any(not chunk for chunk in chunks):
        raise ValueError(
            f"sink band partition of [{base},{base + width}) into {count} did not tile cleanly: {chunks}"
        )
    return chunks


@dataclass
class ShardCertSinkReport:
    """One SINK process's outcome — the delivered/order tally over ITS owned destination-port chunk.

    **The invariant this tier rests on, stated so it holds in BOTH routing modes:** a FIFO lane key is
    ``(source shard, [lane,] DESTINATION)`` (``_shape.fifo_lane``, stamped into MSH-6). The DESTINATION
    determines the outbound port, and :func:`_partition_band` tiles the port band into non-overlapping
    chunks — one owning sink each. Therefore **the per-sink lane-key SETS ARE DISJOINT**, in both modes, and
    the sinks' union IS the run's lane set.

    What DIFFERS by mode is only how much of that set one sink sees:

    * ``broadcast`` — every accepted message fans to every DELIVERED dest, so a sink owning a port in
      ``[0, D)`` observes every SOURCE lane, and ``lanes_observed`` is (shards × lanes_per_shard × its own
      dests). Sinks owning the non-delivering tail at ``D < dests`` legitimately see nothing.
    * ``partitioned`` — a message goes to exactly ONE dest, so a sink observes only the lane keys whose
      destination is in ITS chunk: a FRACTION of the lane set, never all of it.

    An earlier version of this docstring asserted the broadcast case as if it were the invariant ("every lane
    fans to every delivered dest, so a sink observes EVERY lane"), and the coordinator's MAX aggregation was
    derived from it. Under ``partitioned`` at ``dests <= 8`` each sink owns ONE destination, so its
    ``lanes_observed`` is just the number of shards feeding that dest — and a MAX over the sinks reads 4 where
    the truth is 256, or false-FAILS the ``>= 2`` non-vacuity bar outright. The coordinator now unions the
    lane-key SETS instead (see :func:`run_shardcert_drive`), which is why ``lane_keys`` is reported here.

    Counts + the bound port numbers + the SYNTHETIC lane labels (shard/lane/dest — stamped by this harness's
    own ``apply_transform``, never patient data) only. Never control-ids / bodies (PHI rule)."""

    sink_index: int
    sink_count: int
    ports: tuple[int, ...]
    sink_received: int
    lane_inversions: int
    lane_repeats: int
    lanes_observed: int  # == len(lane_keys); THIS SINK's chunk only, never the run's lane count
    #: The DISTINCT FIFO lane keys this sink observed. The coordinator unions these across sinks to get the
    #: run's true lane count — a bare SUM of ``lanes_observed`` would be right only while the keys really are
    #: disjoint, and the ONE case where they are not is exactly the vacuity the ``>= 2`` bar exists to catch
    #: (an unstamped MSH-6 collapses EVERY delivery onto the key ``""``, in every sink at once: MAX reads 1
    #: and correctly fails, SUM reads `sink_count` and would FALSE-PASS). Unioning the sets is right in both.
    lane_keys: tuple[str, ...] = ()
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f"ShardCert SINK {self.sink_index}/{self.sink_count}  "
            f"ports={','.join(str(p) for p in self.ports) or '-'}",
            f"  sink_received={self.sink_received} lane_inversions={self.lane_inversions} "
            f"lane_repeats(dups)={self.lane_repeats} lanes_observed={self.lanes_observed}",
        ]
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)

    def to_json_dict(self) -> dict[str, object]:
        """Counts + synthetic port/lane topology only (never message bodies / control-id lists — PHI rule)."""
        return {
            "schema_version": 1,
            "kind": "shardcert_sink",
            "sink_index": self.sink_index,
            "sink_count": self.sink_count,
            "ports": list(self.ports),
            "sink_received": self.sink_received,
            "lane_inversions": self.lane_inversions,
            "lane_repeats": self.lane_repeats,
            # THIS sink's chunk only — the run's lane count is the coordinator's UNION over sinks.
            "lanes_observed": self.lanes_observed,
            "lane_keys": list(self.lane_keys),
            "notes": self.notes,
        }


async def run_shardcert_sink(
    *,
    sink_host: str = "127.0.0.1",
    sink_base: int,
    sink_ports: int,
    sink_index: int,
    sink_count: int,
    coord: FileDropCoord,
    drive_complete_timeout: float = 600.0,
    post_complete_grace: float = 2.0,
) -> ShardCertSinkReport:
    """One SINK-tier process of the multi-process drive. Binds a :class:`CorrelationSink` (its OWN
    ``Correlator`` + ``FailoverTracker`` + ``LiveMetrics``) over its CONTIGUOUS chunk of the
    ``[sink_base, sink_base+sink_ports)`` (== ``dests``, the destination-CONNECTION count — the band is
    sized by TOPOLOGY, not by the fan-out ``delivering``) destination-port band — chunk ``sink_index`` of
    the ``sink_count`` partition — posts :data:`SINK_BOUND`.``<sink_index>`` once bound, absorbs the
    engine's outbound fan-out until it observes the coordinator's :data:`DRIVE_COMPLETE` (or a bounded
    ``drive_complete_timeout``), then records its final tally and posts :data:`SINK_DONE`.``<sink_index>``.

    B6: ``drive_complete_timeout``'s 600s default applies ONLY to a manual standalone ``shardcert-sink``
    run. The coordinator ALWAYS threads its :func:`_derive_drive_complete_timeout` value into the spawn
    argv, because the safe bound depends on the run's hold/drain — which this child cannot see. Do not
    "simplify" that back to the default: a hold ≳540s then silently truncates the tally (see B6 there).

    It binds a sink but NEVER drives load and NEVER spawns an engine — the sender tier
    (:func:`run_shardcert_driver_worker`) drives, the coordinator (:func:`run_shardcert_drive`) spawns.
    **Fail loud** if ``sink_index`` is out of range or the band does not partition cleanly (see
    :func:`_partition_band`) — a silently-unbound port would drop deliveries the reconcile never counts."""
    if not (0 <= sink_index < sink_count):
        raise ValueError(
            f"sink_index {sink_index} out of range [0,{sink_count}) — a sink can only bind an existing "
            "partition chunk"
        )
    chunk = _partition_band(sink_base, sink_ports, sink_count)[sink_index]
    chunk_ports = tuple(chunk)

    ids = SHARDCERT_IDS
    metrics = LiveMetrics(counters=Counters(), ack=Histogram(), e2e=Histogram())
    correlator = Correlator(capacity=1 << 20, metrics=metrics)
    tracker = FailoverTracker()
    sink = CorrelationSink(
        ids, correlator, metrics, host=sink_host, ports=chunk_ports, tracker=tracker
    )
    notes: list[str] = []
    try:
        await sink.start()
        # Advertise that THIS sink's port chunk is bound (metadata: which ports it owns) so the
        # coordinator can gate the drive on every sink being ready before releasing the senders.
        coord.post(
            f"{SINK_BOUND}.{sink_index}",
            {"sink_index": sink_index, "ports": list(chunk_ports)},
        )
        # Absorb the fan-out until the coordinator says the engine has drained (DRIVE_COMPLETE), then the
        # tally is final. A bounded max-wait so a lost DRIVE_COMPLETE can't hang the sink forever — it
        # reports its partial tally with a note (the coordinator's reconcile will catch the shortfall).
        try:
            await coord.await_message(DRIVE_COMPLETE, timeout=drive_complete_timeout)
        except CoordTimeout:
            notes.append(
                f"DRIVE_COMPLETE not observed within {drive_complete_timeout}s — reporting partial tally"
            )
        # A short grace so any in-flight delivery already on the socket is absorbed before the tally read.
        if post_complete_grace > 0:
            await asyncio.sleep(post_complete_grace)
    finally:
        with contextlib.suppress(Exception):
            await sink.stop()

    ctr = metrics.counters
    report = ShardCertSinkReport(
        sink_index=sink_index,
        sink_count=sink_count,
        ports=chunk_ports,
        sink_received=ctr.sink_received,
        lane_inversions=tracker.lane_inversions,
        lane_repeats=tracker.lane_repeats,
        lanes_observed=tracker.lanes_observed,
        lane_keys=tracker.lane_keys,
        notes=notes,
    )
    # Metadata-only DONE drop: counts + the synthetic port/lane topology, never control-ids / bodies.
    # `lane_keys` (not just the count) because the coordinator must UNION them: this sink saw only the lanes
    # whose DESTINATION is in its own port chunk, which under `partitioned` is a fraction of the run's lanes.
    coord.post(
        f"{SINK_DONE}.{sink_index}",
        {
            "sink_index": sink_index,
            "sink_received": report.sink_received,
            "lane_inversions": report.lane_inversions,
            "lane_repeats": report.lane_repeats,
            "lanes_observed": report.lanes_observed,
            "lane_keys": list(report.lane_keys),
            "ports": list(chunk_ports),
        },
    )
    return report


# --- sender tier (band-slice worker, external sinks) -------------------------------------------------


def _band_slice(total_bands: int, driver_count: int, driver_index: int) -> tuple[int, int]:
    """Sender-worker ``driver_index``'s CONTIGUOUS band slice ``[start, stop)`` of the
    ``total_bands = shards*lanes`` inbound bands. ``B = ceil(total_bands/driver_count)``; worker ``j`` owns
    ``[j*B, min((j+1)*B, total_bands))`` (the last clamped to the end).

    **Fail loud** (:class:`ValueError`) on ``driver_index`` out of range, ``driver_count > total_bands``
    (a worker would drive no bands), or an EMPTY slice for this worker (a ``driver_count`` that doesn't
    tile the bands leaves some worker idle) — a silently-undriven band would understate offered/delivered
    and false-PASS the sizing reconcile. Choose a ``driver_count`` that tiles ``total_bands``."""
    if driver_count < 1:
        raise ValueError(f"driver_count must be >= 1, got {driver_count}")
    if not (0 <= driver_index < driver_count):
        raise ValueError(f"driver_index {driver_index} out of range [0,{driver_count})")
    if driver_count > total_bands:
        raise ValueError(
            f"driver_count ({driver_count}) > bands G={total_bands}: a worker would drive no bands — "
            "use at most one sender-worker per band"
        )
    b = -(-total_bands // driver_count)  # ceil division
    start = driver_index * b
    stop = min(start + b, total_bands)
    if start >= stop:
        raise ValueError(
            f"sender-worker {driver_index}/{driver_count} owns an EMPTY band slice of G={total_bands} "
            f"(B={b}); choose a driver_count that tiles the bands"
        )
    return start, stop


@dataclass
class ShardCertDriverWorkerReport:
    """One SENDER-tier process's outcome — the intake tally over ITS owned band slice. Counts only (never
    control-ids / message bodies — PHI rule); the delivered/order VERDICT is the sinks' + the coordinator's
    (a metadata-only coord can't correlate this proc's acks to another proc's deliveries per-message)."""

    driver_index: int
    driver_count: int
    bands: tuple[int, ...]
    sent: int
    acked: int
    ack_p50_ms: float
    ack_p99_ms: float
    #: THE DEFERRAL CAUSE SPLIT (gate v2). This worker's own tally of WHY its offers did not reach the wire:
    #: full send buffers (⇒ the ENGINE stopped reading — backpressure) vs its own tick-lag (⇒ THE RIG). The
    #: coordinator sums them across workers; the fidelity gate reads the sum. Without this, `sent` — which is
    #: ENGINE-PACED through the bounded queue + `drain()` — was the gate's only shortfall input, and it
    #: cannot name a culprit.
    deferred_backpressure: int = 0
    deferred_schedule: int = 0
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f"ShardCert DRIVER-WORKER {self.driver_index}/{self.driver_count}  "
            f"bands={','.join(str(b) for b in self.bands) or '-'}",
            f"  sent={self.sent} acked={self.acked} "
            f"ack p50/p99={self.ack_p50_ms:.1f}/{self.ack_p99_ms:.1f}ms",
            f"  deferred: backpressure={self.deferred_backpressure} (engine not reading) "
            f"schedule={self.deferred_schedule} (rig behind)",
        ]
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)

    def to_json_dict(self) -> dict[str, object]:
        """Counts + synthetic band topology only (never message bodies / control-id lists — PHI rule)."""
        return {
            # v2: +the deferral CAUSE SPLIT (`deferred_backpressure` / `deferred_schedule`). Purely additive.
            "schema_version": 2,
            "kind": "shardcert_driver_worker",
            "driver_index": self.driver_index,
            "driver_count": self.driver_count,
            "bands": list(self.bands),
            "sent": self.sent,
            "acked": self.acked,
            "deferred_backpressure": self.deferred_backpressure,
            "deferred_schedule": self.deferred_schedule,
            "ack_ms": {"p50": round(self.ack_p50_ms, 3), "p99": round(self.ack_p99_ms, 3)},
            "notes": self.notes,
        }


async def run_shardcert_driver_worker(
    *,
    engine_host: str,
    aggregate_rate: float,
    hold_seconds: float,
    driver_index: int,
    driver_count: int,
    coord: FileDropCoord,
    shards_ready_timeout: float = 300.0,
    inbound_ready_timeout: float = 60.0,
    drive_go_timeout: float = 300.0,
) -> ShardCertDriverWorkerReport:
    """One SENDER-tier process of the multi-process drive. Learns the topology from :data:`SHARDS_READY`
    (``shards``, ``inbound_base``, ``lanes``), owns the CONTIGUOUS band slice ``_band_slice`` assigns it
    of the ``G = shards*lanes`` inbound bands (band ``g = i*lanes + l`` dials ``engine_host:inbound_base+g``),
    opens ONE :class:`PersistentConnection` per owned band, proves reachability, posts
    :data:`DRIVER_ARMED`.``<driver_index>``, WAITS for the coordinator's :data:`DRIVE_GO`, drives its slice
    at ``len(slice) * (aggregate_rate / G)`` for ``hold_seconds`` (:func:`_drive_load`, no kill), then posts
    :data:`DRIVER_DONE`.``<driver_index>`` with its sent/acked/ack-latency tally.

    It NEVER binds a sink (the external sink tier owns delivery) and NEVER spawns an engine — the whole
    point is CPU isolation and horizontal sender scale. **Fail loud** if the band slice is empty / the
    worker count exceeds the bands (see :func:`_band_slice`)."""
    ready = await coord.await_message(SHARDS_READY, timeout=shards_ready_timeout)
    ids_list = [str(s) for s in ready["shards"]]
    inbound_base = int(ready["inbound_base"])
    lanes = int(ready.get("lanes", 1))
    total_bands = len(ids_list) * lanes
    start, stop = _band_slice(total_bands, driver_count, driver_index)
    bands = tuple(range(start, stop))

    # Per-band offered rate is the aggregate divided across ALL G bands; this worker drives only its
    # owned bands, so its share is len(slice) * per_band (the whole fleet re-sums to `aggregate_rate`).
    per_band = aggregate_rate / total_bands if total_bands else 0.0
    worker_rate = len(bands) * per_band

    ids = SHARDCERT_IDS
    metrics = LiveMetrics(counters=Counters(), ack=Histogram(), e2e=Histogram())
    correlator = Correlator(capacity=1 << 20, metrics=metrics)
    # DISJOINT sequence space per sender PROCESS. Every worker builds its own Corpus in its own process, and
    # a Corpus starts at seq 0 — so left unbased, all K workers emit the IDENTICAL stream 0,1,2,…. That (a)
    # stamps the same control id on K different messages, and (b) PHASE-LOCKS the partitioned selector, which
    # derives the destination lane FROM the seq: all K workers would target the same lane at the same instant,
    # so the tier walks the lanes K-deep in bursts instead of spreading K concurrent messages over K distinct
    # lanes. Long-run per-lane load is unaffected (still R/L), but the bursty arrival process aliases against
    # the soak's 0.5s in_pipeline sampler and can flip a healthy soak's flat-or-draining slope gate.
    corpus = build_corpus(
        load_profile_text(_CORPUS_PROFILE, where="<shardcert>"),
        ids,
        driver_index * SEQ_BASE_STRIDE,
    )
    mix = TypeMix({"ADT^A01": 1.0})
    conns: list[PersistentConnection] = []
    notes: list[str] = []
    try:
        # One persistent connection per owned band, dialing the ENGINE box at inbound_base + g. No sink,
        # no tracker (the sinks own the delivery-side verdict; this proc only counts intake/ACK latency).
        for g in bands:
            pc = PersistentConnection(
                engine_host,
                inbound_base + g,
                correlator,
                metrics,
                expect_ack=True,
            )
            pc.start()
            conns.append(pc)
        # Prove the exact off-box reachability the drive will use before arming — every owned band port.
        for g in bands:
            port = inbound_base + g
            if not await _await_port(engine_host, port, timeout=inbound_ready_timeout):
                raise RuntimeError(
                    f"engine inbound {engine_host}:{port} not reachable from the load-gen box"
                )
        # Armed: connections open + reachable. Advertise the owned band indices (synthetic topology) and
        # wait for the coordinator to release every worker in lockstep.
        coord.post(
            f"{DRIVER_ARMED}.{driver_index}",
            {"driver_index": driver_index, "bands": list(bands)},
        )
        await coord.await_message(DRIVE_GO, timeout=drive_go_timeout)
        await _drive_load(
            conns, corpus, mix, metrics, aggregate_rate=worker_rate, hold_seconds=hold_seconds
        )
        await asyncio.gather(*(c.stop(2.0) for c in conns))
    finally:
        for pc in conns:
            with contextlib.suppress(Exception):
                await pc.stop(0.5)

    ctr = metrics.counters
    ack = metrics.ack.summary()
    report = ShardCertDriverWorkerReport(
        driver_index=driver_index,
        driver_count=driver_count,
        bands=bands,
        sent=ctr.sent,
        acked=ctr.acked,
        deferred_backpressure=ctr.deferred_backpressure,
        deferred_schedule=ctr.deferred_schedule,
        ack_p50_ms=ack.p50_ms,
        ack_p99_ms=ack.p99_ms,
        notes=notes,
    )
    # Metadata-only DONE drop: counts + ack latency + the synthetic band topology, never control-ids.
    #
    # The deferral CAUSE SPLIT rides here because the coordinator is the only half that can SUM it across
    # workers, and the fidelity gate reads that sum. Send it and the gate can tell an engine backpressure
    # bind from a rig shortfall; omit it and the gate falls back to `sent`, which cannot.
    coord.post(
        f"{DRIVER_DONE}.{driver_index}",
        {
            "driver_index": driver_index,
            "sent": report.sent,
            "acked": report.acked,
            "deferred_backpressure": report.deferred_backpressure,
            "deferred_schedule": report.deferred_schedule,
            "ack_p50_ms": report.ack_p50_ms,
            "ack_p99_ms": report.ack_p99_ms,
            "bands": list(bands),
        },
    )
    return report


# --- coordinator (spawns K senders + M sinks, aggregates, count-balance reconcile) -------------------


async def _spawn_proc(argv: list[str]) -> Any:
    """Spawn ``python -m harness <argv...>`` as a CHILD process (a sink or sender-worker tier). A
    module-level seam so a test can FAKE it (record argv + itself write the child's expected coord
    messages, so the coordinator's awaits resolve without a real subprocess/socket). stdout/stderr →
    PIPE for a diagnostic tail; the AUTHORITATIVE result is always the coord DONE file, never stdout.
    (Windows: ``create_subprocess_exec`` needs the Proactor loop — the platform default there.)"""
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "harness",
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )


async def _await_indexed(
    coord: FileDropCoord, base_name: str, count: int, *, timeout: float
) -> list[dict[str, Any]]:
    """Await the per-child-index messages ``base_name.0 .. base_name.<count-1>`` (each posted by one
    child), returning their payloads in index order. Sequential awaits are fine — the children post
    around the same time, so the total wait is bounded by the slowest to appear, not their sum."""
    return [await coord.await_message(f"{base_name}.{i}", timeout=timeout) for i in range(count)]


async def _reap_child(label: str, proc: Any, *, grace: float) -> str:
    """Best-effort reap ONE spawned child + capture a short stdout tail for the diagnostic log (never
    the authority — that is the coord DONE file). A child that hasn't exited within ``grace`` is killed
    so the coordinator never hangs on an orphan."""
    out = b""
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=grace)
    except TimeoutError:
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            out, _ = await proc.communicate()
    except Exception:  # noqa: BLE001 - reaping is strictly best-effort diagnostics
        pass
    tail = (out or b"").decode("utf-8", "replace").strip().splitlines()[-4:]
    return f"[{label}] " + " / ".join(t.strip() for t in tail) if tail else f"[{label}] (no output)"


@dataclass
class ShardCertDriveReport:
    """The multi-process SIZING drive's verdict — a COUNT-BALANCE + engine-store-truth reconcile over the
    K sender-workers' intake and the M sinks' delivery tallies (a metadata-only coord can't correlate
    acked↔delivered per-message across processes, so no-loss is a count identity, NOT PR-B's per-message
    ``acked ⊆ delivered``). The coordinator reads the engine ``/stats`` REMOTELY, so the store-truth
    stranded / dead-at-any-stage authority stays the ENGINE half's report; this verdict is the count
    balance + per-lane FIFO/dup + the engine's REMOTE done/dead/in_pipeline. Counts + synthetic topology
    labels only — never control-ids / message bodies (PHI rule)."""

    shards: tuple[str, ...]
    # TOPOLOGY: shared outbound destination CONNECTIONS = the sink port-band width. NOT the fan-out —
    # `delivering` is (BACKLOG #209). Never put this in delivery arithmetic.
    dests: int
    # H: handlers the router SELECTS per (shard, lane). Cost model only — never delivery arithmetic.
    handlers: int
    # D: destinations an accepted message actually delivers to. *** THE FAN-OUT ***
    delivering: int
    driver_count: int
    sink_count: int
    aggregate_rate: float
    hold_seconds: float
    offered: int  # round(aggregate_rate * hold_seconds)
    sent: int  # Σ sender-worker sent
    acked: int  # A = Σ sender-worker acked (accept-ACK'd intake)
    sink_received: int  # S = Σ sink delivered copies
    lane_inversions: int  # Σ over sinks
    lane_repeats: int  # Σ over sinks (no kill ⇒ strict zero)
    #: UNION of the sinks' lane-key SETS — the run's true distinct-lane count (the non-vacuous FIFO gate).
    #: Not a MAX (which under `partitioned` reads a per-sink fraction, and false-FAILS the >= 2 bar when each
    #: sink owns one destination) and not a bare Σ (which multiply-counts iff the keys collapse — the very
    #: vacuity the bar exists to catch). See the aggregation note in `run_shardcert_drive`.
    lanes_observed: int
    ack_p50_ms: (
        float  # max over sender-workers (per-proc histograms don't merge cleanly cross-proc)
    )
    ack_p99_ms: float  # max over sender-workers
    engine_done: int  # engine /stats outbound done (deliveries the store marked done) — REMOTE
    engine_dead: int  # engine /stats outbound dead — REMOTE
    in_pipeline_final: int  # engine /stats in_pipeline at drain — REMOTE
    drained: bool
    drain_seconds: float | None
    #: WHICH SHAPE produced the numbers above (learned from SHARDS_READY — the engine box owns the mode).
    #: `handlers`/`delivering` are the DERIVED accounting pair, so without this the artifact is AMBIGUOUS:
    #: a partitioned `--dests 64` run writes {dests: 64, handlers: 1, delivering: 1}, byte-identical to a
    #: LEGAL broadcast `--dests 64 --handlers 1 --delivering 1` — which is a completely different shape
    #: (one handler, all traffic on destination 0, ONE FIFO lane, ~16 msg/s vs ~800+). See `routing` on
    #: ShardCertReport.
    routing: str = BROADCAST
    #: ARTIFACT 5: lanes-per-shard, learned from SHARDS_READY (the engine box derives it from the BUILT
    #: graph). The drive already received this and used it ONLY to slice sender bands, then discarded it — so
    #: ``G = len(shards) x lanes`` (the INGRESS/ROUTED pool width) appeared in NO report, and a lane sweep
    #: that plateaued on the inbound pool was unattributable.
    lanes: int = 1
    #: THE DEFERRAL CAUSE SPLIT (gate v2), Σ over the sender workers (from the DRIVER_DONE drops). ``-1`` =
    #: NOT RECORDED (an older sender half) ⇒ a ``sent`` shortfall scores OFFER_SHORTFALL, never
    #: DRIVE_SHORTFALL. See :class:`RungFidelity` for why ``sent`` alone cannot name the culprit.
    deferred_backpressure: int = -1
    deferred_schedule: int = -1
    #: ARTIFACT 2: the store pool this rung ran on. **THE ENGINE BOX IS THE ONLY HALF THAT CAN SEE THE POOL
    #: AND THE DRIVE BOX IS THE ONLY HALF THAT WRITES A REPORT**, so without a wire the pool size is
    #: unrecoverable from the single-rung two-box artifact — i.e. ``harness shardcert-engine
    #: --store-pool-size N`` + ``harness shardcert-drive --report-json x.json`` would produce a JSON from
    #: which ``N`` cannot be reconstructed (it lived only on the engine box's stderr). That is a direct hit on
    #: "a run whose configuration cannot be reconstructed from its own artifact is unauditable". The REQUESTED
    #: size rides SHARDS_READY (available before the fleet drives); the full saturation evidence + tripwire
    #: rides the ENGINE_DRAINED gate, which upgrades this in place when it arrives.
    pool: PoolStats = EMPTY_POOL_STATS
    notes: list[str] = field(default_factory=list)

    @property
    def sent_ratio(self) -> float | None:
        """``sent / offered`` — the drive's fidelity to its own plan, emitted so :data:`_FIDELITY_SENT_FLOOR`
        (the ONE pre-registered bar the code admits is UNMEASURED) can be RE-DERIVED from banked runs."""
        if self.offered <= 0 or self.sent < 0:
            return None
        return self.sent / self.offered

    @property
    def inbound_bands(self) -> int:
        """``G`` — the inbound MLLP band count the fleet exposed = the width of the INGRESS and ROUTED
        per-lane pools. ``dests`` (L) is the width of the OUTBOUND one. THE LANE-SCALING LAW APPLIES TO ALL
        THREE (``ingress ≈ G/cycle``, ``routed ≈ G/cycle``, ``outbound ≈ L/cycle``), so at ``G < L`` the
        INTAKE is the narrow pool and a destination sweep plateaus on ingress — indistinguishable, in every
        column, from a pooled-claim wall unless G is recorded. Which it now is."""
        return inbound_band_count(len(self.shards), self.lanes)

    @property
    def inbound_band_narrower(self) -> bool:
        """``G < L`` — the INBOUND pool is the narrow one, so this rung's ceiling may be an INGRESS ceiling.
        True at the SHIPPED DEFAULTS (4 shards x 1 lane = 4 bands vs 8 dests), which is exactly why it is a
        recorded WARNING rather than a refusal."""
        return self.dests > 0 and self.inbound_bands < self.dests

    @property
    def fidelity(self) -> RungFidelity:
        """ARTIFACT 4 — was this rung EVIDENCE ABOUT THE ENGINE? :func:`rung_fidelity` on the numbers this
        report already holds (``sent``/``acked``/``offered``). The ladder's ``classify_rung`` never compared
        any of them, so a rung the drive could not push (``sent`` short of the plan) and a rung the engine
        would not take (``acked`` short of a fine ``sent``) BOTH serialised as SUSTAINED — and the ceiling
        that came out was a function of the PLAN. This is the same predicate ``ShardCertStepRecord.fidelity``
        calls: ONE definition, both record types."""
        return rung_fidelity(
            sent=self.sent,
            acked=self.acked,
            offered=self.offered,
            deferred_backpressure=self.deferred_backpressure,
            deferred_schedule=self.deferred_schedule,
        )

    @property
    def fidelity_reason(self) -> str | None:
        """The VOID/BIND reason, from the SAME inputs as :attr:`fidelity` — so they cannot disagree."""
        return fidelity_note(
            self.fidelity,
            sent=self.sent,
            acked=self.acked,
            offered=self.offered,
            deferred_backpressure=self.deferred_backpressure,
            deferred_schedule=self.deferred_schedule,
        )

    @property
    def txn_per_message(self) -> int:
        """The ADR 0051 durable-write cost of one ingress message on the shape that was SERVED:
        ``3 + 2H + 2D``. Reported, never gated on — the bench's own self-report of what it charged the
        store, welded to the store-measured model in ``tests/test_txn_per_message_cost_model.py``.

        ``handlers``/``delivering`` are the SELECTED/DELIVERED pair, so under ``partitioned`` this is the
        true ``3 + 2(1) + 2(1) = 7`` — not the ``3 + 2(64) + 2(64) = 259`` the graph's BUILD counts imply."""
        return 3 + 2 * self.handlers + 2 * self.delivering

    @property
    def events_per_message(self) -> int:
        """Counted message events per ingress message (the 45M/day currency): ``1 + D``. NEVER
        ``1 + dests`` — a destination CONNECTION no handler sends to produces no event."""
        return 1 + self.delivering

    @property
    def no_loss(self) -> bool:
        """Count-balance on SINK SOCKET-TRUTH ONLY (NO-KILL, strict): the sinks' socket-observed
        deliveries (``S``) equal the accept-ACK'd intake fanned out (``A * delivering``), with both sides
        non-vacuous (``A > 0``, ``S > 0``).

        BACKLOG #209 — the fan-out is ``delivering`` (D), **NOT** ``dests``. ``dests`` is the count of
        destination CONNECTIONS (the port-band width); at ``H != D`` the self-filtering handlers deliver
        nothing, so ``A * dests`` would over-expect and this would read LOSS on every healthy rung —
        nothing would ever sustain.

        Deliberately does NOT gate on the poller terms (``drained``, ``engine_dead``, ``engine_done``):
        they are read from the engine ``/stats`` REMOTELY and are UNRELIABLE on a unified store — the
        gauges SUM ``done``/``dead`` over all shard APIs (4× overcount) and ``await_drain`` zeroes/misses
        under load (the exact metric ``mf-bench-attribution-policy`` + the C1 runbook say to NEVER gate
        on). The strand / dead-at-any-stage authority is the ENGINE half's report, which reads the store
        DIRECTLY (store-truth) and owns that verdict; the sinks are the DRIVE box's only reliable truth.
        The poller terms remain as ADVISORY cross-check fields (see ``render``/``to_json_dict``)."""
        fanout = self.acked * self.delivering
        return self.sink_received == fanout and self.acked > 0 and self.sink_received > 0

    @property
    def ok(self) -> bool:
        """Pass bar: sink-truth no-loss AND per-lane FIFO (non-vacuous, ``lanes_observed >= 2``) AND no
        duplicates. The collector-nonzero gates (``A > 0``, ``S > 0``) fold into ``no_loss`` — a vacuous
        run that sent or delivered nothing must NOT silently certify. Excludes the poller terms
        (``drained``/``engine_dead``/``engine_done``) for the reason stated on ``no_loss``: they are
        advisory here; dead-letters + strands are the engine half's store-truth verdict, not the drive's."""
        return (
            self.no_loss
            and self.lane_inversions == 0
            and self.lanes_observed >= 2
            and self.lane_repeats == 0
        )

    @property
    def ceiling(self) -> bool:
        """The fleet could not SUSTAIN the offered load — the shared :func:`_is_ceiling` bar (``not
        no_loss`` OR the accept-INTAKE fell materially short of offered beyond ``_INTAKE_TOL``), the
        measured-intake-shortfall rule, NEVER ``delivered < offered``.

        **``filling=False`` is an EXPLICIT ABSTAIN, not a measurement.** The two-box drive CANNOT compute
        the filling term: its senders and sinks are separate processes and the coord is metadata-only, so
        a sink's ``Correlator`` never sees ``on_send`` and there is no E2E stream to split (this class has
        no e2e field at all — check the field list above). Passing it explicitly is the point: this used to
        build a ``ShardCertStepRecord`` and simply omit the four half fields, which took the 0 sentinel and
        abstained SILENTLY — a dead gate that read exactly like a live one. If a cross-process E2E
        correlation ever lands, replace this ``False`` with the real term AND add it to
        ``shardcert_ladder.classify_rung`` (which is what actually decides a two-box rung); changing only
        one of the two changes nothing. See the ``_FILLING_RATIO`` scope block."""
        return _is_ceiling(
            no_loss=self.no_loss,
            achieved_intake=self.acked,
            offered=self.offered,
            filling=False,  # ABSTAIN — see the docstring; the two-box tier has no E2E to split.
        )

    def render(self) -> str:
        a = self.acked
        fid = self.fidelity
        # ARTIFACT 4: the fidelity read sits WITH the counts it is computed from, so an operator cannot read
        # `offered`/`acked` without also reading whether the rung was DRIVEN at its own plan.
        if self.offered > 0:
            fid_line = (
                f"  fidelity: {fid.value.upper()} "
                f"(sent/offered={self.sent / self.offered:.1%} "
                f"acked/offered={a / self.offered:.1%}; bars "
                f"{_FIDELITY_SENT_FLOOR:.0%}/{_FIDELITY_ACKED_FLOOR:.0%}; deferred "
                f"backpressure={self.deferred_backpressure} schedule={self.deferred_schedule})"
            )
        else:
            fid_line = "  fidelity: UNKNOWN (offered not recorded)"
        lines = [
            f"ShardCert DRIVE {'/'.join(self.shards)}  verdict={'PASS' if self.ok else 'FAIL'}  "
            f"routing={self.routing}  "
            f"K={self.driver_count}sender x M={self.sink_count}sink  "
            f"fanout(delivering)={self.delivering} of dests={self.dests} conns  "
            f"H={self.handlers} (txn/msg={self.txn_per_message}, events/msg={self.events_per_message})",
            # ARTIFACT 5: G beside L, always — a plateau cannot be attributed without both.
            f"  pools: G={self.inbound_bands} inbound bands "
            f"({len(self.shards)} shards x {self.lanes} lanes) vs L={self.dests} outbound lanes"
            + ("   <= INBOUND IS THE NARROW POOL" if self.inbound_band_narrower else ""),
            f"  rate={self.aggregate_rate:g}/s hold={self.hold_seconds:g}s offered={self.offered} "
            f"sent={self.sent} acked(A)={a} sink_received(S)={self.sink_received}",
            fid_line,
            f"  no-loss (SINK truth): sink_received(S)={self.sink_received} "
            f"(expect A*delivering={a * self.delivering}) -> {'OK' if self.no_loss else 'LOSS'}",
            f"  FIFO: lane_inversions={self.lane_inversions} lanes_observed={self.lanes_observed} "
            f"lane_repeats(dups)={self.lane_repeats}",
            f"  ack p50/p99(max over senders)={self.ack_p50_ms:.1f}/{self.ack_p99_ms:.1f}ms "
            f"drain_s={self.drain_seconds}" + ("  <= CEILING" if self.ceiling else ""),
            # ARTIFACT 2: the pool this rung ran on, on the SINGLE-RUNG path too — the one that used to be
            # hand-scraped from /status, which is exactly what this artifact set out to end.
            f"  {self.pool.render()}",
            # ADVISORY poller cross-check, NOT gated (unreliable on a unified store: 4x shard-API
            # overcount / zeroes under load; the engine half's DIRECT store-truth owns strand/dead).
            f"  advisory (poller x-check, NOT gated): engine_done={self.engine_done} "
            f"engine_dead={self.engine_dead} in_pipeline_final={self.in_pipeline_final} "
            f"drained={self.drained}",
        ]
        for n in self.notes:
            lines.append(f"  note: {n}")
        return "\n".join(lines)

    def to_json_dict(self) -> dict[str, object]:
        """Metrics + metadata only (never message bodies or control-id lists — PHI rule)."""
        return {
            # v2 (BACKLOG #209): `dests` no longer means the fan-out — it is the destination-CONNECTION
            # count (topology) only. `topology.handlers` (H) and `topology.delivering` (D, THE fan-out) are
            # new and REQUIRED reading: `no_loss` is now S == A*delivering, and a consumer that kept
            # multiplying by `dests` would over-expect deliveries on any H != D run.
            #
            # v3 (PARTITIONED routing): `topology.routing` is new and NAMES THE SHAPE. Two things moved:
            # (1) under `partitioned`, `handlers`/`delivering` are the DERIVED accounting pair (1, 1) while
            #     the graph BUILT H = D = dests — so `{dests: 64, handlers: 1, delivering: 1}` is emitted by
            #     BOTH a partitioned 64-lane run (~800+ msg/s) and a legal broadcast `--handlers 1
            #     --delivering 1` run (ONE lane, ~16 msg/s). `routing` is the only key that separates them.
            # (2) `correctness.lanes_observed` is now the UNION of the sinks' lane-key sets, not the MAX —
            #     the MAX under-reported the lane count (and false-FAILED the >= 2 bar at one dest/sink).
            #
            # v4 (ARTIFACTS 4 + 5, 2026-07-14) — purely ADDITIVE; nothing removed or redefined:
            #  * `traffic.fidelity` — the per-rung FIDELITY GATE. `sent` and `offered` were both already
            #    here and were never COMPARED, so a DRIVE SHORTFALL and an ENGINE INTAKE BIND were the same
            #    serialization. They are opposite findings ("my load generator is too small" vs "the engine
            #    bound"), and the ceiling could not tell them apart.
            #  * `topology.lanes_per_shard` / `inbound_bands` — G. The drive LEARNED `lanes` from
            #    SHARDS_READY, used it to slice sender bands, and discarded it; G appeared in no artifact.
            #
            # v5 (2026-07-14) — purely ADDITIVE; nothing removed or redefined:
            #  * `store_pool` — ARTIFACT 2 ON THE SINGLE-RUNG PATH. The ENGINE box is the only half that can
            #    SEE the pool and the DRIVE box is the only half that WRITES a report, so `shardcert-engine
            #    --store-pool-size N` + `shardcert-drive --report-json x.json` produced an artifact from which
            #    N was UNRECOVERABLE (it existed only on the engine box's stderr). The requested size now
            #    rides SHARDS_READY and the acquire_wait evidence + tripwire ride the ENGINE_DRAINED gate.
            #  * `traffic.deferred_backpressure` / `traffic.deferred_schedule` — the FIDELITY GATE'S CAUSE
            #    SPLIT (gate v2). `sent` is ENGINE-PACED (bounded queue + drain()), so a `sent` shortfall
            #    cannot say whose fault it was; these can. ⚠️ `traffic.fidelity` is therefore NARROWED: a v4
            #    `drive_shortfall` is a v5 `backpressure_bind`, `drive_shortfall` or `offer_shortfall`.
            #  * `traffic.sent_ratio` — so the UNMEASURED 0.98 sent bar can be re-derived from banked runs.
            "schema_version": 5,
            "kind": "shardcert_drive",
            "verdict": "PASS" if self.ok else "FAIL",
            "shards": list(self.shards),
            "topology": {
                "dests": self.dests,
                "handlers": self.handlers,
                "delivering": self.delivering,
                # broadcast | partitioned — see the v3 note above; do NOT read handlers/delivering without it.
                "routing": self.routing,
                "txn_per_message": self.txn_per_message,
                "events_per_message": self.events_per_message,
                "driver_count": self.driver_count,
                "sink_count": self.sink_count,
                # v4 (ARTIFACT 5): G, the INGRESS/ROUTED per-lane pool width, beside `dests` (L, the OUTBOUND
                # one). At G < L a lane/destination sweep plateaus on the INBOUND pool and manufactures what
                # reads, column for column, as a pooled-claim wall.
                "lanes_per_shard": self.lanes,
                "inbound_bands": self.inbound_bands,
                "inbound_bands_narrower_than_dests": self.inbound_band_narrower,
            },
            "traffic": {
                "aggregate_rate": round(self.aggregate_rate, 3),
                "hold_seconds": self.hold_seconds,
                "offered": self.offered,
                "sent": self.sent,
                # v5: so the UNMEASURED pre-registered 0.98 sent bar can be RE-DERIVED from banked artifacts,
                # which is that bar's own stated remediation plan.
                "sent_ratio": None if self.sent_ratio is None else round(self.sent_ratio, 4),
                "acked": self.acked,
                "sink_received": self.sink_received,
                # v5: THE DEFERRAL CAUSE SPLIT — the gate's shortfall discriminator. `sent` is incremented
                # only after a pop from a BOUNDED queue whose writer drain()s first, so ENGINE BACKPRESSURE
                # suppresses `sent`: `offered - sent` is ENGINE-PACED, not a rig-only quantity. Full buffers
                # ⇒ `deferred_backpressure` (the ENGINE would not read); tick-lag ⇒ `deferred_schedule` (THE
                # RIG). Opposite findings; one counter until now.
                "deferred_backpressure": self.deferred_backpressure,
                "deferred_schedule": self.deferred_schedule,
                # v4 (ARTIFACT 4): admissible ⇒ this rung is evidence about the ENGINE and may PIN a ceiling.
                # `fidelity_driven` ⇒ the offered RATE was established (or the engine refused to read it), so
                # the rung may BRACKET one. NOTE `sent` is counted at write-buffer time, so `sent >= 98% of
                # offered` proves the GENERATOR could offer the plan — NOT that the bytes reached the engine.
                "fidelity": self.fidelity.value,
                "fidelity_admissible": self.fidelity.admissible,
                "fidelity_driven": self.fidelity.driven,
                "fidelity_reason": self.fidelity_reason,
                "fidelity_gate_version": FIDELITY_GATE_VERSION,
            },
            # v5 (ARTIFACT 2): the store pool this rung ran on — requested size + the engine's own maximum +
            # the acquire_wait saturation evidence + the PRE-REGISTERED TRIPWIRE. A pool bind is
            # column-for-column identical to the pooled-claim wall; this block is the only discriminator, and
            # on the single-rung path it did not exist in ANY artifact.
            "store_pool": {
                **self.pool.to_json_dict(),
                "product_default": PRODUCT_STORE_POOL_SIZE,
                "adr_0062_optimum": POOL_SIZE_OPTIMUM,
                "adr_0062_cliff": POOL_SIZE_CLIFF,
            },
            "correctness": {
                # SINK socket-truth only — the gated verdict. See ``no_loss``/``ok`` for why the
                # poller terms (engine_done/engine_dead/drained) are excluded (they live in
                # ``advisory_poller`` below).
                "no_loss": self.no_loss,
                "lane_inversions": self.lane_inversions,
                "lanes_observed": self.lanes_observed,
                "lane_repeats": self.lane_repeats,
            },
            "throughput": {
                "drain_seconds": self.drain_seconds,
                "ceiling": self.ceiling,
                # WHICH sustain bar produced `ceiling`, and the fact that its `filling` term ABSTAINED on
                # this (two-box) path by construction — so a reader cannot mistake a two-box ceiling for a
                # filling-corrected one. See ShardCertDriveReport.ceiling / the `_FILLING_RATIO` block.
                "ceiling_gate_version": CEILING_GATE_VERSION,
                "filling_evaluated": False,
                "filling_abstain_reason": (
                    "two-box tier has no cross-process E2E correlation (metadata-only coord): the sink's "
                    "Correlator never sees on_send, so there is no E2E stream to split"
                ),
            },
            "advisory_poller": {
                # Poller cross-check, NOT gated: unreliable on a unified store (4x shard-API overcount
                # on done/dead; await_drain zeroes/misses under load). Retained for telemetry; the
                # engine half's DIRECT store-truth is the strand/dead authority.
                "note": "poller cross-check, NOT gated (unreliable on a unified store)",
                "engine_done": self.engine_done,
                "engine_dead": self.engine_dead,
                "in_pipeline_final": self.in_pipeline_final,
                "drained": self.drained,
            },
            "ack_ms": {"p50": round(self.ack_p50_ms, 3), "p99": round(self.ack_p99_ms, 3)},
            "notes": self.notes,
        }


async def run_shardcert_drive(
    *,
    engine_host: str,
    aggregate_rate: float = 40.0,
    hold_seconds: float = 20.0,
    driver_count: int = 1,
    sink_count: int | None = None,
    sink_host: str = "127.0.0.1",
    coord: FileDropCoord,
    shards_ready_timeout: float = 300.0,
    child_ready_timeout: float = 120.0,
    driver_done_timeout: float | None = None,
    drive_complete_timeout: float | None = None,
    sink_done_timeout: float = 120.0,
    drain_timeout: float = 90.0,
    reap_grace: float = 10.0,
    allow_insecure: bool = False,
    await_engine_drained: bool = False,
    engine_drained_timeout: float | None = None,
) -> ShardCertDriveReport:
    """The multi-process SIZING drive COORDINATOR (load-gen box). Learns the topology from
    :data:`SHARDS_READY` (the engine half posts it), spawns ``sink_count`` :func:`run_shardcert_sink` +
    ``driver_count`` :func:`run_shardcert_driver_worker` CHILD processes (seam :func:`_spawn_proc`),
    orchestrates the handshake, drains the engine's REMOTE ``/stats``, then aggregates the children's
    coord DONE files into a COUNT-BALANCE + engine-store-truth reconcile.

    Handshake order: await SHARDS_READY → spawn+await all :data:`SINK_BOUND` → spawn+await all
    :data:`DRIVER_ARMED` → post :data:`DRIVE_START` (the engine's kill anchor — no kill here) +
    :data:`DRIVE_GO` (release the senders) → await all :data:`DRIVER_DONE` → drain REMOTE ``/stats`` →
    post :data:`DRIVE_COMPLETE` → await all :data:`SINK_DONE` → reconcile.

    The coordinator + all spawned children run on the load-gen box — NEVER co-located with the engine
    fleet (the attribution isolation; an operator/runbook concern). **Fail loud** early on a mis-sized
    fleet (a sink partition or band slice that doesn't tile) rather than spawning doomed children.

    ``await_engine_drained`` (default OFF ⇒ the standalone C1 drive path is byte-identical) is the PR-C2
    ladder's **drain gate**: before signalling :data:`DRIVE_COMPLETE` (which releases the sinks to record
    their final tally), wait for the ENGINE half's RELIABLE store-truth :data:`ENGINE_DRAINED`. The remote
    ``/stats`` poller below is advisory (it can zero out under load on a unified store), so tallying on it
    alone risks reading a teardown-frozen in-flight tail as loss; awaiting the engine's DIRECT store read
    closes that window. Bounded + best-effort — a missing signal degrades to the advisory-drain fallback
    with a note, never a hang."""
    ready = await coord.await_message(SHARDS_READY, timeout=shards_ready_timeout)
    ids_list = [str(s) for s in ready["shards"]]
    dests = int(ready["dests"])
    # BACKLOG #209: REQUIRED keys, never `.get(..., dests)`. These are GATE INPUTS — `delivering` is the
    # multiplier in `no_loss` (S == A*D) and in the ladder's `sustained_events_per_s` (the number the
    # 45M/day decision keys off). Defaulting them to `dests` against an engine box that did not send them
    # would silently reinstate the H = D = dests assumption and fabricate a plausible headline. A KeyError
    # here says "the two boxes are running different code" — which is exactly true, and must be loud.
    handlers = int(ready["handlers"])
    delivering = int(ready["delivering"])
    # REQUIRED for the same reason, one level up: `handlers`/`delivering` above are the DERIVED accounting
    # pair, and (1, 1) is a shape BOTH modes can legally produce. Defaulting this to "broadcast" against an
    # engine box that did not send it would MISLABEL a partitioned run in the banked artifact — which is the
    # exact provenance hole this key closes. A KeyError says "the two boxes are running different code".
    routing = str(ready["routing"])
    sink_base = int(ready.get("sink_base", ready["sink_port"]))
    sink_ports = int(ready.get("sink_ports", 1))
    api_ports = [int(p) for p in ready["api_ports"]]
    lanes = int(ready.get("lanes", 1))
    # ARTIFACT 2 (single-rung path): the REQUESTED pool size, learned at SHARDS_READY. `.get` with the
    # not-measured sentinel — an engine half that predates this key must read as "not recorded", never as a
    # confident 0/40. The acquire_wait EVIDENCE + the tripwire arrive later on the ENGINE_DRAINED gate and
    # upgrade this record in place; if that gate never comes, the run still names the pool it ASKED for.
    pool = PoolStats(requested=int(ready.get("store_pool_size", -1)))

    # BACKLOG #209 back-compat: the engine's `--sink-ports` is now DERIVED from `--dests`, so a `--dests`
    # below the old literal-8 default advertises a band narrower than 8. Default `sink_count` to the
    # LEARNED band width (clamped at 8), never a fixed 8 sitting beside a `--dests` that can be anything —
    # a stale constant beside a parameter is this harness's B1-B10 defect class. An explicit caller value
    # is honored (and still validated by _partition_band below). One sink per port, up to 8.
    if sink_count is None:
        sink_count = min(8, sink_ports)

    if driver_count < 1 or sink_count < 1:
        raise ValueError("driver_count and sink_count must both be >= 1")
    # Fail LOUD here on a mis-sized fleet (a partition/slice that can't tile) — otherwise K/M silently
    # doomed children would each fail-loud + never post BOUND/ARMED, and the coordinator would only see
    # an opaque timeout. Validating up front turns that into a crisp setup error.
    _partition_band(sink_base, sink_ports, sink_count)
    total_bands = len(ids_list) * lanes
    for j in range(driver_count):
        _band_slice(total_bands, driver_count, j)

    # Fresh-run hygiene: clear the child/handshake drops this run will (re)post so a stale prior-run file
    # can't be mis-read. NOT SHARDS_READY — the engine posted it and we just consumed it.
    coord.clear_messages(
        DRIVE_START,
        DRIVE_GO,
        DRIVE_COMPLETE,
        *(f"{SINK_BOUND}.{m}" for m in range(sink_count)),
        *(f"{SINK_DONE}.{m}" for m in range(sink_count)),
        *(f"{DRIVER_ARMED}.{j}" for j in range(driver_count)),
        *(f"{DRIVER_DONE}.{j}" for j in range(driver_count)),
    )

    coord_dir = str(coord.directory)
    run_id = coord.run_id
    procs: list[tuple[str, Any]] = []
    notes: list[str] = []
    poller: EnginePoller | None = None
    # B6: the sink children each bound their DRIVE_COMPLETE await, and their window OPENS at SINK_BOUND
    # (below) and CLOSES at our DRIVE_COMPLETE post (step 5) — strictly wider than our own DRIVER_DONE wait.
    # They cannot derive it (they never see hold/drain), so derive it HERE and thread it into the argv. A
    # sink that fires early truncates its tally with no RUNG_ABORTED marker, so B3 cannot invalidate the
    # rung and the engine reports a real stranded>0: a fabricated collapse.
    # B7: resolve the gate wait FIRST — B6's sink bound has to dominate it, so it must be the value we will
    # actually wait on, not the bare default it used to be.
    engine_drained_wait = _derive_engine_drained_timeout(drain_timeout, engine_drained_timeout)
    sink_drive_complete_wait = _derive_drive_complete_timeout(
        hold_seconds,
        drain_timeout,
        child_ready_timeout=child_ready_timeout,
        engine_drained_timeout=engine_drained_wait,
        await_engine_drained=await_engine_drained,
        driver_done_timeout=driver_done_timeout,
        override=drive_complete_timeout,
    )
    try:
        # (1) Spawn the M sink children over CONTIGUOUS chunks of the [sink_base, sink_base+sink_ports)
        #     (== dests) band; await each SINK_BOUND.<m>.
        for m in range(sink_count):
            proc = await _spawn_proc(
                [
                    "shardcert-sink",
                    "--sink-host",
                    sink_host,
                    "--sink-base",
                    str(sink_base),
                    "--sink-ports",
                    str(sink_ports),
                    "--sink-index",
                    str(m),
                    "--sink-count",
                    str(sink_count),
                    "--drive-complete-timeout",
                    str(sink_drive_complete_wait),
                    "--coord-dir",
                    coord_dir,
                    "--run-id",
                    run_id,
                ]
            )
            procs.append((f"sink-{m}", proc))
        await _await_indexed(coord, SINK_BOUND, sink_count, timeout=child_ready_timeout)

        # (2) Spawn the K sender-worker children over CONTIGUOUS band slices; await each DRIVER_ARMED.<j>.
        for j in range(driver_count):
            proc = await _spawn_proc(
                [
                    "shardcert-driver-worker",
                    "--engine-host",
                    engine_host,
                    "--aggregate-rate",
                    str(aggregate_rate),
                    "--hold-seconds",
                    str(hold_seconds),
                    "--driver-index",
                    str(j),
                    "--driver-count",
                    str(driver_count),
                    "--coord-dir",
                    coord_dir,
                    "--run-id",
                    run_id,
                ]
            )
            procs.append((f"worker-{j}", proc))
        await _await_indexed(coord, DRIVER_ARMED, driver_count, timeout=child_ready_timeout)

        # (3) Release: DRIVE_START keeps the ENGINE half's handshake unchanged (its kill anchor; no kill
        #     here); DRIVE_GO releases the armed sender-workers into their hold in lockstep.
        coord.post(DRIVE_START, {"t0": time.time()})
        coord.post(DRIVE_GO, {"go": True})

        # (4) Await every sender-worker's DONE, then drain the engine's REMOTE /stats (the authoritative
        #     drain signal, polled off-box) before declaring the pipeline empty. B1: a child posts DRIVER_DONE
        #     only AFTER its full hold, so a FIXED timeout under-shoots any hold near it — a long soak would
        #     abort mid-send, reaping the sinks while the engine still delivers and manufacturing a fake
        #     collapse (B3). Derive the timeout from hold + drain + margin instead.
        driver_done_wait = _derive_driver_done_timeout(
            hold_seconds, drain_timeout, driver_done_timeout
        )
        driver_dones = await _await_indexed(
            coord, DRIVER_DONE, driver_count, timeout=driver_done_wait
        )
        urls = [f"http://{engine_host}:{p}" for p in api_ports]
        # allow_insecure threads the plaintext-http-to-remote posture: the engine box's API is http and
        # off-box, so without it EngineClient fail-closes and poller.open() raises AFTER the children are
        # spawned. (A loopback co-located engine never needs it.) The finally below still tears the
        # children down on any early failure, but threading this is what makes the run succeed.
        poller = EnginePoller(urls, None, origin=time.perf_counter(), allow_insecure=allow_insecure)
        await poller.open()
        drain_s = await poller.await_drain(timeout=drain_timeout, interval=0.5)
        final = poller.final

        # (4b) PR-C2 ladder drain gate (default OFF): before releasing the sinks to tally, wait for the
        # ENGINE half's RELIABLE store-truth drain signal. The remote poller above is advisory (zeroes
        # under load on a unified store), so tallying on it alone can read a teardown-frozen tail as loss;
        # the engine's DIRECT store read closes that window. B7: the wait is now DERIVED from drain_timeout
        # (it must cover the engine's own drain + its store read), not a fixed 300s that a raised drain
        # window silently outgrew. Best-effort — a missing signal is noted rather than hanging.
        if await_engine_drained:
            try:
                drained_msg = await coord.await_message(ENGINE_DRAINED, timeout=engine_drained_wait)
                notes.append(
                    f"engine drain gate: engine_ok={drained_msg.get('engine_ok')} "
                    f"stranded={drained_msg.get('stranded')} dead_total={drained_msg.get('dead_total')}"
                )
                # ARTIFACT 2: the pool's SATURATION EVIDENCE + tripwire ride the RELIABLE gate (not only the
                # later, more fragile ENGINE_RUNG_REPORT). The gate is the message the drive AWAITS before it
                # tallies, so pool evidence is now exactly as reliable as the store-truth it accompanies —
                # instead of vanishing on a lost report while the rung still pinned and bracketed a ceiling.
                gate_pool = drained_msg.get("store_pool")
                if isinstance(gate_pool, Mapping):
                    pool = PoolStats.from_json_dict(gate_pool)
                if pool.tripped and pool.trip_reason is not None:
                    notes.append(pool.trip_reason)
            except CoordTimeout:
                # NOT "tallying on the advisory poller" — the VERDICT never consumes it (classify_rung takes
                # store-truth from the gate or, failing that, ENGINE_RUNG_REPORT). What is actually lost is
                # the barrier: the sinks tally before the engine finished delivering, so a healthy rung can
                # render FROZEN_TAIL (benign, excluded from the ceiling) and a healthy SOAK can read
                # soak_ok=False. A false negative, never a fabricated collapse.
                notes.append(
                    f"ENGINE_DRAINED not seen within {engine_drained_wait}s — sinks tally WITHOUT the "
                    "store-truth drain barrier; an early tally may render FROZEN_TAIL (a false negative). "
                    "Store-truth still comes from ENGINE_RUNG_REPORT, never the advisory poller"
                )

        # (5) Signal drained → every sink records its final tally and posts SINK_DONE.<m>.
        coord.post(DRIVE_COMPLETE, {"t": time.time()})
        sink_dones = await _await_indexed(coord, SINK_DONE, sink_count, timeout=sink_done_timeout)
    finally:
        if poller is not None:
            with contextlib.suppress(Exception):
                await poller.close()
        # Reap CONCURRENTLY so an early failure (e.g. a poller.open() raise while M+K children are still
        # live, some blocked on DRIVE_COMPLETE) tears the whole tier down in ~one reap_grace, not
        # (M+K)*reap_grace — no lingering child processes on the load-gen box between ladder steps.
        if procs:
            notes.extend(
                await asyncio.gather(
                    *(_reap_child(label, proc, grace=reap_grace) for label, proc in procs)
                )
            )

    # (6) Aggregate the children's coord DONE files (the authority) + the engine's REMOTE drain gauge.
    a = sum(int(d["acked"]) for d in driver_dones)
    sent = sum(int(d["sent"]) for d in driver_dones)
    # THE DEFERRAL CAUSE SPLIT, Σ over the sender workers. A worker half that predates the split omits the
    # keys entirely — in which case the sum is -1 (NOT RECORDED), and the fidelity gate scores a shortfall
    # OFFER_SHORTFALL (cause unattributed) rather than blaming the rig on evidence it does not have.
    if all("deferred_backpressure" in d and "deferred_schedule" in d for d in driver_dones):
        deferred_bp = sum(int(d["deferred_backpressure"]) for d in driver_dones)
        deferred_sched = sum(int(d["deferred_schedule"]) for d in driver_dones)
    else:
        deferred_bp, deferred_sched = -1, -1
        notes.append(
            "deferral CAUSE SPLIT not reported by every sender worker — a `sent` shortfall on this rung "
            "CANNOT be attributed to the rig or to engine backpressure (it scores OFFER_SHORTFALL)"
        )
    ack_p50 = max((float(d["ack_p50_ms"]) for d in driver_dones), default=0.0)
    ack_p99 = max((float(d["ack_p99_ms"]) for d in driver_dones), default=0.0)
    s_total = sum(int(d["sink_received"]) for d in sink_dones)
    inversions = sum(int(d["lane_inversions"]) for d in sink_dones)
    repeats = sum(int(d["lane_repeats"]) for d in sink_dones)
    # UNION the sinks' lane-key SETS — the run's true distinct-lane count.
    #
    # This used to be a MAX over the per-sink COUNTS, justified by a BROADCAST-only reading ("every lane fans
    # to every delivered dest, so a sink observes EVERY lane"). Under PARTITIONED a message goes to exactly
    # ONE destination, so a sink sees only the lanes whose dest is in its own port chunk. `sink_count` defaults
    # to `min(8, sink_ports)` and `sink_ports` defaults to `dests`, so at dests <= 8 each sink owns exactly ONE
    # destination and its lanes_observed is just the shard count feeding it — MAX then reads 4 where the truth
    # is 32, and reads 1 (FAILING the >= 2 non-vacuity bar on a perfectly healthy, lossless, in-order rung) as
    # soon as a dest has a single feeding shard.
    #
    # A bare SUM is not the fix either, even though the keys ARE disjoint by construction (the key contains the
    # DESTINATION, and _partition_band gives each destination exactly one owning sink): the ONE case where they
    # are NOT disjoint is exactly the vacuity this gate exists to catch — an unstamped MSH-6 collapses every
    # delivery onto the key "" in EVERY sink at once, where SUM would report `sink_count` lanes and FALSE-PASS.
    # Unioning the actual keys is correct in both cases and needs no assumption about the routing mode at all.
    lane_key_union: set[str] = set()
    for d in sink_dones:
        lane_key_union.update(str(k) for k in d["lane_keys"])
    lanes_observed = len(lane_key_union)

    return ShardCertDriveReport(
        shards=tuple(ids_list),
        dests=dests,
        handlers=handlers,
        delivering=delivering,
        routing=routing,
        # ARTIFACT 5: `lanes` came over SHARDS_READY and was used ONLY for `_band_slice` above, then dropped.
        # Carried into the report now, so G = len(shards) x lanes is recoverable from the artifact.
        lanes=lanes,
        driver_count=driver_count,
        sink_count=sink_count,
        aggregate_rate=aggregate_rate,
        hold_seconds=hold_seconds,
        offered=round(aggregate_rate * hold_seconds),
        sent=sent,
        deferred_backpressure=deferred_bp,
        deferred_schedule=deferred_sched,
        # ARTIFACT 2: the pool, so the SINGLE-RUNG two-box artifact can name the configuration it ran under.
        pool=pool,
        acked=a,
        sink_received=s_total,
        lane_inversions=inversions,
        lane_repeats=repeats,
        lanes_observed=lanes_observed,
        ack_p50_ms=ack_p50,
        ack_p99_ms=ack_p99,
        engine_done=(final.done if final else 0),
        engine_dead=(final.dead if final else 0),
        in_pipeline_final=(final.in_pipeline if final else -1),
        drained=drain_s is not None,
        drain_seconds=drain_s,
        notes=notes,
    )
