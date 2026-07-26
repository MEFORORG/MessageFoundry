# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Engine-side sampling — the aggregate view the per-message metrics can't give.

Polls the engine's HTTP API on an interval (``/stats``, ``/connections``, ``/status``) to track
engine-side throughput (Δdone/Δt), backlog, dead-letter accumulation, and DB/WAL growth over the run,
then measures **drain time** after offered load stops. The :class:`~messagefoundry.apiclient`
``EngineClient`` is synchronous (httpx), so every call runs in a thread via ``run_in_executor`` — the
load engine's event loop is never blocked. The harness reaches the engine only through this API; it
never touches the store.

**Cluster-wide aggregation.** A ``messagefoundry supervise`` cluster spreads inbounds across several
shard subprocesses, each with its own API. The poller takes a **list** of engine base-URLs (the
primary ``--engine`` plus any ``--shard-engine``, de-duped), polls each in turn off the event loop,
and **sums** each shard's read/written/backlog/in_pipeline/queue_depth/dead into one cluster sample
(the sum is order-independent, so the sequential per-shard reads need no ordering) — so the no-loss
reconcile compares cluster-aggregate ``read``/``written``/``backlog`` against the (already cluster-
aggregate) client ``sent``/``sink_received``, and drain requires **every** shard to empty. With a
single URL (the default) a sample is byte-identical to the one-shard behavior.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence, TypeVar

from messagefoundry.apiclient import ApiError, EngineClient

from harness.load.metrics import Counters

_T = TypeVar("_T")


def _first_not_none(values: Iterable[_T | None]) -> _T | None:
    """The first non-``None`` value, or ``None`` if all are ``None`` (per-process gauges: the connscale
    harness drives a single engine, so this is exactly that engine's reading)."""
    for value in values:
        if value is not None:
            return value
    return None


def _pool_attr(status: Any, name: str) -> int | None:
    """Read ``status.pool.<name>`` (the server-only pool field), or ``None`` on SQLite / an older
    engine whose ``SystemStatus`` has no ``pool`` field."""
    pool = getattr(status, "pool", None)
    if pool is None:
        return None
    value = getattr(pool, name, None)
    return int(value) if value is not None else None


def _pool_wait_attr(status: Any, name: str) -> float | None:
    """Read ``status.pool.acquire_wait.<name>`` (the PRIMARY pool-wait percentiles), or ``None``."""
    pool = getattr(status, "pool", None)
    if pool is None:
        return None
    wait = getattr(pool, "acquire_wait", None)
    if wait is None:
        return None
    value = getattr(wait, name, None)
    return float(value) if value is not None else None


@dataclass(frozen=True)
class EngineSample:
    """One engine-side observation. ``read``/``written``/``done``/``dead`` are cumulative since engine
    start, so run totals are last − first. Under a multi-shard cluster every field is the **sum**
    across all polled shards."""

    elapsed_s: float
    pending: int  # outbound stage, status=pending
    inflight: int  # outbound stage, status=inflight
    done: int  # outbound stage, status=done (delivered)
    dead: int  # outbound stage, status=dead (dead-lettered)
    read: int  # Σ inbound `read` (messages received)
    written: int  # Σ outbound `written` (deliveries made)
    out_dead: int  # Σ outbound `errored` (deliveries dead-lettered)
    queue_depth: int  # Σ outbound queue_depth (pending + inflight)
    in_pipeline: (
        int  # NOT-DONE rows across ALL stages (ingress+routed+outbound) — whole-pipeline gauge
    )
    db_size_bytes: int
    journal_mode: str
    synchronous: (
        str | None
    )  # SQLite durability mode ("normal"/"full"); None on server backends (B7)
    uptime_s: float
    # B11 connection-scale instrumentation (read-only, additive; default 0/None so an OLDER engine
    # without these fields deserializes to zeros — the established back-compat pattern). Summed across
    # shards where summable; pool gauges take the first server-store shard reporting one.
    empty_claims: int = 0  # Σ cumulative empty claims (wall #3)
    empty_claims_idle_poll: int = 0  # the idle-poll re-SELECT share
    empty_claims_wake_fanout: int = 0  # the per-commit wake-fanout (thundering-herd) share
    # A1 live cost counters (cumulative since engine start; run totals are last − first). committed_txns =
    # physical transactions committed (the 3+2H+2N/msg cost-model currency, ADR 0051); body_copies =
    # raw/payload body strings durably written (the 2+H+N/msg amplification). Σ across shards; default 0 so
    # an older engine without the /stats fields reads as zero.
    # Pool acquire-wait COUNT + MEAN (2026-07-13). PoolWaitInfo exposes both; the poller read only the
    # percentiles. Differencing mean_ms x count across the soak splits a store round-trip into
    # engine-side QUEUEING vs actual STORE SERVICE:  store_service_ms = claim_mean_ms - acquire_wait_mean_ms.
    # Until now the "~2.84 ms round-trip" was never measured -- it was 20 / 7 (ADR 0057 §1).
    pool_acquire_wait_count: int = 0
    pool_acquire_wait_mean_ms: float = 0.0
    committed_txns: int = 0
    body_copies: int = 0
    executor_queue_depth: int | None = None  # default-pool submit-queue depth (wall #1; shim-only)
    executor_busy: int | None = None  # default-pool in-flight count (wall #1; shim-only)
    pool_size: int | None = None  # server-store pool: connections open (wall #2; None on SQLite)
    pool_idle: int | None = None  # server-store pool: connections free (idle==0 ⇒ saturated)
    pool_wait_p50_ms: float | None = None  # PRIMARY wall #2: acquire-wait percentiles (ms)
    pool_wait_p95_ms: float | None = None
    pool_wait_p99_ms: float | None = None
    pool_wait_max_ms: float | None = None
    # ARTIFACT 2 (2026-07-14). The four fields above take the FIRST shard reporting a pool
    # (`_first_not_none`), which MASKS a per-shard bind: one saturated shard among four averages into
    # invisibility if it is not the first. These are the shard-aware aggregates — added rather than
    # redefining the existing ones, so no banked consumer moves. (`pool_wait_max_ms` was briefly flipped to
    # a max-across-shards; that REDEFINED a field `connscale/report.py` emits as `pool_wait.max_ms` under an
    # unbumped SCHEMA_VERSION, so it is back to first-shard and the max lives here, beside its siblings.)
    #
    # `pool_max_size` is the engine's OWN view of its configured maximum (`status.pool.max_size`), which the
    # poller never read. It is the only way to CHECK the harness's requested MEFOR_STORE_POOL_SIZE actually
    # took effect — a mismatch between requested and observed is itself a finding.
    pool_max_size: int | None = None  # configured pool MAXIMUM (per engine process)
    pool_idle_min: int | None = (
        None  # MIN idle across shards (0 ⇒ at least one shard's pool is dry)
    )
    pool_wait_p95_max_ms: float | None = (
        None  # MAX p95 across shards — the un-maskable saturation read
    )
    pool_wait_p99_max_ms: float | None = None
    #: MAX of the per-shard acquire-wait MAXIMUM — "the worst acquire ANY shard saw". The legacy
    #: `pool_wait_max_ms` is first-shard-wins (like its p50/p95/p99 siblings) and stays that way; this is the
    #: across-shard read, and it is the one :meth:`PoolStats.from_sample` uses.
    pool_wait_max_max_ms: float | None = None
    pool_shards_reporting: int = 0  # how many shards reported a pool at all (0 ⇒ SQLite / no pool)

    @property
    def backlog(self) -> int:
        return self.pending + self.inflight


@dataclass(frozen=True)
class _ShardSample:
    """A single shard's contribution to one cluster sample (the per-URL summable parts)."""

    pending: int
    inflight: int
    done: int
    dead: int
    read: int
    written: int
    out_dead: int
    queue_depth: int
    in_pipeline: int
    db_size_bytes: int
    uptime_s: float
    journal_mode: str
    synchronous: str | None
    # B11 (read-only, additive): empty-claim counts (summable) + executor gauges + the server-store
    # pool snapshot. All default 0/None so an older engine without these fields reads as zeros.
    empty_claims: int = 0
    empty_claims_idle_poll: int = 0
    empty_claims_wake_fanout: int = 0
    committed_txns: int = 0  # A1 live cost counter (summable across shards)
    # Pool acquire-wait COUNT + MEAN (2026-07-13) — PoolWaitInfo exposes both; the poller read only the
    # percentiles. mean_ms x count differenced across a soak splits a store round-trip into engine-side
    # QUEUEING vs actual STORE SERVICE. Mirrors the same two fields on EngineSample.
    pool_acquire_wait_count: int = 0
    pool_acquire_wait_mean_ms: float = 0.0
    body_copies: int = 0  # A1 live cost counter (summable across shards)
    executor_queue_depth: int | None = None
    executor_busy: int | None = None
    pool_size: int | None = None
    pool_idle: int | None = None
    pool_wait_p50_ms: float | None = None
    pool_wait_p95_ms: float | None = None
    pool_wait_p99_ms: float | None = None
    pool_wait_max_ms: float | None = None
    #: The engine's OWN configured pool maximum (``status.pool.max_size``) — see EngineSample.pool_max_size.
    pool_max_size: int | None = None


#: The pool ``acquire_wait`` MEAN measured on the STEP-2 rig at the ~16 msg/s broadcast plateau, where the
#: pool provably was NOT the constraint (560 txn/s against 32 fleet-wide connections ⇒ ~21% utilisation).
#: Every tripwire bar below is stated as a multiple of THIS, so the numbers are anchored to a measurement
#: rather than to taste.
POOL_ACQUIRE_WAIT_BASELINE_MS = 0.0135

#: PRE-REGISTERED POOL TRIPWIRE (ARTIFACT 2, 2026-07-14). If any of these fires, the STORE POOL is the
#: constraint and the run's ceiling is a POOL BIND — not a claim wall, not a lane wall. A pool bind strands
#: at outbound, grows claim_mean, and is immune to drive and to the drive box's disk, i.e. it is IDENTICAL
#: to the pooled-claim wall in every column we have ever looked at. This is the discriminator.
#:
#: ⚠️ The MEAN is the WEAK instrument and must never be the only one. ``AcquireWaitHistogram.record()`` fires
#: on EVERY acquire (``store/sqlserver.py``), not only ones that waited — so ``count`` is really a
#: store-round-trip counter and ``mean_ms`` is DILUTED by the flood of zero-wait acquires. A pool that is dry
#: 5% of the time (and blocking for 20 ms when it is) still reports a ~1 ms mean. Hence the PRIMARY bar is
#: p95: at a healthy pool the 95th percentile acquire is still ~free, so a p95 in the milliseconds means one
#: acquire in twenty is QUEUEING for a connection.
#:
#: ⚠️ THE p95 BAR IS NOT ANCHORED TO A MEASUREMENT ON THIS RIG. :data:`POOL_ACQUIRE_WAIT_BASELINE_MS` is a
#: MEAN, and no p95 was recorded at that known-unbound reference point — so only the SECONDARY (mean) bar is
#: stated as a multiple of a measured baseline. The p95 bar below is imported wholesale from the STEP-4
#: falsifier doc. The JSON therefore emits ``baseline_p95_ms: null`` beside ``p95_ms``, so a reader cannot
#: assume the p95 bar shares the mean's anchor. Record a p95 at the unbound reference rung and restate this
#: as an explicit multiple of it.
_POOL_TRIP_P95_MS = (
    5.0  # the STEP-4 falsifier bar (docs/benchmarks/STEP4-bracket-and-littles-law.md) — UN-ANCHORED
)
#: The p99 bar. ``record()`` fires on EVERY acquire, so the flood of zero-wait acquires dilutes the
#: PERCENTILES as well as the mean: a pool that is dry for 4% of acquires (blocking ~12 ms each) leaves
#: p95 ≈ 0 and mean ≈ 0.5 ms — BOTH bars abstain while the pool is materially constraining. p99 is the only
#: instrument that sees a 1–5% bind, and it is already surfaced per-shard (`pool_wait_p99_max_ms`), so it
#: gets a bar. Same 5 ms value as the p95 bar: at a healthy pool even the 99th-percentile acquire is ~free
#: (baseline mean 0.0135 ms), so 5 ms at p99 is a wall of waiters however few of them there are.
_POOL_TRIP_P99_MS = 5.0
_POOL_TRIP_MEAN_MS = 1.0  # ~74x the measured baseline — a mean this high needs a wall of waiters


@dataclass(frozen=True)
class PoolStats:
    """The store connection pool's saturation evidence for ONE rung — the record that makes a POOL BIND
    impossible to mistake for a claim wall ever again (ARTIFACT 2).

    ``requested`` is what the HARNESS asked for (``MEFOR_STORE_POOL_SIZE`` handed to every ``serve --shard``
    subprocess, per PROCESS); ``max_size`` is what the ENGINE says it configured (``/status`` ``pool.max_size``,
    per process). They are recorded SEPARATELY on purpose: asserting the pool size from the harness's own env
    is exactly the kind of unverified assumption this whole exercise exists to kill, so the run also MEASURES
    it, and a divergence is a finding rather than a silent 8-vs-40.

    All sentinels mean "not measured", never "zero": ``requested`` -1, the ``max_size``/``idle`` fields None,
    and ``shards_reporting`` 0 (which is also the honest reading on SQLite, where there IS no pool)."""

    requested: int = (
        -1
    )  # MEFOR_STORE_POOL_SIZE the harness set on each shard process (-1 = unrecorded)
    max_size: int | None = None  # the engine's OWN configured maximum, per process
    size: int | None = None  # connections currently open
    idle_min: int | None = None  # MIN free connections across shards (0 ⇒ a shard's pool is dry)
    shards_reporting: int = (
        0  # shards that reported a pool (0 ⇒ no pool: SQLite, or /status too old)
    )
    acquire_wait_count: int = 0  # Σ acquires (NOT Σ waits — record() fires on every acquire)
    acquire_wait_mean_ms: float = 0.0  # diluted by zero-wait acquires — SECONDARY evidence only
    acquire_wait_p95_ms: float | None = None  # PRIMARY: max across shards
    acquire_wait_p99_ms: float | None = None
    acquire_wait_max_ms: float | None = None

    @property
    def measured(self) -> bool:
        """A pool was actually observed (some shard reported one). ``False`` ⇒ the tripwire ABSTAINS — it
        never reads "no data" as "no queueing" (the dead-gate failure mode this whole PR is about)."""
        return self.shards_reporting > 0

    @property
    def tripped(self) -> bool:
        """THE PRE-REGISTERED TRIPWIRE: the pool is the constraint. p95 is primary, p99 catches the 1–5%
        bind that dilutes p95 to ~0, and the mean is the weakest (most diluted) bar. Never fires on absent
        data — an unmeasured pool is UNKNOWN, not innocent."""
        if not self.measured:
            return False
        p95 = self.acquire_wait_p95_ms
        p99 = self.acquire_wait_p99_ms
        return (
            (p95 is not None and p95 >= _POOL_TRIP_P95_MS)
            or (p99 is not None and p99 >= _POOL_TRIP_P99_MS)
            or (self.acquire_wait_mean_ms >= _POOL_TRIP_MEAN_MS)
        )

    @property
    def trip_reason(self) -> str | None:
        """WHY it tripped, in the operator's own units, or ``None``. Also reports the un-tripped
        ``idle_min == 0`` observation as advisory — it is read at the DRAIN sample (after the offer stopped),
        where an idle pool is expected, so it is NOT a gate; a mid-hold sampler would be needed for that."""
        if not self.measured:
            return None
        p95 = self.acquire_wait_p95_ms
        p99 = self.acquire_wait_p99_ms
        if p95 is not None and p95 >= _POOL_TRIP_P95_MS:
            return (
                f"pool acquire_wait p95={p95:.3f}ms >= {_POOL_TRIP_P95_MS}ms — one acquire in twenty "
                f"QUEUED for a store connection (baseline {POOL_ACQUIRE_WAIT_BASELINE_MS}ms). THE POOL IS "
                f"THE CONSTRAINT: raise --store-pool-size before attributing this rung to the claim query"
            )
        if p99 is not None and p99 >= _POOL_TRIP_P99_MS:
            return (
                f"pool acquire_wait p99={p99:.3f}ms >= {_POOL_TRIP_P99_MS}ms (p95 is BELOW its bar) — the "
                "pool is dry for a MINORITY of acquires (1-5%), which is exactly the bind that dilutes p95 "
                "and the mean toward zero because record() fires on EVERY acquire, not only on the ones "
                "that waited. THE POOL IS THE CONSTRAINT: raise --store-pool-size before attributing this "
                "rung to the claim query"
            )
        if self.acquire_wait_mean_ms >= _POOL_TRIP_MEAN_MS:
            return (
                f"pool acquire_wait mean={self.acquire_wait_mean_ms:.3f}ms >= {_POOL_TRIP_MEAN_MS}ms "
                f"(~{self.acquire_wait_mean_ms / POOL_ACQUIRE_WAIT_BASELINE_MS:.0f}x the "
                f"{POOL_ACQUIRE_WAIT_BASELINE_MS}ms baseline) — and the mean is DILUTED by zero-wait "
                "acquires, so the true queueing is worse. THE POOL IS THE CONSTRAINT"
            )
        return None

    @property
    def requested_matches_engine(self) -> bool | None:
        """Whether the engine CONFIRMED the pool size the harness requested. ``None`` when either side is
        unrecorded (can't compare). ``False`` is a real finding: the env did not reach the process."""
        if self.requested < 0 or self.max_size is None:
            return None
        return self.requested == self.max_size

    @classmethod
    def from_sample(cls, sample: Any | None, *, requested: int = -1) -> PoolStats:
        """Fold a poller sample (the fleet aggregate at drain) into the rung's pool record. ``None`` sample
        ⇒ everything stays at the not-measured sentinels.

        ``getattr``-with-default throughout, and typed ``Any`` rather than ``EngineSample``, for the same
        reason :meth:`EnginePoller._sample_shard` reads the engine's ``/stats`` that way: the caller may hand
        us a partial/older sample object, and a pool record that RAISES rather than reading "not measured" is
        a measurement instrument that takes the whole bench down with it."""
        if sample is None:
            return cls(requested=requested)
        return cls(
            requested=requested,
            max_size=getattr(sample, "pool_max_size", None),
            size=getattr(sample, "pool_size", None),
            idle_min=getattr(sample, "pool_idle_min", None),
            shards_reporting=int(getattr(sample, "pool_shards_reporting", 0) or 0),
            acquire_wait_count=int(getattr(sample, "pool_acquire_wait_count", 0) or 0),
            acquire_wait_mean_ms=float(getattr(sample, "pool_acquire_wait_mean_ms", 0.0) or 0.0),
            acquire_wait_p95_ms=getattr(sample, "pool_wait_p95_max_ms", None),
            acquire_wait_p99_ms=getattr(sample, "pool_wait_p99_max_ms", None),
            # The ACROSS-SHARD max (`pool_wait_max_max_ms`), not the legacy first-shard `pool_wait_max_ms`:
            # this is the only consumer that wants "the worst acquire ANY shard saw", and reading the legacy
            # field would mask a bind on a non-first shard exactly as the p95/p99 fields used to.
            acquire_wait_max_ms=getattr(sample, "pool_wait_max_max_ms", None),
        )

    def to_json_dict(self) -> dict[str, object]:
        return {
            "requested_pool_size": self.requested,
            "engine_max_size": self.max_size,
            "requested_matches_engine": self.requested_matches_engine,
            "size": self.size,
            "idle_min": self.idle_min,
            "shards_reporting": self.shards_reporting,
            "measured": self.measured,
            # count = Σ ACQUIRES (record() fires on every acquire), so mean_ms is diluted by zero-wait
            # acquires. Emitted with that caveat in the key comment because a reader WILL otherwise treat a
            # small mean as proof of no queueing — the exact fake instrument the tripwire is built around.
            "acquire_wait": {
                "count": self.acquire_wait_count,
                "mean_ms": round(self.acquire_wait_mean_ms, 4),
                "p95_ms": self.acquire_wait_p95_ms,
                "p99_ms": self.acquire_wait_p99_ms,
                "max_ms": self.acquire_wait_max_ms,
                "baseline_mean_ms": POOL_ACQUIRE_WAIT_BASELINE_MS,
                # EXPLICITLY null: no p95 was recorded at the known-unbound reference point, so the p95 BAR
                # below is NOT a multiple of a measurement on this rig (it is the STEP-4 doc's bar). Emitted
                # so a reader does not assume it shares `baseline_mean_ms`'s anchor.
                "baseline_p95_ms": None,
            },
            "tripwire": {
                "p95_ms_bar": _POOL_TRIP_P95_MS,
                "p95_bar_anchored_to_baseline": False,  # see baseline_p95_ms
                "p99_ms_bar": _POOL_TRIP_P99_MS,
                "mean_ms_bar": _POOL_TRIP_MEAN_MS,
                "tripped": self.tripped,
                "reason": self.trip_reason,
            },
        }

    @classmethod
    def from_json_dict(cls, d: Mapping[str, Any]) -> PoolStats:
        wait = d.get("acquire_wait") or {}
        wait_map: Mapping[str, Any] = wait if isinstance(wait, Mapping) else {}

        def _opt_f(key: str) -> float | None:
            v = wait_map.get(key)
            return None if v is None else float(v)

        raw_max = d.get("engine_max_size")
        raw_size = d.get("size")
        raw_idle = d.get("idle_min")
        return cls(
            requested=int(d.get("requested_pool_size", -1)),
            max_size=None if raw_max is None else int(raw_max),
            size=None if raw_size is None else int(raw_size),
            idle_min=None if raw_idle is None else int(raw_idle),
            shards_reporting=int(d.get("shards_reporting", 0)),
            acquire_wait_count=int(wait_map.get("count", 0)),
            acquire_wait_mean_ms=float(wait_map.get("mean_ms", 0.0)),
            acquire_wait_p95_ms=_opt_f("p95_ms"),
            acquire_wait_p99_ms=_opt_f("p99_ms"),
            acquire_wait_max_ms=_opt_f("max_ms"),
        )

    def render(self) -> str:
        if not self.measured:
            return (
                f"store pool: (not measured — no shard reported a pool; requested={self.requested})"
            )
        p95 = "n/a" if self.acquire_wait_p95_ms is None else f"{self.acquire_wait_p95_ms:.3f}ms"
        p99 = "n/a" if self.acquire_wait_p99_ms is None else f"{self.acquire_wait_p99_ms:.3f}ms"
        mismatch = "" if self.requested_matches_engine is not False else "  <= REQUESTED != ENGINE"
        return (
            f"store pool: requested={self.requested} engine_max={self.max_size} "
            f"open={self.size} idle_min={self.idle_min} shards={self.shards_reporting} | "
            f"acquire_wait n={self.acquire_wait_count} mean={self.acquire_wait_mean_ms:.4f}ms "
            f"p95={p95} p99={p99}"
            + mismatch
            + ("  <= POOL BIND (tripwire)" if self.tripped else "")
        )


#: A :class:`PoolStats` with nothing measured — the default when a rung's engine report carried no pool
#: block (an older engine half, a lost ENGINE_RUNG_REPORT, or a SQLite store, which has no pool at all).
EMPTY_POOL_STATS = PoolStats()


def _min_not_none(values: Iterable[int | None]) -> int | None:
    """The MIN over the non-``None`` values (``None`` if all are ``None``). Used for pool IDLE: taking the
    FIRST shard's reading (as the legacy fields do) masks a bind on any other shard."""
    seen = [v for v in values if v is not None]
    return min(seen) if seen else None


def _max_not_none(values: Iterable[float | None]) -> float | None:
    """The MAX over the non-``None`` values (``None`` if all are ``None``). Used for the pool WAIT
    percentiles: the fleet is bound if ANY shard's pool is bound, so the worst shard is the reading."""
    seen = [v for v in values if v is not None]
    return max(seen) if seen else None


async def sample_until_reconciled(
    poller: EnginePoller, counters: Counters, *, timeout: float, interval: float
) -> EngineSample | None:
    """Re-sample the engine until the no-loss reconcile condition SETTLES — every CONFIRMED send has
    been read (``read >= sent - timeouts``) and every delivery has reached the sink
    (``sink_received >= written``) — or ``timeout`` elapses. The durable fix for the intake/delivery
    count-lag a noisy runner shows even after a clean drain: assert the actual settled condition, not
    a single fixed-instant sample (mf-ci-test-flakes). The baseline-relative deltas are used,
    mirroring the reconcile. On timeout the last sample is returned and the no-loss check reports the
    residual shortfall honestly (no masking).

    ``sent - timeouts`` because a ``timeouts``-counted message (in-flight at a connection close with
    no ACK seen — a mid-run reset or the stop-grace expiring) is UNCONFIRMED: ``sent`` was counted at
    write-buffer time, so the frame may never have left the closed socket. Waiting for ``read`` to
    reach the full ``sent`` would poll the entire timeout for a message that may never arrive; the
    reconcile applies the same accounting, so the settled condition must match it. With
    ``timeouts == 0`` (every healthy run) this is exactly ``read >= sent``. (This is only the
    STOP-SAMPLING heuristic — the reconcile itself additionally caps how many unconfirmed sends are
    excusable, so a timeout flood still fails the run regardless of when sampling stopped.)"""
    loop = asyncio.get_running_loop()
    base = poller.baseline
    start = loop.time()
    last = poller.final
    while loop.time() - start < timeout:
        sample = await poller.sample_once()
        if sample is not None:
            last = sample
            if base is not None:
                read = sample.read - base.read
                written = sample.written - base.written
                # Settled: every confirmed send fully read AND every counted delivery arrived at the
                # sink AND the pipeline is empty (no in-flight rows that could still move the counts).
                if (
                    read >= counters.sent - counters.timeouts
                    and counters.sink_received >= written
                    and sample.in_pipeline == 0
                ):
                    return sample
        await asyncio.sleep(interval)
    return last


class EnginePoller:
    """Samples one or more engine APIs off the event loop, aggregates them, and detects post-load
    drain across the whole cluster."""

    def __init__(
        self,
        engine_urls: str | Sequence[str],
        token: str | None,
        *,
        origin: float,
        allow_insecure: bool = False,
    ) -> None:
        # Accept a single URL (back-compat) or a list. The first URL is the "primary" whose `client`
        # is exposed for one-off preflight reads (served-ports check). `allow_insecure` (default False)
        # is REQUIRED to poll a REMOTE engine over plaintext http (a co-located loopback engine is
        # always allowed) — the two-box shardcert drives poll the engine box's http API off-box, so
        # they thread it True; without it EngineClient fail-closes on the non-loopback http URL.
        urls = [engine_urls] if isinstance(engine_urls, str) else list(engine_urls)
        if not urls:
            raise ValueError("EnginePoller needs at least one engine URL")
        # De-dup, order-preserving (primary first): passing the primary --engine ALSO as a
        # --shard-engine would otherwise double-count that shard's read/written/backlog and mask real
        # loss. Distinct shard APIs are unaffected; the single-URL default stays exactly one client.
        seen: set[str] = set()
        deduped: list[str] = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        self._urls = deduped
        self._token = token
        self._origin = origin
        self._allow_insecure = allow_insecure
        self._clients: list[EngineClient] = []
        self._samples: list[EngineSample] = []

    @property
    def client(self) -> EngineClient | None:
        """The PRIMARY shard's client (set after :meth:`open`) — for one-off preflight reads."""
        return self._clients[0] if self._clients else None

    @property
    def samples(self) -> list[EngineSample]:
        return self._samples

    @property
    def baseline(self) -> EngineSample | None:
        return self._samples[0] if self._samples else None

    @property
    def final(self) -> EngineSample | None:
        return self._samples[-1] if self._samples else None

    async def open(self) -> None:
        await asyncio.get_running_loop().run_in_executor(None, self._open_sync)

    async def close(self) -> None:
        loop = asyncio.get_running_loop()
        clients, self._clients = self._clients, []
        for client in clients:
            await loop.run_in_executor(None, client.close)

    async def sample_once(self) -> EngineSample | None:
        sample = await asyncio.get_running_loop().run_in_executor(None, self._sample_sync)
        if sample is not None:
            self._samples.append(sample)
        return sample

    async def run(self, interval: float, stop: asyncio.Event) -> None:
        """Sample every ``interval`` seconds until ``stop`` is set."""
        await self.sample_once()
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except TimeoutError:
                await self.sample_once()

    async def await_drain(self, *, timeout: float, interval: float) -> float | None:
        """Poll until the **whole cluster's** pipeline is empty and inbound/delivery counters stop
        moving. Returns seconds-to-drain, or ``None`` on timeout.

        Drain requires the *aggregate* ``in_pipeline == 0`` (no NOT-DONE rows in ANY stage of ANY
        shard — ingress, routed, or outbound), the summed outbound backlog + per-edge ``queue_depth``
        at zero, and ``read``/``written`` unchanged across a poll. Because the cluster sample sums
        every shard, this only completes once **every** shard reports ``in_pipeline == 0`` and an
        empty backlog. The ``in_pipeline`` gauge (from ``/stats``) closes the prior blind spot: a
        fully **stalled** router/transform leaves the outbound backlog at 0 but ``in_pipeline > 0``,
        so it no longer reads as drained."""
        loop = asyncio.get_running_loop()
        start = loop.time()
        prev = self.final or await self.sample_once()
        while loop.time() - start < timeout:
            try:
                await asyncio.wait_for(asyncio.sleep(interval), timeout=interval + 1.0)
            except TimeoutError:  # pragma: no cover - defensive
                pass
            cur = await self.sample_once()
            if cur is None:
                continue
            stable = prev is not None and cur.read == prev.read and cur.written == prev.written
            if cur.backlog == 0 and cur.queue_depth == 0 and cur.in_pipeline == 0 and stable:
                return loop.time() - start
            prev = cur
        return None

    # --- sync helpers (run in the executor) ----------------------------------

    def _open_sync(self) -> None:
        clients: list[EngineClient] = []
        for url in self._urls:
            client = EngineClient(url, allow_insecure=self._allow_insecure)
            if self._token:
                client.set_token(self._token)  # does a /me request to validate
            clients.append(client)
        self._clients = clients

    def _sample_sync(self) -> EngineSample | None:
        """Sample every shard and SUM into one cluster observation.

        Reachability mirrors the single-shard semantics: a shard that is transiently unreachable makes
        the whole sample unavailable (return ``None`` → skip this tick, keep polling), rather than
        silently reporting a too-low aggregate that would poison the baseline/final no-loss math."""
        if not self._clients:
            return None
        shard_samples: list[_ShardSample] = []
        for client in self._clients:
            shard = self._sample_shard(client)
            if shard is None:
                return None  # one shard unreachable → skip the aggregate (keep polling)
            shard_samples.append(shard)
        # Journal mode + synchronous are reported per shard; they share a backend in practice, so take
        # the first (informational only — neither feeds the no-loss check).
        return EngineSample(
            elapsed_s=time.perf_counter() - self._origin,
            pending=sum(s.pending for s in shard_samples),
            inflight=sum(s.inflight for s in shard_samples),
            done=sum(s.done for s in shard_samples),
            dead=sum(s.dead for s in shard_samples),
            read=sum(s.read for s in shard_samples),
            written=sum(s.written for s in shard_samples),
            out_dead=sum(s.out_dead for s in shard_samples),
            queue_depth=sum(s.queue_depth for s in shard_samples),
            in_pipeline=sum(s.in_pipeline for s in shard_samples),
            db_size_bytes=sum(s.db_size_bytes for s in shard_samples),
            journal_mode=shard_samples[0].journal_mode,
            synchronous=shard_samples[0].synchronous,
            uptime_s=max(s.uptime_s for s in shard_samples),
            # B11: empty-claim counts SUM across shards (each shard runs its own workers). Executor
            # gauges + the pool snapshot are per-process; take the MAX queue depth/busy and the first
            # shard reporting a pool (in practice the connscale harness runs a single engine, so this
            # is exactly that one engine's reading).
            empty_claims=sum(s.empty_claims for s in shard_samples),
            empty_claims_idle_poll=sum(s.empty_claims_idle_poll for s in shard_samples),
            empty_claims_wake_fanout=sum(s.empty_claims_wake_fanout for s in shard_samples),
            committed_txns=sum(s.committed_txns for s in shard_samples),  # A1
            body_copies=sum(s.body_copies for s in shard_samples),  # A1
            # Pool acquire-wait: the COUNT sums across shards, but the MEAN must be N-WEIGHTED —
            # a plain mean-of-means would let an idle shard with 3 waits outvote a busy one with 3,000.
            pool_acquire_wait_count=sum(s.pool_acquire_wait_count for s in shard_samples),
            pool_acquire_wait_mean_ms=(
                sum(s.pool_acquire_wait_mean_ms * s.pool_acquire_wait_count for s in shard_samples)
                / _wait_n
                if (_wait_n := sum(s.pool_acquire_wait_count for s in shard_samples))
                else 0.0
            ),
            executor_queue_depth=_first_not_none(s.executor_queue_depth for s in shard_samples),
            executor_busy=_first_not_none(s.executor_busy for s in shard_samples),
            pool_size=_first_not_none(s.pool_size for s in shard_samples),
            pool_idle=_first_not_none(s.pool_idle for s in shard_samples),
            pool_wait_p50_ms=_first_not_none(s.pool_wait_p50_ms for s in shard_samples),
            pool_wait_p95_ms=_first_not_none(s.pool_wait_p95_ms for s in shard_samples),
            pool_wait_p99_ms=_first_not_none(s.pool_wait_p99_ms for s in shard_samples),
            pool_wait_max_ms=_first_not_none(s.pool_wait_max_ms for s in shard_samples),
            # ARTIFACT 2: the shard-aware pool aggregates. The `_first_not_none` fields above are kept
            # byte-identical — `pool_wait_max_ms` is read by `connscale/runner.py` and emitted as
            # `pool_wait.max_ms` in connscale's OWN report (SCHEMA_VERSION 1), so flipping its aggregation
            # here would silently move a banked key in another bench with no schema bump. It MASKS a
            # per-shard bind, so the honest across-shard reads are ADDED beside it (the same pattern as the
            # p95/p99 pair) and `PoolStats.from_sample` reads those. `pool_max_size` is a per-process CONFIG
            # value (identical across shards by construction), so first-wins is right for it.
            pool_max_size=_first_not_none(s.pool_max_size for s in shard_samples),
            pool_idle_min=_min_not_none(s.pool_idle for s in shard_samples),
            pool_wait_p95_max_ms=_max_not_none(s.pool_wait_p95_ms for s in shard_samples),
            pool_wait_p99_max_ms=_max_not_none(s.pool_wait_p99_ms for s in shard_samples),
            pool_wait_max_max_ms=_max_not_none(s.pool_wait_max_ms for s in shard_samples),
            pool_shards_reporting=sum(1 for s in shard_samples if s.pool_size is not None),
        )

    @staticmethod
    def _sample_shard(client: EngineClient) -> _ShardSample | None:
        try:
            stats = client.stats()
            conns = client.connections()
            status = client.status()
        except ApiError:
            return None  # transient unreachability — caller skips the whole sample
        ob = stats.outbox_by_status
        # `read` is populated only on inbound rows, `written` only on outbound rows — so summing the
        # non-None values partitions inbound vs outbound without guessing role/direction strings.
        read = sum(r.read for r in conns if r.read is not None)
        written = sum(r.written for r in conns if r.written is not None)
        out_dead = sum(r.errored or 0 for r in conns if r.written is not None)
        queue_depth = sum(r.queue_depth or 0 for r in conns if r.queue_depth is not None)
        return _ShardSample(
            pending=ob.get("pending", 0),
            inflight=ob.get("inflight", 0),
            done=ob.get("done", 0),
            dead=ob.get("dead", 0),
            read=read,
            written=written,
            out_dead=out_dead,
            queue_depth=queue_depth,
            in_pipeline=stats.in_pipeline,
            db_size_bytes=status.db.size_bytes,
            uptime_s=status.engine.uptime_seconds,
            journal_mode=status.db.journal_mode,
            synchronous=status.db.synchronous,
            # B11 read-only instrumentation. getattr-with-default so an OLDER engine (whose
            # StatsResponse/SystemStatus lack these fields) reads as zeros/None — the established
            # back-compat pattern (mirrors in_pipeline/synchronous). `pool` is the server-only field
            # (None on SQLite); its acquire_wait sub-object carries the PRIMARY pool-wait percentiles.
            empty_claims=getattr(stats, "empty_claims", 0) or 0,
            empty_claims_idle_poll=getattr(stats, "empty_claims_idle_poll", 0) or 0,
            empty_claims_wake_fanout=getattr(stats, "empty_claims_wake_fanout", 0) or 0,
            committed_txns=getattr(stats, "committed_txns", 0)
            or 0,  # A1 (getattr → older-engine safe)
            body_copies=getattr(stats, "body_copies", 0) or 0,  # A1 (getattr → older-engine safe)
            executor_queue_depth=getattr(stats, "executor_queue_depth", None),
            executor_busy=getattr(stats, "executor_busy", None),
            pool_size=_pool_attr(status, "size"),
            pool_idle=_pool_attr(status, "idle"),
            # The engine's OWN configured maximum. Read so the run can CHECK the pool size it asked for,
            # rather than asserting it from the env it set (ARTIFACT 2).
            pool_max_size=_pool_attr(status, "max_size"),
            pool_wait_p50_ms=_pool_wait_attr(status, "p50_ms"),
            pool_wait_p95_ms=_pool_wait_attr(status, "p95_ms"),
            pool_wait_p99_ms=_pool_wait_attr(status, "p99_ms"),
            pool_wait_max_ms=_pool_wait_attr(status, "max_ms"),
            # The two PoolWaitInfo fields the poller never read (2026-07-13) — see the field comments.
            pool_acquire_wait_count=int(_pool_wait_attr(status, "count") or 0),
            pool_acquire_wait_mean_ms=float(_pool_wait_attr(status, "mean_ms") or 0.0),
        )
