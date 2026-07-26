# Copyright (c) MessageFoundry contributors.
# SPDX-License-Identifier: Apache-2.0
"""A3 — value-level coverage for the per-PID CPU collector.

Before this module the CPU path had **no value-level test at all**: ``test_connscale_smoke`` asserted
``fd_count_peak`` only, and ``test_fd_sampler_reads_self`` exercised ``.sample()`` (handles), never
``.sample_proc().cpu_seconds``. A collector that returned a constant ``0.00`` for CPU passed CI — which is
exactly what the SQL-Server rig observed, and exactly this harness's signature defect: a plausible number
where there is no measurement.

Two properties are asserted here:

1. **A flat cumulative CPU counter over a non-trivial span degrades to a GAP (``None``), never ``0.00``.**
   The counter's unit is 100 ns; a process we could read handles for consumed *some* CPU. A flat counter
   means the sampler is bound to the wrong process (an idle launcher/supervisor, or a subtree cached
   before the shard workers spawned), so it must report "unknown", not "idle".
2. **A process that genuinely burns CPU is measured as burning CPU.** The positive control.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from harness.load.connscale.probe import FdSampler, ProcSample
from harness.load.connscale.runner import _PROC_BY_SAMPLE, _drain_proc
from harness.load.enginepoll import EngineSample


def _sample(elapsed: float) -> EngineSample:
    return EngineSample(
        elapsed_s=elapsed,
        pending=0,
        inflight=0,
        done=0,
        dead=0,
        read=0,
        written=0,
        out_dead=0,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=elapsed,
    )


# A stable single-PID subtree — the common case, where every interval is a clean same-set delta.
_STABLE_PIDS = frozenset({1234})


def _derive(pairs: list[tuple[float, float | None]]) -> object:
    """Drive ``_drain_proc`` over (elapsed_s, cumulative_cpu_seconds) readings, holding the summed-over
    PID set constant so every interval is a clean CPU delta (the stable-subtree common case)."""
    return _derive_sets([(e, c, _STABLE_PIDS) for e, c in pairs])


def _derive_sets(
    triples: list[tuple[float, float | None, frozenset[int] | None]],
) -> object:
    """Drive ``_drain_proc`` over (elapsed_s, cumulative_cpu_seconds, cpu_pids) readings, so a test can
    change the summed-over subtree between ticks (#220)."""
    samples = []
    for elapsed, cpu, pids in triples:
        s = _sample(elapsed)
        _PROC_BY_SAMPLE[id(s)] = ProcSample(
            handles=61, cpu_seconds=cpu, working_set_bytes=6_000_000, cpu_pids=pids
        )
        samples.append(s)
    return _drain_proc(samples)


def test_flat_cpu_counter_over_a_long_span_is_a_gap_not_zero() -> None:
    # The rig's "constant 0.00": a readable process whose CPU counter never advances. 30 s is far above
    # the 5 s guard. This must be UNKNOWN, not "0% CPU" — no CPU verdict may be drawn from it.
    d = _derive([(0.0, 12.5), (10.0, 12.5), (20.0, 12.5), (30.0, 12.5)])
    assert d.cpu_seconds_total is None
    assert d.cpu_util_cores_mean is None
    assert d.cpu_util_cores_peak is None
    # The non-CPU gauges still read — the process WAS there, which is precisely why flat CPU is a bug.
    assert d.handles_peak == 61
    assert d.working_set_peak_bytes == 6_000_000


def test_flat_cpu_counter_over_a_short_span_stays_zero() -> None:
    # Under the guard span a genuinely-idle tick may legitimately show no advance; don't over-trigger.
    d = _derive([(0.0, 12.5), (1.0, 12.5)])
    assert d.cpu_seconds_total == 0.0
    assert d.cpu_util_cores_mean == 0.0


def test_advancing_cpu_counter_yields_cores_busy() -> None:
    # 8 CPU-seconds over a 10 s span = 0.8 cores busy; the peak window is 2 s of 1 core = 1.0.
    d = _derive([(0.0, 0.0), (2.0, 2.0), (10.0, 8.0)])
    assert d.cpu_seconds_total == pytest.approx(8.0)
    assert d.cpu_util_cores_mean == pytest.approx(0.8)
    assert d.cpu_util_cores_peak == pytest.approx(1.0)


def test_a_single_reading_cannot_derive_cpu() -> None:
    d = _derive([(0.0, 12.5)])
    assert d.cpu_seconds_total is None  # a delta needs two points


def test_falsifier_a_pid_joining_mid_window_does_not_inflate_cpu_total() -> None:
    # BACKLOG #220 falsifier. The engine subtree = {100}, burning ~1 core. Mid-window a NEW pid 200
    # joins (A3 re-resolution picks up a `serve --shard` worker) carrying its whole-life CPU — the
    # summed counter jumps 12→64. Endpoint-differencing (last − first) over that jump reports 56 CPU-s,
    # ~50 of which is pid 200's PRE-window life; the pre-fix code did exactly that. The piecewise sum
    # over same-set intervals must count only the two clean 2-s/2-CPU intervals ⇒ 4.0, degrading the
    # membership-change interval to a gap. This test FAILS on the pre-fix endpoint-difference code.
    d = _derive_sets(
        [
            (0.0, 10.0, frozenset({100})),
            (2.0, 12.0, frozenset({100})),  # +2 CPU over 2 s (1 core), clean
            (4.0, 64.0, frozenset({100, 200})),  # pid 200 joins: +50 whole-life CPU → GAP
            (6.0, 66.0, frozenset({100, 200})),  # +2 CPU over 2 s (1 core), clean
        ]
    )
    assert d.cpu_seconds_total == pytest.approx(4.0)
    assert d.cpu_seconds_total < 50.0  # the joining PID's pre-window CPU must NOT leak in
    assert d.cpu_util_cores_mean == pytest.approx(1.0)  # 4 CPU-s over 4 s of clean span
    assert d.cpu_util_cores_peak == pytest.approx(1.0)


def test_a_membership_changed_interval_is_degraded_to_a_gap() -> None:
    # Every interval crosses a subtree-set change (a worker joins, then another leaves): no clean
    # interval survives, so the CPU gauges degrade to a GAP rather than a fabricated delta.
    d = _derive_sets(
        [
            (0.0, 10.0, frozenset({100})),
            (2.0, 30.0, frozenset({100, 200})),  # 200 joins → set change → gap
            (4.0, 25.0, frozenset({100})),  # 200 departs → set change (and negative) → gap
        ]
    )
    assert d.cpu_seconds_total is None
    assert d.cpu_util_cores_mean is None
    assert d.cpu_util_cores_peak is None
    # The non-CPU gauges still read — the process set was observed, only its CPU delta is unsound.
    assert d.handles_peak == 61
    assert d.working_set_peak_bytes == 6_000_000


def test_a_departing_pid_does_not_drive_cpu_negative() -> None:
    # A departing PID makes the summed counter DROP; pre-fix `max(0, last−first)` clamped that to 0.0.
    # Post-fix the departure interval is a gap and the surrounding clean intervals still measure CPU.
    d = _derive_sets(
        [
            (0.0, 0.0, frozenset({100, 200})),
            (2.0, 4.0, frozenset({100, 200})),  # +4 CPU over 2 s, clean (2 cores busy)
            (4.0, 1.0, frozenset({100})),  # 200 departs: counter drops → GAP, not −3
            (6.0, 3.0, frozenset({100})),  # +2 CPU over 2 s, clean (1 core busy)
        ]
    )
    assert d.cpu_seconds_total == pytest.approx(6.0)  # 4 + 2, the departure interval excluded
    assert d.cpu_util_cores_peak == pytest.approx(2.0)  # the 2-cores clean interval


def test_flat_counter_with_a_membership_change_still_gaps_not_zero() -> None:
    # Compose the flat-CPU-gap guard with membership degradation: a long flat span where the only
    # non-flat motion is a set-change interval must stay a GAP, never regress into a plausible 0.00.
    d = _derive_sets(
        [
            (0.0, 12.5, frozenset({100})),
            (10.0, 12.5, frozenset({100})),  # flat, clean
            (20.0, 40.0, frozenset({100, 200})),  # set change → gap (not counted)
            (30.0, 40.0, frozenset({100, 200})),  # flat, clean
        ]
    )
    # Clean covered span = 10 + 10 = 20 s, all flat ⇒ 0 CPU over ≥5 s ⇒ gap, not 0.00.
    assert d.cpu_seconds_total is None
    assert d.cpu_util_cores_mean is None


_BURN = "x=0\nfor i in range(300_000_000): x+=i"


@pytest.mark.skipif(sys.platform not in ("win32", "linux"), reason="OS CPU probe path")
def test_sampler_measures_a_descendant_that_actually_burns_cpu() -> None:
    """The positive control the CPU path never had: a burning DESCENDANT is measured as burning.

    This is a real launcher-confound reproduction. On Windows a venv's ``Scripts/python.exe`` is a thin
    redirector that re-execs the base interpreter, so the PID we spawn sits idle at ~0.016 CPU-seconds
    while its GRANDCHILD burns seconds. A sampler bound to the spawned PID alone reports a flat counter —
    which is precisely the constant ``0.00`` seen on the rig. Only a subtree walk sees the work.

    Both readings are taken over a STABLE subtree (the burner already exists when the sampler resolves),
    because differencing a sum across a CHANGING PID set is not a CPU delta.
    """
    child = subprocess.Popen([sys.executable, "-c", _BURN])  # noqa: S603 - fixed argv, no shell
    try:
        time.sleep(
            1.0
        )  # let the redirector's real interpreter appear before the subtree is resolved
        sampler = FdSampler(os.getpid(), resolve_every=1)
        first = sampler.sample_proc()
        if first.cpu_seconds is None:
            pytest.skip("OS CPU probe unavailable on this runner")
        time.sleep(2.0)
        after = sampler.sample_proc()
    finally:
        child.kill()
        child.wait(timeout=10)

    assert after.cpu_seconds is not None
    # The burner consumed ~2 core-seconds in the window. A subtree that stopped at the idle redirector
    # would show only this test process — well under 0.5 s.
    assert after.cpu_seconds - first.cpu_seconds > 0.5


@pytest.mark.skipif(sys.platform not in ("win32", "linux"), reason="OS FD probe path")
def test_subtree_re_resolution_picks_up_a_late_spawned_child() -> None:
    # A3: the subtree used to be resolved exactly ONCE. A sharded engine's `serve --shard` workers appear
    # AFTER the supervisor, so a one-shot walk pins the sampler to an idle parent for the whole run.
    sampler = FdSampler(os.getpid(), resolve_every=1)
    sampler.sample_proc()  # walk 1 — before the child exists
    resolved_before = list(sampler._pids or [])

    child = subprocess.Popen([sys.executable, "-c", _BURN])  # noqa: S603 - fixed argv, no shell
    try:
        time.sleep(1.0)
        sampler.sample_proc()  # walk 2 — must now see the child
        resolved_after = list(sampler._pids or [])
    finally:
        child.kill()
        child.wait(timeout=10)

    assert child.pid not in resolved_before
    assert child.pid in resolved_after


def test_resolve_every_serves_from_cache_between_walks(monkeypatch: pytest.MonkeyPatch) -> None:
    # The cache still amortises the process-table walk: with resolve_every=3, three consecutive calls
    # walk once. (Guards against a fix that re-walks every tick and blows up the probe's cost.)
    sampler = FdSampler(os.getpid(), resolve_every=3)
    walks = {"n": 0}

    def _fake_descendants() -> list[int]:
        walks["n"] += 1
        return []

    monkeypatch.setattr(sampler, "_descendants_windows", _fake_descendants)
    monkeypatch.setattr(sampler, "_descendants_posix", _fake_descendants)

    # resolve_every=3 ⇒ a walk every 3 calls: call 1 walks, calls 2-3 are served from the cache.
    for _ in range(3):
        sampler._resolve_pids()
    assert walks["n"] == 1
    sampler._resolve_pids()  # the 4th call crosses the TTL and re-walks
    assert walks["n"] == 2


def test_a_transient_resolve_error_does_not_blackout_the_rest_of_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A failed re-walk degrades THAT tick only. Without this, one enumeration timeout under load would
    # pin _resolve_errored=True and every later cached tick would emit a gap for the whole run.
    sampler = FdSampler(os.getpid(), resolve_every=3)
    outcomes: list[list[int] | None] = [[], None]

    def _fake_descendants() -> list[int] | None:
        return outcomes.pop(0)

    monkeypatch.setattr(sampler, "_descendants_windows", _fake_descendants)
    monkeypatch.setattr(sampler, "_descendants_posix", _fake_descendants)

    sampler._resolve_pids()  # call 1: walk -> success, caches
    assert sampler._resolve_errored is False
    sampler._resolve_pids()  # call 2: cached
    sampler._resolve_pids()  # call 3: cached
    sampler._resolve_pids()  # call 4: TTL expired -> walk -> ERRORS; this tick degrades
    assert sampler._resolve_errored is True
    sampler._resolve_pids()  # call 5: served from the still-valid cache -> the run recovers
    assert sampler._resolve_errored is False
