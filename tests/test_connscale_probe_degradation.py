# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A wall #4 gap must carry its CAUSE, and the smoke must assert only what that cause entitles it to.

Before this module the connscale FD probe had SEVEN paths that produced a reading-less
:class:`ProcSample`, and all seven produced the SAME one — every field ``None``, nothing naming the
mechanism. Measured before the fix by driving the real ``FdSampler`` down four of them: four distinct
causes, ONE distinct ``repr``. The consequences were both real:

* A CI red carrying ``fd_count_peak=None`` was mis-attributed to unrelated work three times over,
  because the artifact did not contain the information needed to attribute it.
* ``tests/test_connscale_smoke.py`` asserted ``fd_count_peak is not None`` with no tolerance, so a
  process-table walk that timed out on a starved runner reddened a REQUIRED context as though the
  ENGINE were at fault — indistinguishably from an enumerator that ran and returned zero rows.

The two halves are covered here together because they are one contract: the probe records which path
degraded it, and the test reads that cause to pick a verdict. Neither half is worth anything alone —
a cause nobody reads changes no outcome, and a verdict with no cause to read is the tolerance-only
"fix" that buys a green by discarding the evidence.

**The verdict split is the probe's own** (``ProbeDegraded.is_budget_exhausted``) and it is the same
line ``tests/test_connscale_cpu_probe.py`` already draws from the seconds a failed walk spent
(``_BUDGET_CONSUMED_FRACTION``): a shell-out that spent its whole budget measures the RUNNER
(could-not-measure), anything faster means the probe ran and produced nothing (measured-and-broken).
One vocabulary, stated once, read in both places.
"""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
from typing import Any

import pytest

from harness.load.connscale import probe as probe_module
from harness.load.connscale.probe import FdSampler, ProbeDegraded, ProcSample, _gap
from harness.load.connscale.report import ConnScaleRecord, ConnScaleReport, NoLoss, SloCheck
from harness.load.connscale.runner import _PROC_BY_SAMPLE, _drain_proc
from harness.load.enginepoll import EngineSample

# The smoke test owns the verdict helper, beside the assertion it serves and the prose explaining it.
# Imported here rather than re-stated, so this file cannot encode a second, quietly different rule
# about which gaps are tolerable -- that duplication is the failure being fixed, in miniature.
from tests.test_connscale_smoke import _assert_fd_probe, _is_budget_exhausted

#: An implausible PID: nothing can be read for it on any platform, so the POSIX read path is exercised
#: without depending on a live process.
_DEAD_PID = 2**31 - 1

#: The two causes that mean the probe SPENT its timeout budget rather than failing fast.
_BUDGET_EXHAUSTED = (ProbeDegraded.WALK_TIMEOUT, ProbeDegraded.READ_TIMEOUT)


class _FakeSubprocess:
    """Stand-in for the ``subprocess`` module INSIDE ``probe.py`` only.

    Injected by replacing ``probe.subprocess``, not by patching ``subprocess.run`` globally: the probe
    is the only caller under test, and a global patch would also intercept anything pytest or the
    runtime shells out during the test."""

    TimeoutExpired = subprocess.TimeoutExpired
    SubprocessError = subprocess.SubprocessError

    def __init__(self, behaviour: Any) -> None:
        self._behaviour = behaviour

    def run(self, cmd: Any, **kwargs: Any) -> Any:
        return self._behaviour(cmd, **kwargs)


class _Completed:
    """The two attributes ``probe.py`` reads off a completed shell-out."""

    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode


def _spent_its_budget(cmd: Any, **kwargs: Any) -> Any:
    raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 5.0))


def _failed_fast(cmd: Any, **kwargs: Any) -> Any:
    raise OSError("the tool is not on PATH")


def _returned_nothing(cmd: Any, **kwargs: Any) -> Any:
    return _Completed(stdout="")


def _with_subprocess(monkeypatch: pytest.MonkeyPatch, behaviour: Any) -> None:
    monkeypatch.setattr(probe_module, "subprocess", _FakeSubprocess(behaviour))


# --- the vocabulary itself -------------------------------------------------------------------------


def test_every_cause_is_classified_and_only_a_spent_budget_is_tolerable() -> None:
    # The split decides FAIL vs TOLERATE, so pin the whole membership rather than spot-checking two
    # members: a cause added later without being classified must show up here, not as a silent
    # tolerance. Classification is fail-closed by construction (`is_budget_exhausted` names the
    # tolerable members explicitly), so an unclassified newcomer reads as broken, which is the safe
    # direction -- it fails loudly instead of arriving pre-excused.
    tolerable = {c for c in ProbeDegraded if c.is_budget_exhausted}
    assert tolerable == set(_BUDGET_EXHAUSTED)
    # Every member is a real classification, and the not-tolerable side is not empty (a split where
    # everything landed on one side would pass a membership check while deciding nothing).
    assert all(isinstance(c.is_budget_exhausted, bool) for c in ProbeDegraded)
    assert set(ProbeDegraded) - tolerable


def test_a_gap_carries_its_cause_and_no_reading() -> None:
    # `_gap` is the ONLY way a degrade site builds a sample, so this invariant is what makes "every
    # field None" and "a cause is recorded" inseparable -- the pair that used to come apart.
    for cause in ProbeDegraded:
        g = _gap(cause)
        assert g == ProcSample(None, None, None, None, cause)
        assert (g.handles, g.cpu_seconds, g.working_set_bytes, g.cpu_pids) == (None,) * 4
        assert g.degraded is cause


# --- the subtree walk records which walk failure fired ----------------------------------------------
#
# These drive the Windows walk/read methods DIRECTLY on any platform. That is not a shortcut around a
# platform guard: `_enumerate_windows` / `_sample_windows` are pure shell-out-and-parse with no
# OS-specific syscall, so with `subprocess` injected they behave identically everywhere -- which means
# the Linux CI legs cover the Windows paths where the observed red actually happened, instead of
# skipping exactly the code under test.


def test_a_walk_that_spends_its_budget_records_walk_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_subprocess(monkeypatch, _spent_its_budget)
    sampler = FdSampler(_DEAD_PID, resolve_every=1)
    assert sampler._enumerate_windows() is None
    assert sampler._resolve_degraded is ProbeDegraded.WALK_TIMEOUT


def test_a_walk_that_errors_fast_records_walk_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # TimeoutExpired subclasses SubprocessError, so a single `except (OSError, SubprocessError)` would
    # collapse this case into the timeout one. The two earn opposite verdicts; keep them apart.
    _with_subprocess(monkeypatch, _failed_fast)
    sampler = FdSampler(_DEAD_PID, resolve_every=1)
    assert sampler._enumerate_windows() is None
    assert sampler._resolve_degraded is ProbeDegraded.WALK_ERROR


def test_a_walk_that_returns_zero_rows_records_walk_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # A live host always has many processes, so a COMPLETED walk with zero usable rows is a silent
    # enumeration failure -- and, per the scope of this work, the case that must still fail.
    _with_subprocess(monkeypatch, _returned_nothing)
    sampler = FdSampler(_DEAD_PID, resolve_every=1)
    assert sampler._enumerate_windows() is None
    assert sampler._resolve_degraded is ProbeDegraded.WALK_EMPTY
    assert not ProbeDegraded.WALK_EMPTY.is_budget_exhausted


def test_a_snapshot_without_the_root_records_walk_no_root(monkeypatch: pytest.MonkeyPatch) -> None:
    # The enumeration SUCCEEDED here; validation is what failed. Reporting it as an enumeration failure
    # would point a reader at the wrong half of the walk.
    sampler = FdSampler(500, resolve_every=1)
    monkeypatch.setattr(sampler, "_enumerate_windows", lambda: [(900, 1, 10_000.0)])
    assert sampler._descendants_windows() is None
    assert sampler._resolve_degraded is ProbeDegraded.WALK_NO_ROOT


def test_a_resolution_that_fails_without_naming_a_cause_is_still_given_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `_resolve_pids` has a defensive fallback for a descendants-resolver that returns None without
    # recording why. The shipped resolvers always record one, so this branch is reachable only through
    # a stand-in -- which is exactly why it needs pinning: nothing else demonstrates that a resolution
    # failure can never reach `sample_proc` as an UNNAMED gap, and an unnamed gap is the defect.
    monkeypatch.setattr(probe_module, "_WINDOWS", True)
    sampler = FdSampler(500, resolve_every=1)
    monkeypatch.setattr(sampler, "_descendants_windows", lambda: None)
    assert sampler.sample_proc().degraded is ProbeDegraded.WALK_ERROR


def test_a_walk_that_succeeds_records_no_cause(monkeypatch: pytest.MonkeyPatch) -> None:
    # THE POSITIVE CONTROL for the four above: the causes are set by failure, not by merely walking.
    # Without this, a `_resolve_degraded` wired to a constant would pass every rejection test here.
    sampler = FdSampler(500, resolve_every=1)
    monkeypatch.setattr(
        sampler, "_enumerate_windows", lambda: [(500, 1, 10_000.0), (600, 500, 10_001.0)]
    )
    assert sampler._descendants_windows() == [600]
    assert sampler._resolve_degraded is None
    assert sampler._resolve_errored is False


# --- the per-PID read records which read failure fired ----------------------------------------------


def test_a_read_that_spends_its_budget_records_read_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_subprocess(monkeypatch, _spent_its_budget)
    got = FdSampler(_DEAD_PID)._sample_windows([_DEAD_PID])
    assert got.degraded is ProbeDegraded.READ_TIMEOUT


def test_a_read_that_errors_fast_records_read_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _with_subprocess(monkeypatch, _failed_fast)
    got = FdSampler(_DEAD_PID)._sample_windows([_DEAD_PID])
    assert got.degraded is ProbeDegraded.READ_ERROR


def test_a_read_that_returns_zero_rows_records_read_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # The site the scope of this work calls out by name: the enumeration RAN and returned rows == 0,
    # which is NOT a timeout. It must be distinguishable from one, and it must not be tolerable.
    _with_subprocess(monkeypatch, _returned_nothing)
    got = FdSampler(_DEAD_PID)._sample_windows([_DEAD_PID])
    assert got.degraded is ProbeDegraded.READ_EMPTY
    assert not ProbeDegraded.READ_EMPTY.is_budget_exhausted


def test_a_read_that_parses_rows_records_no_cause(monkeypatch: pytest.MonkeyPatch) -> None:
    # POSITIVE CONTROL for the read path: a parseable row yields a real reading and NO cause, so the
    # three assertions above are discriminating rather than vacuous.
    _with_subprocess(monkeypatch, lambda cmd, **kw: _Completed(stdout="61 20000000 6500000 4242\n"))
    got = FdSampler(4242)._sample_windows([4242])
    assert got.degraded is None
    assert (got.handles, got.working_set_bytes, got.cpu_pids) == (61, 6_500_000, frozenset({4242}))


def test_a_posix_read_with_nothing_readable_records_read_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The POSIX side degrades when no PID in the subtree yields any field. It reports READ_EMPTY and
    # deliberately does NOT claim a timeout: /proc reads have no budget to exhaust, and inventing a
    # cause we did not observe is the same defect as recording none.
    _with_subprocess(monkeypatch, _failed_fast)  # no /proc and no lsof
    got = FdSampler(_DEAD_PID)._sample_posix([_DEAD_PID])
    assert got.degraded is ProbeDegraded.READ_EMPTY
    assert got.handles is None


# --- the defect itself: four causes that used to be one artifact -------------------------------------


def _sample_proc_under(monkeypatch: pytest.MonkeyPatch, behaviour: Any) -> ProcSample:
    """One full ``sample_proc()`` through the WINDOWS branch, with ``subprocess`` injected.

    ``_WINDOWS`` is forced so the Windows walk+read path runs on every platform. The observed CI red
    was on a Windows leg, and gating this on ``sys.platform`` would skip the reproduction on the very
    legs that are cheapest and most numerous."""
    monkeypatch.setattr(probe_module, "_WINDOWS", True)
    _with_subprocess(monkeypatch, behaviour)
    return FdSampler(_DEAD_PID, resolve_every=1).sample_proc()


def _is_walk(cmd: Any) -> bool:
    return any("Win32_Process" in str(a) for a in cmd)


def test_four_degradation_paths_that_were_indistinguishable_are_now_distinct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE regression test for the measured defect.

    Driven through the real ``sample_proc()`` entry point, exactly as the pre-fix reproduction was:
    four distinct causes then produced one ``ProcSample`` value, so a record could not say which had
    fired. Asserting the four are now distinct FAILS on the pre-fix probe, where every branch returned
    the same ``_EMPTY_PROC``."""
    live = f"61 20000000 6500000 {_DEAD_PID}\n"
    walk_rows = f"{_DEAD_PID} 1 10000000000\n"

    def walk_timeout(cmd: Any, **kw: Any) -> Any:
        return _spent_its_budget(cmd, **kw) if _is_walk(cmd) else _Completed(stdout=live)

    def walk_zero_rows(cmd: Any, **kw: Any) -> Any:
        return _Completed(stdout="") if _is_walk(cmd) else _Completed(stdout=live)

    def read_timeout(cmd: Any, **kw: Any) -> Any:
        return _Completed(stdout=walk_rows) if _is_walk(cmd) else _spent_its_budget(cmd, **kw)

    def read_zero_rows(cmd: Any, **kw: Any) -> Any:
        return _Completed(stdout=walk_rows if _is_walk(cmd) else "")

    got = {
        "walk timed out": _sample_proc_under(monkeypatch, walk_timeout),
        "walk ran, zero rows": _sample_proc_under(monkeypatch, walk_zero_rows),
        "read timed out": _sample_proc_under(monkeypatch, read_timeout),
        "read ran, zero rows": _sample_proc_under(monkeypatch, read_zero_rows),
    }
    assert {k: v.degraded for k, v in got.items()} == {
        "walk timed out": ProbeDegraded.WALK_TIMEOUT,
        "walk ran, zero rows": ProbeDegraded.WALK_EMPTY,
        "read timed out": ProbeDegraded.READ_TIMEOUT,
        "read ran, zero rows": ProbeDegraded.READ_EMPTY,
    }
    # The pre-fix measurement was "4 causes, 1 distinct sample". State the falsifier as that count.
    assert len({repr(v) for v in got.values()}) == 4
    # Every one of them is still a full gap -- naming the cause must not have invented a reading.
    assert all(v.handles is None for v in got.values())
    # And the two halves of the split land on opposite sides, which is what makes it a verdict.
    assert got["walk timed out"].degraded is not None
    assert got["walk timed out"].degraded.is_budget_exhausted
    assert got["read ran, zero rows"].degraded is not None
    assert not got["read ran, zero rows"].degraded.is_budget_exhausted


def test_a_live_sample_records_a_cause_exactly_when_it_reads_nothing() -> None:
    """The invariant on the REAL probe against the REAL OS, with no injection anywhere.

    A null result needs a mechanism: every test above supplies its own failure, so all of them would
    still pass against a probe that could not read anything at all on this host. This one runs the
    unmodified probe against a live process and pins the biconditional -- a cause is recorded exactly
    when nothing was read -- so it reports honestly whichever way this runner behaves."""
    got = FdSampler(os.getpid(), resolve_every=1).sample_proc()
    read_something = any(
        v is not None for v in (got.handles, got.cpu_seconds, got.working_set_bytes)
    )
    assert (got.degraded is None) is read_something, got


# --- the cause reaches the record --------------------------------------------------------------------


def _engine_sample(elapsed: float) -> EngineSample:
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


def _drain(procs: list[ProcSample]) -> Any:
    samples = []
    for i, p in enumerate(procs):
        s = _engine_sample(float(i))
        _PROC_BY_SAMPLE[id(s)] = p
        samples.append(s)
    return _drain_proc(samples)


def _reading(handles: int, pid: int = 1234) -> ProcSample:
    return ProcSample(handles, 1.0, 6_000_000, frozenset({pid}))


def test_a_fully_degraded_window_reports_its_causes_with_their_scope() -> None:
    d = _drain([_gap(ProbeDegraded.WALK_TIMEOUT), _gap(ProbeDegraded.READ_EMPTY)])
    assert d.handles_peak is None  # the gauge is still a gap...
    assert d.probe_degraded == ("read_empty", "walk_timeout")  # ...but it now says why
    # A degraded count is unreadable without its denominator: 2-of-2 and 2-of-200 differ.
    assert (d.probe_degraded_ticks, d.probe_ticks) == (2, 2)


def test_a_partially_degraded_window_keeps_its_gauges_and_still_reports_the_gap() -> None:
    # The common real shape: some ticks read, some do not. `handles_peak` reads from the good ticks, and
    # the degraded ones must not vanish just because the gauge survived -- a peak drawn from 1 of 3
    # ticks is a different quality of evidence from one drawn from 3 of 3, and only these counts say so.
    d = _drain([_reading(61), _gap(ProbeDegraded.WALK_TIMEOUT), _reading(75)])
    assert d.handles_peak == 75
    assert d.probe_degraded == ("walk_timeout",)
    assert (d.probe_degraded_ticks, d.probe_ticks) == (1, 3)


def test_a_clean_window_records_no_causes() -> None:
    # POSITIVE CONTROL for the two above: provenance is recorded from what happened, not stamped on.
    d = _drain([_reading(61), _reading(75)])
    assert d.handles_peak == 75
    assert d.probe_degraded == ()
    assert (d.probe_degraded_ticks, d.probe_ticks) == (0, 2)


def test_the_no_clean_interval_cpu_gap_path_keeps_the_provenance() -> None:
    # `_drain_proc` has THREE exits and two of them are CPU-gap early returns. Each is a separate
    # `return`, so each can independently forget to carry the cause -- which would be this change
    # failing precisely where a gap is being reported. Exit 1: every interval crossed a subtree
    # membership change, so no clean CPU delta survives.
    d = _drain(
        [
            ProcSample(61, 10.0, 6_000_000, frozenset({100}), None),
            ProcSample(61, 30.0, 6_000_000, frozenset({100, 200}), None),
            _gap(ProbeDegraded.READ_ERROR),
        ]
    )
    assert d.cpu_seconds_total is None  # confirms this exit was actually taken, not the tail one
    assert d.probe_degraded == ("read_error",)
    assert (d.probe_degraded_ticks, d.probe_ticks) == (1, 3)


def test_the_flat_counter_cpu_gap_path_keeps_the_provenance() -> None:
    # Exit 2: a flat cumulative CPU counter across a span past the guard (a wrong PID binding). The
    # elapsed values must exceed `_CPU_FLAT_GAP_SPAN_S` or this silently falls through to the tail
    # return and stops testing the branch it names.
    samples = [
        _engine_sample(0.0),
        _engine_sample(10.0),
        _engine_sample(20.0),
    ]
    flat = [
        ProcSample(61, 12.5, 6_000_000, frozenset({1}), None),
        ProcSample(61, 12.5, 6_000_000, frozenset({1}), None),
        _gap(ProbeDegraded.WALK_TIMEOUT),
    ]
    for s, p in zip(samples, flat, strict=True):
        _PROC_BY_SAMPLE[id(s)] = p
    d = _drain_proc(samples)
    assert d.cpu_seconds_total is None  # confirms the flat-counter exit was taken
    assert d.probe_degraded == ("walk_timeout",)
    assert (d.probe_degraded_ticks, d.probe_ticks) == (1, 3)


# --- the record and its artifacts --------------------------------------------------------------------


def _record(
    *,
    count: int = 12,
    fd: int | None = 100,
    ticks: int = 6,
    degraded_ticks: int = 0,
    degraded: tuple[str, ...] = (),
    mode: str = "fixed_aggregate",
) -> ConnScaleRecord:
    return ConnScaleRecord(
        sweep_mode=mode,
        count=count,
        offered_aggregate_rate=24.0,
        sent=100,
        acked=100,
        nak=0,
        deferred=0,
        no_loss=NoLoss(True, 100, 100, 100, 100, 0, "ok"),
        in_pipeline_peak=1,
        drain_seconds=0.5,
        executor_queue_depth_peak=1,
        executor_busy_peak=1,
        pool_wait_p50_ms=None,
        pool_wait_p95_ms=None,
        pool_wait_p99_ms=None,
        pool_wait_max_ms=None,
        pool_idle_min=None,
        pool_size_max=None,
        empty_claims_per_s=1.0,
        idle_poll_per_s=0.5,
        wake_fanout_per_s=0.5,
        empty_claims_per_msg=None,
        fd_count_peak=fd,
        reload_seconds=0.01,
        ack_p50_ms=1.0,
        ack_p95_ms=1.0,
        ack_p99_ms=1.0,
        fd_probe_ticks=ticks,
        fd_probe_degraded_ticks=degraded_ticks,
        fd_probe_degraded=degraded,
    )


def test_the_json_artifact_carries_the_probe_provenance_beside_the_gauge() -> None:
    # The artifact is what a later reader attributes a red from, so the cause has to survive into it --
    # a cause that lives only in memory attributes nothing after the job ends.
    d = _record(fd=None, ticks=6, degraded_ticks=6, degraded=("walk_timeout",)).to_json_dict()
    wall4 = d["wall4_fd"]
    assert isinstance(wall4, dict)
    assert wall4["count_peak"] is None
    assert wall4["probe"] == {"ticks": 6, "degraded_ticks": 6, "degraded": ["walk_timeout"]}
    # It must round-trip as JSON (a tuple would serialize, an enum member would not have).
    assert json.loads(json.dumps(d))["wall4_fd"]["probe"]["degraded"] == ["walk_timeout"]


def test_an_older_artifact_without_the_provenance_still_builds_a_record() -> None:
    # The three fields default, so a record built from an artifact predating them deserializes
    # unchanged -- and reads as "the probe did not run", which is distinct from "it ran and failed".
    # Constructed by OMITTING them rather than by reading their declared defaults, because the property
    # that matters is that such a call still succeeds, not that a default is written down somewhere.
    added = ("fd_probe_ticks", "fd_probe_degraded_ticks", "fd_probe_degraded")
    legacy: dict[str, Any] = {k: v for k, v in vars(_record()).items() if k not in added}
    r = ConnScaleRecord(**legacy)
    assert (r.fd_probe_ticks, r.fd_probe_degraded_ticks, r.fd_probe_degraded) == (0, 0, ())


def test_the_console_names_the_mechanism_beside_the_n_a() -> None:
    # `fd` renders `n/a` on a gap and nobody can act on `n/a`. The console has to say which path failed
    # and over how many ticks, or the operator-facing view reproduces the original defect.
    report = ConnScaleReport(
        profile="t",
        engine_url="http://127.0.0.1:8800",
        db_backend=None,
        shim_installed=True,
        records=[_record(fd=None, ticks=6, degraded_ticks=5, degraded=("read_empty",))],
        slos=[SloCheck("zero_loss", True, True, True)],
        notes=[],
        result_ok=True,
        exit_code=0,
    )
    text = report.render_console()
    assert "read_empty" in text
    assert "5 of 6 tick(s) measured nothing" in text
    # And a clean record adds no noise.
    clean = dataclasses.replace(report, records=[_record()])
    assert "measured nothing" not in clean.render_console()


# --- the smoke test's verdict ------------------------------------------------------------------------


def test_a_measured_record_is_asserted_exactly_as_strictly_as_before() -> None:
    # The pre-existing strength is preserved where the probe worked: a positive count passes, and a
    # non-positive one still fails. The change adds a verdict for gaps; it does not relax readings.
    # TWO measured readings, because the run-level bound requires a comparable PAIR -- see
    # test_one_measured_reading_in_a_group_is_not_a_comparison for why one is not enough.
    _assert_fd_probe([_record(count=12, fd=100, ticks=6), _record(count=24, fd=110, ticks=6)])
    with pytest.raises(AssertionError):
        _assert_fd_probe([_record(count=12, fd=0, ticks=6), _record(count=24, fd=110, ticks=6)])


def test_a_spent_budget_gap_is_tolerated_beside_a_comparable_pair() -> None:
    # The starved-runner case that was reddening a required context. Tolerated -- but only where the
    # SLO that covers wall #4 still had a pair to compare. Renamed from "when another step measured":
    # one other measuring step is NOT the condition, because two readings split so that no group holds
    # two are never compared with each other.
    _assert_fd_probe(
        [
            _record(count=12, fd=None, ticks=6, degraded_ticks=6, degraded=("walk_timeout",)),
            _record(count=24, fd=140, ticks=6),
            _record(count=48, fd=150, ticks=6),
        ]
    )


def test_one_measured_reading_in_a_group_is_not_a_comparison() -> None:
    # THE REGRESSION TEST FOR A DEFECT THAT SHIPPED HERE. The first version of the run-level bound was
    # `any(fd_count_peak is not None)`, which passes on a run where exactly one step measured -- and
    # `_monotonic_slo` SKIPS None readings, so `fd_count_monotonic` then reports ok=True having
    # compared ZERO pairs. Measured on the real smoke at the time: forcing every step after the first
    # to WALK_TIMEOUT gave PAIRS ACTUALLY COMPARED=0 and the SLO still said "monotonic", and a genuine
    # 1000-handle collapse passed the same way. A green that rests on an empty comparison is exactly
    # what this file exists to prevent.
    with pytest.raises(AssertionError, match="WALL #4 NEVER COMPARED") as e:
        _assert_fd_probe(
            [
                _record(count=12, fd=1000, ticks=6),
                _record(count=24, fd=None, ticks=6, degraded_ticks=6, degraded=("walk_timeout",)),
            ]
        )
    # The verdict must show WHY it is not a comparison, not merely that it failed.
    assert "per group" in str(e.value)


def test_a_broken_probe_still_fails_and_the_message_names_the_cause() -> None:
    # The scope of this work is explicit that a probe which enumerated and returned zero rows must
    # STILL FAIL. A tolerance that swallowed this would buy a green by deleting the finding.
    with pytest.raises(AssertionError, match="PROBE DEFECT") as e:
        _assert_fd_probe(
            [
                _record(count=12, fd=None, ticks=6, degraded_ticks=6, degraded=("read_empty",)),
                _record(count=24, fd=140, ticks=6),
            ]
        )
    assert "read_empty" in str(e.value)
    assert "6 of 6 probe tick(s) degraded" in str(e.value)  # the count, with its scope


def test_a_mixed_gap_fails_on_its_broken_cause_even_beside_a_tolerable_one() -> None:
    # One tolerable cause must not launder a broken one sharing the window.
    with pytest.raises(AssertionError, match="PROBE DEFECT"):
        _assert_fd_probe(
            [
                _record(
                    fd=None, ticks=6, degraded_ticks=6, degraded=("read_empty", "walk_timeout")
                ),
                _record(count=24, fd=140, ticks=6),
            ]
        )


def test_an_unattributed_gap_fails_rather_than_being_tolerated() -> None:
    # A gap naming no cause is precisely the pre-fix artifact. It is not evidence in either direction,
    # so it must not land on the tolerated side -- otherwise the fix would have made the ORIGINAL
    # ambiguous artifact the one thing that always passes.
    with pytest.raises(AssertionError, match="UNATTRIBUTED GAP"):
        _assert_fd_probe([_record(fd=None, ticks=6, degraded_ticks=6, degraded=())])


def test_an_unrecognised_cause_is_treated_as_broken_not_tolerable() -> None:
    # Fail closed on a cause this test does not know: a future degrade path must be classified
    # deliberately rather than arriving pre-excused by a permissive default.
    assert _is_budget_exhausted("walk_timeout") is True
    assert _is_budget_exhausted("something_new") is False
    with pytest.raises(AssertionError, match="PROBE DEFECT"):
        _assert_fd_probe(
            [
                _record(fd=None, ticks=6, degraded_ticks=6, degraded=("something_new",)),
                _record(count=24, fd=140, ticks=6),
            ]
        )


def test_a_run_that_never_measured_wall_four_fails_despite_every_cause_being_tolerable() -> None:
    # The bound on the tolerance, and the reason this is not "a tolerance alone". Each step in
    # isolation is excusable; a whole run that measured wall #4 zero times proves nothing about wall
    # #4, so it fails rather than passing on the strength of four excuses.
    with pytest.raises(AssertionError, match="WALL #4 NEVER COMPARED") as e:
        _assert_fd_probe(
            [
                _record(count=12, fd=None, ticks=6, degraded_ticks=6, degraded=("walk_timeout",)),
                _record(count=24, fd=None, ticks=6, degraded_ticks=6, degraded=("read_timeout",)),
            ]
        )
    # The verdict has to carry the evidence forward, or it repeats the message-nobody-can-act-on defect.
    assert "walk_timeout" in str(e.value) and "read_timeout" in str(e.value)
