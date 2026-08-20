# Copyright (c) MessageFoundry contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A3 — value-level coverage for the per-PID CPU collector, and for the SUBTREE the values cover.

Before this module the CPU path had **no value-level test at all**: ``test_connscale_smoke`` asserted
``fd_count_peak`` only, and ``test_fd_sampler_reads_self`` exercised ``.sample()`` (handles), never
``.sample_proc().cpu_seconds``. A collector that returned a constant ``0.00`` for CPU passed CI — which is
exactly what the SQL-Server rig observed, and exactly this harness's signature defect: a plausible number
where there is no measurement.

Properties asserted here:

1. **A flat cumulative CPU counter over a non-trivial span degrades to a GAP (``None``), never ``0.00``.**
   The counter's unit is 100 ns; a process we could read handles for consumed *some* CPU. A flat counter
   means the sampler is bound to the wrong process (an idle launcher/supervisor, or a subtree cached
   before the shard workers spawned), so it must report "unknown", not "idle".
2. **A process that genuinely burns CPU is measured as burning CPU.** The positive control.
3. **The subtree the gauges are summed over is the engine's** (BACKLOG #1210). A gauge is only as good
   as its covering PID set, and an unvalidated ppid walk adopts a stale-parent subtree wholesale. The
   ``stale_ppid`` group below drives the real probe over a deliberately adopted subtree and asserts the
   reported peak EXCLUDES it, with the adoption itself asserted first as a live positive control.

Note the fixtures derive ``handles``/``working_set_bytes`` FROM each tick's PID set (see
``_HANDLES_PER_PID``) rather than pinning them: pinning is what made property 3 untestable here.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from harness.load.connscale import probe
from harness.load.connscale.probe import (
    _CREATION_SKEW_TOLERANCE_S,
    _PROBE_TIMEOUT_S,
    FdSampler,
    ProcRow,
    ProcSample,
    _posix_stat_ppid_starttime,
    _validated_descendants,
)
from harness.load.connscale.runner import _PROC_BY_SAMPLE, _drain_proc
from harness.load.enginepoll import EngineSample

#: How long to keep re-walking before declaring the subtree re-resolution broken.
#:
#: DERIVED from the probe's own per-walk timeout rather than hardcoded, so raising that timeout cannot
#: silently leave this deadline too short to fit even one attempt. Six walks' worth: enough that a
#: couple of enumerations can time out entirely and the test still reaches a verdict, which is exactly
#: the transient-failure tolerance `_resolve_pids` is written to provide.
_RESOLUTION_DEADLINE_S = max(30.0, 6 * _PROBE_TIMEOUT_S)

#: Per-walk timeout granted during the bounded extension below, in place of the probe's production
#: ``_PROBE_TIMEOUT_S``, for the duration of THIS test only (BACKLOG #1290).
#:
#: The measured cause of the #1290 red is ONE walk failing to complete within 5 s on a starved hosted
#: runner. More 5 s attempts do not attack that: each is cut off at the same point, so six of them buy
#: six identical timeouts and no measurement. A LONGER walk does attack it. The 5 s bound exists to stop
#: a hung shell-out wedging the RUNNER's poll tick; this test is not on that cadence, and no test in this
#: file asserts the bound's value, so raising it here removes no coverage.
_STALLED_WALK_TIMEOUT_S = 3.0 * _PROBE_TIMEOUT_S

#: Hard ceiling on how many long walks the extension may make. BOUNDED on purpose: it is entered only
#: on a runner that has already spent ``_RESOLUTION_DEADLINE_S`` without one usable enumeration, and an
#: unbounded retry there would trade a red required context for a hung job. The healthy path is
#: untouched by any of this — it resolves in one or two walks and costs well under a second.
_STALL_EXTENSION_WALKS = 2

#: Share of this test's own pytest-timeout watchdog that the whole poll may spend before it must reach
#: a verdict. The extension is trimmed to fit, so the walks it is granted DERIVE from the watchdog.
#:
#: This bound is not optional. Being killed by the watchdog fails the test with a thread dump and NO
#: verdict at all — strictly worse than the failure #1290 is fixing, and it would arrive on exactly the
#: stalled runner the extension exists to serve. Reading the watchdog rather than hardcoding it matters
#: because the value is per leg: ci.yml's matrix passes 60 s on ubuntu and 120 s on the Windows legs
#: (`pytest_timeout`), and the Windows legs are the ones where the walk stalls. On a 60 s watchdog the
#: extension trims to ZERO walks and the test degrades to a 30 s poll then a skip, which is the correct
#: answer there; on the 120 s Windows legs both extension walks fit inside 60 s of an 84 s share.
_WATCHDOG_SHARE = 0.7

#: A failed walk counts as BUDGET-EXHAUSTED (the runner was too slow to enumerate) rather than a FAST
#: error (the enumeration itself is broken) when it spent at least this fraction of the timeout it was
#: given. The two get OPPOSITE verdicts -- skip and fail -- so the discriminator is stated once, here.
#: The slack absorbs clock granularity only: ``subprocess.run`` cannot raise ``TimeoutExpired`` before
#: its timeout, so a genuine timeout always lands above this line and an immediate error far below it.
_BUDGET_CONSUMED_FRACTION = 0.9


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

# Per-PID handle / RSS weights, so a fixture tick's handles and working set MOVE WITH the PID set it
# was summed over — as the real probe's do. BACKLOG #1210: the fixture used to pin ``handles=61`` and
# ``working_set_bytes=6_000_000`` on EVERY tick regardless of the ``cpu_pids`` it was varying. On
# Windows both come from the SAME ``Get-Process`` rows, so a PID joining the sum necessarily moves
# both; a tick where the set grows and the handle count does not is physically unrealizable. That made
# it the one input shape in which an over-wide subtree is INVISIBLE, and the fixture then asserted the
# FD/RSS pass-through as correct. Deriving from the set means no test can pin them apart again.
_HANDLES_PER_PID = 61
_WS_BYTES_PER_PID = 6_000_000


def _derive(pairs: list[tuple[float, float | None]]) -> object:
    """Drive ``_drain_proc`` over (elapsed_s, cumulative_cpu_seconds) readings, holding the summed-over
    PID set constant so every interval is a clean CPU delta (the stable-subtree common case)."""
    return _derive_sets([(e, c, _STABLE_PIDS) for e, c in pairs])


def _derive_sets(
    triples: list[tuple[float, float | None, frozenset[int] | None]],
) -> object:
    """Drive ``_drain_proc`` over (elapsed_s, cumulative_cpu_seconds, cpu_pids) readings, so a test can
    change the summed-over subtree between ticks (#220).

    ``handles`` / ``working_set_bytes`` are DERIVED from that tick's PID set (see ``_HANDLES_PER_PID``),
    never pinned: a tick with no observed set reports both as gaps, and a tick over a wider set reports
    a proportionally wider footprint."""
    samples = []
    for elapsed, cpu, pids in triples:
        s = _sample(elapsed)
        _PROC_BY_SAMPLE[id(s)] = ProcSample(
            handles=None if pids is None else _HANDLES_PER_PID * len(pids),
            cpu_seconds=cpu,
            working_set_bytes=None if pids is None else _WS_BYTES_PER_PID * len(pids),
            cpu_pids=pids,
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
    # The subtree here is the single stable PID, so the footprint is one PID's worth.
    assert d.handles_peak == _HANDLES_PER_PID * len(_STABLE_PIDS)
    assert d.working_set_peak_bytes == _WS_BYTES_PER_PID * len(_STABLE_PIDS)


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
    # The non-CPU gauges still read, and they read the WIDER middle tick — `max()` latches the two-PID
    # sum. That is arithmetically fine for an instantaneous gauge over a genuinely larger subtree, and
    # it is exactly why an over-wide subtree is not a #220-shaped problem: the number is not a
    # difference, so no gate here can tell a real second process from an adopted one — provenance has
    # to be established at the WALK, which is what the stale-ppid group below covers (BACKLOG #1210).
    # The old form of this assertion read `== 61` on all three ticks, which pinned the join to zero
    # effect and asserted that pass-through as correct.
    assert d.handles_peak == _HANDLES_PER_PID * 2
    assert d.working_set_peak_bytes == _WS_BYTES_PER_PID * 2


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


def _granted_extension_walks(config: pytest.Config) -> int:
    """How many long walks the bounded extension may make here, trimmed to fit the per-test watchdog.

    The watchdog is READ (``--timeout``, which ci.yml passes per leg) rather than hardcoded: a copy of
    the number in this file would drift from the matrix, and the direction it drifts in is the bad one —
    an extension that outgrows the watchdog converts a clean skip into a timeout kill with no verdict.
    Returns 0 when there is no room, which is a correct outcome, not a degraded one: the poll still runs
    for ``_RESOLUTION_DEADLINE_S`` and still reports which of the two failures occurred."""
    watchdog = config.getoption("timeout", default=None)
    if not isinstance(watchdog, int | float) or watchdog <= 0:
        return _STALL_EXTENSION_WALKS  # no watchdog to fit inside; the hard ceiling still applies
    spare_s = watchdog * _WATCHDOG_SHARE - _RESOLUTION_DEADLINE_S
    return max(0, min(_STALL_EXTENSION_WALKS, int(spare_s // _STALLED_WALK_TIMEOUT_S)))


def _spend_summary(failed: list[tuple[float, float]]) -> str:
    """Group failed walks by the per-walk budget they were given: how many got it, and the range they
    actually spent.

    SUMMARISED rather than enumerated. A stalled runner makes on the order of a hundred attempts inside
    ``_RESOLUTION_DEADLINE_S``, and a per-walk list that long is unreadable in a CI log — which is the
    same "message nobody can act on" failure #1290 is fixing at the verdict level, so it must not be
    reintroduced in the text of the verdict."""
    by_budget: dict[float, list[float]] = {}
    for spent, budget in failed:
        by_budget.setdefault(budget, []).append(spent)
    return "; ".join(
        f"{len(spent)} walk(s) at a {budget:.0f}s budget, spending {min(spent):.1f}-{max(spent):.1f}s"
        for budget, spent in sorted(by_budget.items())
    )


def _walk_succeeded(sampler: FdSampler) -> bool:
    """Run ONE subtree re-resolution and report whether THAT walk enumerated successfully.

    Reads ``_resolve_errored`` rather than ``sampler._pids is not None``, which is what the caller used
    to read. ``_pids`` retains the last GOOD resolution across a subsequent FAILED walk (that is the
    point of the cache), so ``_pids is not None`` scores every later walk a success once any earlier one
    has succeeded, and then reports the stale cache as that walk's result. ``_resolve_errored`` is set
    per walk, so it answers the question actually being asked. With ``resolve_every=1`` the cached-serve
    branch of ``_resolve_pids`` (which clears the flag without walking) is never taken, so the flag here
    is exactly this walk's outcome."""
    sampler.sample_proc()
    return not sampler._resolve_errored


@pytest.mark.skipif(sys.platform not in ("win32", "linux"), reason="OS FD probe path")
def test_subtree_re_resolution_picks_up_a_late_spawned_child(
    monkeypatch: pytest.MonkeyPatch,
    pytestconfig: pytest.Config,
) -> None:
    # A3: the subtree used to be resolved exactly ONCE. A sharded engine's `serve --shard` workers appear
    # AFTER the supervisor, so a one-shot walk pins the sampler to an idle parent for the whole run.
    sampler = FdSampler(os.getpid(), resolve_every=1)
    sampler.sample_proc()  # walk 1 — before the child exists
    resolved_before = list(sampler._pids or [])

    walks = 0
    walked_ok = False  # did ANY enumeration succeed? separates "cannot measure" from "wrong answer"
    child_alive_at_success = False  # was the target still running when a walk finally succeeded?
    resolved_after: list[int] = []
    failed: list[tuple[float, float]] = []  # (seconds spent, seconds allowed) per FAILED walk
    extension_walks = _granted_extension_walks(pytestconfig)

    child = subprocess.Popen([sys.executable, "-c", _BURN])  # noqa: S603 - fixed argv, no shell

    def _attempt(budget_s: float) -> bool:
        """One walk. True once the late-spawned child appears in a FRESH successful resolution.

        A failed walk is recorded with what it SPENT against what it was ALLOWED, because that pair is
        the only thing that separates "this runner is too slow to enumerate" from "this enumeration is
        broken" — and those two get opposite verdicts below."""
        nonlocal walks, walked_ok, resolved_after, child_alive_at_success
        started = time.monotonic()
        ok = _walk_succeeded(sampler)
        spent = time.monotonic() - started
        walks += 1
        if not ok:
            failed.append((spent, budget_s))
            return False
        walked_ok = True
        # A LATCH, NOT A SAMPLE, AND THE DISTINCTION IS LOAD-BEARING. `_BURN` is a BOUNDED loop --
        # roughly 12 s, then it exits on its own -- so a walk succeeding late enough is enumerating a
        # table the child has already left, and its absence there proves nothing about re-resolution.
        # But the poll runs to `_RESOLUTION_DEADLINE_S` (30 s) whenever the child is never found, so
        # the LAST successful walk is post-exit even in runs where EARLY walks succeeded while the
        # child was alive and legitimately showed it missing. Sampling at the end therefore suppresses
        # the real A3 regression; latching on ANY in-lifetime success preserves it. Measured: with a
        # probe that enumerates instantly but never reports descendants -- the genuine defect -- the
        # sampled form skipped and this form fails, which is the whole point of the assertion.
        if child.poll() is None:
            child_alive_at_success = True
        resolved_after = list(sampler._pids or [])
        return child.pid in resolved_after

    try:
        # POLL, don't sleep-and-hope. This used to be `time.sleep(1.0)` then ONE `sample_proc()`, which
        # contradicted the contract under test: `_resolve_pids` treats an ERRORED enumeration as
        # transient — it returns root-only for that tick, leaves `_pids` uncached, and expects the NEXT
        # tick to retry. Giving it a single tick asserts a stricter property than production requires.
        #
        # On Windows the walk shells out to `Get-CimInstance Win32_Process` with a 5 s timeout; on a
        # loaded runner that times out, `_descendants_windows` returns None, `_pids` stays None, and the
        # old assertion read `assert <pid> in []` — which names neither the cause nor the failing
        # property. Measured on windows-2025 (2026-07-30): failed twice in one job, while windows-2022
        # and ubuntu passed the identical commit.
        deadline = time.monotonic() + _RESOLUTION_DEADLINE_S
        found = False
        while not found:
            found = _attempt(_PROBE_TIMEOUT_S)
            if found or time.monotonic() >= deadline:
                break
            time.sleep(0.25)

        # BOUNDED EXTENSION (BACKLOG #1290). Entered only when the loop above produced NO usable
        # enumeration at all — never when a walk succeeded, so it cannot be used to grind a genuine
        # missing-child result into a pass. Each extension walk gets a LONGER budget, because the
        # failure being extended past is a walk that ran out of budget; repeating it at the same 5 s
        # bound reproduces the same cut-off. This is the only place the probe's production timeout is
        # raised, it is undone at teardown, and the walk count is trimmed to fit the watchdog.
        # (`found` is not tested here: it can only be True via a successful walk, so it implies
        # `walked_ok` and would add a condition a reader could mistake for an independent one.)
        if not walked_ok and extension_walks:
            monkeypatch.setattr(probe, "_PROBE_TIMEOUT_S", _STALLED_WALK_TIMEOUT_S)
            for _ in range(extension_walks):
                if _attempt(_STALLED_WALK_TIMEOUT_S):
                    break
    finally:
        child.kill()
        child.wait(timeout=10)

    assert child.pid not in resolved_before

    # Two distinct failures, reported distinctly. Collapsing them is what made the original message
    # useless: "the probe could not enumerate at all" is an environment/probe problem, while "it
    # enumerated and missed a live child" is the re-resolution regression this test exists to catch.
    # #1290 keeps that separation and adds the verdict it was missing: the first is not a defect in the
    # tree under test, so it must stop reddening a required context — but only when the walk actually
    # ran out of budget. A walk that returns None WITHOUT spending its budget is a broken enumerator,
    # and downgrading that to a skip is how a skip-on-load hides a probe regression forever.
    if not walked_ok:
        assert failed, "the loop made no attempt at all, so neither failure can be reported"
        fast = [(s, b) for s, b in failed if s < b * _BUDGET_CONSUMED_FRACTION]
        spend = _spend_summary(failed)
        if fast:
            pytest.fail(
                f"ENUMERATION FAILURE -- failure ONE of the two this test keeps apart, NOT the "
                f"re-resolution regression. The process-table walk never succeeded in {walks} "
                f"attempts, and {len(fast)} of them returned None WITHOUT spending the timeout they "
                f"were given [{spend}]. A walk that fails FAST did not run out of budget -- the "
                f"enumeration errored or returned zero rows -- so this is a probe defect, reported as a "
                f"failure and deliberately NOT downgraded to a skip. Re-resolution could not be "
                f"assessed either way."
            )
        pytest.skip(
            f"ENUMERATION TIMEOUT -- failure ONE of the two this test keeps apart, NOT the "
            f"re-resolution regression. The process-table walk never succeeded in {walks} attempts "
            f"[{spend}], every one of them spending its whole timeout; the bounded extension was "
            f"granted {extension_walks} walk(s) of {_STALLED_WALK_TIMEOUT_S:.0f}s against a per-test "
            f"watchdog of {pytestconfig.getoption('timeout', default=None)}s. The probe could not "
            f"enumerate AT ALL, so this test could not assess re-resolution: it is reporting COULD NOT "
            f"MEASURE, not measured-and-wrong. Skipped rather than failed because an exhausted walk "
            f"budget measures the runner, not this tree (BACKLOG #1290); a walk that fails WITHOUT "
            f"spending its budget still FAILS, so a broken enumerator cannot hide behind this skip."
        )

    # THE TARGET MUST HAVE BEEN ALIVE WHEN THE WALK SUCCEEDED, OR ITS ABSENCE PROVES NOTHING. This
    # guard is failure ONE's third form, and it is the one a bounded burner makes reachable: `_BURN`
    # completes in roughly 12 s on its own, while a walk can succeed later than that -- always, once
    # the bounded extension has spent `_RESOLUTION_DEADLINE_S` first. A child absent because it EXITED
    # is not a child the re-resolution missed, so reporting it as the A3 regression would be a
    # confident false accusation of a product defect that is not there. Skipped rather than failed for
    # the same reason as the enumeration timeout above: the test could not MEASURE, and a green that
    # rests on an unmeasurable run is what this whole item is about.
    #
    # A NARROW FORM OF THIS WAS REACHABLE BEFORE #1290 TOO -- a walk failing past roughly 14 s and then
    # succeeding inside the 30 s deadline hits it identically. The bounded extension widened the window
    # and made post-exit success the DESIGNED path, which is what turned a latent edge into the normal
    # one. This guard closes both.
    if walked_ok and child.pid not in resolved_after and not child_alive_at_success:
        pytest.skip(
            f"COULD NOT MEASURE -- the walk succeeded only AFTER the target exited, so the child's "
            f"absence from the process table proves nothing about re-resolution. `_BURN` is a bounded "
            f"loop (about 12 s); the successful walk landed after it had already completed, following "
            f"{walks} attempt(s) over {_RESOLUTION_DEADLINE_S:.0f}s. This is failure ONE, not the A3 "
            f"regression: reporting it as a regression would accuse the product of a defect the run "
            f"never tested for."
        )

    assert child.pid in resolved_after, (
        f"RE-RESOLUTION REGRESSION -- failure TWO of the two this test keeps apart. The walk SUCCEEDED "
        f"WHILE THE CHILD WAS STILL RUNNING and still did not include the late-spawned child "
        f"{child.pid}, after {walks} attempts over {_RESOLUTION_DEADLINE_S:.0f}s; last resolution was "
        f"{resolved_after}. This is the A3 regression: a subtree resolved once pins the sampler to an "
        f"idle parent, so a sharded engine's `serve --shard` workers are never counted."
    )


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


# --- stale_ppid: the subtree the gauges cover is the ENGINE's (BACKLOG #1210) ----------------------

#: Length of the synthetic post-comm tail: comfortably past field 22 (index 19).
_STAT_TAIL_LEN = 30


def _stat_line(*, ppid: int = 4242, starttime: int = 987654) -> str:
    """A synthetic ``/proc/<pid>/stat`` body, addressed BY INDEX so the fixture cannot drift out of
    alignment with the parser it checks. Fields after the comm are numbered from 3, so index i holds
    field i+3: [0] = state, [1] = ppid (field 4), [19] = starttime (field 22).

    Every other slot is filled with a NON-NUMERIC marker, so a parser that read a neighbouring index
    would return ``None`` rather than a plausible wrong number. The comm deliberately contains a space
    AND a ``)`` so the split-after-the-LAST-``)`` rule is exercised rather than assumed."""
    fields = [f"field{i + 3}" for i in range(_STAT_TAIL_LEN)]
    fields[0] = "S"
    fields[1] = str(ppid)
    fields[19] = str(starttime)
    return "1234 (py thon) proc) " + " ".join(fields) + "\n"


def test_posix_stat_parse_reads_ppid_and_field_22_starttime() -> None:
    # The POSIX half of the provenance check hangs entirely off field 22. Locate it by CONSTRUCT: build
    # a stat body whose field 22 is a distinctive value and require the parser to find exactly that.
    parsed = _posix_stat_ppid_starttime(_stat_line(ppid=77, starttime=555_000))
    assert parsed is not None
    ppid, started = parsed
    assert ppid == 77
    assert started is not None
    # starttime is in clock ticks since boot; the parser divides by SC_CLK_TCK so callers can state a
    # tolerance in seconds. Assert the RATIO, not a hardcoded Hz, so this holds on any tick rate.
    clk = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    assert started == pytest.approx(555_000 / float(clk))


def test_posix_stat_parse_degrades_rather_than_guessing_on_a_truncated_line() -> None:
    # A line long enough for ppid but not for field 22 yields ppid + an UNKNOWN start time. Unknown must
    # stay unknown: the walk rejects an unvalidatable candidate rather than admitting it.
    short = "1234 (py) S 99 " + " ".join(f"field{i + 5}" for i in range(10)) + "\n"
    assert _posix_stat_ppid_starttime(short) == (99, None)
    assert _posix_stat_ppid_starttime("1234 (py)\n") is None


def _rows(*triples: ProcRow) -> list[ProcRow]:
    return list(triples)


def test_a_candidate_that_predates_the_root_is_not_a_descendant() -> None:
    # The #1210 mechanism in miniature: pid 900 is live, its recorded parent PID was RECYCLED onto the
    # root, and 900 predates the root by an hour. It is not a descendant of THIS root.
    root_started = 10_000.0
    walked = _validated_descendants(
        _rows(
            (500, 1, root_started),  # the root
            (900, 500, root_started - 3600.0),  # adopted via a stale ppid
            (901, 500, root_started + 0.05),  # a genuine child, spawned just after the root
        ),
        500,
    )
    assert walked == [901]


def test_the_subtree_of_a_rejected_candidate_is_pruned_not_re_entered() -> None:
    # One wrong ppid link drags in the adoptee's WHOLE TREE, not the adoptee alone. A child of a
    # rejected node is created after the rejected node — so it passes the creation test on its own —
    # and must still be excluded, because its ancestry runs through a node that is not ours.
    root_started = 10_000.0
    walked = _validated_descendants(
        _rows(
            (500, 1, root_started),
            (900, 500, root_started - 3600.0),  # rejected: predates the root
            (901, 900, root_started + 5.0),  # its child: NEWER than the root, still not ours
            (902, 901, root_started + 6.0),  # and its grandchild
        ),
        500,
    )
    assert walked == []


def test_a_candidate_with_no_creation_instant_is_rejected_fail_closed() -> None:
    # Unvalidatable is not validated. Admitting a row whose creation instant the OS did not record
    # would leave the exact hole this check exists to close.
    walked = _validated_descendants(_rows((500, 1, 10_000.0), (900, 500, None)), 500)
    assert walked == []


def test_a_snapshot_without_the_root_cannot_validate_anything() -> None:
    # No root creation instant means no floor, so nothing is checkable. Report "cannot resolve" (None),
    # which the Windows caller turns into a degraded gap plus a retry, rather than walking unchecked.
    assert _validated_descendants(_rows((900, 500, 10_000.0)), 500) is None


def test_a_genuine_child_within_the_clock_skew_tolerance_is_still_adopted() -> None:
    # The POSITIVE CONTROL for the rejections above: the check must not start dropping real
    # descendants. The creation stamp is a wall-clock read (~15.6 ms kernel granularity on Windows), so
    # a child can legitimately timestamp a hair BEFORE its parent; the tolerance covers that, and
    # nothing near the age of a genuine adoption.
    root_started = 10_000.0
    inside = _validated_descendants(
        _rows((500, 1, root_started), (900, 500, root_started - _CREATION_SKEW_TOLERANCE_S / 2)),
        500,
    )
    assert inside == [900]
    outside = _validated_descendants(
        _rows((500, 1, root_started), (900, 500, root_started - _CREATION_SKEW_TOLERANCE_S * 2)),
        500,
    )
    assert outside == []


def test_the_walk_still_terminates_on_a_ppid_cycle() -> None:
    # The pre-#1210 walk's only guard was the cycle guard; keep it. A recycled PID can produce a loop.
    root_started = 10_000.0
    walked = _validated_descendants(
        _rows(
            (500, 1, root_started),
            (600, 500, root_started + 1.0),
            (601, 600, root_started + 2.0),
            (600, 601, root_started + 1.0),  # 600 reappears as its own grandchild
        ),
        500,
    )
    assert sorted(walked) == [600, 601]


# --- the acceptance test: the real probe, over a real deliberately-adopted subtree -----------------

_IDLE = "import time; time.sleep(45)"
#: The adoptee opens a large, countable block of sockets so its contribution to a handle/fd SUM is
#: unmistakable — the point of the acceptance test is the MAGNITUDE, not just set membership.
_ADOPTEE_HANDLES = 200
_HANDLE_HOG = (
    f"import socket, time; s=[socket.socket() for _ in range({_ADOPTEE_HANDLES})]; time.sleep(45)"
)


def _enumerate(sampler: FdSampler) -> list[ProcRow] | None:
    return sampler._enumerate_windows() if sys.platform == "win32" else sampler._enumerate_posix()


def _bfs_unvalidated(rows: list[ProcRow], root: int) -> list[int]:
    """The PRE-#1210 walk, reproduced here so the test can show what it WOULD have reported: BFS the
    ppid map with a cycle guard and no other check."""
    children: dict[int, list[int]] = {}
    for pid, ppid, _ in rows:
        children.setdefault(ppid, []).append(pid)
    out: list[int] = []
    seen = {root}
    queue = list(children.get(root, []))
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        out.append(pid)
        queue.extend(children.get(pid, []))
    return out


def _handles_peak_over(sampler: FdSampler, pids: list[int]) -> int | None:
    """Sum a REAL per-PID OS read over ``pids`` and push it through ``_drain_proc``, so what the test
    asserts is the reported ``handles_peak`` gauge rather than an intermediate."""
    raw = sampler._sample_windows(pids) if sys.platform == "win32" else sampler._sample_posix(pids)
    s = _sample(0.0)
    _PROC_BY_SAMPLE[id(s)] = raw
    return _drain_proc([s]).handles_peak


@pytest.mark.skipif(sys.platform not in ("win32", "linux"), reason="OS process-table probe path")
def test_the_reported_peak_excludes_a_stale_ppid_adopted_subtree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #1210 acceptance. Drive the real probe over a real adopted subtree and show the reported
    ``handles_peak`` no longer carries it.

    Everything here is the OS's own except ONE bit: the adoptee's recorded parent PID is re-pointed at
    the root. That single rewrite is exactly what Windows reports once the adoptee's real parent exits
    and the root is later issued that PID, and it is the one input that cannot be manufactured on
    demand — forcing a real PID recycle means exhausting the PID space. The live PIDs, their creation
    instants, the per-PID handle reads and the peak derivation are all real.
    """
    # Spawn the ADOPTEE first, so it genuinely predates the root by more than the skew tolerance.
    adoptee = subprocess.Popen([sys.executable, "-c", _HANDLE_HOG])  # noqa: S603 - fixed argv
    root: subprocess.Popen[bytes] | None = None
    try:
        time.sleep(2 * _CREATION_SKEW_TOLERANCE_S)
        root = subprocess.Popen([sys.executable, "-c", _IDLE])  # noqa: S603 - fixed argv
        time.sleep(1.0)  # let both settle (and any launcher shim re-exec its base interpreter)

        sampler = FdSampler(root.pid, resolve_every=1)
        real_rows = _enumerate(sampler)
        if not real_rows:
            pytest.skip("process-table enumeration unavailable on this runner")
        if all(pid != root.pid for pid, _, _ in real_rows):
            pytest.skip("the spawned root is not in the process-table snapshot")

        adopted_rows: list[ProcRow] = [
            (pid, root.pid, created) if pid == adoptee.pid else (pid, ppid, created)
            for pid, ppid, created in real_rows
        ]
        monkeypatch.setattr(sampler, "_enumerate_windows", lambda: adopted_rows)
        monkeypatch.setattr(sampler, "_enumerate_posix", lambda: adopted_rows)

        # (1) POSITIVE CONTROL: the adoption is real. The pre-#1210 walk pulls the adoptee in, so this
        #     fixture genuinely reproduces the class rather than asserting a vacuous absence.
        would_have = _bfs_unvalidated(adopted_rows, root.pid)
        assert adoptee.pid in would_have, (adoptee.pid, would_have)

        # (2) The validated walk rejects it.
        resolved = sampler._resolve_pids()
        assert sampler._resolve_errored is False
        assert resolved[0] == root.pid
        assert adoptee.pid not in resolved, (adoptee.pid, resolved)

        # (3) And the number an SLO would judge — handles_peak — excludes it. Measured, not asserted
        #     structurally: the adopted sum must exceed the validated one by at least the block of
        #     sockets the adoptee holds.
        validated_peak = _handles_peak_over(sampler, resolved)
        adopted_peak = _handles_peak_over(sampler, [root.pid, *would_have])
        if validated_peak is None or adopted_peak is None:
            pytest.skip("per-PID handle read unavailable on this runner")
        assert adopted_peak - validated_peak >= _ADOPTEE_HANDLES, (adopted_peak, validated_peak)
    finally:
        for proc in (adoptee, root):
            if proc is not None:
                proc.kill()
                proc.wait(timeout=10)
