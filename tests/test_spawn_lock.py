# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the pwsh burst lock (tests/_spawn_lock.py) -- BACKLOG #1304.

THE PROPERTY UNDER TEST is mutual exclusion between a BURST and a SINGLE launch, and it is asserted
with a positive control: the same probe run with the lock disabled must actually overlap. A
concurrency test that would pass against a no-op is the failure mode this repo has already paid for,
so the control is not optional here.

THE SECOND THING THESE PIN is that the remedy did not quietly disarm what it protects. ``run_single``
must still be interceptable by ``monkeypatch.setattr(harness.subprocess, "run", ...)``, because
``test_worktree_gate_control_plane.py`` drives the #1304 launch-timeout diagnostic that way. An
indirection that bypassed the patch would leave that test passing while proving nothing.
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from tests import _spawn_lock
from tests._spawn_lock import run_single, single_spawn, spawn_burst


@pytest.fixture
def lock_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the module at a private root, so a test never waits on a real run's storm."""
    root = tmp_path / "pwsh-burst"
    (root / "readers").mkdir(parents=True)
    monkeypatch.setattr(_spawn_lock, "_ROOT", root)
    return root


class _Window:
    """Records when each side held the lock, so overlap is decided on timestamps, not on a flag."""

    def __init__(self) -> None:
        self.spans: list[tuple[str, float, float]] = []
        self._guard = threading.Lock()

    def record(self, who: str, start: float, end: float) -> None:
        with self._guard:
            self.spans.append((who, start, end))

    def overlapped(self) -> bool:
        for i, (_, a_start, a_end) in enumerate(self.spans):
            for _, b_start, b_end in self.spans[i + 1 :]:
                if a_start < b_end and b_start < a_end:
                    return True
        return False


def _burst(window: _Window, hold: float, ready: threading.Event) -> None:
    with spawn_burst("probe"):
        start = time.monotonic()
        ready.set()
        time.sleep(hold)
        window.record("burst", start, time.monotonic())


def _single(window: _Window, hold: float) -> None:
    with single_spawn():
        start = time.monotonic()
        time.sleep(hold)
        window.record("single", start, time.monotonic())


def test_a_burst_and_a_single_launch_never_hold_the_lock_at_once(lock_root: Path) -> None:
    """The whole point: while a storm runs, no single launch is in flight beside it."""
    window = _Window()
    ready = threading.Event()
    burst = threading.Thread(target=_burst, args=(window, 0.4, ready))
    burst.start()
    assert ready.wait(10), "the burst never took the lock"
    single = threading.Thread(target=_single, args=(window, 0.05))
    single.start()
    burst.join(30)
    single.join(30)

    assert len(window.spans) == 2, f"a side never recorded: {window.spans}"
    assert not window.overlapped(), f"burst and single launch overlapped: {window.spans}"


def test_the_control_without_the_lock_does_overlap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSITIVE CONTROL for the row above. With the lock disabled the same probe MUST overlap.

    Without this, a lock that silently did nothing -- an unwritable root, a typo in the directory
    name -- would pass the mutual-exclusion assertion by never letting either side run concurrently
    in the first place, and the suite would report a fix that is not there.
    """
    monkeypatch.setattr(_spawn_lock, "_ROOT", None)
    window = _Window()
    ready = threading.Event()
    burst = threading.Thread(target=_burst, args=(window, 0.4, ready))
    burst.start()
    assert ready.wait(10)
    single = threading.Thread(target=_single, args=(window, 0.05))
    single.start()
    burst.join(30)
    single.join(30)

    assert window.overlapped(), (
        f"the unlocked control did NOT overlap, so the locked assertion proves nothing: "
        f"{window.spans}"
    )


def test_a_single_launch_gives_up_and_runs_rather_than_waiting_forever(
    lock_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FAIL-OPEN, the property that makes this safe to land: a wedged turnstile costs a bounded wait,
    never a hung test. A lock that could block forever would be a worse failure than the flake."""
    monkeypatch.setattr(_spawn_lock, "_SINGLE_WAIT_S", 0.3)
    (lock_root / "burst.lock").write_text("wedged", encoding="ascii")

    start = time.monotonic()
    with single_spawn():
        waited = time.monotonic() - start
    assert waited >= 0.25, f"it did not wait for the turnstile at all: {waited:.3f}s"
    assert waited < 20, f"it waited far past its own bound: {waited:.3f}s"


def test_a_burst_starts_even_when_a_reader_never_drains(
    lock_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same fail-open rule on the storm side: an abandoned reader must not stall the burst."""
    monkeypatch.setattr(_spawn_lock, "_BURST_DRAIN_S", 0.3)
    (lock_root / "readers" / "99999-1-0.lock").write_text("", encoding="ascii")

    start = time.monotonic()
    with spawn_burst("probe"):
        waited = time.monotonic() - start
    assert waited < 20, f"the burst stalled behind a stuck reader: {waited:.3f}s"


def test_an_abandoned_turnstile_is_reaped_rather_than_waited_out(lock_root: Path) -> None:
    """A crashed storm must not keep every later launch queued behind a file nobody owns."""
    gate = lock_root / "burst.lock"
    gate.write_text("crashed", encoding="ascii")
    old = time.time() - (_spawn_lock._BURST_STALE_S + 60)
    os.utime(gate, (old, old))

    start = time.monotonic()
    with single_spawn():
        waited = time.monotonic() - start
    assert waited < 5, f"a stale turnstile was waited out instead of reaped: {waited:.3f}s"
    assert not gate.exists(), "the stale turnstile was not reaped"


def test_a_stale_reader_entry_does_not_hold_a_burst(lock_root: Path) -> None:
    """The reader-side twin of the row above: an entry older than any legitimate hold is abandoned."""
    entry = lock_root / "readers" / "99999-1-0.lock"
    entry.write_text("", encoding="ascii")
    old = time.time() - (_spawn_lock._READER_STALE_S + 60)
    os.utime(entry, (old, old))

    assert _spawn_lock._live_readers(lock_root) == 0
    assert not entry.exists(), "the stale reader entry was not reaped"


def test_no_lock_root_runs_both_sides_unsynchronised(monkeypatch: pytest.MonkeyPatch) -> None:
    """No directory, no lock, no failure. A test must never fail BECAUSE the lock was unavailable."""
    monkeypatch.setattr(_spawn_lock, "_ROOT", None)
    with spawn_burst("probe"):
        pass
    with single_spawn():
        pass


def test_a_single_launch_releases_its_ticket(lock_root: Path) -> None:
    """A leaked ticket would make every later burst pay the full drain timeout."""
    with single_spawn():
        assert _spawn_lock._live_readers(lock_root) == 1
    assert _spawn_lock._live_readers(lock_root) == 0


def test_run_single_still_honours_a_patched_subprocess_run(
    lock_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEGATIVE CONTROL protecting the #1304 diagnostic.

    ``test_worktree_gate_control_plane.py::test_a_pwsh_LAUNCH_timeout_is_reported_as_its_own_event``
    drives the launch timeout with ``monkeypatch.setattr(harness.subprocess, "run", ...)``. That
    patches the ``subprocess`` MODULE, so it only reaches ``run_single`` while this looks the
    attribute up at call time. A ``from subprocess import run`` in _spawn_lock.py would bypass it and
    leave that test green against a diagnostic that no longer fires.
    """
    seen: list[Any] = []

    def never_returns(*args: object, **kwargs: object) -> None:
        seen.append(args)
        raise subprocess.TimeoutExpired(cmd="pwsh", timeout=45)

    monkeypatch.setattr(subprocess, "run", never_returns)
    with pytest.raises(subprocess.TimeoutExpired):
        run_single(["pwsh", "-NoProfile", "-Command", "exit 0"], capture_output=True, text=True)
    assert seen, "run_single did not route through the patched subprocess.run"


def test_run_single_returns_what_subprocess_run_returns(lock_root: Path) -> None:
    """The wrapper must be transparent -- it adds a lock, not a behaviour change."""
    proc = run_single(["git", "--version"], capture_output=True, text=True, check=False, timeout=60)
    assert proc.returncode == 0
    assert "git" in proc.stdout.lower()


def test_the_storm_counts_are_unchanged(lock_root: Path) -> None:
    """THE REMEDY MUST NOT HAVE WEAKENED WHAT IT PROTECTS, and this is where that is pinned.

    Cutting ``RACERS`` was the cheap candidate fix for #1304 and it is the wrong one: ``_race``
    exists to prove exactly one of N concurrent claimers wins, and ``_require_real_contention``
    SKIPS when the host cannot produce contention at that N. A lower N turns a race test into a
    sequential one that still reports green -- the always-pass failure ``tests/_dead_pid.py``
    records for a sibling flake. If a later change needs these numbers down, it needs evidence that
    the property survives, not this test deleted.
    """
    from tests.test_session_mail import DRAINS, RACERS

    assert RACERS == 16, "RACERS moved; see tests/_spawn_lock.py for why that is not the #1304 fix"
    assert DRAINS == 8, "DRAINS moved; the same argument applies"


def test_the_run_id_is_shared_by_xdist_workers_and_private_otherwise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scope check. Workers of ONE run must agree; two unrelated local runs must not serialise.

    xdist exports ``PYTEST_XDIST_TESTRUNUID`` into every worker from a single per-run uuid, which is
    what makes the four workers of a CI job share one lock. With it absent the key falls back to the
    process, so a developer's run does not queue behind a peer session's storm.
    """
    monkeypatch.setenv("PYTEST_XDIST_TESTRUNUID", "shared-run-uid")
    assert _spawn_lock._run_id() == "shared-run-uid"

    monkeypatch.delenv("PYTEST_XDIST_TESTRUNUID", raising=False)
    assert _spawn_lock._run_id() == f"pid-{os.getpid()}"
