# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tray poller (ADR 0113 §3): pure `advance` timing + the poller's transition/toast logic."""

from __future__ import annotations

import logging
import queue
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest

from messagefoundry.tray import state as state_mod
from messagefoundry.tray.config import TrayConfig
from messagefoundry.tray.poller import PollResult, StatusPoller, Tracking, advance
from messagefoundry.tray.state import (
    HealthProbe,
    ScmState,
    TrayState,
    UiProbe,
    derive_state,
)
from messagefoundry.tray.winsvc import ScmReading

_ENGINE_URL = "http://127.0.0.1:8765"
_POLLER_LOGGER = "messagefoundry.tray.poller"

# --- pure advance() ---------------------------------------------------------


def test_advance_sets_and_holds_running_since() -> None:
    t0 = Tracking()
    t1, in1 = advance(t0, ScmReading(ScmState.RUNNING), HealthProbe.OK, UiProbe.ENABLED, 100.0)
    assert t1.running_since == 100.0
    assert in1.running_elapsed_s == 0.0
    # Still RUNNING one tick later: the anchor holds, elapsed grows.
    t2, in2 = advance(t1, ScmReading(ScmState.RUNNING), HealthProbe.OK, UiProbe.ENABLED, 130.0)
    assert t2.running_since == 100.0
    assert in2.running_elapsed_s == 30.0


def test_advance_clears_running_since_when_not_running() -> None:
    t1, _ = advance(Tracking(), ScmReading(ScmState.RUNNING), HealthProbe.OK, UiProbe.ENABLED, 10.0)
    t2, in2 = advance(t1, ScmReading(ScmState.STOPPED), HealthProbe.DOWN, UiProbe.UNKNOWN, 11.0)
    assert t2.running_since is None
    assert in2.running_elapsed_s is None


def test_advance_pending_checkpoint_progress() -> None:
    t0 = Tracking()
    r_a = ScmReading(ScmState.START_PENDING, checkpoint=1, wait_hint_s=5.0)
    t1, in1 = advance(t0, r_a, HealthProbe.DOWN, UiProbe.UNKNOWN, 0.0)
    assert t1.pending_since == 0.0
    assert in1.checkpoint_advancing is True  # fresh pending
    assert in1.wait_hint_s == 5.0
    # Checkpoint advanced (1 -> 2): still advancing, and the pending clock re-anchors to `now`.
    # dwWaitHint is the estimate for the NEXT checkpoint, not for the whole transition, so the
    # elapsed the reducer sees is time-since-progress (BACKLOG #1555).
    r_b = ScmReading(ScmState.START_PENDING, checkpoint=2, wait_hint_s=5.0)
    t2, in2 = advance(t1, r_b, HealthProbe.DOWN, UiProbe.UNKNOWN, 3.0)
    assert in2.checkpoint_advancing is True
    assert t2.pending_since == 3.0
    assert in2.pending_elapsed_s == 0.0
    # Checkpoint stalled (2 -> 2): not advancing, and the clock holds the re-anchored t=3.0.
    t3, in3 = advance(t2, r_b, HealthProbe.DOWN, UiProbe.UNKNOWN, 6.0)
    assert in3.checkpoint_advancing is False
    assert t3.pending_since == 3.0
    assert in3.pending_elapsed_s == 3.0


def test_advance_progressing_slow_start_stays_starting_past_the_wait_hint() -> None:
    """A service that keeps reporting progress reads as STARTING however long the start takes."""
    tracking = Tracking()
    for tick, checkpoint in ((0.0, 1), (4.0, 2), (8.0, 3), (12.0, 4), (16.0, 5)):
        reading = ScmReading(ScmState.START_PENDING, checkpoint=checkpoint, wait_hint_s=5.0)
        tracking, inputs = advance(tracking, reading, HealthProbe.DOWN, UiProbe.UNKNOWN, tick)
        assert tracking.pending_since == tick  # re-anchored on every checkpoint increase
        assert derive_state(inputs) is TrayState.STARTING
    # One sample later the checkpoint has not moved yet: 1.0s since progress, well inside the hint,
    # even though 17.0s have passed since the transition began.
    held = ScmReading(ScmState.START_PENDING, checkpoint=5, wait_hint_s=5.0)
    t_final, in_final = advance(tracking, held, HealthProbe.DOWN, UiProbe.UNKNOWN, 17.0)
    assert t_final.pending_since == 16.0  # the anchor holds while the checkpoint does not move
    assert in_final.checkpoint_advancing is False
    assert in_final.pending_elapsed_s == 1.0
    assert derive_state(in_final) is TrayState.STARTING


def test_advance_frozen_checkpoint_still_reaches_wedged() -> None:
    """The other arm: a checkpoint that never moves keeps its anchor and ages past the hint."""
    tracking = Tracking()
    frozen = ScmReading(ScmState.START_PENDING, checkpoint=1, wait_hint_s=5.0)
    # t=0.0 is the fresh pending tick (assumed progressing); t=4.0 is still inside the 5.0s hint;
    # t=17.0 is the paired arm of the test above, which stays STARTING there.
    expected = (
        (0.0, TrayState.STARTING),
        (4.0, TrayState.STARTING),
        (8.0, TrayState.WEDGED),
        (17.0, TrayState.WEDGED),
    )
    for tick, state in expected:
        tracking, inputs = advance(tracking, frozen, HealthProbe.DOWN, UiProbe.UNKNOWN, tick)
        assert tracking.pending_since == 0.0  # never re-anchored
        assert inputs.pending_elapsed_s == tick
        assert derive_state(inputs) is state


def test_advance_stop_pending_re_anchors_harmlessly_and_clears_on_leaving() -> None:
    """STOP_PENDING shares the clock: it re-anchors too, and STOPPING is unconditional."""
    stopping_a = ScmReading(ScmState.STOP_PENDING, checkpoint=1, wait_hint_s=5.0)
    stopping_b = ScmReading(ScmState.STOP_PENDING, checkpoint=2, wait_hint_s=5.0)
    t1, in1 = advance(Tracking(), stopping_a, HealthProbe.DOWN, UiProbe.UNKNOWN, 0.0)
    t2, in2 = advance(t1, stopping_b, HealthProbe.DOWN, UiProbe.UNKNOWN, 9.0)
    assert t2.pending_since == 9.0  # re-anchored on the checkpoint increase
    assert derive_state(in1) is TrayState.STOPPING
    assert derive_state(in2) is TrayState.STOPPING  # the clock never reaches the STOPPING branch
    # Leaving the pending states drops the anchor, so a later pending run cannot inherit it.
    t3, in3 = advance(t2, ScmReading(ScmState.STOPPED), HealthProbe.DOWN, UiProbe.UNKNOWN, 10.0)
    assert t3.pending_since is None
    assert in3.pending_elapsed_s is None


# --- StatusPoller transition/toast logic ------------------------------------


def _scripted_poller(
    scm: list[ScmReading],
    health: list[HealthProbe],
    ui: list[UiProbe],
) -> tuple[StatusPoller, httpx.Client]:
    scm_it: Iterator[ScmReading] = iter(scm)
    health_it: Iterator[HealthProbe] = iter(health)
    ui_it: Iterator[UiProbe] = iter(ui)
    cfg = TrayConfig(engine_url=_ENGINE_URL, service_name="MessageFoundry")

    def reader(_name: str) -> ScmReading:
        return next(scm_it)

    def hp(_c: httpx.Client) -> HealthProbe:
        return next(health_it)

    def up(_c: httpx.Client) -> UiProbe:
        return next(ui_it)

    def noop(_r: PollResult) -> None:
        return None

    poller = StatusPoller(
        cfg,
        on_update=noop,
        scm_reader=reader,
        health_probe=hp,
        ui_probe=up,
    )
    dummy = httpx.Client(base_url=_ENGINE_URL)
    poller._client = dummy  # non-None so the injected probes are consulted
    return poller, dummy


def test_poller_toast_once_then_rate_limited() -> None:
    poller, client = _scripted_poller(
        scm=[
            ScmReading(ScmState.STOPPED),
            ScmReading(ScmState.RUNNING),
            ScmReading(ScmState.RUNNING),
            ScmReading(ScmState.STOPPED),
        ],
        health=[HealthProbe.DOWN, HealthProbe.OK, HealthProbe.OK, HealthProbe.DOWN],
        ui=[UiProbe.UNKNOWN, UiProbe.ENABLED, UiProbe.ENABLED, UiProbe.UNKNOWN],
    )
    try:
        r0 = poller.poll_once(0.0)  # first reading: STOPPED, no startup toast
        r1 = poller.poll_once(1.0)  # → RUNNING: toast
        r2 = poller.poll_once(2.0)  # RUNNING: no change
        r3 = poller.poll_once(5.0)  # → STOPPED within 30s of last toast: suppressed
    finally:
        client.close()

    assert r0.snapshot.state is TrayState.STOPPED and r0.toast is None
    assert r1.snapshot.state is TrayState.RUNNING and r1.toast is not None
    assert "running" in r1.toast.body.lower()
    assert r2.toast is None
    assert r3.snapshot.state is TrayState.STOPPED and r3.toast is None  # rate-limited


def test_poller_toast_fires_again_after_interval() -> None:
    poller, client = _scripted_poller(
        scm=[
            ScmReading(ScmState.STOPPED),
            ScmReading(ScmState.RUNNING),
            ScmReading(ScmState.STOPPED),
        ],
        health=[HealthProbe.DOWN, HealthProbe.OK, HealthProbe.DOWN],
        ui=[UiProbe.UNKNOWN, UiProbe.ENABLED, UiProbe.UNKNOWN],
    )
    try:
        poller.poll_once(0.0)
        r1 = poller.poll_once(1.0)  # → RUNNING: toast at t=1
        r2 = poller.poll_once(100.0)  # → STOPPED well past the 30s window: toast again
    finally:
        client.close()

    assert r1.toast is not None
    assert r2.toast is not None and "stopped" in r2.toast.body.lower()


def test_poller_snapshot_reflects_ui_and_monitor_only() -> None:
    poller, client = _scripted_poller(
        scm=[ScmReading(ScmState.RUNNING)],
        health=[HealthProbe.OK],
        ui=[UiProbe.DISABLED],
    )
    try:
        result = poller.poll_once(0.0)
    finally:
        client.close()
    assert result.snapshot.console_enabled is False  # /ui was DISABLED
    assert result.snapshot.monitor_only is False  # local http engine


# --- the poll thread outlives a failing tick --------------------------------


def test_poll_thread_survives_a_raising_tick_and_publishes_unknown(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A tick that raises is published as UNKNOWN and the thread ticks on, rather than dying."""
    # The real next_poll_seconds against a near-zero base, so the recovery tick lands without a
    # sleep in the test and the cadence function itself is still exercised.
    monkeypatch.setattr(state_mod, "POLL_BASE_S", 0.001)
    caplog.set_level(logging.ERROR, logger=_POLLER_LOGGER)

    first_tick = iter([True])

    def reader(_name: str) -> ScmReading:
        if next(first_tick, False):
            raise OSError("QueryServiceStatusEx blew up")
        return ScmReading(ScmState.RUNNING)

    published: queue.Queue[PollResult] = queue.Queue()
    client = httpx.Client(base_url=_ENGINE_URL)
    poller = StatusPoller(
        TrayConfig(engine_url=_ENGINE_URL, service_name="MessageFoundry"),
        on_update=published.put,
        scm_reader=reader,
        health_probe=lambda _c: HealthProbe.OK,
        ui_probe=lambda _c: UiProbe.ENABLED,
        client_factory=lambda _url: client,
    )
    poller.start()
    try:
        # A dead thread publishes nothing at all, so both gets time out on the unfixed loop.
        fallback = published.get(timeout=10.0)
        recovered = published.get(timeout=10.0)
        thread = poller._thread
        assert thread is not None and thread.is_alive()  # outlived the raising tick
    finally:
        poller.stop()

    assert fallback.snapshot.state is TrayState.UNKNOWN  # published instead of freezing the icon
    assert recovered.snapshot.state is TrayState.RUNNING  # and the tick after it recovered

    # The row asked for the failure to be *logged*, not just absorbed. Without this the whole test
    # stays green with the `log.exception` line deleted, and a silent swallow is the defect the
    # row's own measurement describes -- output going nowhere under `pythonw`.
    failures = _faults(caplog)
    assert len(failures) == 1
    assert "publishing UNKNOWN" in failures[0].getMessage()
    # Read whichever field carries the traceback, because which one that is depends on whether
    # anything else in the process has configured engine logging. `RedactionFilter` renders
    # `exc_info` into `exc_text` and then sets `exc_info` to None on purpose -- "clear exc_info in
    # BOTH paths so no formatter (even a custom one ignoring exc_text) can re-render the raw
    # exception" (`logging_setup._install_phi_filters`, installed on every handler). caplog holds
    # that same mutated record, so asserting on `exc_info` alone passes when this file runs on its
    # own and fails under the full suite, which is what reddened all three CI legs.
    assert failures[0].exc_info or failures[0].exc_text  # a traceback, not a bare one-line error


# --- the UNKNOWN stand-in is a display fallback, not a state transition ------


def test_a_failed_tick_leaves_the_tracking_and_toast_memory_untouched() -> None:
    """The synthetic reading must reach neither `advance` nor `_last_state`.

    Those two wipes are what the five behavioural arms below detect; this pins the mechanism
    directly, so a regression names its own cause rather than surfacing as a stray balloon.
    """
    poller, client = _scripted_poller(
        scm=[ScmReading(ScmState.RUNNING)], health=[HealthProbe.OK], ui=[UiProbe.ENABLED]
    )
    try:
        poller.poll_once(100.0)
        before_tracking, before_state = poller._tracking, poller._last_state
        fallback = poller._unknown_result()
    finally:
        client.close()

    assert fallback.snapshot.state is TrayState.UNKNOWN
    assert fallback.toast is None
    assert poller._tracking == before_tracking  # the boot-grace and pending clocks did not move
    assert poller._last_state is before_state  # the toast machine still holds the last real state


def test_a_wedged_engine_still_reaches_wedged_across_intermittent_poll_failures() -> None:
    """The defect this repair exists for: SCM RUNNING with /health dark, polls failing every 15s.

    Why the fold defeats WEDGED is stated once, on `StatusPoller._unknown_result`.
    """
    poller, client = _scripted_poller(
        scm=[ScmReading(ScmState.RUNNING)] * 3,
        health=[HealthProbe.DOWN] * 3,
        ui=[UiProbe.UNKNOWN] * 3,
    )
    try:
        first = poller.poll_once(0.0)  # SCM RUNNING, /health dark: inside the boot grace
        poller._unknown_result()  # a tick raises at t=10
        mid = poller.poll_once(20.0)  # still inside the 30s grace, measured from t=0
        poller._unknown_result()  # another raises at t=25
        late = poller.poll_once(40.0)  # past the grace, measured from t=0
    finally:
        client.close()

    assert first.snapshot.state is TrayState.STARTING
    assert mid.snapshot.state is TrayState.STARTING
    assert mid.inputs.running_elapsed_s == 20.0  # the anchor survived the failed tick
    assert late.snapshot.state is TrayState.WEDGED  # the detection the tray exists for
    assert late.inputs.running_elapsed_s == 40.0


def test_an_already_wedged_pending_service_stays_wedged_across_a_failed_tick() -> None:
    """A service the tray has ALREADY called WEDGED must not flip back to STARTING.

    This is the wider half of the defect, and the arm above does not catch it. The fold clears
    `last_scm` and `last_checkpoint` together, and **either one alone** is enough: with `last_scm`
    gone the next real pending tick is no longer `same_pending`, so it re-anchors `pending_since`
    AND takes the "freshly entered pending is assumed to be progressing" branch; with
    `last_checkpoint` reset to 0 the stalled checkpoint 7 reads as advancing. Both halves of the
    WEDGED condition are cleared at once, so the fold disables stuck detection outright rather
    than merely delaying it. Unlike the boot-grace arm, this holds regardless of how `advance`
    anchors `pending_since`.
    """
    stalled = ScmReading(ScmState.START_PENDING, checkpoint=7, wait_hint_s=5.0)
    poller, client = _scripted_poller(
        scm=[stalled] * 4, health=[HealthProbe.DOWN] * 4, ui=[UiProbe.UNKNOWN] * 4
    )
    try:
        poller.poll_once(0.0)  # enters START_PENDING at checkpoint 7
        poller.poll_once(4.0)  # checkpoint has not moved, but still inside the 5s wait hint
        wedged = poller.poll_once(8.0)  # stalled past its own wait hint
        poller._unknown_result()  # a tick raises at t=10
        after = poller.poll_once(12.0)  # the service is every bit as stuck as it was
    finally:
        client.close()

    assert wedged.snapshot.state is TrayState.WEDGED
    assert after.snapshot.state is TrayState.WEDGED  # did not flip back to STARTING
    assert after.inputs.checkpoint_advancing is False  # the stalled checkpoint is still stalled
    assert after.inputs.pending_elapsed_s == 12.0  # the pending anchor survived the failed tick


def test_recovery_from_a_transient_failure_raises_no_false_running_balloon() -> None:
    poller, client = _scripted_poller(
        scm=[ScmReading(ScmState.STOPPED)] + [ScmReading(ScmState.RUNNING)] * 2,
        health=[HealthProbe.DOWN, HealthProbe.OK, HealthProbe.OK],
        ui=[UiProbe.UNKNOWN, UiProbe.ENABLED, UiProbe.ENABLED],
    )
    try:
        poller.poll_once(0.0)  # first reading: STOPPED, no startup toast
        came_up = poller.poll_once(1.0)  # STOPPED -> RUNNING: the one real balloon
        poller._unknown_result()  # a tick raises at t=100, on an engine that never stopped
        still_up = poller.poll_once(101.0)  # past the 30s rate-limit window, so nothing suppresses
    finally:
        client.close()

    assert came_up.toast is not None and "running" in came_up.toast.body.lower()
    assert still_up.snapshot.state is TrayState.RUNNING
    assert still_up.toast is None  # the engine never left RUNNING, so there is nothing to announce


def test_a_failed_tick_between_running_and_stopped_keeps_the_stopped_balloon() -> None:
    poller, client = _scripted_poller(
        scm=[ScmReading(ScmState.RUNNING), ScmReading(ScmState.STOPPED)],
        health=[HealthProbe.OK, HealthProbe.DOWN],
        ui=[UiProbe.ENABLED, UiProbe.UNKNOWN],
    )
    try:
        poller.poll_once(0.0)  # first reading: RUNNING, no startup toast
        poller._unknown_result()  # a tick raises at t=50, as the service is going down
        stopped = poller.poll_once(51.0)
    finally:
        client.close()

    assert stopped.snapshot.state is TrayState.STOPPED
    # transition_toast only announces a stop from RUNNING/RUNNING_UNMANAGED/STOPPING/WEDGED, so a
    # stamped UNKNOWN in between silently swallows the one balloon an operator needs most.
    assert stopped.toast is not None and "stopped" in stopped.toast.body.lower()


def test_a_first_tick_failure_does_not_spend_the_startup_no_toast_exemption() -> None:
    poller, client = _scripted_poller(
        scm=[ScmReading(ScmState.RUNNING)], health=[HealthProbe.OK], ui=[UiProbe.ENABLED]
    )
    try:
        poller._unknown_result()  # the very first tick raises
        first_real = poller.poll_once(1.0)
    finally:
        client.close()

    assert first_real.snapshot.state is TrayState.RUNNING
    assert first_real.toast is None  # still the *first* real reading: never toast on startup


@pytest.fixture
def fast_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collapse every cadence, so an arm driving `_run` is bounded ticks and not sleeps.

    All three, not just the base: `next_poll_seconds` clamps a STARTING or STOPPING tick to
    ``POLL_PENDING_MIN_S`` and up, so an arm whose script never reaches UNKNOWN would still
    sleep a second per tick with only the base patched.
    """
    monkeypatch.setattr(state_mod, "POLL_BASE_S", 0.001)
    monkeypatch.setattr(state_mod, "POLL_PENDING_MIN_S", 0.001)
    monkeypatch.setattr(state_mod, "POLL_PENDING_MAX_S", 0.001)


def _scripted_reader(
    script: Sequence[ScmReading | BaseException | None],
) -> Callable[[str], ScmReading]:
    """SCM readings from a fixed script. ``None`` is the ordinary failing tick.

    An exception instance is raised as given, for the arms that need to vary the *cause*
    between ticks rather than just fail.

    Running dry calls `pytest.fail`, which raises a **BaseException** and so sails through
    `_run`'s ``except Exception`` supervisory boundary. A bare `next()` raises `StopIteration`,
    and that *is* an `Exception` -- so the boundary absorbs it, the loop publishes one more
    UNKNOWN and runs on, turning "this arm outran its script" into a runaway loop or a
    baffling state mismatch. That swallow already applied to a scripted reader before this
    branch, because `poll_once` has always been inside the guard.
    """
    remaining = iter(script)

    def reader(_name: str) -> ScmReading:
        try:
            reading = next(remaining)
        except StopIteration:
            pytest.fail("the poll loop asked for an unscripted SCM reading")
        if reading is None:
            raise OSError("QueryServiceStatusEx blew up")
        if isinstance(reading, BaseException):
            raise reading
        return reading

    return reader


def _scripted_clock(script: Sequence[float | None]) -> Callable[[], float]:
    """Monotonic readings from a fixed script; ``None`` raises, and running dry fails loudly.

    Same `pytest.fail` tail, for the same reason, and the clock is the case that made it
    necessary: once the clock read moves inside the supervisory boundary, a dry `next()` is
    caught rather than escaping the thread. Measured on this branch before that move, a forced
    fourth pass over a three-element clock left `_run` as `StopIteration`; the tail is what
    keeps a signal that loud after the boundary widens.
    """
    remaining = iter(script)

    def clock() -> float:
        try:
            value = next(remaining)
        except StopIteration:
            pytest.fail("the poll loop asked for an unscripted clock reading")
        if value is None:
            raise OSError("no monotonic clock")
        return value

    return clock


@contextmanager
def _looping_poller(
    scm_reader: Callable[[str], ScmReading],
    *,
    stop_after: int,
    clock: Callable[[], float] = time.monotonic,
    callback: Callable[[PollResult], None] | None = None,
) -> Iterator[tuple[StatusPoller, list[PollResult]]]:
    """A poller for driving `_run` on the calling thread, stopping after `stop_after` publishes.

    ``/health`` is dark and ``/ui`` unknown throughout, so a RUNNING service ages STARTING ->
    WEDGED across the script. The stop is armed from inside `on_update`, which runs *outside*
    the tick's guarded region, so arming it can never be mistaken for the tick failing --
    and it is armed before `callback` runs, so a callback that raises still ends the loop.
    """
    published: list[PollResult] = []
    client = httpx.Client(base_url=_ENGINE_URL)

    def on_update(result: PollResult) -> None:
        published.append(result)
        if len(published) >= stop_after:  # `>=`, so an unscripted extra tick still ends the loop
            poller._stop.set()
        if callback is not None:
            callback(result)

    poller = StatusPoller(
        TrayConfig(engine_url=_ENGINE_URL, service_name="MessageFoundry"),
        on_update=on_update,
        scm_reader=scm_reader,
        health_probe=lambda _c: HealthProbe.DOWN,
        ui_probe=lambda _c: UiProbe.UNKNOWN,
        clock=clock,
    )
    poller._client = client
    try:
        yield poller, published
    finally:
        client.close()


def _failure_detail(record: logging.LogRecord) -> str:
    """The exception a record carries, from whichever field survived the PHI `RedactionFilter`.

    Why that varies is set out on the `exc_info or exc_text` assertion in
    `test_poll_thread_survives_a_raising_tick_and_publishes_unknown` above.
    """
    if record.exc_text:
        return record.exc_text
    assert record.exc_info is not None
    return repr(record.exc_info[1])


def _faults(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The poller's own records at ERROR or above -- a failure it is claiming, not narrating."""
    return [r for r in caplog.records if r.name == _POLLER_LOGGER and r.levelno >= logging.ERROR]


def test_run_itself_does_not_fold_the_failed_tick_into_tracking(fast_poll: None) -> None:
    """Drive `_run`, because the arms above cannot see where the fallback is actually used.

    They call `_unknown_result()` directly, and that method cannot fold by construction -- so
    they all stay green if `_run` goes back to calling `advance` itself. This is the one arm that
    fails on that, and it is the regression this repair exists to prevent.
    """
    with _looping_poller(
        _scripted_reader([ScmReading(ScmState.RUNNING), None, ScmReading(ScmState.RUNNING)]),
        stop_after=3,
        clock=_scripted_clock([0.0, 10.0, 40.0]),
    ) as (poller, published):
        poller._run()

    assert [r.snapshot.state for r in published] == [
        TrayState.STARTING,  # t=0, inside the boot grace
        TrayState.UNKNOWN,  # t=10, the tick that raised
        TrayState.WEDGED,  # t=40, measured from t=0 because the failed tick held the anchor
    ]


def test_the_poll_thread_outlives_a_clock_that_raises(fast_poll: None) -> None:
    """The clock read opens the tick, so it belongs inside the supervisory boundary.

    `clock` is a public constructor dependency, ranking with the three probes: any caller may
    inject one, and with the read outside the guard one that raises ends the poll thread --
    the single failure this boundary exists to prevent. Production injects `time.monotonic`,
    which does not raise, so this arm is a control on the *claim* the module docstring makes,
    not on a live exposure. A control whose stated guarantee has a hole above it is worth no
    more than the hole.

    It also pins the other half: the failed tick must not reach `advance`, so t=40 is still
    measured from t=0 and the wedged engine is still reported as wedged.
    """
    # Two readings, not three: the clock raises before `poll_once` is entered on the middle
    # tick, so the reader is consulted twice. A spare reading would let an extra loop pass be
    # consumed silently, disarming the dry-script guard `_scripted_reader` exists to provide.
    with _looping_poller(
        _scripted_reader([ScmReading(ScmState.RUNNING)] * 2),
        stop_after=3,
        clock=_scripted_clock([0.0, None, 40.0]),  # the second tick's clock read blows up
    ) as (poller, published):
        poller._run()  # must return, not carry the injected clock's OSError out of the thread

    assert [r.snapshot.state for r in published] == [
        TrayState.STARTING,  # t=0, inside the boot grace
        TrayState.UNKNOWN,  # the clock raised: absorbed and published, not fatal
        TrayState.WEDGED,  # t=40 from t=0 -- the failed tick held the anchor
    ]


# --- a loop guard that never recovers must not flood tray.log ---------------


def test_a_permanently_failing_poll_backs_its_traceback_logging_off(
    fast_poll: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One traceback per tick is what collapses the rotation window, so emissions back off.

    The arithmetic -- cadence, log size, how long the window survives unthrottled -- is on
    `_FailureRun`, where the policy lives.
    """
    caplog.set_level(logging.ERROR, logger=_POLLER_LOGGER)

    with _looping_poller(_scripted_reader([None] * 10), stop_after=10) as (poller, published):
        poller._run()

    faults = _faults(caplog)
    assert len(published) == 10  # every tick still publishes UNKNOWN; only the logging backs off
    assert len(faults) == 4  # ticks 1, 2, 4 and 8 of the ten -- not one traceback each
    assert all(f.exc_info or f.exc_text for f in faults)  # each emitted one still carries a cause
    # The count is what makes the suppression legible: a reader seeing "8" knows the seven ticks
    # between this record and the last one are missing by design, not because nothing happened.
    assert "consecutive failures: 8" in faults[-1].getMessage()


def test_a_failing_update_callback_backs_off_the_same_way(
    fast_poll: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The callback guard shares the loop, the cadence and the log, so it shares the backoff.

    Throttling only the poll path would leave that path's guarantee resting on this sibling
    happening to be quiet: a callback that raises once (a torn-down window handle, an iconset
    that will not load) raises every tick, and rotates out the preserved evidence just as
    effectively as the poll path's own tracebacks would have.
    """
    caplog.set_level(logging.ERROR, logger=_POLLER_LOGGER)

    def boom(_result: PollResult) -> None:
        raise RuntimeError("the tray window handle is gone")

    with _looping_poller(
        _scripted_reader([ScmReading(ScmState.RUNNING)] * 10), stop_after=10, callback=boom
    ) as (poller, published):
        poller._run()

    faults = _faults(caplog)
    assert len(published) == 10  # the loop ran on: the callback guard is still a boundary
    assert len(faults) == 4  # and the same 1, 2, 4, 8 shape, not one traceback per tick
    assert "tray status callback raised" in faults[-1].getMessage()  # the callback, not the poll
    assert "consecutive failures: 8" in faults[-1].getMessage()


def test_a_recovered_poll_records_how_long_it_was_failing(
    fast_poll: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Why the recovery line exists is on `_FailureRun.clear`; this pins that it is emitted."""
    caplog.set_level(logging.INFO, logger=_POLLER_LOGGER)

    with _looping_poller(
        _scripted_reader([None, None, None, ScmReading(ScmState.RUNNING)]), stop_after=4
    ) as (poller, published):
        poller._run()

    assert published[-1].snapshot.state is not TrayState.UNKNOWN  # the poll really did recover
    # INFO exactly, not `>=`: the run's own ERROR tracebacks are not what this arm is reading.
    recoveries = [
        r.getMessage()
        for r in caplog.records
        if r.name == _POLLER_LOGGER and r.levelno == logging.INFO
    ]
    assert recoveries == ["tray status poll recovered after 3 consecutive failures"]


def test_a_new_failure_cause_is_never_suppressed_by_the_backoff(
    fast_poll: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A backoff that hid a *changed* cause behind an old one would be worse than no backoff.

    Five failing ticks: four alike, then a different one. The run-length threshold is at 8 by
    the fifth tick, so a purely count-based backoff would swallow the new cause -- the one
    record in the whole run that carries information the reader does not already have.
    """
    caplog.set_level(logging.ERROR, logger=_POLLER_LOGGER)

    script = [OSError("scm unreachable") for _ in range(4)] + [OSError("access denied")]
    with _looping_poller(_scripted_reader(script), stop_after=5) as (poller, _published):
        poller._run()

    faults = _faults(caplog)
    assert len(faults) == 4  # 1, 2 and 4 under the first cause, then 5 because the cause changed
    assert "access denied" in _failure_detail(faults[-1])
    assert "consecutive failures: 5" in faults[-1].getMessage()  # emitted early, not held to 8


def test_a_changed_cause_gets_its_own_schedule_not_the_old_one_s_position(
    fast_poll: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Emitting a new cause once and then going quiet is not "never held back".

    Eight failures of one cause, then four of another. The schedule counts failures of the
    *current cause*, so the second one is logged on its own 1st, 2nd and 4th. Were the position
    carried across the change instead, the new cause would be logged once and then suppressed
    for as many passes again as the old run had reached -- hundreds, deep in a long run -- which
    is the shape the never-hold-back rule exists to forbid.
    """
    caplog.set_level(logging.ERROR, logger=_POLLER_LOGGER)

    script = [OSError("scm unreachable") for _ in range(8)]
    script += [OSError("access denied") for _ in range(4)]
    with _looping_poller(_scripted_reader(script), stop_after=12) as (poller, _published):
        poller._run()

    faults = _faults(caplog)
    # Four under the first cause (its 1st, 2nd, 4th, 8th) and three under the second (1st, 2nd,
    # 4th), which fall at overall failures 9, 10 and 12. Carrying the position across the change
    # instead would stop this list at 9.
    counts = [int(f.getMessage().rsplit(": ", 1)[1].rstrip(")")) for f in faults]
    assert counts == [1, 2, 4, 8, 9, 10, 12]
    assert "access denied" in _failure_detail(faults[-1])  # and it is the new cause throughout


def test_a_callback_raising_after_stop_is_recorded_as_shutdown_not_as_a_fault(
    fast_poll: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The callback guard's twin of the poll guard's shutdown branch, for the same race.

    `stop()` can land between `_run`'s stop check and the callback call, and the callback then
    repaints a torn-down shell. Claiming a fault for that would write an ERROR traceback into
    tray.log on every clean exit -- which is exactly what the poll path's own stop branch was
    added to prevent, one screen up in the same function.
    """
    caplog.set_level(logging.DEBUG, logger=_POLLER_LOGGER)

    def boom(_result: PollResult) -> None:  # `stop_after=1` armed the stop before this ran
        raise RuntimeError("Cannot repaint, as the shell window has been destroyed.")

    with _looping_poller(
        _scripted_reader([ScmReading(ScmState.RUNNING)]), stop_after=1, callback=boom
    ) as (poller, _published):
        poller._run()

    records = [r for r in caplog.records if r.name == _POLLER_LOGGER]
    assert _faults(caplog) == []  # no fault claimed on a clean exit
    assert [r.levelno for r in records] == [logging.INFO]  # at a level tray.log actually writes
    assert "RuntimeError" in records[0].getMessage()  # the repr, so the cause survives


# --- a tick that outlives stop() must neither log nor publish ----------------


def _stopping_poller(
    reader: Callable[[str], ScmReading], published: list[PollResult]
) -> tuple[StatusPoller, httpx.Client]:
    client = httpx.Client(base_url=_ENGINE_URL)
    poller = StatusPoller(
        TrayConfig(engine_url=_ENGINE_URL, service_name="MessageFoundry"),
        on_update=published.append,
        scm_reader=reader,
        health_probe=lambda _c: HealthProbe.OK,
        ui_probe=lambda _c: UiProbe.ENABLED,
    )
    poller._client = client
    return poller, client


def test_a_tick_raising_after_stop_is_recorded_as_shutdown_not_as_a_fault(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`stop()` joins for 3s then closes the client; two probes at 2s each can outlast that.

    httpx then raises a bare RuntimeError, which `probe_health`/`probe_ui` do not catch (they
    catch only httpx.HTTPError). Claiming a fault for that would put an ERROR traceback in
    tray.log on every clean exit, and publishing it would repaint a torn-down shell after
    `run()` has returned. It is still recorded, at INFO: the branch is reached by *any*
    exception raised inside the join window, so a real defect there must not vanish. INFO and
    not DEBUG because `_setup_logging` pins the root logger to INFO and the tray offers no way
    to lower it -- a DEBUG record here would be a control that never fires.
    """
    caplog.set_level(logging.DEBUG, logger=_POLLER_LOGGER)
    published: list[PollResult] = []

    def reader(_name: str) -> ScmReading:
        poller._stop.set()  # stop() ran and closed the probe client under this in-flight tick
        raise RuntimeError("Cannot send a request, as the client has been closed.")

    poller, client = _stopping_poller(reader, published)
    try:
        poller._run()  # returns rather than looping; driven on this thread, so no race
    finally:
        client.close()

    records = [r for r in caplog.records if r.name == _POLLER_LOGGER]
    assert published == []  # nothing repainted after run() returned
    assert [r for r in records if r.levelno >= logging.ERROR] == []  # no fault claimed
    # Exactly one record, at a level tray.log actually writes, naming the exception. Asserting
    # the level pins the fix for the unreachable-DEBUG defect: a record below INFO is invisible.
    assert [r.levelno for r in records] == [logging.INFO]
    assert "RuntimeError" in records[0].getMessage()  # the repr, so the cause survives


def test_a_successful_tick_that_outlives_stop_does_not_publish() -> None:
    """The same guard for the commoner case: the probes finish, but `stop()` already returned."""
    published: list[PollResult] = []

    def reader(_name: str) -> ScmReading:
        poller._stop.set()
        return ScmReading(ScmState.RUNNING)

    poller, client = _stopping_poller(reader, published)
    try:
        poller._run()
    finally:
        client.close()

    assert published == []


def test_the_default_client_factory_carries_the_config_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pin reaches the probe client. Without it the tray would derive a pin and never use it."""
    seen: list[tuple[str, str | None]] = []

    def factory(url: str, *, cacert: str | None = None) -> httpx.Client:
        seen.append((url, cacert))
        return httpx.Client(base_url=url)

    monkeypatch.setattr("messagefoundry.tray.poller.make_probe_client", factory)
    poller = StatusPoller(
        TrayConfig(engine_url=_ENGINE_URL, engine_cacert="minted.pem"),
        on_update=lambda _r: None,
        scm_reader=lambda _n: ScmReading(ScmState.RUNNING),
        health_probe=lambda _c: HealthProbe.OK,
        ui_probe=lambda _c: UiProbe.ENABLED,
    )
    poller.start()
    poller.stop()
    assert seen == [(_ENGINE_URL, "minted.pem")]


def test_a_pin_minted_after_start_is_picked_up_without_a_restart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A tray started before the engine's first run rebuilds its client once the cert LOADS.

    The half-written step is the case keying on existence got wrong: the engine writes the file
    non-atomically, and an empty file exists but does not load.
    """
    from messagefoundry import pki

    pin = tmp_path / "api-generated-cert.pem"
    built: list[str | None] = []

    def factory(url: str, *, cacert: str | None = None) -> httpx.Client:
        built.append(cacert)
        return httpx.Client(base_url=url)

    monkeypatch.setattr("messagefoundry.tray.poller.make_probe_client", factory)
    poller = StatusPoller(
        TrayConfig(engine_url=_ENGINE_URL, engine_cacert=str(pin)),
        on_update=lambda _r: None,
        scm_reader=lambda _n: ScmReading(ScmState.RUNNING),
        health_probe=lambda _c: HealthProbe.OK,
        ui_probe=lambda _c: UiProbe.ENABLED,
    )
    poller._open_client()  # what start() does, minus the thread
    first = poller._client
    try:
        poller.poll_once(0.0)
        assert poller._client is first  # still waiting: no file, no rebuild
        pin.write_bytes(b"")
        poller.poll_once(1.0)
        assert poller._client is first  # half-written: the file exists but does not load
        pin.write_bytes(pki.make_self_signed("127.0.0.1", ["127.0.0.1"], 1)[0])
        poller.poll_once(2.0)
        assert poller._client is not first  # rebuilt once the pin loads
        rebuilt = poller._client
        poller.poll_once(3.0)
        assert poller._client is rebuilt  # and only once
    finally:
        if poller._client is not None:
            poller._client.close()
    assert len(built) == 2
