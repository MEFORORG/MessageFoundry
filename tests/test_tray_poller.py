"""Tray poller (ADR 0113 §3): pure `advance` timing + the poller's transition/toast logic."""

from __future__ import annotations

from collections.abc import Iterator

import httpx

from messagefoundry.tray.config import TrayConfig
from messagefoundry.tray.poller import StatusPoller, Tracking, advance
from messagefoundry.tray.state import HealthProbe, ScmState, TrayState, UiProbe
from messagefoundry.tray.winsvc import ScmReading

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
    # Checkpoint advanced (1 → 2): still advancing.
    r_b = ScmReading(ScmState.START_PENDING, checkpoint=2, wait_hint_s=5.0)
    t2, in2 = advance(t1, r_b, HealthProbe.DOWN, UiProbe.UNKNOWN, 3.0)
    assert in2.checkpoint_advancing is True
    assert in2.pending_elapsed_s == 3.0
    # Checkpoint stalled (2 → 2): not advancing.
    t3, in3 = advance(t2, r_b, HealthProbe.DOWN, UiProbe.UNKNOWN, 6.0)
    assert in3.checkpoint_advancing is False
    assert in3.pending_elapsed_s == 6.0


# --- StatusPoller transition/toast logic ------------------------------------


def _scripted_poller(
    scm: list[ScmReading],
    health: list[HealthProbe],
    ui: list[UiProbe],
) -> tuple[StatusPoller, httpx.Client]:
    scm_it: Iterator[ScmReading] = iter(scm)
    health_it: Iterator[HealthProbe] = iter(health)
    ui_it: Iterator[UiProbe] = iter(ui)
    cfg = TrayConfig(engine_url="http://127.0.0.1:8765", service_name="MessageFoundry")

    def reader(_name: str) -> ScmReading:
        return next(scm_it)

    def hp(_c: httpx.Client) -> HealthProbe:
        return next(health_it)

    def up(_c: httpx.Client) -> UiProbe:
        return next(ui_it)

    def on_update(_r: object) -> None:
        return None

    poller = StatusPoller(
        cfg,
        on_update=on_update,
        scm_reader=reader,
        health_probe=hp,
        ui_probe=up,
    )
    dummy = httpx.Client(base_url="http://127.0.0.1:8765")
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
