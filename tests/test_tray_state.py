"""Tray status state machine (ADR 0113 §3) — pure, runs on any OS."""

from __future__ import annotations

import pytest

from messagefoundry.tray.state import (
    BOOT_GRACE_S,
    POLL_BASE_S,
    HealthProbe,
    ProbeInputs,
    ScmState,
    TrayState,
    UiProbe,
    derive_state,
    next_poll_seconds,
    tooltip,
    transition_toast,
)


@pytest.mark.parametrize(
    ("scm", "health", "expected"),
    [
        (ScmState.RUNNING, HealthProbe.OK, TrayState.RUNNING),
        (ScmState.STOPPED, HealthProbe.DOWN, TrayState.STOPPED),
        (ScmState.NOT_INSTALLED, HealthProbe.DOWN, TrayState.NOT_INSTALLED),
        (ScmState.STOP_PENDING, HealthProbe.OK, TrayState.STOPPING),
        # A dev `serve` on the port with the service stopped / absent → RUNNING_UNMANAGED.
        (ScmState.STOPPED, HealthProbe.OK, TrayState.RUNNING_UNMANAGED),
        (ScmState.NOT_INSTALLED, HealthProbe.OK, TrayState.RUNNING_UNMANAGED),
        # A non-MessageFoundry responder on the port is FOREIGN in every SCM state.
        (ScmState.RUNNING, HealthProbe.FOREIGN, TrayState.FOREIGN),
        (ScmState.STOPPED, HealthProbe.FOREIGN, TrayState.FOREIGN),
        (ScmState.NOT_INSTALLED, HealthProbe.FOREIGN, TrayState.FOREIGN),
        # SCM unqueryable: fall back to the API probe.
        (ScmState.UNAVAILABLE, HealthProbe.OK, TrayState.RUNNING_UNMANAGED),
        (ScmState.UNAVAILABLE, HealthProbe.FOREIGN, TrayState.FOREIGN),
        (ScmState.UNAVAILABLE, HealthProbe.DOWN, TrayState.UNKNOWN),
    ],
)
def test_derive_state_basic(scm: ScmState, health: HealthProbe, expected: TrayState) -> None:
    assert derive_state(ProbeInputs(scm=scm, health=health)) is expected


def test_running_but_silent_within_grace_is_starting() -> None:
    p = ProbeInputs(
        scm=ScmState.RUNNING, health=HealthProbe.DOWN, running_elapsed_s=BOOT_GRACE_S - 1
    )
    assert derive_state(p) is TrayState.STARTING


def test_running_but_silent_past_grace_is_wedged() -> None:
    p = ProbeInputs(
        scm=ScmState.RUNNING, health=HealthProbe.DOWN, running_elapsed_s=BOOT_GRACE_S + 1
    )
    assert derive_state(p) is TrayState.WEDGED


def test_running_silent_with_no_elapsed_is_wedged() -> None:
    # No grace clock available → do not mask a dead API as "starting".
    p = ProbeInputs(scm=ScmState.RUNNING, health=HealthProbe.DOWN, running_elapsed_s=None)
    assert derive_state(p) is TrayState.WEDGED


def test_start_pending_advancing_is_starting() -> None:
    p = ProbeInputs(
        scm=ScmState.START_PENDING,
        health=HealthProbe.DOWN,
        checkpoint_advancing=True,
        pending_elapsed_s=100.0,
        wait_hint_s=5.0,
    )
    assert derive_state(p) is TrayState.STARTING


def test_start_pending_stuck_is_wedged() -> None:
    p = ProbeInputs(
        scm=ScmState.START_PENDING,
        health=HealthProbe.DOWN,
        checkpoint_advancing=False,
        pending_elapsed_s=30.0,
        wait_hint_s=5.0,
    )
    assert derive_state(p) is TrayState.WEDGED


def test_start_pending_stuck_but_within_wait_hint_is_starting() -> None:
    p = ProbeInputs(
        scm=ScmState.START_PENDING,
        health=HealthProbe.DOWN,
        checkpoint_advancing=False,
        pending_elapsed_s=2.0,
        wait_hint_s=5.0,
    )
    assert derive_state(p) is TrayState.STARTING


def test_next_poll_seconds_base_and_pending() -> None:
    assert next_poll_seconds(TrayState.RUNNING) == POLL_BASE_S
    assert next_poll_seconds(TrayState.STOPPED) == POLL_BASE_S
    # waitHint/10, clamped to [1, 10].
    assert next_poll_seconds(TrayState.STARTING, wait_hint_s=30.0) == 3.0
    assert next_poll_seconds(TrayState.STARTING, wait_hint_s=5.0) == 1.0  # clamp floor
    assert next_poll_seconds(TrayState.STOPPING, wait_hint_s=1000.0) == 10.0  # clamp ceiling
    assert next_poll_seconds(TrayState.STARTING, wait_hint_s=None) == POLL_BASE_S


def test_transition_toast_only_on_meaningful_edges() -> None:
    assert transition_toast(TrayState.RUNNING, TrayState.RUNNING) is None
    up = transition_toast(TrayState.STARTING, TrayState.RUNNING)
    assert up is not None and "running" in up.body.lower()
    down = transition_toast(TrayState.RUNNING, TrayState.STOPPED)
    assert down is not None and "stopped" in down.body.lower()
    wedged = transition_toast(TrayState.RUNNING, TrayState.WEDGED)
    assert wedged is not None and "unreachable" in wedged.body.lower()
    # Transient pending transitions do not toast.
    assert transition_toast(TrayState.RUNNING, TrayState.STOPPING) is None
    assert transition_toast(TrayState.STOPPED, TrayState.STARTING) is None


def test_tooltip_covers_every_state_and_is_bounded() -> None:
    for st in TrayState:
        tip = tooltip(st)
        assert tip.startswith("MessageFoundry")
        assert len(tip) <= 128


def test_ui_probe_field_is_carried_but_does_not_alter_liveness_state() -> None:
    # The /ui probe drives the menu, not the status icon: same state regardless of UiProbe.
    base = ProbeInputs(scm=ScmState.RUNNING, health=HealthProbe.OK, ui=UiProbe.DISABLED)
    enabled = ProbeInputs(scm=ScmState.RUNNING, health=HealthProbe.OK, ui=UiProbe.ENABLED)
    assert derive_state(base) is derive_state(enabled) is TrayState.RUNNING
