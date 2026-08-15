# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tray context-menu builder (ADR 0113 §4) — pure, runs on any OS."""

from __future__ import annotations

import pytest

from messagefoundry.tray.menu import Action, build_menu, status_line
from messagefoundry.tray.state import StatusSnapshot, TrayState


def _snap(
    state: TrayState,
    *,
    console_enabled: bool = True,
    monitor_only: bool = False,
) -> StatusSnapshot:
    return StatusSnapshot(
        state=state,
        service_name="MessageFoundry",
        engine_url="http://127.0.0.1:8765",
        console_enabled=console_enabled,
        monitor_only=monitor_only,
    )


def _by_action(items: list, action: Action):  # type: ignore[no-untyped-def]
    return next((it for it in items if it.action is action), None)


def test_menu_order_and_default_for_running() -> None:
    items = build_menu(
        _snap(TrayState.RUNNING),
        autostart_enabled=False,
        repo_open_available=True,
        log_available=True,
    )
    actions = [it.action for it in items if not it.separator and it.action is not None]
    assert actions == [
        Action.OPEN_CONSOLE,
        Action.OPEN_REPO,
        Action.START,
        Action.STOP,
        Action.RESTART,
        Action.VIEW_LOG,
        Action.TOGGLE_AUTOSTART,
        Action.EDIT_SETTINGS,
        Action.EXIT,
    ]
    # Open Monitor Console is the bold double-click default.
    console = _by_action(items, Action.OPEN_CONSOLE)
    assert console is not None and console.default is True


@pytest.mark.parametrize(
    ("state", "can_start", "can_stop", "can_restart"),
    [
        (TrayState.STOPPED, True, False, False),
        (TrayState.RUNNING, False, True, True),
        (TrayState.WEDGED, False, True, True),
        (TrayState.STARTING, False, True, False),
        (TrayState.STOPPING, False, False, False),
        (TrayState.RUNNING_UNMANAGED, False, False, False),
    ],
)
def test_service_action_enablement(
    state: TrayState, can_start: bool, can_stop: bool, can_restart: bool
) -> None:
    items = build_menu(
        _snap(state), autostart_enabled=False, repo_open_available=True, log_available=True
    )
    assert _by_action(items, Action.START).enabled is can_start  # type: ignore[union-attr]
    assert _by_action(items, Action.STOP).enabled is can_stop  # type: ignore[union-attr]
    assert _by_action(items, Action.RESTART).enabled is can_restart  # type: ignore[union-attr]


def test_monitor_only_disables_all_control_and_repo() -> None:
    items = build_menu(
        _snap(TrayState.RUNNING, monitor_only=True),
        autostart_enabled=False,
        repo_open_available=True,
        log_available=True,
    )
    for act in (Action.START, Action.STOP, Action.RESTART, Action.OPEN_REPO):
        item = _by_action(items, act)
        assert item is not None and item.enabled is False
    # Console still opens for a remote engine.
    assert _by_action(items, Action.OPEN_CONSOLE).enabled is True  # type: ignore[union-attr]


def test_not_installed_shows_install_hint_and_no_service_actions() -> None:
    items = build_menu(
        _snap(TrayState.NOT_INSTALLED, console_enabled=False),
        autostart_enabled=False,
        repo_open_available=False,
        log_available=False,
    )
    assert _by_action(items, Action.START) is None
    assert _by_action(items, Action.STOP) is None
    assert _by_action(items, Action.RESTART) is None
    labels = [it.label for it in items if not it.separator]
    assert any("install-service.ps1" in lb for lb in labels)


def test_console_disabled_when_serve_ui_off() -> None:
    items = build_menu(
        _snap(TrayState.RUNNING, console_enabled=False),
        autostart_enabled=False,
        repo_open_available=True,
        log_available=True,
    )
    console = _by_action(items, Action.OPEN_CONSOLE)
    assert console is not None and console.enabled is False
    assert "not enabled" in console.label


def test_autostart_checkbox_reflects_state() -> None:
    on = build_menu(
        _snap(TrayState.RUNNING),
        autostart_enabled=True,
        repo_open_available=True,
        log_available=True,
    )
    assert _by_action(on, Action.TOGGLE_AUTOSTART).checked is True  # type: ignore[union-attr]
    off = build_menu(
        _snap(TrayState.RUNNING),
        autostart_enabled=False,
        repo_open_available=True,
        log_available=True,
    )
    assert _by_action(off, Action.TOGGLE_AUTOSTART).checked is False  # type: ignore[union-attr]


def test_exit_never_maps_to_a_control_action() -> None:
    # Exit quits the tray only (ADR 0113 §4): the only service-affecting actions are Stop/Restart.
    items = build_menu(
        _snap(TrayState.RUNNING),
        autostart_enabled=False,
        repo_open_available=True,
        log_available=True,
    )
    exit_item = _by_action(items, Action.EXIT)
    assert exit_item is not None and exit_item.action is Action.EXIT
    control_actions = {Action.START, Action.STOP, Action.RESTART}
    assert Action.EXIT not in control_actions


def test_status_line_includes_service_name_except_when_not_installed() -> None:
    assert "MessageFoundry" in status_line(_snap(TrayState.RUNNING))
    assert "MessageFoundry" not in status_line(_snap(TrayState.NOT_INSTALLED))
