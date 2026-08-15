# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure tray context-menu builder (ADR 0113 §4).

``build_menu`` maps a :class:`~messagefoundry.tray.state.StatusSnapshot` (plus a few shell-supplied
availability flags) to an ordered list of :class:`MenuItem`. It is pure — no ctypes, no Qt —
so the whole enable/disable/order matrix is unit-testable on any OS. The Windows shell
(``winshell``) renders this list with ``TrackPopupMenuEx``; a double-click fires the ``default``
item.

The menu carries no workload data — only the status line, the two "open" actions, the three
guarded service actions, and lifecycle items. **Exit quits the tray only**; there is no menu
action that stops the engine except the explicit Stop/Restart items.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from messagefoundry.tray.state import StatusSnapshot, TrayState


class Action(StrEnum):
    """Stable action ids emitted by the menu; the shell dispatches on these, never on labels."""

    OPEN_CONSOLE = "open_console"
    OPEN_REPO = "open_repo"
    START = "start"
    STOP = "stop"
    RESTART = "restart"
    VIEW_LOG = "view_log"
    TOGGLE_AUTOSTART = "toggle_autostart"
    EDIT_SETTINGS = "edit_settings"
    EXIT = "exit"


@dataclass(frozen=True)
class MenuItem:
    """One rendered menu row. ``action is None`` marks a separator or a disabled status line."""

    label: str
    action: Action | None = None
    enabled: bool = True
    default: bool = False  # the bold double-click target
    checked: bool | None = None  # None = not checkable; bool = checkable + state
    separator: bool = False


_SEP = MenuItem(label="", separator=True, enabled=False)

_STATUS_LABEL = {
    TrayState.NOT_INSTALLED: "service not installed",
    TrayState.STOPPED: "Stopped",
    TrayState.STARTING: "Starting…",
    TrayState.RUNNING: "Running",
    TrayState.RUNNING_UNMANAGED: "Running (dev, not the service)",
    TrayState.STOPPING: "Stopping…",
    TrayState.WEDGED: "Unreachable (API not responding)",
    TrayState.FOREIGN: "Port in use by another program",
    TrayState.UNKNOWN: "Status unknown",
}


def status_line(snap: StatusSnapshot) -> str:
    """The disabled status row at the top of the menu."""
    label = _STATUS_LABEL[snap.state]
    if snap.state is TrayState.NOT_INSTALLED:
        return f"Engine: {label}"
    return f"Engine: {label} — {snap.service_name}"


def build_menu(
    snap: StatusSnapshot,
    *,
    autostart_enabled: bool,
    repo_open_available: bool,
    log_available: bool,
) -> list[MenuItem]:
    """Build the full context menu for a snapshot.

    Availability flags are shell concerns kept out of :class:`StatusSnapshot` (which is
    boundary-frozen): whether the ``code`` CLI + repo path resolved, and whether a log file is
    known. Service actions are disabled wholesale when ``monitor_only`` (a remote/https engine —
    ADR 0113 §5), and per-state otherwise.
    """
    st = snap.state
    control = not snap.monitor_only

    can_start = control and st is TrayState.STOPPED
    can_stop = control and st in (TrayState.RUNNING, TrayState.WEDGED, TrayState.STARTING)
    can_restart = control and st in (TrayState.RUNNING, TrayState.WEDGED)

    start_label = "Start Service"
    if st is TrayState.RUNNING_UNMANAGED:
        start_label = "Start Service (port in use)"

    items: list[MenuItem] = [
        MenuItem(label=status_line(snap), action=None, enabled=False),
        _SEP,
        MenuItem(
            label="Open Monitor Console"
            if snap.console_enabled
            else "Open Monitor Console (console not enabled)",
            action=Action.OPEN_CONSOLE,
            enabled=snap.console_enabled,
            default=True,
        ),
        MenuItem(
            label="Open Repo in VS Code"
            if repo_open_available
            else "Open Repo in VS Code (unavailable)",
            action=Action.OPEN_REPO,
            enabled=repo_open_available and not snap.monitor_only,
        ),
        _SEP,
    ]

    if st is TrayState.NOT_INSTALLED:
        # No service to control — collapse to a single non-actionable install hint.
        items.append(
            MenuItem(
                label="Install: scripts\\service\\install-service.ps1",
                action=None,
                enabled=False,
            )
        )
    else:
        items.extend(
            [
                MenuItem(label=start_label, action=Action.START, enabled=can_start),
                MenuItem(label="Stop Service", action=Action.STOP, enabled=can_stop),
                MenuItem(label="Restart Service", action=Action.RESTART, enabled=can_restart),
            ]
        )

    items.extend(
        [
            _SEP,
            MenuItem(label="View Service Log", action=Action.VIEW_LOG, enabled=log_available),
            MenuItem(
                label="Start at Login",
                action=Action.TOGGLE_AUTOSTART,
                checked=autostart_enabled,
            ),
            MenuItem(label="Edit Tray Settings", action=Action.EDIT_SETTINGS),
            _SEP,
            MenuItem(label="Exit", action=Action.EXIT),
        ]
    )
    return items


def assign_command_ids(
    items: list[MenuItem],
) -> tuple[list[tuple[MenuItem, int]], dict[int, Action]]:
    """Assign 1-based Win32 menu command ids to actionable items; 0 (non-selectable) to the rest.

    Pure, so the shell's id→action dispatch is testable without a real menu. ``TrackPopupMenuEx``
    returns the chosen id; :meth:`dict.get` on the mapping recovers the :class:`Action`.
    """
    rendered: list[tuple[MenuItem, int]] = []
    mapping: dict[int, Action] = {}
    next_id = 1
    for item in items:
        if item.separator or item.action is None or not item.enabled:
            rendered.append((item, 0))
            continue
        rendered.append((item, next_id))
        mapping[next_id] = item.action
        next_id += 1
    return rendered, mapping
