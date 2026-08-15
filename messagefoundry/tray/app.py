# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Wires the tray together (ADR 0113): poller → icon/menu, menu actions → open/control.

The pure modules decide *what* to render and *what* an action means; this class connects them to the
Windows shell. It holds the latest :class:`~messagefoundry.tray.poller.PollResult` (updated from the poll thread,
read from the UI thread under a lock), maps it to an icon + tooltip + menu, and routes menu actions
to :mod:`tray.actions` (open console/repo/log) and :mod:`tray.control` (guarded service control).
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
import threading
from pathlib import Path

from messagefoundry.tray import actions, autostart, control
from messagefoundry.tray.config import TrayConfig, default_config_dir, ensure_tray_toml
from messagefoundry.tray.iconset import icon_path
from messagefoundry.tray.menu import Action, MenuItem, build_menu
from messagefoundry.tray.poller import PollResult, StatusPoller
from messagefoundry.tray.state import StatusSnapshot, TrayState
from messagefoundry.tray.theme import detect_theme
from messagefoundry.tray.winshell import TrayShell

log = logging.getLogger("messagefoundry.tray.app")

_MB_YESNO = 0x00000004
_MB_ICONWARNING = 0x00000030
_IDYES = 6


def _confirm(text: str, title: str = "MessageFoundry") -> bool:
    """A modal Yes/No confirm. Windows-only; returns True elsewhere (no gate in tests)."""
    if sys.platform != "win32":
        return True
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    return int(user32.MessageBoxW(None, text, title, _MB_YESNO | _MB_ICONWARNING)) == _IDYES


class TrayApp:
    """The tray application object: owns the poller and the shell, routes updates and actions."""

    def __init__(self, config: TrayConfig, config_dir: Path | None = None) -> None:
        self._config = config
        self._config_dir = config_dir or default_config_dir()
        self._lock = threading.Lock()
        self._snapshot = StatusSnapshot(
            state=TrayState.UNKNOWN,
            service_name=config.service_name,
            engine_url=config.engine_url,
            console_enabled=False,
            monitor_only=config.monitor_only,
        )
        self._vscode = actions.resolve_vscode()
        self._shell = TrayShell(
            on_menu=self._build_menu,
            on_action=self._on_action,
            on_double_click=self._open_console,
            on_theme_change=self._repaint,
        )
        self._poller = StatusPoller(config, on_update=self._on_update)

    # --- lifecycle ---

    def run(self) -> None:
        self._poller.start()
        try:
            self._shell.run(self._icon_for(self._snapshot.state), self._tooltip(self._snapshot))
        finally:
            self._poller.stop()

    # --- poller → shell ---

    def _on_update(self, result: PollResult) -> None:
        with self._lock:
            self._snapshot = result.snapshot
        self._shell.request_update(
            self._icon_for(result.snapshot.state), self._tooltip(result.snapshot)
        )
        if result.toast is not None:
            self._shell.request_notify(result.toast.title, result.toast.body)

    def _repaint(self) -> None:
        with self._lock:
            snapshot = self._snapshot
        self._shell.request_update(self._icon_for(snapshot.state), self._tooltip(snapshot))

    def _icon_for(self, state: TrayState) -> Path:
        return icon_path(state, detect_theme())

    def _tooltip(self, snapshot: StatusSnapshot) -> str:
        from messagefoundry.tray.state import tooltip

        return tooltip(snapshot.state)

    # --- menu ---

    def _build_menu(self) -> list[MenuItem]:
        with self._lock:
            snapshot = self._snapshot
        return build_menu(
            snapshot,
            autostart_enabled=autostart.is_autostart_enabled(),
            repo_open_available=actions.repo_open_available(self._config.repo_path, self._vscode),
            log_available=actions.log_available(self._config.log_path),
        )

    # --- actions ---

    def _on_action(self, action: Action) -> None:
        if action is Action.OPEN_CONSOLE:
            self._open_console()
        elif action is Action.OPEN_REPO:
            self._open_repo()
        elif action in (Action.START, Action.STOP, Action.RESTART):
            self._service_action(action.value)
        elif action is Action.VIEW_LOG:
            self._view_log()
        elif action is Action.TOGGLE_AUTOSTART:
            autostart.set_autostart(not autostart.is_autostart_enabled())
        elif action is Action.EDIT_SETTINGS:
            self._edit_settings()
        elif action is Action.EXIT:
            self._shell.request_quit()

    def _open_console(self) -> None:
        actions.open_console(self._config.engine_url)

    def _open_repo(self) -> None:
        if self._config.repo_path and self._vscode:
            actions.open_repo(self._config.repo_path, self._vscode)

    def _view_log(self) -> None:
        if self._config.log_path:
            actions.open_log(self._config.log_path)

    def _service_action(self, action: str) -> None:
        if control.needs_confirm(action) and not _confirm(
            control.confirm_text(action, self._config.service_name)
        ):
            return
        outcome = control.perform(action, self._config.service_name)
        toast = control.outcome_toast(action, outcome)
        if toast is not None:
            self._shell.request_notify(toast.title, toast.body)

    def _edit_settings(self) -> None:
        # Write a commented template on first use so the operator opens a self-documenting file
        # (repo_path, engine_url, …) rather than an empty folder.
        path = ensure_tray_toml(self._config_dir)
        if sys.platform == "win32":
            os.startfile(str(path))  # nosec B606 - opens the tray.toml in the user's default editor
