# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shell-adjacent seams (ADR 0113 §2/§4/§9): menu id mapping, autostart, single-instance, imports.

The ctypes message pump itself is Windows-only and covered by manual QA; here we pin the decidable
logic and prove the Windows modules import + construct their structs cleanly.
"""

from __future__ import annotations

import os
import sys

import pytest

from messagefoundry.tray.autostart import launcher_command, pythonw_executable
from messagefoundry.tray.menu import Action, assign_command_ids, build_menu
from messagefoundry.tray.state import StatusSnapshot, TrayState


def _snap(state: TrayState = TrayState.RUNNING) -> StatusSnapshot:
    return StatusSnapshot(
        state=state,
        service_name="MessageFoundry",
        engine_url="http://127.0.0.1:8765",
        console_enabled=True,
        monitor_only=False,
    )


def test_assign_command_ids_maps_actionable_items_only() -> None:
    items = build_menu(
        _snap(), autostart_enabled=False, repo_open_available=True, log_available=True
    )
    rendered, mapping = assign_command_ids(items)

    # Separators and the disabled status line get id 0; actionable items get unique 1-based ids.
    for item, cmd_id in rendered:
        if item.separator or item.action is None or not item.enabled:
            assert cmd_id == 0
        else:
            assert cmd_id >= 1
            assert mapping[cmd_id] is item.action

    ids = [cid for _it, cid in rendered if cid]
    assert ids == list(range(1, len(ids) + 1))  # contiguous, 1-based
    assert len(set(ids)) == len(ids)  # unique
    # A round-trip: the id TrackPopupMenuEx would return resolves back to the action.
    assert mapping[ids[0]] is Action.OPEN_CONSOLE


def test_disabled_action_is_not_dispatchable() -> None:
    # In NOT_INSTALLED the console is off and there are no service actions → nothing maps to them.
    snap = StatusSnapshot(
        state=TrayState.NOT_INSTALLED,
        service_name="MessageFoundry",
        engine_url="http://127.0.0.1:8765",
        console_enabled=False,
        monitor_only=False,
    )
    items = build_menu(
        snap, autostart_enabled=False, repo_open_available=False, log_available=False
    )
    _rendered, mapping = assign_command_ids(items)
    assert Action.START not in mapping.values()
    assert Action.OPEN_CONSOLE not in mapping.values()  # disabled → not selectable
    assert Action.EXIT in mapping.values()  # always available


def test_launcher_command_quotes_absolute_pythonw() -> None:
    cmd = launcher_command(r"C:\repo\.venv\Scripts\pythonw.exe")
    assert cmd == r'"C:\repo\.venv\Scripts\pythonw.exe" -m messagefoundry.tray'


def test_pythonw_executable_falls_back_to_given_path(tmp_path: object) -> None:
    # A python.exe with no sibling pythonw.exe → returns the python.exe itself (no crash).
    fake = r"C:\nowhere\python.exe"
    assert pythonw_executable(fake) == fake


def test_tray_windows_modules_import_and_build_structs() -> None:
    # Importing the shell/app/entry must not fail (validates the ctypes struct definitions load).
    import ctypes

    import messagefoundry.tray.__main__  # noqa: F401
    import messagefoundry.tray.app  # noqa: F401
    import messagefoundry.tray.instance  # noqa: F401
    import messagefoundry.tray.winshell as winshell

    # The NOTIFYICONDATAW / WNDCLASSEXW structs must be constructible with a sane cbSize.
    assert ctypes.sizeof(winshell._NOTIFYICONDATAW) > 0
    assert ctypes.sizeof(winshell._WNDCLASSEXW) > 0


@pytest.mark.skipif(sys.platform != "win32", reason="named mutex is Windows-only")
def test_single_instance_second_acquire_detects_running() -> None:
    from messagefoundry.tray.instance import SingleInstance

    # SLOT-SCOPED, because a named mutex is global to the Windows SESSION, not to this process. A
    # fixed name means any second pytest running concurrently -- an xdist sibling worker, or simply a
    # developer's run overlapping a CI-like run on the same box -- holds the mutex this test asserts
    # it can take, and the `is False` below then passes for the wrong reason while `is True` fails.
    # MEFOR_TEST_SLOT is unique per process under xdist (see tests/conftest.py) and falls back to the
    # serial default, so this is the same name as before on a single serial run.
    name = f"Local\\MessageFoundryTrayTest-{os.environ.get('MEFOR_TEST_SLOT', '0')}"
    first = SingleInstance(name)
    second = SingleInstance(name)
    try:
        assert first.acquire() is True
        assert second.acquire() is False  # first holds it
        assert second.already_running is True
    finally:
        first.release()
        second.release()
