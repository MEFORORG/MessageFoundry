# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shell-adjacent seams (ADR 0113 §2/§4/§9): menu id mapping, autostart, single-instance, imports.

The ctypes message pump itself is Windows-only and covered by manual QA; here we pin the decidable
logic and prove the Windows modules import + construct their structs cleanly.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from messagefoundry import _child_bootstrap
from messagefoundry.childenv import python_child_argv
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


@pytest.mark.parametrize(
    ("pythonw", "written"),
    [
        (r"C:\repo\.venv\Scripts\pythonw.exe", r"C:\repo\.venv\Scripts\pythonw.exe"),
        (r"C:\Program Files\Py\pythonw.exe", r'"C:\Program Files\Py\pythonw.exe"'),
    ],
)
def test_launcher_command_starts_the_tray_through_the_bootstrap(pythonw: str, written: str) -> None:
    """Vault BACKLOG #2822: the login command starts the first tray process like the engine's own
    Python children, so no working directory leads its import path. The flags are typed out rather
    than read from childenv, so the test does not check a list against itself."""
    bootstrap = subprocess.list2cmdline([str(Path(_child_bootstrap.__file__).resolve())])
    assert launcher_command(pythonw) == (
        f"{written} -P -X disable-remote-debug {bootstrap} messagefoundry.tray"
    )


def _windows_argv(command_line: str) -> list[str]:
    """``command_line`` split by Windows' own parser, ``CommandLineToArgvW``. A local copy: the one
    in ``tests/test_provision_first_administrator.py`` sits in a module that imports the CLI, the
    store and auth, which a tray test has no reason to load."""
    if sys.platform != "win32":  # the skipif already guarantees it; this narrows mypy's linux pass
        pytest.skip("Win32 only")
    import ctypes
    from ctypes import wintypes

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    shell32.CommandLineToArgvW.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int))
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
    count = ctypes.c_int()
    parsed = shell32.CommandLineToArgvW(command_line, ctypes.byref(count))
    assert parsed, ctypes.get_last_error()
    try:
        return [parsed[i] for i in range(count.value)]
    finally:
        kernel32.LocalFree(ctypes.cast(parsed, wintypes.HLOCAL))


@pytest.mark.skipif(sys.platform != "win32", reason="the Run key and its parser are Windows-only")
@pytest.mark.parametrize(
    "pythonw",
    [r"C:\Program Files\Python 3.14\pythonw.exe", r"C:\repo\.venv\Scripts\pythonw.exe"],
)
def test_windows_reads_the_launcher_command_back_as_the_child_command_line(pythonw: str) -> None:
    """Windows splits the Run-key string into exactly the argument list a child gets, with a space
    in a path and without one."""
    assert _windows_argv(launcher_command(pythonw)) == python_child_argv(
        "messagefoundry.tray", executable=pythonw
    )


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
