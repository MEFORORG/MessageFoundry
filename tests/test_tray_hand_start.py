# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A tray started by hand, measured with stand-ins (vault BACKLOG #2914).

Two hand starts reach ``pythonw.exe`` with no interpreter options: the ``messagefoundry-tray``
GUI-script launcher the installer writes, and ``pythonw -m messagefoundry.tray``. The real tray
is never started: the launcher is a throwaway one written into ``tmp_path`` by the same distlib
``ScriptMaker`` pip uses, and every start runs a stand-in that writes a marker file recording
whether it had a stderr. A click in Explorer or on a Start-menu shortcut is not measured here;
the launcher is started through ShellExecute, the shell call such a click makes, instead.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.tray import autostart

_WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="the tray is Windows-only")

#: At least these stop a pythonw start that has no stderr. Typed out rather than imported from the
#: branding tests, which measure the login command against them (vault BACKLOG #2852).
_NEEDS_A_STDERR = ("PYTHONFAULTHANDLER", "PYTHONDEVMODE")

_STAND_IN = "mf_tray_hand_start_stand_in"

#: The stand-in writes ``True`` here when it ran with no stderr, ``False`` when it had one.
_MARKER_VARIABLE = "MF_TRAY_HAND_START_MARKER"

_STAND_IN_SOURCE = (
    "import os, pathlib, sys\n"
    f"pathlib.Path(os.environ[{_MARKER_VARIABLE!r}])"
    ".write_text(repr(sys.stderr is None), encoding='utf-8')\n"
)

#: Each start's own budget. A test makes three starts, inside its own 120 s pytest timeout.
_START_TIMEOUT_S = 30

#: The outcomes a start can have: the stand-in did not run, or it ran with or without a stderr.
_DID_NOT_RUN, _RAN_WITH_NO_STDERR, _RAN_WITH_A_STDERR = "did not run", "no stderr", "a stderr"


def _pythonw() -> str:
    pythonw = autostart.pythonw_executable(sys.executable)
    if Path(pythonw).name.lower() != "pythonw.exe":
        pytest.skip("no pythonw.exe beside this interpreter")
    return pythonw


def _gui_script_launcher(tmp_path: Path, pythonw: str) -> str:
    """A throwaway GUI-script launcher, of the kind pip writes for ``[project.gui-scripts]``."""
    try:
        from pip._vendor.distlib.scripts import ScriptMaker
    except ImportError:
        pytest.skip("pip's distlib is not installed here, so no launcher can be written")
    target = tmp_path / "launcher"
    target.mkdir()
    # No ``executable``, as pip sets none: distlib derives the GUI interpreter from sys.executable.
    maker = ScriptMaker(None, str(target))
    maker.variants = {""}
    # The template's whole body is the stand-in, so the launcher imports nothing of ours.
    maker.script_template = _STAND_IN_SOURCE
    made = maker.make(f"{_STAND_IN} = unused:unused", options={"gui": True})
    exe = next((p for p in made if p.lower().endswith(".exe")), None)
    assert exe is not None, f"ScriptMaker wrote no launcher: {made}"
    assert os.fsencode(pythonw) in Path(exe).read_bytes(), "the launcher names another pythonw"
    return exe


def _environment(marker: Path, variable: str | None) -> dict[str, str]:
    """This process's environment with no other ``PYTHON*`` variable, so only ``variable`` acts."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PYTHON")}
    env[_MARKER_VARIABLE] = str(marker)
    if variable is not None:
        env[variable] = "1"
    return env


def _outcome(marker: Path, returncode: int, what: object) -> str:
    """What the stand-in did, read from its marker once the start has exited. The exit code must
    agree: 1 where the stand-in did not run, 0 where it did."""
    if not marker.is_file():
        assert returncode == 1, f"{what} exited {returncode} without running"
        return _DID_NOT_RUN
    assert returncode == 0, f"{what} ran and exited {returncode}"
    return (
        _RAN_WITH_NO_STDERR if marker.read_text(encoding="utf-8") == "True" else _RAN_WITH_A_STDERR
    )


def _run(command: list[str], cwd: Path, variable: str | None, *, inherit: bool) -> str:
    """Start ``command`` and wait for it. With ``inherit`` False no standard handle reaches it, as
    from a Run value; with it True the child inherits this process's handles, as from a terminal
    that hands its own on."""
    marker = cwd / "marker.txt"
    done = subprocess.run(  # noqa: S603 - this interpreter, our own command line
        command,
        cwd=cwd,
        env=_environment(marker, variable),
        close_fds=not inherit,
        timeout=_START_TIMEOUT_S,
        check=False,
    )
    return _outcome(marker, done.returncode, command)


#: Run by this interpreter: open argv[1] through ShellExecuteExW in folder argv[2], wait for the
#: process it starts, and print its exit code. The struct is the one ``service.py`` already uses.
_SHELL_EXECUTE_SOURCE = f"""
import ctypes, sys
from ctypes import wintypes
from messagefoundry.service import _SHELLEXECUTEINFOW
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32.ShellExecuteExW.argtypes = (ctypes.c_void_p,)
shell32.ShellExecuteExW.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, wintypes.LPDWORD)
kernel32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
info = _SHELLEXECUTEINFOW()
info.cbSize = ctypes.sizeof(info)
info.fMask = 0x40  # SEE_MASK_NOCLOSEPROCESS, so the start's process handle comes back
info.lpFile = sys.argv[1]
info.lpDirectory = sys.argv[2]
info.nShow = 1
if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
    sys.exit(f"ShellExecuteExW failed: {{ctypes.get_last_error()}}")
try:
    if kernel32.WaitForSingleObject(info.hProcess, {(_START_TIMEOUT_S - 5) * 1000}) != 0:
        kernel32.TerminateProcess(info.hProcess, 99)
        sys.exit("the start did not exit in time")
    code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    print(code.value)
finally:
    kernel32.CloseHandle(info.hProcess)
"""


def _shell_execute(launcher: str, cwd: Path, variable: str | None) -> str:
    """Start ``launcher`` through ShellExecuteExW, from a child that carries the environment.
    ShellExecute passes no standard handles on; the child's own are pipes, so it has a stderr
    whatever the variable."""
    marker = cwd / "marker.txt"
    done = subprocess.run(  # noqa: S603 - this interpreter, our own command line
        [sys.executable, "-c", _SHELL_EXECUTE_SOURCE, launcher, str(cwd)],
        env=_environment(marker, variable),
        capture_output=True,
        text=True,
        timeout=_START_TIMEOUT_S,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return _outcome(marker, int(done.stdout), f"ShellExecute of {launcher}")


def _gui_script(tmp_path: Path, variable: str | None) -> str:
    return _run([_gui_script_launcher(tmp_path, _pythonw())], tmp_path, variable, inherit=False)


def _pythonw_dash_m(tmp_path: Path, variable: str | None) -> str:
    (tmp_path / f"{_STAND_IN}.py").write_text(_STAND_IN_SOURCE, encoding="utf-8")
    return _run([_pythonw(), "-m", _STAND_IN], tmp_path, variable, inherit=False)


def _gui_script_through_shell_execute(tmp_path: Path, variable: str | None) -> str:
    return _shell_execute(_gui_script_launcher(tmp_path, _pythonw()), tmp_path, variable)


_NO_HANDLE_STARTS = [
    pytest.param(_gui_script, id="gui-script"),
    pytest.param(_pythonw_dash_m, id="pythonw-m"),
    pytest.param(_gui_script_through_shell_execute, id="gui-script-shell-execute"),
]


@_WINDOWS_ONLY
@pytest.mark.timeout(120)
@pytest.mark.parametrize("start", _NO_HANDLE_STARTS)
def test_a_hand_start_with_no_stderr_does_not_run_under_either_variable(
    tmp_path: Path, start: Callable[[Path, str | None], str]
) -> None:
    """Vault BACKLOG #2914: a hand start that has no stderr does not run the stand-in under either
    variable, and runs it when neither is set. ``docs/DANGEROUS-FUNCTIONALITY.md`` section 3 rests on
    this test. Each fresh ``tmp_path`` subfolder holds one start, so no state carries over.

    Skipped where the control shows the stand-in had a stderr anyway: such a host cannot show the
    defect, so a pass there would prove nothing. Under a variable a run is a failure, not a skip,
    because the control has already shown this start has no stderr."""
    (tmp_path / "control").mkdir()
    control = start(tmp_path / "control", None)
    if control == _RAN_WITH_A_STDERR:
        pytest.skip("this host gives the start a stderr, so it cannot show the exit")
    assert control == _RAN_WITH_NO_STDERR, f"the control: {control}"
    for variable in _NEEDS_A_STDERR:
        cwd = tmp_path / variable
        cwd.mkdir()
        assert start(cwd, variable) == _DID_NOT_RUN, f"it ran under {variable}"


@_WINDOWS_ONLY
@pytest.mark.timeout(120)
def test_pythonw_dash_m_with_inherited_handles_runs_under_either_variable(tmp_path: Path) -> None:
    """The contrast: ``pythonw -m`` that inherits this process's handles has a stderr and runs
    under each variable. Skipped where this process has no handles to hand on."""
    (tmp_path / f"{_STAND_IN}.py").write_text(_STAND_IN_SOURCE, encoding="utf-8")
    command = [_pythonw(), "-m", _STAND_IN]
    for variable in (None, *_NEEDS_A_STDERR):
        outcome = _run(command, tmp_path, variable, inherit=True)
        if variable is None and outcome == _RAN_WITH_NO_STDERR:
            pytest.skip("this process has no stderr to hand on")
        assert outcome == _RAN_WITH_A_STDERR, f"under {variable}: {outcome}"
