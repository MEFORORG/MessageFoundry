# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A tray started by hand, measured with stand-ins (vault BACKLOG #2914).

Two hand starts reach ``pythonw.exe`` with no interpreter options: the ``messagefoundry-tray``
GUI-script launcher the installer writes, and ``pythonw -m messagefoundry.tray`` typed by hand.
The real tray is never started: the launcher is a throwaway one written into ``tmp_path`` by
the same distlib ``ScriptMaker`` pip uses, and both starts run a stand-in that only writes a
marker file. A start from Explorer or a Start-menu shortcut is not measured here.
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

#: Typed out rather than imported from the branding tests, so each file states what it measures.
_NEEDS_A_STDERR = ("PYTHONFAULTHANDLER", "PYTHONDEVMODE")

_STAND_IN = "mf_tray_hand_start_stand_in"

#: The stand-in writes this file, so a zero exit code is not read as "the code ran" on its own.
_MARKER_VARIABLE = "MF_TRAY_HAND_START_MARKER"

_STAND_IN_SOURCE = (
    "import os, pathlib\n"
    f"pathlib.Path(os.environ[{_MARKER_VARIABLE!r}]).write_text('ran', encoding='utf-8')\n"
)


def _pythonw() -> str:
    pythonw = autostart.pythonw_executable(sys.executable)
    if Path(pythonw).name.lower() != "pythonw.exe":
        pytest.skip("no pythonw.exe beside this interpreter")
    return pythonw


def _gui_script_launcher(tmp_path: Path, pythonw: str) -> list[str]:
    """A throwaway GUI-script launcher, of the kind pip writes for ``[project.gui-scripts]``."""
    try:
        from pip._vendor.distlib.scripts import ScriptMaker
    except ImportError:
        pytest.skip("pip's distlib is not installed here, so no launcher can be written")
    target = tmp_path / "launcher"
    target.mkdir()
    maker = ScriptMaker(None, str(target))
    # Given python.exe, as pip gives it; for a GUI script distlib names pythonw.exe in the shebang.
    # distlib's class attribute is a bare ``executable = None``, so mypy infers ``None`` for it.
    maker.executable = str(Path(pythonw).with_name("python.exe"))  # type: ignore[assignment]
    maker.variants = {""}
    # The template's whole body is the stand-in, so the launcher imports nothing of ours.
    maker.script_template = _STAND_IN_SOURCE
    made = maker.make(f"{_STAND_IN} = unused:unused", options={"gui": True})
    exe = next((p for p in made if p.lower().endswith(".exe")), None)
    assert exe is not None, f"ScriptMaker wrote no launcher: {made}"
    shebang = b"#!" + os.fsencode(pythonw) + b"\n"
    assert shebang in Path(exe).read_bytes(), "the launcher does not start this pythonw.exe"
    return [exe]


def _pythonw_dash_m(tmp_path: Path, pythonw: str) -> list[str]:
    """``pythonw -m <module>`` typed by hand; the working directory puts the stand-in on the path."""
    (tmp_path / f"{_STAND_IN}.py").write_text(_STAND_IN_SOURCE, encoding="utf-8")
    return [pythonw, "-m", _STAND_IN]


def _marked_exit_code(command: list[str], cwd: Path, variable: str | None) -> int:
    """Run ``command`` with no stdin, stdout or stderr argument, and return its exit code.

    A GUI-subsystem child such as ``pythonw.exe`` then gets no standard handles, as it does from a
    Run value. The marker file says whether the stand-in ran."""
    marker = cwd / "marker.txt"
    marker.unlink(missing_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PYTHON")}
    env[_MARKER_VARIABLE] = str(marker)
    if variable is not None:
        env[variable] = "1"
    done = subprocess.run(  # noqa: S603 - this interpreter, our own command line
        command, cwd=cwd, env=env, timeout=60, check=False
    )
    ran = marker.is_file()
    assert ran == (done.returncode == 0), f"exit {done.returncode}, stand-in ran: {ran}"
    return done.returncode


@_WINDOWS_ONLY
@pytest.mark.parametrize("variable", _NEEDS_A_STDERR)
@pytest.mark.parametrize(
    "make",
    [
        pytest.param(_gui_script_launcher, id="gui-script"),
        pytest.param(_pythonw_dash_m, id="pythonw-m"),
    ],
)
def test_a_hand_start_with_no_std_handles_exits_1_before_any_code_under_the_variable(
    tmp_path: Path, make: Callable[[Path, str], list[str]], variable: str
) -> None:
    """Vault BACKLOG #2914: with either variable set, a hand start that has no stderr exits 1
    before the stand-in runs. With neither set, the control, the same start runs it.
    ``docs/DANGEROUS-FUNCTIONALITY.md`` section 3 rests on this test.

    Skipped where the start runs anyway under the variable. A host that hands ``pythonw.exe`` a
    stderr even when the parent passes none would do that, and such a host cannot show the exit,
    so a pass there would prove nothing."""
    command = make(tmp_path, _pythonw())
    assert _marked_exit_code(command, tmp_path, None) == 0, "the control failed"
    code = _marked_exit_code(command, tmp_path, variable)
    if code == 0:
        pytest.skip(f"{command} runs here under {variable}; this host gives pythonw a stderr")
    assert code == 1, f"{command} exited {code} under {variable}"
