# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Branded launcher (ADR 0113): pure VS_VERSIONINFO structure + the Windows round-trip."""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import messagefoundry
from messagefoundry import _child_bootstrap
from messagefoundry.tray import autostart, branding


def test_build_version_info_is_self_consistent() -> None:
    data = branding.build_version_info()
    # The top VS_VERSIONINFO wLength (first WORD) must equal the whole block length.
    (wlength,) = struct.unpack("<H", data[:2])
    assert wlength == len(data)
    # VS_FIXEDFILEINFO signature and the branded strings (stored UTF-16LE) must be present.
    assert struct.pack("<I", 0xFEEF04BD) in data
    assert branding.FILE_DESCRIPTION.encode("utf-16-le") in data
    assert "FileDescription".encode("utf-16-le") in data
    assert "MessageFoundry".encode("utf-16-le") in data


def test_is_branded_process(monkeypatch: pytest.MonkeyPatch) -> None:
    # Forward slashes so pathlib extracts the basename on any OS (Linux PosixPath does not split
    # on backslashes) — this pure test runs on every CI leg.
    monkeypatch.setattr(sys, "executable", "/opt/app/MessageFoundryTray.exe")
    assert branding.is_branded_process() is True
    monkeypatch.setattr(sys, "executable", "/opt/app/pythonw.exe")
    assert branding.is_branded_process() is False


def test_off_windows_is_fail_soft(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert branding.ensure_branded_launcher() is None
    assert branding.read_file_description(Path("nope.exe")) is None


def test_relaunch_returns_false_when_branding_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(branding, "ensure_branded_launcher", lambda *a, **k: None)
    assert branding.relaunch_branded() is False


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("0.1.0", (0, 1, 0, 0)),
        ("1.0.0rc1", (1, 0, 0, 0)),  # leading digit run only → pre-release maps to its base
        ("0.1.0-rc1", (0, 1, 0, 0)),
        ("70000.1.2.3", (0xFFFF, 1, 2, 3)),  # clamped to 16 bits → no struct.pack overflow
        ("", (0, 0, 0, 0)),
    ],
)
def test_version_tuple_normalizes(
    monkeypatch: pytest.MonkeyPatch, version: str, expected: tuple[int, int, int, int]
) -> None:
    monkeypatch.setattr(branding, "__version__", version)
    assert branding._version_tuple() == expected
    assert len(branding.build_version_info()) > 0  # never raises on any of these


def test_relaunch_falls_back_when_child_dies_immediately(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exe = tmp_path / branding.BRANDED_EXE_NAME
    exe.write_bytes(b"")
    monkeypatch.setattr(branding, "ensure_branded_launcher", lambda *a, **k: exe)

    class _Dead:
        returncode = 9

        def wait(self, timeout: float | None = None) -> int:
            return 9  # already exited

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: _Dead())
    assert branding.relaunch_branded() is False  # child died → parent must run unbranded


def test_relaunch_hands_over_to_a_child_started_like_every_other_python_child(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A child still alive after the grace window owns the tray. Vault BACKLOG #2801: it starts
    through the same command line as the engine's own children, ``-P`` and bootstrap included."""
    exe = tmp_path / branding.BRANDED_EXE_NAME
    exe.write_bytes(b"")
    monkeypatch.setattr(branding, "ensure_branded_launcher", lambda *a, **k: exe)
    # A relative entry names the working directory and would undo -P; an absolute one stays.
    kept = str(tmp_path / "site")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([".", kept]))
    monkeypatch.setenv("MF_2801_ORDINARY", "crosses")
    started: list[tuple[Any, dict[str, Any]]] = []

    class _Alive:
        returncode = None

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired("cmd", timeout or 0)

    def _popen(argv: Any, **kwargs: Any) -> _Alive:
        started.append((argv, kwargs))
        return _Alive()

    monkeypatch.setattr(subprocess, "Popen", _popen)
    assert branding.relaunch_branded() is True  # still alive → the child owns the tray

    [(argv, kwargs)] = started
    # Typed out rather than read from childenv, so the test does not check a list against itself.
    assert argv[:4] == [str(exe), "-P", "-X", "disable-remote-debug"]
    assert Path(argv[4]) == Path(_child_bootstrap.__file__).resolve()
    assert argv[5:] == ["messagefoundry.tray"]
    env = kwargs["env"]
    assert env["PYTHONPATH"] == kept
    assert env["MF_2801_ORDINARY"] == "crosses"  # the tray keeps the user's environment


# --- Real children through the bootstrap (vault BACKLOG #2822) -----------------------------------
#
# A broken bootstrap does not fail the tray loudly: the branded child dies inside the grace window
# and the first process runs the tray unbranded. So these start real interpreters. Each runs a
# trivial module in place of the tray, from a working directory holding a decoy `messagefoundry`
# package, and reports what it saw. A `-m` start would import the decoy and exit nonzero.

_PROBE_MODULE = "mf_2822_tray_probe"
_PROBE_SOURCE = """\
import json, sys
import messagefoundry
with open(sys.argv[1], "w", encoding="utf-8") as out:
    json.dump({"executable": sys.executable, "safe_path": sys.flags.safe_path,
               "remote_debug": sys.is_remote_debug_enabled(), "package": messagefoundry.__file__},
              out)
"""


def _probe_layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    """The probe's folder, a working directory with a decoy package in it, and the report path."""
    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    (probe_dir / f"{_PROBE_MODULE}.py").write_text(_PROBE_SOURCE, encoding="utf-8")
    cwd = tmp_path / "cwd"
    decoy = cwd / "messagefoundry"
    decoy.mkdir(parents=True)
    (decoy / "__init__.py").write_text("raise SystemExit('the decoy answered')\n", encoding="utf-8")
    return probe_dir, cwd, tmp_path / "report.json"


def _assert_started_through_the_bootstrap(report: Path) -> dict[str, Any]:
    seen: dict[str, Any] = json.loads(report.read_text(encoding="utf-8"))
    assert Path(seen["package"]).resolve() == Path(messagefoundry.__file__).resolve()
    assert seen["safe_path"] is True
    assert seen["remote_debug"] is False
    return seen


_WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="the tray is Windows-only")


@_WINDOWS_ONLY
def test_the_login_command_starts_a_real_first_process_through_the_bootstrap(
    tmp_path: Path,
) -> None:
    """The Run-key string itself, parsed by Windows, from a working directory Windows chose. Red
    before vault BACKLOG #2822: ``-m`` put the working directory first and the decoy answered."""
    probe_dir, cwd, report = _probe_layout(tmp_path)
    command = autostart.launcher_command(sys.executable)
    assert command.endswith(" messagefoundry.tray"), command
    # A temporary path holds no quote, and does not end in a backslash.
    command = command.removesuffix("messagefoundry.tray") + f'{_PROBE_MODULE} "{report}"'
    env = {k: v for k, v in os.environ.items() if k.upper() != "PYTHONSAFEPATH"}
    env["PYTHONPATH"] = str(probe_dir)
    done = subprocess.run(  # noqa: S603 - this interpreter, our own command line
        command, cwd=cwd, env=env, capture_output=True, text=True, timeout=120, check=False
    )
    assert done.returncode == 0, done.stderr
    _assert_started_through_the_bootstrap(report)


@_WINDOWS_ONLY
def test_the_relaunch_starts_a_real_branded_child_through_the_bootstrap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``relaunch_branded`` itself, with a real branded launcher. Only the module name changes on
    the way out, so the command line and the environment are the relaunch's own."""
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    branded = branding.ensure_branded_launcher(scripts_dir=scripts)
    if branded is None:
        pytest.skip("no base pythonw.exe available to brand")
    # The branded copy finds the standard library through the pyvenv.cfg one folder up, as it does
    # in a real venv. Measured: without one it dies with "No module named 'encodings'".
    (tmp_path / "pyvenv.cfg").write_text(
        f"home = {branding._base_pythonw().parent}\n", encoding="utf-8"
    )
    probe_dir, cwd, report = _probe_layout(tmp_path)
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("PYTHONPATH", str(probe_dir))
    real_popen = subprocess.Popen
    children: list[subprocess.Popen[bytes]] = []

    def _popen(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        assert argv[-1] == "messagefoundry.tray", argv
        child = real_popen([*argv[:-1], _PROBE_MODULE, str(report)], **kwargs)  # noqa: S603
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", _popen)
    monkeypatch.setattr(branding, "ensure_branded_launcher", lambda *a, **k: branded)
    branding.relaunch_branded()  # the probe may outlive the grace window or not; either is fine
    [child] = children
    assert child.wait(timeout=120) == 0
    seen = _assert_started_through_the_bootstrap(report)
    assert Path(seen["executable"]).name == branding.BRANDED_EXE_NAME


@pytest.mark.skipif(sys.platform != "win32", reason="version resource + parser are Windows-only")
def test_branded_launcher_round_trip(tmp_path: Path) -> None:
    # The acid test: after writing our hand-built resource, Windows' OWN version parser (the same
    # source the tray-icon list uses) must read the branded FileDescription back. Sources the base
    # pythonw + its runtime DLLs into tmp_path.
    exe = branding.ensure_branded_launcher(scripts_dir=tmp_path)
    if exe is None:
        pytest.skip("no base pythonw.exe available to brand")
    assert exe.name == branding.BRANDED_EXE_NAME
    assert branding.read_file_description(exe) == branding.FILE_DESCRIPTION
    assert list(tmp_path.glob("python3*.dll"))  # runtime staged beside it

    # Idempotent: a second call returns the same path, no error.
    again = branding.ensure_branded_launcher(scripts_dir=tmp_path)
    assert again == exe
