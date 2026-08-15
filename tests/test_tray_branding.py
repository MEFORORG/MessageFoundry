# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Branded launcher (ADR 0113): pure VS_VERSIONINFO structure + the Windows round-trip."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

from messagefoundry.tray import branding


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
    monkeypatch.setattr(branding.sys, "executable", "/opt/app/MessageFoundryTray.exe")
    assert branding.is_branded_process() is True
    monkeypatch.setattr(branding.sys, "executable", "/opt/app/pythonw.exe")
    assert branding.is_branded_process() is False


def test_off_windows_is_fail_soft(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(branding.sys, "platform", "linux")
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

    monkeypatch.setattr(branding.subprocess, "Popen", lambda *a, **k: _Dead())
    assert branding.relaunch_branded() is False  # child died → parent must run unbranded


def test_relaunch_returns_true_when_child_survives(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exe = tmp_path / branding.BRANDED_EXE_NAME
    exe.write_bytes(b"")
    monkeypatch.setattr(branding, "ensure_branded_launcher", lambda *a, **k: exe)

    class _Alive:
        returncode = None

        def wait(self, timeout: float | None = None) -> int:
            raise branding.subprocess.TimeoutExpired("cmd", timeout or 0)

    monkeypatch.setattr(branding.subprocess, "Popen", lambda *a, **k: _Alive())
    assert branding.relaunch_branded() is True  # still alive → the child owns the tray


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
