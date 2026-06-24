# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guards for the one-click console launch (ADR 0032):

- the MessageFoundry badge ships in the package as a valid multi-resolution .ico,
- ``_app_icon()`` loads it into a non-null QIcon (window/taskbar branding), and
- the windowed ``messagefoundry-console`` gui-script entry point stays declared in pyproject.

The .ico + pyproject checks are pure-Python (run everywhere); the QIcon check needs Qt offscreen and
is skipped without PySide6.
"""

from __future__ import annotations

import os
import struct
from importlib.resources import files
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# 16/24/32/48/64/128/256 — see scripts/console/pack_ico.py.
_EXPECTED_FRAMES = 7


def _ico_bytes() -> bytes:
    return (files("messagefoundry.console") / "resources" / "app.ico").read_bytes()


def test_app_icon_resource_is_a_valid_multi_resolution_ico() -> None:
    data = _ico_bytes()
    reserved, image_type, count = struct.unpack("<HHH", data[:6])
    assert reserved == 0
    assert image_type == 1  # 1 = icon
    assert count == _EXPECTED_FRAMES

    widths = set()
    for i in range(count):
        entry = data[6 + i * 16 : 6 + (i + 1) * 16]
        width = entry[0]
        widths.add(256 if width == 0 else width)  # the ICO spec encodes 256 as 0
    assert 16 in widths  # smallest taskbar size present
    assert 256 in widths  # largest present (via the 0 sentinel)


def test_app_icon_loads_into_a_non_null_qicon() -> None:
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication

    QApplication.instance() or QApplication([])

    from messagefoundry.console.__main__ import _app_icon

    icon = _app_icon()
    assert not icon.isNull()
    # A real pixmap can be produced at a taskbar size (proves the .ico actually decoded).
    assert not icon.pixmap(32, 32).isNull()


def test_gui_script_entry_point_is_declared() -> None:
    import tomllib

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if not pyproject.exists():  # installed (non-editable) layout: nothing to assert against
        pytest.skip("pyproject.toml not alongside the tests (installed layout)")

    data = tomllib.loads(pyproject.read_text("utf-8"))
    gui_scripts = data["project"]["gui-scripts"]
    # The windowed launcher behind the desktop shortcut (no flashing console window).
    assert gui_scripts["messagefoundry-console"] == "messagefoundry.console.__main__:main"
