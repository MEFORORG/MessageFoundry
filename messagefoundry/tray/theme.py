# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Taskbar theme detection for the tray icon (ADR 0113 §8).

The tray picks a dark-glyph or light-glyph icon by the **taskbar** appearance, read from
``HKCU\\…\\Themes\\Personalize\\SystemUsesLightTheme`` — the documented control for the system
chrome, **not** ``AppsUseLightTheme`` (using the wrong one is the classic invisible-icon trap). The
value→theme mapping is pure and tested; the ``winreg`` read is Windows-only and defaults to a light
taskbar on any failure.
"""

from __future__ import annotations

import sys
from enum import Enum

_PERSONALIZE = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"


class Theme(Enum):
    """The **taskbar** appearance (so the icon glyph contrasts against it)."""

    LIGHT = "light"  # light taskbar → use a dark glyph
    DARK = "dark"  # dark taskbar → use a light glyph


def theme_from_registry_value(system_uses_light_theme: int | None) -> Theme:
    """Map ``SystemUsesLightTheme`` (1=light chrome, 0=dark chrome, missing) to a :class:`Theme`.

    A missing key defaults to a light taskbar (the Windows default), which is the safe assumption:
    a dark glyph on an unexpectedly-dark taskbar is dim, never invisible.
    """
    if system_uses_light_theme is None:
        return Theme.LIGHT
    return Theme.LIGHT if system_uses_light_theme else Theme.DARK


def detect_theme() -> Theme:
    """Read the current taskbar theme. Windows-only; defaults to :data:`Theme.LIGHT` off Windows."""
    if sys.platform != "win32":
        return Theme.LIGHT
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _PERSONALIZE) as key:
            value, _kind = winreg.QueryValueEx(key, "SystemUsesLightTheme")
    except OSError:
        return Theme.LIGHT
    return theme_from_registry_value(value if isinstance(value, int) else None)
