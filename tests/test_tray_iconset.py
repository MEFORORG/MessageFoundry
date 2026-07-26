"""Tray theme detection + icon asset set (ADR 0113 §8)."""

from __future__ import annotations

from messagefoundry.tray.iconset import ASSETS_DIR, all_icon_filenames, icon_filename, icon_path
from messagefoundry.tray.state import TrayState
from messagefoundry.tray.theme import Theme, detect_theme, theme_from_registry_value


def test_theme_from_registry_value() -> None:
    assert theme_from_registry_value(1) is Theme.LIGHT  # light taskbar → dark glyph
    assert theme_from_registry_value(0) is Theme.DARK  # dark taskbar → light glyph
    assert theme_from_registry_value(None) is Theme.LIGHT  # missing key → safe default


def test_detect_theme_returns_a_theme() -> None:
    assert isinstance(detect_theme(), Theme)


def test_icon_filename_shape() -> None:
    assert icon_filename(TrayState.RUNNING, Theme.LIGHT) == "running_light.ico"
    assert icon_filename(TrayState.WEDGED, Theme.DARK) == "wedged_dark.ico"


def test_icon_path_under_assets() -> None:
    path = icon_path(TrayState.RUNNING, Theme.DARK)
    assert path.parent == ASSETS_DIR
    assert path.name == "running_dark.ico"


def test_asset_set_is_complete_and_unique() -> None:
    names = all_icon_filenames()
    assert len(names) == len(TrayState) * len(Theme) == 18
    assert len(set(names)) == len(names)


def test_every_declared_icon_is_checked_in() -> None:
    # Guards against a bad/partial regeneration: every (state, theme) icon must exist on disk.
    missing = [name for name in all_icon_filenames() if not (ASSETS_DIR / name).is_file()]
    assert not missing, f"missing checked-in tray icons: {missing}"
