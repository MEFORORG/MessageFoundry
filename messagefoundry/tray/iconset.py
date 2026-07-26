"""Icon asset selection for the tray (ADR 0113 §8).

Pure mapping from ``(TrayState, Theme)`` to a checked-in ``.ico`` file under ``tray/assets/``. The
files themselves are pre-baked (see ``scripts/tray/make_icons.py``) so the runtime needs no image
library. There are ``len(TrayState) × 2`` icons — one per state, per taskbar theme.
"""

from __future__ import annotations

from pathlib import Path

from messagefoundry.tray.state import TrayState
from messagefoundry.tray.theme import Theme

ASSETS_DIR = Path(__file__).resolve().parent / "assets"


def icon_filename(state: TrayState, theme: Theme) -> str:
    """The ``.ico`` basename for a state + taskbar theme, e.g. ``running_light.ico``."""
    return f"{state.value}_{theme.value}.ico"


def icon_path(state: TrayState, theme: Theme, assets_dir: Path = ASSETS_DIR) -> Path:
    """The full path to the icon for a state + theme."""
    return assets_dir / icon_filename(state, theme)


def all_icon_filenames() -> list[str]:
    """Every icon file the asset set must contain (state × theme). Used by the generator + a test."""
    return [icon_filename(state, theme) for state in TrayState for theme in Theme]
