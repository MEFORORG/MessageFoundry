# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Central visual theme for the admin console.

A single, token-driven ``QPalette`` + Qt Style Sheet — a soft neutral **light** theme applied
regardless of the OS appearance setting. This module is the **one** source of truth for console
colours: other modules import the accent / status colours from here instead of hardcoding hex, so
the palette can't drift.

Purely presentational: no engine state, I/O, or behaviour, and it never changes *what* a widget
shows — only how it looks. Font *sizes* are deliberately never set in the style sheet (only the app
font's family is set, preserving its point size) so the Ctrl +/- zoom — which scales the application
font — keeps working.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from string import Template

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

__all__ = [
    "Tokens",
    "TOKENS",
    "ERROR_TEXT",
    "apply_theme",
    "active_tokens",
    "build_qss",
    "build_palette",
    "badge_palette",
]

#: Stable "error red" used for inline rich-text error messages (message-detail error, the auth
#: dialogs, the heart's stopped state); ``widgets.ERROR_COLOR`` aliases it so the old name keeps
#: working and there is a single source of truth for the console's error colour.
ERROR_TEXT = "#c62828"


@dataclass(frozen=True)
class Tokens:
    """The console's colour palette. Every field is a CSS-style colour string the style sheet and
    the item delegates consume. ``*_bg`` fields are the tinted pill backgrounds for status badges."""

    bg_base: str  # window / page background (lowest layer)
    bg_surface: str  # cards, tables, nav, header (one layer up)
    bg_elevated: str  # hover/alternate surfaces, default buttons (two layers up)
    border: str  # standard hairline border
    border_subtle: str  # faint separators / disabled borders
    text_primary: str  # body text
    text_secondary: str  # labels, headers, nav items at rest
    text_muted: str  # de-emphasised text and empty "—" cells
    accent: str  # the single brand accent (links, active nav, primary button)
    accent_hover: str  # accent under hover/press
    on_accent: str  # text/icon drawn on top of the accent
    success: str  # running / healthy
    success_bg: str
    warning: str  # degraded / simulated / transitional
    warning_bg: str
    danger: str  # stopped / failed / errored
    danger_bg: str
    selection_bg: str  # selected table row / menu item
    hover_bg: str  # generic hover wash
    header_bg: str  # table header + app header bar


#: Soft neutral light — near-white surfaces, gentle greys, one restrained slate-indigo accent.
TOKENS = Tokens(
    bg_base="#f4f5f7",
    bg_surface="#ffffff",
    bg_elevated="#eceef2",
    border="#d7dae1",
    border_subtle="#e6e8ed",
    text_primary="#1f2329",
    text_secondary="#5b616e",
    text_muted="#9aa0ab",
    accent="#4a5bd4",
    accent_hover="#3a49b8",
    on_accent="#ffffff",
    success="#2e7d52",
    success_bg="#e4f3ea",
    warning="#8a6418",
    warning_bg="#faf0db",
    danger="#c0392b",
    danger_bg="#fbe6e3",
    selection_bg="#e6e9fb",
    hover_bg="#eceef2",
    header_bg="#ffffff",
)


def active_tokens() -> Tokens:
    """The tokens in effect — read by item delegates / pages at paint/populate time."""
    return TOKENS


_QSS = Template(
    """
* { outline: 0; }

QWidget { background-color: $bg_base; color: $text_primary; }
QLabel { background: transparent; }
QToolTip {
    background-color: $bg_surface; color: $text_primary;
    border: 1px solid $border; padding: 4px 6px;
}

#header { background-color: $header_bg; border-bottom: 1px solid $border; }
#wordmark { color: $accent; font-weight: 700; padding: 2px 4px; }
#statusline { color: $danger; padding: 2px 6px; }
#footer { background-color: $bg_surface; border-top: 1px solid $border; }

QListWidget#nav {
    background-color: $bg_surface; border: none; border-right: 1px solid $border; padding: 8px 6px;
}
QListWidget#nav::item {
    color: $text_secondary; border-left: 3px solid transparent;
    border-radius: 6px; padding: 9px 10px; margin: 2px 2px;
}
QListWidget#nav::item:hover { background-color: $hover_bg; color: $text_primary; }
QListWidget#nav::item:selected {
    background-color: $bg_elevated; color: $text_primary; border-left: 3px solid $accent;
}

QListWidget { background-color: $bg_surface; border: 1px solid $border; border-radius: 8px; }

QTableView, QTableWidget {
    background-color: $bg_surface; alternate-background-color: $bg_elevated;
    gridline-color: transparent; border: 1px solid $border; border-radius: 8px;
    selection-background-color: $selection_bg; selection-color: $text_primary;
}
QTableView::item, QTableWidget::item { padding: 6px 10px; border: none; }
QHeaderView { background-color: $header_bg; }
QHeaderView::section {
    background-color: $header_bg; color: $text_secondary; border: none;
    border-bottom: 1px solid $border; padding: 8px 10px; font-weight: 600;
}
QHeaderView::section:hover { color: $text_primary; }
QTableCornerButton::section { background-color: $header_bg; border: none; }

QPushButton {
    background-color: $bg_elevated; color: $text_primary;
    border: 1px solid $border; border-radius: 6px; padding: 6px 14px;
}
QPushButton:hover { background-color: $hover_bg; border-color: $accent; }
QPushButton:pressed { background-color: $selection_bg; }
QPushButton:disabled {
    color: $text_muted; background-color: $bg_surface; border-color: $border_subtle;
}
QPushButton[primary="true"] {
    background-color: $accent; color: $on_accent; border: 1px solid $accent;
}
QPushButton[primary="true"]:hover { background-color: $accent_hover; border-color: $accent_hover; }
QPushButton[primary="true"]:disabled {
    background-color: $bg_elevated; color: $text_muted; border-color: $border_subtle;
}

QToolButton {
    background-color: $bg_elevated; color: $text_primary;
    border: 1px solid $border; border-radius: 6px; padding: 6px 10px;
}
QToolButton:hover { background-color: $hover_bg; border-color: $accent; }
QToolButton:disabled {
    color: $text_muted; background-color: $bg_surface; border-color: $border_subtle;
}
QToolButton::menu-indicator { image: none; }

QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {
    background-color: $bg_surface; color: $text_primary;
    border: 1px solid $border; border-radius: 6px; padding: 5px 8px;
    selection-background-color: $accent; selection-color: $on_accent;
}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus { border-color: $accent; }
QComboBox::drop-down { border: none; width: 18px; }

QMenu { background-color: $bg_surface; color: $text_primary; border: 1px solid $border; padding: 4px; }
QMenu::item { padding: 6px 18px; border-radius: 4px; }
QMenu::item:selected { background-color: $selection_bg; }
QMenu::separator { height: 1px; background: $border; margin: 4px 6px; }

QTabWidget::pane { border: 1px solid $border; border-radius: 8px; top: -1px; }
QTabBar::tab {
    background: transparent; color: $text_secondary; padding: 7px 14px;
    border: none; border-bottom: 2px solid transparent;
}
QTabBar::tab:hover { color: $text_primary; }
QTabBar::tab:selected { color: $text_primary; border-bottom: 2px solid $accent; }

QScrollBar:vertical { background: transparent; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: $bg_elevated; border-radius: 6px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: $text_muted; }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 0; }
QScrollBar::handle:horizontal { background: $bg_elevated; border-radius: 6px; min-width: 28px; }
QScrollBar::handle:horizontal:hover { background: $text_muted; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; background: none; border: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
"""
)


def build_qss(t: Tokens) -> str:
    """Render the full style sheet for ``t``."""
    return _QSS.substitute(asdict(t))


def build_palette(t: Tokens) -> QPalette:
    """A ``QPalette`` matching ``t`` so native-drawn widgets (message boxes, the auth dialogs,
    rich-text links) share the theme even where the style sheet doesn't reach."""
    p = QPalette()
    role = QPalette.ColorRole
    group = QPalette.ColorGroup
    p.setColor(role.Window, QColor(t.bg_base))
    p.setColor(role.WindowText, QColor(t.text_primary))
    p.setColor(role.Base, QColor(t.bg_surface))
    p.setColor(role.AlternateBase, QColor(t.bg_elevated))
    p.setColor(role.Text, QColor(t.text_primary))
    p.setColor(role.Button, QColor(t.bg_elevated))
    p.setColor(role.ButtonText, QColor(t.text_primary))
    p.setColor(role.Highlight, QColor(t.accent))
    p.setColor(role.HighlightedText, QColor(t.on_accent))
    p.setColor(role.ToolTipBase, QColor(t.bg_surface))
    p.setColor(role.ToolTipText, QColor(t.text_primary))
    p.setColor(role.PlaceholderText, QColor(t.text_muted))
    p.setColor(role.Link, QColor(t.accent))
    for disabled in (role.Text, role.ButtonText, role.WindowText):
        p.setColor(group.Disabled, disabled, QColor(t.text_muted))
    return p


def badge_palette(status: str, t: Tokens) -> tuple[str, str, str]:
    """Map a connection status string to ``(background, foreground, label)`` for a pill badge.

    Reads the raw status the server reports (``running`` / ``stopped`` / ``failed`` / …); the
    ``[SIMULATED]`` suffix the page appends is recognised and flagged amber rather than coloured as a
    live connection. Unknown statuses get a neutral pill."""
    raw = status.strip()
    simulated = "[simulated]" in raw.lower()
    base = raw.lower().replace("[simulated]", "").strip()
    if base in {"running", "started", "ok", "healthy", "connected"}:
        bg, fg = t.success_bg, t.success
    elif base in {"stopped", "failed", "error", "errored", "dead", "down"}:
        bg, fg = t.danger_bg, t.danger
    elif base in {"degraded", "starting", "stopping", "retrying", "connecting"}:
        bg, fg = t.warning_bg, t.warning
    else:
        bg, fg = t.bg_elevated, t.text_secondary
    label = (base or raw).upper()
    if simulated:  # a simulated endpoint is never a real "running" — flag it amber.
        bg, fg = t.warning_bg, t.warning
        label = f"{label} · SIM"
    return bg, fg, label


def apply_theme(app: QApplication) -> None:
    """Apply the console's light theme to ``app``.

    Switches to the Fusion style (so the palette drives a consistent look on every platform,
    independent of the OS appearance setting), sets the UI font family while preserving the point
    size (so Ctrl +/- zoom still works), and installs the palette + style sheet."""
    app.setStyle("Fusion")
    font = app.font()
    font.setFamilies(["Segoe UI Variable Text", "Segoe UI"])
    app.setFont(font)
    app.setPalette(build_palette(TOKENS))
    app.setStyleSheet(build_qss(TOKENS))
