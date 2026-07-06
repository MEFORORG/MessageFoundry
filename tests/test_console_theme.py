# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless tests for the console visual theme: style-sheet rendering, the status-badge colour map,
and that applying the theme installs a style sheet + palette.
Runs Qt offscreen; skipped if PySide6 isn't installed."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from messagefoundry.console import theme  # noqa: E402


@pytest.fixture(scope="module")
def qapp():  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def test_build_qss_substitutes_every_placeholder() -> None:
    # The theme must render fully — a missing token would raise KeyError from Template.substitute.
    qss = theme.build_qss(theme.TOKENS)
    assert theme.TOKENS.accent in qss
    assert theme.TOKENS.bg_base in qss
    assert "$" not in qss  # no leftover unsubstituted placeholders


def test_build_palette_uses_tokens() -> None:
    from PySide6.QtGui import QPalette

    palette = theme.build_palette(theme.TOKENS)
    assert palette.color(QPalette.ColorRole.Window).name() == theme.TOKENS.bg_base
    assert palette.color(QPalette.ColorRole.Highlight).name() == theme.TOKENS.accent


def test_badge_palette_maps_known_statuses() -> None:
    t = theme.TOKENS
    assert theme.badge_palette("running", t) == (t.success_bg, t.success, "RUNNING")
    assert theme.badge_palette("stopped", t) == (t.danger_bg, t.danger, "STOPPED")
    assert theme.badge_palette("failed", t) == (t.danger_bg, t.danger, "FAILED")
    assert theme.badge_palette("degraded", t) == (t.warning_bg, t.warning, "DEGRADED")
    # Unknown status -> neutral pill, not mistaken for healthy.
    bg, fg, label = theme.badge_palette("whatever", t)
    assert (bg, fg, label) == (t.bg_elevated, t.text_secondary, "WHATEVER")


def test_badge_palette_flags_simulated() -> None:
    t = theme.TOKENS
    bg, fg, label = theme.badge_palette("running [SIMULATED]", t)
    # A simulated endpoint is amber + tagged, never coloured as a live "running".
    assert (bg, fg) == (t.warning_bg, t.warning)
    assert label == "RUNNING · SIM"


def test_apply_theme_installs_stylesheet_and_palette(qapp) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtGui import QPalette

    theme.apply_theme(qapp)
    assert qapp.styleSheet()  # a style sheet is installed
    tokens = theme.active_tokens()
    assert isinstance(tokens, theme.Tokens)
    # The palette was applied from the active tokens (the window background matches).
    assert qapp.palette().color(QPalette.ColorRole.Window).name() == tokens.bg_base


def test_status_badge_delegate_paints(qapp) -> None:  # type: ignore[no-untyped-def]
    # The delegate must render a status cell without error (paint-only; the item text is unchanged).
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem

    from messagefoundry.console.delegates import StatusBadgeDelegate

    table = QTableWidget(1, 1)
    table.setItem(0, 0, QTableWidgetItem("running [SIMULATED]"))
    table.setItemDelegateForColumn(0, StatusBadgeDelegate(table))
    table.resize(220, 60)
    pixmap = table.grab()  # exercises the delegate's paint() path
    assert not pixmap.isNull()
    item = table.item(0, 0)
    assert item is not None and item.text() == "running [SIMULATED]"  # data untouched by delegate
