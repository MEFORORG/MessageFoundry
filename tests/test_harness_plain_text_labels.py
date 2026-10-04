# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A harness label that shows an engine's or a peer's text renders it as plain text (ASVS 1.1.2).

A QLabel's default text format is AutoText, which renders a string as rich text when it looks like
HTML. A label fed the engine's error text, a stat key, or a peer's address must show that string
as written, so each such label is set to ``PlainText``.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import Qt as GuiQt  # noqa: E402

from messagefoundry.apiclient import ApiError  # noqa: E402

#: Engine text that AutoText would take for rich text.
_HTML = "<b>refused</b> <img src='x'> <a href='https://example.invalid/'>click</a>"


@pytest.fixture
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_the_monitor_status_shows_engine_text_as_written(qapp: Any) -> None:
    from PySide6.QtWidgets import QLabel

    from harness.monitor import MonitorPanel

    # Control: an AutoText label takes this string for rich text, so the check below can fail.
    assert GuiQt.mightBeRichText(_HTML)
    assert QLabel().textFormat() == Qt.TextFormat.AutoText

    panel = MonitorPanel()
    try:
        panel._set_status(_HTML, error=True)
        assert panel._status.textFormat() == Qt.TextFormat.PlainText
    finally:
        panel.shutdown()


def test_the_receive_status_shows_a_peers_text_as_written(qapp: Any) -> None:
    from harness.receive import ReceivePanel

    panel = ReceivePanel()
    try:
        assert panel._status.textFormat() == Qt.TextFormat.PlainText
    finally:
        panel.shutdown()


class _RefusingClient:
    def providers(self) -> None:
        raise ApiError("no providers", status=404)

    def login(self, *args: object, **kw: object) -> None:
        raise ApiError(_HTML, status=403)


def test_the_sign_in_error_shows_the_engines_refusal_as_written(qapp: Any) -> None:
    from harness._login import LoginDialog

    dialog = LoginDialog(_RefusingClient())  # type: ignore[arg-type]
    dialog._username.setText("op")
    dialog._password.setText("pw")
    dialog._attempt()
    assert dialog._error.textFormat() == Qt.TextFormat.PlainText
    assert dialog._error.text() == _HTML  # the refusal reached the label, as written
