# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Log Search page: search options on top, the message list below, and the single-message
detail (parse tree / raw / deliveries / audit) at the bottom. Composes the existing
``MessagesPanel`` and ``MessageDetailPanel``, stacked vertically.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QSplitter, QVBoxLayout, QWidget

from messagefoundry.console.client import EngineClient
from messagefoundry.console.widgets import MessageDetailPanel, MessagesPanel


class LogSearchPage(QWidget):
    """Message browser + detail, the relocated home of the old console's lower half."""

    error = Signal(str)

    def __init__(self, client: EngineClient, *, poll_client: EngineClient | None = None) -> None:
        super().__init__()
        self.messages = MessagesPanel(client, poll_client=poll_client)
        self.detail = MessageDetailPanel(client, poll_client=poll_client)

        self.messages.message_selected.connect(self.detail.load)
        self.messages.selection_cleared.connect(self.detail.clear)
        self.detail.changed.connect(self.messages.refresh)
        self.messages.error.connect(self.error.emit)
        self.detail.error.connect(self.error.emit)

        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.messages)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 2)

        layout = QVBoxLayout(self)
        layout.addWidget(split)

    def refresh(self) -> None:
        """Silent refresh — used by the auto-refresh timer (no PHI audit)."""
        self.messages.refresh()

    def reload(self) -> None:
        """User-initiated load (opening the page) — audits summary display."""
        self.messages.refresh(audit=True)

    def set_channel(self, channel_id: str) -> None:
        """Filter the list to one channel (used by the Connections 'Logs' link)."""
        self.messages.set_channel_filter(channel_id)

    def stop(self) -> None:
        """Stop the message-list + detail background runners (call on window close)."""
        self.messages.stop()
        self.detail.stop()
