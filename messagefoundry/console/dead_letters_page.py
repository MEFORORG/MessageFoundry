# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Dead Letters page — the deliveries that exhausted their retries and were dead-lettered.

Lists dead-lettered (message → destination) deliveries and lets an operator re-queue them, either a
single selected one (scoped to its inbound + outbound) or all at once. Listing needs ``messages:read``;
replay needs ``messages:replay`` + step-up (the engine enforces both — this page is a thin view, the
engine is the source of truth, and ``self._client`` transparently handles the step-up/MFA prompts).

The read runs OFF the main thread (a slow/wedged engine would otherwise freeze the GUI for the whole
``/dead-letters`` call); replay actions run on the main thread through ``self._client`` so a sensitive
action can put up its step-up/MFA modal.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from messagefoundry.api.models import DeadLetterList
from messagefoundry.console._async import AsyncRunner
from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.console.widgets import ConfigurableTable, fmt_ts

#: Tooltip shown on the replay buttons when the signed-in user can't replay (no ``messages:replay``).
_NO_REPLAY_TIP = "You need the messages:replay permission to re-queue dead-lettered deliveries."


class DeadLettersPage(QWidget):
    """Table of dead-lettered deliveries + replay-selected / replay-all actions (audited server-side)."""

    error = Signal(str)

    COLUMNS = [
        "Failed at",
        "Inbound",
        "Destination",
        "Type",
        "Control ID",
        "Attempts",
        "Last error",
        "Summary",
    ]

    def __init__(self, client: EngineClient, *, poll_client: EngineClient | None = None) -> None:
        super().__init__()
        self._client = client  # replay actions — main thread, may step-up/MFA
        self._poll = poll_client or client  # dead-letter list read — runs off the main thread
        self._runner = AsyncRunner(self)
        self._loading = False  # in-flight reload guard (don't pile up during a slow call)
        # A reload requested while one is in flight is latched (not dropped) and re-fired on
        # completion, so a post-replay reload isn't lost if it lands during an in-flight read.
        self._pending = False

        # The selected row's (channel_id, destination_name) is stashed on its column-0 item (not a
        # parallel list) because the table sorts — rows reorder, so a row-indexed list would desync.
        self._table = ConfigurableTable(self.COLUMNS, settings_key="dead_letters")

        self._replay_selected_btn = QPushButton("Replay selected…")
        self._replay_selected_btn.clicked.connect(self._replay_selected)
        self._replay_all_btn = QPushButton("Replay all…")
        self._replay_all_btn.clicked.connect(self._replay_all)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.reload)

        # Replay is permission-gated; disable both buttons (with an explanatory tooltip) when the
        # signed-in user lacks messages:replay rather than letting the action 403 server-side. A
        # channel-scoped operator still passes this check but is denied an unscoped replay-all by the
        # engine — the console can't see its own channel scope (CurrentUser carries no scope, and the
        # scope route is users:manage-gated), so that case is handled by surfacing the server's 403 on
        # the error signal (see _replay_all), not by pre-disabling the button.
        can_replay = self._client.can("messages:replay")
        for button in (self._replay_selected_btn, self._replay_all_btn):
            button.setEnabled(can_replay)
            if not can_replay:
                button.setToolTip(_NO_REPLAY_TIP)

        buttons = QHBoxLayout()
        buttons.addWidget(refresh_btn)
        buttons.addWidget(self._replay_selected_btn)
        buttons.addWidget(self._replay_all_btn)
        buttons.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addLayout(buttons)
        layout.addWidget(self._table)

    # --- page interface (auto-refresh timer + nav) ---------------------------

    def refresh(self) -> None:
        # NO-OP on the silent auto-refresh tick. GET /dead-letters audits PHI exposure server-side
        # whenever the summary/last_error are returned (there is no audit_summary opt-out on this
        # route, unlike /messages) — reloading on every timer tick would cause a periodic audit
        # storm. The user reloads explicitly (nav, the Refresh button, or after a replay).
        return

    def reload(self) -> None:
        # Read the dead-letter list OFF the main thread; apply on the main thread (a slow/wedged
        # engine would otherwise freeze the GUI for the whole /dead-letters call).
        if self._runner._stopped:
            # The page is being torn down (stop() ran). submit() would no-op, so neither _apply nor
            # _on_error would fire and _loading would latch True forever — strand a late reload (e.g. a
            # post-replay reload landing behind a closing modal) instead. Guard it here.
            return
        if self._loading:
            self._pending = True  # latch — re-fire when the in-flight read completes (don't drop)
            return
        self._pending = False
        self._loading = True
        self._runner.submit(self._fetch, on_done=self._apply, on_error=self._on_error)

    def stop(self) -> None:
        """Stop the background runner (call on window close) so a late result can't touch dead widgets."""
        self._runner.stop()

    def _fetch(self) -> DeadLetterList:
        """Runs on a worker thread — only blocking I/O, no widget access."""
        return self._poll.list_dead_letters(limit=200)

    def _on_error(self, exc: BaseException) -> None:
        self._loading = False
        self.error.emit(str(exc))
        self._drain_pending()

    def _drain_pending(self) -> bool:
        """Re-fire a reload that was latched while one was in flight. Returns True if it did."""
        if not self._pending:
            return False
        self._pending = False
        self.reload()
        return True

    def _apply(self, data: DeadLetterList) -> None:
        """Runs on the main thread (result slot) — safe to touch widgets."""
        self._loading = False
        if self._drain_pending():
            return  # a reload was requested mid-flight — re-fire it, skip this superseded result
        self._table.begin_populate()
        self._table.setRowCount(len(data.dead_letters))
        for row, r in enumerate(data.dead_letters):
            cells = [
                fmt_ts(r.failed_at),
                r.channel_id,
                r.destination_name,
                r.message_type or "",
                r.control_id or "",
                str(r.attempts),
                r.last_error or "",
                r.summary or "",
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 0:
                    # Stash the replay scope on column 0 so a selected row resolves to its
                    # (channel_id, destination_name) regardless of the current sort order.
                    item.setData(Qt.ItemDataRole.UserRole, (r.channel_id, r.destination_name))
                self._table.setItem(row, col, item)
        self._table.end_populate(autosize=True)

    # --- actions -------------------------------------------------------------

    def _selected_scope(self) -> tuple[str, str] | None:
        """The selected row's (channel_id, destination_name), read from the column-0 item data
        (sort-stable), or None if nothing is selected."""
        model = self._table.selectionModel()
        rows = model.selectedRows() if model else []
        if not rows:
            return None
        cell = self._table.item(rows[0].row(), 0)
        data = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        if not isinstance(data, tuple):
            return None
        channel_id, destination_name = data
        return str(channel_id), str(destination_name)

    def _replay_selected(self) -> None:
        scope = self._selected_scope()
        if scope is None:
            return  # nothing selected — no-op
        channel_id, destination_name = scope
        reply = QMessageBox.question(
            self,
            "Replay dead letter",
            f"Re-queue the dead-lettered deliveries for {channel_id} → {destination_name}? "
            "This re-transmits the message (which may contain PHI) to the destination.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            result = self._client.replay_dead_letters(
                channel_id=channel_id, destination_name=destination_name
            )
        except ApiError as exc:
            self.error.emit(str(exc))
            return
        QMessageBox.information(
            self, "Re-queued", f"Re-queued {result.requeued} dead-lettered deliveries."
        )
        self.reload()

    def _replay_all(self) -> None:
        reply = QMessageBox.question(
            self,
            "Replay all dead letters",
            "Re-queue ALL dead-lettered deliveries? This re-transmits every dead-lettered message "
            "(which may contain PHI) to its destination. A channel-scoped account is not permitted "
            "to replay all and the engine will reject it.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            result = self._client.replay_dead_letters()  # None scope = all
        except ApiError as exc:
            # A channel-scoped operator is denied an unscoped replay-all (403) — surface it on the
            # error signal so the shell shows it, rather than failing silently.
            self.error.emit(str(exc))
            return
        QMessageBox.information(
            self, "Re-queued", f"Re-queued {result.requeued} dead-lettered deliveries."
        )
        self.reload()
