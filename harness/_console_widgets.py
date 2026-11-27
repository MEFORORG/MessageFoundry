# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Reusable PySide6 leaf widgets for the harness monitor GUI.

The HL7 parse-tree view, the message browser, the single-message detail pane, and the
auto-refresh interval dialog. The harness monitor composes these — see ``monitor.py``,
``compose.py``, ``receive.py``, ``send.py``, ``file_panel.py``. Every widget takes an
:class:`~messagefoundry.apiclient.EngineClient`-shaped object and exposes a
``refresh()`` so the UI can be driven (and smoke-tested headless) without user input.

API calls run synchronously on the GUI thread — localhost latency is negligible — and any
:class:`ApiError` is surfaced via the ``error`` signal rather than raising into Qt.

Rehomed verbatim from the retired ``messagefoundry.console`` package (BACKLOG #103, ADR 0032 retired):
the web console is now the sole operator UI, but the harness (itself a PySide6 app) keeps reusing these
view widgets, so they now live beside it.
"""

from __future__ import annotations

import html
import logging
import traceback
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime

from PySide6.QtCore import QPoint, QSettings, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from harness._async import AsyncRunner
from messagefoundry.api.models import MessageDetail, MessageSummary
from messagefoundry.apiclient import ApiError, EngineClient, StepUpRequired
from messagefoundry.parsing import HL7PeekError, parse_tree

_log = logging.getLogger(__name__)

#: The GUI-thread step-up the monitor hands its panels: given the action a refusal named
#: (``StepUpRequired.action``, None for a session-window gate), it prompts for the password,
#: re-proves it bound to that action, and returns True iff it did. It may raise ApiError when the
#: re-proof itself is refused. A panel calls it only for a ``StepUpRequired`` its worker read
#: raised, and repeats that read once after a True (BACKLOG #5945).
StepUpPrompt = Callable[[str | None], bool]

#: Shared "error red" for inline error text — the message-detail error, the auth dialogs'
#: error labels, and the heart's stopped state — so the palette can't drift across modules.
#: Carried over from the retired console theme so there is a single source of truth for this colour.
ERROR_TEXT = "#c62828"
ERROR_COLOR = ERROR_TEXT

__all__ = [
    "ParseTreeView",
    "MessageDetailPanel",
    "MessagesPanel",
    "RefreshSettingsDialog",
    "ConfigurableTable",
    "ERROR_COLOR",
    "fmt_ts",
    "fill_table",
]


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def fill_table(table: QTableWidget, headers: list[str], *, multi: bool = False) -> None:
    table.setColumnCount(len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    mode = (
        QAbstractItemView.SelectionMode.ExtendedSelection
        if multi
        else QAbstractItemView.SelectionMode.SingleSelection
    )
    table.setSelectionMode(mode)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(True)
    # Modern table chrome (purely visual): zebra striping instead of a hard grid, a touch more row
    # height, and a single-pixel-thin selection. The harsh default gridlines are dropped — the
    # alternating rows + theme borders carry the structure.
    table.setAlternatingRowColors(True)
    table.setShowGrid(False)
    table.verticalHeader().setDefaultSectionSize(30)
    table.horizontalHeader().setHighlightSections(False)


class ConfigurableTable(QTableWidget):
    """A table whose columns are left-aligned, reorderable (drag), sortable (click header), and
    show/hide-able (header right-click), with order/visibility/sort persisted across runs.

    Repopulate between :meth:`begin_populate` and :meth:`end_populate` so insertion is stable and
    the user's sort/layout survive an auto-refresh; pass ``autosize=True`` to fit columns to
    contents (do this on user-initiated loads, not silent ticks, so it won't fight a manual
    resize)."""

    def __init__(self, columns: list[str], *, settings_key: str, multi: bool = False) -> None:
        super().__init__(0, len(columns))
        self._columns = columns
        self._settings_key = settings_key
        self._suppress_save = True
        fill_table(self, columns, multi=multi)
        self.setSortingEnabled(True)
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionsMovable(True)
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_header_menu)
        header.sectionMoved.connect(lambda *_: self._save_state())
        header.sortIndicatorChanged.connect(lambda *_: self._save_state())
        # No sort until the user clicks a header — preserve the server's natural row order
        # (e.g. messages newest-first, connections source-then-destinations).
        header.setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self._restore_state()
        self._suppress_save = False

    def begin_populate(self) -> None:
        self._suppress_save = True
        self.setSortingEnabled(False)

    def end_populate(self, *, autosize: bool = False) -> None:
        self.setSortingEnabled(True)
        if autosize:
            self.resizeColumnsToContents()
        self._suppress_save = False

    def _restore_state(self) -> None:
        state = QSettings().value(self._settings_key)
        if state is not None:
            self.horizontalHeader().restoreState(state)

    def _save_state(self) -> None:
        if self._suppress_save:
            return
        QSettings().setValue(self._settings_key, self.horizontalHeader().saveState())

    def _show_header_menu(self, pos: QPoint) -> None:
        menu = QMenu(self)
        for col, label in enumerate(self._columns):
            act = menu.addAction(label)
            act.setCheckable(True)
            act.setChecked(not self.isColumnHidden(col))
            act.toggled.connect(lambda checked, c=col: self._set_column_visible(c, checked))
        menu.exec(self.horizontalHeader().mapToGlobal(pos))

    def _set_column_visible(self, col: int, visible: bool) -> None:
        self.setColumnHidden(col, not visible)
        self._save_state()


class ParseTreeView(QTreeWidget):
    """Renders an HL7 message as an explorable segment/field/component tree."""

    def __init__(self) -> None:
        super().__init__()
        self.setHeaderLabels(["Element", "Value"])
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)

    def show_message(self, raw: str) -> None:
        self.clear()
        try:
            nodes = parse_tree(raw)
        except HL7PeekError as exc:
            self.addTopLevelItem(QTreeWidgetItem(["(unparseable)", str(exc)]))
            return
        for node in nodes:
            self.addTopLevelItem(self._item(node))
        self.expandToDepth(0)

    def _item(self, node: object) -> QTreeWidgetItem:
        # node is a parsing.TreeNode; value shown only on leaves to reduce noise.
        value = node.value if not node.children else ""  # type: ignore[attr-defined]
        item = QTreeWidgetItem([node.label, value])  # type: ignore[attr-defined]
        for child in node.children:  # type: ignore[attr-defined]
            item.addChild(self._item(child))
        return item


@dataclass(frozen=True)
class _StepUpRefusal:
    """A worker read's ``StepUpRequired``, reduced to what the GUI-thread re-proof needs. Not the
    exception itself: its traceback holds the worker frame, and through it the panel."""

    action: str | None  # the refusal's X-Step-Up-Action; None for a session-window gate


def _ask_step_up(step_up: StepUpPrompt, refusal: _StepUpRefusal) -> bool | str:
    """Run the GUI-thread step-up for a worker read's refusal. True: re-proved, so the caller
    repeats the read once. False: declined, and the caller reports the refusal. A string: the
    re-proof itself was refused, and the string is its cause, which the caller reports instead of
    the original 403."""
    try:
        return step_up(refusal.action)
    except ApiError as exc:
        return str(exc)


@dataclass(frozen=True)
class _DetailSnapshot:
    """One off-thread message-detail read, applied on the main thread. ``message_id`` lets a stale
    result (superseded by a newer ``load``) be dropped; ``error`` set means the read failed. It
    carries no body: the engine serves that from its own audited fetch (BACKLOG #2345), and this
    panel asks for it only when the operator presses Show body (BACKLOG #2346). ``open_seq`` names
    the load() that asked, so an earlier open of the same message that lands late is dropped."""

    message_id: str
    open_seq: int
    detail: MessageDetail | None
    error: str | None
    # The open was refused for want of a fresh step-up, which the handler-less polling client
    # cannot prompt for; the panel answers it on the GUI thread (BACKLOG #5945).
    refusal: _StepUpRefusal | None = None


@dataclass(frozen=True)
class _BodySnapshot:
    """One off-thread body read, started by the Show body button and applied on the main thread.
    Exactly one of ``raw`` and ``error`` is set. ``open_seq`` names the open it was asked for, so a
    body is never painted onto a later open of the same message that nobody asked to see."""

    message_id: str
    open_seq: int
    raw: str | None
    error: str | None
    refusal: _StepUpRefusal | None = None  # as on _DetailSnapshot


#: What the Raw tab says until the operator asks for the body (BACKLOG #2346, ASVS 14.2.6).
_BODY_HIDDEN_TEXT = (
    "The raw message is not loaded. Press Show body to fetch it; each view is audited."
)


class MessageDetailPanel(QWidget):
    """Shows one message: summary, raw, parse tree, outbox, audit trail, and replay."""

    error = Signal(str)
    changed = Signal()  # emitted after a successful replay so lists can refresh

    def __init__(
        self,
        client: EngineClient,
        *,
        poll_client: EngineClient | None = None,
        step_up: StepUpPrompt | None = None,
    ) -> None:
        super().__init__()
        self._client = client  # replay action — main thread, may step-up/MFA
        self._poll = poll_client or client  # message read — runs off the main thread
        # The open and the body read can be refused with a step-up, at least from a host the
        # session has not verified from, and the worker's polling client cannot prompt. Such a
        # refusal calls this on the GUI thread and, on True, repeats that read once. None: the
        # refusal is reported as is.
        self._step_up = step_up
        self._runner = AsyncRunner(self)
        self._message_id: str | None = None
        self._pending_id: str | None = None  # the latest requested load (drops stale results)
        # Bumped by every load() and clear(). A body fetch carries the value it started under, and
        # _apply_body drops it once the number has moved on (BACKLOG #2346).
        self._open_seq = 0

        self._summary = QLabel("Select a message")
        self._summary.setWordWrap(True)
        self._replay = QPushButton("Replay")
        self._replay.setEnabled(False)
        self._replay.clicked.connect(self._on_replay)
        # The explicit act that fetches the body (BACKLOG #2346, ASVS 14.2.6). Selecting a row opens
        # the message and nothing more; the body is a second, separately audited request.
        self._show_body = QPushButton("Show body")
        self._show_body.setEnabled(False)
        self._show_body.clicked.connect(self._on_show_body)

        header = QHBoxLayout()
        header.addWidget(self._summary, stretch=1)
        header.addWidget(self._show_body)
        header.addWidget(self._replay)

        self._tree = ParseTreeView()
        self._raw = QPlainTextEdit()
        self._raw.setReadOnly(True)
        self._raw.setPlaceholderText(_BODY_HIDDEN_TEXT)
        self._outbox = QTableWidget(0, 5)
        fill_table(
            self._outbox, ["Destination", "Status", "Attempts", "Next attempt", "Last error"]
        )
        self._events = QTableWidget(0, 4)
        fill_table(self._events, ["Time", "Event", "Destination", "Detail"])

        tabs = QTabWidget()
        tabs.addTab(self._tree, "Parse tree")
        tabs.addTab(self._raw, "Raw")
        tabs.addTab(self._outbox, "Deliveries")
        tabs.addTab(self._events, "Audit / events")

        layout = QVBoxLayout(self)
        layout.addLayout(header)
        layout.addWidget(tabs)

    def clear(self) -> None:
        self._open_seq += 1
        self._pending_id = None  # a pending load() must not re-populate after an explicit clear
        self._reset("Select a message")

    def _reset(self, label: str) -> None:
        """Show no message: no metadata, no body, and neither action offered."""
        self._message_id = None
        self._summary.setText(label)
        self._replay.setEnabled(False)
        self._show_body.setEnabled(False)
        self._tree.clear()
        self._raw.clear()
        self._outbox.setRowCount(0)
        self._events.setRowCount(0)

    def load(self, message_id: str) -> None:
        self._open(message_id, retried=False)

    def _open(self, message_id: str, *, retried: bool) -> None:
        # Read the message OFF the main thread; apply on the main thread. A newer load() supersedes
        # an in-flight one (rapid row clicks / replay), so a stale result is dropped in _apply.
        self._open_seq += 1
        self._pending_id = message_id
        # Nothing is open until this open lands. The previous message leaves the screen now, and
        # Show body or Replay pressed meanwhile would act on it, so both go too (BACKLOG #5848).
        self._reset("Opening the message...")
        self._submit_open(message_id, self._open_seq, retried=retried)

    def _reopen_after_proof(self) -> None:
        """A prompt re-proved after its nested event loop started a newer open, which went out
        under the old session. That open may come back refused, or already has and was reported,
        since a refusal arriving while a prompt is up is declined. So the current selection is
        opened again, as the one repeat after a step-up, unless it has already landed."""
        message_id = self._pending_id
        if message_id is not None and message_id != self._message_id:
            self._open(message_id, retried=True)

    def _submit_open(self, message_id: str, open_seq: int, *, retried: bool) -> None:
        self._runner.submit(
            lambda: self._fetch(message_id, open_seq),
            on_done=lambda snap: self._apply(snap, retried=retried),
            on_error=lambda exc: self._open_raised(message_id, open_seq, exc),
        )

    def _open_raised(self, message_id: str, open_seq: int, exc: BaseException) -> None:
        """The open raised something other than ApiError. The client wraps transport errors in
        ApiError, so this is a contract break, such as a closed client or a decode bug: log it and
        take _apply's error path, which drops it if a newer open superseded it. Its text can quote
        message fields (a decode error names its input), so no level logs the text: WARNING carries
        the type name, and DEBUG the traceback's frames without the message."""
        _log.warning("message detail open raised %s", type(exc).__name__)
        _log.debug(
            "message detail open raised %s at:\n%s",
            type(exc).__name__,
            "".join(traceback.format_tb(exc.__traceback__)),
        )
        error = f"the message could not be opened: {type(exc).__name__}"
        self._apply(_DetailSnapshot(message_id, open_seq, None, error))

    def stop(self) -> None:
        """Stop the background runner (call on window close) so a late result can't touch dead widgets."""
        self._runner.stop()

    def _fetch(self, message_id: str, open_seq: int) -> _DetailSnapshot:
        """Runs on a worker thread — only blocking I/O, no widget access.

        Opens the message and nothing more. The body is a separate audited act (BACKLOG #2345) that
        waits for the Show body button (BACKLOG #2346), so selecting a row charges the PHI-read
        budget once, not twice."""
        try:
            detail = self._poll.get_message(message_id)
        except StepUpRequired as exc:
            # Not IdpStepUpRequired, which only the web console can answer, and not a role, scope
            # or second-factor refusal, which a password would not clear.
            return _DetailSnapshot(message_id, open_seq, None, str(exc), _StepUpRefusal(exc.action))
        except ApiError as exc:
            return _DetailSnapshot(message_id, open_seq, None, str(exc))
        return _DetailSnapshot(message_id, open_seq, detail, None)

    def _answer_step_up(self, refusal: _StepUpRefusal | None, retried: bool) -> bool | str:
        """Answer a worker read's step-up refusal: False when there is none to answer, because the
        read was not refused, is already the repeat, or no step-up was given; otherwise
        :func:`_ask_step_up`'s answer."""
        if refusal is None or retried or self._step_up is None:
            return False
        return _ask_step_up(self._step_up, refusal)

    def _apply(self, snap: _DetailSnapshot, *, retried: bool = False) -> None:
        """Runs on the main thread (result slot) — safe to touch widgets. ``retried``: this read is
        the one repeat after a step-up, so a refusal of it is reported, never prompted again."""
        if snap.open_seq != self._open_seq or snap.message_id != self._pending_id:
            return  # a newer load() (or a clear()) superseded this result
        try:
            answer = self._answer_step_up(snap.refusal, retried)
        except Exception as exc:  # noqa: BLE001 -- as the runner's on_error: report, never wedge
            self._open_raised(snap.message_id, snap.open_seq, exc)
            return
        if snap.open_seq != self._open_seq or snap.message_id != self._pending_id:
            # The prompt's nested event loop ran a newer load() or a clear(). That one wins, so
            # this one is dropped whatever the prompt answered.
            if answer is True:
                self._reopen_after_proof()
            return
        if answer is True:
            # The polling client reads the rotated token through the shared cell, so the repeat
            # carries the fresh proof.
            self._submit_open(snap.message_id, snap.open_seq, retried=True)
            return
        if isinstance(answer, str):
            snap = replace(snap, error=answer)
        if snap.error is not None:
            self.error.emit(snap.error)
            # Never leave the previous message's metadata and body under the newly selected row.
            self._reset("The message could not be opened.")
            return
        detail = snap.detail
        assert detail is not None
        message_id = snap.message_id
        self._message_id = message_id
        self._replay.setEnabled(True)
        self._show_body.setEnabled(True)
        # Escape HL7-derived fields (message_type/control_id/error come from raw message content)
        # before interpolating into this rich-text label, so a crafted message can't inject HTML (H1).
        self._summary.setText(
            f"<b>{html.escape(detail.message_type or '?')}</b> "
            f"&nbsp; control={html.escape(detail.control_id or '?')} "
            f"&nbsp; status=<b>{html.escape(detail.status)}</b> "
            f"&nbsp; received {fmt_ts(detail.received_at)}"
            + (
                f"<br><span style='color:{ERROR_COLOR}'>{html.escape(detail.error)}</span>"
                if detail.error
                else ""
            )
        )
        # A newly opened message shows no body, and never the previous message's body: the operator
        # asks for this one's with Show body.
        self._tree.clear()
        self._raw.clear()

        self._outbox.setRowCount(len(detail.outbox))
        for r, o in enumerate(detail.outbox):
            for c, text in enumerate(
                [
                    o.destination_name,
                    o.status,
                    str(o.attempts),
                    fmt_ts(o.next_attempt_at),
                    o.last_error or "",
                ]
            ):
                self._outbox.setItem(r, c, QTableWidgetItem(text))

        self._events.setRowCount(len(detail.events))
        for r, e in enumerate(detail.events):
            for c, text in enumerate([fmt_ts(e.ts), e.event, e.destination or "", e.detail or ""]):
                self._events.setItem(r, c, QTableWidgetItem(text))

    def _on_show_body(self) -> None:
        """The explicit act (BACKLOG #2346): fetch the open message's body, tagged ``harness`` so
        the engine's ``message_body_view`` row names this client. Each press is its own request, and
        the button stays disabled until it answers, so a double-click is one read, not two."""
        message_id = self._message_id
        if message_id is None or message_id != self._pending_id:
            return  # nothing open, or a newer load() is still in flight
        self._show_body.setEnabled(False)
        self._submit_body(message_id, self._open_seq, retried=False)

    def _submit_body(self, message_id: str, open_seq: int, *, retried: bool) -> None:
        self._runner.submit(
            lambda: self._fetch_body(message_id, open_seq),
            on_done=lambda snap: self._apply_body(snap, retried=retried),
            on_error=lambda exc: self._body_failed(open_seq, exc),
        )

    def _body_failed(self, open_seq: int, exc: BaseException) -> None:
        """A body fetch raised something other than ApiError. Report it and offer the button
        again, rather than leaving Show body greyed out with nothing said."""
        if open_seq != self._open_seq:
            return
        self._show_body.setEnabled(self._message_id is not None)
        self.error.emit(f"the body could not be read: {type(exc).__name__}")

    def _fetch_body(self, message_id: str, open_seq: int) -> _BodySnapshot:
        """Runs on a worker thread — only blocking I/O, no widget access."""
        try:
            body = self._poll.get_message_body(message_id, surface="harness")
        except StepUpRequired as exc:
            # As in _fetch: only a password step-up is answered on the GUI thread.
            return _BodySnapshot(message_id, open_seq, None, str(exc), _StepUpRefusal(exc.action))
        except ApiError as exc:
            # A 429 from the PHI-read budget, say. The open stays on screen; only the body failed.
            return _BodySnapshot(message_id, open_seq, None, str(exc))
        return _BodySnapshot(message_id, open_seq, body.raw, None)

    def _apply_body(self, snap: _BodySnapshot, *, retried: bool = False) -> None:
        """Runs on the main thread (result slot). Drops a body asked for under an earlier open, so a
        slow fetch never paints onto another message, nor onto a later open of the same message
        (a re-selection, or the reload after Replay) that nobody asked to see. ``retried`` is as
        on :meth:`_apply`."""
        if snap.open_seq != self._open_seq or snap.message_id != self._message_id:
            return
        # Show body stays disabled while the prompt is up, so a press in its nested event loop
        # cannot start a second read and a second prompt.
        try:
            answer = self._answer_step_up(snap.refusal, retried)
        except Exception as exc:  # noqa: BLE001 -- as the runner's on_error: report, never wedge
            self._body_failed(snap.open_seq, exc)
            return
        if snap.open_seq != self._open_seq or snap.message_id != self._message_id:
            # The prompt's nested event loop opened another message, or cleared this one.
            if answer is True:
                self._reopen_after_proof()
            return
        if answer is True:
            self._submit_body(snap.message_id, snap.open_seq, retried=True)
            return
        if isinstance(answer, str):
            snap = replace(snap, error=answer)
        self._show_body.setEnabled(True)
        if snap.raw is None:
            self.error.emit(snap.error or "the body could not be read")
            return
        self._tree.show_message(snap.raw)
        self._raw.setPlainText(snap.raw.replace("\r", "\n"))

    def _on_replay(self) -> None:
        # Read once: replay() can open a step-up prompt whose nested event loop runs a load() or
        # clear(). That newer selection wins, so the refresh below runs only if none did.
        message_id = self._message_id
        if message_id is None:
            return  # nothing open, or a newer load() is still in flight
        open_seq = self._open_seq
        try:
            self._client.replay(message_id)
        except ApiError as exc:
            self.error.emit(str(exc))
            return
        if open_seq == self._open_seq:
            self.load(message_id)  # refresh detail (status/events updated)
        self.changed.emit()


@dataclass(frozen=True)
class _MessagesSnapshot:
    """One off-thread message-list (or content-search) read, applied on the main thread. ``error`` set
    ⇒ the read failed (the table is left as-is); otherwise ``messages`` is the page to render,
    ``count_text`` the status-bar label, and ``truncated`` whether a content search hit its scan cap (so
    the label can prompt the operator to narrow filters)."""

    messages: list[MessageSummary] | None
    count_text: str
    truncated: bool
    error: str | None
    # A content search refused for want of a fresh step-up. The polling client has no step-up
    # handler, so the refusal surfaces here instead of prompting; the panel answers it on the GUI
    # thread, re-proving for the action the refusal named.
    refusal: _StepUpRefusal | None = None


class MessagesPanel(QWidget):
    """A filterable message list with configurable columns (show/hide, reorder, sort, persisted).

    ``refresh(autosize=True)`` is the user-initiated form (the Refresh button, Enter in a filter box)
    and re-fits the columns to the new rows; the auto-refresh timer calls ``refresh()``, which leaves
    the operator's column widths alone.

    PHI-summary access auditing is **not** a client concern: the engine audits every list response
    that returns non-redacted summaries, whatever this panel sends and whether or not the Summary
    column is visible. There is no opt-in to pass."""

    error = Signal(str)
    message_selected = Signal(str)
    selection_cleared = Signal()  # the selected row vanished on refresh — clear the detail pane

    COLUMNS = [
        "Time",
        "Channel",
        "Event",
        "Msg. Type",
        "Status",
        "Control ID",
        "Summary",
        "Metadata",
    ]

    def __init__(
        self,
        client: EngineClient,
        *,
        poll_client: EngineClient | None = None,
        step_up: StepUpPrompt | None = None,
    ) -> None:
        super().__init__()
        self._client = client
        self._poll = poll_client or client  # message-list read — runs off the main thread
        # The content search is step-up gated, and the worker's polling client cannot prompt. A
        # search refused for a step-up (StepUpRequired) calls this on the GUI thread (it prompts
        # and re-proves) and, if it returns True, resubmits the same refresh once. None: the
        # refusal is reported as is.
        self._step_up = step_up
        self._stepped_up = False  # the in-flight read is the one retry after a step-up
        self._runner = AsyncRunner(self)
        self._loading = False  # in-flight refresh guard (don't pile up during a slow call)
        # A refresh requested WHILE one is in flight is latched here (not dropped) and re-fired when
        # the in-flight read finishes, so a filter change (set_channel_filter / Enter / the Connections
        # 'Logs' link) or a post-replay refresh can't leave the filter box and the list mismatched —
        # which would never self-heal with auto-refresh off. None = none pending; bool = the pending
        # request's autosize flag.
        self._pending: bool | None = None
        self._loaded = False  # autosize columns on the first (and user-initiated) loads

        self._channel_filter = QLineEdit()
        self._channel_filter.setPlaceholderText("channel id")
        self._status_filter = QLineEdit()
        self._status_filter.setPlaceholderText("status")
        # Content search (ADR 0046 #51): an HL7 field path (e.g. PID-3) OR a raw/summary substring. When
        # set, the panel switches from the metadata list to the scan-and-decrypt /messages/search route
        # (step-up gated server-side). The field-path box, when filled, takes precedence over content.
        self._content_filter = QLineEdit()
        self._content_filter.setPlaceholderText("content contains…")
        self._field_path_filter = QLineEdit()
        self._field_path_filter.setPlaceholderText("HL7 field (e.g. PID-3)")
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(lambda: self.refresh(autosize=True))
        for box in (
            self._channel_filter,
            self._status_filter,
            self._content_filter,
            self._field_path_filter,
        ):
            box.returnPressed.connect(lambda: self.refresh(autosize=True))

        filters = QHBoxLayout()
        filters.addWidget(QLabel("Search"))
        filters.addWidget(self._channel_filter)
        filters.addWidget(self._status_filter)
        filters.addWidget(self._content_filter)
        filters.addWidget(self._field_path_filter)
        filters.addWidget(refresh)

        self._table = ConfigurableTable(self.COLUMNS, settings_key="logsearch/header_state")
        self._table.itemSelectionChanged.connect(self._on_select)

        self._count = QLabel("")

        layout = QVBoxLayout(self)
        layout.addLayout(filters)
        layout.addWidget(self._table)
        layout.addWidget(self._count)

    def set_channel_filter(self, channel_id: str) -> None:
        """Filter to one channel and refresh (used by the Connections 'Logs' link)."""
        self._channel_filter.setText(channel_id)
        self._status_filter.clear()
        self._content_filter.clear()
        self._field_path_filter.clear()
        self.refresh(autosize=True)

    def refresh(self, *, autosize: bool = False) -> None:
        # Read the message list OFF the main thread (the 200-row read is the heaviest console query,
        # and a slow/wedged engine would otherwise freeze the GUI for the whole call). The query
        # parameters are read from the filter widgets HERE, on the main thread, then handed to the
        # worker — the worker must never touch a widget.
        if self._loading:
            # Don't pile up on a slow engine, but don't lose a filter change either — latch it
            # (OR-merge the autosize flag) so it re-fires once the in-flight read completes.
            self._pending = autosize if self._pending is None else (self._pending or autosize)
            return
        self._pending = None
        channel = self._channel_filter.text().strip() or None
        status = self._status_filter.text().strip() or None
        content = self._content_filter.text().strip() or None
        field_path = self._field_path_filter.text().strip() or None
        self._loading = True
        self._runner.submit(
            lambda: self._fetch(channel, status, content, field_path),
            on_done=lambda snap: self._apply(snap, autosize=autosize),
            on_error=self._on_error,
        )

    def stop(self) -> None:
        """Stop the background runner (call on window close) so a late result can't touch dead widgets."""
        self._runner.stop()

    def _on_error(self, exc: BaseException) -> None:
        # Belt-and-suspenders: list_messages raises only ApiError (handled via the snapshot in _apply),
        # but an unexpected error must still clear the in-flight guard or the panel wedges forever.
        self._loading = False
        self._stepped_up = False
        self.error.emit(str(exc))
        self._drain_pending()

    def _drain_pending(self) -> bool:
        """Re-fire a refresh that was latched while one was in flight. Returns True if it did."""
        if self._pending is None:
            return False
        autosize = self._pending
        self._pending = None
        self.refresh(autosize=autosize)
        return True

    def _fetch(
        self,
        channel: str | None,
        status: str | None,
        content: str | None,
        field_path: str | None,
    ) -> _MessagesSnapshot:
        """Runs on a worker thread — only blocking I/O, no widget access.

        With a content/field-path needle this routes to the scan-and-decrypt /messages/search endpoint
        (ADR 0046 #51) instead of the metadata list; the field-path box wins over the content box."""
        try:
            if field_path or content:
                # The field-path box, when filled, is the needle (the content box becomes its value
                # predicate); otherwise the content box is a raw/summary substring.
                search = self._poll.search_messages(
                    content=content if not field_path else None,
                    field_path=field_path,
                    field_value=content if field_path else None,
                    channel_id=channel,
                    status=status,
                    limit=200,
                )
                count = f"{search.matched} matched of {search.scanned} scanned"
                if search.truncated:
                    count += " — narrow your filters (scan cap hit)"
                return _MessagesSnapshot(list(search.messages), count, search.truncated, None)
            result = self._poll.list_messages(channel_id=channel, status=status, limit=200)
            return _MessagesSnapshot(
                list(result.messages),
                f"{len(result.messages)} shown of {result.total}",
                False,
                None,
            )
        except StepUpRequired as exc:
            # Not IdpStepUpRequired, which only the web console can answer, and not a role, scope
            # or second-factor refusal, which a password would not clear.
            return _MessagesSnapshot(None, "", False, str(exc), refusal=_StepUpRefusal(exc.action))
        except ApiError as exc:
            return _MessagesSnapshot(None, "", False, str(exc))

    def _apply(self, snap: _MessagesSnapshot, *, autosize: bool = False) -> None:
        """Runs on the main thread (result slot) — safe to touch widgets."""
        retried, self._stepped_up = self._stepped_up, False
        if snap.refusal is not None and not retried and self._step_up is not None:
            # _loading stays set while the prompt is up: its nested event loop may deliver a
            # refresh, which must latch rather than start a second search and a second prompt.
            try:
                answer = _ask_step_up(self._step_up, snap.refusal)
            finally:
                self._loading = False
            if answer is True:
                # Re-proved on the GUI thread; the polling client reads the rotated token through
                # the shared cell, so the resubmitted search carries the fresh grant. One retry
                # only: a second 403 is reported below rather than prompting again. The retry
                # re-reads the filters, so it also covers any refresh latched meanwhile, and keeps
                # that refresh's column refit.
                self._stepped_up = True
                self.refresh(autosize=autosize or bool(self._pending))
                return
            if isinstance(answer, str):
                # A refused re-proof: report its own cause, not the original 403.
                snap = replace(snap, error=answer)
            # Declined or refused: a refresh latched while the prompt was up would run the same
            # refused search and prompt again at once, so it is dropped.
            self._pending = None
        self._loading = False
        if snap.error is not None:
            self.error.emit(snap.error)
            self._drain_pending()
            return
        messages = snap.messages
        assert messages is not None
        previously_selected = self._selected_id()
        self._table.begin_populate()
        self._table.setRowCount(len(messages))
        for r, m in enumerate(messages):
            cells = [
                fmt_ts(m.received_at),
                m.channel_id,
                m.event or "",
                m.message_type or "",
                m.status,
                m.control_id or "",
                m.summary or "",
                m.metadata or "",
            ]
            for c, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if c == 0:
                    item.setData(Qt.ItemDataRole.UserRole, m.id)
                self._table.setItem(r, c, item)
        self._table.end_populate(autosize=(autosize or not self._loaded))
        self._loaded = True
        self._count.setText(snap.count_text)
        if previously_selected is not None and not self._reselect(previously_selected):
            # The selected message rolled off the list (deleted / filtered / aged past the 200-row
            # limit); tell the detail pane to clear so it stops showing a now-absent message (M2).
            self.selection_cleared.emit()
        # LAST, and only after rendering: re-fire a refresh that was latched while this one was in
        # flight. This used to run FIRST and `return` early, discarding the snapshot as "superseded"
        # — which livelocked the panel (BACKLOG #17). Under sustained refresh pressure there is ALWAYS
        # a latched request when a fetch lands, so every snapshot was discarded and the table never
        # updated: not slow, permanently stuck. Rendering first costs at most one fetch of staleness
        # (the drained refresh re-reads the current filters and renders again immediately), and the
        # list still converges on the latest filter — but it can no longer starve itself.
        self._drain_pending()

    def _on_select(self) -> None:
        message_id = self._selected_id()
        if message_id:
            self.message_selected.emit(message_id)

    def _selected_id(self) -> str | None:
        model = self._table.selectionModel()
        rows = model.selectedRows() if model else []
        if not rows:
            return None
        cell = self._table.item(rows[0].row(), 0)
        data = cell.data(Qt.ItemDataRole.UserRole) if cell else None
        return str(data) if data else None

    def _reselect(self, message_id: str) -> bool:
        """Restore a row selection after a refresh *without* re-emitting selection, so an
        auto-refresh tick keeps the highlighted row but doesn't reload the open detail pane.

        Returns True if the row was found and re-selected, False if the message is gone."""
        for r in range(self._table.rowCount()):
            cell = self._table.item(r, 0)
            if cell is not None and cell.data(Qt.ItemDataRole.UserRole) == message_id:
                self._table.blockSignals(True)
                self._table.selectRow(r)
                self._table.blockSignals(False)
                return True
        return False


class RefreshSettingsDialog(QDialog):
    """Modal picker for the auto-refresh interval. ``0`` means *off*."""

    #: (label, seconds) presets shown in the dropdown.
    PRESETS: list[tuple[str, float]] = [
        ("Off", 0.0),
        ("1 second", 1.0),
        ("2 seconds", 2.0),
        ("5 seconds", 5.0),
        ("10 seconds", 10.0),
        ("30 seconds", 30.0),
    ]

    def __init__(self, current: float, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Auto-refresh interval")

        self._combo = QComboBox()
        for label, seconds in self.PRESETS:
            self._combo.addItem(label, seconds)
        # Keep a non-preset value (e.g. a custom --poll) selectable rather than snapping it.
        if not any(abs(current - s) < 1e-9 for _, s in self.PRESETS):
            self._combo.addItem(f"{current:g} seconds", float(current))
        self._select_current(current)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Refresh the active page every:"))
        layout.addWidget(self._combo)
        layout.addWidget(buttons)

    def _select_current(self, current: float) -> None:
        for i in range(self._combo.count()):
            if abs(float(self._combo.itemData(i)) - current) < 1e-9:
                self._combo.setCurrentIndex(i)
                return

    def selected_seconds(self) -> float:
        return float(self._combo.currentData())
