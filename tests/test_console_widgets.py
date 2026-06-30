# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless tests for the console: leaf widgets, the Connections + Log Search pages, and
the app shell. Runs Qt offscreen with a stub client returning canned API models, so we
verify the UI builds, populates, and wires actions without a display or a live server.
Skipped if PySide6 isn't installed."""

from __future__ import annotations

import os
import threading

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from messagefoundry.api.models import (  # noqa: E402
    ChannelInfo,
    ClusterNode,
    ClusterNodeList,
    ClusterStatus,
    ConnectionRow,
    DbInfo,
    EngineInfo,
    EventInfo,
    IntegrityResult,
    MessageDetail,
    MessageList,
    MessageSearchResults,
    MessageSummary,
    OutboxInfo,
    PurgeResult,
    ReplayResult,
    StatsResetResult,
    StatsResponse,
    SystemStatus,
)

ADT = "MSH|^~\\&|APP|FAC|RAPP|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def _channel_info() -> ChannelInfo:
    return ChannelInfo(
        id="ch1",
        name="One",
        enabled=True,
        running=True,
        source_type="mllp",
        destinations=["archive"],
    )


class StubClient:
    """Implements the EngineClient surface the console uses, with canned data."""

    def __init__(self) -> None:
        self.replayed: list[str] = []
        self.started: list[str] = []
        self.stopped: list[str] = []
        self.restarted: list[str] = []
        self.purged: list[tuple[str, str]] = []
        self.reset_calls: list[tuple[bool, list[tuple[str, str, str | None]]]] = []
        self.detail_loads = 0
        self.last_audit_summary: object = None
        self.search_calls: list[dict[str, object]] = []
        # Thread each read ran on, so tests can prove the per-page refresh now runs off the main
        # thread (the off-thread conversion of Connections / Log Search, M-25 / backlog #2).
        self.connections_thread: int | None = None
        self.list_messages_thread: int | None = None
        self.get_message_thread: int | None = None

    @property
    def current_user(self) -> None:  # stub console runs unauthenticated (embedding-style)
        return None

    def can(self, permission: str) -> bool:
        return False

    def list_channels(self) -> list[ChannelInfo]:
        return [_channel_info()]

    def list_messages(self, **kw: object) -> MessageList:
        self.list_messages_thread = threading.get_ident()
        self.last_audit_summary = kw.get("audit_summary")
        msg = MessageSummary(
            id="m1",
            channel_id="ch1",
            received_at=1_700_000_000.0,
            source_type="mllp",
            control_id="MSG1",
            message_type="ADT^A01",
            status="processed",
            error=None,
            event="delivered",
            summary="MRN 100001 · DOE, JANE",
            metadata=None,
        )
        return MessageList(total=1, limit=200, offset=0, messages=[msg])

    def search_messages(self, **kw: object) -> MessageSearchResults:
        self.search_calls.append(kw)
        msg = MessageSummary(
            id="s1",
            channel_id="ch1",
            received_at=1_700_000_000.0,
            source_type="mllp",
            control_id="MSGS",
            message_type="ADT^A01",
            status="processed",
            error=None,
            event="delivered",
            summary="MRN 100001 · DOE, JANE",
            metadata=None,
        )
        return MessageSearchResults(
            messages=[msg], scanned=5, matched=1, truncated=True, limit=200, scan_limit=2000
        )

    def get_message(self, message_id: str) -> MessageDetail:
        self.detail_loads += 1
        self.get_message_thread = threading.get_ident()
        return MessageDetail(
            id=message_id,
            channel_id="ch1",
            received_at=1_700_000_000.0,
            source_type="mllp",
            control_id="MSG1",
            message_type="ADT^A01",
            status="processed",
            error=None,
            raw=ADT,
            outbox=[
                OutboxInfo(
                    id="o1",
                    destination_name="archive",
                    status="done",
                    attempts=1,
                    next_attempt_at=1_700_000_000.0,
                    last_error=None,
                )
            ],
            events=[EventInfo(ts=1_700_000_000.0, event="received", destination=None, detail="1")],
        )

    def replay(self, message_id: str) -> ReplayResult:
        self.replayed.append(message_id)
        return ReplayResult(message_id=message_id, requeued=1)

    def start_connection(self, name: str) -> None:
        self.started.append(name)

    def stop_connection(self, name: str) -> None:
        self.stopped.append(name)

    def restart_connection(self, name: str) -> None:
        self.restarted.append(name)

    def purge_connection(self, name: str, scope: str = "all") -> PurgeResult:
        self.purged.append((name, scope))
        return PurgeResult(cancelled=1)

    def reset_stats(
        self,
        *,
        all_connections: bool = False,
        targets: object = (),
    ) -> StatsResetResult:
        items = list(targets)  # type: ignore[call-overload]
        self.reset_calls.append((all_connections, items))
        return StatsResetResult(reset=(99 if all_connections else len(items)))

    def connections(self) -> list[ConnectionRow]:
        self.connections_thread = threading.get_ident()
        return [
            ConnectionRow(
                role="source",
                channel_id="ch1",
                channel_name="One",
                destination=None,
                name="One ▸ source",
                status="running",
                direction="in",
                method="MLLP",
                peer="0.0.0.0",
                port=2575,
                queue_depth=None,
                idle_seconds=5.0,
                alerts_active=0,
                errored=0,
                read=3,
                written=None,
                backlog_seconds=None,
                delivered_age_seconds=None,
            ),
            ConnectionRow(
                role="destination",
                channel_id="ch1",
                channel_name="One",
                destination="archive",
                name="One ▸ archive",
                status="running",
                direction="out",
                method="File",
                peer="/out",
                port=None,
                queue_depth=2,
                idle_seconds=1.0,
                alerts_active=0,
                errored=0,
                read=None,
                written=5,
                backlog_seconds=120.0,
                delivered_age_seconds=30.0,
            ),
        ]

    def stats(self) -> StatsResponse:
        return StatsResponse(outbox_by_status={"done": 1})

    def status(self) -> SystemStatus:
        return SystemStatus(
            engine=EngineInfo(
                version="0.0.1",
                uptime_seconds=65.0,
                pid=1234,
                channels_total=1,
                channels_running=1,
                channels_stopped=0,
                outbox_by_status={"done": 1},
            ),
            db=DbInfo(
                path="C:/mefor.db",
                size_bytes=2048,
                disk_free_bytes=10 * 1024**3,
                journal_mode="wal",
                messages=5,
                events=9,
                audit=2,
            ),
        )

    def integrity_check(self) -> IntegrityResult:
        return IntegrityResult(ok=True, detail="ok")

    def cluster_status(self) -> ClusterStatus:
        return ClusterStatus(
            node_id="local", clustered=False, is_leader=True, role="single-node", config_version=0
        )

    def cluster_nodes(self) -> ClusterNodeList:
        return ClusterNodeList(
            nodes=[
                ClusterNode(
                    node_id="local",
                    host=None,
                    pid=None,
                    status="single-node",
                    started_at=None,
                    last_seen=None,
                    is_leader=True,
                )
            ],
            leader_node_id="local",
            lease_owner=None,
            lease_expires_at=None,
        )


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def _settle(qapp, *runners) -> None:
    """Let off-thread page runner(s) finish and deliver their queued results to the main thread.

    The per-page refresh/load now runs the engine read on a worker thread (M-25 / backlog #2) and
    applies on the main thread via a queued signal, so a test must wait for the worker and pump the
    event loop before asserting the rendered result."""
    for runner in runners:
        runner._pool.waitForDone(5000)
    for _ in range(5):
        qapp.processEvents()


# --- leaf widgets ------------------------------------------------------------


def test_parse_tree_view_handles_unparseable(qapp) -> None:
    from messagefoundry.console.widgets import ParseTreeView

    view = ParseTreeView()
    view.show_message("not hl7")
    assert view.topLevelItemCount() == 1
    assert view.topLevelItem(0).text(0) == "(unparseable)"


def test_message_detail_loads_and_replays(qapp) -> None:
    from messagefoundry.console.widgets import MessageDetailPanel

    client = StubClient()
    detail = MessageDetailPanel(client)
    detail.load("m1")
    _settle(qapp, detail._runner)
    assert "MSH" in detail._raw.toPlainText()
    assert detail._tree.topLevelItemCount() == 2  # MSH + PID
    assert detail._outbox.rowCount() == 1
    detail._on_replay()
    assert client.replayed == ["m1"]
    detail.stop()


def test_message_detail_escapes_html_in_summary(qapp) -> None:
    from messagefoundry.console.widgets import MessageDetailPanel

    class EvilClient(StubClient):
        def get_message(self, message_id: str) -> MessageDetail:
            return MessageDetail(
                id=message_id,
                channel_id="ch1",
                received_at=1_700_000_000.0,
                source_type="mllp",
                control_id="<img src=x onerror=alert(1)>",  # HL7-derived, attacker-influenced
                message_type="<b>ADT</b>",
                status="error",
                error="<script>beacon()</script>",
                raw=ADT,
                outbox=[],
                events=[],
            )

    detail = MessageDetailPanel(EvilClient())
    detail.load("m1")
    _settle(qapp, detail._runner)
    text = detail._summary.text()
    # H1: the rich-text summary must render HL7-derived fields as escaped text, never as live markup.
    assert "<img" not in text and "<script>" not in text
    assert "&lt;img" in text and "&lt;script&gt;" in text
    detail.stop()


def test_refresh_settings_dialog_presets(qapp) -> None:
    from messagefoundry.console.widgets import RefreshSettingsDialog

    assert RefreshSettingsDialog(5.0).selected_seconds() == 5.0
    assert RefreshSettingsDialog(0.0).selected_seconds() == 0.0
    assert RefreshSettingsDialog(3.0).selected_seconds() == 3.0  # non-preset kept selectable


# --- Connections page --------------------------------------------------------


def test_connections_page_renders_endpoint_rows(qapp) -> None:
    from messagefoundry.console.connections import ConnectionsPage

    page = ConnectionsPage(StubClient())
    page.refresh()
    _settle(qapp, page._runner)
    assert page._table.rowCount() == 2
    assert page._table.item(0, 0).text() == "One ▸ source"
    assert page._table.item(0, 2).text() == "in"  # Direction (source)
    assert page._table.item(1, 2).text() == "out"  # Direction (destination)
    assert page._table.item(0, 3).text() == "MLLP"  # Method (source)
    assert page._table.item(1, 3).text() == "File"  # Method (destination)
    assert page._table.item(0, 4).text() == "Logs"  # Logs (clickable cell)
    assert page._table.item(0, 5).text() == "—"  # source row: no Queue Depth
    assert page._table.item(1, 5).text() == "2"  # destination row has a queue


def test_connections_start_targets_inbound(qapp) -> None:
    from messagefoundry.console.connections import ConnectionsPage

    client = StubClient()
    page = ConnectionsPage(client)
    page.refresh()
    _settle(qapp, page._runner)
    page._table.selectAll()  # both endpoint rows
    page._start.click()
    assert client.started == ["ch1"]  # only the inbound (source) row, by connection name
    page.stop()


def test_connections_purge_targets_outbound_only(qapp, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from messagefoundry.console import connections as conn_mod
    from messagefoundry.console.connections import ConnectionsPage

    # M-28: "Purge all" now confirms first — auto-accept so this test exercises the purge path.
    monkeypatch.setattr(
        conn_mod.QMessageBox,
        "question",
        lambda *a, **k: conn_mod.QMessageBox.StandardButton.Yes,
    )
    client = StubClient()
    page = ConnectionsPage(client)
    page.refresh()
    _settle(qapp, page._runner)
    page._table.selectAll()
    page._purge("all")
    assert client.purged == [("archive", "all")]  # the outbound (destination) connection
    page.stop()


def test_connections_purge_all_requires_confirmation(qapp, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # M-28: declining the confirmation dialog must NOT purge anything.
    from messagefoundry.console import connections as conn_mod
    from messagefoundry.console.connections import ConnectionsPage

    monkeypatch.setattr(
        conn_mod.QMessageBox,
        "question",
        lambda *a, **k: conn_mod.QMessageBox.StandardButton.No,
    )
    client = StubClient()
    page = ConnectionsPage(client)
    page.refresh()
    _settle(qapp, page._runner)
    page._table.selectAll()
    page._purge("all")
    assert client.purged == []  # declined → nothing purged
    page.stop()


def test_connections_reset_selected_sends_targets(qapp) -> None:  # type: ignore[no-untyped-def]
    from messagefoundry.console.connections import ConnectionsPage

    client = StubClient()
    page = ConnectionsPage(client)
    page.refresh()
    _settle(qapp, page._runner)
    page._table.selectAll()  # both rows: the source and the destination
    page._reset_stats(all_connections=False)
    # Source rows carry no destination (None); the destination row carries its outbound name.
    assert client.reset_calls == [
        (False, [("source", "ch1", None), ("destination", "ch1", "archive")])
    ]
    page.stop()


def test_connections_reset_selected_requires_selection(qapp) -> None:  # type: ignore[no-untyped-def]
    from messagefoundry.console.connections import ConnectionsPage

    client = StubClient()
    page = ConnectionsPage(client)
    page.refresh()
    _settle(qapp, page._runner)
    errors: list[str] = []
    page.error.connect(errors.append)
    page._reset_stats(all_connections=False)  # nothing selected
    assert client.reset_calls == []
    assert errors and "Reset All" in errors[0]
    page.stop()


def test_connections_reset_all_confirms_and_sends(qapp, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from messagefoundry.console import connections as conn_mod
    from messagefoundry.console.connections import ConnectionsPage

    monkeypatch.setattr(
        conn_mod.QMessageBox, "question", lambda *a, **k: conn_mod.QMessageBox.StandardButton.Yes
    )
    client = StubClient()
    page = ConnectionsPage(client)
    page.refresh()
    _settle(qapp, page._runner)
    page._reset_stats(all_connections=True)  # no selection needed for "all"
    assert client.reset_calls == [(True, [])]
    page.stop()


def test_connections_reset_all_declined_does_nothing(qapp, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from messagefoundry.console import connections as conn_mod
    from messagefoundry.console.connections import ConnectionsPage

    monkeypatch.setattr(
        conn_mod.QMessageBox, "question", lambda *a, **k: conn_mod.QMessageBox.StandardButton.No
    )
    client = StubClient()
    page = ConnectionsPage(client)
    page.refresh()
    _settle(qapp, page._runner)
    page._reset_stats(all_connections=True)
    assert client.reset_calls == []  # declined → no call
    page.stop()


def test_connections_logs_link_emits_open_logs(qapp) -> None:
    from messagefoundry.console.connections import ConnectionsPage

    page = ConnectionsPage(StubClient())
    page.refresh()
    _settle(qapp, page._runner)
    seen: list[str] = []
    page.open_logs.connect(seen.append)
    page._table.cellClicked.emit(0, 4)  # click the Logs cell on the source row
    assert seen == ["ch1"]
    page.stop()


# --- Log Search page ---------------------------------------------------------


def test_log_search_preserves_selection_without_reloading_detail(qapp) -> None:
    from messagefoundry.console.search import LogSearchPage

    client = StubClient()
    page = LogSearchPage(client)
    page.refresh()
    _settle(qapp, page.messages._runner)
    page.messages._table.selectRow(0)  # selecting loads detail once (off-thread)
    _settle(qapp, page.detail._runner)
    assert client.detail_loads == 1
    page.refresh()  # an auto-refresh tick keeps selection but must not reload detail
    _settle(qapp, page.messages._runner)
    assert page.messages._selected_id() == "m1"
    _settle(qapp, page.detail._runner)  # a spurious detail reload would have landed here
    assert client.detail_loads == 1
    page.stop()


def test_log_search_clears_detail_when_selection_drops(qapp) -> None:
    from messagefoundry.api.models import MessageList
    from messagefoundry.console.search import LogSearchPage

    client = StubClient()
    page = LogSearchPage(client)
    page.refresh()
    _settle(qapp, page.messages._runner)
    page.messages._table.selectRow(0)  # loads detail for m1 (off-thread)
    _settle(qapp, page.detail._runner)
    assert page.detail._message_id == "m1"
    # The selected message rolls off the list on the next refresh.
    client.list_messages = lambda **kw: MessageList(total=0, limit=200, offset=0, messages=[])  # type: ignore[assignment,method-assign]
    page.refresh()
    _settle(qapp, page.messages._runner)
    # M2: the detail pane is cleared rather than left showing the now-absent message.
    assert page.detail._message_id is None
    page.stop()


def test_log_search_set_channel_filters(qapp) -> None:
    from messagefoundry.console.search import LogSearchPage

    page = LogSearchPage(StubClient())
    page.set_channel("ch1")
    assert page.messages._channel_filter.text() == "ch1"
    _settle(qapp, page.messages._runner)
    page.stop()


def test_messages_panel_renders_new_columns(qapp) -> None:
    from messagefoundry.console.widgets import MessagesPanel

    panel = MessagesPanel(StubClient())
    panel.refresh()
    _settle(qapp, panel._runner)
    assert panel.COLUMNS == [
        "Time",
        "Channel",
        "Event",
        "Msg. Type",
        "Status",
        "Control ID",
        "Summary",
        "Metadata",
    ]
    assert panel._table.columnCount() == 8
    assert panel._table.item(0, 1).text() == "ch1"  # Channel
    assert panel._table.item(0, 2).text() == "delivered"  # Event (latest processing event)
    assert panel._table.item(0, 6).text() == "MRN 100001 · DOE, JANE"  # Summary
    panel.stop()


def test_log_search_audits_user_refresh_not_timer(qapp) -> None:
    from messagefoundry.console.search import LogSearchPage

    client = StubClient()
    page = LogSearchPage(client)

    page.reload()  # user-initiated open -> audit (Summary column visible by default)
    _settle(qapp, page.messages._runner)
    assert client.last_audit_summary is True

    page.refresh()  # auto-refresh tick -> no audit
    _settle(qapp, page.messages._runner)
    assert client.last_audit_summary is False
    page.stop()


# --- off-thread reads (M-25 / backlog #2): the per-page refresh no longer blocks the GUI thread ---


def test_connections_refresh_reads_off_main_thread(qapp) -> None:
    from messagefoundry.console.connections import ConnectionsPage

    client = StubClient()
    page = ConnectionsPage(client)
    main = threading.get_ident()
    page.refresh()
    _settle(qapp, page._runner)
    assert client.connections_thread is not None and client.connections_thread != main  # off-thread
    assert page._table.rowCount() == 2  # ...and the result applied on the main thread
    page.stop()


def test_messages_refresh_reads_off_main_thread(qapp) -> None:
    from messagefoundry.console.widgets import MessagesPanel

    client = StubClient()
    panel = MessagesPanel(client)
    main = threading.get_ident()
    panel.refresh()
    _settle(qapp, panel._runner)
    assert client.list_messages_thread is not None and client.list_messages_thread != main
    assert panel._table.rowCount() == 1
    panel.stop()


def test_message_detail_load_reads_off_main_thread(qapp) -> None:
    from messagefoundry.console.widgets import MessageDetailPanel

    client = StubClient()
    detail = MessageDetailPanel(client)
    main = threading.get_ident()
    detail.load("m1")
    _settle(qapp, detail._runner)
    assert client.get_message_thread is not None and client.get_message_thread != main
    assert detail._message_id == "m1"
    detail.stop()


def test_message_detail_drops_stale_load(qapp) -> None:
    # Rapid row clicks: only the latest load() applies; an earlier in-flight result is dropped so the
    # pane can't end up showing an older message than the one currently selected.
    from messagefoundry.console.widgets import MessageDetailPanel

    detail = MessageDetailPanel(StubClient())
    detail.load("m1")
    detail.load("m2")  # supersedes m1
    _settle(qapp, detail._runner)
    assert detail._message_id == "m2"
    detail.stop()


def test_messages_panel_latches_refresh_while_loading(qapp) -> None:
    # A refresh requested while one is in flight (e.g. a filter change via the Connections 'Logs'
    # link) must be latched + re-fired, not dropped — otherwise the filter box and the list mismatch
    # and never self-heal with auto-refresh off.
    from messagefoundry.console.widgets import MessagesPanel

    client = StubClient()
    panel = MessagesPanel(client)
    panel._loading = True  # simulate a read already in flight
    panel.refresh(audit=True)
    assert panel._pending is True  # latched, not dropped
    # The in-flight read completes: _apply drains the pending request and re-fires it off-thread.
    panel._apply(panel._fetch(None, None, None, None, False))
    _settle(qapp, panel._runner)
    assert panel._pending is None  # drained
    assert panel._table.rowCount() == 1  # the latched refresh actually ran + rendered
    panel.stop()


def test_messages_panel_content_search_routes_to_search_endpoint(qapp) -> None:
    # ADR 0046 #51: when the content box is filled the panel calls /messages/search (scan-and-decrypt),
    # not the metadata list, and surfaces the truncated "narrow your filters" signal.
    from messagefoundry.console.widgets import MessagesPanel

    client = StubClient()
    panel = MessagesPanel(client)
    panel._content_filter.setText("JANE")
    panel.refresh(audit=True)
    _settle(qapp, panel._runner)
    assert client.search_calls, "content needle must route to search_messages"
    assert client.search_calls[0]["content"] == "JANE"
    assert client.search_calls[0]["field_path"] is None
    assert panel._table.rowCount() == 1
    assert "narrow your filters" in panel._count.text()  # truncated signal shown
    panel.stop()


def test_messages_panel_field_path_search_passes_path_and_value(qapp) -> None:
    # A filled field-path box is the needle; the content box becomes its value predicate.
    from messagefoundry.console.widgets import MessagesPanel

    client = StubClient()
    panel = MessagesPanel(client)
    panel._field_path_filter.setText("PID-3")
    panel._content_filter.setText("100001")
    panel.refresh(audit=True)
    _settle(qapp, panel._runner)
    assert client.search_calls[0]["field_path"] == "PID-3"
    assert client.search_calls[0]["field_value"] == "100001"
    assert (
        client.search_calls[0]["content"] is None
    )  # content folds into field_value, not a substring
    panel.stop()


def test_connections_unexpected_error_clears_loading(qapp) -> None:
    # An unexpected (non-ApiError) exception in the off-thread read must still clear the in-flight
    # guard via on_error, or the page would wedge forever (every later refresh short-circuits).
    from messagefoundry.console.connections import ConnectionsPage

    client = StubClient()
    client.connections = lambda: (_ for _ in ()).throw(RuntimeError("kaboom"))  # type: ignore[assignment,method-assign]
    page = ConnectionsPage(client)
    errors: list[str] = []
    page.error.connect(errors.append)
    page.refresh()
    _settle(qapp, page._runner)
    assert page._loading is False  # not wedged
    assert errors and "kaboom" in errors[0]
    # ...and a subsequent valid refresh is no longer blocked by a stuck guard.
    client.connections = StubClient().connections  # type: ignore[method-assign]
    page.refresh()
    _settle(qapp, page._runner)
    assert page._table.rowCount() == 2
    page.stop()


def test_uses_poll_client_for_reads_not_the_action_client(qapp) -> None:
    # The off-thread read must go through the dedicated poll client, leaving the primary (action)
    # client untouched by worker threads — the separation that closes the cross-thread hazard.
    from messagefoundry.console.connections import ConnectionsPage

    actions = StubClient()
    poll = StubClient()
    page = ConnectionsPage(actions, poll_client=poll)
    page.refresh()
    _settle(qapp, page._runner)
    assert poll.connections_thread is not None  # the read ran on the poll client
    assert actions.connections_thread is None  # ...never on the action client
    page.stop()


# --- app shell ---------------------------------------------------------------


def test_app_window_builds_nav_and_default_page(qapp) -> None:
    from messagefoundry.console.shell import AppWindow

    window = AppWindow(StubClient(), poll_seconds=2.0)
    # Connections, Alerts, Dead Letters, Event Log, Log Search, Engine Status
    assert window._nav.count() == 6
    assert window._timer.isActive() and window._timer.interval() == 2000
    _settle(qapp, window.connections._runner)  # the default page reloads its rows off-thread
    assert window.connections._table.rowCount() == 2  # default page rendered
    window.close()


def test_poll_health_401_emits_session_expired(qapp, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # M-26: a 401 on the health poll is a session expiry, not "engine unreachable" — distinct heart
    # state + a session_expired signal so the entrypoint can re-prompt sign-in.
    from messagefoundry.console import shell
    from messagefoundry.console.client import ApiError
    from messagefoundry.console.shell import AppWindow

    monkeypatch.setattr(shell.service_control, "service_state", lambda name: "unknown")
    client = StubClient()

    def _raise_401() -> object:
        raise ApiError("token expired", status=401)

    monkeypatch.setattr(client, "status", _raise_401)
    window = AppWindow(client)  # __init__ runs one poll (no listener yet)
    seen: list[bool] = []
    window.session_expired.connect(lambda: seen.append(True))
    # Drive the off-thread poll's fetch+apply synchronously (the threaded path is covered in
    # test_console_status.py). The fetch sees the 401; the apply must treat it as session expiry.
    window._apply_health(window._fetch_health())
    assert seen == [True]
    assert "Session expired" in window._heart.toolTip()
    window.close()  # drops the constructor's pending async poll


def test_app_window_close_stops_timers(qapp) -> None:
    from messagefoundry.console.shell import AppWindow

    window = AppWindow(StubClient(), poll_seconds=2.0)
    assert window._timer.isActive() and window._health_timer.isActive()
    window.close()
    # M3: both timers stop on close so a queued tick can't touch widgets mid-teardown.
    assert not window._timer.isActive()
    assert not window._health_timer.isActive()


def test_app_window_interval_controls(qapp) -> None:
    from messagefoundry.console.shell import AppWindow

    window = AppWindow(StubClient(), poll_seconds=2.0)
    seen: list[float] = []
    window.interval_changed.connect(seen.append)
    window.set_interval(0)
    assert not window._timer.isActive()
    window.set_interval(5)
    assert window._timer.interval() == 5000
    assert seen == [0.0, 5.0]


def test_app_window_open_logs_navigates_and_filters(qapp) -> None:
    from messagefoundry.console.shell import AppWindow

    window = AppWindow(StubClient())
    window.connections.open_logs.emit("ch1")
    # Log Search (after Connections, Alerts, Dead Letters, Event Log)
    assert window._nav.currentRow() == 4
    assert window.log_search.messages._channel_filter.text() == "ch1"


def test_app_window_zoom_scales_and_resets(qapp) -> None:
    from PySide6.QtWidgets import QApplication

    from messagefoundry.console.shell import AppWindow

    app = QApplication.instance()
    base = app.font().pointSizeF()
    window = AppWindow(StubClient())
    window._zoom(1)
    assert app.font().pointSizeF() > base
    window._zoom(0)  # reset to launch size
    assert abs(app.font().pointSizeF() - base) < 0.01


def test_messages_panel_headers_left_aligned(qapp) -> None:
    from PySide6.QtCore import Qt

    from messagefoundry.console.widgets import MessagesPanel

    panel = MessagesPanel(StubClient())
    align = panel._table.horizontalHeader().defaultAlignment()
    assert bool(align & Qt.AlignmentFlag.AlignLeft)


def test_engine_status_page_renders(qapp) -> None:
    from messagefoundry.console.status import EngineStatusPage

    page = EngineStatusPage(StubClient())
    page._apply(page._fetch())  # synchronous fetch+apply (off-thread path covered separately)
    assert page._engine["Reachable"].text() == "yes"
    assert page._engine["Version"].text() == "0.0.1"
    assert page._engine["Channels"].text() == "1 running / 1 total"
    assert page._db["Messages"].text() == "5"
    assert page._db["Journal mode"].text() == "wal"
    page.stop()


def test_engine_status_integrity_button(qapp) -> None:
    from messagefoundry.console.status import EngineStatusPage

    page = EngineStatusPage(StubClient())
    page._integrity_btn.click()  # runs the check off-thread, then applies the result
    page._runner._pool.waitForDone(5000)
    for _ in range(5):
        qapp.processEvents()
    assert "ok" in page._integrity_result.text().lower()
    assert page._integrity_btn.isEnabled()  # re-enabled after the check completes
    page.stop()


def test_engine_status_service_controls(qapp, monkeypatch) -> None:
    from messagefoundry.console import service_control
    from messagefoundry.console.status import EngineStatusPage

    monkeypatch.setattr(service_control, "service_state", lambda name: "running")
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        service_control,
        "control_service",
        lambda action, name: calls.append((action, name)) or True,
    )
    page = EngineStatusPage(StubClient())
    page._apply(page._fetch())  # synchronous fetch+apply
    assert page._service_state.text() == "running"
    assert page._svc_stop.isEnabled() and page._svc_restart.isEnabled()
    assert not page._svc_start.isEnabled()  # already running

    monkeypatch.setattr(page, "_confirm_admin", lambda action: False)  # user declines the prompt
    page._svc_stop.click()
    assert calls == []

    monkeypatch.setattr(page, "_confirm_admin", lambda action: True)  # user confirms
    page._svc_stop.click()
    assert calls == [("stop", "MessageFoundry")]
    page.stop()


def test_control_service_rejects_unsafe_name() -> None:
    # low-16: the service name is interpolated into an ELEVATED cmd.exe line; a name with shell
    # metacharacters must be refused before any execution (validated before the platform check).
    from messagefoundry.console import service_control

    assert service_control._is_safe_service_name("MessageFoundry Engine")
    assert not service_control._is_safe_service_name('evil" & calc & "')
    with pytest.raises(ValueError):
        service_control.control_service("start", 'x" & shutdown /s & "')


def test_engine_status_install_offered_when_not_installed(qapp, monkeypatch) -> None:
    from pathlib import Path

    from messagefoundry.console import service_control
    from messagefoundry.console.status import EngineStatusPage

    monkeypatch.setattr(service_control, "service_state", lambda name: "not installed")
    monkeypatch.setattr(service_control, "install_script_path", lambda: Path("install-service.ps1"))
    installs: list[tuple[str, str]] = []
    monkeypatch.setattr(
        service_control, "install_service", lambda p, env: installs.append((p, env)) or True
    )

    page = EngineStatusPage(StubClient())
    page._apply(page._fetch())  # synchronous fetch+apply
    assert not page._svc_install.isHidden()  # install offered only when not installed
    assert not page._svc_start.isEnabled()

    # The operator picks the active environment (ADR 0017 — no silent default) before confirming.
    monkeypatch.setattr(page, "_prompt_environment", lambda: "prod")

    monkeypatch.setattr(page, "_confirm_install", lambda env: False)  # user declines the dialog
    page._svc_install.click()
    assert installs == []

    monkeypatch.setattr(page, "_confirm_install", lambda env: True)  # user confirms
    page._svc_install.click()
    assert installs == [("install-service.ps1", "prod")]

    # Cancelling / failing the environment prompt aborts before any confirm or install.
    installs.clear()
    monkeypatch.setattr(page, "_prompt_environment", lambda: None)
    page._svc_install.click()
    assert installs == []
    page.stop()


def test_install_service_validates_environment() -> None:
    # The environment name is interpolated into an ELEVATED PowerShell line and becomes a filename
    # segment (environments/<name>.toml), so an unsafe value must be refused before any execution
    # (validated on every platform, before the win32 gate).
    from messagefoundry.console import service_control

    assert service_control.is_safe_environment("prod")
    assert service_control.is_safe_environment("site-a_test.1")
    assert not service_control.is_safe_environment("")
    assert not service_control.is_safe_environment('evil" & calc & "')

    params = service_control._install_params(r"C:\repo\install-service.ps1", "prod")
    assert '-Environment "prod"' in params
    assert r'-File "C:\repo\install-service.ps1"' in params

    with pytest.raises(ValueError):
        service_control._install_params("install-service.ps1", 'x" & shutdown /s & "')
    with pytest.raises(ValueError):
        service_control.install_service("install-service.ps1", "bad name")


# --- nav health heart --------------------------------------------------------


def test_heart_indicator_states(qapp) -> None:
    from messagefoundry.console.shell import HeartIndicator

    heart = HeartIndicator()
    assert heart._state == "green"
    heart.set_state("orange")
    assert heart._state == "orange"
    heart.set_state("red")
    assert heart._state == "red"


def test_heart_reflects_health(qapp, monkeypatch) -> None:
    from messagefoundry.api.models import DbInfo, SystemStatus
    from messagefoundry.console import service_control
    from messagefoundry.console.client import ApiError
    from messagefoundry.console.shell import AppWindow

    # No service installed -> the heart tracks the engine API + disk. Drive the poll's fetch+apply
    # synchronously (the off-thread path itself is covered in test_console_status.py).
    monkeypatch.setattr(service_control, "service_state", lambda name: "not installed")
    window = AppWindow(StubClient())

    def poll() -> None:
        window._apply_health(window._fetch_health())

    poll()
    assert window._heart._state == "green"  # the stub is healthy
    assert window._status.text() == ""  # reachable -> no stale error

    healthy = StubClient().status()
    low = SystemStatus(
        engine=healthy.engine,
        db=DbInfo(**{**healthy.db.model_dump(), "disk_free_bytes": 1024}),
    )
    monkeypatch.setattr(window._client, "status", lambda: low)
    poll()
    assert window._heart._state == "orange"  # low disk

    def boom() -> SystemStatus:
        raise ApiError("down")

    monkeypatch.setattr(window._client, "status", boom)
    poll()
    assert window._heart._state == "red"  # API unreachable
    assert "down" in window._status.text()  # error surfaced while the engine is down

    # Service installed but stopped -> red, even though the API is healthy (service-aware).
    monkeypatch.setattr(window._client, "status", lambda: healthy)
    monkeypatch.setattr(service_control, "service_state", lambda name: "stopped")
    poll()
    assert window._heart._state == "red"
    assert window._status.text() == ""  # engine still reachable -> stale error cleared
    window.close()


def test_health_poll_preserves_page_error(qapp, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # low-14: a page-level error in the shared status line must survive the periodic health poll —
    # the poll clears only its OWN reachability error, not an error a page slot set.
    from messagefoundry.console import service_control
    from messagefoundry.console.shell import AppWindow

    monkeypatch.setattr(service_control, "service_state", lambda name: "not installed")
    window = AppWindow(StubClient())
    window._apply_health(window._fetch_health())  # healthy
    window._show_error("could not delete user: 403")  # a page action failed
    window._apply_health(window._fetch_health())  # engine still reachable
    assert window._status.text() == "could not delete user: 403"  # not wiped by the poll
    window.close()
