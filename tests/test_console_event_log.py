# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""P6 — headless tests for the console Event Log page (#46)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from messagefoundry.api.models import ConnectionEventInfo  # noqa: E402


def _ev(
    *,
    id: int = 1,
    ts: float = 1_700_000_000.0,
    connection: str = "IB_ACME_ADT",
    transport: str = "mllp",
    direction: str = "inbound",
    kind: str = "established",
    peer_host: str | None = "10.0.0.1",
    message_id: str | None = None,
    reason: str | None = None,
) -> ConnectionEventInfo:
    return ConnectionEventInfo(
        id=id,
        ts=ts,
        connection=connection,
        transport=transport,
        direction=direction,
        kind=kind,
        peer_host=peer_host,
        message_id=message_id,
        reason=reason,
    )


class FakeClient:
    """The EngineClient surface the Event Log page uses, with canned data + call recording."""

    def __init__(self, events: list[ConnectionEventInfo]) -> None:
        self._events = events
        self.calls: list[tuple[str | None, str | None, int]] = []

    def list_connection_events(
        self, *, connection: str | None = None, kind: str | None = None, limit: int = 200
    ) -> list[ConnectionEventInfo]:
        self.calls.append((connection, kind, limit))
        return list(self._events)


@pytest.fixture(scope="module")
def qapp():  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def _settle(qapp, runner) -> None:  # type: ignore[no-untyped-def]
    runner._pool.waitForDone(5000)
    for _ in range(5):
        qapp.processEvents()


def test_table_populates_from_events(qapp) -> None:  # type: ignore[no-untyped-def]
    from messagefoundry.console.event_log_page import EventLogPage
    from messagefoundry.console.widgets import fmt_ts

    client = FakeClient(
        [
            _ev(kind="closed", reason="eof"),
            _ev(
                connection="OB_PARTNER",
                direction="outbound",
                kind="connection_lost",
                peer_host=None,
                message_id="m1",
                reason="connect refused",
            ),
        ]
    )
    page = EventLogPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)

    assert page._table.rowCount() == 2
    assert page._table.item(0, 0).text() == fmt_ts(1_700_000_000.0)  # Time
    assert page._table.item(0, 1).text() == "IB_ACME_ADT"  # Connection
    assert page._table.item(0, 2).text() == "inbound"  # Direction
    assert page._table.item(0, 4).text() == "closed"  # Event
    assert page._table.item(0, 5).text() == "10.0.0.1"  # Peer
    assert page._table.item(1, 4).text() == "connection_lost"
    assert page._table.item(1, 5).text() == ""  # None peer_host renders blank
    assert page._table.item(1, 6).text() == "connect refused"  # Reason
    page.stop()


def test_refresh_reloads_metadata_only_no_audit_concern(qapp) -> None:  # type: ignore[no-untyped-def]
    # Unlike Dead Letters, the event log is metadata-only, so the auto-refresh tick DOES reload.
    from messagefoundry.console.event_log_page import EventLogPage

    client = FakeClient([_ev()])
    page = EventLogPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)
    assert len(client.calls) == 1

    page.refresh()  # auto-refresh tick — reloads (no PHI audit storm)
    _settle(qapp, page._runner)
    assert len(client.calls) == 2
    page.stop()


def test_filters_are_passed_to_the_client(qapp) -> None:  # type: ignore[no-untyped-def]
    from messagefoundry.console.event_log_page import EventLogPage

    client = FakeClient([_ev()])
    page = EventLogPage(client)  # type: ignore[arg-type]
    page._connection.setText("IB_ACME_ADT")
    page._kind.setCurrentText("connection_lost")  # triggers reload via currentIndexChanged
    _settle(qapp, page._runner)

    connection, kind, _limit = client.calls[-1]
    assert connection == "IB_ACME_ADT" and kind == "connection_lost"
    page.stop()


def test_reload_after_stop_does_not_strand_loading(qapp) -> None:  # type: ignore[no-untyped-def]
    from messagefoundry.console.event_log_page import EventLogPage

    client = FakeClient([_ev()])
    page = EventLogPage(client)  # type: ignore[arg-type]
    page.stop()
    page.reload()  # after stop()
    assert client.calls == []  # no read started
    assert page._loading is False
