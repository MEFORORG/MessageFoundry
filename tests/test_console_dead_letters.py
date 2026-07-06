# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Headless tests for the console Dead Letters page (BACKLOG #22)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from messagefoundry.api.models import (  # noqa: E402
    DeadLetterList,
    DeadLetterReplayResult,
    DeadLetterRow,
)
from messagefoundry.console.client import ApiError  # noqa: E402


def _row(
    *,
    channel_id: str,
    destination_name: str,
    failed_at: float = 1_700_000_000.0,
    message_type: str = "ADT^A01",
    control_id: str = "MSG1",
    attempts: int = 5,
    last_error: str | None = "connection refused",
    summary: str | None = None,
) -> DeadLetterRow:
    return DeadLetterRow(
        outbox_id=f"o-{destination_name}",
        message_id=f"m-{destination_name}",
        channel_id=channel_id,
        destination_name=destination_name,
        attempts=attempts,
        last_error=last_error,
        failed_at=failed_at,
        control_id=control_id,
        message_type=message_type,
        received_at=failed_at,
        summary=summary,
    )


class FakeClient:
    """The EngineClient surface the Dead Letters page uses, with canned data + call recording."""

    def __init__(
        self,
        rows: list[DeadLetterRow],
        *,
        can_replay: bool = True,
        replay_all_error: ApiError | None = None,
    ) -> None:
        self._rows = rows
        self._can_replay = can_replay
        # When set, an UNSCOPED replay-all raises this (simulating a channel-scoped operator's 403).
        self._replay_all_error = replay_all_error
        self.list_calls = 0
        self.replay_calls: list[tuple[str | None, str | None]] = []

    def can(self, permission: str) -> bool:
        return self._can_replay if permission == "messages:replay" else False

    def list_dead_letters(self, **kw: object) -> DeadLetterList:
        self.list_calls += 1
        return DeadLetterList(
            total=len(self._rows), limit=200, offset=0, dead_letters=list(self._rows)
        )

    def replay_dead_letters(
        self, *, channel_id: str | None = None, destination_name: str | None = None
    ) -> DeadLetterReplayResult:
        self.replay_calls.append((channel_id, destination_name))
        if self._replay_all_error is not None and channel_id is None and destination_name is None:
            raise self._replay_all_error
        return DeadLetterReplayResult(requeued=len(self._rows))


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


def _settle(qapp, runner) -> None:
    """Let the off-thread dead-letter read finish and deliver its result to the main thread."""
    runner._pool.waitForDone(5000)
    for _ in range(5):
        qapp.processEvents()


def test_table_populates_from_dead_letter_list(qapp) -> None:
    from messagefoundry.console.dead_letters_page import DeadLettersPage
    from messagefoundry.console.widgets import fmt_ts

    client = FakeClient(
        [
            _row(channel_id="IB_ACME_ADT", destination_name="OB_FILE", summary="MRN 100 · DOE"),
            _row(channel_id="IB_ACME_ORM", destination_name="OB_LAB", last_error=None),
        ]
    )
    page = DeadLettersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)

    assert page._table.rowCount() == 2
    assert page._table.item(0, 0).text() == fmt_ts(1_700_000_000.0)  # Failed at
    assert page._table.item(0, 1).text() == "IB_ACME_ADT"  # Inbound
    assert page._table.item(0, 2).text() == "OB_FILE"  # Destination
    assert page._table.item(0, 3).text() == "ADT^A01"  # Type
    assert page._table.item(0, 5).text() == "5"  # Attempts
    assert page._table.item(0, 7).text() == "MRN 100 · DOE"  # Summary
    assert page._table.item(1, 6).text() == ""  # None last_error renders blank
    page.stop()


def test_refresh_is_a_noop_no_audit_storm(qapp) -> None:
    # The silent auto-refresh tick must NOT reload (GET /dead-letters audits PHI exposure with no
    # opt-out, so a per-tick reload would cause a periodic server-side audit storm).
    from messagefoundry.console.dead_letters_page import DeadLettersPage

    client = FakeClient([_row(channel_id="IB_A", destination_name="OB_A")])
    page = DeadLettersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)
    assert client.list_calls == 1

    page.refresh()  # auto-refresh tick — must not hit the client
    _settle(qapp, page._runner)
    assert client.list_calls == 1  # unchanged: refresh() is a no-op
    page.stop()


def test_replay_selected_uses_selected_scope_and_reloads(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.console import dead_letters_page

    client = FakeClient(
        [
            _row(channel_id="IB_A", destination_name="OB_A"),
            _row(channel_id="IB_B", destination_name="OB_B"),
        ]
    )
    page = dead_letters_page.DeadLettersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)

    page._table.selectRow(1)  # the second row -> IB_B / OB_B
    monkeypatch.setattr(
        dead_letters_page.QMessageBox,
        "question",
        staticmethod(lambda *a, **k: dead_letters_page.QMessageBox.StandardButton.Yes),
    )
    monkeypatch.setattr(
        dead_letters_page.QMessageBox, "information", staticmethod(lambda *a, **k: None)
    )
    page._replay_selected()
    _settle(qapp, page._runner)  # the success path reloads off-thread

    assert client.replay_calls == [("IB_B", "OB_B")]  # the SELECTED row's scope
    assert client.list_calls == 2  # initial load + reload after replay
    page.stop()


def test_replay_selected_declined_does_nothing(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.console import dead_letters_page

    client = FakeClient([_row(channel_id="IB_A", destination_name="OB_A")])
    page = dead_letters_page.DeadLettersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)
    page._table.selectRow(0)
    monkeypatch.setattr(
        dead_letters_page.QMessageBox,
        "question",
        staticmethod(lambda *a, **k: dead_letters_page.QMessageBox.StandardButton.No),
    )
    page._replay_selected()
    assert client.replay_calls == []  # declined -> no replay
    page.stop()


def test_replay_all_uses_unscoped_replay(qapp, monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.console import dead_letters_page

    client = FakeClient([_row(channel_id="IB_A", destination_name="OB_A")])
    page = dead_letters_page.DeadLettersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)
    monkeypatch.setattr(
        dead_letters_page.QMessageBox,
        "question",
        staticmethod(lambda *a, **k: dead_letters_page.QMessageBox.StandardButton.Yes),
    )
    monkeypatch.setattr(
        dead_letters_page.QMessageBox, "information", staticmethod(lambda *a, **k: None)
    )
    page._replay_all()
    _settle(qapp, page._runner)
    assert client.replay_calls == [(None, None)]  # unscoped replay-all
    page.stop()


def test_replay_all_scoped_user_403_reaches_error_signal(
    qapp, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A channel-scoped operator can hold messages:replay (so the button is enabled) yet be denied an
    # unscoped replay-all (403). The console can't see its own scope, so it relies on surfacing the
    # server's 403 on the error signal — assert that path, and that it does NOT then reload.
    from messagefoundry.console import dead_letters_page

    denied = ApiError("403: replay-all not permitted for a channel-scoped account", status=403)
    client = FakeClient([_row(channel_id="IB_A", destination_name="OB_A")], replay_all_error=denied)
    page = dead_letters_page.DeadLettersPage(client)  # type: ignore[arg-type]
    page.reload()
    _settle(qapp, page._runner)

    errors: list[str] = []
    page.error.connect(errors.append)
    monkeypatch.setattr(
        dead_letters_page.QMessageBox,
        "question",
        staticmethod(lambda *a, **k: dead_letters_page.QMessageBox.StandardButton.Yes),
    )
    # information() must NOT be reached on the error path — make it fail loudly if it is.
    monkeypatch.setattr(
        dead_letters_page.QMessageBox,
        "information",
        staticmethod(lambda *a, **k: pytest.fail("success dialog shown on a denied replay-all")),
    )
    page._replay_all()
    _settle(qapp, page._runner)

    assert client.replay_calls == [(None, None)]  # the unscoped replay-all was attempted
    assert errors == [str(denied)]  # the 403 reached the error signal
    assert client.list_calls == 1  # no reload after the failed replay (only the initial load)
    page.stop()


def test_reload_after_stop_does_not_strand_loading(qapp) -> None:
    # A reload() that lands AFTER stop() (e.g. a post-replay reload behind a closing modal) must not
    # latch _loading=True forever: submit() no-ops on a stopped runner, so neither _apply nor
    # _on_error would fire. reload() guards against the stopped runner instead.
    from messagefoundry.console.dead_letters_page import DeadLettersPage

    client = FakeClient([_row(channel_id="IB_A", destination_name="OB_A")])
    page = DeadLettersPage(client)  # type: ignore[arg-type]
    page.stop()

    page.reload()  # after stop()
    assert client.list_calls == 0  # no read was started
    assert page._loading is False  # not stranded


def test_replay_buttons_disabled_without_permission(qapp) -> None:
    from messagefoundry.console.dead_letters_page import DeadLettersPage

    denied = FakeClient([_row(channel_id="IB_A", destination_name="OB_A")], can_replay=False)
    page = DeadLettersPage(denied)  # type: ignore[arg-type]
    assert not page._replay_selected_btn.isEnabled()
    assert not page._replay_all_btn.isEnabled()
    assert page._replay_selected_btn.toolTip()  # explanatory tooltip present
    page.stop()

    allowed = FakeClient([_row(channel_id="IB_A", destination_name="OB_A")], can_replay=True)
    page2 = DeadLettersPage(allowed)  # type: ignore[arg-type]
    assert page2._replay_selected_btn.isEnabled()
    assert page2._replay_all_btn.isEnabled()
    page2.stop()
