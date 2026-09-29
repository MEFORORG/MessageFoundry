# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness detail panel fetches the body only on the Show body act (BACKLOG #2345, #2346).

``GET /messages/{id}`` no longer carries the raw body (#2345). Selecting a row opens the message and
nothing more; the body is a second, separately audited request that the operator starts with the
Show body button (#2346, ASVS 14.2.6). The fetch is tagged ``harness`` so the engine's
``message_body_view`` row names this client.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("PySide6")

from harness._console_widgets import MessageDetailPanel  # noqa: E402
from messagefoundry.apiclient import ApiError  # noqa: E402

_RAW = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


class _FakeClient:
    """Only the surface ``MessageDetailPanel`` touches, recording each body fetch's surface.
    ``body_fails`` makes the body fetch raise, as a 429 from the PHI-read budget would."""

    def __init__(self, *, body_fails: bool = False) -> None:
        self.body_surfaces: list[str] = []
        self.opens = 0
        self._body_fails = body_fails

    def get_message(self, message_id: str) -> Any:
        self.opens += 1
        return SimpleNamespace(
            id=message_id,
            message_type="ADT^A01",
            control_id="MSG1",
            status="PROCESSED",
            received_at=1_780_000_000.0,
            error=None,
            outbox=[],
            events=[],
        )

    def get_message_body(self, message_id: str, *, surface: str) -> Any:
        self.body_surfaces.append(surface)
        if self._body_fails:
            raise ApiError("too many requests; please slow down", status=429)
        return SimpleNamespace(message_id=message_id, raw=_RAW)


def _open(panel: MessageDetailPanel, message_id: str) -> None:
    """Open a message as load() then the runner's result slot would, on this thread."""
    panel._open_seq += 1
    panel._pending_id = message_id
    panel._apply(panel._fetch(message_id))


def test_selecting_a_row_opens_the_message_and_fetches_no_body(qapp: Any) -> None:
    """The open charges the PHI-read budget once and reads no body. The enabled Show body button
    and the rendered metadata are the control that the open itself worked."""
    client = _FakeClient()
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
    try:
        _open(panel, "m1")
        assert client.opens == 1
        assert client.body_surfaces == []
        assert "ADT^A01" in panel._summary.text()
        assert panel._show_body.isEnabled()
        assert panel._raw.toPlainText() == ""
    finally:
        panel.stop()


def test_show_body_fetches_the_body_as_the_harness_and_renders_it(qapp: Any) -> None:
    client = _FakeClient()
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
    try:
        _open(panel, "m1")
        snap = panel._fetch_body("m1", panel._open_seq)
        assert snap.error is None and snap.raw == _RAW
        assert client.body_surfaces == ["harness"]
        panel._apply_body(snap)
        assert "PID|1||100" in panel._raw.toPlainText()
    finally:
        panel.stop()


def test_opening_the_next_message_clears_the_last_body(qapp: Any) -> None:
    """A body shown for one message must not stay on screen under the next one's metadata. The
    first message's body on screen is the control."""
    client = _FakeClient()
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
    try:
        _open(panel, "m0")
        panel._apply_body(panel._fetch_body("m0", panel._open_seq))
        assert "PID|1||100" in panel._raw.toPlainText()
        _open(panel, "m1")
        assert panel._raw.toPlainText() == ""
        assert client.body_surfaces == ["harness"]  # the second open fetched no body
    finally:
        panel.stop()


def test_a_body_asked_for_under_an_earlier_open_is_dropped(qapp: Any) -> None:
    """A slow body fetch must not paint once its open is gone: not onto another message, and not
    onto a later open of the SAME message (a re-selection, or the reload after Replay), where the
    operator has not pressed Show body. A fetch started under the current open is the control."""
    client = _FakeClient()
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
    try:
        _open(panel, "m0")
        late = panel._fetch_body("m0", panel._open_seq)
        _open(panel, "m1")
        panel._apply_body(late)
        assert panel._raw.toPlainText() == ""
        _open(panel, "m0")  # the same message again, with no Show body pressed
        panel._apply_body(late)
        assert panel._raw.toPlainText() == ""
        panel._apply_body(panel._fetch_body("m0", panel._open_seq))
        assert "PID|1||100" in panel._raw.toPlainText()
    finally:
        panel.stop()


def test_a_failed_open_clears_the_previous_message(qapp: Any) -> None:
    """When the newly selected row cannot be opened, the previous message's metadata and body must
    not stay on screen under it, and Show body must not stay offered. The previous message's body
    on screen is the control."""

    class _OpenFails(_FakeClient):
        def get_message(self, message_id: str) -> Any:
            raise ApiError("too many requests; please slow down", status=429)

    panel = MessageDetailPanel(_FakeClient())  # type: ignore[arg-type]
    errors: list[str] = []
    panel.error.connect(errors.append)
    try:
        _open(panel, "m0")
        panel._apply_body(panel._fetch_body("m0", panel._open_seq))
        assert "PID|1||100" in panel._raw.toPlainText()
        panel._poll = _OpenFails()  # type: ignore[assignment]
        _open(panel, "m1")
        assert errors == ["too many requests; please slow down"]
        assert panel._raw.toPlainText() == ""
        assert "ADT^A01" not in panel._summary.text()
        assert not panel._show_body.isEnabled()
    finally:
        panel.stop()


def test_a_failed_body_fetch_keeps_the_open_and_reports_the_error(qapp: Any) -> None:
    """The open succeeded and was audited, so a failed body fetch leaves it on screen and emits the
    error rather than discarding both."""
    panel = MessageDetailPanel(_FakeClient(body_fails=True))  # type: ignore[arg-type]
    errors: list[str] = []
    panel.error.connect(errors.append)
    try:
        _open(panel, "m1")
        snap = panel._fetch_body("m1", panel._open_seq)
        assert snap.raw is None
        panel._apply_body(snap)
        assert errors == ["too many requests; please slow down"]
        assert "ADT^A01" in panel._summary.text()
        assert panel._raw.toPlainText() == ""
    finally:
        panel.stop()


def test_show_body_does_nothing_while_a_newer_open_is_in_flight(qapp: Any) -> None:
    """Pressing Show body between a new row click and its open landing must not fetch the previous
    message's body. With the open landed, the same press does fetch: the control."""
    client = _FakeClient()
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
    submitted: list[Any] = []
    panel._runner.submit = lambda fn, **_kw: submitted.append(fn)  # type: ignore[method-assign]
    try:
        _open(panel, "m0")
        panel._pending_id = "m1"  # load("m1") has started; its open has not landed
        panel._on_show_body()
        assert submitted == []
        panel._pending_id = "m0"
        panel._on_show_body()
        assert len(submitted) == 1
        # And the button waits for the answer, so a double-click is one audited read, not two.
        assert not panel._show_body.isEnabled()
    finally:
        panel.stop()
