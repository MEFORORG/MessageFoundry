# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness detail panel reads the body through its own audited fetch (BACKLOG #2345).

``GET /messages/{id}`` no longer carries the raw body, so the panel opens the message AND fetches the
body, tagging the fetch ``harness`` so the engine's ``message_body_view`` row names it. The panel still
shows the body as soon as a row is selected; waiting for an explicit act is BACKLOG #2346.
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
    """Only the surface ``MessageDetailPanel._fetch`` touches, recording each body fetch's surface.
    ``body_fails`` makes the body fetch raise, as a 429 from the PHI-read budget would."""

    def __init__(self, *, body_fails: bool = False) -> None:
        self.body_surfaces: list[str] = []
        self._body_fails = body_fails

    def get_message(self, message_id: str) -> Any:
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


def test_the_panel_fetches_the_body_as_the_harness_and_renders_it(qapp: Any) -> None:
    client = _FakeClient()
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
    try:
        panel._pending_id = "m1"  # as load() sets it before the worker runs
        snap = panel._fetch("m1")
        assert snap.error is None
        assert snap.raw == _RAW
        assert client.body_surfaces == ["harness"]
        # Apply on this thread, as the runner's result slot would, and read the rendered body back.
        panel._pending_id = "m1"
        panel._apply(snap)
        assert "PID|1||100" in panel._raw.toPlainText()
    finally:
        panel.stop()


def test_a_failed_body_fetch_keeps_the_open_and_clears_the_last_body(qapp: Any) -> None:
    """The open succeeded and was audited, so a failed body fetch must not discard it: the metadata
    renders and the error is emitted. The PREVIOUS message's body must not stay on screen under the
    new message's metadata, so a successful load is applied first and its body read back as the
    control."""
    good = _FakeClient()
    panel = MessageDetailPanel(good)  # type: ignore[arg-type]
    errors: list[str] = []
    panel.error.connect(errors.append)
    try:
        panel._pending_id = "m0"
        panel._apply(panel._fetch("m0"))
        assert "PID|1||100" in panel._raw.toPlainText()  # the control: a body is on screen
        panel._poll = _FakeClient(body_fails=True)  # type: ignore[assignment]
        panel._pending_id = "m1"
        snap = panel._fetch("m1")
        assert snap.detail is not None and snap.raw is None
        panel._apply(snap)
        assert errors == ["too many requests; please slow down"]
        assert "ADT^A01" in panel._summary.text()
        assert panel._raw.toPlainText() == ""
    finally:
        panel.stop()


def test_a_superseded_load_fetches_no_body(qapp: Any) -> None:
    """A load that a newer click replaced while its open ran must not fetch the body: that would
    write a message_body_view row for a body nobody sees. The first test is the control that the
    same fake does fetch the body for a current load."""
    client = _FakeClient()
    panel = MessageDetailPanel(client)  # type: ignore[arg-type]
    try:
        panel._pending_id = "m2"  # a newer load() already replaced m1
        snap = panel._fetch("m1")
        assert snap.raw is None and snap.error is None
        assert client.body_surfaces == []
    finally:
        panel.stop()
