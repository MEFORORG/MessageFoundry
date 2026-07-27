# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""MessagesPanel refresh convergence — the BACKLOG #17 livelock.

``refresh()`` reads the message list off the main thread and guards against pile-up with ``_loading``;
a refresh requested mid-flight is latched in ``_pending`` and re-fired when the read lands. ``_apply``
used to drain that latch FIRST and ``return`` early, discarding the snapshot as "superseded".

That is a livelock, not an optimisation. Whenever a caller refreshes faster than a fetch completes
there is ALWAYS a latched request when the fetch lands, so EVERY snapshot was discarded and the table
never rendered — permanently, not slowly. It surfaced as a flaky harness-monitor test on loaded CI
runners (which lose the race the local machine wins), but the same wedge is reachable in the real GUI.

These tests would both fail against the old ordering.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("PySide6")

from harness._console_widgets import MessagesPanel, _MessagesSnapshot  # noqa: E402


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _msg(mid: str) -> Any:
    return SimpleNamespace(
        id=mid,
        received_at=1_780_000_000.0,
        channel_id="ch",
        event="ADT^A01",
        message_type="ADT",
        status="delivered",
        control_id=mid,
        summary="",
        metadata="",
    )


class _FakeClient:
    """Only the surface MessagesPanel._fetch touches. ``delay`` makes the read slower than the caller's
    refresh cadence, which is precisely the condition that used to wedge the panel."""

    def __init__(self, *, delay: float = 0.0) -> None:
        self._delay = delay
        self.calls = 0

    def list_messages(self, **_kw: Any) -> Any:
        self.calls += 1
        if self._delay:
            time.sleep(self._delay)
        return SimpleNamespace(messages=[_msg("m1")], total=1)

    def search_messages(self, **_kw: Any) -> Any:  # pragma: no cover - no filters are set here
        raise AssertionError("content search should not be reached without a content/field filter")


def test_a_latched_refresh_no_longer_discards_the_snapshot(qapp: Any) -> None:
    """The unit form: _apply must RENDER even when another refresh is already latched behind it."""
    panel = MessagesPanel(_FakeClient())  # type: ignore[arg-type]
    try:
        panel._loading = True  # a read is in flight...
        panel._pending = False  # ...and a second refresh was latched behind it
        panel._apply(_MessagesSnapshot([_msg("m1")], "1 shown of 1", False, None))

        assert panel._table.rowCount() == 1, (
            "snapshot discarded as 'superseded' — this is the BACKLOG #17 livelock"
        )
        # Dropping the render must not come back as dropping the re-fire either.
        assert panel._pending is None, "the latched refresh was never drained"
    finally:
        panel.stop()


def test_sustained_refresh_pressure_still_converges(qapp: Any) -> None:
    """The integration form, and the shape the harness-monitor test actually hits: a caller polling
    refresh() faster than the read completes. Every _apply lands with a latch set, so under the old
    ordering the table stayed empty forever and this loop ran to its deadline."""
    panel = MessagesPanel(_FakeClient(delay=0.05))  # type: ignore[arg-type]
    deadline = time.time() + 15
    try:
        while panel._table.rowCount() == 0 and time.time() < deadline:
            panel.refresh()  # 5ms cadence vs a 50ms read — always latches
            qapp.processEvents()
            time.sleep(0.005)

        assert panel._table.rowCount() > 0, (
            f"table never rendered in 15s under sustained refresh (livelock); "
            f"the fake engine served {panel._client.calls} reads, every one discarded"  # type: ignore[attr-defined]
        )
    finally:
        panel.stop()
