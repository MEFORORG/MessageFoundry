# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness File tab generates a batch on the worker thread, caps its result rows, and shuts
down without ``QThread.terminate`` (BACKLOG #5948).

The tab generated every message of a batch of up to a million in a loop on the GUI thread before
the worker started, added a result row per file with no cap, and on close waited six seconds and
then terminated a worker that sat in a pause between files.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("PySide6")

from harness import file_panel  # noqa: E402
from harness.file_transport import DropResult  # noqa: E402
from harness.mllp import SendItem  # noqa: E402
from messagefoundry_toolkit.generators import _core  # noqa: E402

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\rEVN|A01|20260101\r"


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.fixture
def off_gui_generation(monkeypatch: pytest.MonkeyPatch) -> list[threading.Thread]:
    """Generation refuses the GUI thread and records where it ran."""
    threads: list[threading.Thread] = []

    def generate(code: str, trigger: str, index: int, **_kw: object) -> str:
        if threading.current_thread() is threading.main_thread():
            raise AssertionError("a message was generated on the GUI thread")
        threads.append(threading.current_thread())
        return _MSG

    monkeypatch.setattr(_core, "generate_message", generate)
    return threads


def _until(qapp: Any, cond: Any, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qapp.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def _item(seq: int) -> SendItem:
    return SendItem(seq, "ADT", "A01", f"X{seq}", _MSG)


# --- File tab (BACKLOG #5948) ---------------------------------------------------------------------


def test_file_drop_generates_on_the_worker_and_stops_inside_a_pause(
    qapp: Any, tmp_path: Path, off_gui_generation: list[threading.Thread]
) -> None:
    panel = file_panel.FilePanel()
    panel._count.setValue(1_000_000)
    panel._rate.setValue(0.1)  # a ten-second pause after each file
    panel._drop_dir.setText(str(tmp_path))
    try:
        started = time.monotonic()
        panel._start_drop()
        assert time.monotonic() - started < 2, "the batch was built before the worker started"
        assert _until(qapp, lambda: panel._dropped >= 1)
        assert off_gui_generation
        thread = panel._thread
        assert thread is not None
        started = time.monotonic()
        panel.shutdown()
        assert time.monotonic() - started < 3, "shutdown waited out the pause"
        assert thread.isFinished()
    finally:
        panel.shutdown()
    assert len(list(tmp_path.glob("*.hl7"))) == 1


def test_file_drop_rows_are_capped_and_the_summary_counts_all(
    qapp: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(file_panel, "MAX_RESULT_ROWS", 3)
    panel = file_panel.FilePanel()
    try:
        for seq in range(1, 6):
            panel._on_drop_result(DropResult(_item(seq), f"X{seq}.hl7", "" if seq != 5 else "e"))
        assert panel._drop_results.rowCount() == 3
        text = panel._drop_summary.text()
        assert "dropped 5" in text and "written 4" in text and "failed 1" in text
        assert "first 3" in text
    finally:
        panel.shutdown()


def test_a_generation_fault_is_reported_not_shown_as_done(
    qapp: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Generation now runs on the worker, so a fault there ends the batch after its finished
    # signal; the summary must say it stopped early rather than read as a complete run.
    def generate(code: str, trigger: str, index: int, **_kw: object) -> str:
        if index == 2:
            raise ValueError("generator fault")
        return _MSG

    monkeypatch.setattr(_core, "generate_message", generate)
    panel = file_panel.FilePanel()
    panel._count.setValue(5)
    panel._drop_dir.setText(str(tmp_path))
    try:
        panel._start_drop()
        assert _until(qapp, lambda: panel._worker is None)
        text = panel._drop_summary.text()
        assert "stopped early: ValueError: generator fault" in text
        assert "dropped 1" in text
    finally:
        panel.shutdown()
