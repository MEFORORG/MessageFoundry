# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness File tab: the drop worker writes pollable files; the folder watcher sees new ones."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("PySide6")

from harness.file_panel import FilePanel  # noqa: E402
from harness.file_transport import FileDropWorker, FolderWatcher  # noqa: E402
from harness.mllp import SendItem  # noqa: E402
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES  # noqa: E402

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|X1|P|2.5.1\rEVN|A01|20260101\r"


@pytest.fixture(scope="module")
def qapp() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _spin(qapp: Any, predicate: Any, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while not predicate():
        qapp.processEvents()
        time.sleep(0.05)
        if time.time() > deadline:
            raise AssertionError("condition not met within timeout")


def test_file_panel_builds(qapp: Any) -> None:
    panel = FilePanel()
    codes = [panel._code.itemText(i) for i in range(panel._code.count())]
    assert "ADT" in codes  # registry-driven type list
    assert not panel._watcher.is_watching()


def test_drop_worker_writes_pollable_files(qapp: Any, tmp_path: Path) -> None:
    items = [
        SendItem(1, "ADT", "A01", "MEFORADTA0100001", _MSG),
        SendItem(2, "ADT", "A02", "MEFORADTA0200002", _MSG),
    ]
    results: list[Any] = []
    worker = FileDropWorker(str(tmp_path), items, rate=0.0)
    worker.result.connect(results.append)
    worker.run()  # synchronous; run it directly on this thread

    assert len(results) == 2 and all(not r.error for r in results)
    written = sorted(p.name for p in tmp_path.glob("*.hl7"))
    assert written == ["MEFORADTA0100001.hl7", "MEFORADTA0200002.hl7"]
    # Compare bytes: the CR-delimited HL7 lands on disk verbatim (read_text would normalize \r→\n).
    assert (tmp_path / "MEFORADTA0100001.hl7").read_bytes() == _MSG.encode("utf-8")
    assert not list(tmp_path.glob("*.part"))  # temp files cleaned up by the atomic rename


def test_watcher_reports_new_files_only(qapp: Any, tmp_path: Path) -> None:
    (tmp_path / "old.hl7").write_text(_MSG, encoding="utf-8")  # pre-existing: must be ignored
    watcher = FolderWatcher()
    got: list[Any] = []
    watcher.received.connect(got.append)
    assert watcher.start(str(tmp_path))

    (tmp_path / "new.hl7").write_text(_MSG, encoding="utf-8")  # appears while watching
    try:
        _spin(qapp, lambda: bool(got))
    finally:
        watcher.stop()

    assert [r.peer for r in got] == ["new.hl7"]  # only the new arrival, not old.hl7
    assert got[0].code == "ADT" and got[0].trigger == "A01" and got[0].control_id == "X1"


def test_watcher_cap_defaults_to_the_engine_message_cap(qapp: Any) -> None:
    """The watch pane reads files another party writes, so it is an ASVS 5.1.1 upload feature and
    bounds each file like the engine bounds a message (BACKLOG #1127 follow-up)."""
    assert FolderWatcher().max_file_bytes == DEFAULT_MAX_MESSAGE_BYTES


def test_watcher_refuses_an_over_cap_file_without_reading_it(
    qapp: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[str] = []
    real_open = Path.open

    def spy_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opened.append(self.name)
        return real_open(self, *args, **kwargs)

    watcher = FolderWatcher()
    cap = len(_MSG.encode())
    watcher.max_file_bytes = cap
    got: list[Any] = []
    refused: list[str] = []
    watcher.received.connect(got.append)
    watcher.refused.connect(refused.append)
    assert watcher.start(str(tmp_path))
    try:
        (tmp_path / "at-cap.hl7").write_text(_MSG, encoding="utf-8", newline="")
        (tmp_path / "big.hl7").write_text(_MSG + "X", encoding="utf-8", newline="")
        monkeypatch.setattr(Path, "open", spy_open)  # after the writes, which open too
        watcher._scan()
        watcher._scan()  # a refused file is not retried on every rescan
    finally:
        watcher.stop()
    assert [r.peer for r in got] == ["at-cap.hl7"]
    assert len(refused) == 1
    assert refused[0].startswith("big.hl7: ") and f"{cap}-byte cap" in refused[0]
    assert "big.hl7" not in opened, "the over-cap file was opened before it was refused"


def test_watcher_refuses_anything_but_a_regular_file(qapp: Any, tmp_path: Path) -> None:
    """A directory (or, on POSIX, a FIFO) named ``*.hl7`` is refused once, not opened: a FIFO
    reports size 0 and would block the GUI thread on open."""
    watcher = FolderWatcher()
    refused: list[str] = []
    watcher.refused.connect(refused.append)
    assert watcher.start(str(tmp_path))
    try:
        (tmp_path / "dir.hl7").mkdir()
        watcher._scan()
        watcher._scan()
    finally:
        watcher.stop()
    assert refused == ["dir.hl7: not a regular file; not read"]


def test_file_panel_counts_a_refused_file_beside_the_watch_state(qapp: Any, tmp_path: Path) -> None:
    panel = FilePanel()
    panel._watch_dir.setText(str(tmp_path))
    panel._toggle_watch()
    try:
        panel._watcher.refused.emit("big.hl7: over the cap")
        panel._watcher.received.emit(FolderWatcher._describe("ok.hl7", _MSG))
        status = panel._watch_status.text()
    finally:
        panel.shutdown()
    # A later arrival keeps the refusal beside the count rather than erasing it.
    assert status == "watching · 1 seen · 1 refused (last: big.hl7: over the cap)"
