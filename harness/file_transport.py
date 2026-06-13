"""File transport for the test harness: drop generated messages for the engine to poll, and watch
a directory the engine writes to.

The engine's File **inbound** polls a directory for ``*.hl7`` and the File **outbound** writes
them; this mirrors both ends so the harness can exercise the file connector without MLLP. Dropping
writes atomically (a hidden ``.part`` temp then ``os.replace``) so the engine never reads a
half-written file — the same guarantee the engine's own File destination gives. Watching is
event-driven (:class:`QFileSystemWatcher`) with a periodic rescan as a safety net for missed
notifications; it reports only files that appear *while watching* (like the MLLP receiver shows
only live arrivals).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QFileSystemWatcher, QObject, QTimer, Signal

from messagefoundry.parsing import HL7PeekError, Peek, normalize
from harness.mllp import Received, SendItem

_RESCAN_MS = 1000  # safety-net poll; QFileSystemWatcher can miss bursts on some platforms


@dataclass
class DropResult:
    """The outcome of writing one generated message to the drop directory."""

    item: SendItem
    filename: str
    error: str


def _unique(target: Path) -> Path:
    """``target`` if free, else ``stem-1.hl7``, ``stem-2.hl7``, … (don't clobber a prior drop)."""
    if not target.exists():
        return target
    stem, suffix = target.stem, target.suffix
    n = 1
    while True:
        candidate = target.with_name(f"{stem}-{n}{suffix}")
        if not candidate.exists():
            return candidate
        n += 1


class FileDropWorker(QObject):
    """Writes a batch of generated messages into a directory the engine's File inbound polls.

    Lives in a worker thread (file writes can block); emits one :class:`DropResult` per file.
    """

    result = Signal(object)  # DropResult
    finished = Signal()

    def __init__(self, directory: str, items: list[SendItem], *, rate: float) -> None:
        super().__init__()
        self._directory = directory
        self._items = items
        self._rate = rate
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        import time

        delay = 1.0 / self._rate if self._rate > 0 else 0.0
        try:
            Path(self._directory).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            for item in self._items:
                self.result.emit(DropResult(item, "", str(exc)))
            self.finished.emit()
            return
        for item in self._items:
            if self._stop:
                break
            self.result.emit(self._write_one(item))
            if delay:
                time.sleep(delay)
        self.finished.emit()

    def _write_one(self, item: SendItem) -> DropResult:
        try:
            target = _unique(Path(self._directory) / f"{item.control_id}.hl7")
            tmp = target.with_name(
                f".{target.name}.part"
            )  # hidden + not *.hl7 → engine won't poll it
            tmp.write_bytes(item.payload.encode("utf-8"))
            os.replace(tmp, target)  # atomic publish
            return DropResult(item, target.name, "")
        except OSError as exc:
            return DropResult(item, "", str(exc))


class FolderWatcher(QObject):
    """Watches a directory the engine writes to and emits each newly-appearing ``*.hl7`` file."""

    received = Signal(object)  # Received

    def __init__(self) -> None:
        super().__init__()
        self._watcher = QFileSystemWatcher(self)
        self._watcher.directoryChanged.connect(self._scan)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._scan)
        self._dir: Path | None = None
        self._seen: set[str] = set()

    def is_watching(self) -> bool:
        return self._dir is not None

    def start(self, directory: str) -> bool:
        path = Path(directory)
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        self._dir = path
        self._seen = {
            p.name for p in path.glob("*.hl7")
        }  # ignore pre-existing; report new arrivals
        self._watcher.addPath(str(path))
        self._timer.start(_RESCAN_MS)
        return True

    def stop(self) -> None:
        self._timer.stop()
        if self._dir is not None:
            self._watcher.removePath(str(self._dir))
        self._dir = None
        self._seen.clear()

    def _scan(self, *_: object) -> None:
        if self._dir is None:
            return
        for path in sorted(self._dir.glob("*.hl7")):
            if path.name in self._seen:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue  # transient lock/vanish — leave out of _seen so the next rescan retries
            self._seen.add(path.name)  # only after a successful read, so a failed read is retried
            self.received.emit(self._describe(path.name, text))

    @staticmethod
    def _describe(filename: str, text: str) -> Received:
        try:
            peek = Peek.parse(normalize(text))
            code = peek.message_code or "?"
            trigger = peek.trigger_event or ""
            control_id = peek.control_id or ""
        except HL7PeekError:
            code, trigger, control_id = "?", "", ""
        return Received(
            datetime.now().strftime("%H:%M:%S"), filename, code, trigger, control_id, text
        )
