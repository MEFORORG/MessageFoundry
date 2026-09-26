# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-tick intake ceilings on the three POLL sources: FILE, REMOTEFILE and DATABASE.

Each source now takes at most ``DEFAULT_MAX_ITEMS_PER_POLL`` items per tick and leaves the rest where
they are. The ceiling **ships on**, which is safe here and only here: on a poll source it is a
**deferral**, not a drop — an unread file stays in the drop directory and an unfetched row stays in the
table, so the next tick takes it. Nothing is quarantined, errored or unaccounted for, so the
count-and-log invariant is untouched.

**Every volume test asserts on the LEFTOVERS, not only on the count.** A ceiling that discarded its
overflow would satisfy "exactly N were handled this tick" and be far worse than no ceiling at all, so
each source is also polled a second time and the remainder must arrive intact.

This file does not claim any ASVS cell moves. The three ceilings are buildable on their own merits;
the acts that could re-grade 2.4.1 are the owner's.
"""

from __future__ import annotations

import inspect
import logging
import posixpath
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import DatabasePoll, File, Ftp, Sftp
from messagefoundry.transports import build_source, remotefile
from messagefoundry.transports import database as db_mod
from messagefoundry.transports.base import DEFAULT_MAX_ITEMS_PER_POLL
from messagefoundry.transports.database import DatabaseSource
from messagefoundry.transports.file import FileSource
from messagefoundry.transports.remotefile import RemoteFileSource, _RemoteClient, _RemoteError

_FILE_LOGGER = "messagefoundry.transports.file"
_REMOTE_LOGGER = "messagefoundry.transports.remotefile"
_DB_LOGGER = "messagefoundry.transports.database"

#: A minimal conformant message: the sources sniff the leading bytes against the declared
#: content_type (None → hl7v2), so a body without an MSH would be quarantined before the ceiling
#: could be measured.
_ADT = "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101||ADT^A01|{n}|P|2.5"


class _RecordingHandler:
    def __init__(self) -> None:
        self.bodies: list[bytes] = []

    async def __call__(self, raw: bytes) -> str | None:
        self.bodies.append(raw)
        return None


# === FILE =====================================================================


def _file_source(directory: Path, **over: Any) -> FileSource:
    settings: dict[str, Any] = {"directory": str(directory)}
    settings.update(over)
    src = build_source(Source(type=ConnectorType.FILE, settings=settings))
    assert isinstance(src, FileSource)
    src._prepare_subdirs()  # .processed/.error, which start() would otherwise create
    return src


async def _settle(src: FileSource) -> None:
    """Take the settle poll (BACKLOG #1811). A file's first sighting only records its stat and charges
    nothing, so the scan after this one is the one these ceiling tests measure."""
    await src._scan_once()


def _drop(directory: Path, count: int, *, first: int = 0) -> None:
    """Write ``count`` numbered HL7 files. Zero-padded so name order is numeric order, which is the
    source's default ``sort`` — a test that could not predict the order could not name the leftovers."""
    for n in range(first, first + count):
        (directory / f"m{n:03d}.hl7").write_text(_ADT.format(n=n), encoding="utf-8")


def _pending(directory: Path) -> list[str]:
    """Names still waiting in the poll directory (the archive/quarantine subdirs are not candidates)."""
    return sorted(p.name for p in directory.iterdir() if p.is_file())


async def test_file_scan_stops_at_the_ceiling_and_leaves_the_rest_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """One scan hands off exactly the ceiling and the remaining files are STILL in the drop directory.

    Red mutation: delete the ``_at_ceiling`` break in ``_scan_once`` — all five files are emitted in one
    scan and the two leftovers are gone from the poll directory. Asserting only on the hand-off count
    would also pass a ceiling that deleted or quarantined the overflow, which is why the leftovers are
    named here."""
    from messagefoundry.transports import file as file_mod

    monkeypatch.setattr(file_mod, "DEFAULT_MAX_ITEMS_PER_POLL", 3)
    inbox = tmp_path / "in"
    inbox.mkdir()
    _drop(inbox, 5)
    src = _file_source(inbox)  # no operator configuration at all — the shipped default applies
    handler = _RecordingHandler()
    src._handler = handler
    await _settle(src)
    with caplog.at_level(logging.INFO, logger=_FILE_LOGGER):
        await src._scan_once()
    assert len(handler.bodies) == 3
    assert _pending(inbox) == ["m003.hl7", "m004.hl7"]  # deferred, still on disk, untouched
    assert sorted(p.name for p in (inbox / ".processed").iterdir()) == [
        "m000.hl7",
        "m001.hl7",
        "m002.hl7",
    ]
    assert list((inbox / ".error").iterdir()) == []  # a deferral is not a quarantine
    assert "reached poll_max_files" in caplog.text
    assert "2 candidate(s) left" in caplog.text


async def test_file_second_scan_drains_the_deferred_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The next scan picks up what the first one left, so every file is ingested exactly once.

    Red mutation: make the ceiling drop its overflow (quarantine or unlink the untouched candidates at
    the break). The first scan still reports three hand-offs, and only this test goes red — the second
    scan finds nothing and the last two messages never arrive.

    Second red mutation (BACKLOG #1811): charge the settle wait against the budget. The settle poll then
    records only three files, the two deferred ones are first seen on the second scan, and only three
    messages arrive. A deferred file must not have to settle twice."""
    from messagefoundry.transports import file as file_mod

    monkeypatch.setattr(file_mod, "DEFAULT_MAX_ITEMS_PER_POLL", 3)
    inbox = tmp_path / "in"
    inbox.mkdir()
    _drop(inbox, 5)
    src = _file_source(inbox)
    handler = _RecordingHandler()
    src._handler = handler
    await _settle(src)
    assert handler.bodies == []
    await src._scan_once()
    await src._scan_once()
    assert len(handler.bodies) == 5  # every file, once — nothing dropped, nothing duplicated
    assert [b.decode() for b in handler.bodies] == [_ADT.format(n=n) for n in range(5)]
    assert _pending(inbox) == []  # fully drained by the second scan


async def test_file_scan_below_the_ceiling_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Negative control: a scan whose work fits under the ceiling behaves exactly as before it existed.

    Three files against a ceiling of three is the boundary, so an off-by-one (``>`` for ``>=``, or a
    budget charged on candidates examined rather than files disposed of) stops the scan early and reds
    this test. No ceiling log line is emitted when nothing was deferred."""
    from messagefoundry.transports import file as file_mod

    monkeypatch.setattr(file_mod, "DEFAULT_MAX_ITEMS_PER_POLL", 3)
    inbox = tmp_path / "in"
    inbox.mkdir()
    _drop(inbox, 3)
    src = _file_source(inbox)
    handler = _RecordingHandler()
    src._handler = handler
    with caplog.at_level(logging.INFO, logger=_FILE_LOGGER):
        await _settle(src)
        await src._scan_once()
    assert len(handler.bodies) == 3
    assert _pending(inbox) == []
    assert "poll_max_files" not in caplog.text


async def test_file_ceiling_is_on_by_default_and_operator_overridable(tmp_path: Path) -> None:
    """The shipped default is ON at ``DEFAULT_MAX_ITEMS_PER_POLL``, with no setting anywhere; a falsy
    ``poll_max_files`` is the documented opt-out.

    Red mutation: default the knob to ``None`` (off) — the first assertion reds. This is the assertion
    that would catch the ceiling quietly becoming opt-in, which is the failure mode the shipped-on
    argument exists to prevent. The ``File()`` assertion is a drift guard: the factory has to repeat the
    number as a literal (``config/`` cannot import ``transports/``), so the two can diverge silently."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    assert DEFAULT_MAX_ITEMS_PER_POLL == 500
    assert File(directory=str(inbox)).settings["poll_max_files"] == DEFAULT_MAX_ITEMS_PER_POLL
    assert _file_source(inbox).poll_max_files == DEFAULT_MAX_ITEMS_PER_POLL
    assert _file_source(inbox, poll_max_files=25).poll_max_files == 25
    assert _file_source(inbox, poll_max_files=0).poll_max_files is None  # explicit unlimited


async def test_file_unlimited_scan_takes_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``poll_max_files=0`` restores the unbounded scan, so the opt-out is a real opt-out.

    Red mutation: treat a falsy value as "use the default" — five files against a ceiling of three
    leaves two behind and this test reds."""
    from messagefoundry.transports import file as file_mod

    monkeypatch.setattr(file_mod, "DEFAULT_MAX_ITEMS_PER_POLL", 3)
    inbox = tmp_path / "in"
    inbox.mkdir()
    _drop(inbox, 5)
    src = _file_source(inbox, poll_max_files=0)
    handler = _RecordingHandler()
    src._handler = handler
    await _settle(src)
    await src._scan_once()
    assert len(handler.bodies) == 5
    assert _pending(inbox) == []


async def test_file_stuck_files_do_not_charge_the_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fair progress: a file left in place for a later retry must not spend the budget.

    Two unreadable files sort ahead of two healthy ones. The unreadable arm leaves them in the
    directory, so if it charged the budget it would spend the whole ceiling on the same two files every
    scan and the healthy ones behind them would never be ingested.

    Red mutation: add ``disposed += 1`` to the transient-read arm of ``_scan_once`` — the ceiling of two
    is spent on the locked files and ``handler.bodies`` is empty."""
    from messagefoundry.transports import file as file_mod

    monkeypatch.setattr(file_mod, "DEFAULT_MAX_ITEMS_PER_POLL", 2)
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "a_locked1.hl7").write_text(_ADT.format(n=1), encoding="utf-8")
    (inbox / "a_locked2.hl7").write_text(_ADT.format(n=2), encoding="utf-8")
    (inbox / "b_good1.hl7").write_text(_ADT.format(n=3), encoding="utf-8")
    (inbox / "b_good2.hl7").write_text(_ADT.format(n=4), encoding="utf-8")
    real_read = Path.read_bytes

    def read_bytes(self: Path) -> bytes:
        if self.name.startswith("a_locked"):
            raise OSError("locked by another process")
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    src = _file_source(inbox)
    handler = _RecordingHandler()
    src._handler = handler
    await _settle(src)
    await src._scan_once()
    assert [b.decode() for b in handler.bodies] == [_ADT.format(n=3), _ADT.format(n=4)]
    assert _pending(inbox) == ["a_locked1.hl7", "a_locked2.hl7"]  # still there, still retryable


async def test_file_leave_mode_files_already_taken_do_not_charge_the_ceiling(
    tmp_path: Path,
) -> None:
    """Under ``after_read="leave"`` a file already taken stays in the directory, and it must not spend
    the budget on later ticks.

    This is the defect PR 948 fixed and BACKLOG #1518 recorded: the old ceiling cut the candidate list
    before the leave-mode dedup ran, so files already taken used up the budget and new ones behind
    them were never reached.

    Red mutation: add ``disposed += 1`` before the leave-mode ``continue`` in ``_scan_once``. The third
    scan then spends its budget of two on m000 and m001 again, and m002 and m003 never arrive."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    _drop(inbox, 3)
    src = _file_source(inbox, after_read="leave", poll_max_files=2)
    handler = _RecordingHandler()
    src._handler = handler
    await _settle(src)
    await src._scan_once()
    assert len(handler.bodies) == 2
    await src._scan_once()  # m000 and m001 are skipped as already taken; m002 fits the budget
    assert len(handler.bodies) == 3
    _drop(inbox, 1, first=3)
    await src._scan_once()  # m003's first sighting only records its stat (BACKLOG #1811)
    await src._scan_once()
    assert [b.decode() for b in handler.bodies] == [_ADT.format(n=n) for n in range(4)]
    assert _pending(inbox) == ["m000.hl7", "m001.hl7", "m002.hl7", "m003.hl7"]  # leave means leave


async def test_a_tick_in_progress_stops_when_the_source_stops(tmp_path: Path) -> None:
    """``_scan_once`` consults the stop event per file, as ``remotefile.py`` already did.

    Measured before that check existed: ``file.py`` held exactly one ``_stop.is_set()``, in the
    ``_run`` loop header, so a tick over a large drop ran to completion before ``stop()`` could
    return. The check is the sibling of the ceiling break above and is read here with the CEILING
    DISABLED on purpose -- left on, a low ceiling would end the scan by itself and this test would
    pass with the stop check deleted.
    """
    inbox = tmp_path / "in"
    inbox.mkdir()
    _drop(inbox, 7)
    src = _file_source(inbox, poll_max_files=0)  # unlimited: only the stop may end this scan
    seen: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        seen.append(raw)
        if len(seen) == 2:
            src._stop.set()
        return None

    src._handler = handler
    await _settle(src)
    await src._scan_once()
    assert len(seen) == 2, "the scan ignored the stop signal and drained the whole directory"
    assert len(_pending(inbox)) == 5, "the unscanned remainder must be left in place"


# === REMOTEFILE ===============================================================


class _FakeRemoteClient(_RemoteClient):
    """In-memory SFTP/FTP stand-in: enough of the client contract for the poll path (list, retrieve,
    rename, remove, ensure_dir). Files live in one flat ``{path: bytes}`` map, so a moved file is
    visible under its new directory and a leftover is visible under the poll directory."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = dict(files)

    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        return [
            (posixpath.basename(path), len(data))
            for path, data in self.files.items()
            if posixpath.dirname(path) == remote_dir
        ]

    def retrieve(self, path: str, *, max_bytes: int | None = None) -> bytes:
        try:
            return self.files[path]
        except KeyError:
            raise _RemoteError(f"no such file: {path}", permanent=True) from None

    def store(self, path: str, data: bytes) -> None:
        self.files[path] = data

    def rename(self, src: str, dst: str) -> None:
        self.files[dst] = self.files.pop(src)

    def remove(self, path: str) -> None:
        self.files.pop(path, None)

    def dispose_unless_changed(self, path: str, expected_size: int, dest: str | None) -> int | None:
        # #116: nothing here writes behind the poll, so there is never a size change to report.
        if dest is None:
            self.remove(path)
        else:
            self.rename(path, dest)
        return None

    def ensure_dir(self, remote_dir: str) -> bool:
        return False


def _remote_source(
    monkeypatch: pytest.MonkeyPatch, client: _FakeRemoteClient, **over: Any
) -> RemoteFileSource:
    monkeypatch.setattr(remotefile, "_make_client", lambda settings, **_: client)
    base: dict[str, Any] = {"host": "sftp.example.com", "remote_dir": "/in", "pattern": "*.hl7"}
    base.update(over)
    settings = dict(Sftp(**base).settings)
    if "poll_max_files" not in over:
        # The factory writes its OWN default into every settings dict, so leaving the key in place
        # would test the wiring literal rather than the connector's shipped default. Dropping it is
        # what a connections.toml table that never mentions the knob looks like — and the two defaults
        # are pinned equal by test_remote_ceiling_is_on_by_default_and_operator_overridable.
        settings.pop("poll_max_files", None)
    src = build_source(Source(type=ConnectorType.REMOTEFILE, settings=settings))
    assert isinstance(src, RemoteFileSource)
    return src


def _remote_files(count: int) -> dict[str, bytes]:
    return {f"/in/m{n:03d}.hl7": _ADT.format(n=n).encode() for n in range(count)}


def _remote_pending(client: _FakeRemoteClient) -> list[str]:
    return sorted(posixpath.basename(p) for p in client.files if posixpath.dirname(p) == "/in")


async def test_remote_poll_stops_at_the_ceiling_and_leaves_the_rest_on_the_share(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """One poll retrieves exactly the ceiling; the rest are still on the remote share afterwards.

    Red mutation: delete the ``_at_ceiling`` break in ``_poll_once`` — all five are retrieved and the
    two leftovers move into ``.processed``, so both the count and the share listing change."""
    monkeypatch.setattr(remotefile, "DEFAULT_MAX_ITEMS_PER_POLL", 3)
    client = _FakeRemoteClient(_remote_files(5))
    src = _remote_source(monkeypatch, client)  # no operator configuration — the shipped default
    handler = _RecordingHandler()
    src._handler = handler
    with caplog.at_level(logging.INFO, logger=_REMOTE_LOGGER):
        await src._poll_once()
    assert len(handler.bodies) == 3
    assert _remote_pending(client) == ["m003.hl7", "m004.hl7"]  # deferred, untouched on the share
    assert "/in/.processed/m000.hl7" in client.files
    assert not [p for p in client.files if p.startswith("/in/.error/")]
    assert "reached poll_max_files" in caplog.text


async def test_remote_second_poll_drains_the_deferred_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The next poll takes what the first left, so every remote file is ingested exactly once.

    Red mutation: quarantine or remove the unreached listing entries at the break — the first poll's
    count is unchanged and only this test reds."""
    monkeypatch.setattr(remotefile, "DEFAULT_MAX_ITEMS_PER_POLL", 3)
    client = _FakeRemoteClient(_remote_files(5))
    src = _remote_source(monkeypatch, client)
    handler = _RecordingHandler()
    src._handler = handler
    await src._poll_once()
    await src._poll_once()
    assert [b.decode() for b in handler.bodies] == [_ADT.format(n=n) for n in range(5)]
    assert _remote_pending(client) == []


async def test_remote_poll_below_the_ceiling_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Negative control at the boundary: three files against a ceiling of three are all ingested and
    nothing is logged as deferred.

    Red mutation: an off-by-one at the comparison (``disposed >= ceiling - 1``, or charging the budget
    before the file is disposed of) stops the poll one file short."""
    monkeypatch.setattr(remotefile, "DEFAULT_MAX_ITEMS_PER_POLL", 3)
    client = _FakeRemoteClient(_remote_files(3))
    src = _remote_source(monkeypatch, client)
    handler = _RecordingHandler()
    src._handler = handler
    with caplog.at_level(logging.INFO, logger=_REMOTE_LOGGER):
        await src._poll_once()
    assert len(handler.bodies) == 3
    assert _remote_pending(client) == []
    assert "poll_max_files" not in caplog.text


async def test_remote_ceiling_is_on_by_default_and_operator_overridable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shipped on at ``DEFAULT_MAX_ITEMS_PER_POLL`` with no setting; a falsy value opts out.

    Red mutation: default the knob to ``None`` — the first assertion reds. Both remote factories are
    pinned against the constant because each repeats the number as a literal."""
    for factory in (Sftp, Ftp):
        settings = factory(host="sftp.example.com", remote_dir="/in").settings
        assert settings["poll_max_files"] == DEFAULT_MAX_ITEMS_PER_POLL
    client = _FakeRemoteClient({})
    assert _remote_source(monkeypatch, client)._poll_max_files == DEFAULT_MAX_ITEMS_PER_POLL
    assert _remote_source(monkeypatch, client, poll_max_files=25)._poll_max_files == 25
    assert _remote_source(monkeypatch, client, poll_max_files=0)._poll_max_files is None


async def test_remote_refused_listing_name_does_not_charge_the_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fair progress: an entry refused as an unsafe path component is left in place forever, so it must
    never spend the budget.

    Red mutation: charge the budget on the ``_is_contained_name`` refusal — the two refused entries eat
    a ceiling of two on every poll and the healthy files behind them are never ingested."""
    monkeypatch.setattr(remotefile, "DEFAULT_MAX_ITEMS_PER_POLL", 2)
    files = _remote_files(2)
    client = _FakeRemoteClient(files)
    # Two hostile listing entries that sort ahead of the healthy ones. They are refused at the source
    # and deliberately NOT quarantined (joining a hostile name onto a directory is the refused act).
    monkeypatch.setattr(
        client,
        "list_dir",
        lambda remote_dir: [
            ("../escape.hl7", 4),
            ("also/bad.hl7", 4),
            *_FakeRemoteClient.list_dir(client, remote_dir),
        ],
    )
    src = _remote_source(monkeypatch, client)
    handler = _RecordingHandler()
    src._handler = handler
    await src._poll_once()
    assert [b.decode() for b in handler.bodies] == [_ADT.format(n=0), _ADT.format(n=1)]


# === DATABASE =================================================================


#: A payload column value that ``_body`` cannot turn into a body: raw bytes that are not valid UTF-8,
#: so ``bytes(value).decode(encoding)`` raises ``UnicodeDecodeError`` (a ``ValueError``). This is the
#: genuinely PER-ROW decode failure — the static one (a ``body_column`` naming no selected column) is
#: caught once per poll and never reaches a row at all.
_POISON = b"\xff\xfe\xfd"


class _FakeTable:
    """A poll table. ``mark`` deletes a row, which is the shape ``mark_statement`` is documented to
    have, and it is what makes a deferral drain: an unmarked row is still selected by the next poll."""

    def __init__(self, count: int, *, rows: list[tuple[int, Any]] | None = None) -> None:
        self.rows: list[tuple[int, Any]] = (
            rows if rows is not None else [(n, _ADT.format(n=n)) for n in range(count)]
        )

    def mark(self, row_id: int) -> None:
        self.rows = [row for row in self.rows if row[0] != row_id]


class _FakeCursor:
    description = [("id",), ("payload",)]

    def __init__(self, table: _FakeTable, fetches: list[tuple[str, int | None]]) -> None:
        self._table = table
        self._buffer: list[tuple[int, Any]] = []
        self._position = 0
        self._fetches = fetches

    async def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> None:
        if params is None:  # the poll SELECT
            self._buffer = list(self._table.rows)
            self._position = 0
        else:  # a per-row mark
            self._table.mark(params[0])

    async def fetchall(self) -> list[tuple[int, Any]]:
        self._fetches.append(("fetchall", None))
        rows = self._buffer[self._position :]
        self._position = len(self._buffer)
        return rows

    async def fetchmany(self, size: int) -> list[tuple[int, Any]]:
        self._fetches.append(("fetchmany", size))
        rows = self._buffer[self._position : self._position + size]
        self._position += len(rows)
        return rows

    async def close(self) -> None:
        return None


class _FakeConn:
    def __init__(self, table: _FakeTable, fetches: list[tuple[str, int | None]]) -> None:
        self._table = table
        self._fetches = fetches

    async def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._table, self._fetches)


class _FakePool:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    async def acquire(self) -> _FakeConn:
        return self._conn

    async def release(self, conn: _FakeConn) -> None:
        return None


def _db_source(**over: Any) -> DatabaseSource:
    base: dict[str, Any] = {
        "server": "sql.example.com",
        "database": "MFDB",
        "poll_statement": "SELECT id, payload FROM mf_inbox WHERE status='NEW' ORDER BY id",
        "mark_statement": "UPDATE mf_inbox SET status='DONE' WHERE id=:id",
        "body_column": "payload",
    }
    base.update(over)
    src = build_source(Source(type=ConnectorType.DATABASE, settings=DatabasePoll(**base).settings))
    assert isinstance(src, DatabaseSource)
    return src


def _attach(src: DatabaseSource, table: _FakeTable) -> list[tuple[str, int | None]]:
    fetches: list[tuple[str, int | None]] = []
    src._pool = _FakePool(_FakeConn(table, fetches))
    return fetches


async def test_db_poll_stops_at_the_shipped_ceiling_and_leaves_the_rest_in_the_table(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One poll takes exactly the SHIPPED 500 rows and the surplus row is still in the table, unmarked.

    This one runs at the real default rather than a patched one, so the number the engine ships is the
    number under test on at least one source.

    Red mutation: restore the unbounded ``fetchall`` in ``_select`` — all 501 rows are handed off and
    the table empties, so both the count and the leftover assertion red."""
    table = _FakeTable(DEFAULT_MAX_ITEMS_PER_POLL + 1)
    src = _db_source()  # no operator configuration at all — the shipped default applies
    fetches = _attach(src, table)
    handler = _RecordingHandler()
    src._handler = handler
    with caplog.at_level(logging.INFO, logger=_DB_LOGGER):
        await src._poll_once()
    assert len(handler.bodies) == DEFAULT_MAX_ITEMS_PER_POLL
    assert table.rows == [(500, _ADT.format(n=500))]  # deferred, unmarked, still selectable
    # The ceiling is charged at the FETCH: the driver is asked for EXACTLY the ceiling, never for the
    # whole result set and never for a probe row past it. A row here can carry a message body
    # (`body_column`), so a ceiling+1 probe would marshal a whole payload out of the driver and throw
    # it away on every poll, to decide one word in a log line.
    assert fetches == [("fetchmany", DEFAULT_MAX_ITEMS_PER_POLL)]
    assert "filled poll_max_rows" in caplog.text


async def test_db_second_poll_drains_the_deferred_rows() -> None:
    """The next poll takes the rows the first one left, so every row is handed off exactly once.

    Red mutation: mark or delete the rows past the ceiling at the fetch — the first poll's count is
    unchanged and only this test reds, with the surplus row's body never arriving."""
    table = _FakeTable(DEFAULT_MAX_ITEMS_PER_POLL + 1)
    src = _db_source()
    _attach(src, table)
    handler = _RecordingHandler()
    src._handler = handler
    await src._poll_once()
    await src._poll_once()
    assert len(handler.bodies) == DEFAULT_MAX_ITEMS_PER_POLL + 1
    assert handler.bodies[-1].decode() == _ADT.format(n=500)
    assert table.rows == []


async def test_db_poll_below_the_ceiling_is_unchanged(caplog: pytest.LogCaptureFixture) -> None:
    """Negative control: a result set under the ceiling is handled exactly as before, with no deferral
    log line.

    Red mutation: fetch ``poll_max_rows - 1``, or log the ceiling unconditionally — either reds here
    while the over-ceiling tests stay green.

    STRICTLY below, three rows against a ceiling of four, and the margin is load-bearing. Since the
    fetch asks for exactly the ceiling rather than a probe row past it, a FULL batch is the only
    signal that more may remain, so a result set of exactly ``poll_max_rows`` logs the deferral even
    when the table happens to be empty behind it. That is the accepted imprecision of not paying for
    a probe row, and this test would silently stop being a negative control if it sat on the
    boundary."""
    table = _FakeTable(3)
    src = _db_source(poll_max_rows=4)
    fetches = _attach(src, table)
    handler = _RecordingHandler()
    src._handler = handler
    with caplog.at_level(logging.INFO, logger=_DB_LOGGER):
        await src._poll_once()
    assert [b.decode() for b in handler.bodies] == [_ADT.format(n=n) for n in range(3)]
    assert table.rows == []  # all three marked
    assert fetches == [("fetchmany", 4)]
    assert "poll_max_rows" not in caplog.text  # nothing deferred, so nothing said
    assert "poll_max_rows" not in caplog.text


async def test_db_ceiling_is_on_by_default_and_the_opt_out_restores_fetchall() -> None:
    """Shipped on at ``DEFAULT_MAX_ITEMS_PER_POLL`` with no setting; ``poll_max_rows=0`` restores the
    unbounded ``fetchall``.

    Red mutation: default the knob to ``None`` — the first assertion reds. Second red mutation: keep
    using ``fetchmany`` when the knob is falsy, and the recorded fetch call names it."""
    factory_default = DatabasePoll(
        server="sql.example.com", database="MFDB", poll_statement="SELECT 1"
    ).settings["poll_max_rows"]
    assert factory_default == DEFAULT_MAX_ITEMS_PER_POLL  # the factory repeats it as a literal
    assert _db_source()._poll_max_rows == DEFAULT_MAX_ITEMS_PER_POLL
    assert _db_source(poll_max_rows=25)._poll_max_rows == 25
    src = _db_source(poll_max_rows=0)
    assert src._poll_max_rows is None
    table = _FakeTable(7)
    fetches = _attach(src, table)
    handler = _RecordingHandler()
    src._handler = handler
    await src._poll_once()
    assert len(handler.bodies) == 7
    assert fetches == [("fetchall", None)]


# --- BACKLOG #1662: an undecodable row must not spend a ceiling slot ----------


class _CapturingSink:
    """The runner's connection-event sink, recorded. The runner injects one onto EVERY source, this
    one included — the DATABASE source simply never called it before #1662."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str | None, str | None]] = []

    async def __call__(self, kind: str, peer_host: str | None, reason: str | None) -> None:
        self.events.append((kind, peer_host, reason))


async def test_db_a_poison_row_does_not_starve_the_ceiling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The measured starvation, at the ceiling that reproduces it in one poll.

    With ``poll_max_rows=1`` and an undecodable row sorting first, the shipped code charged the
    ceiling at the fetch and skipped the row afterwards: every poll handled nothing, marked nothing
    and logged one ERROR, for ever, while the good row behind it was never reached.

    Red mutation: charge the ceiling at the fetch again (take ``fetchmany(poll_max_rows)`` once and
    decode in ``_poll_once``) — no body arrives, the good row is still in the table, and the
    single-fetch assertion reds with it.
    """
    table = _FakeTable(0, rows=[(0, _POISON), (1, _ADT.format(n=1))])
    src = _db_source(poll_max_rows=1)
    fetches = _attach(src, table)
    handler = _RecordingHandler()
    src._handler = handler
    with caplog.at_level(logging.ERROR, logger=_DB_LOGGER):
        await src._poll_once()
    assert [b.decode() for b in handler.bodies] == [_ADT.format(n=1)]  # the row behind IS reached
    assert table.rows == [(0, _POISON)]  # ... and marked; the poison row stays, unmarked
    assert "skipping row" in caplog.text  # the skip is still reported, not swallowed
    # The top-up asks only for the SHORTFALL, so one poll pulls at most the ceiling plus the rows it
    # skipped — never the rest of the result set.
    assert fetches == [("fetchmany", 1), ("fetchmany", 1)]


async def test_db_a_poison_row_emits_a_connection_event(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The visibility half of #1662: an operator must be able to SEE rows being skipped.

    The shipped code wrote no store row, no disposition and no event — only a logger line — so a feed
    quietly ingesting nothing looked identical to an idle one on the console.

    Red mutation: delete the ``_emit_event`` call in ``_poll_once``. Reds here while the starvation
    test above stays green, so the two halves are pinned independently.
    """
    table = _FakeTable(0, rows=[(0, _POISON), (1, _ADT.format(n=1))])
    src = _db_source(poll_max_rows=4)
    _attach(src, table)
    sink = _CapturingSink()
    src.on_connection_event = sink
    src._handler = _RecordingHandler()
    with caplog.at_level(logging.ERROR, logger=_DB_LOGGER):
        await src._poll_once()
    assert [kind for kind, _peer, _reason in sink.events] == ["row_undecodable"]
    reason = sink.events[0][2] or ""
    assert "UnicodeDecodeError" in reason  # the type is kept; safe_exc renders it
    assert sink.events[0][1] is None  # a poll source dials out — there is no peer to name


async def test_db_a_missing_body_column_is_reported_once_per_poll_not_once_per_row(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The dominant ``_body`` failure is STATIC — ``body_column`` naming a column ``poll_statement``
    does not select fails every row — so replacing skipped rows without catching it first would trade
    a starved ceiling for a log flood.

    Checked once against the cursor's own description, before any row is read: one line, one event,
    and nothing fetched at all. The shipped code logged once per row, up to the ceiling.

    Red mutation: drop the static pre-check and let ``_body`` raise per row. The counts red (four
    lines and four events), and the empty ``fetches`` assertion reds with them.
    """
    table = _FakeTable(4)
    src = _db_source(body_column="nope", poll_max_rows=500)
    fetches = _attach(src, table)
    sink = _CapturingSink()
    src.on_connection_event = sink
    handler = _RecordingHandler()
    src._handler = handler
    with caplog.at_level(logging.ERROR, logger=_DB_LOGGER):
        await src._poll_once()
    assert handler.bodies == []
    assert caplog.text.count("skipping row") == 1
    assert len(sink.events) == 1
    assert "'nope'" in (sink.events[0][2] or "")  # the operator's own column name, no row value
    assert fetches == []  # nothing pulled out of the driver for a poll that cannot decode anything
    assert len(table.rows) == 4  # nothing marked


async def test_db_the_skip_budget_stops_one_poll_and_defers_the_rest(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Replacement is bounded: one poll steps past at most ``_MAX_SKIPPED_ROWS_PER_POLL`` rows.

    Without this bound a table whose rows all fail per-row decoding would be walked end to end on
    every tick, one log line per row.

    Red mutation: remove the budget check — every poison row is skipped and logged, so both the
    budget line and the skip count red.
    """
    poison = [(n, _POISON) for n in range(db_mod._MAX_SKIPPED_ROWS_PER_POLL + 5)]
    table = _FakeTable(0, rows=poison)
    src = _db_source(poll_max_rows=500)
    _attach(src, table)
    handler = _RecordingHandler()
    src._handler = handler
    with caplog.at_level(logging.ERROR, logger=_DB_LOGGER):
        await src._poll_once()
    assert handler.bodies == []
    assert caplog.text.count("skipping row") == db_mod._MAX_SKIPPED_ROWS_PER_POLL
    assert "stopped fetching" in caplog.text
    assert len(table.rows) == len(poison)  # deferred, not dropped and not marked


async def test_db_a_poison_row_is_never_marked() -> None:
    """A row that never became a message is NOT marked, and that is deliberate.

    ``mark_statement`` is an operator-authored ``UPDATE``, so marking here would record data DONE that
    was never ingested — see the reasoning in ``database.py``'s handler-failure arm. There is no store
    disposition to record either: a row the source could not read was never a received message, the
    same reading ``file.py`` applies to an oversize or unscannable drop.

    Red mutation: mark the row on the skip arm — the table empties and this reds.
    """
    table = _FakeTable(0, rows=[(0, _POISON)])
    src = _db_source(poll_max_rows=4)
    _attach(src, table)
    src._handler = _RecordingHandler()
    await src._poll_once()
    await src._poll_once()
    assert table.rows == [(0, _POISON)]  # still there after two polls, unmarked


# === all three poll sources ===================================================


async def test_a_negative_ceiling_is_refused_at_build_on_every_poll_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A negative ceiling is a build error, not a running connection that ingests nothing.

    Accepted, ``poll_max_files=-1`` would make ``_at_ceiling`` true on the first candidate of every
    tick: the source would report running and take nothing, for ever. That is the worst outcome this
    control can produce, so a typo is refused where a bad ``after_read`` is — at wiring, before start.

    Text that is not a number is refused on every source too, with a message naming the setting.

    Red mutation: replace ``resolve_poll_ceiling`` with ``int(value) if value else None`` — no negative
    build raises, and this test reds at the first one."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    with pytest.raises(ValueError, match="positive number of items per poll"):
        _file_source(inbox, poll_max_files=-1)
    with pytest.raises(ValueError, match="positive number of items per poll"):
        _remote_source(monkeypatch, _FakeRemoteClient({}), poll_max_files=-1)
    with pytest.raises(ValueError, match="positive number of items per poll"):
        _db_source(poll_max_rows=-1)
    with pytest.raises(ValueError, match="poll_max_files='many' is not a valid int value"):
        _file_source(inbox, poll_max_files="many")
    with pytest.raises(ValueError, match="poll_max_files='many' is not a valid int value"):
        _remote_source(monkeypatch, _FakeRemoteClient({}), poll_max_files="many")
    with pytest.raises(ValueError, match="poll_max_rows='many' is not a valid int value"):
        _db_source(poll_max_rows="many")


# === the security record ======================================================
#
# ``docs/SECURITY.md``'s Ingest plane row is the operator-facing statement of this control. After PR
# 948 renamed the knob, that row still named ``max_files_per_poll`` at 1000 and called the Database
# poll uncovered (BACKLOG #1518). The guard lives HERE, beside the tests that measure the ceiling, so
# a rename of the knob or a new default reds the doc check in the same module. It reads what it
# compares against from the code: knob names and their sources from the factory signatures, the
# default from ``DEFAULT_MAX_ITEMS_PER_POLL``. The conditions and the charging mechanics are stated
# once, in ``docs/CONNECTIONS.md``; the row must link there, and this guard checks that it does.
#
# It is a prose screen, so it catches the shapes it was cut from and a set of near misses, not every
# possible wrong sentence. The control at the end of this section lists the shapes it is known to see.

_SECURITY_DOC = Path(__file__).resolve().parent.parent / "docs" / "SECURITY.md"

#: The four factories that take a per-tick ceiling. Listed, because "is a poll source" is a judgment;
#: the KNOB each one takes is derived below rather than listed.
_POLL_FACTORIES: tuple[Callable[..., Any], ...] = (File, Sftp, Ftp, DatabasePoll)

#: A name shaped like a poll-ceiling knob in either word order (``poll_max_files``,
#: ``max_files_per_poll``), backticked or not. Every one the row names must be a knob a factory takes.
_KNOB_SHAPED = re.compile(r"\b([a-z_]*(?:max[a-z_]*poll|poll[a-z_]*max)[a-z_]*)\b")

#: A whole number, thousands separators allowed, so "1,000" reads as 1000 rather than as 1 and 0.
_NUMBER = re.compile(r"\d+(?:,\d{3})*")

_ITEM_2 = "(2) "
_NOT_COVERED = "**Still not covered even when set:**"
_SHIPS_ON = "**Resource bounds that DO ship on**"
_LINK = "CONNECTIONS.md#per-tick-poll-ceilings"


def _ingest_row() -> str:
    # A copy of the helper in test_dicom_association_intake_bound.py, kept rather than imported:
    # that module skips itself at import when the [dicom] extra is absent, which would take this
    # guard down with it.
    doc = _SECURITY_DOC.read_text(encoding="utf-8")
    return next(line for line in doc.splitlines() if line.startswith("| **Ingest plane**"))


def _poll_ceiling_knobs() -> dict[str, str]:
    """``{factory name: its per-tick ceiling knob}``, read from the signatures.

    Exactly one ``poll_max_*`` parameter per factory, or this fails: a rename that dropped the prefix
    would otherwise empty the set and let every check below pass vacuously."""
    knobs: dict[str, str] = {}
    for factory in _POLL_FACTORIES:
        found = [n for n in inspect.signature(factory).parameters if n.startswith("poll_max_")]
        assert len(found) == 1, (
            f"{factory.__name__}() takes {found} as its poll ceiling; expected exactly one "
            "poll_max_* parameter. Re-derive this guard against the new name."
        )
        knobs[factory.__name__] = found[0]
    return knobs


def _numbers(text: str) -> set[int]:
    return {int(n.replace(",", "")) for n in _NUMBER.findall(text)}


def _poll_row_complaints(row: str, knobs: dict[str, str], default: int) -> list[str]:
    """Every way ``row`` contradicts the shipped poll ceiling. Empty means the row agrees.

    A pure function of its inputs, so the planted-wording control below can prove each check fires.
    Each landmark it reads by must be present: a missing one is a complaint, never a skipped check."""
    missing = [m for m in (_ITEM_2, _NOT_COVERED, _SHIPS_ON) if m not in row]
    if missing:
        return [f"the row has lost the landmark(s) {missing} this guard reads it by; re-derive it"]
    complaints: list[str] = []
    for name in sorted(set(_KNOB_SHAPED.findall(row)) - set(knobs.values())):
        complaints.append(f"the row names `{name}`, which no poll factory takes")
    if re.search(r"no row ceiling", row, re.IGNORECASE):
        complaints.append("the row says a source has no row ceiling; DatabasePoll() takes one")

    # Item (2) is the ceiling's own statement. It may state no number but the default, so a wrong
    # default is caught wherever in the item it is written, before or after the knob.
    item = row[row.index(_ITEM_2) + len(_ITEM_2) : row.index(_NOT_COVERED)]
    by_knob: dict[str, set[str]] = {}
    for factory, knob in knobs.items():
        by_knob.setdefault(knob, set()).add(factory)
    for knob, factories in sorted(by_knob.items()):
        # The parenthesis after the knob's first mention names the sources that take it, exactly.
        scope = re.search(rf"`{re.escape(knob)}` \(([^)]*)\)", item)
        named = set(re.findall(r"`([A-Za-z]+)`", scope.group(1))) if scope else set()
        if named != factories:
            complaints.append(
                f"item (2) does not tie `{knob}` to exactly {sorted(factories)}; it names "
                f"{sorted(named)}"
            )
    if (stated := _numbers(item)) != {default}:
        complaints.append(
            f"item (2) states the number(s) {sorted(stated)}; the only number it may state is the "
            f"shipped default, {default}"
        )
    for phrase in (
        f"ship ON at {default}",
        "not how many it lists",
        "deferred, not refused",
        "on the Database source only under conditions",
        "refused when the connection is built",
        _LINK,
    ):
        if phrase not in item:
            complaints.append(f"item (2) no longer says {phrase!r}")

    # The "not covered" sentence must not list the Database poll, which now has a ceiling. The
    # sentence runs to the next bold landmark, so an "e.g." inside it does not cut it short.
    clause = re.split(r"\.\s+\*\*", row.split(_NOT_COVERED, 1)[1], maxsplit=1)[0]
    if re.search(r"database|\bDB\b", clause, re.IGNORECASE):
        complaints.append(
            "the row lists the Database poll as uncovered; DatabasePoll() takes a ceiling"
        )

    # The ship-on list names each knob, and every number in the parenthesis after them is the default.
    ships_on = row.split(_SHIPS_ON, 1)[1]
    listed = re.search(r"((?:`[a-z_]+`(?:,? and |, ))*`poll_max_[a-z_]+`) \(([^)]*)\)", ships_on)
    if listed is None:
        complaints.append("the ship-on list no longer names the poll ceiling with its default")
    else:
        for knob in sorted(set(knobs.values()) - set(_KNOB_SHAPED.findall(listed.group(1)))):
            complaints.append(f"the ship-on list does not name `{knob}`")
        if (in_list := _numbers(listed.group(2))) != {default}:
            complaints.append(
                f"the ship-on list states {sorted(in_list)}; the code ships {default}"
            )
    return complaints


def test_the_security_ingest_row_agrees_with_the_shipped_poll_ceiling() -> None:
    """The SECURITY.md Ingest plane row names the real knobs with the sources that take them, states
    the real default as shipped ON, covers the Database source, links the conditions it does not
    restate, and keeps two statements an operator relies on: the excess waits for a later tick, and a
    bad value is refused before the connection starts.

    Those behaviours are measured earlier in this module, by the ``*_second_*_drains_*`` tests,
    ``test_file_leave_mode_files_already_taken_do_not_charge_the_ceiling`` and
    ``test_a_negative_ceiling_is_refused_at_build_on_every_poll_source``. This test holds the prose
    to them. It restores the guard withdrawn from ``tests/test_dicom_association_intake_bound.py``
    when PR 948 renamed the knob (BACKLOG #1518). The factory-default loop repeats the per-source
    default pins above on purpose: a factory default that split from the constant would leave the
    doc no single number to state."""
    knobs = _poll_ceiling_knobs()
    for factory in _POLL_FACTORIES:
        knob = knobs[factory.__name__]
        assert inspect.signature(factory).parameters[knob].default == DEFAULT_MAX_ITEMS_PER_POLL, (
            f"{factory.__name__}({knob}=...) defaults to a different number than the connector "
            "constant, so the doc cannot state one default for both"
        )
    complaints = _poll_row_complaints(_ingest_row(), knobs, DEFAULT_MAX_ITEMS_PER_POLL)
    assert not complaints, "docs/SECURITY.md Ingest plane row: " + "; ".join(complaints)


def test_the_poll_row_guard_fires_on_the_wording_it_replaced() -> None:
    """Proves the guard above can fail. It feeds the guard the wording #1518 replaced, then plants a
    set of wrong facts into the live row, and each plant must draw the complaint aimed at it rather
    than any complaint at all."""
    knobs = _poll_ceiling_knobs()
    default = DEFAULT_MAX_ITEMS_PER_POLL

    def complaints(row: str) -> str:
        return " ".join(_poll_row_complaints(row, knobs, default))

    retired = (
        "(2) `max_files_per_poll` bounds one **poll tick** on the `File`, `Sftp` and `Ftp` sources, "
        "and it **ships ON** (1000) -- the opposite default, deliberately, because those sources have "
        "no sender to back-pressure and the excess is **deferred to the next tick, never refused**: the "
        "files stay where they are and a later tick takes them, so a guessed number costs latency, "
        "never a message. **Still not covered even when set:** the **Database poll** source (its "
        "`fetchall` has no row ceiling), any **per-message** bound on the DICOM SCP. "
        "**Resource bounds that DO ship on** -- at least `max_connections` (256), "
        "`max_files_per_poll` (1000, on the poll sources), `source_ip_allowlist` |"
    )
    got = complaints(retired)
    for expected in (
        "`max_files_per_poll`, which no poll factory takes",
        "does not tie `poll_max_files`",
        "does not tie `poll_max_rows`",
        "states the number(s) [1000]",
        "no row ceiling",
        "Database poll as uncovered",
        "ship-on list no longer names the poll ceiling",
    ):
        assert expected in got, f"the guard missed {expected!r} in the retired wording: {got}"

    live = _ingest_row()
    assert not _poll_row_complaints(live, knobs, default), "the live row must pass, or this is moot"
    sources = "(the `File`, `Sftp` and `Ftp` sources)"
    plants: dict[str, tuple[str, str]] = {
        "the ceiling shipped off": (
            live.replace("ship ON at 500", "ship OFF (500 when set)"),
            "'ship ON at 500'",
        ),
        "a wrong default in its own sentence": (
            live.replace("why 500", "why 500 (it used to be 1,000)"),
            "states the number(s) [500, 1000]",
        ),
        "a wrong default before the knob": (
            live.replace(
                _ITEM_2 + "`poll_max_files`", _ITEM_2 + "At 1000 per tick, `poll_max_files`"
            ),
            "states the number(s) [500, 1000]",
        ),
        "the knobs swapped between sources": (
            live.replace(
                "`poll_max_files` " + sources, "`poll_max_files` (the `DatabasePoll` source)"
            ),
            "does not tie `poll_max_files`",
        ),
        "a source dropped": (
            live.replace(sources, "(the `File` and `Sftp` sources)"),
            "does not tie `poll_max_files`",
        ),
        "the retired no-ceiling sentence in item (2)": (
            live.replace(
                "before it starts. ", "before it starts. Its `fetchall` has no row ceiling. ", 1
            ),
            "no row ceiling",
        ),
        "the Database poll uncovered after an e.g.": (
            live.replace(_NOT_COVERED, _NOT_COVERED + " (e.g. the Database poll source)"),
            "Database poll as uncovered",
        ),
        "the Database poll uncovered in lower case": (
            live.replace(_NOT_COVERED, _NOT_COVERED + " the database poll source,"),
            "Database poll as uncovered",
        ),
        "the Database poll uncovered as DB": (
            live.replace(_NOT_COVERED, _NOT_COVERED + " the DB poll source,"),
            "Database poll as uncovered",
        ),
        "the conditions link removed": (live.replace(_LINK, "CONNECTIONS.md"), repr(_LINK)),
        "an unbackticked retired knob": (
            live.replace(
                ", `source_ip_allowlist`", ", max_files_per_poll (1000), `source_ip_allowlist`"
            ),
            "`max_files_per_poll`, which no poll factory takes",
        ),
        "a second default in the ship-on list": (
            live.replace("(500, on the poll sources)", "(500 on files, 1000 on the database)"),
            "the ship-on list states [500, 1000]",
        ),
        "a reworded landmark": (
            live.replace(_NOT_COVERED, "**Not covered even when set:**"),
            "lost the landmark",
        ),
    }
    for what, (row, expected) in plants.items():
        assert row != live, f"the plant for {what} did not apply; its anchor text has moved"
        got = complaints(row)
        assert expected in got, f"the guard missed {what}: expected {expected!r}, got {got!r}"
