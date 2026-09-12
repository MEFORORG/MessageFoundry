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

import logging
import posixpath
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import DatabasePoll, File, Ftp, Sftp
from messagefoundry.transports import build_source, remotefile
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
    scan finds nothing and the last two messages never arrive."""
    from messagefoundry.transports import file as file_mod

    monkeypatch.setattr(file_mod, "DEFAULT_MAX_ITEMS_PER_POLL", 3)
    inbox = tmp_path / "in"
    inbox.mkdir()
    _drop(inbox, 5)
    src = _file_source(inbox)
    handler = _RecordingHandler()
    src._handler = handler
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
    await src._scan_once()
    assert [b.decode() for b in handler.bodies] == [_ADT.format(n=3), _ADT.format(n=4)]
    assert _pending(inbox) == ["a_locked1.hl7", "a_locked2.hl7"]  # still there, still retryable


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


class _FakeTable:
    """A poll table. ``mark`` deletes a row, which is the shape ``mark_statement`` is documented to
    have, and it is what makes a deferral drain: an unmarked row is still selected by the next poll."""

    def __init__(self, count: int) -> None:
        self.rows: list[tuple[int, str]] = [(n, _ADT.format(n=n)) for n in range(count)]

    def mark(self, row_id: int) -> None:
        self.rows = [row for row in self.rows if row[0] != row_id]


class _FakeCursor:
    description = [("id",), ("payload",)]

    def __init__(self, table: _FakeTable, fetches: list[tuple[str, int | None]]) -> None:
        self._table = table
        self._buffer: list[tuple[int, str]] = []
        self._position = 0
        self._fetches = fetches

    async def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> None:
        if params is None:  # the poll SELECT
            self._buffer = list(self._table.rows)
            self._position = 0
        else:  # a per-row mark
            self._table.mark(params[0])

    async def fetchall(self) -> list[tuple[int, str]]:
        self._fetches.append(("fetchall", None))
        rows = self._buffer[self._position :]
        self._position = len(self._buffer)
        return rows

    async def fetchmany(self, size: int) -> list[tuple[int, str]]:
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


# === all three poll sources ===================================================


async def test_a_negative_ceiling_is_refused_at_build_on_every_poll_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A negative ceiling is a build error, not a running connection that ingests nothing.

    Accepted, ``poll_max_files=-1`` would make ``_at_ceiling`` true on the first candidate of every
    tick: the source would report running and take nothing, for ever. That is the worst outcome this
    control can produce, so a typo is refused where a bad ``after_read`` is — at wiring, before start.

    Red mutation: replace ``resolve_poll_ceiling`` with ``int(value) if value else None`` — no build
    raises, and this test reds three times."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    with pytest.raises(ValueError, match="positive number of items per poll"):
        _file_source(inbox, poll_max_files=-1)
    with pytest.raises(ValueError, match="positive number of items per poll"):
        _remote_source(monkeypatch, _FakeRemoteClient({}), poll_max_files=-1)
    with pytest.raises(ValueError, match="positive number of items per poll"):
        _db_source(poll_max_rows=-1)
