# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A file a partner is still writing in place must not pass as a complete message (BACKLOG #116).

A drop written in place, rather than to a temp name and then renamed, can be read while it is still
growing. Before #116 the File and REMOTEFILE sources took no stat between the read and the move. So the
engine emitted the prefix as if it were the whole message, then archived the full file with its unread
tail, and logged nothing. These tests pin both halves of the fix:

- a file that changes while it is read is not emitted on that poll; and
- a file that changes after it was read is not moved or deleted, so the next poll reads it whole.

In the second case the message already handed off cannot be recalled: the handler returns an ACK
string, not a handle on the stored row. The WARNING is what makes that visible. All HL7 is synthetic.
"""

from __future__ import annotations

import ftplib  # nosec B402 - a stub's error type only; nothing here opens a connection
import os
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _phi_log_capture import (
    IDENTIFIER_SHAPE,
    IDENTIFIER_SHAPED_NAMES,
    FilteredCapture,
    filtered_sink,
    strip_safe_labels,
)

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports import remotefile
from messagefoundry.transports.file import FileSource
from messagefoundry.transports.remotefile import _FtpClient, _SftpClient
from tests.test_remotefile_transport import _FakeClient, _src

_FILE_LOGGER = "messagefoundry.transports.file"
_REMOTE_LOGGER = "messagefoundry.transports.remotefile"

#: A synthetic ORU cut off mid-OBX-5, as a partner writing in place leaves it between two writes.
_HEAD = (
    rb"MSH|^~\&|LAB|FAC|EHR|FAC|20260918||ORU^R01|CTRL1|P|2.5" + b"\rPID|1||SYN01\rOBX|1|NM|GLU||"
)
_TAIL = b"98|mg/dL\rOBX|2|NM|K||4.1|mmol/L\r"
_WHOLE = _HEAD + _TAIL

#: The client-level tests only need a path; the source-level ones take a name from
#: IDENTIFIER_SHAPED_NAMES, because the new WARNINGs must name a file by its safe label only (#1748).
_PATH = "/in/a.hl7"
_names = pytest.mark.parametrize("name", IDENTIFIER_SHAPED_NAMES)


def _assert_no_name(
    sink: FilteredCapture, caplog: pytest.LogCaptureFixture, name: str, *, strip: str = ""
) -> None:
    """The WARNINGs must name ``name`` by its safe label only, checked on two instruments.

    ``sink`` is what a shipped log would write, after the production redaction filters. ``caplog``
    sees each record before any handler filter runs, so it pins the call site itself: a filter that
    later learned to scrub file names could not hide a WARNING that logged the raw one.

    ``strip`` removes the operator's own directory path, which a WARNING may carry and which a
    pytest temp path (``pytest-21248``) can make look identifier-shaped. The last check is the
    control: an instrument that caught nothing would pass the first two by default."""
    for instrument, text in (("sink", sink.text), ("caplog", caplog.text)):
        assert name not in text, f"{instrument}: the raw file name was logged"
        assert IDENTIFIER_SHAPE.search(strip_safe_labels(text.replace(strip, ""))) is None
        assert "[name:" in text, f"{instrument}: no WARNING naming the file reached it"


class _Recorder:
    """A pipeline handler that records each hand-off and can run a partner's write on the first one."""

    def __init__(self, on_first: Callable[[], None] | None = None) -> None:
        self.got: list[bytes] = []
        self._on_first = on_first

    async def __call__(self, raw: bytes) -> str | None:
        self.got.append(raw)
        if len(self.got) == 1 and self._on_first is not None:
            self._on_first()
        return None


# === local File source ============================================================================


def _local(inbox: Path, **over: object) -> FileSource:
    settings: dict[str, object] = {"directory": str(inbox), "pattern": "*.hl7"}
    settings.update(over)
    src = FileSource(Source(type=ConnectorType.FILE, settings=settings))
    src._prepare_subdirs()
    return src


def _append_tail(path: Path) -> None:
    with path.open("ab") as fh:
        fh.write(_TAIL)


@_names
@pytest.mark.parametrize("after_read", ["move", "delete"])
async def test_a_file_that_grows_after_the_read_is_neither_archived_nor_deleted(
    tmp_path: Path, after_read: str, name: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The probe's case: the partner finishes writing while the message is in flight."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / name
    drop.write_bytes(_HEAD)
    src = _local(inbox, after_read=after_read)
    handler = _Recorder(on_first=lambda: _append_tail(drop))
    src._handler = handler
    with filtered_sink(_FILE_LOGGER) as sink:
        await src._scan_once()
    assert handler.got == [_HEAD]  # handed off before the change; the source cannot recall it
    assert drop.exists(), "the file was archived or deleted with its unread tail"
    assert drop.read_bytes() == _WHOLE
    assert list((inbox / ".processed").iterdir()) == []
    assert "changed after it was read" in sink.text
    _assert_no_name(sink, caplog, name, strip=str(inbox))
    # The next poll reads the settled file whole and only then disposes of it: nothing is lost.
    await src._scan_once()
    assert handler.got == [_HEAD, _WHOLE]
    assert not drop.exists()


@_names
async def test_a_file_that_grows_during_the_read_is_not_emitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, caplog: pytest.LogCaptureFixture
) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / name
    drop.write_bytes(_HEAD)
    real_read = Path.read_bytes

    def read_then_partner_writes(self: Path) -> bytes:
        data = real_read(self)
        if self.name == name:
            _append_tail(self)  # the partner's next write lands as the read finishes
        return data

    monkeypatch.setattr(Path, "read_bytes", read_then_partner_writes)
    src = _local(inbox)
    handler = _Recorder()
    src._handler = handler
    with filtered_sink(_FILE_LOGGER) as sink:
        await src._scan_once()
    monkeypatch.undo()
    assert handler.got == [], "a file read mid-write was emitted as a complete message"
    assert drop.read_bytes() == _WHOLE  # left in place for the next poll
    assert "changed while it was read" in sink.text
    _assert_no_name(sink, caplog, name, strip=str(inbox))
    await src._scan_once()
    assert handler.got == [_WHOLE]


async def test_a_same_length_rewrite_during_the_read_is_caught_by_the_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Size alone cannot see a rewrite that keeps the length; the modification time still moves."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "a.hl7"
    drop.write_bytes(_WHOLE)
    real_read = Path.read_bytes

    def read_then_partner_rewrites(self: Path) -> bytes:
        data = real_read(self)
        st = self.stat()
        os.utime(self, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))
        return data

    monkeypatch.setattr(Path, "read_bytes", read_then_partner_rewrites)
    src = _local(inbox)
    handler = _Recorder()
    src._handler = handler
    await src._scan_once()
    assert handler.got == []
    assert drop.exists()


@pytest.mark.parametrize("after_read", ["move", "delete", "leave"])
async def test_a_stable_file_is_processed_exactly_as_before(
    tmp_path: Path, after_read: str
) -> None:
    """The control: a file nobody is writing flows through once, with no new WARNING."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "a.hl7"
    drop.write_bytes(_WHOLE)
    src = _local(inbox, after_read=after_read)
    handler = _Recorder()
    src._handler = handler
    with filtered_sink(_FILE_LOGGER) as sink:
        await src._scan_once()
        await src._scan_once()  # a second poll must not re-emit it, in any mode
    assert handler.got == [_WHOLE]
    assert "changed" not in sink.text
    archived = inbox / ".processed" / "a.hl7"
    if after_read == "move":
        assert archived.read_bytes() == _WHOLE and not drop.exists()
    elif after_read == "delete":
        assert not drop.exists() and not archived.exists()
    else:
        assert drop.read_bytes() == _WHOLE and not archived.exists()


async def test_leave_mode_warns_and_reingests_a_file_that_grew_after_the_read(
    tmp_path: Path,
) -> None:
    """``leave`` never lost the tail: its dedup key folds size and mtime, so the grown file gets a new
    key. What it lacked was any sign that the first message was partial."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "a.hl7"
    drop.write_bytes(_HEAD)
    src = _local(inbox, after_read="leave")
    handler = _Recorder(on_first=lambda: _append_tail(drop))
    src._handler = handler
    with filtered_sink(_FILE_LOGGER) as sink:
        await src._scan_once()
    assert "changed after it was read" in sink.text
    await src._scan_once()
    await src._scan_once()  # the settled file is ingested once, then deduplicated
    assert handler.got == [_HEAD, _WHOLE]
    assert drop.read_bytes() == _WHOLE


# === REMOTEFILE source ============================================================================
# The in-memory client is the shared _FakeClient, so a retrieve runs through the shipped bounded sink.


@_names
@pytest.mark.parametrize("after_read", ["move", "delete"])
async def test_a_remote_file_that_grows_after_the_read_is_neither_archived_nor_deleted(
    monkeypatch: pytest.MonkeyPatch,
    after_read: str,
    name: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    path = f"/in/{name}"
    client = _FakeClient(files={path: _HEAD})
    src = _src(monkeypatch, client, after_read=after_read)

    def partner_finishes() -> None:
        client.files[path] += _TAIL

    handler = _Recorder(on_first=partner_finishes)
    src._handler = handler
    with filtered_sink(_REMOTE_LOGGER) as sink:
        await src._poll_once()
    assert handler.got == [_HEAD]
    assert path in client.files, "the file was archived or deleted with its unread tail"
    assert client.files[path] == _WHOLE
    assert not any(p.startswith("/in/.processed/") for p in client.files)
    assert "changed after it was read" in sink.text
    _assert_no_name(sink, caplog, name)
    await src._poll_once()
    assert handler.got == [_HEAD, _WHOLE]
    assert path not in client.files


@_names
async def test_a_remote_file_that_changed_during_the_retrieve_is_not_emitted(
    monkeypatch: pytest.MonkeyPatch, name: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The source's arm for the client's refusal. The clients' own detection is pinned below."""

    class _GrowingClient(_FakeClient):
        def retrieve(self, path: str, *, max_bytes: int | None = None) -> bytes:
            body = super().retrieve(path, max_bytes=max_bytes)
            if [op for op, _ in self.ops].count("retrieve") == 1:
                self.files[path] = body + _TAIL  # the partner writes as the transfer ends
                raise remotefile._RemoteChanged(
                    before=len(body), read=len(body), after=len(self.files[path])
                )
            return body

    path = f"/in/{name}"
    client = _GrowingClient(files={path: _HEAD})
    src = _src(monkeypatch, client)
    handler = _Recorder()
    src._handler = handler
    with filtered_sink(_REMOTE_LOGGER) as sink:
        await src._poll_once()
    assert handler.got == []
    assert client.files[path] == _WHOLE  # left in place, not quarantined
    assert "changed while it was retrieved" in sink.text
    _assert_no_name(sink, caplog, name)
    await src._poll_once()
    assert handler.got == [_WHOLE]
    assert client.files[f"/in/.processed/{name}"] == _WHOLE


async def test_a_stable_remote_file_is_processed_exactly_as_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient(files={_PATH: _WHOLE})
    src = _src(monkeypatch, client)
    handler = _Recorder()
    src._handler = handler
    with filtered_sink(_REMOTE_LOGGER) as sink:
        await src._poll_once()
    assert handler.got == [_WHOLE]
    assert client.files == {"/in/.processed/a.hl7": _WHOLE}
    assert "changed" not in sink.text


# --- the clients' own size reads -------------------------------------------------------------------


class _SftpFile:
    """A paramiko ``SFTPFile`` stand-in whose ``stat()`` reports ``sizes`` in turn."""

    def __init__(self, body: bytes, sizes: list[int]) -> None:
        self._body = body
        self._pos = 0
        self._sizes = sizes

    def stat(self) -> SimpleNamespace:
        size = self._sizes.pop(0) if len(self._sizes) > 1 else self._sizes[0]
        return SimpleNamespace(st_size=size)

    def read(self, n: int) -> bytes:
        chunk = self._body[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk

    def __enter__(self) -> _SftpFile:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _Sftp:
    """A paramiko ``SFTPClient`` stand-in: one open file, a path ``stat``, and the two dispositions."""

    def __init__(self, fh: _SftpFile | None = None, *, size: int = 0) -> None:
        self._fh = fh
        self._size = size
        self.calls: list[str] = []

    def open(self, path: str, mode: str) -> _SftpFile:
        assert self._fh is not None
        return self._fh

    def stat(self, path: str) -> SimpleNamespace:
        return SimpleNamespace(st_size=self._size)

    def posix_rename(self, src: str, dst: str) -> None:
        self.calls.append("rename")

    def remove(self, path: str) -> None:
        self.calls.append("remove")


class _Ftp:
    """An ``ftplib.FTP`` stand-in: ``SIZE`` answers from ``sizes`` in turn, or refuses when empty."""

    def __init__(self, body: bytes, sizes: list[int]) -> None:
        self._body = body
        self._sizes = sizes
        self.calls: list[str] = []

    def voidcmd(self, cmd: str) -> str:
        self.calls.append(cmd)
        return "200 OK"

    def size(self, path: str) -> int:
        if not self._sizes:
            raise ftplib.error_perm("502 SIZE not implemented")
        return self._sizes.pop(0) if len(self._sizes) > 1 else self._sizes[0]

    def retrbinary(self, cmd: str, callback: Any, blocksize: int = 8192) -> None:
        callback(self._body)

    def rename(self, src: str, dst: str) -> None:
        self.calls.append("rename")

    def delete(self, path: str) -> None:
        self.calls.append("delete")


def test_sftp_retrieve_refuses_a_file_that_grew_during_the_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fh = _SftpFile(_HEAD, [len(_HEAD), len(_WHOLE)])
    monkeypatch.setattr(_SftpClient, "_op", lambda self, fn: fn(_Sftp(fh)))
    client = _SftpClient({"host": "sftp.example.com"})
    with pytest.raises(remotefile._RemoteChanged) as caught:
        client.retrieve(_PATH, max_bytes=1024)
    assert (caught.value.before, caught.value.read, caught.value.after) == (
        len(_HEAD),
        len(_HEAD),
        len(_WHOLE),
    )


def test_ftp_retrieve_refuses_a_file_that_grew_during_the_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ftp = _Ftp(_HEAD, [len(_HEAD), len(_WHOLE)])
    monkeypatch.setattr(_FtpClient, "_op", lambda self, fn: fn(ftp))
    client = _FtpClient({"host": "ftp.example.com"}, tls=False)
    with pytest.raises(remotefile._RemoteChanged):
        client.retrieve(_PATH, max_bytes=1024)
    assert ftp.calls == ["TYPE I"]  # sent once, before SIZE: common servers refuse it in ASCII mode


def test_ftp_retrieve_without_size_support_still_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    """A server that cannot report a size gives no evidence either way, so it never blocks a feed."""
    ftp = _Ftp(_WHOLE, [])
    monkeypatch.setattr(_FtpClient, "_op", lambda self, fn: fn(ftp))
    client = _FtpClient({"host": "ftp.example.com"}, tls=False)
    assert client.retrieve(_PATH, max_bytes=1024) == _WHOLE


@pytest.mark.parametrize(("dest", "call"), [("/in/.processed/a.hl7", "rename"), (None, "remove")])
def test_sftp_dispose_checks_the_size_first(
    monkeypatch: pytest.MonkeyPatch, dest: str | None, call: str
) -> None:
    sftp = _Sftp(size=len(_WHOLE))
    monkeypatch.setattr(_SftpClient, "_op", lambda self, fn: fn(sftp))
    client = _SftpClient({"host": "sftp.example.com"})
    assert client.dispose_unless_changed(_PATH, len(_HEAD), dest) == len(_WHOLE)
    assert sftp.calls == []  # it grew since the read: left in place
    assert client.dispose_unless_changed(_PATH, len(_WHOLE), dest) is None
    assert sftp.calls == [call]


@pytest.mark.parametrize(("dest", "call"), [("/in/.processed/a.hl7", "rename"), (None, "delete")])
def test_ftp_dispose_checks_the_size_first(
    monkeypatch: pytest.MonkeyPatch, dest: str | None, call: str
) -> None:
    grown = _Ftp(b"", [len(_WHOLE)])
    monkeypatch.setattr(_FtpClient, "_op", lambda self, fn: fn(grown))
    client = _FtpClient({"host": "ftp.example.com"}, tls=False)
    assert client.dispose_unless_changed(_PATH, len(_HEAD), dest) == len(_WHOLE)
    assert call not in grown.calls
    no_size = _Ftp(b"", [])  # SIZE unsupported: dispose as before rather than strand the file
    monkeypatch.setattr(_FtpClient, "_op", lambda self, fn: fn(no_size))
    assert client.dispose_unless_changed(_PATH, len(_HEAD), dest) is None
    assert call in no_size.calls
