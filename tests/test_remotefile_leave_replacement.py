# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2758: the RemoteFile leave-mode dedup key sees a same-size replacement.

The key used to be the full remote path plus the listed size, on the premise that a remote listing
carries no reliable modification time. SFTP lists ``st_mtime`` and FTP ``MLSD`` lists ``modify``, so
the shipped key could not tell a same-length rewrite of one fixed name from the file already read,
so on first deployment such a new version would have been skipped with no log line. Now the listed mtime is folded into the key where the server gives
one, and where it gives none the skip is logged at INFO, once per file version per process.
"""

from __future__ import annotations

import ftplib
import hashlib
import logging
import posixpath
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.transports.remotefile import _FtpClient, _Listed, _SftpClient
from tests.test_remotefile_transport import (
    _FakeClient,
    _FakeLedger,
    _RecordingHandler,
    _settle,
    _src,
)

_LOGGER = "messagefoundry.transports.remotefile"
#: A partner-chosen name that embeds an MRN-like token, so a log line that leaked it is caught.
_NAME = "MRN9988776655_ADT.hl7"
_PATH = f"/in/{_NAME}"
_V1 = b"MSH|^~\\&|A|v1"
_V2 = b"MSH|^~\\&|A|v2"  # the same length as _V1: the replacement the old key could not see


class _StampedClient(_FakeClient):
    """A fake whose listing carries a modification time per path, as SFTP and FTP ``MLSD`` do."""

    def __init__(self, files: dict[str, bytes], mtimes: dict[str, str]) -> None:
        super().__init__(files=files)
        self.mtimes = mtimes

    def list_entries(self, remote_dir: str) -> list[_Listed]:
        return [
            _Listed(name, size, self.mtimes.get(posixpath.join(remote_dir, name)))
            for name, size in self.list_dir(remote_dir)
        ]


def _leave_source(monkeypatch: pytest.MonkeyPatch, client: _FakeClient) -> Any:
    src = _src(monkeypatch, client, after_read="leave", pattern="*.hl7")
    src.processed_ledger = _FakeLedger()
    src._handler = _RecordingHandler()
    return src


async def test_a_same_size_replacement_with_a_new_mtime_is_ingested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert len(_V1) == len(_V2)
    client = _StampedClient({_PATH: _V1}, {_PATH: "20261006120000"})
    src = _leave_source(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert src._handler.bodies == [_V1]

    await src._poll_once()  # unchanged: the dedup still holds
    assert src._handler.bodies == [_V1]

    client.files[_PATH] = _V2
    client.mtimes[_PATH] = "20261006130000"
    await _settle(src)  # a new version settles like any new file (BACKLOG #2071)
    await src._poll_once()
    assert src._handler.bodies == [_V1, _V2]
    assert len(src.processed_ledger.keys) == 2


async def test_without_an_mtime_the_skip_is_logged_once_at_info_by_safe_label(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The residual: a server that lists no mtime keeps the path + size key, so the replacement is
    not read. It must not be silent, and it must not name the file in the clear."""
    client = _FakeClient(files={_PATH: _V1})  # the default listing has no mtime
    src = _leave_source(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert src._handler.bodies == [_V1]

    client.files[_PATH] = _V2
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    caplog.clear()
    await src._poll_once()
    await src._poll_once()
    assert src._handler.bodies == [_V1]  # not told apart: the stated residual

    skips = [r for r in caplog.records if "skipped as already ingested" in r.getMessage()]
    assert [r.levelno for r in skips] == [logging.INFO, logging.DEBUG]
    text = skips[0].getMessage()
    assert "MRN9988776655" not in text and _NAME not in text
    assert "[name:" in text
    assert "and size" in text  # a size was listed, so only a same-size version is missed


async def test_a_listing_with_no_size_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    client = _FakeClient(files={_PATH: _V1}, sizes={_PATH: 0})
    src = _leave_source(monkeypatch, client)
    src.processed_ledger.keys.add(src._file_key(_NAME, 0, None))
    caplog.set_level(logging.INFO, logger=_LOGGER)
    await src._poll_once()
    (skip,) = [r for r in caplog.records if "skipped as already ingested" in r.getMessage()]
    assert skip.levelno == logging.INFO
    assert "no modification time and a size of 0" in skip.getMessage()


async def test_a_skip_on_a_key_with_an_mtime_is_not_reported(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """CONTROL: the report is for keys that cannot see a replacement, not for every left file."""
    client = _StampedClient({_PATH: _V1}, {_PATH: "1700000000"})
    src = _leave_source(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    caplog.clear()
    await src._poll_once()
    assert src._handler.bodies == [_V1]
    assert not [r for r in caplog.records if "skipped as already ingested" in r.getMessage()]


def test_the_key_folds_the_mtime_and_keeps_the_size_only_shape_without_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    src = _src(monkeypatch, _FakeClient(), after_read="leave")
    plain = src._file_key(_NAME, 13, None)
    assert plain == hashlib.sha256(f"/in/{_NAME}\x0013".encode()).hexdigest()
    assert src._file_key(_NAME, 13, "1") != plain
    assert src._file_key(_NAME, 13, "1") != src._file_key(_NAME, 13, "2")


class _Ftp:
    def __init__(self, mlsd: list[tuple[str, dict[str, str]]] | None) -> None:
        self._mlsd = mlsd

    def mlsd(self, path: str) -> list[tuple[str, dict[str, str]]]:
        if self._mlsd is None:
            raise ftplib.error_perm("500 MLSD not understood")
        return self._mlsd

    def nlst(self, path: str) -> list[str]:
        return [f"{path}/a.hl7"]

    def size(self, path: str) -> int:
        return 7


def test_ftp_mlsd_lists_the_modify_fact() -> None:
    ftp: Any = _Ftp(
        [
            (".", {"type": "cdir"}),
            ("a.hl7", {"type": "file", "size": "7", "modify": "20261006120000.5"}),
            ("b.hl7", {"type": "file", "size": "3"}),
        ]
    )
    assert _FtpClient._list(ftp, "/in") == [
        _Listed("a.hl7", 7, "20261006120000.5"),
        _Listed("b.hl7", 3, None),
    ]


def test_ftp_without_mlsd_lists_no_mtime() -> None:
    entries = _FtpClient._list(_Ftp(None), "/in")  # type: ignore[arg-type]
    assert entries == [_Listed("a.hl7", 7, None)]


def test_sftp_lists_st_mtime_where_the_server_gives_it(monkeypatch: pytest.MonkeyPatch) -> None:
    regular = 0o100644

    class _Listing:
        def listdir_attr(self, path: str) -> list[Any]:
            return [
                SimpleNamespace(filename="a.hl7", st_mode=regular, st_size=7, st_mtime=1700000000),
                SimpleNamespace(filename="b.hl7", st_mode=regular, st_size=3, st_mtime=None),
                SimpleNamespace(filename="sub", st_mode=0o040755, st_size=0, st_mtime=1),
            ]

    monkeypatch.setattr(_SftpClient, "_op", lambda self, fn: fn(_Listing()))
    client = _SftpClient({"host": "sftp.example.com"})
    assert client.list_entries("/in") == [
        _Listed("a.hl7", 7, "1700000000"),
        _Listed("b.hl7", 3, None),
    ]
    assert client.list_dir("/in") == [("a.hl7", 7), ("b.hl7", 3)]


async def test_a_same_size_rewrite_waits_until_its_mtime_stops_moving(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The settle gate compares the listed mtime too, now the leave-mode key does: a same-size
    rewrite still in progress gets a new key, and must not be admitted while its mtime moves."""
    client = _StampedClient({_PATH: _V1}, {_PATH: "1"})
    src = _leave_source(monkeypatch, client)
    await _settle(src)
    await src._poll_once()
    assert src._handler.bodies == [_V1]

    client.files[_PATH] = _V2
    client.mtimes[_PATH] = "2"
    await src._poll_once()  # first sighting of the new version
    client.mtimes[_PATH] = "3"  # still being written, at the same length
    await src._poll_once()
    assert src._handler.bodies == [_V1], "admitted while its mtime was still moving"
    await src._poll_once()  # unchanged since the last poll: settled
    assert src._handler.bodies == [_V1, _V2]


async def test_a_listing_that_loses_its_mtime_for_a_poll_does_not_hold_a_file_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The settle gate compares mtimes only when both sightings carry one, so a server whose
    ``MLSD`` is refused on one poll (falling back to ``NLST``) still lets a still file through."""
    client = _StampedClient({_PATH: _V1}, {_PATH: "1"})
    src = _src(monkeypatch, client, pattern="*.hl7")  # move mode
    src._handler = _RecordingHandler()
    await src._poll_once()  # first sighting, with an mtime
    del client.mtimes[_PATH]  # this poll's listing has none
    await src._poll_once()
    assert src._handler.bodies == [_V1]


def test_ftp_mlsd_type_fact_is_case_insensitive() -> None:
    ftp: Any = _Ftp([("a.hl7", {"type": "File", "size": "7", "modify": "20261006120000"})])
    assert _FtpClient._list(ftp, "/in") == [_Listed("a.hl7", 7, "20261006120000")]
