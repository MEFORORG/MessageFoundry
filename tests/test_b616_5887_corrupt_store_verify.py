# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A corrupt ``store.db`` inside an archive is a verify FAIL, never an escaping ``sqlite3`` error.

Restore-verify, restore and a backup's own post-write verify all read the extracted snapshot through
``sqlite3``. A member that is not a database raised ``sqlite3.DatabaseError`` out of every one of them:
the standalone verify and the restore crashed instead of reporting, and a backup skipped the
failed-archive quarantine. Synthetic bytes only.
"""

from __future__ import annotations

import io
import json
import sqlite3
import tarfile
import tempfile
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupError, BackupRunner
from messagefoundry.redaction import safe_exc

_NOT_A_DATABASE = b"this is not a sqlite database, just synthetic bytes " * 200


@pytest.fixture(autouse=True)
def _own_os_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A standalone verify and a restore stage under the OS temp dir, so it is the test's own."""
    (tmp_path / "ostemp").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "ostemp"))


def _plaintext_archive(path: Path, store_bytes: bytes) -> str:
    """A plaintext (unencrypted) archive: a tar holding a manifest and the given ``store.db`` bytes."""
    manifest = json.dumps({"row_counts": {"messages": 0}, "config_only": False}).encode("utf-8")
    with tarfile.open(path, "w") as tar:
        for name, data in (
            (dr_backup._MANIFEST_MEMBER, manifest),
            (dr_backup._STORE_MEMBER, store_bytes),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return str(path)


def _good_db_archive(tmp_path: Path) -> str:
    db = tmp_path / "good.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE messages (id INTEGER)")
    conn.commit()
    conn.close()
    return _plaintext_archive(tmp_path / "good.mfbak", db.read_bytes())


def _verify(archive: str, tmp_path: Path, *, standalone: bool = False) -> dr_backup.VerifyResult:
    return dr_backup._verify_archive_blocking(
        archive_path=archive,
        keys=[],
        full=False,
        staging_root=None if standalone else tmp_path / "staging",
        secure=True,
    )


def _coded(cls: type[sqlite3.Error], text: str, code: int) -> sqlite3.Error:
    exc = cls(text)
    exc.sqlite_errorcode = code
    return exc


def _io_error(*_a: object) -> object:
    raise _coded(sqlite3.OperationalError, "disk I/O error", sqlite3.SQLITE_IOERR)


@pytest.mark.parametrize("standalone", [False, True], ids=["backup-staging", "standalone"])
def test_verify_reports_a_store_member_that_is_not_a_database_as_a_fail(
    tmp_path: Path, standalone: bool
) -> None:
    archive = _plaintext_archive(tmp_path / "bad.mfbak", _NOT_A_DATABASE)
    result = _verify(archive, tmp_path, standalone=standalone)
    assert result.status == "FAIL"
    assert result.integrity_ok is False
    assert result.manifest_counts == {"messages": 0}
    assert result.reason == (
        "integrity_check failed: the file could not be read: DatabaseError: file is not a database"
    )


def test_a_count_that_will_not_decode_is_a_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Python-side decode error carries no result code, and it is still the snapshot's bytes."""

    def _undecodable(_path: Path) -> dict[str, int]:
        raise sqlite3.OperationalError("Could not decode to UTF-8 column 'name' with text 'x'")

    monkeypatch.setattr(dr_backup, "_count_tables", _undecodable)
    result = _verify(_good_db_archive(tmp_path), tmp_path)
    assert result.status == "FAIL"
    # integrity_check passed, so the result must not say it failed.
    assert result.integrity_ok is True
    assert result.reason is not None
    assert result.reason.startswith("the row-count check failed: its tables could not be counted")
    assert "integrity_check" not in result.reason
    assert "with text" not in result.reason


def test_an_integrity_failure_stays_the_verdict_when_the_count_hits_a_snapshot_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A coded SQLITE_CORRUPT from the count, a real code rather than an uncoded stand-in, reaches the
    arm that keeps the failed integrity_check as the verdict and logs the count's error. Any count
    error reaches it once integrity_check has failed; the volume-fault sibling below covers that."""

    def _count_raises(_path: Path) -> dict[str, int]:
        raise _coded(
            sqlite3.DatabaseError, "database disk image is malformed", sqlite3.SQLITE_CORRUPT
        )

    monkeypatch.setattr(dr_backup, "_integrity_check", lambda _p: (False, "page 2 is never used"))
    monkeypatch.setattr(dr_backup, "_count_tables", _count_raises)
    with caplog.at_level("WARNING", logger=dr_backup.log.name):
        result = _verify(_good_db_archive(tmp_path), tmp_path)
    assert result.status == "FAIL"
    assert result.integrity_ok is False
    assert result.reason == "integrity_check failed: page 2 is never used"
    assert any(
        "snapshot row count failed after a failed integrity_check" in r.getMessage()
        and "database disk image is malformed" in r.getMessage()
        for r in caplog.records
    )


def test_a_volume_fault_in_a_backups_verify_raises_so_nothing_is_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A disk I/O error is about the volume, so a backup's own verify must not FAIL a good archive
    on it, which would quarantine it."""
    monkeypatch.setattr(dr_backup, "_integrity_check", _io_error)
    with pytest.raises(sqlite3.OperationalError):
        _verify(_good_db_archive(tmp_path), tmp_path)


def test_a_volume_fault_in_a_standalone_verify_is_a_fail_that_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dr_backup, "_integrity_check", _io_error)
    result = _verify(_good_db_archive(tmp_path), tmp_path, standalone=True)
    assert result.status == "FAIL"
    assert result.reason == "not a fault in the archive: OperationalError: disk I/O error"


def test_a_volume_fault_in_a_restore_is_a_restore_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dr_backup, "_integrity_check", _io_error)
    dest = tmp_path / "restored" / "store.db"
    with pytest.raises(BackupError) as caught:
        dr_backup._restore_blocking(
            archive_path=_good_db_archive(tmp_path),
            dest_store_path=dest,
            config_dest=None,
            keys=[],
            max_age_seconds=None,
        )
    assert caught.value.kind == "restore"
    assert not dest.exists()


def test_restore_reports_a_store_member_that_is_not_a_database_as_a_verify_error(
    tmp_path: Path,
) -> None:
    archive = _plaintext_archive(tmp_path / "bad.mfbak", _NOT_A_DATABASE)
    dest = tmp_path / "restored" / "store.db"
    with pytest.raises(BackupError) as caught:
        dr_backup._restore_blocking(
            archive_path=archive,
            dest_store_path=dest,
            config_dest=None,
            keys=[],
            max_age_seconds=None,
        )
    assert caught.value.kind == "verify"
    assert "failed integrity_check" in str(caught.value)
    assert not dest.exists()


@pytest.mark.parametrize(
    ("exc", "verdict"),
    [
        (_coded(sqlite3.DatabaseError, "file is not a database", sqlite3.SQLITE_NOTADB), True),
        (_coded(sqlite3.DatabaseError, "malformed", sqlite3.SQLITE_CORRUPT), True),
        # The file's schema: an unsupported format, an unknown collation (an extended code).
        (_coded(sqlite3.OperationalError, "unsupported file format", sqlite3.SQLITE_ERROR), True),
        (
            _coded(sqlite3.OperationalError, "no such collation", sqlite3.SQLITE_ERROR | 1 << 8),
            True,
        ),
        # An extended code is read by its primary family (SQLITE_CORRUPT_VTAB = CORRUPT | 1 << 8).
        (_coded(sqlite3.DatabaseError, "vtab", sqlite3.SQLITE_CORRUPT | (1 << 8)), True),
        (sqlite3.OperationalError("Could not decode to UTF-8 column 'name'"), True),
        (_coded(sqlite3.OperationalError, "disk I/O error", sqlite3.SQLITE_IOERR), False),
        (_coded(sqlite3.OperationalError, "locking protocol", sqlite3.SQLITE_PROTOCOL), False),
        (_coded(sqlite3.OperationalError, "interrupted", sqlite3.SQLITE_INTERRUPT), False),
        (_coded(sqlite3.DatabaseError, "internal", sqlite3.SQLITE_INTERNAL), False),
        (_coded(sqlite3.DatabaseError, "schema changed", sqlite3.SQLITE_SCHEMA), False),
        (_coded(sqlite3.DatabaseError, "no lfs", sqlite3.SQLITE_NOLFS), False),
        (_coded(sqlite3.DatabaseError, "abort", sqlite3.SQLITE_ABORT), False),
        # Code-less but not the decode error: not a verdict on the bytes.
        (sqlite3.OperationalError("something else"), False),
        (sqlite3.ProgrammingError("Cannot operate on a closed database."), False),
        (sqlite3.InterfaceError("bad parameter"), False),
    ],
)
def test_only_the_snapshots_own_bytes_are_a_verdict_on_it(
    exc: sqlite3.Error, verdict: bool
) -> None:
    assert dr_backup._is_snapshot_fault(exc) is verdict


def test_an_unlisted_code_in_a_backups_verify_raises_so_nothing_is_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _protocol(*_a: object) -> object:
        raise _coded(sqlite3.OperationalError, "locking protocol", sqlite3.SQLITE_PROTOCOL)

    monkeypatch.setattr(dr_backup, "_integrity_check", _protocol)
    with pytest.raises(sqlite3.OperationalError):
        _verify(_good_db_archive(tmp_path), tmp_path)


def test_a_failed_integrity_check_stays_the_verdict_when_the_count_hits_a_volume_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dr_backup, "_integrity_check", lambda _p: (False, "page 2 is never used"))
    monkeypatch.setattr(dr_backup, "_count_tables", _io_error)
    result = _verify(_good_db_archive(tmp_path), tmp_path)
    assert result.status == "FAIL"
    assert result.integrity_ok is False
    assert result.reason == "integrity_check failed: page 2 is never used"


def test_restore_reports_a_count_that_will_not_decode_as_a_verify_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _undecodable(_path: Path) -> dict[str, int]:
        raise sqlite3.OperationalError("Could not decode to UTF-8 column 'name' with text 'x'")

    monkeypatch.setattr(dr_backup, "_count_tables", _undecodable)
    dest = tmp_path / "restored" / "store.db"
    with pytest.raises(BackupError) as caught:
        dr_backup._restore_blocking(
            archive_path=_good_db_archive(tmp_path),
            dest_store_path=dest,
            config_dest=None,
            keys=[],
            max_age_seconds=None,
        )
    assert caught.value.kind == "verify"
    assert "row-count check" in str(caught.value)
    assert "integrity_check" not in str(caught.value)
    assert not dest.exists()


async def test_a_volume_fault_in_a_backups_verify_fails_the_run_naming_the_archive_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The verify re-raises the fault; the run turns it into its typed error naming the `.part`
    archive it left unpublished, as it does a staging refusal."""

    def _faulted_verify(**_kw: object) -> object:
        exc = _coded(sqlite3.OperationalError, "disk I/O error", sqlite3.SQLITE_IOERR)
        exc.add_note("staging directory mefor-verify-x could not be removed")
        raise exc

    monkeypatch.setattr(dr_backup, "_verify_archive_blocking", _faulted_verify)
    runner = BackupRunner(
        cast(Any, None),
        BackupSettings(enabled=True, destination=str(tmp_path / "dest"), verify_after_backup=True),
        store_settings=StoreSettings(path=str(tmp_path / "msg.db")),
        config_dir=None,
        instance="dev",
    )
    with pytest.raises(BackupError) as caught:
        await runner._verify_and_publish(
            tmp_path / "a.mfbak.part",
            tmp_path / "a.mfbak",
            key=None,
            staging_root=tmp_path,
            secure=False,
        )
    assert caught.value.kind == "write"
    # The directory the verify's teardown left, which may hold decrypted bytes, leads; the
    # archive's location follows it.
    assert str(caught.value) == (
        "staging directory mefor-verify-x could not be removed; "
        "archive written but not verified, left at a.mfbak.part: OperationalError: disk I/O error"
    )
    assert isinstance(caught.value.__cause__, sqlite3.OperationalError)


async def test_the_leftover_plaintext_path_survives_the_failure_records_cut(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failure record keeps 200 characters of ``safe_exc``; with a long ``.part`` name the
    message passes that, and the verify staging directory's path must be in what is kept."""
    leftover = "staging directory mefor-verify-leftover7 could not be removed"

    def _faulted_verify(**_kw: object) -> object:
        exc = _coded(sqlite3.OperationalError, "disk I/O error", sqlite3.SQLITE_IOERR)
        exc.add_note(leftover)
        raise exc

    monkeypatch.setattr(dr_backup, "_verify_archive_blocking", _faulted_verify)
    runner = BackupRunner(
        cast(Any, None),
        BackupSettings(enabled=True, destination=str(tmp_path / "dest"), verify_after_backup=True),
        store_settings=StoreSettings(path=str(tmp_path / "msg.db")),
        config_dir=None,
        instance="dev",
    )
    name = "b" * 160 + ".mfbak"
    with pytest.raises(BackupError) as caught:
        await runner._verify_and_publish(
            tmp_path / f"{name}.part",
            tmp_path / name,
            key=None,
            staging_root=tmp_path,
            secure=False,
        )
    assert len(str(caught.value)) > 200
    kept = safe_exc(caught.value)
    # Positive control: the cut applied, so the tail of the message did not survive it.
    assert "disk I/O error" not in kept
    assert leftover in kept


def _schema_format_5(tmp_path: Path) -> bytes:
    """A real store.db whose header names a schema format SQLite does not support (offset 44)."""
    db = tmp_path / "format5.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE messages (id INTEGER)")
    conn.commit()
    conn.close()
    data = bytearray(db.read_bytes())
    data[44:48] = (5).to_bytes(4, "big")
    return bytes(data)


def _undecodable_schema(tmp_path: Path) -> bytes:
    """A real store.db with a schema row whose name is not UTF-8, so SQLite's own error message
    quotes bytes CPython cannot decode."""
    db = tmp_path / "badname.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE messages (id INTEGER)")
    conn.commit()
    conn.execute("PRAGMA writable_schema=ON")
    conn.execute(
        "INSERT INTO sqlite_master(type, name, tbl_name, rootpage, sql) VALUES ('table', "
        "CAST(x'ff41' AS TEXT), CAST(x'ff41' AS TEXT), 0, "
        "CAST(x'435245415445205441424c45202241ff22202861293b' AS TEXT))"
    )
    conn.commit()
    conn.close()
    return db.read_bytes()


@pytest.mark.parametrize("standalone", [False, True], ids=["backup-staging", "standalone"])
@pytest.mark.parametrize("build", [_schema_format_5, _undecodable_schema], ids=["format", "decode"])
def test_a_real_schema_the_engine_cannot_read_is_a_fail_on_the_archive(
    tmp_path: Path, standalone: bool, build: Any
) -> None:
    archive = _plaintext_archive(tmp_path / "bad.mfbak", build(tmp_path))
    result = _verify(archive, tmp_path, standalone=standalone)
    assert result.status == "FAIL"
    assert result.integrity_ok is False
    assert result.reason is not None
    assert result.reason.startswith("integrity_check failed: the file could not be read: ")
    assert "not a fault in the archive" not in result.reason


def test_restore_reports_a_schema_that_will_not_decode_as_a_verify_error(tmp_path: Path) -> None:
    archive = _plaintext_archive(tmp_path / "bad.mfbak", _undecodable_schema(tmp_path))
    dest = tmp_path / "restored" / "store.db"
    with pytest.raises(BackupError) as caught:
        dr_backup._restore_blocking(
            archive_path=archive,
            dest_store_path=dest,
            config_dest=None,
            keys=[],
            max_age_seconds=None,
        )
    assert caught.value.kind == "verify"
    assert not dest.exists()
