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
from pathlib import Path

import pytest

from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupError

_NOT_A_DATABASE = b"this is not a sqlite database, just synthetic bytes " * 200


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


@pytest.mark.parametrize("standalone", [False, True], ids=["backup-staging", "standalone"])
def test_verify_reports_a_store_member_that_is_not_a_database_as_a_fail(
    tmp_path: Path, standalone: bool
) -> None:
    archive = _plaintext_archive(tmp_path / "bad.mfbak", _NOT_A_DATABASE)
    result = dr_backup._verify_archive_blocking(
        archive_path=archive,
        keys=[],
        full=False,
        staging_root=None if standalone else tmp_path / "staging",
        secure=True,
    )
    assert result.status == "FAIL"
    assert result.integrity_ok is False
    assert result.manifest_counts == {"messages": 0}
    assert result.reason is not None
    assert "integrity_check failed: DatabaseError: file is not a database" in result.reason


def test_an_error_that_is_not_about_the_snapshot_still_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a file that is not a database, or is corrupt, is a verdict on the archive. A lock or an
    I/O error is about the volume, so it must not become a FAIL that quarantines a good archive."""
    db = tmp_path / "good.db"
    sqlite3.connect(db).close()

    class _Conn:
        def execute(self, _sql: str) -> object:
            exc = sqlite3.OperationalError("disk I/O error")
            exc.sqlite_errorcode = sqlite3.SQLITE_IOERR
            raise exc

        def close(self) -> None:
            pass

    monkeypatch.setattr(dr_backup, "connect_readonly", lambda *_a, **_k: _Conn())
    with pytest.raises(sqlite3.OperationalError):
        dr_backup._integrity_check(db)


def test_verify_tests_integrity_before_it_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A snapshot that fails ``integrity_check`` may not count at all, so the count must not run first
    and turn the integrity verdict into a different failure."""
    db = tmp_path / "good.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE messages (id INTEGER)")
    conn.commit()
    conn.close()
    archive = _plaintext_archive(tmp_path / "torn.mfbak", db.read_bytes())

    def _count_raises(_path: Path) -> dict[str, int]:
        raise sqlite3.DatabaseError("database disk image is malformed")

    monkeypatch.setattr(dr_backup, "_integrity_check", lambda _p: (False, "page 2 is never used"))
    monkeypatch.setattr(dr_backup, "_count_tables", _count_raises)
    result = dr_backup._verify_archive_blocking(
        archive_path=archive,
        keys=[],
        full=False,
        staging_root=tmp_path / "staging",
        secure=True,
    )
    assert result.status == "FAIL"
    assert result.integrity_ok is False
    assert result.reason is not None and "integrity_check failed" in result.reason


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
