# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4940: a configured uploads root that is not there is not zero uploads.

The reseal pass returned all-zero counts for a root that was not a directory, so ``rotate-key``
printed OK, stamped the key and closed the rotation record. Behind an unmounted volume every upload
was still under the prior key, which the OK invited the operator to retire. ``rotate-key`` now
checks the root before it writes anything and refuses, exit 2, with nothing changed. A root that
goes away during the run fails it as a skip does: exit 1, no stamp, the record left open. A site
with no uploads, an empty root or no ``uploads_dir`` at all, still completes.

The root is created on the first save (``UploadStore._ensure_root``), not at ``serve``, so a site
that configured ``uploads_dir`` and never stored an upload has no root either. Nothing tells that from an
unmounted volume, so both refuse, and the error says to create the directory in the first case
only."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.pipeline.secret_rotation import ROTATION_RECORD_ID, dek_fingerprint
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from messagefoundry.uploads import ResealResult, UploadStore
from tests.test_cli import _rotate_env
from tests.test_rotate_key_rotation_record import _DEK, _OLD_DATE, _key_id, _open, _rows, _seed


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, str, str]:
    monkeypatch.chdir(tmp_path)
    db, uploads = tmp_path / "rot.db", tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    asyncio.run(_seed(db, uploads, key_a))
    return db, uploads, key_a, key_b


def _completes_once_mounted(db: Path, uploads: Path, key_b: str) -> None:
    """A re-run over the directory back in place seals its upload, stamps and closes the record."""
    assert main(["rotate-key", "--db", str(db)]) == 0
    rows = asyncio.run(_rows(db, key_b))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[ROTATION_RECORD_ID].fingerprint == ""

    async def read_with_the_new_key_alone() -> list[str]:
        store = await _open(db, key_b)  # key A is gone
        try:
            listed = await UploadStore(uploads, store.cipher(), max_bytes=1 << 20).list_files()
            return [m.filename for m in listed]
        finally:
            await store.close()

    assert asyncio.run(read_with_the_new_key_alone()) == ["a.hl7"]


@pytest.mark.parametrize("shape", ["missing", "a file"])
def test_an_unmounted_uploads_root_is_refused_before_anything_is_written(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    shape: str,
) -> None:
    """The closing condition. The rename stands in for an unmount: the uploads are still under the
    prior key, just not where the run looks. The refusal opens no record and rolls nothing, so
    key A alone still opens the store."""
    db, uploads, key_a, key_b = rig
    unmounted = uploads.with_name("uploads-elsewhere")
    uploads.rename(unmounted)
    if shape == "a file":
        uploads.write_text("not a directory", encoding="utf-8")
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=uploads)

    assert main(["rotate-key", "--db", str(db)]) == 2
    captured = capsys.readouterr()
    assert "OK" not in captured.out
    assert (
        f"the uploads directory {uploads.absolute()} ([store].uploads_dir) does not exist or is "
        "not a directory, so rotate-key changed nothing" in captured.err
    )
    assert "a volume that is not mounted" in captured.err
    rows = asyncio.run(_rows(db, key_a))  # key A alone: nothing was re-encrypted or rolled
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))
    assert rows[_DEK].last_rotated == _OLD_DATE
    assert ROTATION_RECORD_ID not in rows

    if shape == "a file":
        uploads.unlink()
    unmounted.rename(uploads)
    _completes_once_mounted(db, uploads, key_b)


def test_an_uploads_root_gone_mid_run_fails_it_and_leaves_the_record_open(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The backstop: the root passes the check before the store opens and is gone by the uploads
    pass. The reseal reports it rather than zero uploads, so the run fails as a skip does."""
    db, uploads, key_a, key_b = rig
    unmounted = uploads.with_name("uploads-elsewhere")
    reencrypt = MessageStore.reencrypt_to_active

    async def unmount_then_reencrypt(self: MessageStore) -> int:
        uploads.rename(unmounted)
        return await reencrypt(self)

    monkeypatch.setattr(MessageStore, "reencrypt_to_active", unmount_then_reencrypt)
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=uploads)

    assert main(["rotate-key", "--db", str(db)]) == 1
    captured = capsys.readouterr()
    assert "PARTIAL:" in captured.out and "OK: re-encrypted" not in captured.out
    assert "went away during the run, so no uploaded file was re-sealed" in captured.err
    assert "remove the two files" not in captured.out  # that remedy is a skip's, not this
    assert "you cannot go back to the prior key" in captured.out
    rows = asyncio.run(_rows(db, key_b, key_a))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))  # no stamp
    assert rows[_DEK].last_rotated == _OLD_DATE
    assert rows[ROTATION_RECORD_ID].fingerprint == dek_fingerprint(_key_id(key_b))  # still open
    assert not uploads.exists()  # the run created nothing where the volume should be

    monkeypatch.setattr(MessageStore, "reencrypt_to_active", reencrypt)
    unmounted.rename(uploads)
    _completes_once_mounted(db, uploads, key_b)


@pytest.mark.parametrize("uploads_dir", ["empty", "unset"])
def test_a_site_with_no_uploads_still_completes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    uploads_dir: str,
) -> None:
    """Told apart from a missing root: an empty root, or no ``uploads_dir`` at all, holds nothing
    under the prior key, so the run completes, stamps and closes the record."""
    monkeypatch.chdir(tmp_path)
    db, seeded = tmp_path / "rot.db", tmp_path / "seed-uploads"
    key_a, key_b = generate_key(), generate_key()
    asyncio.run(_seed(db, seeded, key_a))
    empty = tmp_path / "uploads"
    empty.mkdir()
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=empty)
    if uploads_dir == "unset":
        monkeypatch.delenv("MEFOR_STORE_UPLOADS_DIR")

    assert main(["rotate-key", "--db", str(db)]) == 0
    captured = capsys.readouterr()
    assert "OK: re-encrypted" in captured.out
    assert "uploads directory" not in captured.err
    rows = asyncio.run(_rows(db, key_b))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[ROTATION_RECORD_ID].fingerprint == ""


@pytest.mark.parametrize("shape", ["missing", "a file", "empty"])
async def test_reseal_reports_a_root_that_is_not_a_directory(tmp_path: Path, shape: str) -> None:
    """Only a root that is not a directory is missing; an empty one is a site with no uploads."""
    root = tmp_path / "uploads"
    if shape == "a file":
        root.write_text("not a directory", encoding="utf-8")
    elif shape == "empty":
        root.mkdir()
    result = await UploadStore(
        root, make_cipher(generate_key()), max_bytes=1 << 20
    ).reseal_to_active()
    missing = shape != "empty"
    assert result == ResealResult(root_missing=missing)
    assert result.incomplete is missing
    assert root.is_dir() is not missing  # the pass creates nothing
