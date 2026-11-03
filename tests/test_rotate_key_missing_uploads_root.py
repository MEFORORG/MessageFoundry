# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4940: a configured uploads root that is not there is not zero uploads.

The reseal pass returned all-zero counts for a root that was not a directory, so ``rotate-key``
printed OK, stamped the key and closed the rotation record. Behind an unmounted volume every upload
was still under the prior key, which the OK invited the operator to retire. A missing root now fails
the run as a skip does: exit 1, no stamp, the record left open. A site with no uploads, an empty root
or no ``uploads_dir`` at all, still completes.

The root is created on the first save (``UploadStore._ensure_root``), not at ``serve``, so a site that
configured ``uploads_dir`` and never stored an upload has no root either. The pass cannot tell that
from an unmounted volume, and refuses both; the error tells the operator to create the directory in
the first case."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.pipeline.secret_rotation import ROTATION_RECORD_ID, dek_fingerprint
from messagefoundry.store.crypto import generate_key, make_cipher
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


def test_an_unmounted_uploads_root_fails_the_run_and_leaves_the_record_open(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The closing condition. The rename stands in for an unmount: the uploads are still under the
    prior key, just not where the run looks. Mounted again, a re-run seals them and completes."""
    db, uploads, key_a, key_b = rig
    unmounted = uploads.with_name("uploads-elsewhere")
    uploads.rename(unmounted)
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=uploads)

    assert main(["rotate-key", "--db", str(db)]) == 1
    captured = capsys.readouterr()
    assert "PARTIAL:" in captured.out and "OK: re-encrypted" not in captured.out
    assert f"the uploads directory {uploads} ([store].uploads_dir) does not exist" in captured.err
    assert "create the directory" in captured.err
    rows = asyncio.run(_rows(db, key_b, key_a))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))  # no stamp
    assert rows[_DEK].last_rotated == _OLD_DATE
    assert rows[ROTATION_RECORD_ID].fingerprint == dek_fingerprint(_key_id(key_b))  # still open
    assert not uploads.exists()  # the run created nothing where the volume should be

    unmounted.rename(uploads)
    assert main(["rotate-key", "--db", str(db)]) == 0
    assert "OK: re-encrypted" in capsys.readouterr().out
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
