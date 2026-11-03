# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4940: a configured uploads root that is not there is not zero uploads.

The reseal pass returned all-zero counts for a root that was not a directory, so ``rotate-key``
printed OK, stamped the key and closed the rotation record. Behind an unmounted volume every upload
was still under the prior key, which the OK invited the operator to retire. ``rotate-key`` now
checks the root before it writes anything and refuses, exit 2, with nothing changed. A root the
uploads pass cannot list after that aborts the run before the audit roll, which is not a skip:
exit 1, no roll, no stamp, the record left open. A site with no uploads, an empty root or no
``uploads_dir`` at all, still completes.

The root is created on the first save (``UploadStore._ensure_root``), not at ``serve``, so a site
that configured ``uploads_dir`` and never stored an upload has no root either. Nothing tells that from an
unmounted volume, so both refuse, and the error says to create the directory in the first case
only."""

from __future__ import annotations

import asyncio
import errno
import os
from pathlib import Path

import pytest

from messagefoundry.__main__ import _uploads_root_refusal, main
from messagefoundry.pipeline.secret_rotation import ROTATION_RECORD_ID, dek_fingerprint
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from messagefoundry.uploads import ResealResult, UploadStore
from tests.test_cli import _rotate_env
from tests.test_rotate_key_rotation_record import (
    _DEK,
    _MSG,
    _OLD_DATE,
    _key_id,
    _open,
    _rows,
    _seed,
)


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
    # The chain did not roll: key A alone still verifies it.
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key_a)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED")
    assert main(["audit-verify", "--db", str(db)]) == 0, capsys.readouterr()
    capsys.readouterr()

    if shape == "a file":
        uploads.unlink()
    unmounted.rename(uploads)
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=uploads)
    _completes_once_mounted(db, uploads, key_b)


def test_an_uploads_root_it_cannot_list_is_refused_with_its_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory that is there but cannot be listed is not told to be created."""

    def denied(path: object) -> object:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os, "scandir", denied)
    refusal = _uploads_root_refusal(str(tmp_path))
    assert refusal is not None
    assert "cannot be listed (Permission denied), so rotate-key changed nothing" in refusal
    assert "Create it" not in refusal


def test_a_missing_root_is_told_to_be_created_owner_only(tmp_path: Path) -> None:
    """The engine creates the root owner-only and never tightens one already there, so a directory
    the operator creates must be owner-only from the start."""
    refusal = _uploads_root_refusal(str(tmp_path / "never-created"))
    assert refusal is not None
    assert "Create it, empty and readable only by the account the engine runs as" in refusal
    assert "does not tighten a directory that is already there" in refusal


def test_a_nul_in_uploads_dir_is_refused_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No filesystem call takes a NUL; it raises ValueError, which the run's OSError arms miss."""
    monkeypatch.chdir(tmp_path)
    refusal = _uploads_root_refusal("up\0loads")
    assert refusal is not None
    assert "contains a NUL character, which no path can hold, so rotate-key changed nothing" in (
        refusal
    )


def test_rotate_key_refuses_a_nul_in_uploads_dir_with_exit_2(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """End to end: the refusal's exit 2 with nothing written, not a ValueError at exit 1. An
    environment variable cannot hold a NUL, so the settings file carries it as a TOML escape."""
    db, uploads, key_a, key_b = rig
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=uploads)
    monkeypatch.delenv("MEFOR_STORE_UPLOADS_DIR")
    cfg = db.with_name("nul.toml")
    cfg.write_text('[store]\nuploads_dir = "up\\u0000loads"\n', encoding="utf-8")
    assert main(["rotate-key", "--service-config", str(cfg), "--db", str(db)]) == 2
    assert "contains a NUL character" in capsys.readouterr().err
    rows = asyncio.run(_rows(db, key_a))  # key A alone: nothing was re-encrypted
    assert ROTATION_RECORD_ID not in rows


@pytest.mark.parametrize(
    "error",
    [
        # Windows raises PermissionError for a volume that is not ready (ERROR_NOT_READY, 21).
        PermissionError(errno.EACCES, "The device is not ready"),
        OSError(getattr(errno, "ESTALE", 116), "Stale file handle"),
    ],
    ids=["volume not ready", "stale network mount"],
)
def test_a_root_it_cannot_list_names_an_offline_volume_as_a_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: OSError
) -> None:
    """Either error can mean the volume is gone rather than a missing right, so the refusal names
    both causes and does not send the operator to grant rights alone."""

    def offline(path: object) -> object:
        raise error

    monkeypatch.setattr(os, "scandir", offline)
    refusal = _uploads_root_refusal(str(tmp_path))
    assert refusal is not None
    assert f"cannot be listed ({error.strerror}), so rotate-key changed nothing" in refusal
    assert "at least an account that may not list it and a volume that is offline" in refusal
    assert "bring the volume back" in refusal
    assert "Create it" not in refusal


def test_a_relative_root_under_a_gone_working_directory_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolving a relative path reads the working directory; one that is gone is a refusal, not a
    traceback."""

    def gone() -> str:
        raise FileNotFoundError(errno.ENOENT, "No such file or directory")

    monkeypatch.setattr(os, "getcwd", gone)
    refusal = _uploads_root_refusal("uploads")
    assert refusal is not None
    assert (
        "the uploads directory uploads ([store].uploads_dir) is relative, and the directory this "
        "command runs in cannot be read (No such file or directory), so rotate-key changed nothing"
    ) in refusal


def test_a_relative_uploads_dir_is_named_as_read(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Read from the command's own directory, which need not be serve's, so the run says where."""
    db, uploads, key_a, key_b = rig
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=Path(uploads.name))
    assert main(["rotate-key", "--db", str(db)]) == 0
    assert f"relative, so it was read here as {uploads.absolute()}" in capsys.readouterr().err


def _chain_rolled(db: Path, key_b: str, monkeypatch: pytest.MonkeyPatch) -> bool:
    """Whether the audit chain rolled to key B, by ``audit-verify`` itself: with key B alone, a chain
    whose current range is still under key A does not verify (BACKLOG #1945), and a rolled one
    does. The store's cells are under key B either way, since its pass runs first."""
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key_b)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED", raising=False)
    return main(["audit-verify", "--db", str(db)]) == 0


def test_an_uploads_root_gone_mid_run_aborts_before_the_audit_roll(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The backstop: the root passes the check before the store opens and is gone by the uploads
    pass. The reseal reports it rather than zero uploads, and the run stops before the one-way audit
    roll, as a listing error that escaped the pass did. Not a skip, so the 2026-10-30 ruling does not
    roll it: the chain stays under key A, nothing is stamped and the record stays open."""
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
    assert "OK" not in captured.out and "PARTIAL" not in captured.out
    assert "error: rotation aborted -- the uploads directory" in captured.err
    assert "could not be by its uploads pass, so no uploaded file was re-sealed" in captured.err
    assert "do not create an empty one" in captured.err  # it was there when the run started
    # Any listing error lands here, so the remedy is not "mount it" alone.
    assert "at least a volume that went offline or was unmounted" in captured.err
    assert "a directory that was moved" in captured.err
    assert "a right to list it that was taken away" in captured.err
    assert "so the audit chain did not roll" in captured.err
    assert "you cannot go back to the prior key" not in captured.out + captured.err
    rows = asyncio.run(_rows(db, key_b, key_a))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))  # no stamp
    assert rows[_DEK].last_rotated == _OLD_DATE
    assert rows[ROTATION_RECORD_ID].fingerprint == dek_fingerprint(_key_id(key_b))  # still open
    assert not uploads.exists()  # the run created nothing where the volume should be
    assert not _chain_rolled(db, key_b, monkeypatch), "the run rolled the audit chain"
    capsys.readouterr()

    monkeypatch.setattr(MessageStore, "reencrypt_to_active", reencrypt)
    unmounted.rename(uploads)
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=uploads)
    _completes_once_mounted(db, uploads, key_b)


def test_a_skip_still_rolls_the_audit_chain(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The control for the abort above, and the owner ruling of 2026-10-30 it leaves alone: a run
    whose uploads pass skips a file still rolls, so the same instrument reads a rolled chain."""
    db, uploads, key_a, key_b = rig
    real = UploadStore.reseal_to_active

    async def one_skip(self: UploadStore) -> ResealResult:
        await real(self)
        return ResealResult(skipped=1)

    monkeypatch.setattr(UploadStore, "reseal_to_active", one_skip)
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=uploads)
    assert main(["rotate-key", "--db", str(db)]) == 1
    captured = capsys.readouterr()
    assert "PARTIAL:" in captured.out
    assert "you cannot go back to the prior key" in captured.out
    rows = asyncio.run(_rows(db, key_b, key_a))
    assert rows[_DEK].last_rotated == _OLD_DATE  # no stamp
    assert rows[ROTATION_RECORD_ID].fingerprint == dek_fingerprint(_key_id(key_b))  # still open
    assert _chain_rolled(db, key_b, monkeypatch), capsys.readouterr()


def test_a_relative_root_gone_mid_run_with_its_working_directory_still_warns(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Printing the path must not need the working directory: one gone mid-run used to raise there
    and lose the error."""
    db, uploads, key_a, key_b = rig
    reencrypt = MessageStore.reencrypt_to_active
    getcwd = os.getcwd

    def gone() -> str:
        raise FileNotFoundError(errno.ENOENT, "No such file or directory")

    async def lose_the_working_directory(self: MessageStore) -> int:
        uploads.rename(uploads.with_name("uploads-elsewhere"))
        monkeypatch.setattr(os, "getcwd", gone)
        return await reencrypt(self)

    monkeypatch.setattr(MessageStore, "reencrypt_to_active", lose_the_working_directory)
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=Path(uploads.name))
    try:
        code = main(["rotate-key", "--db", str(db)])
    finally:
        monkeypatch.setattr(os, "getcwd", getcwd)
    assert code == 1
    captured = capsys.readouterr()
    assert f"the uploads directory {uploads.absolute()} ([store].uploads_dir) could be" in (
        captured.err
    )
    assert "so the audit chain did not roll" in captured.err


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


async def test_reseal_reports_a_root_it_cannot_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory that is there but cannot be listed is read as nothing, so it is missing too."""
    root = tmp_path / "uploads"
    store = UploadStore(root, make_cipher(generate_key()), max_bytes=1 << 20)
    await store.save(data=_MSG.encode(), filename="a.hl7", uploader="op", uploader_id="u")

    def denied(self: Path) -> object:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "iterdir", denied)
    assert await store.reseal_to_active() == ResealResult(root_missing=True)
