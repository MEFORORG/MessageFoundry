# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3181 item 5 and vault BACKLOG #3740 item 12.

#3181 item 5: ``rotate-key`` refuses a held store only on SQLite, so an engine on a server store
can delete an upload while the re-seal runs. The re-seal read a file, then replaced it with no
re-check, so a pair deleted in between came back. Every engine removal now holds the uploads root's
pair lock across its unlinks, and the re-seal replaces only under it, only while the file is still
the one it read. The race tests below fail on the code before the fix: the deleted pair is back.

#3740 item 12: ``discard`` waited through its own copy of :meth:`UploadStore._run_to_completion`."""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import uploads as uploads_mod
from messagefoundry.config.atomic_edit import LOCK_FILE_NAME, edit_lock
from messagefoundry.store.crypto import AesGcmCipher, cell_aad, generate_key, make_cipher
from messagefoundry.uploads import UploadStore
from tests._upload_root import upload_names

_BODY = b"MSH|^~\\&|A|B|C|D|202601010000||ADT^A01|1|P|2.5\rPID|1||1\r"
_MAX = 1 << 20


def _aes(key: str, *retired: str) -> AesGcmCipher:
    cipher = make_cipher(key, retired, write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    return cipher


def _store(root: Path, key: str, *retired: str) -> UploadStore:
    return UploadStore(root, _aes(key, *retired), max_bytes=_MAX)


def _seed(root: Path, key: str) -> str:
    meta = asyncio.run(
        _store(root, key).save(data=_BODY, filename="a.hl7", uploader="op", uploader_id="u")
    )
    return meta.file_id


def _remove_by_delete(engine: UploadStore, fid: str) -> None:
    asyncio.run(engine.delete(fid))


def _remove_by_prune(engine: UploadStore, fid: str) -> None:
    assert engine._prune_pair_sync(asyncio.run(engine.get_meta(fid)))


def _remove_by_discard(engine: UploadStore, fid: str) -> None:
    assert engine._discard_cancelled_sync(fid)


_REMOVALS = {
    "delete": _remove_by_delete,
    "prune": _remove_by_prune,
    "discard": _remove_by_discard,
}


def _during_the_reseal_of(
    monkeypatch: pytest.MonkeyPatch, fid: str, kind: str, act: Callable[[], None]
) -> None:
    """Run ``act`` once, after the re-seal has read the ``kind`` half and before it writes it."""
    real = uploads_mod._reencrypt_value
    target = cell_aad("uploaded_file", kind, fid)
    done = False

    def _reencrypt(cipher: AesGcmCipher, stored: str, aad: bytes) -> str:
        nonlocal done
        if not done and aad == target:
            done = True
            act()
        return real(cipher, stored, aad)

    monkeypatch.setattr(uploads_mod, "_reencrypt_value", _reencrypt)


@pytest.mark.parametrize("removal", sorted(_REMOVALS))
@pytest.mark.parametrize("kind", ["body", "meta"])
def test_a_pair_an_engine_removes_mid_reseal_does_not_come_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    removal: str,
    kind: str,
) -> None:
    """The engine removes the pair between the re-seal's read of one half and its write. Neither
    half may be written back, and the run must not read as complete."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fid = _seed(root, old)
    engine = _store(root, old)
    _during_the_reseal_of(monkeypatch, fid, kind, lambda: _REMOVALS[removal](engine, fid))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert upload_names(root) == [], "a removed pair was re-created"
    assert result.incomplete
    assert result.skipped == 1
    assert f"uploaded file {fid} (meta): skipped" in caplog.text, caplog.text


def test_a_file_replaced_mid_reseal_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sidecar replaced after the read keeps the replacement, and the pair is a skip."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fid = _seed(root, old)
    sidecar = root / f"{fid}.meta"
    replacement = sidecar.read_text(encoding="utf-8")

    def _replace() -> None:
        planted = root / "planted"
        planted.write_text(replacement, encoding="utf-8")
        os.replace(planted, sidecar)

    _during_the_reseal_of(monkeypatch, fid, "meta", _replace)
    result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert result.skipped == 1
    assert sidecar.read_text(encoding="utf-8") == replacement


def test_a_reseal_with_no_race_still_writes_both_halves(tmp_path: Path) -> None:
    """The control: the identity check passes for a file nobody touched."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fid = _seed(root, old)
    result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert (result.resealed, result.skipped) == (2, 0)
    assert asyncio.run(_store(root, new).read_bytes(fid)) == _BODY


def _held_elsewhere(path: Path) -> bool:
    """Whether another thread, and so another process, would find the pair lock taken now."""
    found: list[bool] = []

    def _try() -> None:
        try:
            with edit_lock(path, timeout=0):
                found.append(False)
        except TimeoutError:
            found.append(True)

    probe = threading.Thread(target=_try)
    probe.start()
    probe.join(10)
    return found == [True]


@pytest.mark.parametrize("removal", sorted(_REMOVALS))
def test_every_engine_removal_unlinks_under_the_pair_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, removal: str
) -> None:
    root = tmp_path / "uploads"
    key = generate_key()
    fid = _seed(root, key)
    engine = _store(root, key)
    seen: list[tuple[str, bool]] = []
    real_unlink = Path.unlink

    def _unlink(self: Path, missing_ok: bool = False) -> None:
        if self.parent == root.resolve() or self.parent == root:
            seen.append((self.suffix, _held_elsewhere(self)))
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", _unlink)
    _REMOVALS[removal](engine, fid)
    assert seen == [(".blob", True), (".meta", True)], seen


def test_the_reseal_replaces_under_the_pair_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    _seed(root, old)
    seen: list[bool] = []
    real_replace = os.replace

    def _replace(src: Any, dst: Any) -> None:
        seen.append(_held_elsewhere(Path(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", _replace)
    asyncio.run(_store(root, new, old).reseal_to_active())
    assert seen == [True, True], seen


# --- vault BACKLOG #3740 item 12: discard waits through _run_to_completion ----------------------


async def test_discard_waits_through_run_to_completion_held_from_the_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The removal is held while its caller still waits, so the shutdown drain sees it; a caller
    cancelled past the bound propagates, the removal goes on, and the bound is logged by file_id."""
    monkeypatch.setattr(uploads_mod, "_LEDGER_CANCEL_WAIT_SECONDS", 0.05)
    store = UploadStore(tmp_path / "uploads", make_cipher(generate_key()), max_bytes=4096)
    meta = await store.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u")
    release = threading.Event()
    real_remove = store._discard_cancelled_sync

    def _slow_remove(file_id: str) -> bool:
        assert release.wait(10)
        return real_remove(file_id)

    monkeypatch.setattr(store, "_discard_cancelled_sync", _slow_remove)
    discard = asyncio.create_task(store.discard(meta.file_id))
    await asyncio.sleep(0.05)
    assert store._stragglers, "the removal is not held while its caller waits"
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        discard.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(discard, 10)
    assert f"the removal of upload {meta.file_id} did not finish within" in caplog.text
    release.set()
    for _ in range(500):
        if not store._stragglers:
            break
        await asyncio.sleep(0.02)
    assert not store._stragglers
    assert await store.list_files() == []


def _refuse_the_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every pair lock refused, as a 0600 lock file another account created refuses it."""

    def _refused(path: Path, **_: Any) -> Any:
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(uploads_mod, "edit_lock", _refused)
    monkeypatch.setattr(uploads_mod, "_unlocked_logged", set())


def test_an_engine_that_cannot_take_the_lock_still_removes_and_says_so_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Retention and delete must not depend on a file anyone who can write the root can plant. The
    removal goes on unlocked, and one ERROR names the lock file and the likely cause."""
    root = tmp_path / "uploads"
    key = generate_key()
    first, second = _seed(root, key), _seed(root, key)
    engine = _store(root, key)
    _refuse_the_lock(monkeypatch)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.uploads"):
        assert engine._discard_cancelled_sync(first) is True
        asyncio.run(engine.delete(second))
    assert upload_names(root) == []
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1, caplog.text
    assert LOCK_FILE_NAME in errors[0].getMessage()
    assert "another account owns it" in errors[0].getMessage()


def test_a_reseal_that_cannot_take_the_lock_writes_nothing_and_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The re-seal fails closed, once, before it reads any upload."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fids = [_seed(root, old), _seed(root, old)]
    before = {n: (root / n).read_bytes() for n in upload_names(root)}
    _refuse_the_lock(monkeypatch)
    reads: list[str] = []
    real = uploads_mod._reencrypt_value

    def _reencrypt(cipher: AesGcmCipher, stored: str, aad: bytes) -> str:
        reads.append("read")
        return real(cipher, stored, aad)

    monkeypatch.setattr(uploads_mod, "_reencrypt_value", _reencrypt)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.uploads"):
        result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert result.skipped == len(fids) and result.incomplete
    assert reads == []
    assert {n: (root / n).read_bytes() for n in upload_names(root)} == before
    assert "Run rotate-key as the account the engine runs as" in caplog.text, caplog.text
