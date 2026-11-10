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
import errno
import logging
import os
import shutil
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, get_args

import pytest

from messagefoundry import uploads as uploads_mod
from messagefoundry.config.atomic_edit import LOCK_FILE_NAME, edit_lock, lock_path_for
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
    try:
        await asyncio.sleep(0.05)
        assert store._stragglers, "the removal is not held while its caller waits"
        with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
            discard.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(discard, 10)
        assert f"the removal of upload {meta.file_id} did not finish within" in caplog.text
    finally:
        # Released whatever an assertion found, or the executor thread blocks the loop teardown.
        release.set()
    for _ in range(500):
        if not store._stragglers:
            break
        await asyncio.sleep(0.02)
    assert not store._stragglers
    assert await store.list_files() == []


def _refused(path: Path, **_: Any) -> Any:
    """A pair lock refused, as a 0600 lock file another account created refuses it."""
    raise PermissionError(errno.EACCES, "Permission denied", str(path))


def _busy(path: Path, **kwargs: Any) -> Any:
    """The pair lock still held past the wait, as ``edit_lock`` reports it."""
    raise kwargs["busy_error"](f"another edit of {path} is still in progress after 2s")


def _timed_out(path: Path, **_: Any) -> Any:
    """A pair lock the OS timed out on (``ETIMEDOUT``), as a network file system can."""
    raise TimeoutError(errno.ETIMEDOUT, "Connection timed out", str(path))


def _root_gone(path: Path, **_: Any) -> Any:
    """A pair lock whose open finds the uploads root gone: the root is removed, then the open
    fails as it would."""
    lock = lock_path_for(path)
    shutil.rmtree(lock.parent)
    raise FileNotFoundError(errno.ENOENT, "No such file or directory", str(lock))


def _dangling(path: Path, **_: Any) -> Any:
    """A pair lock whose open fails ``ENOENT`` while the uploads root is there, as Windows, which
    has no ``O_NOFOLLOW``, fails it for a link planted at the lock path whose target's directory is
    missing."""
    lock = lock_path_for(path)
    assert lock.parent.is_dir()
    raise FileNotFoundError(errno.ENOENT, "No such file or directory", str(lock))


def _record_decrypts(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """The AAD of every value the re-seal decrypts to re-encrypt, in order."""
    reads: list[bytes] = []
    real = uploads_mod._reencrypt_value

    def _reencrypt(cipher: AesGcmCipher, stored: str, aad: bytes) -> str:
        reads.append(aad)
        return real(cipher, stored, aad)

    monkeypatch.setattr(uploads_mod, "_reencrypt_value", _reencrypt)
    return reads


def _refuse_the_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every pair lock refused (:func:`_refused`), with the once-per-lock ERROR record cleared."""
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
    """The re-seal fails closed: one ERROR, and no upload is decrypted or written."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fids = [_seed(root, old), _seed(root, old)]
    before = {n: (root / n).read_bytes() for n in upload_names(root)}
    _refuse_the_lock(monkeypatch)
    reads = _record_decrypts(monkeypatch)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.uploads"):
        result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert result.skipped == len(fids) and result.incomplete
    assert reads == []
    assert {n: (root / n).read_bytes() for n in upload_names(root)} == before
    assert "Run rotate-key as the account the engine runs as" in caplog.text, caplog.text


def _busy_at(
    monkeypatch: pytest.MonkeyPatch,
    *,
    names: Callable[[str], bool],
    fail: Callable[..., Any] = _busy,
) -> None:
    """The pair lock fails as ``fail`` makes it (busy by default) for the lock taken on a path whose
    name ``names`` selects; the real lock for every other path."""

    def _lock(path: Path, **kwargs: Any) -> Any:
        if names(path.name):
            return fail(path, **kwargs)
        return edit_lock(path, **kwargs)

    monkeypatch.setattr(uploads_mod, "edit_lock", _lock)
    monkeypatch.setattr(uploads_mod, "_unlocked_logged", set())


def test_a_busy_lock_is_a_warning_and_does_not_use_up_the_refusal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A lock held past the wait is contention, not a refused lock file, so the removal says so at
    WARNING and a later refusal still gets its one ERROR."""
    root = tmp_path / "uploads"
    key = generate_key()
    first, second = _seed(root, key), _seed(root, key)
    engine = _store(root, key)
    _busy_at(monkeypatch, names=lambda _name: True)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert engine._discard_cancelled_sync(first) is True
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], caplog.text
    assert "still in progress" in caplog.text
    assert "another account owns it" not in caplog.text
    assert uploads_mod._unlocked_logged == set()
    caplog.clear()
    monkeypatch.setattr(uploads_mod, "edit_lock", _refused)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.uploads"):
        assert engine._discard_cancelled_sync(second) is True
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "another account owns it" in errors[0].getMessage(), caplog.text


def test_a_busy_lock_at_a_reseal_write_is_a_skip_that_does_not_blame_the_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The pre-check takes the lock; a half's write then finds it held past the wait. That half is
    a skip, nothing is written over it, and the log says to re-run, not to change accounts."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    _seed(root, old)
    before = {n: (root / n).read_bytes() for n in upload_names(root)}
    _busy_at(monkeypatch, names=lambda name: name != LOCK_FILE_NAME)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert result.skipped == 1 and result.incomplete
    assert {n: (root / n).read_bytes() for n in upload_names(root)} == before
    assert "re-run rotate-key once whatever holds the lock releases it" in caplog.text, caplog.text
    assert "Run rotate-key as the account" not in caplog.text


def test_a_refused_lock_over_uploads_already_current_is_no_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A half already under the active key needs no write, so a lock the re-run cannot take does
    not count it as one that may still be under the prior key."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    _seed(root, old)
    store = _store(root, new, old)
    # The first pass, unrefused, puts both halves under this store's active marker.
    assert asyncio.run(store.reseal_to_active()).resealed == 2
    _refuse_the_lock(monkeypatch)
    result = asyncio.run(store.reseal_to_active())
    assert result.skipped == 0 and not result.incomplete


@pytest.mark.parametrize(
    ("lock", "cause"),
    [
        (
            _busy,
            "the uploads pair lock was still held when the wait ran out; re-run rotate-key once",
        ),
        (_timed_out, "the file system timed out taking the uploads pair lock"),
        (_refused, "the uploads pair lock could not be taken"),
    ],
    ids=["busy", "timeout", "refused"],
)
def test_a_first_lock_check_that_fails_stops_the_reseal_before_any_decrypt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    lock: Callable[..., Any],
    cause: str,
) -> None:
    """The lock fails at the pass's first check and at every later try. The pass decrypts nothing,
    takes the lock no second time, writes nothing, and fails, and each skip names the cause. Only a
    refusal gives the account advice, at ERROR."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fids = [_seed(root, old), _seed(root, old)]
    before = {n: (root / n).read_bytes() for n in upload_names(root)}
    tries: list[str] = []

    def _lock(path: Path, **kwargs: Any) -> Any:
        tries.append(path.name)
        return lock(path, **kwargs)

    monkeypatch.setattr(uploads_mod, "edit_lock", _lock)
    monkeypatch.setattr(uploads_mod, "_unlocked_logged", set())
    reads = _record_decrypts(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert reads == []
    assert tries == [LOCK_FILE_NAME]
    assert result.skipped == len(fids) and result.incomplete and result.resealed == 0
    assert {n: (root / n).read_bytes() for n in upload_names(root)} == before
    assert f"uploaded file {fids[0]} (body): skipped, nothing is written: {cause}" in caplog.text
    refused = lock is _refused
    assert ("Run rotate-key as the account" in caplog.text) is refused, caplog.text
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == int(refused), caplog.text


def test_a_root_gone_at_the_first_lock_check_is_root_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The root went after the listing, before the first lock check: the pass reports the missing
    root (BACKLOG #4940) and reads no file, rather than calling every body lost."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    _seed(root, old)
    monkeypatch.setattr(uploads_mod, "edit_lock", _root_gone)
    reads = _record_decrypts(monkeypatch)
    result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert not root.exists()
    assert result.root_missing and result.incomplete
    assert (result.skipped, result.body_lost, reads) == (0, 0, [])


def _root_gone_answers(monkeypatch: pytest.MonkeyPatch, *answers: bool) -> list[bool]:
    """``_root_gone`` answers ``answers`` in turn, then the last one, as a root that went or came
    back between two looks would; returns the answers it gave."""
    given: list[bool] = []

    def _gone(exc: OSError, root: Path) -> bool:
        given.append(answers[min(len(given), len(answers) - 1)])
        return given[-1]

    monkeypatch.setattr(uploads_mod, "_root_gone", _gone)
    return given


@pytest.mark.parametrize("first", [True, False], ids=["logged-gone", "logged-refused"])
def test_the_first_check_acts_on_the_failure_the_lock_logged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    first: bool,
) -> None:
    """``ENOENT`` at the first check is classified once. A root that comes back (or goes) after
    that look does not turn the logged "directory is gone" into a refusal, or the logged refusal
    into a missing root."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fids = [_seed(root, old), _seed(root, old)]
    monkeypatch.setattr(uploads_mod, "edit_lock", _dangling)
    given = _root_gone_answers(monkeypatch, first, not first)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert given == [first], given
    assert ("its directory is gone" in caplog.text) is first, caplog.text
    assert ("Run rotate-key as the account" in caplog.text) is not first, caplog.text
    assert result.root_missing is first
    assert result.skipped == (0 if first else len(fids)) and result.incomplete


@pytest.mark.parametrize("first", [True, False], ids=["logged-gone", "logged-refused"])
def test_a_half_write_acts_on_the_failure_the_lock_logged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    first: bool,
) -> None:
    """The first check takes the lock; a half's write gets ``ENOENT`` at the lock's open. The
    half's warning gives the cause ``_pair_lock`` logged, whatever a second look would say."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fid = _seed(root, old)
    _busy_at(monkeypatch, names=lambda name: name != LOCK_FILE_NAME, fail=_dangling)
    given = _root_gone_answers(monkeypatch, first, not first)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert result.skipped == 1 and result.incomplete
    assert given[0] is first
    half = [
        r.getMessage() for r in caplog.records if f"uploaded file {fid} (body)" in r.getMessage()
    ]
    assert len(half) == 1, caplog.text
    assert half[0].endswith("the uploads directory is gone") is first, half


def test_a_lock_path_missing_under_a_root_still_there_is_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """``ENOENT`` at the lock's open while the root is there is no missing root: something planted
    at the lock path, such as a link whose target's directory is missing, keeps it from being taken. The engine
    removal logs the refusal at ERROR with the advice to remove it; the re-seal skips every half
    that needs a write and does not report the root missing."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fids = [_seed(root, old), _seed(root, old)]
    before = {n: (root / n).read_bytes() for n in upload_names(root)}
    monkeypatch.setattr(uploads_mod, "edit_lock", _dangling)
    monkeypatch.setattr(uploads_mod, "_unlocked_logged", set())
    reads = _record_decrypts(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert not result.root_missing
    assert result.skipped == len(fids) and result.incomplete and result.resealed == 0
    assert reads == []
    assert {n: (root / n).read_bytes() for n in upload_names(root)} == before
    assert (
        f"uploaded file {fids[0]} (body): skipped, nothing is written: the uploads pair lock "
        "could not be taken"
    ) in caplog.text, caplog.text
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert _store(root, old)._discard_cancelled_sync(fids[0]) is True
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1, caplog.text
    assert "if it is not a regular file, remove it" in errors[0].getMessage()
    assert LOCK_FILE_NAME in errors[0].getMessage()


def test_a_refusal_that_comes_back_after_the_lock_was_taken_is_an_error_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """While a refusal lasts it is one ERROR, then DEBUG. Once the lock is taken again, a refusal
    that comes back is a new ERROR, not hidden by the first."""
    root = tmp_path / "uploads"
    key = generate_key()
    fids = [_seed(root, key) for _ in range(4)]
    engine = _store(root, key)
    _refuse_the_lock(monkeypatch)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.uploads"):
        assert engine._discard_cancelled_sync(fids[0]) is True
        assert engine._discard_cancelled_sync(fids[1]) is True
        assert len([r for r in caplog.records if r.levelno == logging.ERROR]) == 1, caplog.text
        monkeypatch.setattr(uploads_mod, "edit_lock", edit_lock)
        assert engine._discard_cancelled_sync(fids[2]) is True
        assert uploads_mod._unlocked_logged == set()
        monkeypatch.setattr(uploads_mod, "edit_lock", _refused)
        assert engine._discard_cancelled_sync(fids[3]) is True
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 2, caplog.text
    assert all("another account owns it" in r.getMessage() for r in errors)
    assert upload_names(root) == []


def test_an_os_timeout_on_an_engine_removal_is_a_warning_not_the_account_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An OS timeout is neither another account's lock file nor a busy lock: the removal goes on,
    one WARNING names the timeout, and the refusal's ERROR is not used up."""
    root = tmp_path / "uploads"
    key = generate_key()
    fid = _seed(root, key)
    engine = _store(root, key)
    monkeypatch.setattr(uploads_mod, "edit_lock", _timed_out)
    monkeypatch.setattr(uploads_mod, "_unlocked_logged", set())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert engine._discard_cancelled_sync(fid) is True
    assert upload_names(root) == []
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], caplog.text
    assert "the file system timed out taking it" in caplog.text, caplog.text
    assert "another account owns it" not in caplog.text
    assert uploads_mod._unlocked_logged == set()


@pytest.mark.parametrize(
    ("fail", "gone"), [(_root_gone, True), (_dangling, False)], ids=["root-gone", "root-there"]
)
def test_enoent_at_a_half_write_names_the_directory_only_when_it_is_gone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fail: Callable[..., Any],
    gone: bool,
) -> None:
    """The first check takes the lock; a half's write then finds ``ENOENT`` at the lock's open.
    That half is a skip. Its warning says the uploads directory is gone only when the root is
    really gone, and does not name the lock file then; under a root still there it gives the
    error."""
    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fid = _seed(root, old)
    _busy_at(monkeypatch, names=lambda name: name != LOCK_FILE_NAME, fail=fail)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = asyncio.run(_store(root, new, old).reseal_to_active())
    assert root.exists() is not gone
    assert result.skipped == 1 and result.incomplete and not result.root_missing
    half = [
        r.getMessage() for r in caplog.records if f"uploaded file {fid} (body)" in r.getMessage()
    ]
    written = f"uploaded file {fid} (body): skipped, could not be written: "
    if gone:
        assert half == [written + "the uploads directory is gone"], caplog.text
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR], caplog.text
    else:
        assert len(half) == 1 and half[0].startswith(written), caplog.text
        assert "[Errno 2]" in half[0] and "is gone" not in half[0], half


def test_pair_lock_failures_are_classified_apart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``edit_lock`` raises ``busy_error`` for a planted link too, chained from the ELOOP; that one
    is a refusal. An OS ``ETIMEDOUT`` is a timeout, neither contention nor a refusal. ``ENOENT`` is
    a gone root only while the root is no directory. Only an errno in ``atomic_edit._REFUSED``, a
    planted file that is not regular, or ``ENOENT`` under a root still there is a refusal, which
    gets the account and remove-it advice."""

    def failure(exc: OSError, root: Path = tmp_path) -> str:
        return uploads_mod._pair_lock_failure(exc, root)

    try:
        try:
            raise OSError(errno.ELOOP, "Too many levels of symbolic links")
        except OSError as loop:
            raise uploads_mod._PairLockBusy("x is a link") from loop
    except OSError as exc:
        assert failure(exc) == "refused"
    assert failure(uploads_mod._PairLockBusy("still in progress")) == "busy"
    assert failure(TimeoutError(errno.ETIMEDOUT, "Connection timed out")) == "timeout"
    missing = FileNotFoundError(errno.ENOENT, "gone")
    assert failure(missing, tmp_path / "absent") == "gone"
    assert failure(missing) == "refused"
    for code in (errno.EACCES, errno.EPERM, errno.EROFS, errno.EISDIR, errno.ENXIO):
        assert failure(OSError(code, os.strerror(code))) == "refused", code
    for code in (errno.EIO, errno.EINVAL, errno.ESTALE, errno.ENOTDIR):
        assert failure(OSError(code, os.strerror(code))) == "failed", code
    # The socket and planted-link errnos of macOS and the BSDs are refusals only there.
    linux = uploads_mod._not_a_file_errnos("linux")
    assert linux == uploads_mod._not_a_file_errnos("win32") == {errno.EISDIR, errno.ENXIO}
    darwin = uploads_mod._not_a_file_errnos("darwin")
    assert errno.EOPNOTSUPP in darwin and errno.EMLINK not in darwin
    eftype = getattr(errno, "EFTYPE", None)
    assert eftype is None or eftype in darwin
    freebsd = uploads_mod._not_a_file_errnos("freebsd14")
    assert {errno.EOPNOTSUPP, errno.EMLINK} <= freebsd
    bsd_only = sorted(freebsd - linux)
    monkeypatch.setattr(uploads_mod, "_NOT_A_FILE", freebsd)
    for code in bsd_only:
        assert failure(OSError(code, os.strerror(code))) == "refused", code
    monkeypatch.setattr(uploads_mod, "_NOT_A_FILE", linux)
    for code in bsd_only:
        assert failure(OSError(code, os.strerror(code))) == "failed", code


@pytest.mark.parametrize(
    "code", [errno.EIO, errno.EINVAL, errno.ESTALE], ids=["EIO", "EINVAL", "ESTALE"]
)
def test_an_os_error_that_is_no_refusal_is_failed_without_the_account_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, code: int
) -> None:
    """An error outside ``atomic_edit._REFUSED`` (an NFS soft mount's ``EIO``, Windows'
    ``ERROR_SEM_TIMEOUT`` as ``EINVAL``, ``ESTALE``) is no account's lock file. The removal goes on,
    a WARNING names the error each time, the refusal's ERROR is not used up, and the re-seal skips
    with the neutral cause and no account advice."""

    def _fails(path: Path, **_: Any) -> Any:
        raise OSError(code, os.strerror(code), str(path))

    root = tmp_path / "uploads"
    old, new = generate_key(), generate_key()
    fid = _seed(root, old)
    monkeypatch.setattr(uploads_mod, "edit_lock", _fails)
    monkeypatch.setattr(uploads_mod, "_unlocked_logged", set())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = asyncio.run(_store(root, new, old).reseal_to_active())
        assert _store(root, old)._discard_cancelled_sync(fid) is True
        removal = "This removal goes on without it"
        assert caplog.text.count(removal) == 1, caplog.text
        second = _seed(root, old)
        assert _store(root, old)._discard_cancelled_sync(second) is True
        assert caplog.text.count(removal) == 2, caplog.text
    assert result.skipped == 1 and result.incomplete and result.resealed == 0
    assert upload_names(root) == []
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], caplog.text
    assert (
        f"uploaded file {fid} (body): skipped, nothing is written: the file system failed taking "
        "the uploads pair lock"
    ) in caplog.text, caplog.text
    assert f"OSError: [Errno {code}]" in caplog.text, caplog.text
    assert "another account" not in caplog.text and "Run rotate-key as" not in caplog.text
    assert uploads_mod._unlocked_logged == set()


def test_every_pair_lock_failure_has_a_reseal_cause() -> None:
    """``blocked`` takes any failure kind, so the cause lookup cannot raise ``KeyError``."""
    kinds = set(get_args(uploads_mod._PairLockFailure.__value__))
    assert set(uploads_mod._RESEAL_BLOCKED) == kinds
