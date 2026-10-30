# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3737: what the upload reseal does with a file the engine did not write.

The pass opened whatever sat at a body or sidecar path. A FIFO blocked it for good, a symlink out of
the root failed the path guard on every run, and a huge file was read whole, where a ``MemoryError``
aborts the pass. Its skip log kept only the cause's class, which is the same for a missing key and a
damaged file. Each test fails on the code before #3737."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store.crypto import AesGcmCipher, generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from messagefoundry.uploads import ResealResult, UploadStore

_BODY = b"MSH|^~\\&|A|B|C|D|202601010000||ADT^A01|1|P|2.5\rPID|1||1\r"
_MAX = 1 << 20


def _aes(key: str, *retired: str) -> AesGcmCipher:
    cipher = make_cipher(key, retired, write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    return cipher


def _save(root: Path, cipher: AesGcmCipher) -> str:
    meta = asyncio.run(
        UploadStore(root, cipher, max_bytes=_MAX).save(
            data=_BODY, filename="a.hl7", uploader="op", uploader_id="u"
        )
    )
    return meta.file_id


def _reseal(root: Path, cipher: AesGcmCipher) -> ResealResult:
    return asyncio.run(UploadStore(root, cipher, max_bytes=_MAX).reseal_to_active())


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError as exc:  # Windows without the privilege
        pytest.skip(f"cannot make a symlink here: {exc}")


@pytest.fixture
def keys() -> tuple[str, str]:
    return generate_key(), generate_key()


def test_a_directory_at_a_body_path_is_reported_and_not_a_skip(
    tmp_path: Path, keys: tuple[str, str]
) -> None:
    """Any non-regular file, on every platform. The sidecar is still re-sealed, so nothing of the
    upload the pass can see stays under the prior key."""
    key_a, key_b = keys
    fid = _save(tmp_path, _aes(key_a))
    blob = tmp_path / f"{fid}.blob"
    blob.unlink()
    blob.mkdir()
    rotated = _aes(key_b, key_a)  # one instance: a cipher's marker carries its own store salt
    result = _reseal(tmp_path, rotated)
    assert (result.skipped, result.not_regular, result.body_lost) == (0, 1, 0)
    assert result.resealed == 1
    stored = (tmp_path / f"{fid}.meta").read_text(encoding="utf-8")
    assert stored.startswith(rotated.active_marker_prefix)
    # A second run reads the sidecar as current and reports the same body again.
    again = _reseal(tmp_path, rotated)
    assert (again.resealed, again.skipped, again.not_regular) == (0, 0, 1)


def test_a_directory_at_a_sidecar_path_leaves_the_body_sealed_and_is_not_a_skip(
    tmp_path: Path, keys: tuple[str, str]
) -> None:
    key_a, key_b = keys
    fid = _save(tmp_path, _aes(key_a))
    sidecar = tmp_path / f"{fid}.meta"
    sidecar.unlink()
    sidecar.mkdir()
    rotated = _aes(key_b, key_a)
    result = _reseal(tmp_path, rotated)
    assert (result.skipped, result.not_regular, result.resealed) == (0, 1, 1)
    stored = (tmp_path / f"{fid}.blob").read_text(encoding="utf-8")
    assert stored.startswith(rotated.active_marker_prefix)


def test_a_plaintext_sidecar_over_a_non_regular_body_stays_unsealed(
    tmp_path: Path, keys: tuple[str, str]
) -> None:
    """Sealing it would list an upload with no usable body. It is not ``unsealable``: that count
    promises the retention prune, which cannot read a body like this one."""
    key_a, key_b = keys
    fid = _save(tmp_path, _aes(key_a))
    sidecar = tmp_path / f"{fid}.meta"
    plaintext = '{"file_id": "' + fid + '", "uploader_id": "u"}'
    sidecar.write_text(plaintext, encoding="utf-8")
    blob = tmp_path / f"{fid}.blob"
    blob.unlink()
    blob.mkdir()
    result = _reseal(tmp_path, _aes(key_b, key_a))
    assert (result.skipped, result.not_regular, result.unsealable) == (0, 1, 0)
    assert sidecar.read_text(encoding="utf-8") == plaintext


def test_a_skip_on_the_other_half_outranks_a_non_regular_file(
    tmp_path: Path, keys: tuple[str, str]
) -> None:
    """The pair may still hold something under the prior key, so the run must fail."""
    key_a, key_b = keys
    fid = _save(tmp_path, _aes(generate_key()))  # a body no run has the key for
    sidecar = tmp_path / f"{fid}.meta"
    sidecar.unlink()
    sidecar.mkdir()
    result = _reseal(tmp_path, _aes(key_b, key_a))
    assert (result.skipped, result.not_regular) == (1, 0)


def test_a_symlink_out_of_the_root_is_neither_followed_nor_a_skip(
    tmp_path: Path, keys: tuple[str, str]
) -> None:
    """On the old code it failed the path guard, so every run exited 1. The target stays as it was."""
    key_a, key_b = keys
    root = tmp_path / "uploads"
    fid = _save(root, _aes(key_a))
    outside = tmp_path / "outside.blob"
    blob = root / f"{fid}.blob"
    outside.write_bytes(blob.read_bytes())
    before = outside.read_bytes()
    blob.unlink()
    _symlink(blob, outside)
    result = _reseal(root, _aes(key_b, key_a))
    assert (result.skipped, result.not_regular, result.resealed) == (0, 1, 1)
    assert outside.read_bytes() == before
    assert blob.is_symlink()


def test_a_dangling_symlink_is_not_taken_for_a_lost_body(
    tmp_path: Path, keys: tuple[str, str]
) -> None:
    """``stat`` follows it to nothing and would call the body missing, and the note for a missing
    body promises the prune."""
    key_a, key_b = keys
    fid = _save(tmp_path, _aes(key_a))
    blob = tmp_path / f"{fid}.blob"
    blob.unlink()
    _symlink(blob, tmp_path / "nowhere")
    result = _reseal(tmp_path, _aes(key_b, key_a))
    assert (result.not_regular, result.body_lost) == (1, 0)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
@pytest.mark.timeout(60)
def test_a_fifo_at_a_body_path_does_not_block_the_pass(
    tmp_path: Path, keys: tuple[str, str]
) -> None:
    key_a, key_b = keys
    fid = _save(tmp_path, _aes(key_a))
    blob = tmp_path / f"{fid}.blob"
    blob.unlink()
    os.mkfifo(blob)
    result = _reseal(tmp_path, _aes(key_b, key_a))
    assert (result.skipped, result.not_regular) == (0, 1)


def test_a_file_too_large_for_an_upload_is_a_skip_and_is_never_read_whole(
    tmp_path: Path, keys: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A skip and not a lost body: it may be a real one from before ``max_upload_bytes`` came down.
    The spy stands in for the ``MemoryError`` a real read of such a file would raise."""
    key_a, key_b = keys
    fid = _save(tmp_path, _aes(key_a))
    blob = tmp_path / f"{fid}.blob"
    with blob.open("ab") as handle:
        handle.truncate(2 * _MAX + 4097)
    real = Path.read_text

    def refuse_the_big_one(self: Path, *args: object, **kwargs: object) -> str:
        if self == blob:
            raise MemoryError
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", refuse_the_big_one)
    result = _reseal(tmp_path, _aes(key_b, key_a))
    assert (result.skipped, result.body_lost) == (1, 0)


def test_a_large_file_already_under_the_active_key_is_not_a_skip(
    tmp_path: Path, keys: tuple[str, str]
) -> None:
    """The marker is read before the size, so a lowered limit cannot fail a run over a file that
    needs nothing done. Pinned because the size test is the easy thing to move up."""
    cipher = _aes(keys[0])
    fid = _save(tmp_path, cipher)
    with (tmp_path / f"{fid}.blob").open("ab") as handle:
        handle.write(b"a" * (2 * _MAX + 4097))
    result = _reseal(tmp_path, cipher)
    assert (result.resealed, result.skipped) == (0, 0)


def test_a_body_that_is_not_utf8_is_decoded_once(
    tmp_path: Path, keys: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failed read already decided it. The old code asked ``_lost_body_size``, which read and
    decoded the whole file a second time."""
    key_a, key_b = keys
    fid = _save(tmp_path, _aes(key_a))
    (tmp_path / f"{fid}.blob").write_bytes(b"\xff\xfe not text")

    def fail(self: UploadStore, blob: Path) -> int | None:
        raise AssertionError("the body's first read already decided this")

    monkeypatch.setattr(UploadStore, "_lost_body_size", fail)
    result = _reseal(tmp_path, _aes(key_b, key_a))
    assert (result.body_lost, result.skipped) == (1, 0)


def test_the_skip_log_tells_a_missing_key_from_a_damaged_file(
    tmp_path: Path, keys: tuple[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    """The two used to log one class name. A key to supply and a file to restore are different
    jobs, and the id of the missing key is what the operator goes looking for."""
    key_a, key_b = keys
    stranger = _aes(generate_key())
    fid_foreign = _save(tmp_path, stranger)
    fid_damaged = _save(tmp_path, _aes(key_a))
    damaged = tmp_path / f"{fid_damaged}.blob"
    text = damaged.read_text(encoding="utf-8")
    damaged.write_text(text[:-8] + ("A" if text[-8] != "A" else "B") + text[-7:], encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert _reseal(tmp_path, _aes(key_b, key_a)).skipped == 2

    foreign = [r.getMessage() for r in caplog.records if fid_foreign in r.getMessage()]
    assert any(f"key {stranger.active_key_id} is not configured" in m for m in foreign), foreign
    held = [r.getMessage() for r in caplog.records if fid_damaged in r.getMessage()]
    assert any(
        f"key {_aes(key_a).active_key_id} is configured and did not open it" in m for m in held
    ), held


def test_the_skip_log_carries_no_text_from_a_malformed_marker(
    tmp_path: Path, keys: tuple[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    """A malformed marker's key id is cut from the stored text, so the id must pass a shape test
    before it is logged. What it would print here is a planted line from a file."""
    key_a, key_b = keys
    fid = _save(tmp_path, _aes(key_a))
    planted = "PLANTED-PATIENT-NAME"
    (tmp_path / f"{fid}.meta").write_text(f"mfenc:v1:{planted}:abcd", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert _reseal(tmp_path, _aes(key_b, key_a)).skipped == 1
    assert planted not in caplog.text
    assert "its marker names no key" in caplog.text


@pytest.mark.parametrize(
    "stored",
    ["mfenc:v1:" + "a" * 15 + ":x", "mfenc:v1:" + "A" * 16 + ":x", "plain", "", "mfenc:v9:a:b"],
)
def test_named_key_id_passes_nothing_but_a_whole_id(stored: str) -> None:
    assert _aes(generate_key()).named_key_id(stored) is None


def test_named_key_id_reads_the_id_of_a_real_value() -> None:
    cipher = _aes(generate_key())
    assert cipher.named_key_id(cipher.encrypt("x", aad=b"cell")) == cipher.active_key_id


def test_the_command_reports_a_non_regular_file_and_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Not a skip, so the run is whole: OK, exit 0, a note that says what to do."""
    monkeypatch.chdir(tmp_path)
    db, uploads = tmp_path / "rot.db", tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()

    async def seed() -> str:
        store = await MessageStore.open(db, cipher=make_cipher(key_a))
        try:
            meta = await UploadStore(uploads, store.cipher(), max_bytes=_MAX).save(
                data=_BODY, filename="a.hl7", uploader="op", uploader_id="u"
            )
            return meta.file_id
        finally:
            await store.close()

    fid = asyncio.run(seed())
    blob = uploads / f"{fid}.blob"
    blob.unlink()
    blob.mkdir()
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key_b)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED", key_a)
    monkeypatch.setenv("MEFOR_STORE_UPLOADS_DIR", str(uploads))
    assert main(["rotate-key", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "OK:" in out and "PARTIAL:" not in out
    assert "note: 1 uploaded file(s) have a body or sidecar that is a symlink" in out
    assert "that file was not rotated" in out
