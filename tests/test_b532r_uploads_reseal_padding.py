# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``rotate-key`` over a sidecar every reader refuses before decrypting, and the startup count over
the same kinds (BACKLOG #5387). Synthetic data only.

A sidecar sealed under a PRIOR key and padded past 128 KiB was classed damaged, so the rotation
completed and the prior key read as safe to retire, though trimming the padding recovers the value
with that key. Marker scans of the refused bytes were tried next and each was defeated, by at least
a cut at the read bound, stripped padding and a UTF-16 re-save. So the rule is fail-safe: a
sidecar refused before decrypting is a skip, whatever it holds, and only one that provably holds
nothing, read in full within the cap, is damaged. The startup count agrees with ``rotate-key``
over every one of these kinds."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO

import pytest

import messagefoundry.uploads as uploads
from messagefoundry.store.crypto import AesGcmCipher, generate_key, make_cipher
from messagefoundry.uploads import ResealResult, UploadStore

_BODY = b"synthetic diagnostic line\n"
_LIMIT = uploads._SIDECAR_LIMIT  # noqa: SLF001 - the test plants a file at the seam
_OVER = _LIMIT + 1


def _aes(key: str, *retired: str) -> AesGcmCipher:
    cipher = make_cipher(key, retired, write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    return cipher


def _save(root: Path, key: str | AesGcmCipher | None) -> str:
    cipher = _aes(key) if isinstance(key, str) else key if key is not None else make_cipher(None)
    store = UploadStore(root, cipher, max_bytes=4096)
    meta = asyncio.run(store.save(data=_BODY, filename="a.txt", uploader="op", uploader_id="u-op"))
    return meta.file_id


def _reseal(root: Path, cipher: AesGcmCipher) -> ResealResult:
    return asyncio.run(UploadStore(root, cipher, max_bytes=4096).reseal_to_active())


def _is_refused_skip(result: ResealResult) -> bool:
    return (result.skipped, result.refused_sidecars, result.damaged) == (1, 1, 0) and (
        result.incomplete
    )


def _padded_past_the_cap(sealed: bytes, where: str) -> bytes:
    # Sized in bytes, so the file is over the cap whatever the sealed value's length.
    pad = b" " * (_OVER - len(sealed))
    return sealed + pad if where == "trailing" else pad + sealed


# --- a refused sidecar is a skip, whatever it holds ----------------------------------------------


@pytest.mark.parametrize("where", ["trailing", "leading"])
def test_a_prior_key_sidecar_padded_past_the_cap_is_a_skip(tmp_path: Path, where: str) -> None:
    """Fails at 18d2789dd0: it was ``damaged``, the run completed, and the prior key read as safe
    to retire. Trimming the padding and re-running then seals it under the new key."""
    key_a, key_b = generate_key(), generate_key()
    fid = _save(tmp_path, key_a)
    sidecar = tmp_path / f"{fid}.meta"
    sealed = sidecar.read_bytes()
    planted = _padded_past_the_cap(sealed, where)
    sidecar.write_bytes(planted)
    rotated = _aes(key_b, key_a)

    result = _reseal(tmp_path, rotated)
    assert _is_refused_skip(result)
    assert sidecar.read_bytes() == planted  # left as it is

    sidecar.write_bytes(sealed)
    again = _reseal(tmp_path, rotated)
    assert (again.skipped, again.damaged) == (0, 0)
    assert not again.incomplete
    assert sidecar.read_text(encoding="utf-8").startswith(rotated.active_marker_prefix)


@pytest.mark.parametrize("codec", ["utf-16", "utf-16-le", "utf-16-be"])
def test_a_utf16_resave_of_a_prior_key_value_is_a_skip(tmp_path: Path, codec: str) -> None:
    """An editor that re-saves the value as UTF-16 hides its marker from any byte scan."""
    key_a, key_b = generate_key(), generate_key()
    fid = _save(tmp_path, key_a)
    sidecar = tmp_path / f"{fid}.meta"
    text = sidecar.read_text(encoding="utf-8")
    # With no byte-order mark, ASCII in UTF-16 is still valid UTF-8, so the BOM-less forms are
    # given one; a BOM-less re-save reads as plaintext, the pre-existing stray-prefix case.
    bom = {"utf-16": "", "utf-16-le": "\ufeff", "utf-16-be": "\ufeff"}[codec]
    planted = (bom + text).encode(codec)
    sidecar.write_bytes(planted)
    result = _reseal(tmp_path, _aes(key_b, key_a))
    assert _is_refused_skip(result)
    assert sidecar.read_bytes() == planted


def test_an_active_key_sidecar_padded_past_the_cap_is_a_skip(tmp_path: Path) -> None:
    """Replaces a damaged-outcome test that was about one percent flaky. Under the active key a
    trim recovers nothing the prior key holds, but the pass does not read inside a refused
    sidecar to tell, so it is a skip too."""
    cipher = _aes(generate_key())  # one instance: a cipher's marker carries its own store salt
    fid = _save(tmp_path, cipher)
    sidecar = tmp_path / f"{fid}.meta"
    sidecar.write_bytes(_padded_past_the_cap(sidecar.read_bytes(), "trailing"))
    assert _is_refused_skip(_reseal(tmp_path, cipher))


@pytest.mark.parametrize("extra", [1, 4, 4096], ids=["one-over", "four-over", "page-over"])
def test_an_over_cap_sidecar_whose_head_is_only_padding_is_a_skip(
    tmp_path: Path, extra: int
) -> None:
    """The pass reads no more than the cap, so it cannot see whether a value follows."""
    cipher = _aes(generate_key())
    fid = _save(tmp_path, cipher)
    (tmp_path / f"{fid}.meta").write_bytes(b" " * (_LIMIT + extra))
    assert _is_refused_skip(_reseal(tmp_path, cipher))


@pytest.mark.parametrize(
    "planted",
    [b"\xff", b"\xff\xfe{}", b"\xa0" + b"x" * 64, b"\xc3"],
    ids=["ff", "utf16-bom", "a0", "cut-sequence"],
)
@pytest.mark.parametrize("prior", [True, False], ids=["prior-key", "active-key"])
@pytest.mark.parametrize("at", ["before", "after"])
def test_a_sidecar_that_is_not_utf8_is_a_skip(
    tmp_path: Path, planted: bytes, prior: bool, at: str
) -> None:
    """Appended after an active-key value, the marker test must not take it for current: every
    reader refuses it before decrypting, so it is a skip too (review round 1)."""
    key_a, key_b = generate_key(), generate_key()
    saved = _aes(key_a)  # one instance: a cipher's marker carries its own store salt
    fid = _save(tmp_path, saved)
    sidecar = tmp_path / f"{fid}.meta"
    sealed = sidecar.read_bytes()
    if not prior:
        assert sealed.startswith(saved.active_marker_prefix.encode("ascii"))
    sidecar.write_bytes(planted + sealed if at == "before" else sealed + planted)
    assert _is_refused_skip(_reseal(tmp_path, _aes(key_b, key_a) if prior else saved))


def test_a_plaintext_sidecar_padded_past_the_cap_is_a_skip(tmp_path: Path) -> None:
    """Even one under no key: the pass does not read inside it to tell."""
    fid = _save(tmp_path, None)
    sidecar = tmp_path / f"{fid}.meta"
    sidecar.write_bytes(_padded_past_the_cap(sidecar.read_bytes(), "trailing"))
    assert _is_refused_skip(_reseal(tmp_path, _aes(generate_key())))


def test_a_too_long_plaintext_sidecar_holding_a_prior_key_value_is_a_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_a, key_b = generate_key(), generate_key()
    fid = _save(tmp_path, key_a)
    sidecar = tmp_path / f"{fid}.meta"
    sealed = sidecar.read_text(encoding="utf-8")
    sidecar.write_text("x" + sealed, encoding="utf-8")
    monkeypatch.setattr(uploads, "_PLAIN_SIDECAR_LIMIT", len(sealed) - 1)
    assert _is_refused_skip(_reseal(tmp_path, _aes(key_b, key_a)))


@pytest.mark.parametrize("lost", [True, False], ids=["lost-body", "body"])
def test_a_too_long_plaintext_sidecar_is_a_skip_over_any_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lost: bool
) -> None:
    """Over a lost body it was the never-sealable kind, reported apart; it is refused before any
    decrypt all the same, so it is a skip there too."""
    fid = _save(tmp_path, None)
    sidecar = tmp_path / f"{fid}.meta"
    monkeypatch.setattr(uploads, "_PLAIN_SIDECAR_LIMIT", len(sidecar.read_bytes()) - 1)
    if lost:
        (tmp_path / f"{fid}.blob").unlink()
    result = _reseal(tmp_path, _aes(generate_key()))
    assert _is_refused_skip(result)
    assert result.unsealable == 0


def test_the_reseal_reads_nothing_of_a_sidecar_its_fstat_puts_over_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """However large the file, the pass refuses it on its size alone and reads none of it. The
    bounded read of one that grew after its fstat is pinned in test_b532r_uploads_refusals."""
    key_a, key_b = generate_key(), generate_key()
    fid = _save(tmp_path, key_a)
    sidecar = tmp_path / f"{fid}.meta"
    sidecar.write_bytes(b"x" * (4 * _OVER) + sidecar.read_bytes())
    real = uploads._open_plain  # noqa: SLF001 - the spy wraps the seam the pass reads through
    taken: list[int] = []

    class _Counted:
        def __init__(self, inner: BinaryIO) -> None:
            self._inner = inner

        def read(self, size: int = -1) -> bytes:
            data = self._inner.read(size)
            taken.append(len(data))
            return data

        def __enter__(self) -> _Counted:
            return self

        def __exit__(self, *exc: object) -> None:
            self._inner.close()

    def spy(path: Path) -> tuple[Any, os.stat_result]:
        handle, info = real(path)
        return (_Counted(handle), info) if path == sidecar else (handle, info)

    monkeypatch.setattr(uploads, "_open_plain", spy)
    result = _reseal(tmp_path, _aes(key_b, key_a))
    assert taken == []
    assert _is_refused_skip(result)


# --- the one damaged kind: a sidecar that provably holds nothing ---------------------------------


@pytest.mark.parametrize(
    "planted",
    [b"", b"  \n", b"\t\r\n ", b"\xef\xbb\xbf", b"\xef\xbb\xbf \n", b" " * _LIMIT],
    ids=["empty", "spaces", "whitespace", "bom", "bom-and-space", "padding-to-the-cap"],
)
@pytest.mark.parametrize("prior", [True, False], ids=["prior-key", "active-key"])
def test_a_blank_sidecar_within_the_cap_is_damaged(
    tmp_path: Path, planted: bytes, prior: bool
) -> None:
    """Read in full within the cap, it holds nothing under any key, so retiring the prior key
    loses nothing and the run completes."""
    key_a, key_b = generate_key(), generate_key()
    saved = _aes(key_a)  # one instance, as above
    fid = _save(tmp_path, saved)
    sidecar = tmp_path / f"{fid}.meta"
    sidecar.write_bytes(planted)
    result = _reseal(tmp_path, _aes(key_b, key_a) if prior else saved)
    assert (result.skipped, result.refused_sidecars, result.damaged) == (0, 0, 1)
    assert not result.incomplete
    assert sidecar.read_bytes() == planted


# --- the startup count and rotate-key agree over every kind --------------------------------------


def _oversized(sidecar: Path) -> None:
    sidecar.write_bytes(_padded_past_the_cap(sidecar.read_bytes(), "trailing"))


def _padding_past_the_cap(sidecar: Path) -> None:
    sidecar.write_bytes(b" " * (_OVER + 8))


def _too_long(sidecar: Path) -> None:
    # Past the plaintext seal bound and under the cap, with the bound lowered below the file.
    sidecar.write_bytes(sidecar.read_bytes() + b" x" * 8)


def _blank(sidecar: Path) -> None:
    sidecar.write_bytes(b"  \n")


def _empty(sidecar: Path) -> None:
    sidecar.write_bytes(b"")


def _not_utf8(sidecar: Path) -> None:
    sidecar.write_bytes(b"\xff\xfe" + sidecar.read_bytes())


def _utf16(sidecar: Path) -> None:
    sidecar.write_bytes(sidecar.read_text(encoding="utf-8").encode("utf-16"))


_KINDS: list[Callable[[Path], None]] = [
    _oversized,
    _padding_past_the_cap,
    _too_long,
    _blank,
    _empty,
    _not_utf8,
    _utf16,
]


# The plaintext seal bound holds only a plaintext sidecar, so the too-long kind is plaintext only.
_PAIRS = [
    pytest.param(
        damage, sealed, id=f"{damage.__name__.strip('_')}-{'sealed' if sealed else 'plain'}"
    )
    for damage in _KINDS
    for sealed in (False, True)
    if not (sealed and damage is _too_long)
]


@pytest.mark.parametrize(("damage", "sidecar_sealed"), _PAIRS)
@pytest.mark.parametrize(
    "body", ["plaintext", "lost", "not-text", "not-text-late", "too-large", "as-saved"]
)
def test_the_startup_count_agrees_with_rotate_key_over_a_refused_or_blank_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    damage: Callable[[Path], None],
    body: str,
    sidecar_sealed: bool,
) -> None:
    """Both counts are driven over the same pair: the startup count's plaintext and never-sealable
    totals must be ``rotate-key``'s ``sealed_plaintext`` and ``unsealable``. At 18d2789dd0 they
    disagreed on at least the oversized and too-long kinds, and the startup count named an
    oversized sidecar over a lost body as one ``rotate-key`` cannot seal while that pass skips it."""
    cipher = _aes(generate_key())
    fid = _save(tmp_path, cipher if sidecar_sealed else None)
    sidecar = tmp_path / f"{fid}.meta"
    blob = tmp_path / f"{fid}.blob"
    monkeypatch.setattr(uploads, "_PLAIN_SIDECAR_LIMIT", len(sidecar.read_bytes()))
    damage(sidecar)
    if body == "plaintext":
        blob.write_bytes(_BODY)
    elif body == "lost":
        blob.unlink()
    elif body == "not-text-late":
        # Past the count's first decoded chunk, so its head read succeeds and the body test decides.
        blob.write_bytes(b"p" * 9000 + b"\xff")
    elif body == "not-text":
        blob.write_bytes(b"p" * 3000 + b"\xff")
    elif body == "too-large":
        blob.write_bytes(b"p" * (2 * 4096 + 4096 + 10))
    # "as-saved": the body as save wrote it, under the key when the sidecar was sealed.
    store = UploadStore(tmp_path, cipher, max_bytes=4096)

    counted, unsealable = store._count_unsealed_sync()  # noqa: SLF001 - both totals, unlogged
    logged = asyncio.run(store.warn_if_unsealed())
    result = _reseal(tmp_path, cipher)
    assert logged == counted
    assert (counted, unsealable) == (result.sealed_plaintext, result.unsealable)
    assert result.unsealable == 0
    blank = damage in (_blank, _empty)
    # A skipped body takes the pair's one count, so a blank sidecar over it is not counted damaged.
    assert result.damaged == int(blank and body != "too-large")
    assert result.refused_sidecars == int(not blank)
    assert result.incomplete == (not blank or body == "too-large")


def test_the_startup_count_skips_a_body_too_large_to_seal(tmp_path: Path) -> None:
    """rotate-key skips a body larger than a body can be, so the count must not include it."""
    cipher = _aes(generate_key())
    fid = _save(tmp_path, cipher)
    (tmp_path / f"{fid}.blob").write_bytes(b"p" * (2 * 4096 + 4096 + 10))
    counted = asyncio.run(UploadStore(tmp_path, cipher, max_bytes=4096).warn_if_unsealed())
    result = _reseal(tmp_path, cipher)
    assert (counted, result.sealed_plaintext, result.skipped) == (0, 0, 1)


# --- the command's error over a refused sidecar ---------------------------------------------------


def _rotate_over_a_refused_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, also_unopenable: bool = False
) -> int:
    """Run ``main(["rotate-key"])`` over one upload whose sidecar is padded past the cap, so every
    reader refuses it. ``also_unopenable`` adds a second upload sealed under a key the run is not
    given, a skip that is not a refused sidecar. Returns the exit code."""
    from messagefoundry.__main__ import main
    from tests.test_cli import _rotate_env, _seed_store_and_upload

    monkeypatch.chdir(tmp_path)
    db, root = tmp_path / "rot.db", tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    fid = _seed_store_and_upload(db, root, key_a)
    sidecar = root / f"{fid}.meta"
    sidecar.write_bytes(_padded_past_the_cap(sidecar.read_bytes(), "trailing"))
    if also_unopenable:
        _save(root, generate_key())
    _rotate_env(monkeypatch, active=key_b, retired=key_a, uploads=root)
    return main(["rotate-key", "--db", str(db)])


#: Phrases that advise removing or deleting an upload's files. "deliberately removed" is not one:
#: it is the condition the prior key waits on, never advice to remove.
_REMOVAL_ADVICE = ("remove its two files", "remove the two files", "delete", "remove it")


def test_rotate_key_never_advises_deleting_a_refused_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Deleting it could destroy a value under the prior key, so the error says every reader
    refuses it, that it may hold such a value, and that the prior key stays until it is fixed or
    deliberately removed."""
    assert _rotate_over_a_refused_sidecar(tmp_path, monkeypatch) == 1
    err = capsys.readouterr().err
    refused = [line for line in err.splitlines() if line.startswith("error: 1 of those")]
    assert len(refused) == 1, err
    line = refused[0]
    assert "error: 1 of those uploaded file(s) have a sidecar that every reader refuses" in line
    assert "It may hold a value under the prior key" in line
    assert "Do not retire the prior key until each such sidecar is fixed" in line
    assert "deliberately removed" in line
    assert "delete" not in line.lower() and "two files" not in line


def test_rotate_key_output_over_only_a_refused_sidecar_advises_no_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #5387. When every skip is a refused sidecar, no line of the command's output, the
    closing note after the audit roll included, advises removing or deleting an upload's files.
    At 0639d3657d the closing note offered removing the two files of an upload that cannot be
    fixed, and the skip error advised removing a damaged file's two files, whatever the skip."""
    assert _rotate_over_a_refused_sidecar(tmp_path, monkeypatch) == 1
    out = capsys.readouterr()
    lines = (out.out + out.err).splitlines()
    assert any(line.startswith("note: this run did not complete") for line in lines), lines
    advising = [line for line in lines if any(p in line.lower() for p in _REMOVAL_ADVICE)]
    assert advising == [], advising


def test_rotate_key_still_offers_removal_for_a_skip_that_is_not_a_refused_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: with a second skip that is not a refused sidecar, the removal advice is still
    given, and it says it does not cover the refused sidecar."""
    assert _rotate_over_a_refused_sidecar(tmp_path, monkeypatch, also_unopenable=True) == 1
    out = capsys.readouterr()
    assert "That does not apply to a sidecar every reader refuses" in out.err
    note = [line for line in out.out.splitlines() if line.startswith("note: this run did not")]
    assert len(note) == 1, out.out
    assert "for a skip that is not a sidecar every reader refuses, remove the two files" in note[0]
