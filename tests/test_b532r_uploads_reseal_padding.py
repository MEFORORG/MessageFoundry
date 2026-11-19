# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``rotate-key`` over a sidecar padded past the cap, and the startup count over every kind of
damaged sidecar (BACKLOG #5387). Synthetic data only.

A sidecar sealed under a PRIOR key and padded past 128 KiB was classed damaged, so the rotation
completed and the prior key read as safe to retire, though trimming the padding recovers the value
with that key. It is now a skip. And the startup count skipped the body under an oversized sidecar
while ``rotate-key`` sealed it, so the operator's cross-check of the two disagreed."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest

import messagefoundry.uploads as uploads
from messagefoundry.store.crypto import AesGcmCipher, generate_key, make_cipher
from messagefoundry.uploads import ResealResult, UploadStore

_BODY = b"synthetic diagnostic line\n"
_OVER = uploads._SIDECAR_LIMIT + 1  # noqa: SLF001 - the test plants a file at the seam


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


# --- item 1: a padded sidecar under a prior key is a skip -----------------------------------------


@pytest.mark.parametrize("where", ["trailing", "leading"])
def test_a_prior_key_sidecar_padded_past_the_cap_is_a_skip(tmp_path: Path, where: str) -> None:
    """Fails at 18d2789dd0: it was ``damaged``, the run completed, and the prior key read as safe
    to retire. Trimming the padding and re-running then seals it under the new key."""
    key_a, key_b = generate_key(), generate_key()
    fid = _save(tmp_path, key_a)
    sidecar = tmp_path / f"{fid}.meta"
    sealed = sidecar.read_text(encoding="utf-8")
    pad = " " * (_OVER - len(sealed))
    sidecar.write_text(sealed + pad if where == "trailing" else pad + sealed, encoding="utf-8")
    rotated = _aes(key_b, key_a)

    result = _reseal(tmp_path, rotated)
    assert (result.skipped, result.damaged) == (1, 0)
    assert result.incomplete
    assert sidecar.read_text(encoding="utf-8").strip() == sealed  # left as it is

    sidecar.write_text(sealed, encoding="utf-8")
    again = _reseal(tmp_path, rotated)
    assert (again.skipped, again.damaged) == (0, 0)
    assert not again.incomplete
    assert sidecar.read_text(encoding="utf-8").startswith(rotated.active_marker_prefix)


def test_a_sidecar_that_is_padding_to_the_cap_is_a_skip(tmp_path: Path) -> None:
    """The bounded head cannot see past the padding, so it cannot rule out a marker after it."""
    key_a, key_b = generate_key(), generate_key()
    fid = _save(tmp_path, key_a)
    sidecar = tmp_path / f"{fid}.meta"
    sealed = sidecar.read_text(encoding="utf-8")
    sidecar.write_text(" " * _OVER + sealed, encoding="utf-8")
    result = _reseal(tmp_path, _aes(key_b, key_a))
    assert (result.skipped, result.damaged) == (1, 0)


def test_an_active_key_sidecar_padded_past_the_cap_is_damaged(tmp_path: Path) -> None:
    """Control: under the active key, retiring the prior key loses nothing, so it stays terminal."""
    cipher = _aes(generate_key())  # one instance: a cipher's marker carries its own store salt
    fid = _save(tmp_path, cipher)
    sidecar = tmp_path / f"{fid}.meta"
    sealed = sidecar.read_text(encoding="utf-8")
    sidecar.write_text(sealed + " " * (_OVER - len(sealed)), encoding="utf-8")
    result = _reseal(tmp_path, cipher)
    assert (result.skipped, result.damaged) == (0, 1)
    assert not result.incomplete


@pytest.mark.parametrize("prior", [True, False], ids=["prior-key", "active-key"])
def test_a_sealed_sidecar_with_a_stray_non_utf8_byte_is_a_skip_only_under_a_prior_key(
    tmp_path: Path, prior: bool
) -> None:
    """Trimming the stray byte recovers the value with the key its marker names, so under a prior
    key it is a skip; under the active key, retiring the prior key loses nothing."""
    key_a, key_b = generate_key(), generate_key()
    fid = _save(tmp_path, key_a)
    sidecar = tmp_path / f"{fid}.meta"
    sidecar.write_bytes(sidecar.read_bytes() + b"\xff")
    result = _reseal(tmp_path, _aes(key_b, key_a) if prior else _aes(key_a))
    assert (result.skipped, result.damaged) == ((1, 0) if prior else (0, 1))


def test_a_plaintext_sidecar_padded_past_the_cap_is_damaged(tmp_path: Path) -> None:
    """Control: a plaintext one is under no key, so it is not a skip."""
    fid = _save(tmp_path, None)
    sidecar = tmp_path / f"{fid}.meta"
    plain = sidecar.read_text(encoding="utf-8")
    sidecar.write_text(plain + " " * (_OVER - len(plain)), encoding="utf-8")
    result = _reseal(tmp_path, _aes(generate_key()))
    assert (result.skipped, result.damaged) == (0, 1)


# --- item 2: the startup count and rotate-key agree over every damage kind ------------------------


def _oversized(sidecar: Path, plain: str) -> None:
    sidecar.write_text(plain + " " * (_OVER - len(plain)), encoding="utf-8")


def _too_long(sidecar: Path, plain: str) -> None:
    # Past the plaintext seal bound and under the cap, with the bound lowered below the file.
    sidecar.write_text(plain + " x" * 8, encoding="utf-8")


def _blank(sidecar: Path, plain: str) -> None:
    sidecar.write_text("  \n", encoding="utf-8")


def _not_utf8(sidecar: Path, plain: str) -> None:
    sidecar.write_bytes(b"\xff\xfe" + plain.encode("utf-8"))


@pytest.mark.parametrize(
    "damage", [_oversized, _too_long, _blank, _not_utf8], ids=lambda f: f.__name__.strip("_")
)
def test_the_startup_count_matches_rotate_keys_sealed_count_over_a_damaged_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: Callable[[Path, str], None]
) -> None:
    """Each sidecar is one ``rotate-key`` leaves as it is, while it seals the plaintext body under
    it. At 18d2789dd0 the startup count stopped at the oversized and too-long kinds and counted
    the blank and non-UTF-8 kinds, so the operator's cross-check disagreed on two of the four."""
    fid = _save(tmp_path, None)
    sidecar = tmp_path / f"{fid}.meta"
    plain = sidecar.read_text(encoding="utf-8")
    monkeypatch.setattr(uploads, "_PLAIN_SIDECAR_LIMIT", len(plain.encode("utf-8")))
    damage(sidecar, plain)
    cipher = _aes(generate_key())

    counted = asyncio.run(UploadStore(tmp_path, cipher, max_bytes=4096).warn_if_unsealed())
    result = _reseal(tmp_path, cipher)
    assert (counted, result.sealed_plaintext) == (1, 1)
    assert (result.damaged, result.skipped) == (1, 0)
