# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rotation steps over a tag failure, and over nothing else (BACKLOG #5610).

``rotate-key``'s tagged-cell loops leave a cell that fails its own tag under a held key and count it
in a WARNING (BACKLOG #2593). They used to catch every ``CipherError`` from the decrypt AND the
encrypt, gated only by :func:`is_tag_failure`, which reads the marker and the keyring and never the
exception. So a malformed envelope under a held key, or the active key's invocation ceiling on the
re-encrypt, would have been counted as a tag failure: rows left under a retired key while the
rotation reported success. Each backend now routes through :func:`reseal_unless_tag_failure`, which
skips only an :class:`UnauthenticatedCipherError` from the decrypt.

PostgreSQL and SQL Server cannot run here, so their loops are pinned structurally to the shared seam
the SQLite end-to-end test drives.
"""

from __future__ import annotations

import inspect
import pathlib
import sqlite3

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import (
    _GCM_MAX_INVOCATIONS,
    _GCM_RESERVE_BLOCK,
    AesGcmCipher,
    CipherError,
    UnauthenticatedCipherError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.queue_tag import reseal_unless_tag_failure

_AAD = b"synthetic-cell-aad"


def _aes(key: str, *, retired: list[str] | None = None) -> AesGcmCipher:
    cipher = make_cipher(key, retired_b64=retired or [], write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    return cipher


def _malformed(sealed: str) -> str:
    """``sealed`` with its body cut too short to hold a nonce and a tag, but its marker, and so its
    named key, intact. (A stray non-base64 character would not do: the decoder drops it.)"""
    return sealed.rsplit(":", 1)[0] + ":AAAA"


def test_a_tag_failure_under_a_held_key_is_skipped() -> None:
    old, new = generate_key(), generate_key()
    sealed = _aes(old).encrypt("SYNTH", aad=_AAD)
    rotator = _aes(new, retired=[old])
    assert reseal_unless_tag_failure(rotator, sealed, b"another-cell") is None


def test_a_good_cell_is_resealed_under_the_active_key() -> None:
    old, new = generate_key(), generate_key()
    sealed = _aes(old).encrypt("SYNTH", aad=_AAD)
    rotator = _aes(new, retired=[old])
    resealed = reseal_unless_tag_failure(rotator, sealed, _AAD)
    assert resealed is not None and resealed != sealed
    assert _aes(new).decrypt(resealed, aad=_AAD) == "SYNTH"


def test_an_unsupplied_key_still_stops_the_rotation() -> None:
    sealed = _aes(generate_key()).encrypt("SYNTH", aad=_AAD)
    with pytest.raises(UnauthenticatedCipherError):
        reseal_unless_tag_failure(_aes(generate_key()), sealed, _AAD)


def test_a_malformed_envelope_under_a_held_key_stops_the_rotation() -> None:
    old, new = generate_key(), generate_key()
    rotator = _aes(new, retired=[old])
    bad = _malformed(_aes(old).encrypt("SYNTH", aad=_AAD))
    assert rotator.holds_key_for(bad), (
        "the marker must still name a held key, or this proves nothing"
    )
    with pytest.raises(CipherError, match="malformed") as info:
        reseal_unless_tag_failure(rotator, bad, _AAD)
    assert not isinstance(info.value, UnauthenticatedCipherError)


def test_the_invocation_ceiling_on_the_reencrypt_stops_the_rotation() -> None:
    old, new = generate_key(), generate_key()
    sealed = _aes(old).encrypt("SYNTH", aad=_AAD)
    rotator = _aes(new, retired=[old])
    rotator.enable_invocation_bound()
    rotator.grant_invocations(_GCM_RESERVE_BLOCK, _GCM_MAX_INVOCATIONS + _GCM_RESERVE_BLOCK)
    with pytest.raises(CipherError, match="invocation ceiling"):
        reseal_unless_tag_failure(rotator, sealed, _AAD)


async def test_sqlite_rotation_refuses_a_malformed_queue_cell_instead_of_skipping_it(
    tmp_path: pathlib.Path,
) -> None:
    """End to end on SQLite: a malformed queue payload under a held key used to be counted as a tag
    failure, and ``reencrypt_to_active`` returned as a success with that row left as it was."""
    db = tmp_path / "rotate.db"
    old_key, new_key = generate_key(), generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(old_key, write_v2=True))
    try:
        await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[("OB_A", "B1")])
    finally:
        await store.close()
    side = sqlite3.connect(db, timeout=30)
    try:
        (payload,) = side.execute(
            "SELECT payload FROM queue WHERE destination_name='OB_A'"
        ).fetchone()
        side.execute(
            "UPDATE queue SET payload=? WHERE destination_name='OB_A'", (_malformed(payload),)
        )
        side.commit()
    finally:
        side.close()

    rotated = await MessageStore.open(
        db, cipher=make_cipher(new_key, retired_b64=[old_key], write_v2=True)
    )
    try:
        with pytest.raises(CipherError, match="malformed"):
            await rotated.reencrypt_to_active()
    finally:
        await rotated.close()


def test_every_backends_tagged_rotation_loop_skips_only_through_the_seam() -> None:
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    for cls in (MessageStore, PostgresStore, SqlServerStore):
        src = inspect.getsource(cls._reencrypt_tagged_to_active)
        assert "reseal_unless_tag_failure(" in src, cls.__name__
        assert "except CipherError" not in src, (
            f"{cls.__name__}._reencrypt_tagged_to_active catches every CipherError again, so a "
            "malformed envelope or the invocation ceiling would be counted as a tag failure"
        )
        assert "is_tag_failure(" not in src, cls.__name__
