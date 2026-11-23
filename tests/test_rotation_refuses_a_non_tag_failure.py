# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Key rotation stops on a cipher failure that is not a tag failure (BACKLOG #5610).

The rotation's tagged-cell loops leave a cell that fails its own tag under a held key and count it
in a WARNING (BACKLOG #2593). They used to catch every ``CipherError`` from the decrypt and the
re-encrypt, gated only by ``is_tag_failure``, which reads the marker and the keyring and never the
exception. So a malformed envelope under a held key, or the active key's invocation ceiling on the
re-encrypt, was counted as a tag failure: the row stayed under the retired key and the rotation
returned as a success.

These drive the rotation through entry points that predate the fix and import nothing it added, so
on the unfixed code each fails on what the rotation does, not on a missing name: SQLite end to end
through ``reencrypt_to_active``, and the PostgreSQL and SQL Server loops through
``_reencrypt_tagged_to_active`` over a stubbed row read, since neither server runs here. Each
failing case has a control: a real tag failure is still skipped and the rotation returns.
"""

from __future__ import annotations

import logging
import pathlib
import sqlite3
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import (
    _GCM_MAX_INVOCATIONS,
    _GCM_RESERVE_BLOCK,
    AesGcmCipher,
    CipherError,
    generate_key,
    make_cipher,
)
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore

_AAD = b"synthetic-cell-aad"


def _aes(key: str, *, retired: list[str] | None = None) -> AesGcmCipher:
    cipher = make_cipher(key, retired_b64=retired or [], write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    return cipher


def _malformed(sealed: str) -> str:
    """``sealed`` with its body cut too short to hold a nonce and a tag, but its marker, and so its
    named key, intact. (A stray non-base64 character would not do: the decoder drops it.)"""
    return sealed.rsplit(":", 1)[0] + ":AAAA"


def _at_the_ceiling(cipher: AesGcmCipher) -> AesGcmCipher:
    """``cipher`` with its invocation bound on and every invocation already spent, so its next
    encrypt raises the ceiling's ``CipherError``."""
    cipher.enable_invocation_bound()
    cipher.grant_invocations(_GCM_RESERVE_BLOCK, _GCM_MAX_INVOCATIONS + _GCM_RESERVE_BLOCK)
    return cipher


# --- SQLite, end to end ----------------------------------------------------------------------------


async def _queue_store_under(db: pathlib.Path, key: str) -> str:
    """A store under ``key`` holding one queue row; returns that row's sealed payload."""
    store = await MessageStore.open(db, cipher=make_cipher(key, write_v2=True))
    try:
        await store.enqueue_message(channel_id="IB", raw="MSH|r", deliveries=[("OB_A", "B1")])
    finally:
        await store.close()
    side = sqlite3.connect(db, timeout=30)
    try:
        (payload,) = side.execute(
            "SELECT payload FROM queue WHERE destination_name='OB_A'"
        ).fetchone()
    finally:
        side.close()
    return str(payload)


def _set_payload(db: pathlib.Path, payload: str) -> None:
    side = sqlite3.connect(db, timeout=30)
    try:
        side.execute("UPDATE queue SET payload=? WHERE destination_name='OB_A'", (payload,))
        side.commit()
    finally:
        side.close()


async def test_sqlite_rotation_stops_on_a_malformed_queue_cell(tmp_path: pathlib.Path) -> None:
    db = tmp_path / "rotate.db"
    old_key, new_key = generate_key(), generate_key()
    payload = await _queue_store_under(db, old_key)
    _set_payload(db, _malformed(payload))

    rotated = await MessageStore.open(
        db, cipher=make_cipher(new_key, retired_b64=[old_key], write_v2=True)
    )
    try:
        with pytest.raises(CipherError, match="malformed"):
            await rotated.reencrypt_to_active()
    finally:
        await rotated.close()


async def test_control_sqlite_rotation_skips_a_queue_cell_that_fails_its_tag(
    tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The same row, sealed under a held key but for another cell, is a tag failure: the rotation
    leaves it, counts it, and returns."""
    db = tmp_path / "rotate.db"
    old_key, new_key = generate_key(), generate_key()
    await _queue_store_under(db, old_key)
    _set_payload(db, _aes(old_key).encrypt("SYNTH", aad=b"another-cell"))

    rotated = await MessageStore.open(
        db, cipher=make_cipher(new_key, retired_b64=[old_key], write_v2=True)
    )
    try:
        with caplog.at_level(logging.WARNING):
            await rotated.reencrypt_to_active()
    finally:
        await rotated.close()
    assert "queue.payload value(s) that do not open under their own row's tag" in caplog.text


# --- PostgreSQL and SQL Server, through the tagged loop -------------------------------------------


def _loop_over(cls: type[Any], cipher: AesGcmCipher, stored: str) -> Callable[[], Any]:
    """A coroutine factory running ``cls``'s tagged rotation loop over one row holding ``stored``,
    with the row read stubbed and no server behind it. An UPDATE would need a connection, which
    this stub does not have, so a loop that reaches one fails loudly rather than passes."""
    store: Any = object.__new__(cls)
    store._cipher = cipher
    pages = [[{"id": "row-1", "v": stored}], []]

    async def _fetchall(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        return pages.pop(0)

    store._fetchall = _fetchall

    def _run() -> Any:
        common: dict[str, Any] = {
            "table": "queue",
            "column": "payload",
            "select": "id",
            "aad_of": lambda r: _AAD,
        }
        if cls is PostgresStore:
            return store._reencrypt_tagged_to_active(cipher, "mf:%", 10, **common)
        return store._reencrypt_tagged_to_active("mf:%", 10, **common)

    return _run


_SERVER_STORES = pytest.mark.parametrize(
    "cls", [PostgresStore, SqlServerStore], ids=["postgres", "sqlserver"]
)


@_SERVER_STORES
async def test_server_rotation_stops_on_a_malformed_cell_under_a_held_key(cls: type[Any]) -> None:
    old, new = generate_key(), generate_key()
    rotator = _aes(new, retired=[old])
    bad = _malformed(_aes(old).encrypt("SYNTH", aad=_AAD))
    assert rotator.holds_key_for(bad), "the marker must name a held key, or this proves nothing"
    with pytest.raises(CipherError, match="malformed"):
        await _loop_over(cls, rotator, bad)()


@_SERVER_STORES
async def test_server_rotation_stops_at_the_invocation_ceiling(cls: type[Any]) -> None:
    old, new = generate_key(), generate_key()
    sealed = _aes(old).encrypt("SYNTH", aad=_AAD)
    rotator = _at_the_ceiling(_aes(new, retired=[old]))
    with pytest.raises(CipherError, match="invocation ceiling"):
        await _loop_over(cls, rotator, sealed)()


@_SERVER_STORES
async def test_control_server_rotation_skips_a_cell_that_fails_its_tag(
    cls: type[Any], caplog: pytest.LogCaptureFixture
) -> None:
    old, new = generate_key(), generate_key()
    rotator = _aes(new, retired=[old])
    wrong_cell = _aes(old).encrypt("SYNTH", aad=b"another-cell")
    with caplog.at_level(logging.WARNING):
        assert await _loop_over(cls, rotator, wrong_cell)() == 0
    assert "queue.payload value(s) that do not open under their own row's tag" in caplog.text
