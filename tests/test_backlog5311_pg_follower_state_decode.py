# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5311: PostgreSQL follower state convergence decodes each cell through the guarded path.

``converge_state_cache`` used to feed ``self._cipher.decrypt(...)`` straight to ``json.loads``. A
keyless follower of an encrypted store then raised a bare ``JSONDecodeError`` rather than
``StoreKeylessError``, and a corrupt cell raised a ``JSONDecodeError`` whose ``.doc`` held the whole
decrypted plaintext. It now decodes through ``decrypt_json_cell``, as the open-time load does.

Checked WITHOUT a database, so it runs everywhere: ``_fetchall`` is faked, and only the follower
read-through runs. The values are synthetic.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.store.crypto import (
    CipherError,
    IdentityCipher,
    StoreKeylessError,
    cell_aad,
    generate_key,
    make_cipher,
)
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sealed_cache import new_state_cache
from tests._content_free import assert_chain_severed

MARKER = "synthetic-mrn-marker"


def _follower(cipher: Any, stored: list[str]) -> PostgresStore:
    """A bare follower whose shared ``state`` table holds ``stored`` under namespace ``ns``."""
    store = object.__new__(PostgresStore)
    store._cipher = cipher
    store._state_cache = new_state_cache()
    store._state_versions = {}

    async def fake_fetchall(sql: str, *_params: Any) -> list[dict[str, Any]]:
        if "FROM state_version" in sql:
            return [{"namespace": "ns", "version": 1}]
        assert "WHERE namespace" in sql, sql
        return [{"key": f"K{i}", "value": v} for i, v in enumerate(stored)]

    store._fetchall = fake_fetchall  # type: ignore[method-assign]
    return store


def _enc(cipher: Any, plaintext: str, key: str) -> str:
    return str(cipher.encrypt(plaintext, aad=cell_aad("state", "value", "ns", key)))


def _assert_carries_no_secret(exc: BaseException) -> None:
    """The raised error does not hold the plaintext, and nothing is chained to it that could."""
    assert MARKER not in f"{exc} | {exc!r}"
    assert MARKER not in str(getattr(exc, "doc", ""))
    assert_chain_severed(exc)


async def test_a_valid_cell_converges() -> None:
    """The control: a well-formed encrypted cell decodes and lands in the cache."""
    cipher = make_cipher(generate_key())
    store = _follower(cipher, [_enc(cipher, json.dumps(MARKER), "K0")])
    assert await store.converge_state_cache() == ["ns"]
    assert store._state_cache[("ns", "K0")] == MARKER


async def test_a_keyless_follower_raises_store_keyless_error() -> None:
    writer = make_cipher(generate_key())
    store = _follower(make_cipher(None), [_enc(writer, json.dumps(MARKER), "K0")])
    with pytest.raises(StoreKeylessError):
        await store.converge_state_cache()
    assert store._state_versions == {}  # nothing recorded, so the next tick tries again


async def test_a_corrupt_encrypted_cell_raises_without_its_plaintext() -> None:
    cipher = make_cipher(generate_key())
    # Decrypts under the configured key, but the plaintext is not JSON.
    store = _follower(cipher, [_enc(cipher, f"not json {MARKER}", "K0")])
    with pytest.raises(CipherError) as info:
        await store.converge_state_cache()
    assert "corrupt" in str(info.value)
    _assert_carries_no_secret(info.value)
    assert len(store._state_cache) == 0


async def test_a_malformed_legacy_plaintext_cell_raises_a_body_free_error() -> None:
    store = _follower(IdentityCipher(), [f"{{not json {MARKER}"])
    with pytest.raises(json.JSONDecodeError) as info:
        await store.converge_state_cache()
    assert info.value.doc == ""
    _assert_carries_no_secret(info.value)
