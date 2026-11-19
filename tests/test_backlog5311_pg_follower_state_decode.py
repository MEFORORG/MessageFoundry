# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5311: PostgreSQL follower state convergence decodes each cell through the guarded path.

``converge_state_cache`` used to feed ``self._cipher.decrypt(...)`` straight to ``json.loads``. A
keyless follower of an encrypted store then raised a bare ``JSONDecodeError`` rather than
``StoreKeylessError``, and a corrupt cell raised a ``JSONDecodeError`` whose ``.doc`` held the whole
decrypted plaintext. It now decodes through ``decrypt_json_cell``, as the open-time load does.

Checked WITHOUT a database, so it runs everywhere: ``_fetchall`` is faked, and only the follower
read-through runs. The keyed cipher writes the cell-bound ``mfenc:v4`` form, the production default,
so a cell decoded under the wrong associated data is refused. The values are synthetic.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.store.crypto import (
    Cipher,
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


def _keyed() -> Cipher:
    return make_cipher(generate_key(), write_v2=True)


def _follower(cipher: Cipher, table: dict[str, list[str]]) -> PostgresStore:
    """A bare follower whose shared ``state`` table holds ``table``: namespace -> stored values,
    keyed ``K0``, ``K1``, ... Every namespace is at version 1, which this handle has not seen."""
    store = object.__new__(PostgresStore)
    store._cipher = cipher
    store._state_cache = new_state_cache()
    store._state_versions = {}

    async def fake_fetchall(sql: str, *params: Any) -> list[dict[str, Any]]:
        if "FROM state_version" in sql:
            return [{"namespace": ns, "version": 1} for ns in table]
        assert "WHERE namespace" in sql, sql
        return [{"key": f"K{i}", "value": v} for i, v in enumerate(table[params[0]])]

    store._fetchall = fake_fetchall  # type: ignore[method-assign]
    return store


def _enc(cipher: Cipher, plaintext: str, ns: str, key: str) -> str:
    return cipher.encrypt(plaintext, aad=cell_aad("state", "value", ns, key))


def _assert_carries_no_marker(exc: BaseException) -> None:
    """The raised error's message, repr and ``.doc`` do not hold the plaintext, and nothing is
    chained to it that could. Its traceback's frame locals are out of scope here."""
    assert MARKER not in f"{exc} | {exc!r}"
    assert MARKER not in str(getattr(exc, "doc", ""))
    assert_chain_severed(exc)


async def test_a_valid_cell_converges() -> None:
    """The control: a well-formed encrypted cell decodes and lands in the cache."""
    cipher = _keyed()
    store = _follower(cipher, {"ns": [_enc(cipher, json.dumps(MARKER), "ns", "K0")]})
    assert await store.converge_state_cache() == ["ns"]
    assert store._state_cache[("ns", "K0")] == MARKER


@pytest.mark.parametrize(("sealed_ns", "sealed_key"), [("other", "K1"), ("ns", "K0")])
async def test_a_cell_sealed_for_another_place_is_refused(sealed_ns: str, sealed_key: str) -> None:
    """The decode binds the cell's own namespace and key. Row K1 of ``ns`` holds a cell sealed for
    another namespace, or for row K0 of the same namespace, and either way it is refused."""
    cipher = _keyed()
    good = _enc(cipher, json.dumps(MARKER), "ns", "K0")
    moved = _enc(cipher, json.dumps(MARKER), sealed_ns, sealed_key)
    store = _follower(cipher, {"ns": [good, moved]})
    with pytest.raises(CipherError):
        await store.converge_state_cache()
    assert len(store._state_cache) == 0


async def test_a_keyless_follower_raises_store_keyless_error() -> None:
    writer = _keyed()
    store = _follower(make_cipher(None), {"ns": [_enc(writer, json.dumps(MARKER), "ns", "K0")]})
    with pytest.raises(StoreKeylessError):
        await store.converge_state_cache()
    assert store._state_versions == {}  # nothing recorded, so the next tick tries again


def test_the_marker_check_can_fail() -> None:
    """The positive control: a bare json.loads of the corrupt text keeps the marker on ``.doc``."""
    with pytest.raises(json.JSONDecodeError) as info:
        json.loads(f"not json {MARKER}")
    with pytest.raises(AssertionError):
        _assert_carries_no_marker(info.value)


async def test_a_corrupt_encrypted_cell_raises_without_its_plaintext() -> None:
    cipher = _keyed()
    # Decrypts under the configured key, but the plaintext is not JSON.
    store = _follower(cipher, {"ns": [_enc(cipher, f"not json {MARKER}", "ns", "K0")]})
    with pytest.raises(CipherError) as info:
        await store.converge_state_cache()
    assert "corrupt" in str(info.value)
    _assert_carries_no_marker(info.value)
    assert len(store._state_cache) == 0


async def test_a_malformed_legacy_plaintext_cell_raises_a_body_free_error() -> None:
    store = _follower(IdentityCipher(), {"ns": [f"{{not json {MARKER}"]})
    with pytest.raises(json.JSONDecodeError) as info:
        await store.converge_state_cache()
    assert info.value.doc == ""
    _assert_carries_no_marker(info.value)


async def test_a_corrupt_later_namespace_leaves_an_earlier_good_one_untouched() -> None:
    """Every changed namespace decodes before any cache write or version record, so a failure in
    the second leaves the first neither reseeded nor recorded."""
    cipher = _keyed()
    store = _follower(
        cipher,
        {
            "good": [_enc(cipher, json.dumps(MARKER), "good", "K0")],
            "bad": [_enc(cipher, "not json", "bad", "K0")],
        },
    )
    with pytest.raises(CipherError):
        await store.converge_state_cache()
    assert len(store._state_cache) == 0
    assert store._state_versions == {}
