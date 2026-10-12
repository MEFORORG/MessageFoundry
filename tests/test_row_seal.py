# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The row-seal primitives: the purpose-separated key, its id, and the one encoder (BACKLOG #2592).

Each property here has a control beside it, so a test cannot pass by the sealer accepting
everything or refusing everything.
"""

from __future__ import annotations

import base64

import pytest

from messagefoundry.store.crypto import (
    NO_STORE_ID,
    IdentityCipher,
    _derive_audit_mac_key,
    _derive_authz_root,
    derive_row_seal_key,
    generate_key,
    make_cipher,
    row_seal_key_id,
)
from messagefoundry.store.row_seal import SEAL_PREFIX, RowSealer, seal_bytes

_FIELDS = (("token_hash", "a" * 64), ("user_id", "u1"), ("created_at", 1.5), ("revoked_at", None))


def _sealer(key_b64: str | None = None) -> RowSealer:
    sealer = RowSealer.for_cipher(make_cipher(key_b64 or generate_key()))
    assert sealer is not None
    return sealer


def test_a_seal_verifies_over_the_fields_it_was_made_from() -> None:
    sealer = _sealer()
    stored = sealer.seal("session", _FIELDS)
    assert stored.startswith(f"{SEAL_PREFIX}{sealer.key_id}:")
    assert sealer.verify("session", _FIELDS, stored)


@pytest.mark.parametrize(
    "changed",
    [
        (("token_hash", "a" * 64), ("user_id", "u2"), ("created_at", 1.5), ("revoked_at", None)),
        (("token_hash", "a" * 64), ("user_id", "u1"), ("created_at", 1.25), ("revoked_at", None)),
        (("token_hash", "a" * 64), ("user_id", "u1"), ("created_at", 1.5), ("revoked_at", 9.0)),
        (("token_hash", "a" * 64), ("user_id", "u1"), ("created_at", 1.5)),
    ],
    ids=["user", "stamp", "revoked", "dropped-field"],
)
def test_any_change_to_the_fields_fails_the_seal(changed: tuple[tuple[str, object], ...]) -> None:
    sealer = _sealer()
    stored = sealer.seal("session", _FIELDS)
    assert sealer.verify("session", _FIELDS, stored)  # control: the original still verifies
    assert not sealer.verify("session", changed, stored)


def test_a_seal_of_one_kind_never_verifies_as_another() -> None:
    sealer = _sealer()
    stored = sealer.seal("session", _FIELDS)
    assert sealer.verify("session", _FIELDS, stored)
    assert not sealer.verify("user", _FIELDS, stored)


@pytest.mark.parametrize("stored", [None, "", "mfseal:v1:", "mfseal:v1:abc", "x" * 90])
def test_a_missing_or_malformed_seal_fails(stored: str | None) -> None:
    assert not _sealer().verify("session", _FIELDS, stored)


def test_a_seal_under_another_key_fails_and_names_that_key() -> None:
    one, other = _sealer(), _sealer()
    stored = other.seal("session", _FIELDS)
    assert one.key_id != other.key_id
    assert other.verify("session", _FIELDS, stored)
    assert not one.verify("session", _FIELDS, stored)


def test_a_seal_with_a_flipped_mac_character_fails() -> None:
    sealer = _sealer()
    stored = sealer.seal("session", _FIELDS)
    flipped = stored[:-1] + ("0" if stored[-1] != "0" else "1")
    assert not sealer.verify("session", _FIELDS, flipped)
    assert not sealer.verify("session", _FIELDS, stored[:-1] + "é")  # non-ASCII, no raise


def test_the_encoder_tells_none_empty_and_the_text_none_apart() -> None:
    encodings = {seal_bytes("k", [("f", v)]) for v in (None, "", "None")}
    assert len(encodings) == 3


def test_the_encoder_tells_a_bool_an_int_and_a_float_apart() -> None:
    encodings = {seal_bytes("k", [("f", v)]) for v in (True, 1, 1.0, "1")}
    assert len(encodings) == 4


def test_the_encoder_is_unambiguous_across_field_boundaries() -> None:
    assert seal_bytes("k", [("ab", "c")]) != seal_bytes("k", [("a", "bc")])
    assert seal_bytes("k", [("a", "b"), ("c", "d")]) != seal_bytes("k", [("a", "bcd")])


def test_the_encoder_refuses_a_type_it_cannot_encode() -> None:
    with pytest.raises(TypeError):
        seal_bytes("k", [("f", object())])


def test_a_float_encodes_exactly() -> None:
    import math

    a = 1_700_000_000.123456
    b = math.nextafter(a, math.inf)  # the next double up: one unit in the last place
    assert a != b
    assert seal_bytes("k", [("f", a)]) != seal_bytes("k", [("f", b)])


def test_a_keyless_cipher_has_no_sealer() -> None:
    assert RowSealer.for_cipher(IdentityCipher()) is None


def test_one_key_gives_one_sealer_across_processes() -> None:
    key = generate_key()
    a, b = _sealer(key), _sealer(key)
    assert a.key_id == b.key_id
    assert b.verify("session", _FIELDS, a.seal("session", _FIELDS))


def test_the_seal_key_is_separate_from_the_audit_key_and_the_dek() -> None:
    dek = base64.b64decode(generate_key())
    root = _derive_authz_root(dek)
    seal_key = derive_row_seal_key(root, NO_STORE_ID)
    assert len({dek, root, seal_key, _derive_audit_mac_key(dek)}) == 4


def test_the_key_id_moves_with_the_store_id() -> None:
    root = _derive_authz_root(base64.b64decode(generate_key()))
    unpinned = derive_row_seal_key(root, NO_STORE_ID)
    pinned = derive_row_seal_key(root, b"\x01" * 16)
    assert unpinned != pinned
    assert row_seal_key_id(unpinned) != row_seal_key_id(pinned)
    # Control: the same inputs give the same key and id.
    assert row_seal_key_id(derive_row_seal_key(root, NO_STORE_ID)) == row_seal_key_id(unpinned)


def test_a_retired_key_seal_is_recognised_but_never_accepted() -> None:
    old, new = generate_key(), generate_key()
    stored = _sealer(old).seal("session", _FIELDS)
    rekeyed = RowSealer.for_cipher(make_cipher(new, [old]))
    assert rekeyed is not None
    assert not rekeyed.verify("session", _FIELDS, stored)
    assert rekeyed.sealed_by_retired_key("session", _FIELDS, stored)
    # Controls: a changed row, or a key the cipher never held, is not a key change.
    assert not rekeyed.sealed_by_retired_key("session", _FIELDS[:-1], stored)
    stranger = _sealer().seal("session", _FIELDS)
    assert not rekeyed.sealed_by_retired_key("session", _FIELDS, stranger)
    assert not _sealer(new).sealed_by_retired_key("session", _FIELDS, stored)


def test_the_cipher_root_is_the_active_keys() -> None:
    active, retired = generate_key(), generate_key()
    cipher = make_cipher(active, [retired])
    assert cipher.authz_root() == _derive_authz_root(base64.b64decode(active))
    assert cipher.authz_root() != _derive_authz_root(base64.b64decode(retired))
