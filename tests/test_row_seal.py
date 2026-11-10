# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The row-seal primitives: the purpose-separated key, its id, and the one encoder (BACKLOG #2592).

Each property here has a control beside it, so a test cannot pass by the sealer accepting
everything or refusing everything.
"""

from __future__ import annotations

import base64
import contextlib
import sqlite3
from collections.abc import Callable
from typing import Any

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


_NOT_FINITE = (float("nan"), float("inf"), float("-inf"))


def _through_sqlite_real(value: float) -> object:
    """``value`` as a SQLite ``REAL`` column hands it back, the round trip a stored row makes."""
    with contextlib.closing(sqlite3.connect(":memory:")) as conn:
        conn.execute("CREATE TABLE t (v REAL)")
        conn.execute("INSERT INTO t VALUES (?)", (value,))
        return conn.execute("SELECT v FROM t").fetchone()[0]


def test_a_negative_zero_seal_survives_a_sqlite_real_round_trip() -> None:
    # BACKLOG #6717. SQLite's REAL column reads -0.0 back as 0.0, so a seal over -0.0's own
    # encoding failed the next read as if the row had been changed.
    back = _through_sqlite_real(-0.0)  # 0.0 on SQLite 3.50; the check holds either way
    sealer = _sealer()
    stored = sealer.seal("session", (("revoked_at", -0.0),))
    assert sealer.verify("session", (("revoked_at", back),), stored)
    # Control: a different value still fails, so the check did not open up.
    assert not sealer.verify("session", (("revoked_at", 5e-324),), stored)


@pytest.mark.parametrize(
    "value", [0.0, 1.5, -1.5, 1_700_000_000.123456, 5e-324, -5e-324, 1e308, -1e308]
)
def test_every_float_but_negative_zero_keeps_its_float_hex_encoding(value: float) -> None:
    # Only -0.0 moved: a seal made before the change over any other float still verifies.
    expected = b"F" + len(value.hex()).to_bytes(4, "big") + value.hex().encode("ascii")
    assert seal_bytes("k", [("f", value)]).endswith(expected)


def test_negative_zero_encodes_as_zero_does() -> None:
    assert seal_bytes("k", [("f", -0.0)]) == seal_bytes("k", [("f", 0.0)])


@pytest.mark.parametrize("value", _NOT_FINITE)
def test_a_seal_refuses_a_float_that_is_not_finite(value: float) -> None:
    # BACKLOG #6717. SQLite stores a NaN as NULL, so a seal over one could never verify again.
    sealer = _sealer()
    with pytest.raises(ValueError):
        sealer.seal("session", (("expires_at", value),))
    assert sealer.seal("session", (("expires_at", 1.5),))  # control: a finite value seals


@pytest.mark.parametrize("value", _NOT_FINITE)
def test_a_row_changed_to_a_float_that_is_not_finite_fails_without_raising(value: float) -> None:
    sealer = _sealer()
    stored = sealer.seal("session", (("expires_at", 1.5),))
    assert sealer.verify("session", (("expires_at", 1.5),), stored)  # control
    assert sealer.verify_held("session", (("expires_at", 1.5),), stored)  # control
    assert not sealer.verify("session", (("expires_at", value),), stored)
    assert not sealer.verify_held("session", (("expires_at", value),), stored)


def test_a_seal_reads_a_one_shot_iterable_of_fields_whole() -> None:
    sealer = _sealer()
    stored = sealer.seal("session", (pair for pair in _FIELDS))
    assert sealer.verify("session", _FIELDS, stored)
    assert sealer.verify("session", iter(_FIELDS), stored)


@pytest.mark.parametrize(
    "as_type",
    [lambda s: s.encode("ascii"), lambda s: bytearray(s, "ascii"), lambda s: 7, lambda s: 7.5],
    ids=["bytes", "bytearray", "int", "float"],
)
def test_a_stored_seal_that_is_not_text_fails_every_check_without_raising(
    as_type: Callable[[str], Any],
) -> None:
    # BACKLOG #6718. A SQLite column can hand back a blob or a number whatever the column says;
    # each check must read that as a malformed seal, not raise AttributeError or TypeError.
    old, new = generate_key(), generate_key()
    stored = _sealer(old).seal("session", _FIELDS)
    rekeyed = RowSealer.for_cipher(make_cipher(new, [old]))
    assert rekeyed is not None
    held = _sealer(old)
    assert held.verify("session", _FIELDS, stored)  # controls: the text form verifies
    assert held.verify_held("session", _FIELDS, stored)
    assert held.is_active(stored)
    assert rekeyed.sealed_by_retired_key("session", _FIELDS, stored)  # control
    other = as_type(stored)
    assert not held.verify("session", _FIELDS, other)
    assert not held.verify_held("session", _FIELDS, other)
    assert not held.is_active(other)
    assert not rekeyed.sealed_by_retired_key("session", _FIELDS, other)


@pytest.mark.parametrize(
    "fields",
    [(("f", 10**5000),), (("\udc80", "v"),)],
    ids=["int-past-the-digit-limit", "name-not-utf8"],
)
def test_a_value_the_encoder_cannot_frame_fails_the_check_without_raising(
    fields: tuple[tuple[str, object], ...],
) -> None:
    # BACKLOG #6718: a ValueError escaped every caller's ``except TypeError``.
    sealer = _sealer()
    stored = sealer.seal("session", _FIELDS)
    assert sealer.verify_held("session", _FIELDS, stored)  # control
    assert not sealer.verify("session", fields, stored)
    assert not sealer.verify_held("session", fields, stored)
    assert not sealer.sealed_by_retired_key("session", fields, stored)
