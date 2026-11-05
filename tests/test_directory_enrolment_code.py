# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0207: a directory account's first engine factor is bound only with a single-use enrolment
code an Administrator issued. The acceptance criteria AC-1 to AC-19 are named on each test.

Synthetic accounts and codes only. The store contract is shared with the Postgres and SQL Server
suites (``tests/_enrolment_code_store_contract.py``); this file runs it on SQLite, keyed and keyless.
"""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import (
    USER_SEAL_WHEN_SET,
    MessageStore,
    UserAuthzRecord,
    UserRow,
)


def _row(**overrides: object) -> UserRow:
    base: dict[str, object] = {}
    for f in fields(UserRow):
        text = str(f.type)
        if f.name in USER_SEAL_WHEN_SET:
            base[f.name] = None
        elif "bool" in text:
            base[f.name] = False
        elif "int" in text:
            base[f.name] = 0
        elif "float" in text:
            base[f.name] = 0.0
        else:
            base[f.name] = "x"
    base.update(overrides)
    return UserRow(**base)  # type: ignore[arg-type]


async def test_the_store_contract_holds_on_a_keyless_sqlite_store(tmp_path: Path) -> None:
    """AC-8, AC-9, AC-10, AC-15, AC-19 at the store: issue, revoke, spend, the TOTP fold and the
    disable's clear, each conditional, and two spends of one code where exactly one wins."""
    from tests._enrolment_code_store_contract import assert_enrolment_code_store_contract

    store = await MessageStore.open(tmp_path / "codes.db")
    try:
        await assert_enrolment_code_store_contract(store)
    finally:
        await store.close()


async def test_the_store_contract_holds_on_a_keyed_sqlite_store(tmp_path: Path) -> None:
    from tests._enrolment_code_store_contract import assert_enrolment_code_store_contract

    store = await MessageStore.open(
        tmp_path / "sealed.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    try:
        await assert_enrolment_code_store_contract(store)
    finally:
        await store.close()


def test_a_null_code_column_leaves_the_seal_as_it_was() -> None:
    """Amendment A: an account that never held a code keeps the seal it was sealed under, because
    a NULL code column is left out of the sealed fields."""
    names = [n for n, _ in UserAuthzRecord(row=_row()).seal_fields()]
    assert not USER_SEAL_WHEN_SET & set(names)


def test_a_non_null_value_of_each_code_column_changes_the_seal() -> None:
    """Amendment A's pin: each code column, once set, enters the sealed fields, so a value planted
    outside the store fails the seal."""
    plain = UserAuthzRecord(row=_row()).seal_fields()
    for column, value in (
        ("enrolment_code_digest", "0" * 64),
        ("enrolment_code_expires_at", 1.0),
        ("enrolment_code_issuer", "admin"),
    ):
        changed = UserAuthzRecord(row=_row(**{column: value})).seal_fields()
        assert changed != plain, column
        assert (column, value) in changed, column
