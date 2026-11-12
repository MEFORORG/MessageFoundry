# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5725: the SQL Server AD group-to-role map never seals in a role id that names no role.

SQLite and Postgres declare a roles foreign key on the map, and compare it exactly. SQL Server's map
had none, and its database collation is case-insensitive and pads trailing spaces, so a key alone
would still take ``VIEWER`` or ``viewer `` for ``viewer``. The writer therefore checks the ids
exactly inside its transaction (:func:`existing_role_pairs_only`), the key refuses a role deleted
after that read, and the map read counts a pair live only on an exact id. The behavioural contract
on every backend, the SQL Server live leg included, is ``tests/_role_seal_contract.py``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.store import sqlserver as ss
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import (
    AD_ROLE_MAP,
    AD_SCOPE_MAP,
    AdMap,
    UnknownRoleError,
    existing_role_pairs_only,
)

_G = "cn=ops,dc=example,dc=test"
_H = "cn=other,dc=example,dc=test"
_PRESENT = ("administrator", "operator", "viewer", "custom-1")


def _apply(current: AdMap, change: Any) -> AdMap:
    checked = existing_role_pairs_only(current, change, _PRESENT)
    return checked if isinstance(checked, AdMap) else checked(current)


@pytest.mark.parametrize("bogus", ["VIEWER", "viewer ", " viewer", "no-such-role"])
def test_a_replacement_naming_an_inexact_role_id_is_refused(bogus: str) -> None:
    current = AdMap.of(AD_ROLE_MAP, [(_G, "viewer")])
    replacement = AdMap.of(AD_ROLE_MAP, [(_G, "viewer"), (_H, bogus)])
    with pytest.raises(UnknownRoleError) as raised:
        _apply(current, replacement)
    assert raised.value.role_ids == (bogus,)


def test_a_replacement_of_known_ids_passes_unchanged() -> None:
    """The control: exact ids of live roles are written as given."""
    replacement = AdMap.of(AD_ROLE_MAP, [(_G, "viewer"), (_H, "custom-1")])
    assert _apply(AdMap.of(AD_ROLE_MAP, []), replacement) is replacement


def test_an_edit_drops_a_left_behind_pair_rather_than_refusing() -> None:
    """A role delete edits the map with ``without_value``; a pair a deleted role left behind must
    not refuse that edit, and is not written back, sealed."""
    current = AdMap.of(AD_ROLE_MAP, [(_G, "viewer"), (_H, "gone"), (_H, "custom-1")])
    after = _apply(current, lambda m: m.without_value("custom-1"))
    assert after.pairs == ((_G, "viewer"),)


def test_an_edit_may_not_re_add_a_left_behind_id_to_another_group() -> None:
    """Only the exact pair the map already held counts as left behind; the same dead id under a
    new group is an addition, and refused."""
    current = AdMap.of(AD_ROLE_MAP, [(_H, "gone")])
    with pytest.raises(UnknownRoleError):
        _apply(current, lambda m: AdMap.of(AD_ROLE_MAP, [*m.pairs, (_G, "gone")]))


def test_a_replacement_resubmitting_a_left_behind_pair_is_refused() -> None:
    """An administrator's save is checked whole, as the foreign key on SQLite and Postgres checks
    it: a pair the stored map already held is no exemption for a save."""
    current = AdMap.of(AD_ROLE_MAP, [(_G, "viewer"), (_H, "VIEWER")])
    with pytest.raises(UnknownRoleError):
        _apply(current, AdMap.of(AD_ROLE_MAP, [(_G, "viewer"), (_H, "VIEWER")]))


class _Cur:
    """A cursor answering the role map writer's reads, recording every statement."""

    def __init__(
        self, pairs: list[tuple[str, str]], roles: tuple[str, ...], name: str = AD_ROLE_MAP
    ) -> None:
        self.sql: list[tuple[str, tuple[Any, ...]]] = []
        self._pairs = pairs
        self._roles = roles
        self._pairs_sql = ss._MSSQL_AD_MAP_SQL[name].pairs
        self._last = ""

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.sql.append((sql, params))
        self._last = sql

    async def fetchall(self) -> list[tuple[Any, ...]]:
        if self._last.startswith("SELECT seal FROM authority_set_seal"):
            return []
        if self._last == self._pairs_sql:
            return list(self._pairs)
        if self._last == "SELECT id FROM roles":
            return [(r,) for r in self._roles]
        raise AssertionError(f"unexpected read: {self._last}")


def _store() -> SqlServerStore:
    store = SqlServerStore.__new__(SqlServerStore)
    store._row_sealer = None
    return store


@pytest.mark.parametrize("bogus", ["VIEWER", "viewer ", "no-such-role"])
async def test_the_sql_server_writer_refuses_before_it_writes(bogus: str) -> None:
    cur = _Cur([(_G, "viewer")], _PRESENT)
    with pytest.raises(UnknownRoleError):
        await _store()._write_ad_map(
            cur, AD_ROLE_MAP, AdMap.of(AD_ROLE_MAP, [(_G, "viewer"), (_H, bogus)])
        )
    writes = [s for s, _ in cur.sql if not s.lstrip().upper().startswith("SELECT")]
    assert writes == [], "nothing may be cleared, inserted or sealed"


async def test_the_sql_server_writer_writes_known_ids() -> None:
    """The control for the refusal above: the same write with an exact id clears, inserts each
    pair, and seals."""
    cur = _Cur([(_G, "viewer")], _PRESENT)
    wrote = await _store()._write_ad_map(
        cur, AD_ROLE_MAP, AdMap.of(AD_ROLE_MAP, [(_G, "viewer"), (_H, "operator")])
    )
    assert wrote is True
    sql = ss._MSSQL_AD_MAP_SQL[AD_ROLE_MAP]
    assert (sql.insert, (_H, "operator")) in cur.sql
    assert any(s == ss._MSSQL_SET_SEAL_MERGE for s, _ in cur.sql)


async def test_the_scope_map_writer_reads_no_roles() -> None:
    """The exact check is the role map's: a channel is not a role id."""
    cur = _Cur([], (), AD_SCOPE_MAP)
    await _store()._write_ad_map(cur, AD_SCOPE_MAP, AdMap.of(AD_SCOPE_MAP, [(_G, "IB_A")]))
    assert all(s != "SELECT id FROM roles" for s, _ in cur.sql)


def test_the_map_read_counts_a_pair_live_only_on_an_exact_role_id() -> None:
    read = ss._MSSQL_AD_MAP_SQL[AD_ROLE_MAP].read
    assert (
        " FROM ad_group_role_map m LEFT JOIN roles r ON r.id = m.role_id"
        " AND r.id = m.role_id COLLATE Latin1_General_100_BIN2"
        " AND DATALENGTH(r.id) = DATALENGTH(m.role_id)"
    ) in read


def test_the_schema_declares_the_role_foreign_key_and_its_index() -> None:
    flat = [" ".join(s.split()) for s in ss._SCHEMA]
    fk = (
        "IF OBJECT_ID('fk_ad_group_role_map_role','F') IS NULL ALTER TABLE ad_group_role_map"
        " WITH NOCHECK ADD CONSTRAINT fk_ad_group_role_map_role FOREIGN KEY (role_id)"
        " REFERENCES roles(id)"
    )
    assert fk in flat
    table = next(i for i, s in enumerate(flat) if "CREATE TABLE ad_group_role_map" in s)
    roles = next(i for i, s in enumerate(flat) if "CREATE TABLE roles (" in s)
    assert roles < table < flat.index(fk), "the key needs both tables first"
    assert (
        "IF INDEXPROPERTY(OBJECT_ID('ad_group_role_map'),'ix_ad_group_role_map_role','IndexID')"
        " IS NULL CREATE INDEX ix_ad_group_role_map_role ON ad_group_role_map(role_id)"
    ) in flat


@pytest.mark.parametrize("asked", ["custom:ABC", "custom:abc "])
async def test_a_role_delete_by_a_variant_id_deletes_nothing(asked: str) -> None:
    """The roles lookup compares in the database collation and finds the stored role for a variant
    id; the caller's holder and session reads matched the variant, not it, so the delete is refused
    as no such role rather than removing a role whose holders nobody revoked."""
    ops: list[str] = []

    class _DelCur:
        async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            ops.append(sql)

        async def fetchone(self) -> tuple[Any, ...]:
            return (0, "custom:abc")  # builtin = 0, the stored id

    class _Conn:
        async def rollback(self) -> None:
            ops.append("ROLLBACK")

    store = _store()

    @asynccontextmanager
    async def acquire() -> AsyncIterator[_Conn]:
        yield _Conn()

    @asynccontextmanager
    async def cursor(conn: Any) -> AsyncIterator[_DelCur]:
        yield _DelCur()

    store._acquire = acquire  # type: ignore[method-assign]
    store._cursor = cursor  # type: ignore[method-assign]
    assert await store.delete_custom_role(asked) is False
    assert ops == ["SELECT builtin, id FROM roles WHERE id=?", "ROLLBACK"]
