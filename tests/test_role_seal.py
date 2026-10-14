# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Sealed role definitions and the two sealed AD directory maps on SQLite, and the static guards
that keep them whole (BACKLOG #2592).

The behavioural contract is ``tests/_role_seal_contract.py``; the Postgres and SQL Server suites
run the same one on their own legs. This file runs it on SQLite, and adds what only one place needs
to hold: the column the role seal leaves out, the role table's columns, the loaders in the service,
the list of every statement that writes the role and map tables, ``rotate-key``'s re-seal, and what
a keyed store does with a role written before the seal.
"""

from __future__ import annotations

import ast
import json
import logging
import pathlib
import sqlite3
from collections.abc import AsyncIterator
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import (
    AD_ROLE_MAP,
    AD_SCOPE_MAP,
    ROLE_SEAL_EXCLUDED,
    MessageStore,
    RoleRow,
    ad_map_seal_ok,
    role_seal_ok,
)
from tests._role_seal_contract import assert_role_seal_contract

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_STORE_DIR = _ROOT / "messagefoundry" / "store"
_SERVICE = _ROOT / "messagefoundry" / "auth" / "service.py"
_GROUP = "cn=ops,dc=example,dc=test"


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, Path]]:
    path = tmp_path / "sealed.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        yield store, path
    finally:
        await store.close()


def _raw_for(path: Path) -> Any:
    """Runs one statement on its own stdlib connection, which holds no store key."""

    async def raw(sql: str, params: tuple[Any, ...]) -> None:
        conn = sqlite3.connect(path)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    return raw


async def test_the_role_seal_contract_holds_on_sqlite(keyed: tuple[MessageStore, Path]) -> None:
    store, path = keyed
    await assert_role_seal_contract(store, _raw_for(path))


@pytest.mark.parametrize("check", ["role_seal_ok", "ad_map_seal_ok"])
async def test_the_contract_fails_when_the_service_checks_no_seal(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch, check: str
) -> None:
    """The control for the contract: with either of the service's checks switched off it must
    fail, so a green contract is evidence that both checks run."""
    import messagefoundry.auth.service as service_module

    store, path = keyed
    monkeypatch.setattr(service_module, check, lambda sealer, row: True)
    with pytest.raises(AssertionError):
        await assert_role_seal_contract(store, _raw_for(path))


def test_the_columns_a_role_seal_leaves_out_are_pinned() -> None:
    # A change here is a decision about what a writer may alter unseen; it needs a reason beside it.
    assert dict(ROLE_SEAL_EXCLUDED).keys() == {"seal"}


def test_a_role_seal_covers_every_other_field() -> None:
    row = RoleRow("custom:x", "X", None, False, "[]", "")
    assert [name for name, _ in row.seal_fields()] == [
        f.name for f in fields(RoleRow) if f.name not in ROLE_SEAL_EXCLUDED
    ]


async def test_the_role_row_matches_the_roles_table(keyed: tuple[MessageStore, Path]) -> None:
    _, path = keyed
    conn = sqlite3.connect(path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(roles)")}
        set_columns = {row[1] for row in conn.execute("PRAGMA table_info(authority_set_seal)")}
    finally:
        conn.close()
    assert columns == {f.name for f in fields(RoleRow)}
    assert set_columns == {"name", "seal"}


async def test_a_builtin_row_with_a_custom_id_is_not_edited_or_deleted_as_custom(
    keyed: tuple[MessageStore, Path],
) -> None:
    """The service's custom-role test reads the ``builtin`` column as the store does, so a row the
    store treats as built-in is never rewritten as custom, nor reported deleted when it was not."""
    store, path = keyed
    service = AuthService(store, AuthSettings())
    await service.initialize()
    role = await service.create_custom_role(
        display_name="Flagged", description=None, permissions=["messages:replay"], actor="admin"
    )
    await service.update_custom_role(  # control: a custom row is edited
        role.id,
        display_name="Flagged",
        description="ok",
        permissions=["messages:replay"],
        actor="admin",
    )
    await _raw_for(path)("UPDATE roles SET builtin=1 WHERE id=?", (role.id,))
    for act in (
        service.update_custom_role(
            role.id,
            display_name="Flagged",
            description=None,
            permissions=["messages:replay"],
            actor="admin",
        ),
        service.delete_custom_role(role.id, actor="admin"),
    ):
        with pytest.raises(ValueError, match="no such custom role"):
            await act
    found = await store.get_role(role.id)
    assert found is not None and bool(found["builtin"])
    assert await store.list_audit(action="role.deleted") == []


async def test_a_keyless_store_writes_no_seal_and_checks_none(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "plain.db")
    try:
        assert store.row_sealer() is None
        service = AuthService(store, AuthSettings())
        await service.initialize()
        role = await service.create_custom_role(
            display_name="r", description=None, permissions=["messages:replay"], actor="t"
        )
        found = await store.get_role(role.id)
        assert found is not None and RoleRow.from_mapping(found).seal == ""
        assert await service._load_role(role.id) is not None
        await store.set_ad_group_role_map([(_GROUP, Role.VIEWER.value)])
        assert (await store.get_ad_map(AD_ROLE_MAP)).seal == ""
        assert await service._ad_roles_for_groups([_GROUP]) == {Role.VIEWER.value}
        await store.set_ad_group_scope_map([(_GROUP, "IB_A")])
        assert (await store.get_ad_map(AD_SCOPE_MAP)).seal == ""
        assert await service._ad_channels_for_groups([_GROUP]) == frozenset({"IB_A"})
    finally:
        await store.close()


async def test_a_key_rotation_reseals_roles_and_the_map_under_the_active_key(
    tmp_path: Path,
) -> None:
    """A role or map seal verifies under a retired key the process holds; ``rotate-key``'s pass
    re-seals it under the active key, so dropping the retired key afterwards denies nothing. The
    control is a store given only the new key before that pass: both grant nothing there."""
    old, new = generate_key(), generate_key()
    path = tmp_path / "rotated.db"
    store = await MessageStore.open(path, cipher=make_cipher(old, write_v2=True))
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        role_id = (
            await service.create_custom_role(
                display_name="r", description=None, permissions=["messages:replay"], actor="t"
            )
        ).id
        await store.set_ad_group_role_map([(_GROUP, Role.VIEWER.value)])
        await store.set_ad_group_scope_map([(_GROUP, "IB_A")])
    finally:
        await store.close()

    only_new = await MessageStore.open(path, cipher=make_cipher(new, write_v2=True))
    try:
        service = AuthService(only_new, AuthSettings())
        assert await service._load_role(role_id) is None  # control
        assert await service._ad_roles_for_groups([_GROUP]) == set()  # control
        assert await service._ad_channels_for_groups([_GROUP]) == frozenset()  # control
    finally:
        await only_new.close()

    rotated = await MessageStore.open(path, cipher=make_cipher(new, [old], write_v2=True))
    try:
        sealer = rotated.row_sealer()
        assert sealer is not None
        service = AuthService(rotated, AuthSettings())
        assert await service._load_role(role_id) is not None
        assert await service._ad_roles_for_groups([_GROUP]) == {Role.VIEWER.value}
        await rotated.reencrypt_to_active()  # rotate-key's store pass, which runs the re-seal
        found = await rotated.get_role(role_id)
        assert found is not None and sealer.is_active(RoleRow.from_mapping(found).seal)
        for name in (AD_ROLE_MAP, AD_SCOPE_MAP):
            assert sealer.is_active((await rotated.get_ad_map(name)).seal), name
    finally:
        await rotated.close()

    dropped = await MessageStore.open(path, cipher=make_cipher(new, write_v2=True))
    try:
        service = AuthService(dropped, AuthSettings())
        assert await service._load_role(role_id) is not None
        assert await service._ad_roles_for_groups([_GROUP]) == {Role.VIEWER.value}
        assert await service._ad_channels_for_groups([_GROUP]) == frozenset({"IB_A"})
    finally:
        await dropped.close()


async def test_rotation_leaves_a_failing_role_and_map_as_they_are(
    keyed: tuple[MessageStore, Path],
) -> None:
    """The re-seal pass checks each row under the key it names before it re-seals it, so a row
    changed outside the store is counted and left failing. The control is the role the store
    wrote, which still verifies beside it."""
    store, path = keyed
    sealer = store.row_sealer()
    assert sealer is not None
    service = AuthService(store, AuthSettings())
    await service.initialize()
    good = (
        await service.create_custom_role(
            display_name="good", description=None, permissions=["messages:replay"], actor="t"
        )
    ).id
    bad = (
        await service.create_custom_role(
            display_name="bad", description=None, permissions=["messages:replay"], actor="t"
        )
    ).id
    await store.set_ad_group_role_map([(_GROUP, Role.VIEWER.value)])
    await store.set_ad_group_scope_map([(_GROUP, "IB_A")])
    raw = _raw_for(path)
    # Name a key the process does not hold as active, so each row is due for a re-seal.
    foreign = f"mfseal:v1:not-this-key:{'0' * 64}"
    await raw("UPDATE roles SET seal=? WHERE id=?", (foreign, bad))
    for name in (AD_ROLE_MAP, AD_SCOPE_MAP):
        await raw("UPDATE authority_set_seal SET seal=? WHERE name=?", (foreign, name))
    # The good role's seal and the built-in rows' name the active key, so they have no work.
    resealed, refused = await store.reseal_role_records()
    assert (resealed, refused) == (0, 3)
    bad_row = await store.get_role(bad)
    assert bad_row is not None and RoleRow.from_mapping(bad_row).seal == foreign
    for name in (AD_ROLE_MAP, AD_SCOPE_MAP):
        assert not ad_map_seal_ok(sealer, await store.get_ad_map(name)), name
    good_row = await store.get_role(good)
    assert good_row is not None and role_seal_ok(sealer, RoleRow.from_mapping(good_row))


async def test_a_role_written_before_the_seal_is_named_at_open_and_repaired_by_a_save(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A keyed store treats a blank seal as a failed one, so nothing seals a role at open. The open
    names how many custom roles and maps carry none; an administrator saving the role again seals
    it, which is the repair route."""
    path = tmp_path / "legacy.db"
    key = generate_key()
    store = await MessageStore.open(path, cipher=make_cipher(key, write_v2=True))
    try:
        await AuthService(store, AuthSettings()).initialize()
    finally:
        await store.close()
    await _raw_for(path)(
        "INSERT INTO roles (id, display_name, description, builtin, permissions)"
        " VALUES (?,?,?,?,?)",
        ("custom:legacy", "Legacy", None, 0, json.dumps(["messages:replay"])),
    )
    await _raw_for(path)(
        "INSERT INTO ad_group_role_map (ad_group, role_id) VALUES (?,?)", (_GROUP, "viewer")
    )
    await _raw_for(path)(
        "INSERT INTO ad_group_scope_map (ad_group, channel) VALUES (?,?)", (_GROUP, "IB_A")
    )
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        reopened = await MessageStore.open(path, cipher=make_cipher(key, write_v2=True))
    try:
        warned = [r.getMessage() for r in caplog.records if "integrity seal" in r.getMessage()]
        assert len(warned) == 1 and warned[0].startswith("3 custom role(s) or directory map(s)")
        service = AuthService(reopened, AuthSettings())
        assert await service._load_role("custom:legacy") is None
        assert await service._ad_roles_for_groups([_GROUP]) == set()
        assert await service._ad_channels_for_groups([_GROUP]) == frozenset()
        await service.update_custom_role(
            "custom:legacy",
            display_name="Legacy",
            description=None,
            permissions=["messages:replay"],
            actor="admin",
        )
        await service.set_ad_group_map([(_GROUP, Role.VIEWER.value)], actor="admin")
        await service.set_ad_group_scope_map([(_GROUP, "IB_A")], actor="admin")
        assert await service._load_role("custom:legacy") is not None
        assert await service._ad_roles_for_groups([_GROUP]) == {Role.VIEWER.value}
        assert await service._ad_channels_for_groups([_GROUP]) == frozenset({"IB_A"})
        assert await reopened.count_unsealed_role_records() == 0
    finally:
        await reopened.close()


# --- static guards --------------------------------------------------------------------------

_ROLE_READERS = frozenset(
    {
        "get_role",
        "list_roles",
        "get_ad_map",
        "roles_for_ad_groups",
        "channels_for_ad_groups",
        "list_ad_group_role_map",
        "list_ad_group_scope_map",
    }
)
#: The service functions allowed to call a raw role or map reader.
_LOADERS: dict[str, frozenset[str]] = {
    "_load_role": frozenset({"get_role"}),
    "_load_custom_roles": frozenset({"list_roles"}),
    # An existence question: only a bool leaves it, never the unchecked row.
    "_custom_role_held": frozenset({"get_role"}),
    "_ad_map": frozenset({"get_ad_map"}),
}


def _service_reader_calls() -> list[tuple[str, str]]:
    tree = ast.parse(_SERVICE.read_text("utf-8"))
    found: list[tuple[str, str]] = []
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for node in ast.walk(func):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in _ROLE_READERS
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "_store"
            ):
                found.append((func.name, node.attr))
    return found


def test_the_service_reads_roles_and_the_maps_through_its_loaders() -> None:
    """A raw role or map read outside the loaders would act on a row nobody checked."""
    calls = _service_reader_calls()
    # Liveness first: the walk finds every loader's own read, so an empty walk cannot pass.
    assert len(calls) >= len(_LOADERS), calls
    assert set(_LOADERS) <= {f for f, _ in calls}, set(_LOADERS) - {f for f, _ in calls}
    stray = [(f, r) for f, r in calls if r not in _LOADERS.get(f, frozenset())]
    assert not stray, stray


#: Where each backend may write the role and map tables: each module-level statement, or table of
#: statements, and the functions that may use it. Every other INSERT, UPDATE, MERGE or DELETE must
#: sit inside a helper or on the delete list below.
_SEALING: dict[str, dict[str, frozenset[str]]] = {
    "store.py": {
        "_ROLE_UPSERT": frozenset({"_write_role"}),
        "_AD_ROLE_MAP_CLEAR": frozenset({"_write_ad_map"}),
        "_AD_ROLE_MAP_INSERT": frozenset({"_write_ad_map"}),
        "_AD_SCOPE_MAP_CLEAR": frozenset({"_write_ad_map"}),
        "_AD_SCOPE_MAP_INSERT": frozenset({"_write_ad_map"}),
    },
    "postgres.py": {
        "_PG_ROLE_UPSERT": frozenset({"_write_role"}),
        "_PG_AD_MAP_SQL": frozenset({"get_ad_map", "_write_ad_map"}),
    },
    "sqlserver.py": {
        "_MSSQL_ROLE_MERGE": frozenset({"_write_role"}),
        "_MSSQL_SET_SEAL_MERGE": frozenset({"_write_ad_map"}),
        "_MSSQL_AD_MAP_SQL": frozenset({"get_ad_map", "_write_ad_map"}),
    },
}
#: The helpers that may spell a write to each table inline.
_HELPERS: dict[str, frozenset[str]] = {
    "ROLES": frozenset({"_write_role"}),
    "AD_GROUP_ROLE_MAP": frozenset({"_write_ad_map"}),
    "AD_GROUP_SCOPE_MAP": frozenset({"_write_ad_map"}),
    "AUTHORITY_SET_SEAL": frozenset({"_write_ad_map"}),
}
#: Deletes, which destroy a seal and need no key, and where each may sit outside the helpers: a
#: role delete, and a role delete's removal of its pairs from a role map that already fails.
_DELETES: dict[str, frozenset[str]] = {
    "ROLES": frozenset({"delete_custom_role"}),
    "AD_GROUP_ROLE_MAP": frozenset({"delete_custom_role"}),
    "AD_GROUP_SCOPE_MAP": frozenset(),
    "AUTHORITY_SET_SEAL": frozenset(),
}


def _literal_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "{}"
            for v in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal_text(node.left), _literal_text(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _role_write(text: str) -> tuple[str, str] | None:
    """``(verb, table)`` for a write to a role or map table, else ``None``."""
    flat = " ".join(text.upper().split()) + " "  # so a statement ending at the table name matches
    for verb in ("INSERT INTO ", "UPDATE ", "MERGE ", "DELETE FROM ", "TRUNCATE TABLE "):
        for table in _HELPERS:
            if flat.startswith(verb + table + " ") or flat.startswith(verb + table + "("):
                return verb.split()[0], table
    return None


def _scan(source: str, sealing: dict[str, frozenset[str]]) -> tuple[list[str], set[str]]:
    """Every role or map write in ``source`` that is not where it may be, and the tables the scan
    found a write to."""
    tree = ast.parse(source)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def enclosing(node: ast.AST) -> str | None:
        walk: ast.AST | None = parents.get(node)
        while walk is not None:
            if isinstance(walk, ast.FunctionDef | ast.AsyncFunctionDef):
                return walk.name
            walk = parents.get(walk)
        return None

    def assigned_name(node: ast.AST) -> str | None:
        """The module-level name a statement is assigned to, through any containing literal or
        call (a statement table is a mapping of named tuples)."""
        walk: ast.AST | None = parents.get(node)
        while walk is not None and not isinstance(walk, ast.FunctionDef | ast.AsyncFunctionDef):
            if isinstance(walk, ast.Assign) and isinstance(walk.targets[0], ast.Name):
                return walk.targets[0].id
            if isinstance(walk, ast.AnnAssign) and isinstance(walk.target, ast.Name):
                return walk.target.id
            walk = parents.get(walk)
        return None

    problems: list[str] = []
    tables: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.expr) or isinstance(parents.get(node), ast.BinOp):
            continue
        text = _literal_text(node)
        write = None if text is None else _role_write(text)
        if text is None or write is None:
            continue
        verb, table = write
        tables.add(table)
        func = enclosing(node)
        if func is None and assigned_name(node) in sealing:
            continue
        if func in _HELPERS[table]:
            continue
        if verb == "DELETE" and func in _DELETES[table]:
            continue
        problems.append(f"{func or 'module'}: an unsealed {table.lower()} write: {text[:70]}")
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for inner in ast.walk(fn):
            if (
                isinstance(inner, ast.Name)
                and inner.id in sealing
                and fn.name not in sealing[inner.id]
            ):
                problems.append(f"{fn.name}: uses {inner.id} outside its sealing function")
    return problems, tables


@pytest.mark.parametrize("module", sorted(_SEALING))
def test_every_role_and_map_write_is_sealed_or_listed(module: str) -> None:
    source = (_STORE_DIR / module).read_text("utf-8")
    problems, tables = _scan(source, _SEALING[module])
    assert not problems, "\n".join(problems)
    # Liveness: the scan finds a write to every sealed table in each backend.
    assert tables == set(_HELPERS), f"{module}: writes found only to {tables}"
    used = {n.id for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Name)}
    assert set(_SEALING[module]) <= used, f"{module}: {set(_SEALING[module]) - used}"


def test_the_write_scan_catches_an_unsealed_write() -> None:
    planted = (
        "_STRAY = {'m': ('DELETE FROM ad_group_scope_map',)}\n"
        "async def widen(self, r):\n"
        "    await self._db.execute('UPDATE roles SET permissions=? WHERE id=?', ('[]', r))\n"
        "async def add_pair(self, g):\n"
        "    await self._db.execute('INSERT INTO ad_group_role_map (ad_group) VALUES (?)', (g,))\n"
        "async def drop_seal(self):\n"
        "    await self._db.execute('DELETE FROM authority_set_seal')\n"
        "async def stray(self):\n"
        "    await self._db.execute(_ROLE_UPSERT, ())\n"
    )
    problems, tables = _scan(planted, {"_ROLE_UPSERT": frozenset({"_write_role"})})
    assert tables == set(_HELPERS) and len(problems) == 5, problems
