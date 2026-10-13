# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The sealed user record on SQLite, and the static guards that keep it whole (BACKLOG #2592).

The behavioural contract is ``tests/_user_seal_contract.py``; the Postgres and SQL Server suites
run the same one on their own legs. This file runs it on SQLite, and adds what only one place needs
to hold: the columns the seal leaves out, the single loader in the service, the one place the
checked type is built, the list of every statement that writes the user tables, ``rotate-key``'s
re-seal, and what a keyed store does with a row written before the seal.
"""

from __future__ import annotations

import ast
import logging
import pathlib
import sqlite3
import time
from collections.abc import AsyncIterator
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AUTHORITY_SEAL_FAILED_ACTION, AuthService
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import (
    PASSKEY_DIGEST_EXCLUDED,
    USER_SEAL_EXCLUDED,
    MessageStore,
    RoleGrant,
    UnknownRoleError,
    UserAuthzRecord,
    UserRow,
    existing_roles_only,
    user_seal_ok,
)
from tests._user_seal_contract import (
    assert_user_columns,
    assert_user_record_round_trips,
    assert_user_seal_contract,
)

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_STORE_DIR = _ROOT / "messagefoundry" / "store"
_SERVICE = _ROOT / "messagefoundry" / "auth" / "service.py"


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


async def _user(store: MessageStore, user_id: str) -> None:
    await store.create_user(
        user_id=user_id, username=user_id, auth_provider="local", password_generated=False
    )


async def test_the_user_seal_contract_holds_on_sqlite(keyed: tuple[MessageStore, Path]) -> None:
    store, path = keyed
    await assert_user_seal_contract(store, _raw_for(path))


async def test_the_contract_fails_when_the_service_checks_no_seal(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the contract: with the service's seal check switched off it must fail, so
    a green contract is evidence that the check runs."""
    import messagefoundry.auth.service as service_module

    store, path = keyed
    monkeypatch.setattr(service_module, "user_seal_ok", lambda sealer, record: True)
    with pytest.raises(AssertionError):
        await assert_user_seal_contract(store, _raw_for(path))


async def test_the_record_round_trips_unchanged_on_sqlite(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, _ = keyed
    await assert_user_record_round_trips(store)


def test_the_columns_a_user_seal_leaves_out_are_pinned() -> None:
    # A change here is a decision about what a writer may alter unseen; it needs a reason beside it.
    assert dict(USER_SEAL_EXCLUDED).keys() == {"authz_seal"}
    assert dict(PASSKEY_DIGEST_EXCLUDED).keys() == {"sign_count", "last_used_at"}
    assert all(USER_SEAL_EXCLUDED.values()) and all(PASSKEY_DIGEST_EXCLUDED.values())


def test_a_user_seal_covers_every_other_field_by_default() -> None:
    row = UserRow(**{f.name: _sample(f.type) for f in fields(UserRow)})
    covered = [name for name, _ in UserAuthzRecord(row=row).seal_fields()]
    expected = [f.name for f in fields(UserRow) if f.name not in USER_SEAL_EXCLUDED]
    assert covered[: len(expected)] == expected
    # Then the role rows, counted.
    assert "totp_secret" in covered
    assert covered[len(expected) :] == ["roles"]


def _sample(annotation: object) -> Any:
    text = str(annotation)
    if "bool" in text:
        return False
    if "int" in text:
        return 0
    if "float" in text:
        return 0.0
    return "x"


def _with_roles(*role_ids: str) -> UserAuthzRecord:
    row = UserRow(**{f.name: _sample(f.type) for f in fields(UserRow)})
    return UserAuthzRecord.of(row, [RoleGrant(r, 1.0, "t") for r in role_ids])


def test_a_role_write_refuses_an_added_role_with_no_roles_row() -> None:
    """BACKLOG #2592: an id the write adds, with no ``roles`` row, is refused before anything is
    sealed. Control: the same write with the row present passes unchanged."""
    current = _with_roles("viewer")
    changed = _with_roles("viewer", "custom:gone")
    with pytest.raises(UnknownRoleError) as refused:
        existing_roles_only(current, changed, ["viewer", "operator"])
    assert refused.value.role_ids == ("custom:gone",)
    assert existing_roles_only(current, changed, ["viewer", "custom:gone"]) is changed


def test_a_role_row_left_behind_by_a_deleted_role_is_dropped_not_written_back(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #2592: a held id with no ``roles`` row grants nothing, so the next role write drops
    it, and logs the drop, rather than refusing the account's every role change. The added id
    still goes through."""
    current = _with_roles("viewer", "custom:gone")
    changed = _with_roles("viewer", "custom:gone", "operator")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        kept = existing_roles_only(current, changed, ["viewer", "operator"])
    assert kept.role_ids == ("operator", "viewer")
    assert kept.row == changed.row
    assert "dropped 1 role row" in caplog.text


async def test_the_user_row_matches_the_users_table(keyed: tuple[MessageStore, Path]) -> None:
    _, path = keyed
    conn = sqlite3.connect(path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    finally:
        conn.close()
    assert_user_columns(columns)


async def test_a_refused_account_is_audited_and_alerted_once_per_interval(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, path = keyed
    alerts: list[str] = []
    service = AuthService(store, AuthSettings(), integrity_alert=alerts.append)
    await _user(store, "u")
    assert await service._load_user("u") is not None
    assert alerts == []  # control
    await _raw_for(path)("UPDATE users SET display_name=? WHERE id=?", ("Changed", "u"))
    for _ in range(3):
        assert await service._load_user("u") is None
    assert len(alerts) == 1 and "u" in alerts[0]
    assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1


async def test_a_keyless_store_writes_no_seal_and_checks_none(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "plain.db")
    try:
        assert store.row_sealer() is None
        await _user(store, "u")
        user = await store.get_user("u")
        assert user is not None and user.row is not None and user.row.authz_seal == ""
        service = AuthService(store, AuthSettings())
        assert await service._load_user("u") is not None
    finally:
        await store.close()


async def test_a_key_rotation_reseals_every_account_under_the_active_key(tmp_path: Path) -> None:
    """A user seal verifies under a retired key the process holds, so an account keeps resolving
    after a key change; ``rotate-key``'s pass then re-seals it under the active key, so dropping
    the retired key afterwards locks nobody out. The control is a store given only the new key
    before that pass: the account is refused there."""
    old, new = generate_key(), generate_key()
    path = tmp_path / "rotated.db"
    store = await MessageStore.open(path, cipher=make_cipher(old, write_v2=True))
    try:
        await AuthService(store, AuthSettings()).initialize()  # the built-in roles
        await _user(store, "u")
        await store.set_user_roles("u", [Role.VIEWER.value])
        await store.set_totp_secret("u", secret="JBSWY3DPEHPK3PXP")
    finally:
        await store.close()

    only_new = await MessageStore.open(path, cipher=make_cipher(new, write_v2=True))
    try:
        assert await AuthService(only_new, AuthSettings())._load_user("u") is None  # control
    finally:
        await only_new.close()

    rotated = await MessageStore.open(path, cipher=make_cipher(new, [old], write_v2=True))
    try:
        sealer = rotated.row_sealer()
        assert sealer is not None
        before = await rotated.get_user("u")
        assert before is not None and before.row is not None
        assert not sealer.is_active(before.row.authz_seal)
        assert await AuthService(rotated, AuthSettings())._load_user("u") is not None
        await rotated.reencrypt_to_active()
        after = await rotated.get_user("u")
        assert after is not None and after.row is not None
        assert sealer.is_active(after.row.authz_seal)
    finally:
        await rotated.close()

    dropped = await MessageStore.open(path, cipher=make_cipher(new, write_v2=True))
    try:
        loaded = await AuthService(dropped, AuthSettings())._load_user("u")
        assert loaded is not None and loaded.role_ids == (Role.VIEWER.value,)
        # The secret was re-encrypted with the seal, so it still opens without the old key.
        assert await dropped.get_totp_secret("u") == "JBSWY3DPEHPK3PXP"
    finally:
        await dropped.close()


async def test_the_last_administrator_guard_counts_only_sealed_administrators(
    keyed: tuple[MessageStore, Path],
) -> None:
    """The store's last-administrator backstop counts another administrator only when its record
    passes its seal, as the service's own enumerations do; the control is the same removal with
    the other administrator intact."""
    from messagefoundry.store.store import AdminRemoval

    store, path = keyed
    await AuthService(store, AuthSettings()).initialize()
    for name in ("a", "b"):
        await _user(store, name)
        await store.set_user_roles(name, [Role.ADMINISTRATOR.value])

    async def removable(target: str) -> bool:
        return await store.remove_unless_last_admin(
            target,
            AdminRemoval.SET_ROLES,
            admin_role_id=Role.ADMINISTRATOR.value,
            role_ids=[Role.VIEWER.value],
        )

    await _raw_for(path)("UPDATE users SET display_name=? WHERE id=?", ("bent", "b"))
    assert not await removable("a")  # b is refused, so a is the last usable administrator
    await _user(store, "c")
    await store.set_user_roles("c", [Role.ADMINISTRATOR.value])
    assert await removable("a")  # control: c is a sealed administrator


async def test_a_row_written_before_the_seal_is_refused_and_named_at_open(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A keyed store treats a blank seal as a failed one: a blank seal is exactly what a row
    inserted outside the store carries, so nothing seals it at open. The open names how many such
    accounts there are, and ``provision-admin`` refuses to repair one but accepts a new name."""
    path = tmp_path / "legacy.db"
    key = generate_key()
    store = await MessageStore.open(path, cipher=make_cipher(key, write_v2=True))
    try:
        await _user(store, "sealed")
    finally:
        await store.close()
    await _raw_for(path)(
        "INSERT INTO users (id, username, auth_provider, created_at, updated_at, notify_email)"
        " VALUES (?,?,?,?,?,?)",
        ("legacy", "legacy", "local", time.time(), time.time(), None),
    )
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        reopened = await MessageStore.open(path, cipher=make_cipher(key, write_v2=True))
    try:
        warned = [r.getMessage() for r in caplog.records if "integrity seal" in r.getMessage()]
        assert len(warned) == 1 and warned[0].startswith("1 user account")
        service = AuthService(reopened, AuthSettings())
        assert await service._load_user("legacy") is None
        assert await service._load_user("sealed") is not None  # control
        refusal = await service.provision_refusal("legacy", notify_email="ops@example.test")
        assert refusal is not None and "integrity seal" in refusal
        assert await service.provision_refusal("fresh", notify_email="ops@example.test") is None
    finally:
        await reopened.close()


async def test_a_session_resolves_with_one_role_read(keyed: tuple[MessageStore, Path]) -> None:
    """AC-18: the identity build reads the role rows the loader checked, so resolving a request
    reads the role rows once and the bare role-id reader not at all."""
    store, _ = keyed
    service = AuthService(store, AuthSettings())
    await service.initialize()
    await _user(store, "u")
    await store.set_user_roles("u", [Role.VIEWER.value])
    token = mint_token()
    await store.create_session(
        token_hash=hash_token(token), user_id="u", expires_at=time.time() + 3600
    )
    counts: dict[str, int] = {}
    for name in ("get_user", "get_user_role_ids", "get_user_role_grants", "get_session"):
        original = getattr(store, name)

        def counted(*args: Any, _name: str = name, _original: Any = original, **kw: Any) -> Any:
            counts[_name] = counts.get(_name, 0) + 1
            return _original(*args, **kw)

        setattr(store, name, counted)
    assert await service.identity_for_token(token) is not None
    assert counts == {"get_session": 1, "get_user": 1, "get_user_role_grants": 1}


# --- static guards --------------------------------------------------------------------------

_USER_READERS = frozenset(
    {
        "get_user",
        "get_user_by_username",
        "get_user_by_federated_subject",
        "get_user_by_directory_object_id",
        "list_users",
        "get_user_role_ids",
        "get_user_role_grants",
        "get_recovery_code_hashes",
        "list_webauthn_credentials",
    }
)
#: The service functions allowed to call a raw user reader, and why each needs it.
_LOADERS: dict[str, frozenset[str]] = {
    "_load_user": frozenset({"get_user"}),
    "_lookup_by_username": frozenset({"get_user_by_username"}),
    "_lookup_by_directory_object_id": frozenset({"get_user_by_directory_object_id"}),
    "_load_user_by_federated_subject": frozenset({"get_user_by_federated_subject"}),
    "_load_users": frozenset({"list_users"}),
    # The role rows, and one re-read by id before a failing pair is reported.
    "_verified": frozenset({"get_user_role_grants", "get_user"}),
    "_verified_passkeys": frozenset({"list_webauthn_credentials"}),
    # Existence questions: only a bool leaves them, never the unchecked row.
    "_username_held": frozenset({"get_user_by_username"}),
    "_directory_object_id_held": frozenset({"get_user_by_directory_object_id"}),
    # A count for the holder's notice after a code is spent; it decides nothing.
    "_verify_second_factor": frozenset({"get_recovery_code_hashes"}),
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
                and node.attr in _USER_READERS
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "_store"
            ):
                found.append((func.name, node.attr))
    return found


def test_the_service_reads_users_through_its_loaders() -> None:
    """A raw user read outside the loaders would act on a record nobody checked."""
    calls = _service_reader_calls()
    # Liveness, before the absence check: the walk finds every loader's own read, so it is reading
    # this file, and an empty walk cannot pass for a clean one. A subset rather than an equality, so
    # a stray read in a new function still reaches the stray check below and is named there.
    assert len(calls) >= len(_LOADERS), calls
    assert set(_LOADERS) <= {f for f, _ in calls}, set(_LOADERS) - {f for f, _ in calls}
    stray = [(f, r) for f, r in calls if r not in _LOADERS.get(f, frozenset())]
    assert not stray, stray


def test_only_the_loader_builds_a_checked_user() -> None:
    tree = ast.parse(_SERVICE.read_text("utf-8"))
    builders = [
        func.name
        for func in ast.walk(tree)
        if isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
        for node in ast.walk(func)
        if isinstance(node, ast.Attribute)
        and node.attr == "of"
        and isinstance(node.value, ast.Name)
        and node.value.id == "VerifiedUser"
    ]
    assert builders == ["_verified"]


#: Where each backend may write the user tables: each sealing statement, and the functions that
#: may name it. ``add_webauthn_credential`` hands its INSERT to ``_write_passkeys``, which re-seals.
_SEALING: dict[str, dict[str, frozenset[str]]] = {
    "store.py": {
        "_USER_INSERT": frozenset({"create_user"}),
        "_USER_RESEAL": frozenset({"_write_user"}),
        "_USER_ROLE_INSERT": frozenset({"_write_user"}),
        "_WEBAUTHN_INSERT": frozenset({"add_webauthn_credential"}),
    },
    "postgres.py": {
        "_PG_USER_INSERT": frozenset({"create_user"}),
        "_PG_USER_RESEAL": frozenset({"_write_user"}),
        "_PG_USER_ROLE_INSERT": frozenset({"_write_user"}),
        "_PG_WEBAUTHN_INSERT": frozenset({"add_webauthn_credential"}),
    },
    "sqlserver.py": {
        "_MSSQL_USER_INSERT": frozenset({"create_user"}),
        "_MSSQL_USER_RESEAL": frozenset({"_write_user"}),
        "_USER_ROLE_INSERT": frozenset({"_write_user"}),
        "_WEBAUTHN_INSERT": frozenset({"add_webauthn_credential"}),
    },
}
_TABLES = ("USERS", "USER_ROLES", "WEBAUTHN_CREDENTIALS")
#: Migration functions that may backfill a column they have just added, before any seal exists.
_MIGRATIONS = frozenset({"_migrate", "_migrate_lease_columns"})


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


def _user_write(text: str) -> str | None:
    """``"insert"``/``"update"`` for a write to a user table, ``"delete"`` for a delete, else
    ``None``. A delete destroys a seal and needs no key, so it may sit anywhere."""
    flat = " ".join(text.upper().split())
    for verb, kind in (("INSERT INTO ", "insert"), ("UPDATE ", "update"), ("MERGE ", "update")):
        for table in _TABLES:
            if flat.startswith(verb + table + " ") or flat.startswith(verb + table + "("):
                return kind
    for table in _TABLES:
        if flat.startswith(f"DELETE FROM {table} "):
            return "delete"
    return None


def _allowed_unsealed(text: str, func: str | None) -> bool:
    flat = " ".join(text.split())
    if (
        flat.startswith("UPDATE webauthn_credentials SET sign_count=")
        and flat.split("WHERE")[0].count(",") == 1
    ):
        return True  # the two columns the passkey digest leaves out
    return func in _MIGRATIONS and (
        "password_claimed_at = password_changed_at" in flat or "notify_email = email" in flat
    )


def _scan(source: str, sealing: dict[str, frozenset[str]]) -> tuple[list[str], set[str]]:
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
        parent = parents.get(node)
        if isinstance(parent, ast.Assign) and isinstance(parent.targets[0], ast.Name):
            return parent.targets[0].id
        if isinstance(parent, ast.AnnAssign) and isinstance(parent.target, ast.Name):
            return parent.target.id
        return None

    problems: list[str] = []
    kinds: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.expr) or isinstance(parents.get(node), ast.BinOp):
            continue
        text = _literal_text(node)
        kind = None if text is None else _user_write(text)
        if text is None or kind is None:
            continue
        kinds.add(kind)
        func = enclosing(node)
        if kind == "delete":
            continue
        if func is None and assigned_name(node) in sealing:
            continue
        if _allowed_unsealed(text, func):
            kinds.add("listed")
            continue
        problems.append(f"{func or 'module'}: an unsealed user-table write: {text[:70]}")
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
    return problems, kinds


@pytest.mark.parametrize("module", sorted(_SEALING))
def test_every_user_table_write_is_sealed_or_listed(module: str) -> None:
    source = (_STORE_DIR / module).read_text("utf-8")
    problems, kinds = _scan(source, _SEALING[module])
    assert not problems, "\n".join(problems)
    # Liveness: the scan finds this backend's sealing re-write, its deletes and its listed writes.
    # SQL Server binds store.py's role and passkey INSERTs rather than spelling them, so each sealing
    # statement is also checked to be named in a function here.
    assert {"update", "delete", "listed"} <= kinds, f"{module}: {kinds}"
    used = {n.id for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Name)}
    assert set(_SEALING[module]) <= used, f"{module}: {set(_SEALING[module]) - used}"


def test_the_write_scan_catches_an_unsealed_write() -> None:
    planted = (
        "async def set_scope(self, u):\n"
        "    await self._db.execute('UPDATE users SET channel_scope=? WHERE id=?', (1, u))\n"
        "async def add_role(self, u):\n"
        "    await self._db.execute('INSERT INTO user_roles (user_id) VALUES (?)', (u,))\n"
        "async def stray(self):\n"
        "    await self._db.execute(_USER_RESEAL, ())\n"
    )
    problems, _ = _scan(planted, {"_USER_RESEAL": frozenset({"_write_user"})})
    assert len(problems) == 3, problems


async def test_a_record_that_fails_is_not_resealed_by_a_check(
    keyed: tuple[MessageStore, Path],
) -> None:
    """``user_seal_ok`` is a pure check: a record whose seal fails stays failing after it."""
    store, _ = keyed
    sealer = store.row_sealer()
    assert sealer is not None
    row = UserRow(**{f.name: _sample(f.type) for f in fields(UserRow)})
    record = UserAuthzRecord(row=row)
    assert not user_seal_ok(sealer, record)
    assert not user_seal_ok(sealer, record)
