# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A corrupt or wrongly typed cell in ``users`` or ``sessions`` fails that one row, and one in
``user_roles`` fails its whole account, as a failed seal does, rather than raising a bare parse
error that breaks every account (BACKLOG #5505).

The decoders are shared by all three backends, so the decoder tests below hold for each; the store
tests run the SQLite readers, writing the corrupt cell through a stdlib connection the way an
out-of-band edit would. Synthetic accounts only.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from _totp_clock import pin_totp_clock

from messagefoundry.auth import service as service_module
from messagefoundry.auth import totp
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import (
    AUTHORITY_SEAL_FAILED_ACTION,
    GATE_ONLY_REVOKE_ACTION,
    SESSIONS_REVOKE_FAILED_ACTION,
    AuthService,
    LastAdministratorRefused,
    UserSealRefused,
)
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import (
    SESSION_KIND,
    USER_KIND,
    RevokedRowSealError,
    RowSealer,
    RowSealError,
    TransitSealUnverifiableError,
)
from messagefoundry.store.store import (
    USER_READ_SQL,
    MessageStore,
    RoleGrant,
    SessionRecord,
    UserRecord,
    UserRow,
    _writer_guard,
    session_seal_ok,
    session_seal_ok_async,
    session_sealed_by_retired_key_async,
    user_seal_ok_async,
)
from tests._admin_account import ADMIN_USERNAME, login_admin


def _raw(path: Path, sql: str, params: tuple[Any, ...]) -> None:
    """One statement on its own stdlib connection, which holds no store key."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


async def _user(store: MessageStore, user_id: str) -> None:
    await store.create_user(
        user_id=user_id,
        username=user_id,
        auth_provider="local",
        password_generated=False,
        audits=(),
    )


async def _session(store: MessageStore, user_id: str) -> str:
    token_hash = hash_token(mint_token())
    assert await store.create_session(
        token_hash=token_hash, user_id=user_id, expires_at=time.time() + 3600
    )
    return token_hash


async def _row_mapping(store: MessageStore, table: str, key: str, value: str) -> dict[str, Any]:
    async with store._read() as db:
        cur = await db.execute(f"SELECT * FROM {table} WHERE {key}=?", (value,))
        row = await cur.fetchone()
    assert row is not None
    return dict(row)


async def test_each_decoder_answers_a_corrupt_cell_as_a_failed_seal(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "decode.db")
    try:
        await _user(store, "u-decode")
        token_hash = await _session(store, "u-decode")
        async with store._read() as db:
            cur = await db.execute(f"{USER_READ_SQL} WHERE id=?", ("u-decode",))
            user_row = dict(await cur.fetchone())  # type: ignore[arg-type]
        session_row = await _row_mapping(store, "sessions", "token_hash", token_hash)
    finally:
        await store.close()

    # Controls: the rows as written decode.
    assert UserRecord.from_mapping(user_row).id == "u-decode"
    assert UserRow.from_mapping(user_row).id == "u-decode"
    assert SessionRecord.from_mapping(session_row).token_hash == token_hash

    for decode in (UserRecord.from_mapping, UserRow.from_mapping):
        with pytest.raises(RowSealError) as caught:
            decode({**user_row, "failed_attempts": "not-a-number"})
        assert caught.value.args == (USER_KIND, "u-decode")
        # The cell's text rides on no chain.
        assert caught.value.__context__ is None and caught.value.__cause__ is None

    with pytest.raises(RowSealError) as caught_session:
        SessionRecord.from_mapping({**session_row, "created_at": "yesterday"})
    assert caught_session.value.args == (SESSION_KIND, token_hash[:12])
    assert caught_session.value.__context__ is None

    with pytest.raises(RowSealError) as caught_grant:
        RoleGrant.from_mapping({"role_id": "viewer", "assigned_at": "soon", "assigned_by": None})
    assert caught_grant.value.kind == USER_KIND

    # A missing column is a schema defect, not a corrupt cell, and still fails loudly.
    without = {k: v for k, v in user_row.items() if k != "failed_attempts"}
    with pytest.raises(KeyError):
        UserRow.from_mapping(without)


@pytest.mark.parametrize("cell", ["{not json", '{"a": 1}', "null", "[" * 100_000])
async def test_recovery_codes_that_do_not_parse_fail_the_seal(tmp_path: Path, cell: str) -> None:
    store = await MessageStore.open(tmp_path / "codes.db")
    try:
        await _user(store, "u-codes")
        async with store._read() as db:
            cur = await db.execute(f"{USER_READ_SQL} WHERE id=?", ("u-codes",))
            mapping = dict(await cur.fetchone())  # type: ignore[arg-type]
    finally:
        await store.close()
    assert UserRow.from_mapping({**mapping, "totp_recovery_codes": '["h1"]'}).recovery_code_hashes()
    row = UserRow.from_mapping({**mapping, "totp_recovery_codes": cell})
    with pytest.raises(RowSealError) as caught:
        row.recovery_code_hashes()
    assert caught.value.args == (USER_KIND, "u-codes")
    assert caught.value.__context__ is None


async def test_the_recovery_code_reader_refuses_a_corrupt_cell_too(tmp_path: Path) -> None:
    path = tmp_path / "codes-reader.db"
    store = await MessageStore.open(path)
    try:
        await _user(store, "u-r")
        _raw(path, "UPDATE users SET totp_recovery_codes=? WHERE id=?", ('["h1"]', "u-r"))
        assert await store.get_recovery_code_hashes("u-r") == ["h1"]  # control
        _raw(path, "UPDATE users SET totp_recovery_codes=? WHERE id=?", ("{not json", "u-r"))
        with pytest.raises(RowSealError) as caught:
            await store.get_recovery_code_hashes("u-r")
        assert caught.value.args == (USER_KIND, "u-r")
        assert caught.value.__context__ is None
    finally:
        await store.close()


@pytest.mark.parametrize("keyed", [False, True])
async def test_a_corrupt_account_is_listed_as_failing_beside_the_others(
    tmp_path: Path, keyed: bool
) -> None:
    path = tmp_path / "list.db"
    cipher = make_cipher(generate_key(), write_v2=True) if keyed else None
    store = await MessageStore.open(path, cipher=cipher)
    try:
        await _user(store, "u-good")
        await _user(store, "u-bad")
        _raw(path, "UPDATE users SET failed_attempts=? WHERE id=?", ("garbage", "u-bad"))
        listed_raw = {u.id: u for u in await store.list_users()}
        assert set(listed_raw) == {"u-good", "u-bad"}
        assert listed_raw["u-bad"].unreadable and listed_raw["u-bad"].disabled
        assert not listed_raw["u-good"].unreadable
        # Only the list returns the stand-in; a single-row read raises.
        with pytest.raises(RowSealError):
            await store.get_user("u-bad")
        # The admin list keeps the account, failing, on a keyless store as on a keyed one.
        service = AuthService(store, AuthSettings())
        listed = await service.list_checked_users()
        by_id = {entry.id: entry.user for entry in listed}
        assert set(by_id) == {"u-good", "u-bad"}
        assert by_id["u-good"] is not None and by_id["u-bad"] is None
        # The single-row readers answer it as a record that fails its seal, not an error.
        assert await service._load_user("u-bad") is None
        assert await service._load_user_by_username("u-bad") is None
        with pytest.raises(UserSealRefused):
            await service.checked_user("u-bad")
        # A write still refuses it.
        with pytest.raises(RowSealError):
            await store.set_user_roles("u-bad", [], audits=())
    finally:
        await store.close()


async def test_an_unreadable_administrator_does_not_block_another_admin_change(
    tmp_path: Path,
) -> None:
    path = tmp_path / "admins.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()  # the built-in roles
        for user_id in ("a-1", "a-2", "a-3"):
            await _user(store, user_id)
            await store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], audits=())
        _raw(path, "UPDATE users SET lock_cycles=? WHERE id=?", ("many", "a-2"))
        await service.delete_user("a-3", actor="test")  # a-1 still counts; a-2 is skipped
        assert await store.get_user("a-3") is None
    finally:
        await store.close()


def test_a_corrupt_global_epoch_stays_loud() -> None:
    """One store-wide value every account reads: not a per-row seal failure."""
    with pytest.raises(ValueError, match="invalid literal"):
        UserRecord.from_mapping({"id": "u", "global_session_epoch": "abc"})


async def test_a_presented_session_that_does_not_parse_is_ended_and_no_session(
    tmp_path: Path,
) -> None:
    path = tmp_path / "presented.db"
    store = await MessageStore.open(path)
    try:
        await _user(store, "u-p")
        bad = await _session(store, "u-p")
        _raw(path, "UPDATE sessions SET user_epoch=? WHERE token_hash=?", ("x", bad))
        assert await AuthService(store, AuthSettings())._load_session(bad) is None
        conn = sqlite3.connect(path)
        try:
            revoked = conn.execute(
                "SELECT revoked_at FROM sessions WHERE token_hash=?", (bad,)
            ).fetchone()
        finally:
            conn.close()
        assert revoked is not None and revoked[0] is not None
    finally:
        await store.close()


async def test_a_retired_key_check_reads_an_unencodable_session_as_no_genuine_seal(
    tmp_path: Path,
) -> None:
    old, new = generate_key(), generate_key()
    path = tmp_path / "retired.db"
    store = await MessageStore.open(path, cipher=make_cipher(old, write_v2=True))
    try:
        await _user(store, "u-k")
        token_hash = await _session(store, "u-k")
    finally:
        await store.close()
    rotated = await MessageStore.open(path, cipher=make_cipher(new, [old], write_v2=True))
    try:
        sealer = rotated.row_sealer()
        record = await rotated.get_session(token_hash)
        assert record is not None
        assert await session_sealed_by_retired_key_async(sealer, record)  # control
        wrongly_typed = replace(record, client=Decimal("1"))  # type: ignore[arg-type]
        assert not await session_sealed_by_retired_key_async(sealer, wrongly_typed)
    finally:
        await rotated.close()


async def test_a_corrupt_role_row_fails_its_account_seal_and_no_other(tmp_path: Path) -> None:
    path = tmp_path / "roles.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        await AuthService(store, AuthSettings()).initialize()  # the built-in roles
        for user_id in ("u-good", "u-bad"):
            await _user(store, user_id)
            await store.set_user_roles(user_id, [Role.VIEWER.value], audits=())
        _raw(path, "UPDATE user_roles SET assigned_at=? WHERE user_id=?", ("later", "u-bad"))
        with pytest.raises(RowSealError):  # never left out (BACKLOG #5505)
            await store.get_user_role_grants("u-bad")
        assert [g.role_id for g in await store.get_user_role_grants("u-good")] == ["viewer"]
        service = AuthService(store, AuthSettings())
        listed = {entry.id: entry.user for entry in await service.list_checked_users()}
        assert set(listed) == {"u-good", "u-bad"}
        assert listed["u-good"] is not None
        assert listed["u-bad"] is None  # listed, and failing its seal
    finally:
        await store.close()


async def _admin(store: MessageStore, user_id: str, password: str) -> None:
    await store.create_user(
        user_id=user_id,
        username=user_id,
        auth_provider="local",
        password_hash=hash_password(password),
        must_change_password=False,
        password_generated=False,
        audits=(),
    )
    await store.set_user_roles(user_id, [Role.ADMINISTRATOR.value, Role.VIEWER.value], audits=())


async def test_a_corrupt_role_row_fails_its_account_on_a_keyless_store(tmp_path: Path) -> None:
    """Finding 1 of PR 3007: a keyless store checks no seal, so the role read itself must refuse
    the account, as the write helpers do, or it signs in without the role while every write to it
    is refused. Sign-in refuses it and reports it, and a session issued before is refused. The
    last-administrator guard already skipped it before this fix; it is checked here only to show
    the guard and sign-in now agree."""
    path = tmp_path / "keyless-roles.db"
    password = "a-strong-passphrase-here"
    store = await MessageStore.open(path)
    try:
        assert store.row_sealer() is None
        alerts: list[str] = []
        service = AuthService(store, AuthSettings(require_mfa=False), integrity_alert=alerts.append)
        await service.initialize()  # the built-in roles
        for user_id in ("a-good", "a-bad"):
            await _admin(store, user_id, password)
        before = await service.login("a-bad", password)
        assert before.ok and before.token is not None  # control
        assert await service.identity_for_token(before.token) is not None
        # Control: the guard counts a-bad while it reads, so a-good may go.
        await service.delete_user("a-good", actor="test")
        await _admin(store, "a-good", password)
        _raw(
            path,
            "UPDATE user_roles SET assigned_at=? WHERE user_id=? AND role_id=?",
            ("later", "a-bad", Role.VIEWER.value),
        )
        # Sign-in itself refuses and reports it: nothing read the account before this login.
        out = await service.login("a-bad", password)
        assert not out.ok and out.token is None and out.error == "invalid credentials"
        assert len(alerts) == 1 and "a-bad" in alerts[0]
        assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1
        assert await service.identity_for_token(before.token) is None
        assert await service._load_user("a-bad") is None
        assert await service._load_user("a-good") is not None  # no other account fails
        # a-bad can no longer sign in, so the guard no longer counts it either.
        with pytest.raises(LastAdministratorRefused):
            await service.delete_user("a-good", actor="test")
        assert await store.get_user("a-good") is not None
    finally:
        await store.close()


def _revoked(path: Path, token_hash: str) -> bool:
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT revoked_at FROM sessions WHERE token_hash=?", (token_hash,)
        ).fetchone()
    finally:
        conn.close()
    return row is not None and row[0] is not None


@pytest.mark.parametrize("save", ["role", "scope"])
@pytest.mark.parametrize("keyed", [False, True])
async def test_an_ad_map_save_revokes_every_directory_account_and_every_failing_one(
    tmp_path: Path, keyed: bool, save: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Either AD map save revokes the sessions of each account whose stored row reads as an
    enabled directory account, whatever its check says, of each whose users row does not parse
    (``listed_users`` says which), and of each whose integrity check fails whatever its row says
    (BACKLOG #5505). So on a keyed store a directory row tampered to read as local or disabled is
    ended too. A keyless store checks no seal, so there such a row reads as what it says. A local
    account that passes and a disabled directory account keep their sessions."""
    path = tmp_path / "ad-map.db"
    cipher = make_cipher(generate_key(), write_v2=True) if keyed else None
    store = await MessageStore.open(path, cipher=cipher)
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()  # the built-in roles
        accounts = {
            "ad-good": "ad",
            "ad-bad-role": "ad",
            "ad-bad-row": "ad",
            "ad-disabled": "ad",
            "ad-made-local": "ad",
            "ad-made-disabled": "ad",
            "local-good": "local",
            "local-bad-role": "local",
            "local-bad-row": "local",
        }
        ended = {"ad-good", "ad-bad-role", "ad-bad-row", "local-bad-role", "local-bad-row"}
        if keyed:
            accounts |= {"ad-forged": "ad", "ad-unverifiable": "ad"}
            ended |= {"ad-forged", "ad-unverifiable", "ad-made-local", "ad-made-disabled"}
        tokens: dict[str, str] = {}
        for user_id, provider in accounts.items():
            await store.create_user(
                user_id=user_id,
                username=user_id,
                auth_provider=provider,
                password_generated=False,
                audits=(),
            )
            await store.set_user_roles(user_id, [Role.VIEWER.value], audits=())
            tokens[user_id] = await _session(store, user_id)
        await store.set_user_disabled("ad-disabled", disabled=True)
        for bad in ("ad-bad-role", "local-bad-role"):
            _raw(path, "UPDATE user_roles SET assigned_at=? WHERE user_id=?", ("later", bad))
        for bad in ("ad-bad-row", "local-bad-row"):
            _raw(path, "UPDATE users SET created_at=? WHERE id=?", ("later", bad))
        # Edited outside the store, so the seal (where there is one) no longer matches.
        _raw(path, "UPDATE users SET auth_provider=? WHERE id=?", ("local", "ad-made-local"))
        _raw(path, "UPDATE users SET disabled=? WHERE id=?", (1, "ad-made-disabled"))
        if keyed:
            _raw(path, "UPDATE users SET display_name=? WHERE id=?", ("forged", "ad-forged"))

            async def unverifiable(sealer: Any, record: Any) -> bool:
                if record.row.id == "ad-unverifiable":
                    raise TransitSealUnverifiableError("user", 5, 1)
                return await user_seal_ok_async(sealer, record)

            monkeypatch.setattr(service_module, "user_seal_ok_async", unverifiable)
        gate = await service.sessions_ended_by_ad_map_save()
        assert gate == ended
        if save == "role":
            await service.set_ad_group_map([], actor="test", ended=gate)
        else:
            await service.set_ad_group_scope_map([], actor="test", ended=gate)
        for user_id, token_hash in tokens.items():
            assert _revoked(path, token_hash) is (user_id in ended), user_id
    finally:
        await store.close()


@pytest.mark.parametrize("save", ["update", "delete"])
@pytest.mark.parametrize("keyed", [False, True])
async def test_a_custom_role_save_revokes_every_holder_and_every_failing_account(
    tmp_path: Path, keyed: bool, save: str
) -> None:
    """Finding 4 of round 8b6500f2 on PR 3007: a custom-role edit or delete revokes the sessions of
    each account whose stored role rows hold the role, whatever its check says, of each whose rows
    do not parse, and of each whose integrity check fails whatever its rows say. On a keyed store
    a holder whose role row was deleted outside the store is ended too; a keyless store checks no
    seal, so there it reads as no holder."""
    path = tmp_path / "custom-role.db"
    cipher = make_cipher(generate_key(), write_v2=True) if keyed else None
    store = await MessageStore.open(path, cipher=cipher)
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()  # the built-in roles
        role = await service.create_custom_role(
            display_name="Lab readers", description=None, permissions=["messages:read"], actor="t"
        )
        holders = ("h-good", "h-forged", "h-bad-row", "h-bad-role", "h-dropped")
        others = ("o-good", "o-forged")
        tokens: dict[str, str] = {}
        for user_id in holders + others:
            await _user(store, user_id)
            roles = [Role.VIEWER.value] + ([role.id] if user_id in holders else [])
            await store.set_user_roles(user_id, roles, audits=())
            tokens[user_id] = await _session(store, user_id)
        for forged in ("h-forged", "o-forged"):
            _raw(path, "UPDATE users SET display_name=? WHERE id=?", ("forged", forged))
        _raw(path, "UPDATE users SET created_at=? WHERE id=?", ("later", "h-bad-row"))
        _raw(
            path,
            "UPDATE user_roles SET assigned_at=? WHERE user_id=? AND role_id=?",
            ("later", "h-bad-role", role.id),
        )
        _raw(
            path,
            "DELETE FROM user_roles WHERE user_id=? AND role_id=?",
            ("h-dropped", role.id),
        )
        ended = {"h-good", "h-forged", "h-bad-row", "h-bad-role"}
        if keyed:
            ended |= {"h-dropped", "o-forged"}
        gate = await service.sessions_ended_by_custom_role_save(role.id)
        assert gate == ended
        if save == "update":
            await service.update_custom_role(
                role.id,
                display_name="Lab readers 2",
                description=None,
                permissions=["messages:read"],
                actor="test",
                ended=gate,
            )
        else:
            await service.delete_custom_role(role.id, actor="test", ended=gate)
        for user_id, token_hash in tokens.items():
            assert _revoked(path, token_hash) is (user_id in ended), user_id
        # Finding 4 of round 69e8364ab4: each account the gate named whose rows, read after the
        # save, do not tie it to the role gets a row naming it; a keyless store names none.
        named = {
            json.loads(row["detail"])["user_id"]
            for row in await store.list_audit(action=GATE_ONLY_REVOKE_ACTION)
        }
        assert named == ({"h-dropped", "o-forged"} if keyed else set())
    finally:
        await store.close()


async def test_a_keyless_reread_that_finds_an_unreadable_row_never_verifies_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The role read refuses, and by the re-read the users row no longer parses: the stand-in the
    re-read returns is reported as failing, never built into a verified account."""
    path = tmp_path / "keyless-reread.db"
    store = await MessageStore.open(path)
    try:
        await _user(store, "u-rr")
        user = await store.get_user("u-rr")
        assert user is not None
        real = store.get_user_role_grants
        calls = 0

        async def refuse_once(user_id: str) -> list[RoleGrant]:
            nonlocal calls
            calls += 1
            if calls == 1:
                _raw(path, "UPDATE users SET failed_attempts=? WHERE id=?", ("x", user_id))
                raise RowSealError(USER_KIND, "")
            return await real(user_id)

        monkeypatch.setattr(store, "get_user_role_grants", refuse_once)
        check = await AuthService(store, AuthSettings())._verified(user)
        assert check.failed and check.user is None
    finally:
        await store.close()


async def test_a_corrupt_role_row_inserted_outside_the_store_fails_the_seal(
    tmp_path: Path,
) -> None:
    """Finding 2 of PR 3007: a corrupt role row INSERTed beside the sealed ones is not left out,
    which would leave the record matching its seal; the account fails and is reported."""
    path = tmp_path / "inserted-role.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        alerts: list[str] = []
        service = AuthService(store, AuthSettings(), integrity_alert=alerts.append)
        await service.initialize()  # the built-in roles
        await _user(store, "u-ins")
        await store.set_user_roles("u-ins", [Role.VIEWER.value], audits=())
        assert await service._load_user("u-ins") is not None  # control
        assert alerts == []
        _raw(
            path,
            "INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by) VALUES (?,?,?,?)",
            ("u-ins", Role.ADMINISTRATOR.value, "later", None),
        )
        assert await service._load_user("u-ins") is None
        assert len(alerts) == 1 and "u-ins" in alerts[0]
        assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1
    finally:
        await store.close()


async def test_a_corrupt_session_leaves_the_accounts_other_sessions_listed(tmp_path: Path) -> None:
    path = tmp_path / "sessions.db"
    store = await MessageStore.open(path)
    try:
        await _user(store, "u-s")
        good = await _session(store, "u-s")
        bad = await _session(store, "u-s")
        _raw(path, "UPDATE sessions SET user_epoch=? WHERE token_hash=?", ("x", bad))
        assert [s.token_hash for s in await store.list_sessions("u-s")] == [good]
        service = AuthService(store, AuthSettings())
        assert [s.token_hash for s in await service.list_sessions("u-s")] == [good]
    finally:
        await store.close()


async def test_a_corrupt_account_is_refused_by_the_reseal_and_the_rest_resealed(
    tmp_path: Path,
) -> None:
    old, new = generate_key(), generate_key()
    path = tmp_path / "reseal.db"
    store = await MessageStore.open(path, cipher=make_cipher(old, write_v2=True))
    try:
        await _user(store, "u-good")
        await _user(store, "u-bad")
    finally:
        await store.close()
    _raw(path, "UPDATE users SET lock_cycles=? WHERE id=?", ("many", "u-bad"))
    rotated = await MessageStore.open(path, cipher=make_cipher(new, [old], write_v2=True))
    try:
        assert await rotated.reseal_user_records() == (1, 1)
    finally:
        await rotated.close()


async def test_a_session_field_the_encoder_cannot_read_fails_its_seal(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "typed.db", cipher=make_cipher(generate_key()))
    try:
        sealer = store.row_sealer()
        assert isinstance(sealer, RowSealer)
        await _user(store, "u-t")
        token_hash = await _session(store, "u-t")
        record = await store.get_session(token_hash)
        assert record is not None
        assert session_seal_ok(sealer, record)  # control
        assert await session_seal_ok_async(sealer, record)
        # A driver can hand back a type the seal encoder has no form for (a Decimal here).
        wrongly_typed = replace(record, client=Decimal("1"))  # type: ignore[arg-type]
        assert not session_seal_ok(sealer, wrongly_typed)
        assert not await session_seal_ok_async(sealer, wrongly_typed)
    finally:
        await store.close()


@pytest.mark.parametrize("keyed", [False, True])
async def test_a_recovery_code_cell_that_does_not_parse_is_charged_as_a_wrong_code(
    tmp_path: Path, keyed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 1 of round 8b6500f2 on PR 3007: a wrong code against an account whose recovery-code
    cell does not parse is charged to the second-step lockout. On a
    keyed store the cell is written through the store's own sealing helper, so the record passes
    its seal and only the parse fails."""
    path = tmp_path / "codes-lockout.db"
    cipher = make_cipher(generate_key(), write_v2=True) if keyed else None
    store = await MessageStore.open(path, cipher=cipher)
    try:
        service = AuthService(store, AuthSettings(mfa_verify_min_elapsed_seconds=0))
        identity, token, password = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        activating = totp.totp(enroll.secret, now=t0)
        assert (await service.confirm_mfa_enrollment(identity, activating, token=token)).ok
        if keyed:
            async with _writer_guard(store._db, store._lock):
                written = await store._write_user(
                    identity.user_id, lambda r: r.changed(totp_recovery_codes="{not json")
                )
                await store._commit()
            assert written is not None
        else:
            _raw(
                path,
                "UPDATE users SET totp_recovery_codes=? WHERE id=?",
                ("{not json", identity.user_id),
            )
        assert await service._load_user(identity.user_id) is not None  # the record still loads
        out = await service.login(ADMIN_USERNAME, password)
        assert out.ok and out.mfa_required and out.token is not None
        wrong = "000000" if activating != "000000" else "111111"
        first = await service.verify_mfa(out.token, wrong)
        assert not first.ok
        user = await store.get_user(identity.user_id)
        assert user is not None and user.second_step_failed_attempts == 1
        for _ in range(AuthSettings().lockout_threshold - 1):
            assert not (await service.verify_mfa(out.token, wrong)).ok
        locked = await store.get_user(identity.user_id)
        assert locked is not None and locked.second_step_locked_until is not None
    finally:
        await store.close()


async def test_a_supersession_that_reads_back_an_unparseable_row_keeps_its_revoke(
    tmp_path: Path,
) -> None:
    """Finding 7 of round 8b6500f2 on PR 3007: the read-back refuses the row, but the revoke it
    follows commits, and the service reports the ended row."""
    path = tmp_path / "supersede.db"
    store = await MessageStore.open(path)
    try:
        await _user(store, "u-sup")
        bad = await _session(store, "u-sup")
        other = await _session(store, "u-sup")
        _raw(path, "UPDATE sessions SET user_epoch=? WHERE token_hash=?", ("x", bad))
        with pytest.raises(RevokedRowSealError) as caught:
            await store.supersede_session(bad, now=time.time())
        assert caught.value.args == (SESSION_KIND, bad[:12])
        assert _revoked(path, bad)
        assert not _revoked(path, other)
        alerts: list[str] = []
        service = AuthService(store, AuthSettings(), integrity_alert=alerts.append)
        _raw(path, "UPDATE sessions SET user_epoch=? WHERE token_hash=?", ("x", other))
        # Answered, not raised (finding 1 of round 69e8364ab4): the session has ended.
        assert await service._supersede_session(other, now=time.time()) is not None
        assert _revoked(path, other)
        assert len(alerts) == 1 and other[:12] in alerts[0]
        assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1
    finally:
        await store.close()


async def _token_session(store: MessageStore, user_id: str) -> str:
    token = mint_token()
    assert await store.create_session(
        token_hash=hash_token(token), user_id=user_id, expires_at=time.time() + 3600
    )
    return token


def _unparseable(path: Path, token: str) -> None:
    _raw(path, "UPDATE sessions SET user_epoch=? WHERE token_hash=?", ("x", hash_token(token)))


async def test_a_logout_whose_ended_row_does_not_parse_still_signs_out(tmp_path: Path) -> None:
    """Finding 1 of round 69e8364ab4: the revoke committed, so the sign-out answers as one that
    ended a session, writes its auth.logout row and reports the row, rather than raising."""
    path = tmp_path / "logout.db"
    store = await MessageStore.open(path)
    try:
        await _user(store, "u-out")
        token = await _token_session(store, "u-out")
        _unparseable(path, token)
        alerts: list[str] = []
        service = AuthService(store, AuthSettings(), integrity_alert=alerts.append)
        assert await service.logout(token, client=None, proven_at=None) == "revoked"
        assert _revoked(path, hash_token(token))
        [row] = await store.list_audit(action="auth.logout")
        assert json.loads(row["detail"]) == {
            "outcome": "revoked",
            "session": hash_token(token)[:12],
        }
        assert len(alerts) == 1 and hash_token(token)[:12] in alerts[0]
    finally:
        await store.close()


async def test_a_logout_whose_ended_row_report_fails_still_signs_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Finding 15 of PR 3007: the integrity report for an ended row that does not parse raised a
    defect out of its audit write after the revoke committed, so the sign-out answered 500. The
    report's failure is now logged and the sign-out completes."""
    path = tmp_path / "logout-report.db"
    store = await MessageStore.open(path)
    try:
        await _user(store, "u-out-r")
        token = await _token_session(store, "u-out-r")
        _unparseable(path, token)
        service = AuthService(store, AuthSettings())
        audit = service._audit

        async def _refuse_seal_row(action: str, **kwargs: object) -> None:
            if action == AUTHORITY_SEAL_FAILED_ACTION:
                raise NotImplementedError("planted defect")  # in AUDIT_WRITE_DEFECTS
            await audit(action, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(service, "_audit", _refuse_seal_row)
        with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
            assert await service.logout(token, client=None, proven_at=None) == "revoked"
        assert _revoked(path, hash_token(token))
        assert [json.loads(r["detail"])["outcome"] for r in await store.list_audit()] == ["revoked"]
        said = [
            r.getMessage() for r in caplog.records if "integrity report failed" in r.getMessage()
        ]
        assert len(said) == 1 and hash_token(token)[:12] in said[0]
    finally:
        await store.close()


async def test_a_sign_in_whose_superseded_row_does_not_parse_returns_its_session(
    tmp_path: Path,
) -> None:
    """Finding 2 of round 69e8364ab4: the new session was minted before the prior one is
    superseded, so the sign-in returns it rather than failing after the mint."""
    path = tmp_path / "sign-in.db"
    password = "a-strong-passphrase-here"
    store = await MessageStore.open(path)
    try:
        alerts: list[str] = []
        service = AuthService(store, AuthSettings(require_mfa=False), integrity_alert=alerts.append)
        await service.initialize()  # the built-in roles
        await _admin(store, "a-in", password)
        prior = await _token_session(store, "a-in")
        _unparseable(path, prior)
        out = await service.login("a-in", password, supersedes=prior)
        assert out.ok and out.token is not None
        assert await service.identity_for_token(out.token) is not None
        assert _revoked(path, hash_token(prior))
        assert len(alerts) == 1 and hash_token(prior)[:12] in alerts[0]
    finally:
        await store.close()


async def test_a_lapsed_session_end_whose_row_does_not_parse_writes_its_row(
    tmp_path: Path,
) -> None:
    """Finding 2 of round 69e8364ab4: ending a lapsed session does not raise when the row it
    ended does not parse; its auth.temp_password_expired row is written as for any other."""
    path = tmp_path / "lapsed.db"
    store = await MessageStore.open(path)
    try:
        await _user(store, "u-lapse")
        token = await _token_session(store, "u-lapse")
        _unparseable(path, token)
        service = AuthService(store, AuthSettings())
        await service._end_lapsed_session(hash_token(token), "u-lapse", at="session", client=None)
        assert _revoked(path, hash_token(token))
        assert len(await store.list_audit(action="auth.temp_password_expired")) == 1
    finally:
        await store.close()


@pytest.mark.parametrize("save", ["ad_map", "custom_role"])
async def test_a_refused_reread_after_a_group_save_leaves_the_gate_set_revoked(
    tmp_path: Path, save: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 3 of round 69e8364ab4: the gate's set is revoked before the accounts are read
    again, so a store refusal of that read leaves it revoked, writes a refused-revoke row, and
    still fails the save."""
    path = tmp_path / "reread.db"
    store = await MessageStore.open(path)
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()  # the built-in roles
        role_id = ""
        if save == "custom_role":
            role = await service.create_custom_role(
                display_name="Readers", description=None, permissions=["messages:read"], actor="t"
            )
            role_id = role.id
        await store.create_user(
            user_id="d-1",
            username="d-1",
            auth_provider="ad" if save == "ad_map" else "local",
            password_generated=False,
            audits=(),
        )
        await store.set_user_roles(
            "d-1", [Role.VIEWER.value] + ([role_id] if role_id else []), audits=()
        )
        token_hash = await _session(store, "d-1")
        if save == "ad_map":
            gate = await service.sessions_ended_by_ad_map_save()
        else:
            gate = await service.sessions_ended_by_custom_role_save(role_id)
        assert gate == {"d-1"}  # control

        async def refused() -> list[Any]:
            raise sqlite3.OperationalError("synthetic refusal")

        monkeypatch.setattr(store, "list_users", refused)
        with pytest.raises(sqlite3.OperationalError):
            if save == "ad_map":
                await service.set_ad_group_map([], actor="test", ended=gate)
            else:
                await service.update_custom_role(
                    role_id,
                    display_name="Readers 2",
                    description=None,
                    permissions=["messages:read"],
                    actor="test",
                    ended=gate,
                )
        assert _revoked(path, token_hash)
        [missed] = await store.list_audit(action=SESSIONS_REVOKE_FAILED_ACTION)
        detail = json.loads(missed["detail"])
        assert detail["reread"] == "refused" and detail["error"] == "OperationalError"
    finally:
        await store.close()


@pytest.mark.parametrize("keyed", [False, True])
async def test_mfa_status_reads_an_unparseable_recovery_code_cell_as_none_held(
    tmp_path: Path, keyed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding 10 of round 69e8364ab4: the caller's own MFA status answers with no codes held, as
    the code check reads the cell, rather than refusing."""
    path = tmp_path / "mfa-status.db"
    cipher = make_cipher(generate_key(), write_v2=True) if keyed else None
    store = await MessageStore.open(path, cipher=cipher)
    try:
        service = AuthService(store, AuthSettings(mfa_verify_min_elapsed_seconds=0))
        identity, token, _ = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        activating = totp.totp(enroll.secret, now=t0)
        assert (await service.confirm_mfa_enrollment(identity, activating, token=token)).ok
        assert (await service.mfa_status(identity)).recovery_codes_remaining > 0  # control
        if keyed:
            async with _writer_guard(store._db, store._lock):
                written = await store._write_user(
                    identity.user_id, lambda r: r.changed(totp_recovery_codes="{not json")
                )
                await store._commit()
            assert written is not None
        else:
            _raw(
                path,
                "UPDATE users SET totp_recovery_codes=? WHERE id=?",
                ("{not json", identity.user_id),
            )
        status = await service.mfa_status(identity)
        assert status.enabled and status.recovery_codes_remaining == 0
    finally:
        await store.close()
