# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A keyless SQLite store refuses a NEW NaN or infinity in a sealed field (BACKLOG #6717 item 9).

The local row sealer refuses one; a keyless store wrote it, and SQLite stores a NaN as ``NULL``.
The refusal covers only a value the write brings in: a non-finite value already in the stored row,
put there outside the store, is carried forward as before, so a sign-in on such a row still works.
Synthetic accounts only.
"""

from __future__ import annotations

import math
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_PASSWORD, ADMIN_USERNAME, create_admin

_NON_FINITE = [math.nan, math.inf, -math.inf]


def _raw(path: Path, sql: str, params: tuple[Any, ...]) -> None:
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


@pytest.mark.parametrize("value", _NON_FINITE)
async def test_a_new_session_with_a_non_finite_expiry_is_refused(
    tmp_path: Path, value: float
) -> None:
    store = await MessageStore.open(tmp_path / "k.db")
    try:
        await _user(store, "u-6717")
        with pytest.raises(ValueError, match="not finite"):
            await store.create_session(
                token_hash=hash_token(mint_token()), user_id="u-6717", expires_at=value
            )
        assert await store.list_sessions("u-6717") == []
    finally:
        await store.close()


@pytest.mark.parametrize("value", _NON_FINITE)
async def test_a_session_write_bringing_a_non_finite_value_is_refused(
    tmp_path: Path, value: float
) -> None:
    store = await MessageStore.open(tmp_path / "k.db")
    try:
        await _user(store, "u-6717")
        token_hash = await _session(store, "u-6717")
        before = await store.get_session(token_hash)
        with pytest.raises(ValueError, match="not finite"):
            await store.mark_session_reauthed(token_hash, now=value)
        assert await store.get_session(token_hash) == before
    finally:
        await store.close()


@pytest.mark.parametrize("value", _NON_FINITE)
async def test_a_user_write_bringing_a_non_finite_value_is_refused(
    tmp_path: Path, value: float
) -> None:
    store = await MessageStore.open(tmp_path / "k.db")
    try:
        await _user(store, "u-6717")
        with pytest.raises(ValueError, match="not finite"):
            await store.record_login_failure("u-6717", failed_attempts=1, locked_until=value)
    finally:
        await store.close()


@pytest.mark.parametrize("value", _NON_FINITE)
async def test_a_new_approval_with_a_non_finite_expiry_is_refused(
    tmp_path: Path, value: float
) -> None:
    store = await MessageStore.open(tmp_path / "k.db")
    try:
        with pytest.raises(ValueError, match="not finite"):
            await store.create_pending_approval(
                approval_id="a-6717",
                operation="op",
                params="{}",
                requester="r",
                requester_user_id="u-6717",
                requested_at=1.0,
                expires_at=value,
            )
    finally:
        await store.close()


async def test_a_stored_infinity_is_carried_forward_and_sign_in_still_works(
    tmp_path: Path,
) -> None:
    """As on main: an infinity already in the account row, written outside the store, does not
    stop a sign-in or a failed one on a keyless store; the row keeps the value."""
    path = tmp_path / "k.db"
    store = await MessageStore.open(path)
    try:
        service = AuthService(store, AuthSettings())
        admin = await create_admin(service)
        _raw(path, "UPDATE users SET created_at=? WHERE id=?", (math.inf, admin.user_id))
        bad = await service.login(ADMIN_USERNAME, "not-the-password")
        assert not bad.ok
        good = await service.login(ADMIN_USERNAME, ADMIN_PASSWORD)
        assert good.ok
        user = await store.get_user(admin.user_id)
        assert user is not None and user.created_at == math.inf
    finally:
        await store.close()


async def test_stored_infinities_on_two_role_grants_are_carried_forward(tmp_path: Path) -> None:
    """A user's seal fields repeat ``assigned_at`` once per grant, so a carried value is matched
    against every grant, not the last: a failed sign-in still records, as on main."""
    path = tmp_path / "k.db"
    store = await MessageStore.open(path)
    try:
        service = AuthService(store, AuthSettings())
        admin = await create_admin(service)
        await store.set_user_roles(
            admin.user_id,
            [Role.ADMINISTRATOR.value, Role.VIEWER.value],
            assigned_by="test",
            audits=(),
        )
        for role_id, value in (
            (Role.ADMINISTRATOR.value, math.inf),
            (Role.VIEWER.value, -math.inf),
        ):
            _raw(
                path,
                "UPDATE user_roles SET assigned_at=? WHERE user_id=? AND role_id=?",
                (value, admin.user_id, role_id),
            )
        await store.record_login_failure(admin.user_id, failed_attempts=1, locked_until=None)
        user = await store.get_user(admin.user_id)
        assert user is not None and user.failed_attempts == 1
    finally:
        await store.close()
