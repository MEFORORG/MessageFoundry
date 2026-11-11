# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A session sealed under a retired key ends quietly at the callers (owner ruling 2026-11-07 on
ADR 0217, "Quiet end at callers", built in slice 1b-iv). Synthetic data only.

The store's session writer raises ``RowSealKeyRetiredError`` and writes nothing. A revoke's
kept-session re-stamp ends that session with the rest; ``AuthService``'s stamp and rotation legs
end it with ``key_changed=True``, which revokes it and reports no seal failure. Each control is the
same leg on a Forged session, which still reports one.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.service import AUTHORITY_SEAL_FAILED_ACTION, AuthService
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import (
    SESSION_KIND,
    RowSealError,
    RowSealKeyRetiredError,
    TransitRowSealer,
)
from messagefoundry.store.store import MessageStore, no_audit_row
from tests._admin_account import login_admin
from tests._transit_seal_fake import RETIRED, FakeBackend


async def _service() -> tuple[MessageStore, AuthService]:
    store = await MessageStore.open(":memory:")
    return store, AuthService(store, AuthSettings())


async def _seal_failures(store: MessageStore) -> int:
    return len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION, limit=50))


async def _revoked(store: MessageStore, token: str) -> bool:
    session = await store.get_session(hash_token(token))
    return session is not None and session.revoked_at is not None


@pytest.mark.parametrize("answer", ["retired", "forged"])
async def test_a_stamp_on_a_retired_key_session_ends_it_quietly(answer: str) -> None:
    store, service = await _service()
    try:
        _, token, _ = await login_admin(service)
        exc = RowSealKeyRetiredError(SESSION_KIND) if answer == "retired" else RowSealError("s")
        async with service._sealed_stamp(hash_token(token)) as stamp:
            raise exc
        assert stamp.refused and await _revoked(store, token)
        assert await _seal_failures(store) == (0 if answer == "retired" else 1)
    finally:
        await store.close()


@pytest.mark.parametrize("answer", ["retired", "forged"])
async def test_a_rotation_on_a_retired_key_session_ends_it_quietly(
    answer: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, service = await _service()
    try:
        _, token, _ = await login_admin(service)
        exc = RowSealKeyRetiredError(SESSION_KIND) if answer == "retired" else RowSealError("s")

        async def refused(*_args: Any, **_kwargs: Any) -> Any:
            raise exc

        monkeypatch.setattr(store, "rotate_session", refused)
        assert await service._rotate_session_hash(hash_token(token)) is None
        assert await _revoked(store, token)
        assert await _seal_failures(store) == (0 if answer == "retired" else 1)
    finally:
        await store.close()


@pytest.fixture
async def retired(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, Path, str]]:
    """A store whose account and kept session were sealed under the key now retired."""
    path = tmp_path / "retired.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        store._row_sealer = TransitRowSealer(FakeBackend(active=RETIRED))
        await store.create_user(
            user_id="u-1",
            username="name-u-1",
            auth_provider="local",
            password_hash="synthetic-hash",
            password_generated=False,
            audits=(),
        )
        token = mint_token()
        assert await store.create_session(
            token_hash=hash_token(token), user_id="u-1", expires_at=time.time() + 3600
        )
        store._row_sealer = TransitRowSealer(FakeBackend(), retired_key_names=[RETIRED])
        yield store, path, token
    finally:
        await store.close()


async def test_a_revoke_ends_a_retired_key_kept_session_quietly(
    retired: tuple[MessageStore, Path, str], caplog: pytest.LogCaptureFixture
) -> None:
    store, path, token = retired
    pages: list[str] = []
    store.seal_pager().arm(lambda subject, reason: pages.append(subject))
    caplog.set_level(logging.INFO, logger="messagefoundry.store.store")
    result = await store.revoke_user_sessions(
        "u-1", except_token_hash=hash_token(token), audit=no_audit_row
    )
    assert not result.kept and result.ended_kept
    conn = sqlite3.connect(path)
    try:
        ((revoked_at,),) = conn.execute(
            "SELECT revoked_at FROM sessions WHERE token_hash=?", (hash_token(token),)
        ).fetchall()
    finally:
        conn.close()
    assert revoked_at is not None
    assert pages == [] and await _seal_failures(store) == 0
    assert await store.list_audit(action="integrity.authority_seal_unverifiable") == []
    assert any("retired store key" in r.getMessage() for r in caplog.records)
