# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SQLite store's user, role and session write paths through the awaitable seal seam (ADR 0217
slice 1b-i), run under the Transit sealer with an in-memory Transit stand-in. Synthetic data only.

``for_cipher`` does not yet return a Transit sealer, so each test sets one on the store; the
assertion is that the write paths await it, and that a stored seal Transit will not check refuses
the write as Unverifiable, never as Forged.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import (
    SEAL_PREFIX,
    RowSealError,
    RowSealUnverifiableError,
    TransitRowSealer,
    TransitSealUnavailableError,
)
from messagefoundry.store.store import MessageStore
from tests._transit_seal_fake import FakeBackend


@pytest.fixture
async def transit(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, FakeBackend, Path]]:
    path = tmp_path / "transit.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    backend = FakeBackend()
    store._row_sealer = TransitRowSealer(backend)  # type: ignore[assignment]
    try:
        yield store, backend, path
    finally:
        await store.close()


def _raw(path: Path, sql: str, params: tuple[object, ...]) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def _seal_of(path: Path, sql: str, params: tuple[object, ...]) -> str:
    conn = sqlite3.connect(path)
    try:
        return str(conn.execute(sql, params).fetchone()[0])
    finally:
        conn.close()


def _planted(seal: str) -> str:
    """``seal`` naming a version Transit does not hold, with the same well-formed MAC body."""
    head, mac = seal[len(SEAL_PREFIX) :].split(":", 1)
    body = mac.split(":", 2)[2]
    return f"{SEAL_PREFIX}{head}:vault:v7:{body}"


async def _user(store: MessageStore, user_id: str = "u-1") -> None:
    await store.create_user(
        user_id=user_id,
        username=f"name-{user_id}",
        auth_provider="local",
        password_hash="synthetic-hash",
        password_generated=False,
        audits=(),
    )


async def test_a_user_write_seals_and_checks_through_transit(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    store, backend, path = transit
    await _user(store)
    seal = _seal_of(path, "SELECT authz_seal FROM users WHERE id=?", ("u-1",))
    assert seal.startswith(SEAL_PREFIX) and ":vault:v1:" in seal
    calls = backend.verify_calls
    await store.set_user_disabled("u-1", disabled=True)
    assert backend.verify_calls == calls + 1
    assert _seal_of(path, "SELECT authz_seal FROM users WHERE id=?", ("u-1",)) != seal


async def test_a_user_write_over_an_unverifiable_seal_is_refused_as_unverifiable(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    store, _, path = transit
    await _user(store)
    seal = _seal_of(path, "SELECT authz_seal FROM users WHERE id=?", ("u-1",))
    _raw(path, "UPDATE users SET authz_seal=? WHERE id=?", (_planted(seal), "u-1"))
    with pytest.raises(RowSealUnverifiableError) as caught:
        await store.set_user_disabled("u-1", disabled=True)
    assert not isinstance(caught.value, RowSealError)
    assert caught.value.stored_version == 7
    # Nothing was written: the planted seal is still there.
    assert _seal_of(path, "SELECT authz_seal FROM users WHERE id=?", ("u-1",)) == _planted(seal)
    # Control: a seal over other content is Forged, the sibling type.
    _raw(path, "UPDATE users SET authz_seal=?, disabled=1 WHERE id=?", (seal, "u-1"))
    with pytest.raises(RowSealError):
        await store.set_user_disabled("u-1", disabled=False)


async def test_an_outage_on_a_user_write_writes_nothing(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    store, backend, path = transit
    await _user(store)
    seal = _seal_of(path, "SELECT authz_seal FROM users WHERE id=?", ("u-1",))
    backend.down = True
    with pytest.raises(TransitSealUnavailableError):
        await store.set_user_disabled("u-1", disabled=True)
    backend.down = False
    assert _seal_of(path, "SELECT authz_seal FROM users WHERE id=?", ("u-1",)) == seal
    backend.down = True
    with pytest.raises(TransitSealUnavailableError):
        await _user(store, "u-2")
    backend.down = False
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE id='u-2'").fetchone()[0] == 0
    finally:
        conn.close()


async def test_a_session_write_checks_under_the_active_key(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    store, backend, path = transit
    await _user(store)
    now = time.time()
    token = "cd" * 32
    assert await store.create_session(token_hash=token, user_id="u-1", expires_at=now + 3600)
    seal = _seal_of(path, "SELECT seal FROM sessions WHERE token_hash=?", (token,))
    assert ":vault:v1:" in seal
    calls = backend.verify_calls
    await store.mark_session_reauthed(token)
    assert backend.verify_calls == calls + 1
    _raw(path, "UPDATE sessions SET seal=? WHERE token_hash=?", (_planted(seal), token))
    with pytest.raises(RowSealUnverifiableError) as caught:
        await store.mark_session_reauthed(token)
    # The exception carries no token hash: its args are the kind and a subject.
    assert caught.value.args == ("session", "")
    # Nothing was written: the planted seal is still there.
    assert _seal_of(path, "SELECT seal FROM sessions WHERE token_hash=?", (token,)) == _planted(
        seal
    )


async def test_a_role_upsert_seals_through_transit(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    store, backend, path = transit
    before = len(backend.inputs)
    await store.upsert_role(role_id="r-synthetic", display_name="Synthetic", builtin=False)
    assert len(backend.inputs) == before + 1
    seal = _seal_of(path, "SELECT seal FROM roles WHERE id=?", ("r-synthetic",))
    assert ":vault:v1:" in seal
