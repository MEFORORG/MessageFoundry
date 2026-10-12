# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for session-row integrity seals (BACKLOG #2592).

Deliberately **extra-free**, on the ``_session_rotation_contract`` precedent: it imports nothing
optional, so the live Postgres and SQL Server suites import it inside their test functions and run
the same assertions on legs that install only their own driver extra.

The caller passes a store opened with a store key, and ``raw``: a way to run one SQL statement
against the same database without going through the store's helpers.
``raw`` takes SQL written with ``?`` placeholders and its parameters; each backend's adapter
respells the placeholders for its driver and commits.

Every refusal below has a control beside it: the same row resolves before the change, or the same
change made through the store keeps it resolving. A sealer that refused everything, or accepted
everything, fails this contract.
"""

from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import fields
from typing import Any

from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.row_seal import SEAL_PREFIX, RowSealError
from messagefoundry.store.store import SessionRecord, session_seal_ok

#: Runs one statement with ``?`` placeholders against the store's database, outside the store.
RawSql = Callable[[str, tuple[Any, ...]], Awaitable[None]]


def dollar_placeholders(sql: str) -> str:
    """``sql`` with each ``?`` respelled ``$1``, ``$2``, ... for asyncpg. The contract's statements
    carry no ``?`` inside a literal, so a plain left-to-right count is exact."""
    counter = iter(range(1, sql.count("?") + 1))
    return re.sub(r"\?", lambda _m: f"${next(counter)}", sql)


def assert_session_columns(columns: set[str]) -> None:
    """The ``sessions`` table has exactly :class:`SessionRecord`'s fields, so a column added to one
    and not the other cannot sit outside the seal unnoticed (BACKLOG #2592)."""
    assert {c.lower() for c in columns} == {f.name for f in fields(SessionRecord)}


#: Each sealed column, and a value that differs from what ``_mint`` writes.
_SEALED_CHANGES: tuple[tuple[str, Any], ...] = (
    ("user_id", "seal-u2"),
    ("created_at", 1.0),
    ("expires_at", 4_000_000_000.0),
    ("client", "192.0.2.77"),
    ("reauth_at", 1.0),
    ("mfa_verified_at", 1.0),
    ("auth_mechanism", "oidc"),
    ("idp_auth_time", 1.0),
    ("user_epoch", 7),
)


async def _user(store: Any, user_id: str) -> None:
    await store.create_user(
        user_id=user_id,
        username=user_id,
        auth_provider="local",
        display_name=None,
        email=None,
        password_hash="h",
        now=time.time(),
        password_generated=False,
    )


async def _mint(store: Any, user_id: str = "seal-u1") -> str:
    token = mint_token()
    await store.create_session(
        token_hash=hash_token(token),
        user_id=user_id,
        expires_at=time.time() + 3600,
        client="192.0.2.10",
        auth_mechanism="password",
    )
    return token


async def assert_session_seal_contract(store: Any, raw: RawSql) -> None:
    """Drive the session seal through its whole contract on ``store``'s backend."""
    sealer = store.row_sealer()
    assert sealer is not None, "the contract needs a store opened with a store key"
    service = AuthService(store, AuthSettings())
    await _user(store, "seal-u1")
    await _user(store, "seal-u2")

    # --- a session the store wrote carries a seal and resolves ----------------------------------
    token = await _mint(store)
    row = await store.get_session(hash_token(token))
    assert row is not None and row.seal.startswith(SEAL_PREFIX)
    assert session_seal_ok(sealer, row)
    identity = await service.identity_for_token(token)
    assert identity is not None and identity.user_id == "seal-u1"
    assert await service.has_recent_step_up(token)

    # --- a row the store did not write resolves to nothing -------------------------------------
    unsealed = mint_token()
    now = time.time()
    await raw(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
        " client, reauth_at, mfa_verified_at, auth_mechanism) VALUES (?,?,?,?,?,?,?,?,?)",
        (hash_token(unsealed), "seal-u2", now, now + 3600, now, None, now, now, "password"),
    )
    assert await service.identity_for_token(unsealed) is None
    assert not await service.has_recent_step_up(unsealed)
    ended = await store.get_session(hash_token(unsealed))
    assert ended is not None and ended.revoked_at is not None  # refused, then ended
    # A valid seal copied from another row does not carry over: it covers that row's token hash.
    copied = mint_token()
    await raw(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
        " client, reauth_at, auth_mechanism, user_epoch, seal) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            hash_token(copied),
            row.user_id,
            row.created_at,
            row.expires_at,
            row.last_used_at,
            row.client,
            row.reauth_at,
            row.auth_mechanism,
            row.user_epoch,
            row.seal,
        ),
    )
    assert await service.identity_for_token(copied) is None

    # --- a sealed column changed outside the store resolves to nothing -------------------------
    for column, value in _SEALED_CHANGES:
        changed = await _mint(store)
        assert await service.identity_for_token(changed) is not None, column  # control
        await raw(
            f"UPDATE sessions SET {column}=? WHERE token_hash=?", (value, hash_token(changed))
        )
        assert await service.identity_for_token(changed) is None, column
        assert not await service.has_recent_step_up(changed), column

    # --- the one column outside the seal: last_used_at -----------------------------------------
    touched = await _mint(store)
    await raw(
        "UPDATE sessions SET last_used_at=? WHERE token_hash=?",
        (time.time() - 5, hash_token(touched)),
    )
    assert await service.identity_for_token(touched) is not None

    # --- revoking blanks the seal, so clearing revoked_at brings nothing back ------------------
    revoked = await _mint(store)
    await store.revoke_session(hash_token(revoked))
    gone = await store.get_session(hash_token(revoked))
    assert gone is not None and gone.revoked_at is not None and gone.seal == ""
    await raw("UPDATE sessions SET revoked_at=NULL WHERE token_hash=?", (hash_token(revoked),))
    assert await service.identity_for_token(revoked) is None

    # --- the write helper refuses a row whose seal fails, and does not re-seal it --------------
    bent = await _mint(store)
    await raw("UPDATE sessions SET client=? WHERE token_hash=?", ("192.0.2.99", hash_token(bent)))
    before = await store.get_session(hash_token(bent))
    for write in (
        lambda: store.mark_session_reauthed(hash_token(bent), client="192.0.2.10"),
        lambda: store.mark_session_mfa_verified(hash_token(bent)),
        lambda: store.rotate_session(hash_token(bent), new_token_hash=hash_token(mint_token())),
    ):
        try:
            await write()
        except RowSealError:
            pass
        else:
            raise AssertionError("a write over a row that fails its seal was not refused")
    after = await store.get_session(hash_token(bent))
    assert after == before  # nothing written, so the failing seal was not replaced
    assert await service.identity_for_token(bent) is None

    # --- control: the same writes through the store keep a sealed row resolving -------------
    kept = await _mint(store)
    await store.mark_session_reauthed(hash_token(kept), client="192.0.2.11")
    await store.mark_session_mfa_verified(hash_token(kept))
    stamped = await store.get_session(hash_token(kept))
    assert stamped is not None and stamped.mfa_verified_at is not None
    assert stamped.client == "192.0.2.11" and session_seal_ok(sealer, stamped)
    rotated = mint_token()
    assert await store.rotate_session(hash_token(kept), new_token_hash=hash_token(rotated))
    assert await service.identity_for_token(rotated) is not None
    assert await service.identity_for_token(kept) is None  # the old hash names no row now

    # --- ending every session raises the epoch: an older copy of a row is refused --------------
    mine = await _mint(store)
    other = await _mint(store)
    copy = await store.get_session(hash_token(other))
    assert copy is not None
    assert await store.revoke_user_sessions("seal-u1", except_token_hash=hash_token(mine)) >= 1
    assert await service.identity_for_token(mine) is not None  # the kept session, re-sealed
    assert await service.identity_for_token(other) is None
    await raw(
        "UPDATE sessions SET revoked_at=NULL, seal=? WHERE token_hash=?",
        (copy.seal, hash_token(other)),
    )
    restored = await store.get_session(hash_token(other))
    assert restored is not None and session_seal_ok(sealer, restored)  # the copy's seal holds...
    assert await service.identity_for_token(other) is None  # ...and its epoch is stale
    assert await service.identity_for_token(mine) is not None
