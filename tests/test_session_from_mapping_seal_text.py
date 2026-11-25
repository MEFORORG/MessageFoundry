# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``SessionRecord.from_mapping`` reads the ``seal`` cell as text (BACKLOG #6718 item 2).

``RoleRow``, ``ApprovalRow`` and ``UserRow`` read their seal with ``str(... or "")``; the session
reader passed the cell through, so a seal cell SQLite hands back as a BLOB, after an edit outside
the store, left a ``SessionRecord.seal`` that is not a ``str``. The compare-and-set still binds the
cell as read, so on a keyless store such a row is written through as before. Synthetic values only.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.store.store import MessageStore, SessionRecord


def _row(seal: object) -> dict[str, Any]:
    return {
        "token_hash": "t" * 64,
        "user_id": "u-6718",
        "created_at": 1.0,
        "expires_at": 3.0,
        "last_used_at": 2.0,
        "revoked_at": None,
        "client": "198.51.100.7",
        "reauth_at": None,
        "mfa_verified_at": None,
        "auth_mechanism": "password",
        "idp_auth_time": None,
        "user_epoch": 0,
        "global_epoch": 0,
        "seal": seal,
    }


def test_a_blob_seal_cell_reads_as_text() -> None:
    seal = SessionRecord.from_mapping(_row(b"mfseal:v1:k:ab")).seal
    assert isinstance(seal, str)


@pytest.mark.parametrize(("cell", "expected"), [("mfseal:v1:k:ab", "mfseal:v1:k:ab"), (None, "")])
def test_a_text_or_null_seal_cell_reads_as_before(cell: object, expected: str) -> None:
    """The control: a text seal is kept as it is and a NULL one reads as empty."""
    assert SessionRecord.from_mapping(_row(cell)).seal == expected


def _raw(path: Path, sql: str, params: tuple[Any, ...]) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


async def test_a_blob_seal_row_still_writes_through_on_a_keyless_store(tmp_path: Path) -> None:
    """As on main: a session whose seal cell is a BLOB is still stamped, marked and rotated on a
    keyless store, because the compare-and-set binds the cell as read."""
    path = tmp_path / "k.db"
    store = await MessageStore.open(path)
    try:
        await store.create_user(
            user_id="u-6718",
            username="u-6718",
            auth_provider="local",
            password_generated=False,
            audits=(),
        )
        token_hash = hash_token(mint_token())
        assert await store.create_session(
            token_hash=token_hash, user_id="u-6718", expires_at=time.time() + 3600
        )
        blob = b"mfseal:v1:k:ab"

        _raw(path, "UPDATE sessions SET seal=? WHERE token_hash=?", (blob, token_hash))
        await store.mark_session_reauthed(token_hash, now=12345.0)
        stamped = await store.get_session(token_hash)
        assert stamped is not None and stamped.reauth_at == 12345.0

        _raw(path, "UPDATE sessions SET seal=? WHERE token_hash=?", (blob, token_hash))
        await store.mark_session_mfa_verified(token_hash, now=12346.0)
        marked = await store.get_session(token_hash)
        assert marked is not None and marked.mfa_verified_at == 12346.0

        _raw(path, "UPDATE sessions SET seal=? WHERE token_hash=?", (blob, token_hash))
        new_hash = hash_token(mint_token())
        assert await store.rotate_session(token_hash, new_token_hash=new_hash, now=12347.0)
        assert await store.get_session(new_hash) is not None
    finally:
        await store.close()


async def test_an_empty_blob_seal_row_is_not_written_on_a_keyless_store(tmp_path: Path) -> None:
    """As on main: an empty BLOB seal reads as ``""``, and the compare binds text, which does not
    match the BLOB, so the rewrite lands nothing."""
    path = tmp_path / "k.db"
    store = await MessageStore.open(path)
    try:
        await store.create_user(
            user_id="u-6718",
            username="u-6718",
            auth_provider="local",
            password_generated=False,
            audits=(),
        )
        token_hash = hash_token(mint_token())
        assert await store.create_session(
            token_hash=token_hash, user_id="u-6718", expires_at=time.time() + 3600
        )
        _raw(path, "UPDATE sessions SET seal=? WHERE token_hash=?", (b"", token_hash))
        new_hash = hash_token(mint_token())
        assert not await store.rotate_session(token_hash, new_token_hash=new_hash, now=1.0)
        assert await store.get_session(new_hash) is None
    finally:
        await store.close()
