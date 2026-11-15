# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Three limbs of :meth:`AuthService.bind_federated_subject` (BACKLOG #5625).

1. A holder whose record fails its seal read as no holder through the checked loader. The unique
   index still refused the write, but only after the rebind's clear, so the account was left
   unbound and signed out. The holder check now reads the raw row and refuses before the clear.
2. A case variant of the account's id found the row on SQL Server, whose ids compare in the
   database collation, and every later comparison and write used the variant. The bind now uses
   the id the row holds. SQLite compares ids byte for byte, so the variant lookup is simulated.
3. SQL Server read the bind's and the unbind's session counts from ``cursor.rowcount``, which a
   leaked ``SET NOCOUNT ON`` reports as -1, and the bind audited that. Both now count an
   ``OUTPUT`` rowset; an offline fake driver shows it here, and the live legs run the contract in
   ``tests/_federated_binding_service_contract.py``.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.service import AuthService, FederatedSubjectHeld
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

ISSUER = "https://idp.example/b5625"


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, Path]]:
    path = tmp_path / "b5625.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        yield store, path
    finally:
        await store.close()


async def _directory_user(store: MessageStore, uid: str) -> None:
    await store.create_user(
        user_id=uid,
        username=uid,
        auth_provider="ad",
        directory_object_id=f"guid-{uid}",
        now=1_000.0,
        password_generated=False,
        audits=(),
    )


def _bend_seal(path: Path, uid: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute("UPDATE users SET authz_seal=? WHERE id=?", ("mfseal:v1:b5625:bogus", uid))
        conn.commit()
    finally:
        conn.close()


async def test_a_rebind_onto_a_pair_an_unsealed_row_holds_keeps_the_current_binding(
    keyed: tuple[MessageStore, Path],
) -> None:
    """RED when: the holder check reads through the seal-checked loader, so the clear runs and the
    index refusal leaves the account unbound with its sessions ended."""
    store, path = keyed
    service = AuthService(store, AuthSettings(require_mfa=False, oidc_issuer=ISSUER))
    await _directory_user(store, "taker")
    await _directory_user(store, "bent")
    await service.bind_federated_subject(
        "taker", "sub-mine", expected_issuer=None, expected_subject=None, actor="admin"
    )
    await service.bind_federated_subject(
        "bent", "sub-wanted", expected_issuer=None, expected_subject=None, actor="admin"
    )
    _bend_seal(path, "bent")
    await store.create_session(token_hash="t-taker", user_id="taker", expires_at=9e9, now=1_000.0)

    with pytest.raises(FederatedSubjectHeld) as held:
        await service.bind_federated_subject(
            "taker",
            "sub-wanted",
            expected_issuer=ISSUER,
            expected_subject="sub-mine",
            actor="admin",
        )

    assert "previous binding was removed" not in str(held.value)
    taker = await store.get_user("taker")
    assert taker is not None and (taker.oidc_issuer, taker.oidc_subject) == (ISSUER, "sub-mine")
    session = await store.get_session("t-taker")
    assert session is not None and session.revoked_at is None
    assert [
        a for a in await store.list_audit() if a["action"] == "auth.federated_subject_unbound"
    ] == []


async def test_a_case_variant_id_binds_under_the_id_the_row_holds(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the bind keeps using the caller's spelling of the id after the load found the row.
    The lookup is made case-insensitive here, as SQL Server's default collation makes it."""
    store, _ = keyed
    service = AuthService(store, AuthSettings(require_mfa=False, oidc_issuer=ISSUER))
    await _directory_user(store, "acct-lower")
    real_load = service._load_user

    async def ci_load(user_id: str) -> Any:
        return await real_load(user_id.lower())

    monkeypatch.setattr(service, "_load_user", ci_load)

    bound = await service.bind_federated_subject(
        "ACCT-LOWER", "sub-ci", expected_issuer=None, expected_subject=None, actor="admin"
    )

    assert (bound.issuer, bound.subject) == (ISSUER, "sub-ci")
    holder = await store.get_user_by_federated_subject(ISSUER, "sub-ci")
    assert holder is not None and holder.id == "acct-lower"
    [row] = [a for a in await store.list_audit() if a["action"] == "auth.federated_subject_bound"]
    assert '"user_id": "acct-lower"' in (row["detail"] or "")


# --- SQL Server, offline: the counts under a leaked SET NOCOUNT ON --------------------------------

_USER_ID = "u-5625"


def _nocount_sqlserver(output_rows: int) -> tuple[Any, list[str]]:
    """A SQL Server store whose driver reports -1 for every row count, as a session-wide
    ``SET NOCOUNT ON`` can. The account row read answers a bound account; the session sweep's
    ``OUTPUT`` rowset holds ``output_rows`` rows. ``_write_user`` is stubbed to a landed write."""
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store.pool_metrics import AcquireWaitHistogram
    from messagefoundry.store.row_seal import SealPager
    from messagefoundry.store.sqlserver import SqlServerStore

    seen: list[str] = []

    class _Cursor:
        rowcount = -1
        description: list[tuple[str]] = []

        def __init__(self) -> None:
            self._last = ""

        async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            seen.append(sql)
            self._last = sql

        async def fetchall(self) -> list[Any]:
            if self._last.startswith("SELECT username, oidc_issuer"):
                return [("acct", ISSUER, "sub-old", False, "")]
            if self._last.startswith("UPDATE sessions"):
                return [(f"t{i}",) for i in range(output_rows)]
            return []

        async def close(self) -> None:
            return None

    class _Conn:
        async def cursor(self) -> _Cursor:
            return _Cursor()

        async def commit(self) -> None:
            return None

        async def rollback(self) -> None:
            return None

    store: Any = SqlServerStore.__new__(SqlServerStore)
    store._settings = StoreSettings(command_timeout=0)
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0
    store._row_sealer = None
    store._seal_pager = SealPager()

    @asynccontextmanager
    async def _acquire() -> AsyncIterator[_Conn]:
        yield _Conn()

    async def _write_user(_cur: Any, _user_id: str, _change: Any) -> object:
        return object()

    store._acquire = _acquire
    store._write_user = _write_user
    return store, seen


@pytest.mark.parametrize("output_rows", [0, 2])
async def test_sqlserver_bind_counts_its_sweep_from_output_not_rowcount(output_rows: int) -> None:
    """RED when: the bind reads ``cursor.rowcount`` and returns -1."""
    store, seen = _nocount_sqlserver(output_rows)
    assert await store.set_user_federated_subject(_USER_ID, ISSUER, "sub-new") == output_rows
    assert any("OUTPUT inserted.token_hash" in sql for sql in seen)


@pytest.mark.parametrize("output_rows", [0, 2])
async def test_sqlserver_unbind_counts_its_sweep_from_output_not_rowcount(
    output_rows: int,
) -> None:
    """RED when: the unbind reads ``cursor.rowcount`` and reports -1 sessions revoked."""
    store, seen = _nocount_sqlserver(output_rows)
    cleared = await store.clear_user_federated_subject(
        _USER_ID, expected_issuer=ISSUER, expected_subject="sub-old"
    )
    assert cleared is not None and not cleared.changed
    assert cleared.sessions_revoked == output_rows
    assert any("OUTPUT inserted.token_hash" in sql for sql in seen)
