# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #6720: two callers of ``base.is_store_shape_error`` that the widened
``schema_verify._SHAPE_MESSAGES`` reaches.

An expected name held by an object of another kind (a view, an index, a table) now reads as a store
shape error. At least three callers outside the schema step act on that; this file pins these two
(the ``verify-audit-chain`` walk in ``__main__`` is the third, and is not covered here):

* ``auth.service._is_revoke_defect``: the post-commit session revoke raises such an error at once,
  unretried, and records no ``auth.sessions_revoke_failed`` row, as it does for any other defect.
* ``store.note_audit_chain_read``: the open no longer tags such an error as row evidence about the
  audit chain, so it is reported as a store this build cannot read.

Each case is a real SQLite error from every collision ``test_schema_verify_6719_6720`` measures, so
the code and the text are SQLite's own and a collision added there is pinned here too. The control
is a
syntax error: the same ``SQLITE_ERROR`` code, but not a shape message, which keeps the old handling.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import SESSIONS_REVOKE_FAILED_ACTION, AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.base import is_store_shape_error
from messagefoundry.store.store import AUDIT_CHAIN_READ_NOTE, MessageStore, note_audit_chain_read
from tests.test_schema_verify_6719_6720 import _COLLISIONS

_PASSWORD = "Str0ng-Synthetic-Pass!!"


def _sqlite_error(*statements: str) -> sqlite3.OperationalError:
    """The error SQLite raises on the last of ``statements``, run in a fresh in-memory database."""
    conn = sqlite3.connect(":memory:")
    try:
        for statement in statements[:-1]:
            conn.execute(statement)
        with pytest.raises(sqlite3.OperationalError) as info:
            conn.execute(statements[-1])
    finally:
        conn.close()
    return info.value


#: Same ``SQLITE_ERROR`` code, not a shape message: the old handling applies.
_SYNTAX = ("SELEC 1",)


def _not_shape() -> sqlite3.OperationalError:
    exc = _sqlite_error(*_SYNTAX)
    assert exc.sqlite_errorcode & 0xFF == sqlite3.SQLITE_ERROR  # control: same primary code
    assert not is_store_shape_error(exc), str(exc)
    return exc


# --- auth.service._is_revoke_defect ----------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_module, "_POST_COMMIT_REVOKE_BACKOFF_SECONDS", 0.0)


async def _account(store: MessageStore) -> AuthService:
    service = AuthService(store, AuthSettings(require_mfa=False))
    for role in ("viewer", "operator"):
        await store.upsert_role(role_id=role, display_name=role)
    await store.create_user(
        user_id="u1",
        username="bob",
        auth_provider="local",
        email="bob@example.org",
        password_hash=hash_password(_PASSWORD),
        password_generated=False,
        audits=(),
    )
    await store.set_user_roles("u1", ["viewer"], assigned_by="test")
    out = await service.login("bob", _PASSWORD)
    assert out.ok
    return service


async def _revoke_raising(exc: Exception) -> tuple[int, list[Any]]:
    """Run a role change whose post-commit revoke always raises ``exc``. Returns how many times the
    revoke ran and the audit rows written."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _account(store)
        calls = [0]

        async def refusing(user_id: str, **kwargs: Any) -> Any:
            calls[0] += 1
            raise exc

        store.revoke_user_sessions = refusing  # type: ignore[method-assign]
        with pytest.raises(type(exc)):
            await service.set_roles("u1", ["operator"], actor="admin")
        return calls[0], list(await store.list_audit(limit=200))
    finally:
        await store.close()


@pytest.mark.parametrize(("existing", "step"), _COLLISIONS)
async def test_a_name_held_by_another_kind_of_object_is_a_revoke_defect(
    existing: str, step: str
) -> None:
    exc = _sqlite_error("CREATE TABLE other (a TEXT)", existing, step)
    assert service_module._is_revoke_defect(exc)
    calls, rows = await _revoke_raising(exc)
    assert calls == 1, "a shape error was retried"
    assert not any(r["action"] == SESSIONS_REVOKE_FAILED_ACTION for r in rows)


async def test_a_sqlite_error_that_is_not_a_shape_is_still_retried_and_recorded() -> None:
    exc = _not_shape()
    assert not service_module._is_revoke_defect(exc)
    calls, rows = await _revoke_raising(exc)
    assert calls == service_module._POST_COMMIT_REVOKE_ATTEMPTS
    assert any(r["action"] == SESSIONS_REVOKE_FAILED_ACTION for r in rows)


# --- store.note_audit_chain_read -------------------------------------------------------------------


@pytest.mark.parametrize(("existing", "step"), _COLLISIONS)
def test_a_name_held_by_another_kind_of_object_is_not_tagged_as_row_evidence(
    existing: str, step: str
) -> None:
    exc = _sqlite_error("CREATE TABLE other (a TEXT)", existing, step)
    note_audit_chain_read(exc)
    assert AUDIT_CHAIN_READ_NOTE not in getattr(exc, "__notes__", ())


def test_a_sqlite_error_that_is_not_a_shape_is_still_tagged() -> None:
    exc = _not_shape()
    note_audit_chain_read(exc)
    assert AUDIT_CHAIN_READ_NOTE in getattr(exc, "__notes__", ())
