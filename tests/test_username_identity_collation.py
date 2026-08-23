# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1268: what counts as "the same username" must be decided in ONE place.

Two limbs of one root cause, and fixing either alone leaves the other a live trap:

**Limb 1 -- the column.** ``users.username`` was the one identifier column in the SQL Server schema
without an explicit ``COLLATE``, so it inherited the database default -- case-INsensitive on a stock
install (``SQL_Latin1_General_CP1_CI_AS``). SQLite (``BINARY``) and Postgres (``TEXT``) are both
case-SENSITIVE, so ``Admin`` and ``admin`` were two accounts on two backends and one account on the
third, under a ``UNIQUE`` constraint that reads as if it had settled the question.

**Limb 2 -- the gate.** ``_login_local`` decided whether to run the WP-3 bootstrap
expiry/supersession enforcement with a **Python** ``==`` against the caller's input, while the row
underneath was resolved by the **column's** collation. On a case-insensitive store those disagree in
exactly one direction: a login as ``Admin`` FAILS the Python guard (so retirement never runs) and
then SUCCEEDS at the lookup (returning the still-enabled bootstrap row). The ASVS 6.4.5 control that
disables a lapsed or superseded unclaimed bootstrap was reachable only through the guard it had just
walked past -- a compensating control resting on a false premise (SDS-3.7), the premise being that
the username the gate compared is the username the store matched.

**Why limb 2 is tested against a SIMULATED case-insensitive store rather than a real SQL Server.**
The defect's mechanism is the disagreement between the two comparisons, not anything SQL Server does
uniquely. Gating this test on ``MEFOR_TEST_SQLSERVER`` would mean the assertion that actually pins
the fix does not run in normal CI -- and a green suite on the default store was exactly what made
this invisible in the first place. The proxy below reproduces the disagreement on SQLite, so the
guard is pinned everywhere, and limb 1 keeps the real column honest.
"""

from __future__ import annotations

import re
import time
from typing import Any

import pytest

from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

_BIN2 = "COLLATE Latin1_General_100_BIN2"

#: The users table's declaration in any of the three dialects. Deliberately tolerant of the
#: ``IF NOT EXISTS`` all three actually use, and anchored on a word boundary so it cannot be
#: satisfied by a table merely named ``users_something``.
_USERS_TABLE = re.compile(r"CREATE TABLE(?:\s+IF NOT EXISTS)?\s+users\b", re.IGNORECASE)


# --- Limb 1: the column -------------------------------------------------------------------------


def _sqlserver_users_ddl() -> str:
    sqlserver = pytest.importorskip(
        "messagefoundry.store.sqlserver", reason="requires the sqlserver extra (aioodbc)"
    )
    users = [s for s in sqlserver._SCHEMA if _USERS_TABLE.search(s) is not None]
    assert len(users) == 1, f"expected exactly one users DDL statement, got {len(users)}"
    return users[0]


def test_the_username_column_pins_a_binary_collation() -> None:
    """The auth column must not inherit the database default.

    Carries its own POSITIVE CONTROL: a sibling identifier column in the same statement is asserted
    to already carry the collation. Without it, a test that only looked for ``username ... BIN2``
    would pass identically if ``_SCHEMA`` stopped being readable, if the users statement were
    renamed, or if the collation string itself changed -- the null and the pass are the same output.
    """
    ddl = _sqlserver_users_ddl()
    assert _BIN2 in ddl, "control failed: no binary collation anywhere in the users DDL"
    username = next(
        (seg for seg in ddl.split(",") if seg.strip().startswith("username")),
        None,
    )
    assert username is not None, "control failed: no username column found in the users DDL"
    assert _BIN2 in username, (
        "users.username inherits the database default collation. On a stock SQL Server install that "
        "is case-INsensitive, which makes account identity store-dependent and lets a differently "
        "cased spelling resolve to another account's row (BACKLOG #1268 limb 1)."
    )


def test_no_backend_declares_the_username_case_insensitively() -> None:
    """All three stores must agree that usernames are case-SENSITIVE.

    Stated as a refusal of the case-insensitive spellings rather than a positive match, because the
    three backends express the same decision three different ways (an explicit binary collation on
    SQL Server; the absence of ``COLLATE NOCASE`` on SQLite; the absence of ``CITEXT`` or a
    ``lower()`` functional index on Postgres). A positive match would have to enumerate three
    dialects and would go quiet the moment a fourth backend arrived.
    """
    from messagefoundry.store import store as sqlite_store

    postgres = pytest.importorskip(
        "messagefoundry.store.postgres", reason="requires the postgres extra (asyncpg)"
    )

    # Matched on the table name alone, never on the full "CREATE TABLE users" phrase: every backend
    # here spells it "CREATE TABLE IF NOT EXISTS users", so the literal phrase matches NOTHING and a
    # test written around it reports a clean pass over an empty string. The control below is what
    # turned that into a failure instead of a false green.
    sqlite_ddl = next(
        (s for s in sqlite_store._SCHEMA.split(";") if _USERS_TABLE.search(s) is not None),
        None,
    )
    assert sqlite_ddl is not None, "control failed: no users DDL found in the SQLite schema"
    assert "username" in sqlite_ddl.lower(), "control failed: no username column in the SQLite DDL"
    assert "nocase" not in sqlite_ddl.lower(), (
        "SQLite users.username must not be COLLATE NOCASE (#1268)"
    )

    pg_ddl = next((s for s in postgres._SCHEMA if _USERS_TABLE.search(s) is not None), None)
    assert pg_ddl is not None, "control failed: no users DDL found in the Postgres schema"
    assert "username" in pg_ddl.lower(), "control failed: no username column in the Postgres DDL"
    assert "citext" not in pg_ddl.lower(), "Postgres users.username must not be CITEXT (#1268)"


# --- Limb 2: the gate ---------------------------------------------------------------------------


class _CaseInsensitiveLookupStore:
    """A store whose ``get_user_by_username`` matches case-INsensitively, as a SQL Server column
    under a stock ``CI`` collation does. Everything else delegates to the real store.

    This is the whole mechanism of #1268 limb 2 in one object: the ROW the engine gets back is
    resolved by the store's rules, while the engine's own guard compared with Python's.
    """

    def __init__(self, inner: MessageStore) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def get_user_by_username(self, username: str) -> Any:
        exact = await self._inner.get_user_by_username(username)
        if exact is not None:
            return exact
        for candidate in await self._inner.list_users():
            if candidate.username.casefold() == username.casefold():
                return await self._inner.get_user(candidate.id)
        return None


async def _lapsed_bootstrap(inner: MessageStore, store: Any) -> tuple[AuthService, str]:
    """An UNCLAIMED bootstrap admin whose WP-3 window has LAPSED, with every other refusal disarmed,
    so the login gate is the only thing that can still refuse it. Returns service and password.

    **The EXPIRY arm, deliberately, and the SUPERSESSION arm is the trap.** The first version of
    these tests used supersession -- create a second administrator, then log in. Both tests PASSED
    against the unfixed code, which is what caught it: ``create_local_user`` retires the bootstrap
    eagerly at ``service.py:2685``, so the account was **already disabled before the login ran** and
    both tests were asserting a refusal that had nothing to do with the gate. Supersession can never
    exercise this defect, because it never reaches the login path with retirement still pending.
    Expiry can: nothing evaluates the window except ``_retire_superseded_bootstrap``, and on the
    login path that call sits behind the guard under test.

    ``initial_password_expiry_hours=0`` disarms the ASVS 6.4.1 credential expiry, which would
    otherwise refuse this login on its own and mask the result -- 6.4.1 is checked AFTER the password
    verifies and is not routed through the bootstrap guard, so leaving it on produces a refusal that
    looks like the control working while the control is being walked past.
    """
    service = AuthService(
        store, AuthSettings(bootstrap_expiry_hours=72, initial_password_expiry_hours=0)
    )
    boot = await service.initialize()
    assert boot is not None
    admin = await inner.get_user_by_username("admin")
    assert admin is not None and not admin.disabled
    await inner._db.execute(
        "UPDATE users SET created_at=? WHERE id=?", (time.time() - 73 * 3600, admin.id)
    )
    await inner._db.commit()
    return service, boot.password


async def test_exact_case_login_retires_the_lapsed_bootstrap() -> None:
    """POSITIVE CONTROL for the test below, and it must run against the SAME proxy.

    Its job is to prove the proxy has not broken the ordinary path, so that when the differently
    cased login behaves differently the CASE is the only variable. Run against a plain store it
    would prove nothing about the proxied one.
    """
    inner = await MessageStore.open(":memory:")
    try:
        service, password = await _lapsed_bootstrap(inner, _CaseInsensitiveLookupStore(inner))
        assert not (await service.login("admin", password)).ok
        retired = await inner.get_user_by_username("admin")
        assert retired is not None and retired.disabled
    finally:
        await inner.close()


async def test_a_differently_cased_login_cannot_walk_past_bootstrap_retirement() -> None:
    """The sharp end of #1268.

    MEASURED against the unfixed code, with the control above passing in the same run:
    ``login("admin")`` was refused and the account retired, while ``login("Admin")`` returned
    ``ok=True`` and left ``disabled`` unset -- a lapsed, unclaimed bootstrap credential logging in
    successfully because one letter was capitalised. ``"Admin" == "admin"`` is False, so
    ``_retire_superseded_bootstrap`` never ran; the lookup underneath then resolved
    case-insensitively and handed back the very row the skipped call would have disabled.
    """
    inner = await MessageStore.open(":memory:")
    try:
        service, password = await _lapsed_bootstrap(inner, _CaseInsensitiveLookupStore(inner))
        outcome = await service.login("Admin", password)
        assert not outcome.ok, (
            "a differently cased spelling of the bootstrap username walked past WP-3 retirement "
            "and logged in with a LAPSED credential (BACKLOG #1268 limb 2)"
        )
        retired = await inner.get_user_by_username("admin")
        assert retired is not None and retired.disabled, (
            "retirement never ran for the differently cased login, so the lapsed bootstrap account "
            "is still enabled"
        )
    finally:
        await inner.close()
