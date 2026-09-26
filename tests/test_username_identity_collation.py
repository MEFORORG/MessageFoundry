# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1268: what counts as "the same username" must be decided in ONE place.

Two limbs of one root cause, and fixing either alone leaves the other a live trap:

**Limb 1 -- the column.** ``users.username`` was the one identifier column in the SQL Server schema
without an explicit ``COLLATE``, so it inherited the database default -- case-INsensitive on a stock
install (``SQL_Latin1_General_CP1_CI_AS``). SQLite (``BINARY``) and Postgres (``TEXT``) are both
case-SENSITIVE, so ``Admin`` and ``admin`` were two accounts on two backends and one account on the
third, under a ``UNIQUE`` constraint that reads as if it had settled the question.

**Limb 2 -- the gate -- is retired with the gate it pinned.** ``_login_local`` decided whether
to run the WP-3 bootstrap expiry and supersession check with a **Python** ``==`` against the
caller's input, while the row underneath was resolved by the **column's** collation, so on a
case-insensitive store ``Admin`` walked past a check ``admin`` could not. #1268 fixed the gate to
compare the STORED row. ADR 0183 Amendment A, Wave 2 (BACKLOG #1136), then retired the first-run
account and the WP-3 check with it, so the login path no longer branches on any username and the
limb has nothing left to pin. The lesson stands for any future branch on a name: compare the row
the store resolved, never the caller's spelling.
"""

from __future__ import annotations

import re

import pytest

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
