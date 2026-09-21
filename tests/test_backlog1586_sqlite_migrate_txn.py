# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1586: SQLite runs its startup migrations inside ONE transaction.

Outside a transaction, every ``ALTER TABLE ... ADD COLUMN`` in ``MessageStore._migrate`` commits on
its own. Two of them are paired with a one-time backfill (``users.password_claimed_at``, #1245, and
``users.notify_email``, #1139), and each backfill sits inside a column-missing guard. So a startup
that stops between the ADD and its backfill leaves the column present, and every later open skips
the backfill for good: the claim stamp and the notification address stay NULL on every existing row.

The fix is one ``BEGIN`` in ``MessageStore.open``, and its PLACEMENT is the whole fix, so these
tests pin the placement rather than the happy path. Each wrong spot fails at least one of them:

- no ``BEGIN`` at all: the ADD survives the failed open, so both interrupt tests fail;
- ``BEGIN`` before the PRAGMAs: ``journal_mode=WAL`` raises inside a transaction, so every open fails;
- ``BEGIN`` between ``synchronous`` and ``foreign_keys``: ``foreign_keys=ON`` is a silent no-op
  there, which the PRAGMA test catches;
- ``BEGIN`` before ``executescript(_SCHEMA)``: ``executescript`` COMMITs first, so the migration runs
  outside the transaction again and the interrupt tests fail.

The legacy database is built by hand, not by dropping columns from a fresh store: a users table as
it stood before any column ``_migrate`` adds, with ``_SCHEMA`` then run over it by the stdlib driver.
That file is exactly what ``_migrate`` sees on a real upgrade, primary key and all, so a failed open
must leave its schema and rows exactly as they were.
"""

from __future__ import annotations

import shutil
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from typing import Any

import aiosqlite
import pytest

from messagefoundry.store.store import _SCHEMA, MessageStore
from tests.test_store import _watch_aiosqlite_connects

#: ``users`` before any column ``_migrate`` adds. A frozen historical shape on purpose: the test in
#: this file that reaches the current shape checks the two converge, so drift reds rather than hides.
_LEGACY_USERS = """
CREATE TABLE users (
    id                   TEXT PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE,
    auth_provider        TEXT NOT NULL,
    display_name         TEXT,
    email                TEXT,
    disabled             INTEGER NOT NULL DEFAULT 0,
    created_at           REAL NOT NULL,
    updated_at           REAL NOT NULL,
    last_login_at        REAL,
    password_hash        TEXT,
    password_changed_at  REAL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until         REAL
);
"""

#: One row per backfill outcome: alice gets both, bob neither, carol only the address.
_LEGACY_ROWS = [
    ("u1", "alice", "local", "a@example.org", "h1", 1000.0, 0),
    ("u2", "bob", "local", None, "h2", 2000.0, 1),
    ("u3", "carol", "ad", "c@corp.example", None, None, 0),
]

#: What the two backfills must produce on those rows, by id: (password_claimed_at, notify_email).
_EXPECTED = {
    "u1": (1000.0, "a@example.org"),
    "u2": (None, None),
    "u3": (None, "c@corp.example"),
}

_BACKFILLED = ("password_claimed_at", "notify_email")


class _Interrupted(Exception):  # noqa: N818 -- stands in for a stop, it is not an error condition
    """Whatever stops a startup between a column's ADD and the statement after it."""


def _normal(sql: str) -> str:
    return " ".join(sql.split())


def _add_column(column: str) -> str:
    return f"ALTER TABLE users ADD COLUMN {column}"


def _build_legacy(path: Path) -> None:
    with closing(sqlite3.connect(path)) as con:
        con.executescript(_LEGACY_USERS)
        con.executemany(
            "INSERT INTO users (id, username, auth_provider, email, password_hash,"
            " password_changed_at, must_change_password, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,1.0,1.0)",
            _LEGACY_ROWS,
        )
        con.commit()
        con.executescript(_SCHEMA)
        cols = {row[1] for row in con.execute("PRAGMA table_info(users)")}
        # Positive control: _SCHEMA's CREATE TABLE IF NOT EXISTS must not have widened the table.
        assert not cols & set(_BACKFILLED), cols


def _dump(path: Path) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    """The file's whole schema and its users rows, read by the stdlib driver."""
    with closing(sqlite3.connect(path)) as con:
        schema = con.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        return schema, con.execute("SELECT * FROM users ORDER BY id").fetchall()


def _users(path: Path) -> list[dict[str, Any]]:
    with closing(sqlite3.connect(path)) as con:
        con.row_factory = sqlite3.Row
        return [dict(row) for row in con.execute("SELECT * FROM users ORDER BY id")]


def _users_columns(path: Path) -> list[str]:
    with closing(sqlite3.connect(path)) as con:
        return [row[1] for row in con.execute("PRAGMA table_info(users)")]


def _backfilled(rows: list[dict[str, Any]]) -> dict[str, tuple[Any, ...]]:
    return {row["id"]: tuple(row[c] for c in _BACKFILLED) for row in rows}


def _interrupt_after(m: pytest.MonkeyPatch, prefix: str) -> list[str]:
    """Raise :class:`_Interrupted` right after the first statement starting with ``prefix`` runs.

    The statement itself completes first, so what is under test is exactly the gap the row names:
    the ADD has happened and the statement after it has not. Every other call is passed through
    untouched, so ``async with db.execute(...)`` still works on the ones that do not match.
    """
    real = aiosqlite.Connection.execute
    fired: list[str] = []

    def execute(self: aiosqlite.Connection, sql: str, parameters: Any = None) -> Any:
        result = real(self, sql, parameters)
        if fired or not _normal(sql).startswith(prefix):
            return result

        async def interrupted() -> None:
            await result
            fired.append(sql)
            raise _Interrupted(sql)

        return interrupted()

    m.setattr(aiosqlite.Connection, "execute", execute)
    return fired


async def _open_and_close(path: Path) -> None:
    store = await MessageStore.open(path)
    await store.close()


async def _clean_migration(tmp_path: Path, legacy: Path) -> list[dict[str, Any]]:
    clean = tmp_path / "clean.db"
    shutil.copyfile(legacy, clean)
    await _open_and_close(clean)
    return _users(clean)


@pytest.fixture
def legacy(tmp_path: Path) -> Path:
    path = tmp_path / "legacy.db"
    _build_legacy(path)
    return path


@pytest.mark.parametrize("column", _BACKFILLED)
async def test_an_interrupted_backfill_heals_to_the_clean_migration(
    tmp_path: Path, legacy: Path, column: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row's acceptance: interrupt after the ADD, reopen twice, match a clean migration."""
    clean = await _clean_migration(tmp_path, legacy)
    # Controls on the reference itself. A clean run that skipped a backfill would make the equality
    # below pass on two identically wrong files, and a legacy shape that no longer converges on the
    # current one would make this test about a database nobody can have.
    assert _backfilled(clean) == _EXPECTED
    fresh = tmp_path / "fresh.db"
    await _open_and_close(fresh)
    assert set(clean[0]) == set(_users_columns(fresh))

    case = tmp_path / f"interrupted-{column}.db"
    shutil.copyfile(legacy, case)
    with monkeypatch.context() as m:
        watched: set[threading.Thread] = set()
        opened = _watch_aiosqlite_connects(m, watched)
        fired = _interrupt_after(m, _add_column(column))
        with pytest.raises(_Interrupted):
            await MessageStore.open(case)
    assert fired, f"the interrupt never fired; no statement began {_add_column(column)!r}"
    # The #1670 cleanup still runs on this path: the writer is the only connection a failed
    # migration has opened, and its worker thread is gone by the time open() has raised.
    assert len(opened) == 1, opened
    assert not [t.name for t in watched if t.is_alive()], "a failed open left a live worker"
    # The rollback is what makes the reopen below a real migration rather than a skip.
    assert _dump(case) == _dump(legacy), "the interrupted migration left changes on disk"

    for reopen in (1, 2):
        await _open_and_close(case)
        assert _users(case) == clean, f"reopen {reopen} does not match a clean migration"


async def test_an_interrupt_after_any_column_addition_leaves_the_file_as_it_was(
    tmp_path: Path, legacy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every ADD the migration issues on this file, not only the two with a backfill.

    The additions are DISCOVERED from a clean run rather than listed, so a column added to
    ``_migrate`` later is covered without anyone editing this test.
    """
    seen: list[str] = []
    real = aiosqlite.Connection.execute

    def record(self: aiosqlite.Connection, sql: str, parameters: Any = None) -> Any:
        text = _normal(sql)
        if text.startswith("ALTER TABLE") and " ADD COLUMN " in text:
            seen.append(text)
        return real(self, sql, parameters)

    with monkeypatch.context() as m:
        m.setattr(aiosqlite.Connection, "execute", record)
        await _clean_migration(tmp_path, legacy)
    # Liveness: a recorder that saw nothing would make the loop below pass by never running.
    for column in _BACKFILLED:
        assert any(s.startswith(_add_column(column)) for s in seen), (column, seen)
    assert len(seen) > len(_BACKFILLED), seen

    before = _dump(legacy)
    for index, statement in enumerate(seen):
        case = tmp_path / f"add-{index}.db"
        shutil.copyfile(legacy, case)
        with monkeypatch.context() as m:
            fired = _interrupt_after(m, statement)
            with pytest.raises(_Interrupted):
                await MessageStore.open(case)
        assert [_normal(sql) for sql in fired] == [statement]
        assert _dump(case) == before, f"interrupted after {statement!r}, the file changed"


async def test_the_connection_pragmas_hold_after_the_migration_transaction(
    tmp_path: Path,
) -> None:
    """``foreign_keys=ON`` is a silent no-op inside a transaction; nothing else would notice."""
    store = await MessageStore.open(tmp_path / "pragmas.db")
    try:
        assert await _pragma(store, "foreign_keys") == 1
        assert await _pragma(store, "journal_mode") == "wal"
        assert not store._db.in_transaction, "open() returned with its transaction still open"
    finally:
        await store.close()


async def _pragma(store: MessageStore, name: str) -> Any:
    cur = await store._db.execute(f"PRAGMA {name}")
    row = await cur.fetchone()
    assert row is not None
    return row[0]
