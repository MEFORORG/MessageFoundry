# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ADR 0064 schema-content hash: any DDL edit must change it (forcing one full run on the next
open), and it must be deterministic (or every open would spuriously re-run the batch). No DB needed —
this pins the discriminator the ``schema_meta`` fast-path trusts; the fast-path behavior itself is
exercised by the gated server-store suites (``test_postgres_store.py`` / ``test_sqlserver_store.py``).
"""

from __future__ import annotations

import pytest


def test_sqlserver_schema_hash_tracks_ddl(monkeypatch: pytest.MonkeyPatch) -> None:
    sqlserver = pytest.importorskip(
        "messagefoundry.store.sqlserver", reason="requires the sqlserver extra (aioodbc)"
    )
    h1 = sqlserver._schema_hash()
    assert h1 == sqlserver._schema_hash()  # deterministic — a flap would re-run DDL on every open
    monkeypatch.setattr(sqlserver, "_SCHEMA", [*sqlserver._SCHEMA, "-- a future migration"])
    assert sqlserver._schema_hash() != h1  # ANY batch edit forces a full run: no version to forget


def test_postgres_schema_hash_tracks_ddl(monkeypatch: pytest.MonkeyPatch) -> None:
    postgres = pytest.importorskip(
        "messagefoundry.store.postgres", reason="requires the postgres extra (asyncpg)"
    )
    h1 = postgres._schema_hash()
    assert h1 == postgres._schema_hash()
    monkeypatch.setattr(postgres, "_SCHEMA", [*postgres._SCHEMA, "-- a future migration"])
    assert postgres._schema_hash() != h1


def test_postgres_schema_hash_tracks_migration_rev(monkeypatch: pytest.MonkeyPatch) -> None:
    # _migrate_lease_columns' Python body is invisible to the content hash, so its changes are
    # represented by _MIGRATION_REV — bumping it must invalidate the marker too.
    postgres = pytest.importorskip(
        "messagefoundry.store.postgres", reason="requires the postgres extra (asyncpg)"
    )
    h1 = postgres._schema_hash()
    monkeypatch.setattr(postgres, "_MIGRATION_REV", postgres._MIGRATION_REV + 1)
    assert postgres._schema_hash() != h1


def test_processed_files_table_present_on_all_backends() -> None:
    # ADR 0129 / #142: the processed-file dedup ledger must exist in ALL THREE backend schemas
    # (3-backend parity). SQLite's _SCHEMA is one DDL string; the server backends are DDL-statement
    # lists (adding the table there ALSO bumps their ADR-0064 _schema_hash automatically). SQLite is
    # always checkable here; the server backends run on their CI legs where the extra is installed.
    from messagefoundry.store import store as sqlite_store

    assert "processed_files" in sqlite_store._SCHEMA

    sqlserver = pytest.importorskip(
        "messagefoundry.store.sqlserver", reason="requires the sqlserver extra (aioodbc)"
    )
    assert any("CREATE TABLE processed_files" in stmt for stmt in sqlserver._SCHEMA)

    postgres = pytest.importorskip(
        "messagefoundry.store.postgres", reason="requires the postgres extra (asyncpg)"
    )
    assert any("processed_files" in stmt for stmt in postgres._SCHEMA)


def test_search_presets_table_present_on_all_backends() -> None:
    # ADR 0136 / #151: the per-user saved-search preset table must exist in ALL THREE backend schemas
    # (3-backend parity). Adding the DDL to the server backends' _SCHEMA lists ALSO bumps their
    # ADR-0064 _schema_hash automatically. SQLite is always checkable here; the server backends run on
    # their CI legs where the extra is installed.
    from messagefoundry.store import store as sqlite_store

    assert "search_presets" in sqlite_store._SCHEMA
    # id-keyed cipher column so the criteria (PHI-shaped) rotates on the generic loops.
    assert ("search_presets", "criteria") in sqlite_store.MessageStore._CIPHER_COLUMNS

    sqlserver = pytest.importorskip(
        "messagefoundry.store.sqlserver", reason="requires the sqlserver extra (aioodbc)"
    )
    assert any("CREATE TABLE search_presets" in stmt for stmt in sqlserver._SCHEMA)

    postgres = pytest.importorskip(
        "messagefoundry.store.postgres", reason="requires the postgres extra (asyncpg)"
    )
    assert any("search_presets" in stmt for stmt in postgres._SCHEMA)
    assert ("search_presets", "criteria") in postgres.PostgresStore._CIPHER_COLUMNS


def test_search_presets_last_used_at_present_on_all_backends() -> None:
    # BACKLOG #306: the last-USED retention key must exist on ALL THREE backends, both in the fresh-DB
    # CREATE TABLE *and* as a guarded ADD for an existing DB — a backend that shipped only one of the
    # two would either purge a used preset (no column) or fail every purge (missing column on upgrade).
    # SQLite migrates in _migrate (PRAGMA table_info-gated, not _SCHEMA), so it is checked there; the
    # server backends carry their guarded ALTER inside _SCHEMA, which is what moves _schema_hash.
    import inspect

    from messagefoundry.store import store as sqlite_store

    assert "last_used_at REAL" in sqlite_store._SCHEMA
    migrate_src = inspect.getsource(sqlite_store.MessageStore._migrate)
    assert "ALTER TABLE search_presets ADD COLUMN last_used_at REAL" in migrate_src

    sqlserver = pytest.importorskip(
        "messagefoundry.store.sqlserver", reason="requires the sqlserver extra (aioodbc)"
    )
    assert any(
        "CREATE TABLE search_presets" in s and "last_used_at FLOAT NULL" in s
        for s in sqlserver._SCHEMA
    )
    assert any(
        "COL_LENGTH('search_presets','last_used_at')" in s and "ADD last_used_at FLOAT NULL" in s
        for s in sqlserver._SCHEMA
    )

    postgres = pytest.importorskip(
        "messagefoundry.store.postgres", reason="requires the postgres extra (asyncpg)"
    )
    assert any(
        "CREATE TABLE IF NOT EXISTS search_presets" in s and "last_used_at DOUBLE PRECISION" in s
        for s in postgres._SCHEMA
    )
    assert (
        "ALTER TABLE search_presets ADD COLUMN IF NOT EXISTS last_used_at DOUBLE PRECISION"
        in postgres._SCHEMA
    )
