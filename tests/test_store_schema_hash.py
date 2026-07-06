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
