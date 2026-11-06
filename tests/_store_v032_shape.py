# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A store as release v0.3.2 built it, on each backend, for the BACKLOG #1720 open tests.

v0.3.2 (2026-07-28) is the release the #1720 filing measured; 0.4.0 and the 0.5 releases came after
it, and no test opens a store one of those built. ``_store_v032_shape.json`` holds the DDL v0.3.2 ran
on a store it had just created, verbatim, so a test can build that store and open it with this build:

* ``sqlite``: every object's ``sqlite_master.sql``, in creation order, read from a store the v0.3.2
  ``MessageStore.open`` built. That is ``_SCHEMA`` plus the three indexes its ``_migrate`` built.
  ``sqlite_sequence`` is left out, because SQLite creates it for the first AUTOINCREMENT table.
* ``postgres``: v0.3.2 ``postgres._SCHEMA``, then ``postgres_migration``, the statements its
  ``_migrate_lease_columns`` ran on that new store. Every ALTER there is guarded by a column read and
  is skipped on a store ``_SCHEMA`` just built, so only the index builds and the drops remain.
* ``sqlserver``: v0.3.2 ``sqlserver._SCHEMA``, with its two claim procedures as they rendered. It ran
  no other DDL.
* ``postgres_marker`` and ``sqlserver_marker``: the ``schema_meta`` hash v0.3.2's ``_schema_hash``
  computes from the statements above, which is what each backend wrote.

Where the clone holds the v0.3.2 tag, ``tests/test_sqlserver_postgres_schema_verify_1720.py`` reads
the batches back from it, in order. A shallow CI clone has no tags, so there those tests skip.

Embedded rather than read from the tag when a test runs, because a shallow CI clone carries no tags.
The JSON is ASCII with escapes, so the comments' dashes do not count as new glyphs. Synthetic data
only: one account and one preset it owns, under the names ``tests/test_search_presets.py`` uses.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Final

_DATA = json.loads((Path(__file__).with_name("_store_v032_shape.json")).read_text(encoding="ascii"))

SQLITE_DDL: Final[tuple[str, ...]] = tuple(_DATA["sqlite"])
POSTGRES_BATCH: Final[tuple[str, ...]] = tuple(_DATA["postgres"])
POSTGRES_MIGRATION: Final[tuple[str, ...]] = tuple(_DATA["postgres_migration"])
POSTGRES_MARKER: Final[str] = _DATA["postgres_marker"]
SQLSERVER_BATCH: Final[tuple[str, ...]] = tuple(_DATA["sqlserver"])
SQLSERVER_MARKER: Final[str] = _DATA["sqlserver_marker"]

#: Written into the v0.3.2 tables after the DDL. 0.3.2 keyed a preset on its owner's USERNAME, in a
#: column named ``owner``; the account exists from 1.0 and saved the preset at 2.0.
SEED_ROWS: Final[tuple[str, ...]] = (
    "INSERT INTO users (id, username, auth_provider, created_at, updated_at)"
    " VALUES ('u-alice', 'alice', 'local', 1.0, 1.0)",
    "INSERT INTO search_presets (id, owner, name, created_at, updated_at)"
    " VALUES ('pa', 'alice', 'ACME ADT', 2.0, 2.0)",
)


def build_sqlite_v032(path: Path) -> None:
    """Create ``path`` as the store v0.3.2 built, holding :data:`SEED_ROWS`."""
    conn = sqlite3.connect(path)
    try:
        for statement in (*SQLITE_DDL, *SEED_ROWS):
            conn.execute(statement)
        conn.commit()
    finally:
        conn.close()
