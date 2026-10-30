# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Catalog rows a fake server-DB connection returns for the live-schema check (BACKLOG #1720).

The PostgreSQL and SQL Server ``_ensure_schema`` read the live catalog after the DDL batch and before
the marker. A fake connection that answers every read with no rows would make that check report every
table missing, so the fakes that drive the batch answer the two verify reads here instead: by default
with the shape the batch declares, which is what a database the batch has just built holds. A test of
the check itself passes a shape it has changed, and ``kinds`` names a relation that holds a name as
something other than a table or an index.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from messagefoundry.store.schema_verify import SchemaShape


def pg_declared() -> SchemaShape:
    from messagefoundry.store import postgres

    return postgres._declared_schema()


def mssql_declared() -> SchemaShape:
    from messagefoundry.store import sqlserver

    return sqlserver._declared_schema()


def pg_live_rows(
    sql: str,
    args: Sequence[Any],
    shape: SchemaShape | None = None,
    kinds: Mapping[str, str] | None = None,
    overrides: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """The rows one of PostgreSQL's two verify reads returns, and none for any other statement.

    ``kinds`` maps a name to the relkind that holds it in place of the table or index ``shape`` has.
    ``overrides`` replaces fields of one index's row, such as ``{"usable": False}``."""
    from messagefoundry.store import postgres

    live = pg_declared() if shape is None else shape
    kinds = kinds or {}
    if sql == postgres._LIVE_COLUMNS_SQL:
        rows: list[dict[str, Any]] = []
        for table in args[0]:
            if table in kinds:
                rows.append({"tbl": table, "kind": kinds[table], "col": None})
            elif table not in live.columns:
                rows.append({"tbl": table, "kind": None, "col": None})
            else:
                rows += [{"tbl": table, "kind": "r", "col": c} for c in sorted(live.columns[table])]
        return rows
    if sql == postgres._LIVE_INDEXES_SQL:
        rows = []
        for name in args[0]:
            got = None if name in kinds else live.named_indexes.get(name)
            kind = kinds.get(name, None if got is None else "i")
            rows.append(
                {
                    "idx": name,
                    "kind": kind,
                    "tbl": got and got.table,
                    "uniq": got and got.unique,
                    "partial": got and got.partial,
                    "cols": list(got.columns) if got else [],
                    "usable": True,
                    "method": "btree",
                    **(overrides or {}).get(name, {}),
                }
            )
        return rows
    return []


def mssql_live_rows(
    sql: str,
    params: Sequence[Any] | None,
    shape: SchemaShape | None = None,
    kinds: Mapping[str, str] | None = None,
    flags: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[tuple[Any, ...]]:
    """The rows one of SQL Server's two verify reads returns, and none for any other statement.

    ``kinds`` maps a table name to the ``type_desc`` of the object that holds it. ``flags`` sets an
    index's ``disabled`` or ``hypothetical`` flag, or with ``stats_only`` leaves a statistics object
    of its name and no index."""
    from messagefoundry.store import sqlserver

    live = mssql_declared() if shape is None else shape
    kinds = kinds or {}
    params = list(params or ())
    if sql == sqlserver._live_columns_sql(len(params)):
        rows: list[tuple[Any, ...]] = []
        for table in params:
            if table in kinds:
                rows.append((table, kinds[table], None))
            elif table not in live.columns:
                rows.append((table, None, None))
            else:
                rows += [(table, "USER_TABLE", c) for c in sorted(live.columns[table])]
        return rows
    if sql == sqlserver._live_indexes_sql(len(params) // 2):
        rows = []
        for table, name in zip(params[::2], params[1::2], strict=True):
            got = live.named_indexes.get(name)
            flag = (flags or {}).get(name, {})
            if flag.get("stats_only") or got is None or got.table != table:
                stats = 3 if flag.get("stats_only") else None
                rows.append((name, None, None, None, None, None, stats, None, None, None))
                continue
            disabled, hypothetical = flag.get("disabled", False), flag.get("hypothetical", False)
            head = (name, 2, got.unique, got.partial, disabled, hypothetical, 2)
            for ordinal, col in enumerate(got.columns, start=1):
                desc = col.endswith(" DESC")
                rows.append((*head, ordinal, col.removesuffix(" DESC"), desc))
        return rows
    return []
