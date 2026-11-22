# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5062: DDL forms the server-DB live schema check misread without raising.

Each test here failed before its fix: the reader either built a wrong expected shape or let a form
it cannot place through. A form the reader cannot place now raises ``ValueError``, which the unit
test that reads each shipped batch would surface before an open does. The shipped batches' own
expected shapes are pinned by ``tests/test_sqlserver_postgres_schema_verify_1720.py``.
"""

from __future__ import annotations

import pytest

from messagefoundry.store.server_schema_verify import declared_schema


def test_add_column_takes_any_name_as_a_column() -> None:
    """After ``ADD COLUMN`` what follows is a column, so a column named like a constraint word,
    ``index``, ``period`` or ``exclude``, enters the expected shape rather than being skipped."""
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT)",
            "ALTER TABLE t ADD COLUMN index TEXT",
            "ALTER TABLE t ADD COLUMN IF NOT EXISTS period TEXT",
            "ALTER TABLE t ADD COLUMN exclude TEXT NOT NULL",
        ),
        "postgres",
    )
    assert shape.columns["t"] == frozenset({"a", "index", "period", "exclude"})
    assert shape.column_shapes["t"]["exclude"].nullable is False


@pytest.mark.parametrize(
    ("item", "match"),
    [
        ("INDEX ix_t (a)", "inline index"),
        ("INDEX ix_t NONCLUSTERED (a)", "inline index"),
        ("period INT NULL", "cannot place"),
        ("exclude INT NULL", "cannot place"),
    ],
)
def test_a_table_item_that_is_an_index_or_could_be_a_column_raises(item: str, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        declared_schema((f"CREATE TABLE t (a INT NULL, {item})",), "sqlserver")


def test_a_constraint_of_the_period_or_exclude_shape_is_still_a_constraint() -> None:
    shape = declared_schema(("CREATE TABLE t (a INT, EXCLUDE USING gist (a WITH =))",), "postgres")
    assert shape.columns["t"] == frozenset({"a"})


def test_an_add_constraint_does_not_read_on_into_the_next_statement() -> None:
    """An ``ADD CONSTRAINT`` with no ``;`` after it used to read on into the next ``ALTER TABLE``
    and take that statement's ``PRIMARY KEY`` columns as its own table's."""
    shape = declared_schema(
        (
            "CREATE TABLE a (x INT NOT NULL, id INT NULL)",
            "CREATE TABLE b (id INT NOT NULL)",
            "IF 1 = 1 ALTER TABLE a ADD CONSTRAINT ck_a CHECK (x > 0)\n"
            "ALTER TABLE b ADD CONSTRAINT pk_b PRIMARY KEY (id)",
            "IF 1 = 1 ALTER TABLE a ADD CONSTRAINT ck_b CHECK (x < 9)\n"
            "UPDATE b SET id = 1 WHERE id = 0",
        ),
        "sqlserver",
    )
    assert shape.column_shapes["a"]["id"].nullable is True
    assert shape.column_shapes["b"]["id"].nullable is False


def test_a_foreign_key_action_does_not_end_an_add_clause() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE a (id INT NOT NULL PRIMARY KEY)",
            "CREATE TABLE b (x INT NULL)",
            "ALTER TABLE b ADD a_id INT NULL REFERENCES a(id) ON DELETE CASCADE ON UPDATE NO ACTION",
        ),
        "sqlserver",
    )
    assert shape.column_shapes["b"]["a_id"].nullable is True


def test_a_primary_key_over_a_quoted_name_with_a_space_is_not_null() -> None:
    shape = declared_schema(('CREATE TABLE t ("my col" INT, PRIMARY KEY ("my col"))',), "postgres")
    assert shape.column_shapes["t"]["my col"].nullable is False


def test_a_primary_key_inside_a_check_literal_marks_nothing() -> None:
    shape = declared_schema(
        ("CREATE TABLE t (a INT, b INT, CHECK (a::text <> 'PRIMARY KEY (b)'))",), "postgres"
    )
    assert shape.column_shapes["t"]["b"].nullable is True


@pytest.mark.parametrize(
    "clause",
    [
        "ADD CONSTRAINT pk_t PRIMARY KEY USING INDEX ix_t",
        "ADD PRIMARY KEY USING INDEX ix_t",
        "ADD CONSTRAINT uq_t UNIQUE USING INDEX ix_t",
    ],
)
def test_a_key_built_from_an_existing_index_raises(clause: str) -> None:
    with pytest.raises(ValueError, match="existing index"):
        declared_schema(("CREATE TABLE t (a INT)", f"ALTER TABLE t {clause}"), "postgres")


def test_using_index_tablespace_is_only_a_storage_option() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT)",
            "ALTER TABLE t ADD CONSTRAINT pk_t PRIMARY KEY (a) USING INDEX TABLESPACE fast",
        ),
        "postgres",
    )
    assert shape.column_shapes["t"]["a"].nullable is False


@pytest.mark.parametrize("key", ["(a::text)", "((a :: varchar(10)))", "CAST(a AS text)"])
def test_a_key_that_only_casts_a_column_raises(key: str) -> None:
    """PostgreSQL stores a cast to the column's own type as the column, so the key may read live
    as ``a`` while the reader would say ``<expr>``."""
    with pytest.raises(ValueError, match="cast"):
        declared_schema((f"CREATE INDEX ix ON t ({key})",))


def test_an_expression_around_a_cast_is_still_an_expression() -> None:
    shape = declared_schema(("CREATE INDEX ix ON t (lower(a::text))",))
    assert shape.named_indexes["ix"].columns == ("<expr>",)


def test_a_default_sign_with_nothing_after_it_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="default"):
        declared_schema(("CREATE TABLE t (a INT DEFAULT -)",), "postgres")


@pytest.mark.parametrize("clause", ["ADD COLUMN IF NOT EXISTS", "ADD COLUMN"])
def test_an_add_with_nothing_to_add_raises(clause: str) -> None:
    with pytest.raises(ValueError, match="nothing to add"):
        declared_schema(("CREATE TABLE t (a INT)", f"ALTER TABLE t {clause}"))


def test_an_alter_index_is_refused_as_what_it_is() -> None:
    with pytest.raises(ValueError, match="alter index"):
        declared_schema(("ALTER INDEX ix_t SET (fillfactor = 70)",))


def test_collate_database_default_is_the_database_collation() -> None:
    shape = declared_schema(
        ("CREATE TABLE t (a NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL)",), "sqlserver"
    )
    assert shape.column_shapes["t"]["a"].collation is None


def test_collate_catalog_default_raises() -> None:
    with pytest.raises(ValueError, match="catalog_default"):
        declared_schema(
            ("CREATE TABLE t (a NVARCHAR(64) COLLATE CATALOG_DEFAULT NOT NULL)",), "sqlserver"
        )


def test_a_guarded_drop_of_a_temporary_table_is_not_the_stores() -> None:
    shape = declared_schema(("CREATE TABLE t (a INT)", "DROP TABLE IF EXISTS #tmp"))
    assert set(shape.columns) == {"t"}


def test_a_rename_column_without_to_raises() -> None:
    with pytest.raises(ValueError, match="cannot read"):
        declared_schema(("CREATE TABLE t (a INT)", "ALTER TABLE t RENAME COLUMN a x b"))


def test_a_bracketed_name_with_a_comma_or_a_keyword_is_one_name() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t ([a,b] INT NULL, c INT NULL)",
            "IF COL_LENGTH('t','end') IS NULL ALTER TABLE t ADD [end] INT NULL",
        ),
        "sqlserver",
    )
    assert shape.columns["t"] == frozenset({"a,b", "c", "end"})


def test_a_second_create_table_raises() -> None:
    """A guarded second ``CREATE TABLE`` never runs, so the columns it alone names are never built."""
    with pytest.raises(ValueError, match="second create table"):
        declared_schema(
            ("CREATE TABLE IF NOT EXISTS t (a INT)", "CREATE TABLE IF NOT EXISTS t (a INT, b INT)")
        )
    # After a DROP the table is created again.
    shape = declared_schema(("CREATE TABLE t (a INT)", "DROP TABLE t", "CREATE TABLE t (b INT)"))
    assert shape.columns["t"] == frozenset({"b"})


@pytest.mark.parametrize(
    "index",
    [
        "CREATE INDEX ix ON t (lower(b))",
        "CREATE INDEX ix ON t (a) WHERE b IS NOT NULL",
        "CREATE INDEX ix ON t (a) INCLUDE (b)",
    ],
)
def test_a_drop_column_an_opaque_index_may_use_raises(index: str) -> None:
    with pytest.raises(ValueError, match="drop column"):
        declared_schema(("CREATE TABLE t (a INT, b INT)", index, "ALTER TABLE t DROP COLUMN b"))


def test_a_drop_column_an_opaque_index_does_not_name_keeps_the_index() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT, b INT, c INT)",
            "CREATE INDEX ix ON t (a) WHERE b IS NOT NULL",
            "ALTER TABLE t DROP COLUMN c",
        )
    )
    assert "ix" in shape.named_indexes and shape.columns["t"] == frozenset({"a", "b"})


def test_a_legacy_sqlserver_drop_index_names_its_table() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT NULL)",
            "CREATE TABLE u (a INT NULL)",
            "CREATE INDEX ix ON u (a)",
            "DROP INDEX t.ix",
        ),
        "sqlserver",
    )
    assert shape.named_indexes["ix"].table == "u"
    gone = declared_schema(
        ("CREATE TABLE u (a INT NULL)", "CREATE INDEX ix ON u (a)", "DROP INDEX u.ix"),
        "sqlserver",
    )
    assert "ix" not in gone.named_indexes


@pytest.mark.parametrize(
    "statements",
    [
        ("CREATE TABLE t (a INT)", "ALTER TABLE t ADD CONSTRAINT nn_a NOT NULL a NOT VALID"),
        ("CREATE TABLE t (a INT, CONSTRAINT nn_a NOT NULL a)",),
        ("CREATE TABLE t (a INT, NOT NULL a)",),
    ],
)
def test_a_not_null_table_constraint_raises(statements: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="not-null constraint"):
        declared_schema(statements, "postgres")


def test_the_postgres_expected_shape_holds_no_table_the_migration_drops() -> None:
    """The migration runs ``DROP TABLE IF EXISTS lane_leases`` outside the declared batch, so the
    expected shape must not hold that table, or every open would report it missing."""
    postgres = pytest.importorskip(
        "messagefoundry.store.postgres", reason="requires the postgres extra (asyncpg)"
    )
    assert "lane_leases" not in postgres._declared_schema().columns
