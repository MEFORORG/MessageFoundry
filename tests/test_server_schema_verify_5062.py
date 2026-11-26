# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5062: DDL forms the server-DB live schema check misread without raising.

Each test of a fix failed before it: the reader either built a wrong expected shape or let a form it
cannot place through. The rest are controls that pin what the fixes must not change. A form the reader cannot place now raises ``ValueError``, which the unit
test that reads each shipped batch would surface before an open does. The shipped batches' own
expected shapes are pinned by ``tests/test_sqlserver_postgres_schema_verify_1720.py``.
"""

from __future__ import annotations

import re

import pytest

from messagefoundry.store.server_schema_verify import (
    Dialect,
    ServerSchemaMismatchError,
    declared_schema,
    refuse_short_schema,
)


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


# --- review round 1 ------------------------------------------------------------------------------


def test_a_drop_column_after_a_rename_still_sees_the_opaque_index() -> None:
    with pytest.raises(ValueError, match="drop column"):
        declared_schema(
            (
                "CREATE TABLE t (a INT, b INT)",
                "CREATE INDEX ix ON t (lower(b))",
                "ALTER TABLE t RENAME COLUMN b TO c",
                "ALTER TABLE t DROP COLUMN c",
            )
        )


def test_a_drop_column_reads_the_predicate_to_its_statement_end_only() -> None:
    with pytest.raises(ValueError, match="drop column"):
        declared_schema(
            (
                "CREATE TABLE t (a INT, b TEXT, c INT)",
                "CREATE INDEX ix ON t (a) WHERE b <> ';' AND c IS NULL",
                "ALTER TABLE t DROP COLUMN c",
            )
        )
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT NULL, b INT NULL, c INT NULL)"
            " CREATE INDEX ix ON t (a) WHERE b > 0 ALTER TABLE t DROP COLUMN c",
        ),
        "sqlserver",
    )
    assert "ix" in shape.named_indexes


def test_a_drop_of_an_include_index_key_column_drops_the_index() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT, b INT)",
            "CREATE INDEX ix ON t (a) INCLUDE (b)",
            "ALTER TABLE t DROP COLUMN a",
        )
    )
    assert "ix" not in shape.named_indexes


@pytest.mark.parametrize("item", ['CONSTRAINT "nn a" NOT NULL a', "CONSTRAINT [nn a] NOT NULL a"])
def test_a_not_null_constraint_with_a_quoted_name_raises(item: str) -> None:
    with pytest.raises(ValueError, match="not-null constraint"):
        declared_schema((f"CREATE TABLE t (a INT, {item})",), "postgres")


@pytest.mark.parametrize(
    "key", ["((a)::text)", "(a::pg_catalog.text)", '(a::"text")', "(CAST(a AS pg_catalog.text))"]
)
def test_a_key_that_opens_with_a_cast_raises(key: str) -> None:
    with pytest.raises(ValueError, match="cast"):
        declared_schema((f"CREATE INDEX ix ON t ({key})",))


def test_a_bracketed_filegroup_does_not_hide_the_next_statement() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE a (x INT NOT NULL)",
            "CREATE TABLE b (y INT NULL, z INT NULL)",
            "IF 1 = 1 ALTER TABLE a ADD CONSTRAINT pk_a PRIMARY KEY (x) ON [PRIMARY]\n"
            "UPDATE b SET z = 1, y = 2",
        ),
        "sqlserver",
    )
    assert shape.column_shapes["a"]["x"].nullable is False


@pytest.mark.parametrize("name", ["delete", "update", "insert", "merge", "truncate", "select"])
def test_add_column_takes_a_data_statement_word_as_the_name(name: str) -> None:
    shape = declared_schema(
        ("CREATE TABLE t (a INT)", f"ALTER TABLE t ADD COLUMN {name} TEXT"), "postgres"
    )
    assert name in shape.columns["t"]


def test_a_postgres_column_named_index_is_a_column() -> None:
    shape = declared_schema(("CREATE TABLE t (index TEXT, a INT)",), "postgres")
    assert shape.columns["t"] == frozenset({"index", "a"})


def test_using_index_inside_a_check_literal_is_text() -> None:
    shape = declared_schema(("CREATE TABLE t (a TEXT, CHECK (a <> 'USING INDEX x'))",), "postgres")
    assert shape.columns["t"] == frozenset({"a"})


def test_an_unterminated_add_ends_at_an_alter_database() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE a (x INT NULL)",
            "IF 1 = 1 ALTER TABLE a ADD c INT NULL\n"
            "ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON",
        ),
        "sqlserver",
    )
    assert shape.column_shapes["a"]["c"].nullable is True


# --- review round 2 ------------------------------------------------------------------------------


def test_a_case_in_a_predicate_does_not_end_the_opaque_index_words() -> None:
    with pytest.raises(ValueError, match="drop column"):
        declared_schema(
            (
                "CREATE TABLE t (a INT, b INT, c INT)",
                "CREATE INDEX ix ON t (a) WHERE CASE WHEN b > 0 THEN 1 ELSE 0 END = 1"
                " AND c IS NULL",
                "ALTER TABLE t DROP COLUMN c",
            )
        )


@pytest.mark.parametrize("name", ["delete", "update", "insert"])
def test_a_constraint_named_like_a_data_word_keeps_its_key(name: str) -> None:
    shape = declared_schema(
        ("CREATE TABLE t (id INT)", f"ALTER TABLE t ADD CONSTRAINT {name} PRIMARY KEY (id)"),
        "postgres",
    )
    assert shape.column_shapes["t"]["id"].nullable is False


def test_using_index_tablespace_on_its_own_line_is_a_storage_option() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT)",
            "ALTER TABLE t ADD CONSTRAINT pk_t PRIMARY KEY (a) USING INDEX\n    TABLESPACE fast",
        ),
        "postgres",
    )
    assert shape.column_shapes["t"]["a"].nullable is False


def test_a_t_sql_if_exists_guard_ends_an_unterminated_add() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT NULL)",
            "IF COL_LENGTH('t','y') IS NULL ALTER TABLE t ADD y INT NULL\n"
            "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'ix') CREATE INDEX ix ON t (a)",
        ),
        "sqlserver",
    )
    assert shape.column_shapes["t"]["y"].nullable is True and "ix" in shape.named_indexes


def test_a_nested_subscript_is_not_a_bracketed_name() -> None:
    shape = declared_schema(("CREATE INDEX ix ON t ((a[b[1]]))",))
    assert shape.named_indexes["ix"].columns == ("<expr>",)


@pytest.mark.parametrize(
    "statement",
    ["ALTER TABLE IF EXISTS #t ADD x INT NULL", "CREATE TABLE\n    #tmp (x INT NULL)"],
)
def test_a_temporary_table_is_not_the_stores_in_any_spacing(statement: str) -> None:
    shape = declared_schema(("CREATE TABLE t (a INT NULL)", statement), "sqlserver")
    assert set(shape.columns) == {"t"}


@pytest.mark.parametrize("name", ['"x""y"', "nn$a", "[x]]y]"])
def test_a_not_null_constraint_with_an_escaped_or_dollar_name_raises(name: str) -> None:
    with pytest.raises(ValueError, match="not-null constraint"):
        declared_schema((f"CREATE TABLE t (a INT, CONSTRAINT {name} NOT NULL a)",), "postgres")


# --- review round 3 repair: regressions against main -----------------------------------------------


def test_a_guarded_drop_whose_list_goes_on_past_a_temporary_table_raises() -> None:
    with pytest.raises(ValueError, match="cannot read"):
        declared_schema(("CREATE TABLE u (a INT NULL)", "DROP TABLE IF EXISTS #tmp, u"))


@pytest.mark.parametrize(
    ("statement", "partial"),
    [
        ("IF COL_LENGTH('t','b') IS NOT NULL EXEC('CREATE INDEX ix ON t (a) WHERE b > 0')", True),
        ("EXEC('CREATE INDEX ix ON t (a) INCLUDE (b)')", False),
        ("EXEC('CREATE INDEX ix ON t (a) WHERE b <> ''x''')", True),
    ],
)
def test_an_opaque_index_inside_an_exec_string_is_read(statement: str, partial: bool) -> None:
    shape = declared_schema(("CREATE TABLE t (a INT NULL, b INT NULL)", statement), "sqlserver")
    assert shape.named_indexes["ix"].partial is partial


@pytest.mark.parametrize("name", ["update", "delete", "insert"])
def test_a_rename_to_a_data_word_is_read(name: str) -> None:
    shape = declared_schema(
        ("CREATE TABLE t (a INT)", f"ALTER TABLE t RENAME COLUMN a TO {name}"), "postgres"
    )
    assert shape.columns["t"] == frozenset({name})


@pytest.mark.parametrize(
    "statement",
    ["DROP TABLE IF EXISTS #t$1, u", "DROP TABLE IF EXISTS #a#b, u", "DROP TABLE #tmp, u"],
)
def test_a_drop_list_that_goes_on_past_any_temporary_name_raises(statement: str) -> None:
    with pytest.raises(ValueError, match="cannot read"):
        declared_schema(("CREATE TABLE u (a INT NULL)", statement))


def test_a_partial_index_in_nested_dynamic_sql_is_read() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT NULL, b NVARCHAR(9) NULL)",
            "EXEC('EXEC(''CREATE INDEX ix ON t (a) WHERE b <> ''''x'''''')')",
        ),
        "sqlserver",
    )
    assert shape.named_indexes["ix"].partial


# --- Wave 3 assembly repair --------------------------------------------------------------------


def test_an_array_literal_holding_a_bracket_is_not_a_bracketed_name() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t (a TEXT)",
            "EXEC('ALTER TABLE t ADD CONSTRAINT ck CHECK (a <> ARRAY['']''])')",
        ),
        "postgres",
    )
    assert shape.columns["t"] == frozenset({"a"})


@pytest.mark.parametrize("word", ["merge", "delete", "x$delete"])
def test_a_data_word_in_a_predicate_does_not_end_the_opaque_words(word: str) -> None:
    with pytest.raises(ValueError, match="drop column"):
        declared_schema(
            (
                f"CREATE TABLE t (a INT, {word} INT, c INT)",
                f"CREATE INDEX ix ON t (a) WHERE {word} > 0 AND c IS NULL",
                "ALTER TABLE t DROP COLUMN c",
            )
        )


def test_opaque_words_are_kept_per_table_on_sqlserver() -> None:
    """A SQL Server index name is unique only within its table, so dropping ix on u must not forget
    the partial ix on t. (A second ix on u now raises on its own: see
    test_a_second_create_index_of_a_held_name_raises.)"""
    with pytest.raises(ValueError, match="drop column"):
        declared_schema(
            (
                "CREATE TABLE t (a INT NULL, c INT NULL)",
                "CREATE TABLE u (a INT NULL, c INT NULL)",
                "CREATE INDEX ix ON t (a) WHERE c > 0",
                "DROP INDEX ix ON u",
                "ALTER TABLE t DROP COLUMN c",
            ),
            "sqlserver",
        )


def test_a_sqlserver_data_statement_ends_an_unterminated_predicate() -> None:
    """On SQL Server UPDATE is reserved, so it starts the next statement, whose words are not the
    index's."""
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT NULL, c INT NULL, d INT NULL)",
            "CREATE INDEX ix ON t (a) WHERE c > 0\nUPDATE t SET d = 1",
            "ALTER TABLE t DROP COLUMN d",
        ),
        "sqlserver",
    )
    assert "ix" in shape.named_indexes


# --- BACKLOG #8302 items 3, 5 and 6, and the #5062 remainder built with them -------------------


@pytest.mark.parametrize("second", ["CREATE INDEX ix ON u (a)", "CREATE INDEX ix ON t (c)"])
def test_a_second_create_index_of_a_held_name_raises(second: str) -> None:
    """The expected shape keys an index by name alone. A second ix on another SQL Server table
    replaced the first, and one on the same table is skipped by its guard where the first ran."""
    with pytest.raises(ValueError, match="second create index"):
        declared_schema(
            (
                "CREATE TABLE t (a INT NULL, c INT NULL)",
                "CREATE TABLE u (a INT NULL)",
                "CREATE INDEX ix ON t (a)",
                second,
            ),
            "sqlserver",
        )


def test_an_index_dropped_first_may_be_created_again() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT NULL, c INT NULL)",
            "CREATE INDEX ix ON t (a)",
            "DROP INDEX ix ON t",
            "CREATE INDEX ix ON t (c)",
        ),
        "sqlserver",
    )
    assert shape.named_indexes["ix"].columns == ("c",)


def test_an_else_outside_a_case_ends_an_unterminated_predicate() -> None:
    """On SQL Server an IF's ELSE starts another statement, whose words are not the index's, so
    dropping a column only that statement names keeps the index rather than raising."""
    shape = declared_schema(
        (
            "CREATE TABLE t (a INT NULL, c INT NULL, d INT NULL)",
            "IF 1 = 1 CREATE INDEX ix ON t (a) WHERE c > 0 ELSE PRINT d",
            "ALTER TABLE t DROP COLUMN d",
        ),
        "sqlserver",
    )
    assert "ix" in shape.named_indexes


def test_an_else_and_end_inside_a_case_stay_in_the_predicate() -> None:
    with pytest.raises(ValueError, match="drop column"):
        declared_schema(
            (
                "CREATE TABLE t (a INT, c INT, d INT)",
                "CREATE INDEX ix ON t (a) WHERE CASE WHEN c > 0 THEN 1 ELSE d END = 1",
                "ALTER TABLE t DROP COLUMN d",
            ),
            "postgres",
        )


def test_a_quote_inside_a_subscript_is_a_string() -> None:
    """``m['...']`` is a PostgreSQL subscript, not a bracketed name, so the literal inside it is
    blanked before the reader looks for the table's PRIMARY KEY, as the other scanners read it."""
    shape = declared_schema(
        ("CREATE TABLE t (m JSONB, b INT, CHECK (m['PRIMARY KEY (b)'] IS NULL))",), "postgres"
    )
    assert shape.column_shapes["t"]["b"].nullable is True


def test_an_index_taking_a_table_name_does_not_hide_that_table() -> None:
    """On SQL Server an index may share a table's name. A statistics object holding the index's
    name once hid the table's own missing column, and named the table as never created."""
    expected = declared_schema(
        (
            "CREATE TABLE foo (a INT NULL, b INT NULL)",
            "CREATE TABLE bar (x INT NULL)",
            "CREATE INDEX foo ON bar (x)",
        ),
        "sqlserver",
    )
    rows = [("foo", "table", "a", None), ("bar", "table", "x", None)]
    with pytest.raises(ServerSchemaMismatchError) as caught:
        refuse_short_schema("sqlserver", None, expected, rows, {}, {"foo": "statistics object"})
    assert caught.value.differences == (
        "index 'foo' was never built: the name is taken by a statistics object"
        " (expected on bar(x))",
        "table 'foo' is missing column 'b'",
    )


def test_an_alter_column_that_opens_its_statement_reaches_every_store() -> None:
    shape = declared_schema(
        ("CREATE TABLE t (a VARCHAR(64))", "ALTER TABLE t ALTER COLUMN a TYPE TEXT"), "postgres"
    )
    assert shape.column_shapes["t"]["a"].type == "text"
    bin2 = "CREATE TABLE t (a NVARCHAR(64) COLLATE Latin1_General_100_BIN2 NOT NULL)"
    plain = "ALTER TABLE t ALTER COLUMN a NVARCHAR(64) NOT NULL"
    assert declared_schema((bin2, plain), "sqlserver").column_shapes["t"]["a"].collation is None


def test_an_added_primary_key_follows_the_alter_column_rule() -> None:
    """An added PRIMARY KEY is read as an ALTER COLUMN SET NOT NULL is: everywhere when it opens
    its statement, and otherwise only on an older store, so a nullable CREATE TABLE raises."""
    created = "CREATE TABLE t (a INT)"
    unguarded = declared_schema((created, "ALTER TABLE t ADD PRIMARY KEY (a)"), "postgres")
    assert unguarded.column_shapes["t"]["a"].nullable is False
    for guarded in (
        "DO $$ BEGIN ALTER TABLE t ADD PRIMARY KEY (a); END $$",
        "DO $$ BEGIN ALTER TABLE t ALTER COLUMN a SET NOT NULL; END $$",
    ):
        with pytest.raises(ValueError, match="built two ways"):
            declared_schema((created, guarded), "postgres")


@pytest.mark.parametrize(
    "statement",
    [
        "IF 1 = 0 PRINT 'ALTER TABLE t ADD b INT NULL'",
        "DECLARE @s nvarchar(100) = N'ALTER TABLE t ADD b INT NULL'",
        "SELECT 'CREATE INDEX ix ON t (a)'",
        # A literal inside an EXEC string is held to the same rule, at any depth.
        "EXEC('PRINT ''ALTER TABLE t ADD b INT NULL''')",
        "EXEC('EXEC(''PRINT ''''ALTER TABLE t ADD b INT NULL'''''')')",
        # An EXEC that is itself only a literal's text runs nothing.
        "DECLARE @s nvarchar(99) = N'ALTER TABLE t ADD b INT NULL'; PRINT 'EXEC(@s)'",
    ],
)
def test_ddl_in_a_literal_no_exec_runs_raises(statement: str) -> None:
    with pytest.raises(ValueError, match="sees no EXEC run"):
        declared_schema(("CREATE TABLE t (a INT NULL)", statement), "sqlserver")


@pytest.mark.parametrize(
    "statement",
    [
        "EXEC(N'ALTER TABLE t ADD b INT NULL')",
        "DECLARE @s nvarchar(100) = N'ALTER TABLE t ADD b INT NULL'; EXEC(@s)",
        "DECLARE @s AS nvarchar(100) = N'ALTER TABLE t ADD b INT NULL'; EXEC(@s)",
        "EXEC sp_executesql N'ALTER TABLE t ADD b INT NULL'",
        "EXEC sp_executesql @stmt = N'ALTER TABLE t ADD b INT NULL'",
    ],
)
def test_ddl_in_a_literal_an_exec_runs_is_read(statement: str) -> None:
    shape = declared_schema(("CREATE TABLE t (a INT NULL)", statement), "sqlserver")
    assert shape.columns["t"] == frozenset({"a", "b"})


def test_ddl_in_a_plpgsql_execute_literal_is_read() -> None:
    shape = declared_schema(
        ("CREATE TABLE t (a INT)", "DO $$ BEGIN EXECUTE 'ALTER TABLE t ADD COLUMN b INT'; END $$"),
        "postgres",
    )
    assert shape.columns["t"] == frozenset({"a", "b"})


def test_ddl_in_a_literal_joined_to_more_text_raises() -> None:
    """The literal cut the clause short: ``DROP COLUMN b`` read alone left c expected."""
    with pytest.raises(ValueError, match="join adds more text"):
        declared_schema(
            (
                "CREATE TABLE t (a INT NULL, b INT NULL, c INT NULL)",
                "EXEC(N'ALTER TABLE t DROP COLUMN b' + N', COLUMN c')",
            ),
            "sqlserver",
        )


def test_ddl_in_a_plpgsql_literal_joined_by_a_pipe_pair_raises() -> None:
    with pytest.raises(ValueError, match="join adds more text"):
        declared_schema(
            (
                "CREATE TABLE t (a INT, b INT, c INT)",
                "DO $$ BEGIN EXECUTE 'ALTER TABLE t DROP COLUMN b' || ', DROP COLUMN c'; END $$",
            ),
            "postgres",
        )


@pytest.mark.parametrize(
    "statement",
    [
        "DECLARE @drop nvarchar(400) = N'ALTER TABLE t DROP CONSTRAINT ' + QUOTENAME(@pk);"
        " EXEC(@drop);",
        "EXEC(N'ALTER TABLE t DROP CONSTRAINT ' + QUOTENAME(@pk))",
    ],
)
def test_a_drop_constraint_named_by_quotename_is_still_read(statement: str) -> None:
    shape = declared_schema(("CREATE TABLE t (a INT NOT NULL)", statement), "sqlserver")
    assert shape.columns["t"] == frozenset({"a"})


@pytest.mark.parametrize(
    "between",
    ["SET @s = @s + N', COLUMN c';", "SET @s += N', COLUMN c';", "SELECT @s = N'PRINT 1';"],
)
def test_a_variable_changed_before_its_exec_is_not_read_as_run(between: str) -> None:
    with pytest.raises(ValueError, match="sees no EXEC run"):
        declared_schema(
            (
                "CREATE TABLE t (a INT NULL, b INT NULL, c INT NULL)",
                f"DECLARE @s nvarchar(max) = N'ALTER TABLE t DROP COLUMN b'; {between} EXEC(@s)",
            ),
            "sqlserver",
        )


@pytest.mark.parametrize(
    "statement",
    [
        # A comparison, not an assignment, so the literal is never run.
        "IF @mode = N'ALTER TABLE t ADD b INT NULL' PRINT 1; EXEC(@mode)",
        # T-SQL reads a bare string after EXECUTE as a module's name, not as SQL.
        "EXECUTE N'ALTER TABLE t ADD b INT NULL'",
    ],
)
def test_a_literal_sql_server_does_not_run_as_sql_raises(statement: str) -> None:
    with pytest.raises(ValueError, match="sees no EXEC run"):
        declared_schema(("CREATE TABLE t (a INT NULL)", statement), "sqlserver")


def test_a_guarded_alter_column_after_a_rename_is_held_to_the_create() -> None:
    """A rename once moved the CREATE TABLE shape into the older-store shapes, so a guarded ALTER
    COLUMN after it changed every shape and was read as reaching a new store."""
    with pytest.raises(ValueError, match="built two ways"):
        declared_schema(
            (
                "CREATE TABLE t (a INT NULL)",
                "EXEC sp_rename 't.a', 'b', 'COLUMN'",
                "IF 1 = 0 ALTER TABLE t ALTER COLUMN b BIGINT NULL",
            ),
            "sqlserver",
        )


def test_a_default_of_more_than_one_token_is_named_as_the_default() -> None:
    with pytest.raises(ValueError, match="a default the live-schema check cannot read"):
        declared_schema(
            ("CREATE TABLE t (a TIMESTAMPTZ DEFAULT now() + interval '1 day')",), "postgres"
        )


#: DDL a dynamic-SQL variable carries; ``NOT NULL`` so no rule about NULL refuses it first.
_RUN_DDL = "DECLARE @sql nvarchar(max) = N'CREATE TABLE t (a INT NOT NULL)';"
_DIALECTS: tuple[Dialect | None, ...] = (None, "sqlserver", "postgres")


@pytest.mark.parametrize("dialect", _DIALECTS)
@pytest.mark.parametrize(
    "tail",
    [
        # Both servers nest block comments, so the EXEC is still inside the outer comment.
        "/* /* */ EXEC(@sql) */",
        "/* a /* b */ sp_executesql @sql */",
        # Unterminated under nesting: the server's batch errors rather than running the EXEC.
        "/* /* */ EXEC(@sql);",
        # The inner opener shares its star with the first closer the old reader found.
        "/* a /*/ EXEC(@sql);",
        # Balanced, so the server runs the EXEC; refused by design rather than modelling depth.
        "/* /* */ */ EXEC(@sql)",
    ],
)
def test_a_nested_block_comment_raises(tail: str, dialect: Dialect | None) -> None:
    """BACKLOG #5062 item 26: the comment reader closed a block comment at its first ``*/``, so an
    ``EXEC`` a nesting server comments out was counted as running the literal's DDL. Any ``/*``
    inside a block comment now raises, a balanced nesting too: fail closed, not a depth model."""
    with pytest.raises(ValueError, match="a nested block comment in DDL"):
        declared_schema((f"{_RUN_DDL} {tail}",), dialect)


def test_a_nested_block_comment_in_plpgsql_raises() -> None:
    statement = "DO $$ BEGIN /* /* */ EXECUTE 'CREATE TABLE v (c INT NOT NULL)'; */ END $$;"
    with pytest.raises(ValueError, match="a nested block comment in DDL"):
        declared_schema((statement,), "postgres")


@pytest.mark.parametrize("dialect", _DIALECTS)
@pytest.mark.parametrize("bad", ["\r", "\x00", "\x85", "\u2028"])
def test_a_line_comment_holding_a_break_other_than_lf_raises(
    bad: str, dialect: Dialect | None
) -> None:
    """Review of BACKLOG #5062 item 26: PostgreSQL ends a line comment at a CR and runs what
    follows, where the reader read on to the LF and hid that DDL. The refusal names the character,
    so a NUL is not called a line break."""
    statement = f"CREATE TABLE v (c INT NOT NULL); -- note{bad}CREATE TABLE b (y INT NOT NULL);\n"
    with pytest.raises(ValueError, match=re.escape(f"a DDL line comment holds {bad!r}")):
        declared_schema((statement,), dialect)


@pytest.mark.parametrize("dialect", _DIALECTS)
@pytest.mark.parametrize("ending", ["\r\n", "\r", "\r\r\n"])
def test_a_cr_that_ends_a_line_comment_is_accepted(ending: str, dialect: Dialect | None) -> None:
    """A run of CRs reaching the LF, or the end of the entry, hides nothing: PostgreSQL may end the
    comment at the first CR and the reader ends it at the LF, but only CRs lie between, so nothing
    after the comment is hidden and the exemption refuses nothing main read."""
    shape = declared_schema((f"CREATE TABLE v (c INT NOT NULL); -- note{ending}",), dialect)
    assert shape.columns["v"] == frozenset({"c"})


def test_a_cr_followed_by_more_text_before_the_lf_raises() -> None:
    """The exemption is a run of CRs reaching the LF, not trailing whitespace."""
    with pytest.raises(ValueError, match=re.escape("a DDL line comment holds '\\r'")):
        declared_schema(("CREATE TABLE v (c INT NOT NULL); -- note\r  \n",), "postgres")


@pytest.mark.parametrize("name", ["AS[x--y]", "AS [a[--b]"])
def test_a_comment_marker_inside_a_bracket_name_still_reads_the_ddl_after_it(name: str) -> None:
    """Review of BACKLOG #5062 item 26: reading ``]]`` and a subscript ``[`` in the comment reader
    hid the ``CREATE`` after either name, which main reads. The comment reader's bracket handling
    stays main's."""
    statement = f"SELECT 1 {name}; CREATE TABLE v (a INT NOT NULL)"
    assert set(declared_schema((statement,), "sqlserver").columns) == {"v"}


@pytest.mark.xfail(
    raises=AssertionError,
    strict=True,
    reason="known misread, as on main: the comment reader ends [ at its first ]",
)
@pytest.mark.parametrize("name", ["AS [x]]--y]", "AS [p]]/*q]"])
def test_a_comment_marker_after_a_doubled_bracket_is_a_known_misread(name: str) -> None:
    """SQL Server reads ``]]`` as a ``]`` inside the name, so it builds ``v``; the reader takes the
    marker for a comment and hides it. Named in the module docstring; strict and bound to the
    assertion, so a fix that reads the name, or one that raises instead, shows here."""
    statement = f"SELECT 1 {name}; CREATE TABLE v (a INT NOT NULL); SELECT 1 AS [*/];"
    assert set(declared_schema((statement,), "sqlserver").columns) == {"v"}


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_an_exec_after_a_plain_block_comment_still_runs(dialect: Dialect | None) -> None:
    shape = declared_schema((f"{_RUN_DDL} /* c */ EXEC(@sql)",), dialect)
    assert shape.columns["t"] == frozenset({"a"})


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_an_exec_in_a_line_comment_is_not_a_run(dialect: Dialect | None) -> None:
    with pytest.raises(ValueError, match="sees no EXEC run"):
        declared_schema((f"{_RUN_DDL} -- EXEC(@sql)\n",), dialect)


def test_a_metacharacter_in_an_exec_variable_matches_only_itself() -> None:
    """Red before #5062 item 15: the variable name went into the EXEC and assignment patterns
    unescaped, so a name holding a metacharacter, such as ``a+``, matched other variables. The
    caller's capture is ``\\w+`` today; the escape keeps a wider one later from widening the read."""
    from messagefoundry.store.server_schema_verify import _assigned_and_run, _string_spans

    text = "EXEC(@aaa)"
    spans = _string_spans(text)
    assert not _assigned_and_run(text, spans, "a+", 0)
    assert _assigned_and_run("EXEC(@a+)", _string_spans("EXEC(@a+)"), "a+", 0)  # the control
    assert _assigned_and_run(text, spans, "aaa", 0)  # the control: a plain name still matches
    for run in ("sp_executesql @a+", "sp_executesql @a+;"):  # the second form matches itself too
        assert _assigned_and_run(run, _string_spans(run), "a+", 0), run
    assert not _assigned_and_run("sp_executesql @a+b", _string_spans("sp_executesql @a+b"), "a+", 0)
