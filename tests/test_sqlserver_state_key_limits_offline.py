# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4917: the SQL Server state and reference key checks that need no server.

**Deliberately NOT env-gated**, so it runs everywhere. Each store here is built with
``object.__new__`` and given only the one attribute the method under test reads, so a test reaches
the check and nothing else. The live twins, which show the database itself behaving as these checks
assume, are in ``tests/test_sqlserver_store.py`` and run only on the hosted ``sqlserver-store`` legs.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import pytest

from messagefoundry.store import sqlserver as ss
from messagefoundry.store.crypto import CipherError
from messagefoundry.store.sqlserver import SqlServerStore


def _bare_store(rows: list[dict[str, Any]]) -> tuple[SqlServerStore, list[str]]:
    """A store whose ``_fetchall`` answers every query with ``rows`` and records the SQL."""
    store = object.__new__(SqlServerStore)
    seen: list[str] = []

    async def _fetchall(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        seen.append(sql)
        return rows

    store._fetchall = _fetchall  # type: ignore[method-assign]
    return store, seen


def test_the_state_ddl_names_the_collation_the_report_compares_against() -> None:
    """The report is only as good as its constant: both key columns of the shipped ``state`` DDL
    carry exactly ``_STATE_KEY_COLLATION``."""
    (ddl,) = [stmt for stmt in ss._SCHEMA if "CREATE TABLE state (" in stmt]
    for column in ("namespace", "[key]"):
        assert re.search(
            rf"{re.escape(column)} NVARCHAR\(256\) COLLATE {ss._STATE_KEY_COLLATION} NOT NULL", ddl
        ), column


async def test_a_bin2_state_table_reports_nothing(caplog: pytest.LogCaptureFixture) -> None:
    store, seen = _bare_store(
        [
            {"name": "namespace", "collation_name": "Latin1_General_100_BIN2"},
            {"name": "key", "collation_name": "Latin1_General_100_BIN2"},
        ]
    )
    with caplog.at_level(logging.WARNING, logger=ss.__name__):
        assert await store._report_state_key_collation() is None
    assert caplog.records == []
    assert len(seen) == 1 and "sys.columns" in seen[0] and "OBJECT_ID('state')" in seen[0]


async def test_an_absent_state_table_reports_nothing(caplog: pytest.LogCaptureFixture) -> None:
    store, _ = _bare_store([])
    with caplog.at_level(logging.WARNING, logger=ss.__name__):
        assert await store._report_state_key_collation() is None
    assert caplog.records == []


async def test_an_older_state_table_is_reported_and_not_repaired(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A table made before BACKLOG #1588 took the database default. The report names it at
    WARNING, says nothing is repaired, and issues only the one metadata read: no ALTER, no UPDATE."""
    store, seen = _bare_store(
        [
            {"name": "namespace", "collation_name": "SQL_Latin1_General_CP1_CI_AS"},
            {"name": "key", "collation_name": "SQL_Latin1_General_CP1_CI_AS"},
        ]
    )
    with caplog.at_level(logging.WARNING, logger=ss.__name__):
        found = await store._report_state_key_collation()
    assert found == "SQL_Latin1_General_CP1_CI_AS"
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    text = record.getMessage()
    assert "SQL_Latin1_General_CP1_CI_AS" in text and ss._STATE_KEY_COLLATION in text
    assert "does not repair" in text
    assert len(seen) == 1 and seen[0].lstrip().upper().startswith("SELECT")


async def test_one_drifted_column_is_enough_to_report() -> None:
    store, _ = _bare_store(
        [
            {"name": "namespace", "collation_name": "Latin1_General_100_BIN2"},
            {"name": "key", "collation_name": "Latin1_General_CI_AS"},
        ]
    )
    assert await store._report_state_key_collation() == "Latin1_General_CI_AS"


async def test_an_undecryptable_row_names_the_drifted_collation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The keyed symptom of a merged row is a CipherError at the cache warm-up. It still fails
    closed, and when the report found a folding collation the error carries a note naming it. The
    control: with no drift found, the same error carries no such note."""

    def _refuse(*args: Any, **kwargs: Any) -> Any:
        raise CipherError("could not decrypt a state row")

    monkeypatch.setattr(ss, "decrypt_json_cell", _refuse)
    row = {"namespace": "ns", "key": "k", "value": "mfenc:x"}

    store, _ = _bare_store([row])
    store._cipher = object()  # type: ignore[assignment]
    with pytest.raises(CipherError) as drifted:
        await store._load_state_cache_noting("SQL_Latin1_General_CP1_CI_AS")
    notes = getattr(drifted.value, "__notes__", [])
    assert any("SQL_Latin1_General_CP1_CI_AS" in n and "#4917" in n for n in notes)

    store2, _ = _bare_store([row])
    store2._cipher = object()  # type: ignore[assignment]
    with pytest.raises(CipherError) as plain:
        await store2._load_state_cache_noting(None)
    assert getattr(plain.value, "__notes__", []) == []


def test_reference_keys_differing_only_by_trailing_spaces_are_refused() -> None:
    """``pk_reference`` pads trailing spaces, so these would raise a PK duplicate mid-transaction.
    The guard refuses first, naming both keys by ordinal and hash, never by value."""
    store = object.__new__(SqlServerStore)
    for rows, first, later in (
        ({"MRN-1": 1, "MRN-1 ": 2}, 0, 1),
        ({"MRN-1  ": 1, "other": 2, "MRN-1 ": 3}, 0, 2),  # two padded keys, no bare one
        ({"MRN-1 ": 1, "other": 2, "MRN-1": 3}, 0, 2),  # the bare key comes later
    ):
        with pytest.raises(ValueError, match="only by trailing spaces") as exc:
            store._guard_reference_widths("set", rows)
        text = str(exc.value)
        assert f"keys #{first} and #{later} differ" in text
        assert "MRN" not in text  # raw keys withheld (PHI)


def test_reference_keys_that_do_not_collide_pass_the_guard() -> None:
    """The controls: a lone trailing space, a leading space, a trailing tab, and a case variant are
    each distinct under BIN2 and pass."""
    store = object.__new__(SqlServerStore)
    store._guard_reference_widths("set", {"a ": 1, " a": 2, "a\t": 3, "A": 4, "b": 5})
