# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Only a database driver's own error is read for a SQLSTATE, through one reading the DATABASE
connector and the log chain share (engine PR 3150 open findings 1, 5 and 6), and two log-path
changes in the same module (vault BACKLOG #1661, added items 5 and 6).

Each test was red on the code before its fix, except where its docstring calls it a control. All
values are synthetic.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

import pytest

from messagefoundry.redaction import safe_traceback
from messagefoundry.transports import database
from messagefoundry.transports.base import NegativeAckError
from tests._fake_dbapi_driver import DriverError
from tests.test_database_transport import _dest, _FakeConn, _FakeCursor, _FakePool

_VALUE = "MRN42"  # five characters of the SQLSTATE alphabet, as an identifier can be


def _raised[E: BaseException](exc: E) -> E:
    try:
        raise exc
    except BaseException:  # noqa: BLE001 - only to give it a traceback
        return exc


# --- PR 3150 finding 1: a non-driver error is not read as a SQLSTATE ---------------------------


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(KeyError(_VALUE), id="KeyError"),
        pytest.param(RuntimeError("HYT00", "synthetic"), id="RuntimeError"),
        pytest.param(Exception("23000", "synthetic"), id="Exception"),
    ],
)
def test_a_non_driver_error_is_not_read_as_a_sqlstate(exc: BaseException) -> None:
    """Red on main: ``args[0]`` of five SQLSTATE characters read as one, whoever raised it."""
    assert database._sqlstate(exc) is None
    assert database._log_sqlstate(exc) is None


async def test_a_non_driver_error_in_a_send_is_never_dead_lettered_with_its_text() -> None:
    """Red on main: ``KeyError('MRN42')`` was dead-lettered as ``database rejected the statement
    [MRN42]``, a value in ``last_error`` and the alert. It propagates unchanged now, an internal
    error, so the connector writes no text from it."""
    failure = KeyError(_VALUE)
    conn = _FakeConn(_FakeCursor(failure))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(KeyError) as raised:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert raised.value is failure
    assert not isinstance(raised.value, NegativeAckError)
    assert conn.rolledback


def test_a_non_driver_error_names_no_sqlstate_on_a_log_line() -> None:
    """Red on main: ``_safe_db_error`` printed ``KeyError [MRN42]``, the value as a SQLSTATE."""
    assert f"[{_VALUE}]" not in database._safe_db_error(KeyError(_VALUE))


async def test_a_driver_error_in_a_send_is_still_rejected_by_its_sqlstate() -> None:
    """Control: a driver's error keeps its SQLSTATE, and its message stays out of the text."""
    conn = _FakeConn(_FakeCursor(DriverError("23000", f"duplicate key ({_VALUE})")))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(NegativeAckError) as refused:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert str(refused.value) == "database rejected the statement [23000]"


# --- PR 3150 finding 5: one reading for the connector and the log chain ------------------------


def test_a_sqlite_message_is_not_read_as_a_sqlstate_by_the_connector() -> None:
    """Red on main: the connector's copy read SQLite's ``args[0]``, its message, as a SQLSTATE,
    where the log chain's copy did not, so the two disagreed on one error."""
    exc = sqlite3.IntegrityError(_VALUE)
    assert database._sqlstate(exc) is None
    assert database._log_sqlstate(exc) is None
    assert _VALUE not in database._safe_db_error(exc)


def test_the_connector_and_the_log_chain_read_one_sqlstate() -> None:
    """Control: the same driver error names the same SQLSTATE on both paths."""
    exc = _raised(DriverError("42S02", f"no object {_VALUE}"))
    assert database._log_sqlstate(exc) == "42S02"
    assert database._safe_db_error(exc) == "DriverError [42S02]"
    assert "[42S02] [driver message withheld]" in safe_traceback((type(exc), exc, None))


# --- PR 3150 finding 6: only SQLite's own error carries its result-code name -------------------


class _NamedDriverError(DriverError):
    """A driver error that is not SQLite's, carrying an attribute of SQLite's name."""

    sqlite_errorname = "SQLITE_CONSTRAINT"


def test_a_result_code_name_reads_only_from_sqlite() -> None:
    """Red on main: the trailing ``sqlite_errorname`` read in ``redaction._driver_code`` printed
    the name for any driver's error with no SQLSTATE, and ``database._withheld`` did too."""
    exc = _NamedDriverError(f"no state {_VALUE}")
    assert "SQLITE_CONSTRAINT" not in safe_traceback((type(exc), exc, None))
    assert database._safe_db_error(exc) == "_NamedDriverError [driver message withheld]"


def test_sqlite_still_names_its_result_code() -> None:
    """SQLite's own error keeps its result-code name on both paths. Red on main at the connector,
    which read the message as a SQLSTATE and printed ``IntegrityError [MRN42]``."""
    exc = sqlite3.IntegrityError(_VALUE)
    exc.sqlite_errorname = "SQLITE_CONSTRAINT_UNIQUE"
    assert "[driver message withheld SQLITE_CONSTRAINT_UNIQUE]" in safe_traceback(
        (type(exc), exc, None)
    )
    assert database._safe_db_error(exc) == (
        "IntegrityError [driver message withheld SQLITE_CONSTRAINT_UNIQUE]"
    )


# --- #1661 added item 5: the DEBUG cursor-close lines render only when kept --------------------


def _counting_render(monkeypatch: pytest.MonkeyPatch) -> list[BaseException]:
    rendered: list[BaseException] = []

    def render(exc: BaseException, **_kwargs: Any) -> str:
        rendered.append(exc)
        return "rendered"

    monkeypatch.setattr(database, "_safe_db_error", render)
    return rendered


class _CloseFails:
    def close(self) -> None:
        raise DriverError("HY010", f"close {_VALUE}")


class _AsyncCloseFails:
    async def close(self) -> None:
        raise DriverError("HY010", f"close {_VALUE}")


async def test_a_cursor_close_failure_is_not_rendered_when_debug_is_off(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Red on main: both close sites rendered the error eagerly, before ``logger.debug`` dropped
    the line."""
    rendered = _counting_render(monkeypatch)
    caplog.set_level(logging.INFO, logger=database.logger.name)
    database._close_raw_cursor(_CloseFails())
    await database._close_cursor(_AsyncCloseFails())
    assert rendered == []


async def test_a_cursor_close_failure_is_rendered_when_debug_is_on(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Control: at DEBUG both lines still render and log."""
    rendered = _counting_render(monkeypatch)
    caplog.set_level(logging.DEBUG, logger=database.logger.name)
    database._close_raw_cursor(_CloseFails())
    await database._close_cursor(_AsyncCloseFails())
    assert len(rendered) == 2
    assert caplog.text.count("cursor close failed, ignored: rendered") == 2


# --- #1661 added item 6: an exception group keeps its members in the redacted copy -------------


def test_the_redacted_copy_keeps_an_exception_groups_members() -> None:
    """Red on main: the copy was one ``RedactedDbError``, so the members and their frames were
    dropped from the poll-failure traceback."""
    group = _raised(
        ExceptionGroup(
            "synthetic group",
            [_raised(DriverError("23000", f"duplicate ({_VALUE})")), _raised(ValueError("y"))],
        )
    )
    copy = database._safe_db_exc_info(group)
    assert isinstance(copy, BaseExceptionGroup)
    assert isinstance(copy, database.RedactedDbError)
    lines = [str(member) for member in copy.exceptions]
    assert lines == ["DriverError [23000]", "ValueError [message withheld]"]
    assert all(member.__traceback__ is not None for member in copy.exceptions)
    text = safe_traceback((type(copy), copy, copy.__traceback__))
    assert "DriverError [23000]" in text
    assert _VALUE not in text


def test_a_member_whose_chain_leads_back_to_its_group_does_not_loop() -> None:
    """A member whose context is its own group closes the cycle rather than recursing."""
    member = DriverError("23000", f"duplicate ({_VALUE})")
    group = ExceptionGroup("synthetic group", [member])
    member.__context__ = group
    copy = database._safe_db_exc_info(group)
    assert isinstance(copy, BaseExceptionGroup)
    (copied,) = copy.exceptions
    assert copied.__context__ is not None
    assert copied.__context__.args == (copy.message,)
