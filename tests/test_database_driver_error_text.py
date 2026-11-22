# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Driver-error text in the DATABASE connector and the log chain (vault BACKLOG #1661, added items
1 to 4).

Each test was red on the code before its fix, except where its docstring calls it a control or a
pin. All values are synthetic.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import types
from collections.abc import Iterator
from typing import Any

import pytest

from messagefoundry.redaction import raised_by_a_driver, safe_traceback
from messagefoundry.transports import database
from messagefoundry.transports.base import NegativeAckError
from tests.test_database_transport import (
    _dest,
    _FakeConn,
    _FakeCursor,
    _FakePool,
    _src,
)

_SYNTHETIC_ID = "424242"
#: A driver message that quotes the value a statement carried, as SQL Server's 2627 does.
_DUPLICATE = (
    "[23000] [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]Violation of PRIMARY KEY "
    f"constraint 'PK_p'. The duplicate key value is (MRN{_SYNTHETIC_ID}). (2627) (SQLExecDirectW)"
)
_DRIVER_MODULE = "synthetic_w5_dbapi_driver"


class _DriverError(Exception):
    """A DB-API 2.0 driver's error, from :func:`_dbapi_driver`'s module."""

    __module__ = _DRIVER_MODULE


@pytest.fixture
def _dbapi_driver(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    module = types.ModuleType(_DRIVER_MODULE)
    module.apilevel = "2.0"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, _DRIVER_MODULE, module)
    yield


def _rendered(exc: BaseException) -> str:
    return safe_traceback((type(exc), exc, exc.__traceback__))


def _raised(exc: BaseException) -> BaseException:
    try:
        raise exc
    except BaseException as caught:  # noqa: BLE001 - only to give it a traceback
        return caught


# --- #1661 added items 1 and 2: what reads as a SQLSTATE --------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(OSError("reset"), id="OSError word"),
        pytest.param(UnicodeEncodeError("ascii", "x\xe9", 1, 2, "synthetic"), id="codec name"),
        pytest.param(UnicodeEncodeError("UTF16", "x", 0, 1, "synthetic"), id="codec name, upper"),
    ],
)
def test_a_word_or_a_codec_name_is_not_read_as_a_sqlstate(exc: BaseException) -> None:
    """Items 1 and 2: five alphanumerics read as a SQLSTATE, so ``OSError('reset')`` printed a
    false ``[reset]`` and a codec error a permanent ``[ascii]``. Red on main for each, at
    ``_sqlstate``. The uppercase codec name is refused by its ``UnicodeError`` arm alone."""
    assert database._sqlstate(exc) is None
    assert database._log_sqlstate(exc) is None


@pytest.mark.parametrize("state", ["23000", "08S01", "HYT00", "42S02", "01000"])
def test_a_sqlstate_still_reads(state: str) -> None:
    """Control: SQLSTATEs of the SQL alphabet still read."""
    assert database._sqlstate(Exception(state, "synthetic")) == state


@pytest.mark.parametrize("codec", ["ascii", "UTF16"])
async def test_a_codec_error_in_a_send_is_dead_lettered_naming_no_codec(codec: str) -> None:
    """Item 2: in the destination arm the codec name read as a SQLSTATE, so the send was dead-
    lettered as ``database rejected the statement [ascii]``. It is still dead-lettered, since it
    fails on the message's text, but by its type. Red on main: the text named ``[ascii]``."""
    failure = UnicodeEncodeError(codec, "x\xe9", 1, 2, "synthetic")
    conn = _FakeConn(_FakeCursor(failure))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(NegativeAckError) as refused:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert refused.value.permanent is True
    assert str(refused.value) == (
        "database driver could not encode the message's text (UnicodeEncodeError)"
    )
    assert conn.rolledback


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(KeyError("synthetic"), id="non-driver error"),
        pytest.param(UnicodeDecodeError("utf-8", b"\xff", 0, 1, "synthetic"), id="decode error"),
    ],
)
async def test_a_non_driver_error_in_a_send_still_propagates(failure: Exception) -> None:
    """Control: an error that is no driver's, and a decode of text the driver returned, are still
    internal errors, as on main for a codec whose name is not SQLSTATE-shaped."""
    conn = _FakeConn(_FakeCursor(failure))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(type(failure)):
        await dest.send('{"mrn": "1", "val": "x"}')


async def test_a_driver_error_in_a_send_is_still_rejected() -> None:
    """Control: a driver error with a SQLSTATE is still a permanent rejection naming it."""
    conn = _FakeConn(_FakeCursor(Exception("23000", "synthetic")))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(NegativeAckError, match=r"\[23000\]"):
        await dest.send('{"mrn": "1", "val": "x"}')


# --- #1661 added item 3: the driver arm of safe_traceback --------------------------------------


@pytest.mark.usefixtures("_dbapi_driver")
def test_the_log_chain_withholds_a_driver_message() -> None:
    """Item 3: every ``exc_info`` site renders through ``safe_traceback``, which printed a driver
    error's message, value included. Red on main: the duplicate key reached the text."""
    text = _rendered(_raised(_DriverError("23000", _DUPLICATE)))
    assert _SYNTHETIC_ID not in text
    assert "_DriverError: [23000] [driver message withheld]" in text
    assert "Traceback (most recent call last)" in text  # the frames are kept


@pytest.mark.usefixtures("_dbapi_driver")
def test_the_log_chain_withholds_every_link_under_a_driver_error() -> None:
    """A driver raises its error from the builtin one its codec raised, whose text quotes the value
    too. Red on main: the cause printed the value."""
    try:
        try:
            raise ValueError(f"invalid literal: 'MRN{_SYNTHETIC_ID}'")
        except ValueError as codec:
            raise _DriverError(f"MRN{_SYNTHETIC_ID} could not be bound") from codec
    except _DriverError as caught:
        text = _rendered(caught)
    assert _SYNTHETIC_ID not in text
    assert "ValueError: [driver message withheld]" in text
    assert "_DriverError: [driver message withheld]" in text


@pytest.mark.usefixtures("_dbapi_driver")
def test_the_log_chain_drops_a_driver_errors_notes() -> None:
    """A note is printed after the line, and a caller can build one from the statement's values."""
    exc = _raised(_DriverError("23000", "synthetic"))
    exc.add_note(f"key MRN{_SYNTHETIC_ID}")
    assert _SYNTHETIC_ID not in _rendered(exc)


def test_the_log_chain_names_sqlites_result_code() -> None:
    """SQLite has no SQLSTATE, so its result-code name is the diagnostic kept."""
    import sqlite3

    exc = sqlite3.IntegrityError(f"UNIQUE constraint failed: MRN{_SYNTHETIC_ID}")
    exc.sqlite_errorname = "SQLITE_CONSTRAINT_UNIQUE"
    text = _rendered(_raised(exc))
    assert _SYNTHETIC_ID not in text
    assert "IntegrityError: [driver message withheld SQLITE_CONSTRAINT_UNIQUE]" in text


def test_the_log_chain_keeps_a_non_driver_message() -> None:
    """Control: an error no driver raised keeps its text, the diagnostic for a bug."""
    text = _rendered(_raised(KeyError("synthetic_column")))
    assert "KeyError: 'synthetic_column'" in text


@pytest.mark.parametrize("name", ["SQLITE_CONSTRAINT_TRIGGER", None])
def test_a_short_sqlite_message_is_not_read_as_a_sqlstate(name: str | None) -> None:
    """SQLite has no SQLSTATE, and its ``args[0]`` is its message. Red on 7c7c0cc54cd: a message
    of five uppercase letters or digits printed as ``[MRN42]``, the value as if it were a code,
    and the result-code name was dropped."""
    import sqlite3

    exc = sqlite3.IntegrityError("MRN42")
    if name is not None:
        exc.sqlite_errorname = name
    text = _rendered(_raised(exc))
    assert "MRN42" not in text
    kept = f" {name}" if name is not None else ""
    assert f"IntegrityError: [driver message withheld{kept}]" in text


def test_a_class_chain_that_cannot_be_read_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Red on 7c7c0cc54cd: an error reading the class chain answered "not a driver", so the
    message printed in full. It now answers "a driver", so the message is withheld."""
    import messagefoundry.redaction as redaction

    def unreadable(_kind: type) -> bool:
        raise ImportError("synthetic lazy module")

    monkeypatch.setattr(redaction, "_a_driver_class", unreadable)
    exc = _raised(RuntimeError(f"dup key MRN{_SYNTHETIC_ID}"))
    assert raised_by_a_driver(exc) is True
    assert _SYNTHETIC_ID not in _rendered(exc)


def test_a_class_with_no_text_module_does_not_break_the_traceback() -> None:
    """Review round 1: the driver test read ``__module__`` as text, so a class whose module is not
    text made the renderer raise on every traceback holding it."""
    odd = type("Odd", (Exception,), {"__module__": None})
    assert raised_by_a_driver(odd("synthetic")) is False
    assert "Odd: synthetic" in _rendered(_raised(odd("synthetic")))


@pytest.mark.usefixtures("_dbapi_driver")
def test_a_driver_attribute_that_raises_still_withholds_the_message() -> None:
    """Review round 2: ``_driver_line`` read ``sqlstate`` unguarded, so a property that raises
    broke the whole traceback."""

    class Raising(_DriverError):
        @property
        def sqlstate(self) -> str:
            raise RuntimeError("synthetic")

    text = _rendered(_raised(Raising(_DUPLICATE)))
    assert "Raising: [driver message withheld]" in text
    assert _SYNTHETIC_ID not in text


@pytest.mark.usefixtures("_dbapi_driver")
def test_the_fail_closed_fallback_withholds_a_driver_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review round 1: on a CPython with no ``TracebackException._str`` the renderer returns one
    line, and for a driver error that line was ``safe_exc``'s, which keeps the duplicate key."""
    import traceback

    real = traceback.TracebackException.__init__

    def without_str(self: traceback.TracebackException, *args: Any, **kwargs: Any) -> None:
        real(self, *args, **kwargs)
        self.__dict__.pop("_str", None)

    monkeypatch.setattr(traceback.TracebackException, "__init__", without_str)
    text = _rendered(_raised(_DriverError("23000", _DUPLICATE)))
    assert text == "_DriverError: [23000] [driver message withheld]"


def test_the_log_chain_and_the_connector_share_one_driver_test() -> None:
    """Pin: the connector reads the log chain's test, so the two cannot drift apart."""
    assert database._raised_by_a_driver is raised_by_a_driver


@pytest.mark.usefixtures("_dbapi_driver")
def test_a_logged_driver_error_reaches_the_record_withheld(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """End to end through the log chain's first filter step, as a configured handler runs it."""
    from messagefoundry.redaction import prepare_log_record

    record = logging.LogRecord(
        "synthetic", logging.ERROR, __file__, 1, "store write failed", None, None
    )
    failure = _raised(_DriverError("23000", _DUPLICATE))
    record.exc_info = (type(failure), failure, failure.__traceback__)
    prepare_log_record(record)
    assert record.exc_text is not None
    assert _SYNTHETIC_ID not in record.exc_text
    assert "[23000] [driver message withheld]" in record.exc_text


# --- #1661 added item 4: driver-shaped tests for four log sites ---------------------------------
#
# Pins, not red tests: each site already rendered through ``_safe_db_error``. The red mutation for
# each is to log ``exc`` itself, or ``safe_exc(exc)``, in its place.


def _driver_value_error() -> _DriverError:
    return _DriverError(f"invalid input for query argument $1: 'MRN{_SYNTHETIC_ID}'")


@pytest.mark.usefixtures("_dbapi_driver")
def test_close_raw_cursor_logs_no_driver_value(caplog: pytest.LogCaptureFixture) -> None:
    class Cursor:
        def close(self) -> None:
            raise _driver_value_error()

    caplog.set_level(logging.DEBUG, logger=database.logger.name)
    database._close_raw_cursor(Cursor())
    assert "cursor close failed" in caplog.text
    assert _SYNTHETIC_ID not in caplog.text


@pytest.mark.usefixtures("_dbapi_driver")
def test_leads_or_cut_logs_no_driver_value(caplog: pytest.LogCaptureFixture) -> None:
    src = _src()

    def gate() -> bool:
        raise _driver_value_error()

    src._leads = gate  # type: ignore[method-assign]
    caplog.set_level(logging.WARNING, logger=database.logger.name)
    assert src._leads_or_cut() is False
    assert "leader gate failed" in caplog.text
    assert _SYNTHETIC_ID not in caplog.text


@pytest.mark.usefixtures("_dbapi_driver")
async def test_emit_event_logs_no_driver_value(caplog: pytest.LogCaptureFixture) -> None:
    src = _src()

    async def sink(_kind: str, _peer: object, _reason: str | None) -> None:
        raise _driver_value_error()

    src.on_connection_event = sink
    caplog.set_level(logging.WARNING, logger=database.logger.name)
    await src._emit_event("synthetic_event")
    assert "connection-event emit failed" in caplog.text
    assert _SYNTHETIC_ID not in caplog.text


@pytest.mark.usefixtures("_dbapi_driver")
async def test_finish_stop_logs_no_driver_value(caplog: pytest.LogCaptureFixture) -> None:
    """Both of its log lines: a faulted poll task, and a pool close that fails after a cancel."""
    src = _src()

    async def faulted() -> None:
        raise _driver_value_error()

    task: asyncio.Task[None] = asyncio.ensure_future(faulted())
    await asyncio.wait([task])
    src._task = task

    async def aclose(*, timeout: float | None = None) -> None:
        raise _driver_value_error()

    src.aclose = aclose  # type: ignore[method-assign]
    caplog.set_level(logging.WARNING, logger=database.logger.name)
    await src._finish_stop(task, interrupted=True)
    assert "poll task failed" in caplog.text
    assert "pool close failed" in caplog.text
    assert _SYNTHETIC_ID not in caplog.text
