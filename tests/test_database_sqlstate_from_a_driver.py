# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Only a database driver's own error NAMES a SQLSTATE in text (engine PR 3150 open findings 1,
5 and 6); an error shaped like one is still classified by it. The connector's reading
(``_log_sqlstate``, ``_shown_state``) and the traceback line's (``redaction.driver_sqlstate_of``)
are separate. The connector still classifies an asyncpg error by the shape of its ``args[0]``,
its message, as before; neither reading names a state read from it in text.
Also two log-path changes in the same module (vault BACKLOG #1661, added items 5 and 6).

Each test was red on the code before its fix, except at least those whose docstring calls it a
control or a regression check that is not red on main. All values are synthetic.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import sys
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from messagefoundry.redaction import safe_exc, safe_traceback
from messagefoundry.transports import database
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from tests._fake_dbapi_driver import DriverError
from tests._odbc_cancel_fakes import RawConn, never
from tests.test_backlog2394_database_gate import _aioodbc_serving, _destination, _Rig
from tests.test_backlog5010_database_gate_discard import _WakingPool
from tests.test_database_transport import _dest, _FakeConn, _FakeCursor, _FakePool

_VALUE = "MRN42"  # five characters of the SQLSTATE alphabet, as an identifier can be


def _raised[E: BaseException](exc: E) -> E:
    try:
        raise exc
    except BaseException:  # noqa: BLE001 - only to give it a traceback
        return exc


# --- PR 3150 finding 1: a non-driver error is classified by shape, and its text is withheld ------


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(KeyError(_VALUE), id="KeyError"),
        pytest.param(RuntimeError("HYT00", "synthetic"), id="RuntimeError"),
        pytest.param(Exception("23000", "synthetic"), id="Exception"),
    ],
)
def test_a_non_driver_error_is_classified_by_shape_but_never_named(exc: BaseException) -> None:
    """The state still classifies the failure, as before this branch; text never names it."""
    assert database._sqlstate(exc) == exc.args[0]
    assert database._log_sqlstate(exc) == exc.args[0]
    assert database._shown_state(exc.args[0], exc) is None


async def test_a_non_driver_error_in_a_send_is_never_dead_lettered_with_its_text() -> None:
    """Red on main: ``KeyError('MRN42')`` was dead-lettered as ``database rejected the statement
    [MRN42]``, a value in ``last_error`` and the alert. It is still dead-lettered, by its shape,
    but its text and code name no state."""
    conn = _FakeConn(_FakeCursor(KeyError(_VALUE)))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(NegativeAckError) as refused:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert str(refused.value) == "database rejected the statement [SQLSTATE withheld]"
    assert refused.value.permanent and refused.value.code == "db"
    assert _VALUE not in safe_exc(refused.value)  # what the runner stores as last_error
    assert conn.rolledback


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(RuntimeError("08S01", f"link lost ({_VALUE})"), id="08S01"),
        pytest.param(RuntimeError("HYT00", f"timed out ({_VALUE})"), id="HYT00"),
    ],
)
async def test_a_shaped_transient_send_error_is_retried_naming_no_text(
    exc: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    """Red on the previous head, which made it an internal error: a non-driver error shaped like
    a transient SQLSTATE is retried as before this branch, and no message text reaches the log or
    the error the runner stores."""
    conn = _FakeConn(_FakeCursor(exc))
    dest = _dest()
    dest._pool = _FakePool(conn)
    caplog.set_level(logging.DEBUG, logger=database.logger.name)
    with pytest.raises(DeliveryError) as raised:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert not isinstance(raised.value, NegativeAckError)
    assert str(raised.value) == "database transient error [SQLSTATE withheld]"
    assert _VALUE not in safe_exc(raised.value)
    assert _VALUE not in caplog.text


@pytest.mark.parametrize(
    "exc",
    [
        pytest.param(KeyError(_VALUE), id="KeyError"),
        pytest.param(RuntimeError("23000", f"duplicate key ({_VALUE}2)"), id="driver tuple"),
    ],
)
def test_a_non_driver_error_shaped_like_a_drivers_prints_no_value_on_a_log_line(
    exc: BaseException,
) -> None:
    """Red on main for the KeyError: ``_safe_db_error`` printed ``KeyError [MRN42]``, the value as
    a SQLSTATE. Neither reads as a SQLSTATE now, and neither falls to ``safe_exc``'s text."""
    line = database._safe_db_error(exc)
    assert _VALUE not in line
    assert line == f"{type(exc).__name__} [message withheld]"


class _UnreadableState(DriverError):
    """A driver error whose ``sqlstate`` raises when read."""

    @property
    def sqlstate(self) -> str:
        raise RuntimeError("unreadable")


async def test_a_driver_error_whose_sqlstate_cannot_be_read_still_rolls_back() -> None:
    """The send reads ``args`` alone before its rollback, so an attribute that raises when read
    never skips the rollback and leaves the failed statement's transaction open (BACKLOG #5010).
    The release's connection-lost read of the attribute then raises. A regression check of this
    branch's first head, not red on main."""
    conn = _FakeConn(_FakeCursor(_UnreadableState("23000", "synthetic")))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(RuntimeError, match="unreadable"):
        await dest.send('{"mrn": "1", "val": "x"}')
    assert conn.rolledback


@pytest.mark.parametrize("attribute", ["", None, 7])
def test_an_unusable_sqlstate_attribute_falls_back_to_args(attribute: object) -> None:
    """An attribute that is not a SQLSTATE leaves ``args[0]`` read for classification, so a
    class-08 link is still seen as a lost connection. A regression check, not red on main."""
    exc = DriverError("08S01", "synthetic")
    exc.sqlstate = attribute  # type: ignore[attr-defined]
    assert database._log_sqlstate(exc) == "08S01"
    assert database._connection_lost(exc)


class _UnclassableMeta(type):
    """A class whose ``__mro__`` raises when read, so no driver test can class it."""

    @property
    def __mro__(cls) -> tuple[type, ...]:
        raise RuntimeError("unclassable")


class _Unclassable(Exception, metaclass=_UnclassableMeta):
    pass


def test_an_error_whose_driver_test_raises_is_classified_by_shape() -> None:
    """Red on the previous head, which read no state from such a class: it is classified by the
    shape of ``args[0]``, as on main, so a class-08 link is seen as lost; the state is never named."""
    exc = _Unclassable("08S01", f"link lost ({_VALUE})")
    assert database._sqlstate(exc) == "08S01"
    assert database._log_sqlstate(exc) == "08S01"
    assert database._connection_lost(exc)
    assert database._shown_state("08S01", exc) is None
    named = _Unclassable(_VALUE, "dup (900123) (SQLExecDirectW)")
    assert database._safe_db_error(named) == "_Unclassable [message withheld]"
    assert _VALUE not in database._poll_log_line(named, under=False)
    assert _VALUE not in database._credential_free_detail(named)


async def test_an_unclassable_send_error_is_retried_and_its_text_withheld(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Red on the previous head, where the send raised it as an internal error: an ``('08S01',
    ...)`` error from a class whose driver test raises is retried, as on main, and neither the
    error the runner stores nor the log carries its text or state."""
    conn = _FakeConn(_FakeCursor(_Unclassable("08S01", f"link lost ({_VALUE})")))
    dest = _dest()
    dest._pool = _FakePool(conn)
    caplog.set_level(logging.DEBUG, logger=database.logger.name)
    with pytest.raises(DeliveryError) as raised:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert not isinstance(raised.value, NegativeAckError)
    assert str(raised.value) == "database transient error [SQLSTATE withheld]"
    assert _VALUE not in safe_exc(raised.value)
    assert _VALUE not in caplog.text


async def test_a_driver_error_in_a_send_is_still_rejected_by_its_sqlstate() -> None:
    """Control: a driver's error keeps its SQLSTATE, and its message stays out of the text."""
    conn = _FakeConn(_FakeCursor(DriverError("23000", f"duplicate key ({_VALUE})")))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(NegativeAckError) as refused:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert str(refused.value) == "database rejected the statement [23000]"


# --- PR 3150 finding 5: the connector and the log chain agree on these errors ------------------


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


# --- Regressions of this branch's earlier heads ------------------------------------------------


async def test_a_wrapped_lost_link_still_discards_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red on the previous head, whose withheld error carried no chain: a driver's 08S01 under a
    non-driver error shaped like one is seen by the release's lost-link read, and discarded."""
    try:
        try:
            raise DriverError("08S01", "link lost")
        except DriverError as link:
            raise RuntimeError("HY000", "wrapped") from link
    except RuntimeError as caught:
        failure = caught
    released: list[bool] = []
    real_release = database._close_and_release

    async def recording(pool: Any, conn: Any, cur: Any, *, discard: bool = False) -> None:
        # The release's own lost-link read, as it decides with the exception in flight.
        released.append(discard or database._connection_lost(sys.exc_info()[1]))
        await real_release(pool, conn, cur, discard=discard)

    monkeypatch.setattr(database, "_close_and_release", recording)
    conn = _FakeConn(_FakeCursor(failure))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(NegativeAckError, match=r"\[SQLSTATE withheld\]"):
        await dest.send('{"mrn": "1", "val": "x"}')
    assert released == [True]


@pytest.mark.parametrize("step", ["fetch", "nextset"])
async def test_a_shaped_capture_error_rolls_back_by_its_state(step: str) -> None:
    """A non-driver error shaped like a transient SQLSTATE during the capture is the statement's
    failure, as before this branch: it propagates, the send rolls back and retries, and its text
    is withheld."""
    from tests.test_database_out_params_capture import _FaultCursor, _send_dest

    def error() -> Exception:
        return RuntimeError("40001", f"deadlock victim ({_VALUE})")

    sets: list[Any] = [([(1,)], [("id",)]), ([(0,)], [("status",)])]
    if step == "fetch":
        cur = _FaultCursor(sets, fetch_raises_on=0, fetch_error=error)
    else:
        cur = _FaultCursor(sets, nextset_raises_on=0, nextset_error=error)
    d, conn = _send_dest(cur)
    with pytest.raises(DeliveryError) as raised:
        await d.send('{"mrn": "42"}')
    assert not isinstance(raised.value, NegativeAckError)
    assert _VALUE not in safe_exc(raised.value)
    assert conn.rolledback and not conn.committed


async def test_a_shaped_client_fetch_state_commits_naming_no_text() -> None:
    """Red on the previous head, which rolled it back: a non-driver error shaped like the client
    conversion state 07006 is a capture problem, as before this branch, so the write commits; the
    capture's detail names no state."""
    from tests.test_database_out_params_capture import _FaultCursor, _send_dest

    cur = _FaultCursor(
        [([(1,)], [("id",)])],
        fetch_raises_on=0,
        fetch_error=lambda: RuntimeError("07006", f"restricted ({_VALUE})"),
    )
    d, conn = _send_dest(cur)
    resp = await d.send('{"mrn": "42"}')
    assert resp is not None and resp.outcome == "unparseable"
    assert resp.detail == "result-set not readable (RuntimeError)"
    assert conn.committed and not conn.rolledback


class _AsyncpgMessage(Exception):
    """asyncpg's shape: the message in ``args[0]``, and a ``sqlstate`` that is set but unusable."""

    __module__ = "asyncpg.exceptions._base"
    sqlstate = ""


class _AsyncpgClientMessage(Exception):
    """asyncpg's client-side shape: the message in ``args[0]``, and no ``sqlstate`` at all."""

    __module__ = "asyncpg.exceptions._base"


class _AsyncpgNoneState(Exception):
    """asyncpg's server shape with no state read: the message in ``args[0]``, ``sqlstate`` None."""

    __module__ = "asyncpg.exceptions._base"
    sqlstate = None


_ASYNCPG_SHAPES = [_AsyncpgMessage, _AsyncpgClientMessage, _AsyncpgNoneState]


@pytest.mark.parametrize("make", _ASYNCPG_SHAPES)
def test_the_traceback_line_never_reads_a_message_as_a_sqlstate(make: type[Exception]) -> None:
    """Red on the branch head before this fix (2c4ced1906e): ``_safe_db_error`` named ``[MRN42]``,
    asyncpg's message read from ``args[0]``, and the traceback line did too for an absent or None
    ``sqlstate``. Classification by that shape is kept, as on 2c4ced1906e; only the text changes."""
    exc = _raised(make(_VALUE))
    assert _VALUE not in safe_traceback((type(exc), exc, None))
    assert database._log_sqlstate(exc) == _VALUE  # classified by shape, as on 2c4ced1906e
    assert database._sqlstate(exc) == _VALUE
    assert database._shown_state(_VALUE, exc) is None
    assert database._safe_db_error(exc) == f"{make.__name__} [message withheld]"


def test_an_asyncpg_sqlstate_attribute_is_still_read() -> None:
    """Control: an asyncpg error's own ``sqlstate`` attribute still names its state."""
    exc = _AsyncpgMessage(f"duplicate key ({_VALUE})")
    exc.sqlstate = "23505"
    assert database._log_sqlstate(exc) == "23505"
    assert database._safe_db_error(exc) == "_AsyncpgMessage [23505]"
    assert "[23505] [driver message withheld]" in safe_traceback((type(exc), exc, None))


async def test_an_asyncpg_message_in_a_send_is_dead_lettered_naming_no_state(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Red on the branch head before this fix (2c4ced1906e): the send's arm dead-lettered the
    message as ``database rejected the statement [MRN42]``, code ``MRN42``, the text the runner
    stores as ``last_error`` and the alert carries. It is still dead-lettered by the same arm, a
    permanent rejection after a rollback, as on 2c4ced1906e; its text and code name no state."""
    conn = _FakeConn(_FakeCursor(_AsyncpgClientMessage(_VALUE)))
    dest = _dest()
    dest._pool = _FakePool(conn)
    caplog.set_level(logging.DEBUG, logger=database.logger.name)
    with pytest.raises(NegativeAckError) as refused:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert str(refused.value) == "database rejected the statement [SQLSTATE withheld]"
    assert refused.value.permanent and refused.value.code == "db"
    assert _VALUE not in safe_exc(refused.value)  # what the runner stores as last_error
    assert _VALUE not in caplog.text
    assert conn.rolledback


@pytest.mark.parametrize("make", _ASYNCPG_SHAPES)
async def test_an_asyncpg_message_is_never_printed_as_a_sqlstate(
    make: type[Exception], caplog: pytest.LogCaptureFixture
) -> None:
    """Red on the branch head before this fix (2c4ced1906e): an asyncpg error whose ``sqlstate`` is
    unusable or absent was read by
    its ``args[0]``, its message, so the connect error, the ``last_error`` the runner stores from
    it and the log line all printed ``[MRN42]``."""
    exc = make(_VALUE)

    async def refuse() -> Any:
        raise exc

    caplog.set_level(logging.DEBUG, logger=database.logger.name)
    with pytest.raises(DeliveryError) as raised:
        await database._connect(refuse, 1.0)
    assert _VALUE not in str(raised.value)
    assert _VALUE not in str(getattr(raised.value, "code", ""))
    assert _VALUE not in safe_exc(raised.value)  # what the runner stores as last_error
    closing: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    closing.set_exception(exc)
    database._log_late_pool_close("DATABASE", closing)
    assert "pool close failed" in caplog.text
    assert _VALUE not in caplog.text


class _NoArgs(DriverError):
    """A driver error whose ``args`` is missing when read."""

    @property
    def args(self) -> Any:  # type: ignore[override]
        raise AttributeError("args")


def test_a_missing_args_reads_as_no_sqlstate() -> None:
    """Red on the previous head: ``exc.args`` was read with no default, so an error arm raised
    before its rollback. Read with ``getattr`` and a default, as main read it."""
    assert database._sqlstate(_NoArgs()) is None


@pytest.fixture
async def rig() -> AsyncIterator[_Rig]:
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-w7-db")
    r = _Rig(executor)
    try:
        yield r
    finally:
        r.release.set()  # never leave a worker parked if an arm failed early
        executor.shutdown(wait=True)
        for pool in r.pools:
            pool_executor = database._tracked(database._POOL_EXECUTORS, pool)
            if pool_executor is not None:
                pool_executor.shutdown(wait=True)


class _ShapedTimeoutSetter(RawConn):
    """A connection whose ``timeout`` write fails with a non-driver error shaped like HYT00."""

    @property
    def timeout(self) -> int:
        return 0

    @timeout.setter
    def timeout(self, value: int) -> None:
        if value:  # the fake's own __init__ writes 0
            raise RuntimeError("HYT00", f"timed out ({_VALUE})")


async def test_a_shaped_hyt00_setter_failure_discards_and_retries(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """Red on the previous head, which returned the handle and stopped the lane on a config fault:
    a non-driver error shaped like HYT00 from the statement-timeout write discards the connection
    and retries, as before this branch, and no message text reaches the log or the error."""
    caplog.set_level(logging.DEBUG, logger=database.logger.name)
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_ShapedTimeoutSetter, blocks=never
    )
    with pytest.raises(DeliveryError) as caught:
        await _destination().send('{"a": 1}')
    assert not isinstance(caught.value, NegativeAckError), caught.value
    pool = rig.pools[0]
    assert pool.returned and pool.free == [] and rig.conn.closed
    assert _VALUE not in safe_exc(caught.value)
    assert _VALUE not in caplog.text
