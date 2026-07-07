# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0075 AC-3 — CONTENT-vs-INFRA error attribution is preserved under batching.

The handoff is an all-or-nothing boundary in the pipeline: ANY raise from a ``*_handoff`` (a statement or
the commit) is the ``handoff_exc`` bucket -> INFRA -> T17 re-pend, never a content dead-letter (the
content boundary is ``route_only`` / ``transform_one``, which run BEFORE the handoff). Folding statements
into one ``execute()`` cannot move that boundary — a batched execute that faults still:
  * rolls back the single transaction and re-raises out of the handoff to the SAME (INFRA) place, and
  * carries the SAME SQL Server native code in the exception, so a signal classifier like
    ``_is_lock_timeout`` (which matches the ``(1222)`` code substring) keeps working on the batched error.

These tests inject a fake ODBC-shaped error on the execute that carries the finalize ``sp_getapplock``
(its own execute unbatched; folded into a group when batched) and assert identical propagation +
rollback + preserved native code for BOTH flag states.
"""

from __future__ import annotations

import pytest

from messagefoundry.store import sqlserver as ss

import adr0075_batch_harness as h


class FakeODBCError(Exception):
    """Shaped like a ``pyodbc.Error``: args are ``(sqlstate, message)`` and the ODBC driver embeds the
    SQL Server native code in the message text — exactly what ``_is_lock_timeout`` matches on."""


def _err(native_code: int) -> FakeODBCError:
    return FakeODBCError("HY000", f"[Microsoft][ODBC Driver] ... ({native_code}) ...")


class _RaisingAsyncCursor(h.AsyncRecCursor):
    def __init__(self, exc: Exception) -> None:
        super().__init__()
        self._exc = exc

    async def execute(self, sql: str, params: object = ()) -> None:
        await super().execute(sql, params)
        if "sp_getapplock" in sql:
            raise self._exc


class _RaisingBatchCursor(h.BatchRecCursor):
    def __init__(self, exc: Exception) -> None:
        super().__init__()
        self._exc = exc

    async def execute(self, sql: str, params: object = ()) -> None:
        await super().execute(sql, params)
        if "sp_getapplock" in sql:  # the group that folds the inserts + the applock
            raise self._exc


@pytest.fixture(autouse=True)
def _restore_uuid() -> object:
    saved = ss.uuid4
    yield
    ss.uuid4 = saved  # type: ignore[assignment]


async def _run_raising(*, batch: bool, native_code: int) -> tuple[BaseException, h.RecConn]:
    exc = _err(native_code)
    cur = _RaisingBatchCursor(exc) if batch else _RaisingAsyncCursor(exc)
    conn = h.RecConn()
    ss.uuid4 = h.DetUUID()  # type: ignore[assignment]
    with pytest.raises(FakeODBCError) as caught:
        await h.drive_async(
            h.bare_store(batch=batch), "route_handoff", cursor=cur, conn=conn, **h.ROUTE_KWARGS
        )
    return caught.value, conn


@pytest.mark.parametrize("batch", [False, True])
async def test_lock_timeout_infra_fault_propagates_and_rolls_back(batch: bool) -> None:
    raised, conn = await _run_raising(batch=batch, native_code=ss._LOCK_TIMEOUT_NATIVE_ERROR)
    # The raise propagates OUT of the handoff (INFRA -> handoff_exc -> T17 re-pend), identical to unbatched.
    assert isinstance(raised, FakeODBCError)
    # Rolled back exactly once; never committed.
    assert conn.rollbacks == 1 and conn.commits == 0
    # The native code survives batching -> the lock-timeout classifier still fires on the batched error.
    assert ss._is_lock_timeout(raised) is True


@pytest.mark.parametrize("batch", [False, True])
async def test_content_shaped_code_survives_batching(batch: bool) -> None:
    # A constraint-violation-shaped native code (2627 PK) also survives folding: the batched execute's
    # error still carries it (so downstream classification sees the same signal as unbatched), and it is
    # correctly NOT a lock timeout.
    raised, conn = await _run_raising(batch=batch, native_code=2627)
    assert conn.rollbacks == 1 and conn.commits == 0
    assert "(2627)" in str(raised)
    assert ss._is_lock_timeout(raised) is False


async def test_batched_and_unbatched_raise_identical_signal() -> None:
    # Attribution parity: the SAME native code reaches the SAME place with the SAME string in both arms —
    # so batching changes nothing a classifier keys on.
    raised_un, _ = await _run_raising(batch=False, native_code=ss._LOCK_TIMEOUT_NATIVE_ERROR)
    raised_ba, _ = await _run_raising(batch=True, native_code=ss._LOCK_TIMEOUT_NATIVE_ERROR)
    assert str(raised_un) == str(raised_ba)
    assert ss._is_lock_timeout(raised_un) == ss._is_lock_timeout(raised_ba) is True
