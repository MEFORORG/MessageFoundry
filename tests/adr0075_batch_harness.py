# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared offline (no-DB) harness for the ADR 0075 per-hop statement-batching tests.

Drives the REAL shipped SQL Server handoff methods (``route_handoff`` / ``transform_handoff`` and their
``_*_batched`` forms) against **recording fake cursors** — the same offline style as
``tests/test_sqlserver_sync_handoff_offline.py`` — with NO live SQL Server and no pyodbc/aioodbc extra.

Two recorders:
  * :class:`AsyncRecCursor` records each ``execute`` as one ``(sql, params)`` — the UNBATCHED logical
    sequence and its round-trips are one and the same.
  * :class:`BatchRecCursor` records the batched ROUND-TRIPS in ``.calls`` (one entry per grouped
    ``execute``, carrying the rendered T-SQL batch) AND the per-statement LOGICAL sequence in
    ``.logical`` via the ``record_logical`` seam that ``SqlServerStore._execute_group`` calls. The
    logical sequence is captured pre-render because the rendered batch string cannot be safely re-split
    (statements like ``_SQL_APPLOCK`` / ``_SQL_STATE_MERGE`` contain intra-statement ``;``).

This is not collected by pytest (no ``test_`` prefix); the test modules import it.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import sqlserver as ss
from messagefoundry.store.crypto import IdentityCipher
from messagefoundry.store.sqlserver import SqlServerStore


# --- canned fetch results (steer the common delivered/PROCESSED hot path) --------------------------


def fetchone_for(sql: str) -> Any:
    if "sp_getapplock" in sql:
        return (0,)  # rc = 0 -> lock acquired
    if sql == ss._SQL_DELETE_GUARD:
        return ("consumed-row-id",)  # non-None -> guard proceeds (not the idempotent no-op)
    if sql == ss._SQL_SELECT_METADATA:
        return (None,)  # no parent metadata -> depth 0
    if sql == ss._SQL_SELECT_MESSAGE_EXISTS:
        return None
    return None


# Finalize GROUP BY rows per disposition scenario (steers _finalize_from_queue_rows down each branch):
#   processed    -> an outbound row, all terminal   -> UPDATE messages.status = PROCESSED
#   error        -> a DEAD row                        -> UPDATE messages.status = ERROR
#   still_moving -> a PENDING row                     -> "return" (NO status UPDATE — still in flight)
#   filtered     -> NO queue rows remain              -> "check_message" -> reads _SQL_SELECT_MESSAGE_STATUS
#                                                        ('routed') -> UPDATE messages.status = FILTERED
_FINALIZE_ROWS: dict[str, list[tuple[Any, ...]]] = {
    "processed": [("outbound", "done", 1)],
    "error": [("outbound", "dead", 1)],
    "still_moving": [("routed", "pending", 1)],
    "filtered": [],
}


def fetchall_for(sql: str, scenario: str = "processed") -> Any:
    if sql == ss._SQL_FINALIZE_COUNT:
        return _FINALIZE_ROWS[scenario]
    if sql == ss._SQL_SELECT_MESSAGE_STATUS:
        return [("routed",)]  # only reached on the check_message branch -> FILTERED
    return []


# --- recorders ------------------------------------------------------------------------------------


class AsyncRecCursor:
    """Unbatched recorder: one ``execute`` == one logical statement == one round-trip. ``scenario``
    steers the finalize disposition branch."""

    def __init__(self, scenario: str = "processed") -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.scenario = scenario
        self._last = ""

    async def execute(self, sql: str, params: Any = ()) -> None:
        self.calls.append((sql, tuple(params)))
        self._last = sql

    async def fetchone(self) -> Any:
        return fetchone_for(self._last)

    async def fetchall(self) -> Any:
        return fetchall_for(self._last, self.scenario)

    async def close(self) -> None:
        pass


class BatchRecCursor:
    """Batched recorder. ``.calls`` = the grouped executes (round-trips, rendered T-SQL). ``.logical`` =
    the per-statement logical (sql, params) sequence, captured via ``record_logical`` BEFORE rendering.
    Fetches key off the LAST logical statement of the most recent group (the read boundary). ``scenario``
    steers the finalize disposition branch."""

    def __init__(self, scenario: str = "processed") -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.logical: list[tuple[str, tuple[Any, ...]]] = []
        self.scenario = scenario
        self._last = ""

    def record_logical(self, group: list[tuple[str, tuple[Any, ...]]]) -> None:
        self.logical.extend((s, tuple(p)) for s, p in group)
        self._last = group[-1][0]  # the read boundary is the group's last statement

    async def execute(self, sql: str, params: Any = ()) -> None:
        # Round-trip record only; _last was set by record_logical to the read statement.
        self.calls.append((sql, tuple(params)))

    async def fetchone(self) -> Any:
        return fetchone_for(self._last)

    async def fetchall(self) -> Any:
        return fetchall_for(self._last, self.scenario)

    async def close(self) -> None:
        pass


class RecConn:
    """Records commits/rollbacks so a test can assert commits/msg == 1 per hop (2.000 per pair)."""

    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


class DetUUID:
    """Deterministic uuid4 so batched + unbatched runs mint the SAME row-id sequence (reset between)."""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> SimpleNamespace:
        v = self.n
        self.n += 1
        return SimpleNamespace(hex=f"row-{v:04d}")

    def reset(self) -> None:
        self.n = 0


def bare_store(*, batch: bool = False, command_timeout: int = 30) -> SqlServerStore:
    """A SqlServerStore built WITHOUT opening a pool/DB — just enough state for the handoffs, with the
    ADR 0075 batching flag set explicitly."""
    store = object.__new__(SqlServerStore)
    store._settings = StoreSettings(command_timeout=command_timeout)
    store._cipher = IdentityCipher()
    store._state_cache = {}
    store._sync_pools = {}
    store._batch_handoff_statements = batch
    return store


def _acm(value: Any) -> Any:
    @asynccontextmanager
    async def cm(*_args: Any, **_kwargs: Any) -> Any:
        yield value

    return cm


async def drive_async(
    store: SqlServerStore, method: str, *, cursor: Any, conn: Any, **kwargs: Any
) -> Any:
    """Patch the store's ``_acquire``/``_cursor`` to yield the given fakes and call the async method."""
    store._acquire = _acm(conn)  # type: ignore[method-assign]
    store._cursor = _acm(cursor)  # type: ignore[method-assign]
    return await getattr(store, method)(**kwargs)


ROUTE_KWARGS: dict[str, Any] = dict(
    ingress_id="ing-1",
    message_id="m-1",
    channel_id="IB",
    handlers=[("H1", "p1")],
    disposition=ss.MessageStatus.ROUTED,
    now=100.0,
)

TRANSFORM_KWARGS: dict[str, Any] = dict(
    routed_id="rtd-1",
    message_id="m-1",
    channel_id="IB",
    deliveries=[("OB1", "b1")],
    state_ops=(),
    pt_deliveries=(),
    now=100.0,
)
