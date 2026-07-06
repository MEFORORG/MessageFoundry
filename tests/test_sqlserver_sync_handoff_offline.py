# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0071 B5 PR1 — offline (no-DB) tests for the SQL Server synchronous fused-handoff twins.

These run in normal CI (no ``MEFOR_TEST_SQLSERVER`` gate, no aioodbc/pyodbc): the module imports
cleanly without the extras (aioodbc is imported lazily in ``open``; pyodbc in
``open_sync_handoff_pool``), and the tests drive the async + sync handoff twins against **fake
cursors** to prove the anti-drift guarantee — that ``route_handoff`` / ``transform_handoff`` and their
``*_sync`` twins emit the byte-identical ``(sql, params)`` sequence for identical inputs. Plus the
capability sentinels, the ``command_timeout==0`` fail-closed refusal, and ``publish_state_cache``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import MessageStatus
from messagefoundry.store.crypto import IdentityCipher
from messagefoundry.store import sqlserver as ss
from messagefoundry.store.sqlserver import SqlServerStore, SyncHandoffUnavailable


# --- fakes: record every (sql, params) and drive the shared control flow deterministically --------


def _fetchone_for(sql: str) -> Any:
    """Canned single-row results keyed by the hoisted SQL constant, identical for the async + sync
    recorders so both twins walk the same branch."""
    if "sp_getapplock" in sql:
        return (0,)  # rc = 0 -> lock acquired
    if sql == ss._SQL_DELETE_GUARD:
        return ("consumed-row-id",)  # non-None -> the guard proceeds (not the idempotent no-op)
    if sql == ss._SQL_SELECT_METADATA:
        return (None,)  # no parent metadata -> depth 0
    if sql == ss._SQL_SELECT_MESSAGE_EXISTS:
        return None  # PT child does not exist yet -> produce it
    return None


def _fetchall_for(sql: str) -> Any:
    if sql == ss._SQL_FINALIZE_COUNT:
        return [("outbound", "done", 1)]  # -> PROCESSED -> the finalizer UPDATE fires
    if sql == ss._SQL_SELECT_MESSAGE_STATUS:
        return [("routed",)]
    return []


class _AsyncRecCursor:
    def __init__(self, calls: list[tuple[str, tuple[Any, ...]]]) -> None:
        self.calls = calls
        self._last = ""

    async def execute(self, sql: str, params: Any = ()) -> None:
        self.calls.append((sql, tuple(params)))
        self._last = sql

    async def fetchone(self) -> Any:
        return _fetchone_for(self._last)

    async def fetchall(self) -> Any:
        return _fetchall_for(self._last)

    async def close(self) -> None:
        pass


class _SyncRecCursor:
    def __init__(self, calls: list[tuple[str, tuple[Any, ...]]]) -> None:
        self.calls = calls
        self._last = ""

    def execute(self, sql: str, params: Any = ()) -> None:
        self.calls.append((sql, tuple(params)))
        self._last = sql

    def fetchone(self) -> Any:
        return _fetchone_for(self._last)

    def fetchall(self) -> Any:
        return _fetchall_for(self._last)

    def close(self) -> None:
        pass


class _FakeAsyncConn:
    async def commit(self) -> None:
        pass

    async def rollback(self) -> None:
        pass


class _FakeSyncConn:
    def __init__(self, cur: _SyncRecCursor) -> None:
        self._cur = cur

    def cursor(self) -> _SyncRecCursor:
        return self._cur

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass


class _DetUUID:
    """Deterministic replacement for ``uuid4`` so the async run and the sync run mint the SAME row-id
    sequence (reset between runs); every ``.hex`` is stable given call order."""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> SimpleNamespace:
        v = self.n
        self.n += 1
        return SimpleNamespace(hex=f"row-{v:04d}")

    def reset(self) -> None:
        self.n = 0


def _bare_store(command_timeout: int = 30) -> SqlServerStore:
    """A SqlServerStore built WITHOUT opening a pool/DB — just enough state for the handoff twins."""
    store = object.__new__(SqlServerStore)
    store._settings = StoreSettings(command_timeout=command_timeout)
    store._cipher = IdentityCipher()
    store._state_cache = {}
    store._sync_pools = {}
    return store


def _acm(value: Any) -> Any:
    @asynccontextmanager
    async def cm(*_args: Any, **_kwargs: Any) -> Any:
        yield value

    return cm


async def _record_async(
    store: SqlServerStore, method: str, cur: _AsyncRecCursor, **kwargs: Any
) -> Any:
    store._acquire = _acm(_FakeAsyncConn())  # type: ignore[method-assign]
    store._cursor = _acm(cur)  # type: ignore[method-assign]
    return await getattr(store, method)(**kwargs)


# --- golden ordered-(sql, params) identity: async twin vs sync twin -------------------------------


async def test_golden_route_handoff_sql_param_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    det = _DetUUID()
    monkeypatch.setattr(ss, "uuid4", det)
    kwargs = dict(
        ingress_id="ing-1",
        message_id="m-1",
        channel_id="IB",
        handlers=[("H1", "p1"), ("H2", "p2")],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )

    async_calls: list[tuple[str, tuple[Any, ...]]] = []
    det.reset()
    ok = await _record_async(_bare_store(), "route_handoff", _AsyncRecCursor(async_calls), **kwargs)
    assert ok is True

    sync_calls: list[tuple[str, tuple[Any, ...]]] = []
    det.reset()
    sync_cur = _SyncRecCursor(sync_calls)
    ok2 = _bare_store().route_handoff_sync(_FakeSyncConn(sync_cur), **kwargs)
    assert ok2 is True

    assert async_calls == sync_calls
    assert len(async_calls) > 0
    # Invariant: the leading guard-DELETE opens the txn, so the finalize applock is NEVER first.
    assert async_calls[0][0] == ss._SQL_DELETE_GUARD
    applock_idx = next(i for i, (s, _) in enumerate(async_calls) if "sp_getapplock" in s)
    assert applock_idx > 0


async def test_golden_transform_handoff_sql_param_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    det = _DetUUID()
    monkeypatch.setattr(ss, "uuid4", det)
    kwargs = dict(
        routed_id="rtd-1",
        message_id="m-1",
        channel_id="IB",
        deliveries=[("OB1", "b1")],
        state_ops=[("ns", "k", {"v": 1})],
        pt_deliveries=[("PT", "MSH|child")],
        correlation_depth_cap=8,
        now=100.0,
    )

    async_calls: list[tuple[str, tuple[Any, ...]]] = []
    det.reset()
    ok = await _record_async(
        _bare_store(), "transform_handoff", _AsyncRecCursor(async_calls), **kwargs
    )
    assert ok is True

    sync_calls: list[tuple[str, tuple[Any, ...]]] = []
    det.reset()
    sync_cur = _SyncRecCursor(sync_calls)
    handed_off, applied = _bare_store().transform_handoff_sync(_FakeSyncConn(sync_cur), **kwargs)
    assert handed_off is True
    assert applied == [(("ns", "k"), {"v": 1})]

    assert async_calls == sync_calls
    # The rich path really exercised: state MERGE, outbound insert, PT child+marker, finalize UPDATE.
    seq = [s for s, _ in async_calls]
    assert seq[0] == ss._SQL_DELETE_GUARD
    assert ss._SQL_STATE_MERGE in seq
    assert ss._SQL_SELECT_METADATA in seq
    assert ss._SQL_UPDATE_MESSAGE_STATUS in seq  # finalizer wrote the disposition
    applock_idx = next(i for i, (s, _) in enumerate(async_calls) if "sp_getapplock" in s)
    assert applock_idx > 0


async def test_golden_transform_handoff_multi_item_unsorted_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multi-item transform: >=2 deliveries, >=2 **unsorted** state_ops, >=2 pt_deliveries. The single-
    item sibling cannot exercise the loops, so this differentially proves the shared ``sorted((ns,key))``
    ordering, the outbound-then-PT interleaving, and multiple PT child/marker pairs are byte-identical
    between async ``transform_handoff`` and ``transform_handoff_sync``."""
    det = _DetUUID()
    monkeypatch.setattr(ss, "uuid4", det)
    kwargs = dict(
        routed_id="rtd-2",
        message_id="m-2",
        channel_id="IB",
        deliveries=[("OB2", "b2"), ("OB1", "b1")],
        # deliberately UNSORTED (zeta before alpha; two alpha keys out of order) so the test fails if
        # either twin drops or reorders the shared sorted((namespace, key)) key.
        state_ops=[("zeta", "k2", {"v": 2}), ("alpha", "k1", {"v": 1}), ("alpha", "k0", {"v": 0})],
        pt_deliveries=[("PTB", "MSH|child-b"), ("PTA", "MSH|child-a")],
        correlation_depth_cap=8,
        now=200.0,
    )

    async_calls: list[tuple[str, tuple[Any, ...]]] = []
    det.reset()
    ok = await _record_async(
        _bare_store(), "transform_handoff", _AsyncRecCursor(async_calls), **kwargs
    )
    assert ok is True

    sync_calls: list[tuple[str, tuple[Any, ...]]] = []
    det.reset()
    handed_off, applied = _bare_store().transform_handoff_sync(
        _FakeSyncConn(_SyncRecCursor(sync_calls)), **kwargs
    )
    assert handed_off is True

    assert async_calls == sync_calls
    # applied comes back in sorted((namespace, key)) order regardless of input order — identical set,
    # deterministic order, in BOTH twins (the sync twin's return feeds publish_state_cache).
    assert applied == [
        (("alpha", "k0"), {"v": 0}),
        (("alpha", "k1"), {"v": 1}),
        (("zeta", "k2"), {"v": 2}),
    ]
    # The loops really ran >=2x in the identical sequence: 3 state MERGEs, and 4 outbound inserts =
    # 2 real deliveries + 2 PT terminal markers (each PT also re-ingresses a child; markers reuse the
    # outbound insert). This is what single-item coverage cannot exercise.
    seq = [s for s, _ in async_calls]
    assert seq.count(ss._SQL_STATE_MERGE) == 3
    assert seq.count(ss._SQL_INSERT_QUEUE_OUTBOUND) == 4


async def test_golden_route_handoff_idempotent_noop_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # When the guard-DELETE finds nothing (already consumed), BOTH twins must roll back and return
    # False after emitting ONLY the guard DELETE (identical no-op sequence).
    monkeypatch.setattr(ss, "uuid4", _DetUUID())
    kwargs = dict(
        ingress_id="ing-x",
        message_id="m-x",
        channel_id="IB",
        handlers=[("H1", "p1")],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )

    class _AsyncEmpty(_AsyncRecCursor):
        async def fetchone(self) -> Any:
            return None

    class _SyncEmpty(_SyncRecCursor):
        def fetchone(self) -> Any:
            return None

    async_calls: list[tuple[str, tuple[Any, ...]]] = []
    ok = await _record_async(_bare_store(), "route_handoff", _AsyncEmpty(async_calls), **kwargs)
    assert ok is False

    sync_calls: list[tuple[str, tuple[Any, ...]]] = []
    ok2 = _bare_store().route_handoff_sync(_FakeSyncConn(_SyncEmpty(sync_calls)), **kwargs)
    assert ok2 is False

    assert async_calls == sync_calls
    assert [s for s, _ in async_calls] == [ss._SQL_DELETE_GUARD]


# --- capability sentinels -------------------------------------------------------------------------


def test_capability_flag_true_only_on_sqlserver() -> None:
    from messagefoundry.store.store import MessageStore
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.base import QueueStore

    assert SqlServerStore.supports_fused_sync_handoff is True
    assert MessageStore.supports_fused_sync_handoff is False
    assert PostgresStore.supports_fused_sync_handoff is False
    # The base protocol default is fail-closed (False).
    assert QueueStore.supports_fused_sync_handoff is False


def test_sync_handoff_surface_only_on_sqlserver() -> None:
    from messagefoundry.store.store import MessageStore
    from messagefoundry.store.postgres import PostgresStore

    for attr in (
        "route_handoff_sync",
        "transform_handoff_sync",
        "publish_state_cache",
        "open_sync_handoff_pool",
        "close_sync_handoff_pool",
    ):
        assert hasattr(SqlServerStore, attr), attr
    # No sync fused surface leaks onto the other backends.
    for attr in ("route_handoff_sync", "transform_handoff_sync", "open_sync_handoff_pool"):
        assert not hasattr(MessageStore, attr), attr
        assert not hasattr(PostgresStore, attr), attr


# --- fail-closed: command_timeout == 0 refuses the sync pool (no DB touched) -----------------------


def test_command_timeout_zero_refuses_sync_pool() -> None:
    store = _bare_store(command_timeout=0)
    with pytest.raises(SyncHandoffUnavailable):
        store.open_sync_handoff_pool("routed", 2)
    # The refusal happens BEFORE any pyodbc import / connection attempt, so nothing was built.
    assert store._sync_pools == {}


def test_applock_timeout_ms_formula() -> None:
    # ADR 0071 invariant: command_timeout==0 -> @LockTimeout=-1 (wait forever) — the reason ct==0 is
    # refused for the sync path; a finite ct yields a finite ms bound shared by both twins.
    assert ss._applock_timeout_ms(0) == -1
    assert ss._applock_timeout_ms(30) == 30_000


# --- publish_state_cache (loop-owned cache publish; the sync twin never mutates it directly) -------


def test_publish_state_cache_updates_state_view() -> None:
    store = _bare_store()
    assert dict(store.state_view()) == {}
    store.publish_state_cache([(("ns", "k"), {"v": 1}), (("ns2", "k2"), "x")])
    view = dict(store.state_view())
    assert view[("ns", "k")] == {"v": 1}
    assert view[("ns2", "k2")] == "x"


def test_transform_handoff_sync_does_not_mutate_state_cache_directly() -> None:
    # The sync twin RETURNS applied (for the loop to publish) and must leave self._state_cache untouched
    # from its worker thread. Drive it with a fake conn and assert the cache stays empty until publish.
    store = _bare_store()
    calls: list[tuple[str, tuple[Any, ...]]] = []
    handed_off, applied = store.transform_handoff_sync(
        _FakeSyncConn(_SyncRecCursor(calls)),
        routed_id="rtd",
        message_id="m",
        channel_id="IB",
        deliveries=[("OB", "b")],
        state_ops=[("ns", "k", {"v": 9})],
        now=100.0,
    )
    assert handed_off is True
    assert applied == [(("ns", "k"), {"v": 9})]
    assert dict(store.state_view()) == {}  # NOT published by the worker
    store.publish_state_cache(applied)
    assert dict(store.state_view())[("ns", "k")] == {"v": 9}
