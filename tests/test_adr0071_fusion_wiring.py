# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0071 B5 PR2 — fusion wiring infra (default-OFF, SQL-Server-scoped), non-gated.

These run in normal CI (no ``MEFOR_TEST_SQLSERVER``): they prove the construction sentinel (flag off /
non-SS => NO fusing executor, NO sync pool, ``_fusion_active`` False), the fail-closed activation
(``command_timeout==0`` and a generic pool-open failure => inactive + gauge set + no executor, and the
engine still runs the async path with no lane outage), the slot-budget clamp on the fused INGRESS/ROUTED
dispatchers, and the ERROR-CLASSIFICATION boundary of the fused callables (a route/transform raise is
CONTENT; a sync-conn acquire / handoff raise is INFRA) — driven with a manually-built fusing executor +
a fake sync pool so no live DB is needed. The fused callables persisting real rows on live SQL Server
are in ``test_adr0071_fused_callables_sqlserver.py``.

The fused callables are DEAD CODE in PR2 (not wired into ``_process_*_item`` — that is PR3): these call
them directly. No hashlib/hmac/secrets/ssl here (crypto-inventory gate)."""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxItem, OutboxStatus, Stage
from messagefoundry.store.crypto import IdentityCipher
from messagefoundry.store.sqlserver import SqlServerStore

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "fusion.db")
    yield s
    await s.close()


def _reg(inbox: Path, outdir: Path, *, router: Any = None, handler: Any = None) -> Registry:
    """One FILE inbound → router → handler → one FILE outbound ``OB1`` (swapped for a collector in the
    smoke test; ``router``/``handler`` default to a straight route-to-``h`` → Send-to-``OB1``)."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB1",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", router or (lambda m: ["h"]))
    reg.add_handler("h", handler or (lambda m: Send("OB1", "OUTBODY")))
    return reg


class _Collector:
    def __init__(self) -> None:
        self.deliveries: list[str] = []

    async def send(self, payload: str) -> None:
        self.deliveries.append(payload)

    async def aclose(self) -> None:
        return None


async def _until(pred, *, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out waiting for condition")


def _bare_ss(command_timeout: int = 30) -> SqlServerStore:
    """A SqlServerStore built WITHOUT opening a pool/DB — just enough state for ``_activate_fusion`` to
    reach ``open_sync_handoff_pool`` (mirrors ``test_sqlserver_sync_handoff_offline._bare_store``)."""
    s = object.__new__(SqlServerStore)
    s._settings = StoreSettings(command_timeout=command_timeout)
    s._cipher = IdentityCipher()
    s._state_cache = {}
    s._sync_pools = {}
    return s


class _FakeSyncPool:
    """A stand-in for the dedicated ``_SyncHandoffPool`` so an error-classification test can drive the
    fused handoff branch without a live DB. ``acquire`` yields a throwaway 'connection'; a raise inside
    the ``with`` body propagates (as the real pool does after marking the conn broken)."""

    def __init__(self) -> None:
        self.acquired = 0

    @contextmanager
    def acquire(self, timeout: float | None = None) -> Iterator[Any]:
        self.acquired += 1
        yield object()


# --- construction sentinel: flag off / non-SS => nothing built ------------------------------------


async def test_flag_off_builds_no_fusion(store: MessageStore, tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    runner = RegistryRunner(_reg(inbox, tmp_path / "out"), store, pooled_sweep_interval=0.05)
    assert runner._fuse_thread_hops is False
    assert runner.fusion_active is False
    await runner.start()
    try:
        # The construction sentinel: fusion inactive ⇒ NO fusing executor was built (byte-identical
        # default — the async _process_*_item path is untouched).
        assert runner.fusion_active is False
        assert runner._fuse_route_executor is None
        assert runner._fuse_transform_executor is None
        assert runner._fusion_pool_open_failed is False
    finally:
        await runner.stop()
    assert runner._fuse_route_executor is None and runner._fuse_transform_executor is None


async def test_flag_on_non_ss_ignored_and_flows(store: MessageStore, tmp_path: Path) -> None:
    # Flag ON but SQLite backend: fusion is 'ignored on sqlite (SQL-Server-only)'; the engine runs the
    # async pooled path with NO lane outage — a message flows all the way to PROCESSED.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    runner = RegistryRunner(
        _reg(inbox, outdir),
        store,
        fuse_thread_hops=True,
        claim_mode="pooled",
        pooled_sweep_interval=0.05,
    )
    await runner.start()
    collector = _Collector()
    runner._destinations["OB1"] = collector
    try:
        assert runner.fusion_active is False  # SQL-Server-only → ignored on sqlite
        assert runner._fuse_route_executor is None
        assert set(runner._dispatchers) == {Stage.INGRESS, Stage.ROUTED, Stage.OUTBOUND}
        await runner._handle_inbound(runner.registry.inbound["file_in"], RAW.encode("utf-8"))

        async def _delivered() -> bool:
            return (await store.stats()).get(OutboxStatus.DONE.value, 0) >= 1

        await _until(_delivered)
        assert collector.deliveries == ["OUTBODY"]
    finally:
        await runner.stop()


# --- fail-closed activation (no live DB) ----------------------------------------------------------


async def test_command_timeout_zero_fails_closed(store: MessageStore, tmp_path: Path) -> None:
    # A SQL Server store with [store].command_timeout==0 ⇒ open_sync_handoff_pool raises
    # SyncHandoffUnavailable ⇒ fusion inactive (NOT a crash), gauge set, NO executor built.
    inbox = tmp_path / "in"
    inbox.mkdir()
    runner = RegistryRunner(
        _reg(inbox, tmp_path / "out"),
        _bare_ss(command_timeout=0),
        fuse_thread_hops=True,
        claim_mode="pooled",
    )
    active = await runner._activate_fusion()
    assert active is False
    assert runner._fusion_pool_open_failed is True
    assert runner._fuse_route_executor is None
    assert runner._fuse_transform_executor is None


async def test_pool_open_failure_fails_closed(store: MessageStore, tmp_path: Path) -> None:
    # A generic pool-open failure (session cap / connect fault, simulated) also fails closed: fusion
    # inactive, gauge set, no executor, and close_sync_handoff_pool ran to drop any partial pool.
    inbox = tmp_path / "in"
    inbox.mkdir()
    ss = _bare_ss(command_timeout=30)
    closed = {"n": 0}

    def _raise_open(stage: str, size: int) -> Any:
        raise RuntimeError("simulated session-cap / connect fault")

    ss.open_sync_handoff_pool = _raise_open  # type: ignore[method-assign]
    ss.close_sync_handoff_pool = lambda: closed.__setitem__("n", closed["n"] + 1)  # type: ignore[method-assign]
    runner = RegistryRunner(
        _reg(inbox, tmp_path / "out"), ss, fuse_thread_hops=True, claim_mode="pooled"
    )
    active = await runner._activate_fusion()
    assert active is False
    assert runner._fusion_pool_open_failed is True
    assert runner._fuse_route_executor is None and runner._fuse_transform_executor is None
    assert closed["n"] == 1  # partial-pool cleanup ran (fail-closed drops any opened pool)


# --- slot-budget clamp (fused stages only) --------------------------------------------------------


async def test_slot_clamp_fused_stages_only(store: MessageStore, tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    runner = RegistryRunner(
        _reg(inbox, tmp_path / "out"),
        store,
        claim_mode="pooled",
        pooled_fusing_workers=8,
        pooled_max_processing_lanes=256,
    )
    # Simulate the decision _start_pooled_dispatchers makes on live SS.
    runner._fusion_active = True
    ing = runner._make_dispatcher(Stage.INGRESS)
    rtd = runner._make_dispatcher(Stage.ROUTED)
    ob = runner._make_dispatcher(Stage.OUTBOUND)
    assert ing._max_processing_lanes == 16  # 2 * 8, clamped down from 256
    assert rtd._max_processing_lanes == 16
    assert ob._max_processing_lanes == 256  # non-fused stage NOT clamped
    # Fusion OFF ⇒ no clamp on any stage (byte-identical to today).
    runner._fusion_active = False
    assert runner._make_dispatcher(Stage.INGRESS)._max_processing_lanes == 256


# --- error-classification boundary: CONTENT (route/xform_exc) vs INFRA (handoff_exc) --------------


async def test_fused_route_raising_router_sets_route_exc(
    store: MessageStore, tmp_path: Path
) -> None:
    # A route_only raise is CONTENT ⇒ route_exc set, handoff_exc None, and the handoff is NEVER
    # attempted (the sync pool is never touched).
    inbox = tmp_path / "in"
    inbox.mkdir()

    def _boom(m: Any) -> list[str]:
        raise ValueError("router boom")

    runner = RegistryRunner(_reg(inbox, tmp_path / "out", router=_boom), store, claim_mode="pooled")
    fake_pool = _FakeSyncPool()
    store.sync_handoff_pool = lambda stage: fake_pool  # type: ignore[attr-defined]
    runner._fuse_route_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="t-fuse")
    ic = runner.registry.inbound["file_in"]
    item = OutboxItem(
        id="ing-1",
        message_id="m-1",
        channel_id="file_in",
        destination_name=None,
        payload=RAW,
        attempts=1,
        stage=Stage.INGRESS.value,
    )
    try:
        result = await runner._fused_route_and_handoff("file_in", ic, item)
    finally:
        runner._fuse_route_executor.shutdown(wait=True)
    assert isinstance(result.route_exc, ValueError)
    assert result.handoff_exc is None
    assert result.handed_off is False
    assert result.names == []
    assert result.wake_target is None
    assert fake_pool.acquired == 0  # handoff never reached (route raised first)


async def test_fused_route_handoff_fault_sets_handoff_exc(
    store: MessageStore, tmp_path: Path
) -> None:
    # A sync-handoff raise (route_only succeeded) is INFRA ⇒ handoff_exc set, route_exc None. The
    # pool WAS acquired (the CPU stage completed) before the handoff faulted.
    inbox = tmp_path / "in"
    inbox.mkdir()
    runner = RegistryRunner(_reg(inbox, tmp_path / "out"), store, claim_mode="pooled")
    fake_pool = _FakeSyncPool()
    store.sync_handoff_pool = lambda stage: fake_pool  # type: ignore[attr-defined]

    def _raise_handoff(conn: Any, **kwargs: Any) -> bool:
        raise RuntimeError("handoff commit fault")

    store.route_handoff_sync = _raise_handoff  # type: ignore[attr-defined]
    runner._fuse_route_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="t-fuse")
    ic = runner.registry.inbound["file_in"]
    item = OutboxItem(
        id="ing-2",
        message_id="m-2",
        channel_id="file_in",
        destination_name=None,
        payload=RAW,
        attempts=1,
        stage=Stage.INGRESS.value,
    )
    try:
        result = await runner._fused_route_and_handoff("file_in", ic, item)
    finally:
        runner._fuse_route_executor.shutdown(wait=True)
    assert result.route_exc is None
    assert isinstance(result.handoff_exc, RuntimeError)
    assert result.handed_off is False
    assert result.names == ["h"]  # the CPU stage still produced the route decision
    assert result.disposition is MessageStatus.ROUTED
    assert fake_pool.acquired == 1  # a fresh conn was acquired for the handoff (which then faulted)


async def test_fused_transform_raising_handler_sets_xform_exc(
    store: MessageStore, tmp_path: Path
) -> None:
    # A transform_one raise is CONTENT ⇒ xform_exc set, handoff_exc None, handoff never attempted.
    inbox = tmp_path / "in"
    inbox.mkdir()

    def _boom_handler(m: Any) -> Any:
        raise ValueError("handler boom")

    runner = RegistryRunner(
        _reg(inbox, tmp_path / "out", handler=_boom_handler), store, claim_mode="pooled"
    )
    fake_pool = _FakeSyncPool()
    store.sync_handoff_pool = lambda stage: fake_pool  # type: ignore[attr-defined]
    runner._fuse_transform_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="t-fuse")
    ic = runner.registry.inbound["file_in"]
    item = OutboxItem(
        id="rtd-1",
        message_id="m-3",
        channel_id="file_in",
        destination_name=None,
        payload=RAW,
        attempts=1,
        stage=Stage.ROUTED.value,
        handler_name="h",
    )
    try:
        result = await runner._fused_transform_and_handoff("file_in", ic, item)
    finally:
        runner._fuse_transform_executor.shutdown(wait=True)
    assert isinstance(result.xform_exc, ValueError)
    assert result.handoff_exc is None
    assert result.deliveries == []
    assert result.outbound_wakes == () and result.ingress_wakes == ()
    assert fake_pool.acquired == 0


async def test_fused_transform_handoff_fault_sets_handoff_exc(
    store: MessageStore, tmp_path: Path
) -> None:
    # A transform-handoff raise (transform_one succeeded) is INFRA ⇒ handoff_exc set, xform_exc None.
    inbox = tmp_path / "in"
    inbox.mkdir()
    runner = RegistryRunner(_reg(inbox, tmp_path / "out"), store, claim_mode="pooled")
    fake_pool = _FakeSyncPool()
    store.sync_handoff_pool = lambda stage: fake_pool  # type: ignore[attr-defined]

    def _raise_handoff(conn: Any, **kwargs: Any) -> Any:
        raise RuntimeError("transform handoff commit fault")

    store.transform_handoff_sync = _raise_handoff  # type: ignore[attr-defined]
    runner._fuse_transform_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="t-fuse")
    ic = runner.registry.inbound["file_in"]
    item = OutboxItem(
        id="rtd-2",
        message_id="m-4",
        channel_id="file_in",
        destination_name=None,
        payload=RAW,
        attempts=1,
        stage=Stage.ROUTED.value,
        handler_name="h",
    )
    try:
        result = await runner._fused_transform_and_handoff("file_in", ic, item)
    finally:
        runner._fuse_transform_executor.shutdown(wait=True)
    assert result.xform_exc is None
    assert isinstance(result.handoff_exc, RuntimeError)
    assert result.applied_state == []
    # The CPU stage still produced the delivery decision (surfaced for diagnostics), but no wake fans
    # out on a faulted handoff.
    assert result.deliveries == [("OB1", "OUTBODY")]
    assert result.outbound_wakes == () and result.ingress_wakes == ()
    assert fake_pool.acquired == 1
