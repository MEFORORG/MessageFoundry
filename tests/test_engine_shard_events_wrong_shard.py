# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``GET /connections/{name}/events`` asked of the wrong ENGINE SHARD (vault BACKLOG #3031).

Two engine shards of one config, each built from ``filter_registry_for_shard`` as ``serve --shard``
builds it, share ONE SQLite store. A scoped operator may reach an inbound that engine shard b holds.
Asked of engine shard a, the per-name connection routes refuse it with the 403 and an
``auth.channel_denied`` row, as they refuse an out-of-scope inbound. ``/events`` checked the channel
scope only, so engine shard a answered it from the shared store. These tests pin that ``/events``
now refuses it the same way, and that its answers on the right engine shard did not change.

What it runs: in-process engines and API apps on SQLite. No ``serve --shard`` subprocess and no
server-DB store, the only kind ``serve --shard`` accepts with more than one engine shard (ADR 0063).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.api.message_scope import CONNECTION_DENIED_DETAIL
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, Registry, build_inbound_connection
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.sharding import filter_registry_for_shard
from tests.test_channel_rbac import _add, _client, _login, _probe, _service

_A_OWN = "IB_EVSHARD_A"  # held by engine shard a, in the operator's scope
_A_OUT = "IB_EVSHARD_A_OUT"  # held by engine shard a, outside the operator's scope
_B_OWN = "IB_EVSHARD_B"  # held by engine shard b only, in the operator's scope


def _whole_config(tmp_path: Path) -> Registry:
    reg = Registry()
    for name, shard in ((_A_OWN, "a"), (_A_OUT, "a"), (_B_OWN, "b")):
        reg.add_inbound(
            build_inbound_connection(
                name,
                ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / name)}),
                router="r",
                shard=shard,
            )
        )
    reg.add_router("r", lambda m: [])
    return reg


async def _settle_this_loops_row_writes() -> None:
    """Let this loop's unlanded row writes end before the engines stop."""
    from messagefoundry.api.app import _UNLANDED_ROW_WRITES

    loop = asyncio.get_running_loop()
    mine = {task for task in _UNLANDED_ROW_WRITES if task.get_loop() is loop}
    if mine:
        await asyncio.wait(mine, timeout=2.0)


@pytest.fixture
async def shards(tmp_path: Path) -> AsyncIterator[tuple[Engine, Engine]]:
    whole = _whole_config(tmp_path)
    db = tmp_path / "shared.db"  # ONE store, as every engine shard of a config shares (ADR 0063)
    async with contextlib.AsyncExitStack() as stack:
        engines: list[Engine] = []
        for shard in ("a", "b"):
            eng = await Engine.create(
                db, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
            )
            stack.push_async_callback(eng.stop)
            engines.append(eng)
            eng.add_registry(filter_registry_for_shard(whole, shard))
        stack.push_async_callback(_settle_this_loops_row_writes)  # runs before the stops
        # One synthetic event per inbound, in the shared store, so a leak would show as rows.
        for name in (_A_OWN, _A_OUT, _B_OWN):
            await engines[0].store.record_connection_event(
                connection=name, transport="file", direction="inbound", kind="closed"
            )
        yield engines[0], engines[1]


async def test_the_engine_shard_graphs_are_the_filtered_views(
    shards: tuple[Engine, Engine],
) -> None:
    """Control: each engine shard holds only its own inbounds and pins the whole config's names."""
    for eng, own in ((shards[0], {_A_OWN, _A_OUT}), (shards[1], {_B_OWN})):
        runner = eng.registry_runner
        assert runner is not None
        assert set(runner.registry.inbound) == own
        assert runner.registry.inbound_names() == {_A_OWN, _A_OUT, _B_OWN}


async def test_events_on_the_wrong_engine_shard_gets_the_403_and_a_denial_row(
    shards: tuple[Engine, Engine],
) -> None:
    a, b = shards
    service_a = await _service(a, admin_write_rate_limit=False)
    service_b = await _service(b, admin_write_rate_limit=False)
    uid = await _add(service_a, "op", Role.OPERATOR)
    await service_a.set_channel_scope(uid, [_A_OWN, _B_OWN], actor="admin")

    async with (
        contextlib.AsyncExitStack() as stack,
        _client(a, service_a) as ca,
        _client(b, service_b) as cb,
    ):
        stack.push_async_callback(service_a.close_background)
        stack.push_async_callback(service_b.close_background)
        ha, hb = await _login(ca, "op"), await _login(cb, "op")

        # Controls: on its own engine shard each in-scope inbound still answers with its rows.
        for c, h, eng, name in ((ca, ha, a, _A_OWN), (cb, hb, b, _B_OWN)):
            status, reply, audit = await _probe(c, eng, h, "GET", f"/connections/{name}/events")
            assert status == 200, reply
            assert isinstance(reply, list)
            assert [r["connection"] for r in reply] == [name]
            assert not [x for x in audit if x[0] == "auth.channel_denied"], audit

        # The case: engine shard a does not hold IB_EVSHARD_B, which the operator may reach on b.
        wrong = await _probe(ca, a, ha, "GET", f"/connections/{_B_OWN}/events")
        out = await _probe(ca, a, ha, "GET", f"/connections/{_A_OUT}/events")
        assert wrong[:2] == (403, {"detail": CONNECTION_DENIED_DETAIL}), wrong
        assert out[:2] == wrong[:2]
        assert ("auth.channel_denied", _B_OWN) in wrong[2], wrong
        assert ("auth.channel_denied", _A_OUT) in out[2], out
        assert sorted(act for act, _ in wrong[2]) == sorted(act for act, _ in out[2])
        raw_wrong = await ca.get(f"/connections/{_B_OWN}/events", headers=ha)
        raw_out = await ca.get(f"/connections/{_A_OUT}/events", headers=ha)
        assert (raw_wrong.status_code, raw_wrong.content) == (raw_out.status_code, raw_out.content)

        # The same answer the per-name /metadata route gives on the same wrong engine shard.
        meta = await _probe(ca, a, ha, "GET", f"/connections/{_B_OWN}/metadata")
        assert meta[:2] == wrong[:2]
        assert sorted(act for act, _ in meta[2]) == sorted(act for act, _ in wrong[2])

        # The other direction: engine shard b refuses engine shard a's in-scope inbound the same way.
        status, _, audit = await _probe(cb, b, hb, "GET", f"/connections/{_A_OWN}/events")
        assert status == 403
        assert ("auth.channel_denied", _A_OWN) in audit


async def test_an_unscoped_caller_on_the_wrong_engine_shard_is_unchanged(
    shards: tuple[Engine, Engine],
) -> None:
    """An unscoped caller has no channel scope to deny, so ``/events`` still reads the shared store
    for it on either engine shard and writes no denial row, as before this change."""
    a, _ = shards
    service = await _service(a, admin_write_rate_limit=False)
    wide = await _add(service, "boss", Role.OPERATOR)
    await service.set_channel_scope(wide, [ALL_CHANNELS], actor="admin")
    async with contextlib.AsyncExitStack() as stack, _client(a, service) as ca:
        stack.push_async_callback(service.close_background)
        h = await _login(ca, "boss")
        status, reply, audit = await _probe(ca, a, h, "GET", f"/connections/{_B_OWN}/events")
        assert status == 200, reply
        assert isinstance(reply, list)
        assert [r["connection"] for r in reply] == [_B_OWN]
        assert not [x for x in audit if x[0] == "auth.channel_denied"], audit
