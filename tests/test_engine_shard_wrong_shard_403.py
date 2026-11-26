# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A scoped caller asking the wrong ENGINE SHARD (vault BACKLOG #3031, closing step 2).

``tests/test_multishard_smoke.py`` runs the wrong-engine case against two plain ``serve`` processes,
each with its own graph. That is not the engine-shard code path: under ``serve --shard`` each engine
shard's graph is the whole config filtered by ``filter_registry_for_shard``, which pins the whole
config's inbound names on it. This module runs two engine shards of one config, each built from that
filter as ``serve --shard`` builds it, over ONE store, and asks each about the other's inbound.

What it runs, and what it does not: two in-process engines and their API apps, each on its own
filtered graph, sharing one SQLite store. It runs no ``serve --shard`` subprocess, and no server-DB
store, the only kind ``serve --shard`` accepts with more than one engine shard (ADR 0063,
``require_unified_store``). So the shared audit rows and the flag write are run on SQLite only.

Two answers are pinned:

* ``GET /connections/{name}/metadata`` for an in-scope inbound the OTHER engine shard holds gets the
  403 and an ``auth.channel_denied`` row; the status and raw body are byte for byte the answer an
  out-of-scope inbound gets.
* ``POST /connections/{name}/flag`` for that same inbound is NOT refused: its check reads
  ``Registry.inbound_names()``, which on an engine shard spans the whole config, so the flag and its
  ``connection_flag_set`` row land in the shared store. ``docs/SECURITY.md`` states both.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
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

_A_OWN = "IB_SHARD_A"  # held by engine shard a, in the operator's scope
_A_OUT = "IB_SHARD_A_OUT"  # held by engine shard a, outside the operator's scope
_B_OWN = "IB_SHARD_B"  # held by engine shard b only, in the operator's scope


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
    """Let the row writes this test's loop left running end, so none outlives the engines. Only this
    loop's: a write an earlier test's closed loop left in the set never ends."""
    from messagefoundry.api.app import _UNLANDED_ROW_WRITES

    loop = asyncio.get_running_loop()
    mine = {task for task in _UNLANDED_ROW_WRITES if task.get_loop() is loop}
    if mine:
        await asyncio.wait(mine, timeout=2.0)


@pytest.fixture
async def shards(tmp_path: Path) -> AsyncIterator[tuple[Engine, Engine]]:
    whole = _whole_config(tmp_path)
    db = tmp_path / "shared.db"  # ONE store, as every engine shard of a config shares (ADR 0063)
    async with contextlib.AsyncExitStack() as stack:  # each stop runs even if another raises
        engines: list[Engine] = []
        for shard in ("a", "b"):
            eng = await Engine.create(
                db, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
            )
            stack.push_async_callback(eng.stop)
            engines.append(eng)
            eng.add_registry(filter_registry_for_shard(whole, shard))
        stack.push_async_callback(_settle_this_loops_row_writes)  # runs before the stops
        yield engines[0], engines[1]


async def test_the_engine_shard_graphs_are_the_filtered_views(
    shards: tuple[Engine, Engine],
) -> None:
    """Control: each engine shard holds only its own inbounds and pins the whole config's names.
    Without this, the cases below could be passing on two plain graphs."""
    for eng, own, shard in ((shards[0], {_A_OWN, _A_OUT}, "a"), (shards[1], {_B_OWN}, "b")):
        runner = eng.registry_runner
        assert runner is not None
        assert set(runner.registry.inbound) == own
        assert runner.registry.shard_id == shard
        assert runner.registry.inbound_names() == {_A_OWN, _A_OUT, _B_OWN}


async def test_a_scoped_caller_asking_the_wrong_engine_shard_gets_the_403_and_a_denial_row(
    shards: tuple[Engine, Engine],
) -> None:
    a, b = shards
    service_a = await _service(a, admin_write_rate_limit=False)
    service_b = await _service(b, admin_write_rate_limit=False)
    uid = await _add(service_a, "op", Role.OPERATOR)
    await service_a.set_channel_scope(uid, [_A_OWN, _B_OWN], actor="admin")
    wide = await _add(service_a, "boss", Role.OPERATOR)
    await service_a.set_channel_scope(wide, [ALL_CHANNELS], actor="admin")

    async with (
        contextlib.AsyncExitStack() as stack,
        _client(a, service_a) as ca,
        _client(b, service_b) as cb,
    ):
        # Before the fixture stops the engines, pass or fail (AuthService.drain_background).
        stack.push_async_callback(service_a.close_background)
        stack.push_async_callback(service_b.close_background)
        ha, hb = await _login(ca, "op"), await _login(cb, "op")
        # Controls: each engine shard answers for its own in-scope inbound.
        assert (await ca.get(f"/connections/{_A_OWN}/metadata", headers=ha)).status_code == 200
        assert (await cb.get(f"/connections/{_B_OWN}/metadata", headers=hb)).status_code == 200

        # The case: engine shard a does not hold IB_SHARD_B, which the operator may reach on b.
        wrong = await _probe(ca, a, ha, "GET", f"/connections/{_B_OWN}/metadata")
        out = await _probe(ca, a, ha, "GET", f"/connections/{_A_OUT}/metadata")
        assert wrong[:2] == (403, {"detail": CONNECTION_DENIED_DETAIL}), wrong
        assert out[:2] == wrong[:2]
        assert ("auth.channel_denied", _B_OWN) in wrong[2], wrong
        assert ("auth.channel_denied", _A_OUT) in out[2], out
        assert sorted(act for act, _ in wrong[2]) == sorted(act for act, _ in out[2])
        raw_wrong = await ca.get(f"/connections/{_B_OWN}/metadata", headers=ha)
        raw_out = await ca.get(f"/connections/{_A_OUT}/metadata", headers=ha)
        assert (raw_wrong.status_code, raw_wrong.content) == (raw_out.status_code, raw_out.content)

        # The other direction: engine shard b refuses engine shard a's in-scope inbound the same way.
        status, _, audit = await _probe(cb, b, hb, "GET", f"/connections/{_A_OWN}/metadata")
        assert status == 403
        assert ("auth.channel_denied", _A_OWN) in audit

        # An unscoped caller asking the same wrong engine shard gets 404 and no denial row.
        hw = await _login(ca, "boss")
        status, _, audit = await _probe(ca, a, hw, "GET", f"/connections/{_B_OWN}/metadata")
        assert status == 404
        assert not [x for x in audit if x[0] == "auth.channel_denied"], audit

    # The rows are in the ONE store both engine shards share. Checked here: each detail names its
    # channel and nothing else, and the rows engine shard a wrote and the one b wrote carry the same
    # actor and client, so none of those fields says which engine shard answered.
    rows = await b.store.list_audit(actor="op", action="auth.channel_denied")
    assert {r["channel_id"] for r in rows} == {_A_OWN, _A_OUT, _B_OWN}
    for row in rows:
        assert json.loads(str(row["detail"])) == {"channel": row["channel_id"]}, row
    assert len({(r["actor"], r["client"]) for r in rows}) == 1, rows


async def test_the_flag_route_on_the_wrong_engine_shard_writes_the_flag(
    shards: tuple[Engine, Engine],
) -> None:
    """Unlike the per-name routes, the flag route checks ``inbound_names()``, which on an engine shard
    is the whole config. So engine shard a writes a flag on engine shard b's inbound and writes no
    denial row. The control: a name in no engine shard is still refused."""
    a, _ = shards
    service = await _service(a, admin_write_rate_limit=False)
    uid = await _add(service, "dep", Role.DEPLOYMENT)
    await service.set_channel_scope(uid, [_A_OWN, _B_OWN, "IB_NOWHERE"], actor="admin")
    async with contextlib.AsyncExitStack() as stack, _client(a, service) as ca:
        stack.push_async_callback(service.close_background)
        h = await _login(ca, "dep")
        body = {"direction": "inbound", "flagged": True}
        status, reply, audit = await _probe(
            ca, a, h, "POST", f"/connections/{_B_OWN}/flag", json=body
        )
        assert status == 200, reply
        assert ("connection_flag_set", _B_OWN) in audit, audit
        assert not [x for x in audit if x[0] == "auth.channel_denied"], audit
        status, reply, audit = await _probe(
            ca, a, h, "POST", "/connections/IB_NOWHERE/flag", json=body
        )
        assert (status, reply) == (403, {"detail": CONNECTION_DENIED_DETAIL})
        assert ("auth.channel_denied", "IB_NOWHERE") in audit
    assert await a.store.list_connection_flags() == {(_B_OWN, "inbound")}
