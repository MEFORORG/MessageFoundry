# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DR run-profile status surfacing (#61, ADR 0048 AC-4): a connection the DR run-profile parks below the
threshold reports status:"filtered" on GET /connections and GET /connections/{name}/metadata — a fifth
status value distinct from ADR 0031's "failed". A failed connection (a bad bind) stays "failed", so an
operator can tell a deliberately-parked DR feed from a broken one."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.models import ConnectorType, Priority
from messagefoundry.config.settings import DrSettings, EgressSettings, StoreSettings
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    Send,
    build_inbound_connection,
    build_outbound_connection,
    env,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    store = await MessageStore.open(tmp_path / "status.db")
    eng = Engine(
        store,
        poll_interval=0.02,
        config_dir=None,
        store_settings=StoreSettings(path=str(tmp_path / "status.db")),
        # A DR box, which starts passive (BACKLOG #5965: no setting activates a box at start);
        # the test activates it through the engine callback POST /dr/activate runs, and the
        # threshold is CRITICAL, so a normal-tier inbound is parked status:"filtered".
        dr_settings=DrSettings(
            enabled=True,
            seed_archive="seed.mfbak",
            priority_threshold=Priority.CRITICAL,
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


def _client(engine: Engine) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def test_filtered_vs_failed_status(engine: Engine, tmp_path: Path) -> None:
    reg = Registry()
    # A critical inbound (binds) and a normal inbound (DR-filtered) on an activated DR box.
    reg.add_inbound(
        build_inbound_connection(
            "in_crit", MLLP(port=19601), router="r", priority=Priority.CRITICAL
        )
    )
    reg.add_inbound(
        build_inbound_connection("in_norm", MLLP(port=19602), router="r", priority=Priority.NORMAL)
    )
    reg.add_router("r", lambda m: [])
    engine.add_registry(reg)
    await engine.start()
    await engine._dr_activate_profile()  # the engine callback POST /dr/activate runs

    async with _client(engine) as c:
        rows = (await c.get("/connections")).json()
        by_name = {row["channel_id"]: row for row in rows if row["role"] == "source"}
        # The critical inbound is running; the normal inbound is "filtered" (DR-parked), NOT "failed".
        assert by_name["in_crit"]["status"] == "running"
        assert by_name["in_norm"]["status"] == "filtered"
        assert by_name["in_norm"]["error"]  # carries the parked reason

        # The per-connection metadata endpoint surfaces the same "filtered" reason for the parked feed.
        meta = (await c.get("/connections/in_norm/metadata")).json()
        assert meta["error"]  # the DR-parked reason
        assert not meta["running"]  # not listening


async def test_a_failed_outbound_reads_failed_not_filtered(tmp_path: Path) -> None:
    """ADR 0031: an outbound whose env() cannot resolve fails to build and reads "failed", a
    status distinct from the DR park's "filtered". On a non-DR engine, because an activation
    reload refuses a graph whose critical outbound cannot build."""
    store = await MessageStore.open(tmp_path / "failed.db")
    eng = Engine(
        store,
        poll_interval=0.02,
        config_dir=None,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    reg = Registry()
    reg.add_inbound(build_inbound_connection("in_crit", MLLP(port=19603), router="r"))
    reg.add_outbound(
        build_outbound_connection(
            "out_bad",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": env("missing_dir"), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out_bad", m))
    eng.add_registry(reg)
    try:
        await eng.start()
        async with _client(eng) as c:
            rows = (await c.get("/connections")).json()
            out_rows = [row for row in rows if row.get("destination") == "out_bad"]
            assert out_rows and out_rows[0]["status"] == "failed"
            assert all(row["status"] != "filtered" for row in out_rows)
    finally:
        await eng.stop()
