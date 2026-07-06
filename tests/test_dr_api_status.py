# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from messagefoundry.config.settings import DrSettings, StoreSettings
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
        # A DR box ALREADY activated under the profile this boot (enabled + activate): the run-profile
        # threshold is CRITICAL, so a normal-tier inbound is parked status:"filtered" at start.
        dr_settings=DrSettings(enabled=True, activate=True, priority_threshold=Priority.CRITICAL),
    )
    yield eng
    await eng.stop()


def _client(engine: Engine) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def test_filtered_vs_failed_status(engine: Engine, tmp_path: Path) -> None:
    reg = Registry()
    # A critical inbound (binds), a normal inbound (DR-filtered), and a failed outbound (ADR 0031: its
    # env() can't resolve, so it fails to build) — three distinct statuses on one /connections view.
    reg.add_inbound(
        build_inbound_connection(
            "in_crit", MLLP(port=19601), router="r", priority=Priority.CRITICAL
        )
    )
    reg.add_inbound(
        build_inbound_connection("in_norm", MLLP(port=19602), router="r", priority=Priority.NORMAL)
    )
    reg.add_outbound(
        build_outbound_connection(
            "out_bad",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": env("missing_dir"), "filename": "{MSH-10}.hl7"}
            ),
            priority=Priority.CRITICAL,  # critical, so it is NOT filtered — it FAILS (bad env)
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out_bad", m))
    engine.add_registry(reg)
    await engine.start()

    async with _client(engine) as c:
        rows = (await c.get("/connections")).json()
        by_name = {row["channel_id"]: row for row in rows if row["role"] == "source"}
        # The critical inbound is running; the normal inbound is "filtered" (DR-parked), NOT "failed".
        assert by_name["in_crit"]["status"] == "running"
        assert by_name["in_norm"]["status"] == "filtered"
        assert by_name["in_norm"]["error"]  # carries the parked reason
        # The bad critical outbound is "failed" (ADR 0031), a distinct status from "filtered".
        out_rows = [row for row in rows if row.get("destination") == "out_bad"]
        assert out_rows and out_rows[0]["status"] == "failed"
        assert all(row["status"] != "filtered" for row in out_rows)

        # The per-connection metadata endpoint surfaces the same "filtered" reason for the parked feed.
        meta = (await c.get("/connections/in_norm/metadata")).json()
        assert meta["error"]  # the DR-parked reason
        assert not meta["running"]  # not listening
