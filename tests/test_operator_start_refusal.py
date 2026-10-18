# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3063 item 4: an operator start that a start gate refuses answers 409 and is audited.

An ``auto_start = false`` listener first meets the inbound exposure gates when an operator starts
it. The gate's ``WiringError`` escaped ``_dual_role_control`` as a 500 and wrote no
``connection_control`` row."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline import Engine
from messagefoundry.store import MessageStore


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


def _down_cleartext_listener() -> Registry:
    """One MLLP listener, left down at start, that the exposure gate refuses when it binds."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_DOWN",
            ConnectionSpec(ConnectorType.MLLP, {"port": 0}),
            router="r",
            auto_start=False,
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


@pytest.mark.parametrize("action", ["start", "restart"])
async def test_a_gate_refused_operator_start_answers_409_and_is_audited(
    store: MessageStore, caplog: pytest.LogCaptureFixture, action: str
) -> None:
    engine = Engine(
        store,
        inbound_bind_host="0.0.0.0",
        hop_posture=HopPosture(enforcing=True),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(_down_cleartext_listener())
    await engine.start()
    try:
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
                r = await client.post(f"/connections/IB_DOWN/{action}")
        assert r.status_code == 409, r.text
        detail = r.json()["detail"]
        assert "IB_DOWN" in detail and "see the server log" in detail
        # The answer names only the listener; the gate's own text goes to the operator log.
        assert "without TLS" not in detail
        assert any(
            rec.name == "messagefoundry.api.app" and "without TLS" in rec.getMessage()
            for rec in caplog.records
        )
        rows = await store.list_audit(action="connection_control", limit=10)
        assert len(rows) == 1
        assert json.loads(rows[0]["detail"] or "{}") == {
            "connection": "IB_DOWN",
            "action": action,
            "role": "source",
            "running": False,
        }
        rr = engine.registry_runner
        assert rr is not None and not rr.inbound_running("IB_DOWN")
    finally:
        await engine.stop()
