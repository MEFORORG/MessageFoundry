# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0031 — a connection that fails to build/bind at startup is ISOLATED, never fatal.

The engine starts the rest of the graph and serves the API; a failed outbound retries the rows
routed to it (never drops them) and self-heals on reload; a fully-valid graph is unaffected.
Complements the per-method coverage in test_wiring_engine.py (inbound bind isolation + the fatal
backstop) and test_response_capture.py (capture/backend isolation)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, RetryPolicy
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    env,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, Stage

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "fault.db")
    yield s
    await s.close()


class _RecordingAlertSink:
    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []
        self.buildups: list[tuple[str, int, float]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        self.buildups.append((name, depth, oldest_age_seconds))


async def _until(predicate, timeout: float = 10.0) -> None:  # type: ignore[no-untyped-def]
    elapsed = 0.0
    while not predicate():
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


async def _wait_pending(store: MessageStore, name: str, timeout: float = 10.0) -> int:
    elapsed = 0.0
    while True:
        depth, _ = await store.pending_depth(name, stage=Stage.OUTBOUND.value)
        if depth >= 1:
            return depth
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"no pending outbound row for {name!r} within timeout")


def _file_inbound(inbox: Path) -> InboundConnection:
    return InboundConnection(
        "file_in",
        ConnectionSpec(
            ConnectorType.FILE,
            {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
        ),
        router="r",
    )


async def test_failed_outbound_isolated_retries_and_recovers(
    store: MessageStore, tmp_path: Path
) -> None:
    # An outbound whose env() can't resolve (the real-world SOAP-cert scenario) fails to build. ADR
    # 0031: the engine still starts, the lane is reported failed + alerted, a message routed to it is
    # RETRIED (never dropped), and a reload once the cause is fixed self-heals the lane.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(_file_inbound(inbox))
    reg.add_outbound(
        OutboundConnection(
            "bad_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": env("out_dir"), "filename": "{MSH-10}.hl7"}
            ),
            retry=RetryPolicy(
                backoff_seconds=0.05
            ),  # short, so the stuck row redelivers fast on recovery
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("bad_out", m))
    sink = _RecordingAlertSink()
    runner = RegistryRunner(reg, store, poll_interval=0.02, alert_sink=sink, env_values={})
    await runner.start()
    try:
        # Engine is up despite the broken outbound.
        assert runner.running
        reason = runner.connection_failed("bad_out")
        assert reason and "out_dir" in reason  # the unresolved env key is named in the reason
        assert "bad_out" not in runner._destinations  # no live connector
        assert sink.stopped and sink.stopped[0][0] == "bad_out"  # alerted at start

        # A message routed to the failed lane is retried (a pending outbound row), NOT delivered/dropped.
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _wait_pending(store, "bad_out")
        assert not (outdir.exists() and any(outdir.iterdir()))  # nothing written — never dropped
        assert not await store.list_messages(
            channel_id="file_in", status=MessageStatus.PROCESSED.value
        )  # the message is not finalized PROCESSED — it's stuck retrying, recoverable

        # Fix the cause (a concrete directory, no env) and reload → the lane self-heals.
        good = Registry()
        good.add_inbound(_file_inbound(inbox))
        good.add_outbound(
            OutboundConnection(
                "bad_out",
                ConnectionSpec(
                    ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
                ),
                retry=RetryPolicy(backoff_seconds=0.05),
            )
        )
        good.add_router("r", lambda m: ["h"])
        good.add_handler("h", lambda m: Send("bad_out", m))
        await runner.reload(good)
        assert runner.connection_failed("bad_out") is None  # marker cleared
        assert runner.degraded_connections() == {}
        assert "bad_out" in runner._destinations  # connector built in place

        # The previously-stuck message now DELIVERS — proving the queued row was retried, not lost.
        await _until(lambda: (outdir / "MSG1.hl7").exists())
        assert await store.list_messages(
            channel_id="file_in", status=MessageStatus.PROCESSED.value
        )  # finalized PROCESSED once the recovered lane delivered it
    finally:
        await runner.stop()


async def test_valid_graph_starts_without_degradation(store: MessageStore, tmp_path: Path) -> None:
    # Regression: a fully-valid graph is unaffected — no degraded connections, and it delivers.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(_file_inbound(inbox))
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        assert runner.running
        assert runner.degraded_connections() == {}
        assert runner.connection_failed("file_out") is None
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _until(lambda: (outdir / "MSG1.hl7").exists())
    finally:
        await runner.stop()


async def test_connections_api_reports_degraded_outbound(tmp_path: Path) -> None:
    # The /connections dashboard surfaces a failed outbound that has no traffic edge yet (the
    # standalone-row path), with status "failed" + the reason — so a degraded lane is never hidden.
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.auth import Role
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.pipeline import Engine

    inbox = tmp_path / "in"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(_file_inbound(inbox))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(
        OutboundConnection(
            "bad_out",
            ConnectionSpec(ConnectorType.FILE, {"directory": env("out_dir")}),
        )
    )

    pw = "a-strong-test-passphrase"
    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    engine.add_registry(reg)
    try:
        service = AuthService(engine.store, AuthSettings())
        await service.initialize()
        uid = await service.create_local_user(
            username="vw",
            password=pw,
            display_name=None,
            email=None,
            roles=[Role.VIEWER.value],
            actor="test",
        )
        u = await service.store.get_user(uid)
        assert u is not None and u.password_hash is not None
        await service.store.set_password(
            uid, password_hash=u.password_hash, must_change_password=False
        )
        await engine.start()  # degraded — does NOT raise (ADR 0031)
        assert engine.registry_runner is not None
        assert "bad_out" in engine.registry_runner.degraded_connections()

        transport = httpx.ASGITransport(app=create_app(engine, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post(
                "/auth/login", json={"username": "vw", "password": pw, "provider": "local"}
            )
            headers = {"Authorization": f"Bearer {r.json()['token']}"}
            rows = (await c.get("/connections", headers=headers)).json()
        failed = [row for row in rows if row["status"] == "failed" and "bad_out" in row["name"]]
        assert failed, f"no failed bad_out row in {rows}"
        assert failed[0]["direction"] == "out"
        assert "out_dir" in (failed[0]["error"] or "")
    finally:
        await engine.stop()
