# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-connection auto-start (#115): a persisted ``auto_start=False`` flag makes the RegistryRunner NOT
bind that inbound listener / build that outbound connector at engine start. BOTH roles then report
status:"stopped" (distinct from DR "filtered" and ADR-0031 "failed") — the outbound lane is recorded
START-DISABLED (paused + already quiesced), so it is reported honestly, /connections emits a row for it
even before it ever carries traffic, and its queued rows are RETAINED PENDING (never claimed
connector-less, never buildup-paged).

An operator start is REAL, not merely advertised: ``start_outbound`` BUILDS the connector the boot gate
declined to build, so the retained rows actually drain. And ``auto_start`` gates the ENGINE, not just the
boot instant — neither a reload nor an ADR-0095 scheduler tick may resurrect a start-disabled connection,
while neither may undo one an OPERATOR started at runtime.

The default (``auto_start=True``) is byte-identical — every connection starts as before this seam."""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime, time
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.models import ActiveWindow, ConnectorType, Schedule
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


async def _wait_until(predicate, timeout: float = 2.0) -> None:  # type: ignore[no-untyped-def]
    async def _poll() -> None:
        while not predicate():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(_poll(), timeout)


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "autostart.db")
    yield s
    await s.close()


def _file_out(name: str, tmp_path: Path, *, auto_start: bool = True):  # type: ignore[no-untyped-def]
    return build_outbound_connection(
        name,
        ConnectionSpec(
            ConnectorType.FILE, {"directory": str(tmp_path), "filename": "{MSH-10}.hl7"}
        ),
        auto_start=auto_start,
    )


async def test_auto_start_false_is_not_bound_at_boot(store: MessageStore, tmp_path: Path) -> None:
    # AC: auto_start=False inbound is NOT listening after start (status "stopped"), while the default
    # auto_start=True inbound IS. The stopped one is neither DR-filtered nor a fault.
    on_port, off_port = _free_port(), _free_port()
    reg = Registry()
    reg.add_inbound(build_inbound_connection("in_on", MLLP(port=on_port), router="r"))
    reg.add_inbound(
        build_inbound_connection("in_off", MLLP(port=off_port), router="r", auto_start=False)
    )
    reg.add_outbound(_file_out("out_off", tmp_path, auto_start=False))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        assert runner.running
        assert runner.inbound_running("in_on")  # default: started
        assert not runner.inbound_running("in_off")  # auto_start=False: not listening
        # Not a DR filter and not a fault — a clean deliberate "stopped".
        assert runner.connection_filtered("in_off") is None
        assert runner.connection_failed("in_off") is None
        assert "in_off" not in runner.filtered_connections()
        assert runner.degraded_connections() == {}
    finally:
        await runner.stop()


async def test_start_disabled_inbound_is_startable_at_runtime(
    store: MessageStore, tmp_path: Path
) -> None:
    # The boot gate is boot-only: POST /connections/{name}/start -> start_inbound bypasses it, so an
    # operator can bring a start-disabled feed up without a config change.
    off_port = _free_port()
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection("in_off", MLLP(port=off_port), router="r", auto_start=False)
    )
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        assert not runner.inbound_running("in_off")
        await runner.start_inbound("in_off")
        assert runner.inbound_running("in_off")  # now listening after the manual start
    finally:
        await runner.stop()


async def test_default_auto_start_is_byte_identical(store: MessageStore, tmp_path: Path) -> None:
    # No auto_start argument (the default True) -> every connection starts exactly as before this seam.
    port = _free_port()
    reg = Registry()
    reg.add_inbound(build_inbound_connection("in_default", MLLP(port=port), router="r"))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        assert runner.inbound_running("in_default")
        assert runner.filtered_connections() == {}
    finally:
        await runner.stop()


def test_auto_start_field_defaults_true_and_plumbs() -> None:
    # The field defaults True on both connection kinds and the factories thread it through.
    ic_on = build_inbound_connection("a", MLLP(port=1), router="r")
    ic_off = build_inbound_connection("b", MLLP(port=2), router="r", auto_start=False)
    assert ic_on.auto_start is True and ic_off.auto_start is False
    oc_on = build_outbound_connection(
        "c", ConnectionSpec(ConnectorType.FILE, {"directory": ".", "filename": "x"})
    )
    oc_off = build_outbound_connection(
        "d",
        ConnectionSpec(ConnectorType.FILE, {"directory": ".", "filename": "x"}),
        auto_start=False,
    )
    assert oc_on.auto_start is True and oc_off.auto_start is False


# === BUG A — a start-disabled OUTBOUND must not report itself as running =====


async def test_start_disabled_outbound_reports_stopped(store: MessageStore, tmp_path: Path) -> None:
    """The boot gate used to write NO state at all: it popped the connector and returned, so
    ``outbound_status`` (which reports "running" for any name not in ``_outbound_paused``) called a lane
    with no connector and no worker doing anything "running". Regression: it must report "stopped" —
    and be quiesced (zero in flight), which is what makes it purge-eligible and, below, visible."""
    reg = Registry()
    reg.add_outbound(_file_out("out_on", tmp_path))
    reg.add_outbound(_file_out("out_off", tmp_path, auto_start=False))
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        assert runner.outbound_status("out_on") == "running"
        assert runner.outbound_running("out_on")
        assert runner.outbound_status("out_off") == "stopped"  # was "running" — the lie
        assert not runner.outbound_running("out_off")
        assert runner.outbound_quiesced("out_off")  # never started => nothing in flight
        # Deliberately down, so neither an ADR-0031 fault nor a DR park — the engine is NOT degraded.
        assert runner.connection_failed("out_off") is None
        assert runner.connection_filtered("out_off") is None
        assert runner.degraded_connections() == {}
    finally:
        await runner.stop()


async def test_start_disabled_outbound_is_visible_in_connections(tmp_path: Path) -> None:
    """A never-trafficked start-disabled outbound has no metrics edge, so its only chance of appearing
    in /connections is the standalone-row rescue — which only fires for a "stopping"/"stopped" status.
    With the boot gate reporting "running" it was INVISIBLE: no edge row, no standalone row."""
    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    try:
        reg = Registry()
        reg.add_outbound(_file_out("OB_PARTNER_ADT", tmp_path, auto_start=False))
        engine.add_registry(reg)
        await engine.start()
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            rows = {row["name"]: row for row in (await c.get("/connections")).json()}
        row = rows["OB_PARTNER_ADT ▸ out"]  # KeyError today: the lane emits no row at all
        assert row["status"] == "stopped"
        assert row["error"] is None  # a deliberate stop, not a failure reason
    finally:
        await engine.stop()


# === BUG B — POST /connections/{name}/start must actually START one ===========


async def test_operator_start_builds_the_connector_and_drains(
    store: MessageStore, tmp_path: Path
) -> None:
    """``_start_outbound_unsafe`` only un-paused the lane and respawned the worker — it never called
    ``build_destination``, and the boot gate had popped the connector. So the advertised operator start
    resumed a CONNECTOR-LESS lane: the API said "running" and not one byte was ever delivered. The
    retained row must drain the moment the lane is started."""
    out_dir = tmp_path / "egress"
    out_dir.mkdir()
    reg = Registry()
    reg.add_outbound(_file_out("out_off", out_dir, auto_start=False))
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("out_off", ADT)])
        # A start-disabled lane RETAINS its queue: nothing is claimed, nothing is delivered, nothing
        # is dropped (the count-and-log invariant) — the row simply waits for the operator.
        await asyncio.sleep(0.15)
        assert list(out_dir.iterdir()) == []
        assert "out_off" not in runner._destinations  # the boot gate built no connector

        await runner.start_outbound("out_off")

        assert runner.outbound_running("out_off")
        assert "out_off" in runner._destinations  # the START built it — this is the fix
        await _wait_until(lambda: [p.name for p in out_dir.iterdir()] == ["MSG1.hl7"])
    finally:
        await runner.stop()


# === BUG C — a reload / scheduler tick must not resurrect a start-disabled lane ===


async def test_reload_does_not_resurrect_a_start_disabled_outbound(
    store: MessageStore, tmp_path: Path
) -> None:
    """``_reconcile_outbounds`` had no auto_start gate, and in the DEFAULT pooled claim mode a lane is
    "live" iff its CONNECTOR is built — which the boot gate had just popped. So every reload (and every
    connections.toml GUI save, which reloads) took the not-live branch, rebuilt the connector, and the
    start-disabled outbound silently started delivering."""
    out_dir = tmp_path / "egress"
    out_dir.mkdir()
    reg = Registry()
    reg.add_outbound(_file_out("out_off", out_dir, auto_start=False))
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("out_off", ADT)])

        new = Registry()  # the same graph, re-loaded (an edit elsewhere in connections.toml)
        new.add_outbound(_file_out("out_off", out_dir, auto_start=False))
        await runner.reload(new)

        assert runner.outbound_status("out_off") == "stopped"
        assert not runner.outbound_running("out_off")
        assert "out_off" not in runner._destinations  # the reload rebuilt it — the resurrection
        await asyncio.sleep(0.15)
        assert list(out_dir.iterdir()) == []  # and then it DELIVERED
    finally:
        await runner.stop()


async def test_reload_does_not_bind_a_start_disabled_inbound(store: MessageStore) -> None:
    """The reload inbound loop carried only the DR filter, so a reload BOUND a listener the boot gate
    had deliberately left down."""
    port = _free_port()

    def _reg() -> Registry:
        r = Registry()
        r.add_inbound(
            build_inbound_connection("in_off", MLLP(port=port), router="r", auto_start=False)
        )
        r.add_router("r", lambda m: [])
        return r

    runner = RegistryRunner(_reg(), store, poll_interval=0.02)
    await runner.start()
    try:
        assert not runner.inbound_running("in_off")
        await runner.reload(_reg())
        assert not runner.inbound_running("in_off")  # the reload used to bind it
    finally:
        await runner.stop()


async def test_reload_does_not_undo_an_operator_start(store: MessageStore, tmp_path: Path) -> None:
    """The other half of the gate, and the reason it keys on the lane's LIVE state rather than on the
    flag alone: a reload must not UNDO an operator who started a start-disabled connection at runtime.
    (A reload quiesces every inbound listener at step 1, so the inbound gate consults the pre-quiesce
    snapshot — a naive "is it listening now?" check would park exactly the feed the operator brought up.)
    """
    port = _free_port()

    def _reg() -> Registry:
        r = Registry()
        r.add_inbound(
            build_inbound_connection("in_off", MLLP(port=port), router="r", auto_start=False)
        )
        r.add_router("r", lambda m: [])
        r.add_outbound(_file_out("out_off", tmp_path, auto_start=False))
        return r

    runner = RegistryRunner(_reg(), store, poll_interval=0.02)
    await runner.start()
    try:
        await runner.start_inbound("in_off")
        await runner.start_outbound("out_off")

        await runner.reload(_reg())

        assert runner.inbound_running("in_off")  # still listening across the reload
        assert runner.outbound_running("out_off")  # still delivering across the reload
        assert "out_off" in runner._destinations  # its connector was not torn down
    finally:
        await runner.stop()


async def test_scheduler_tick_does_not_start_a_start_disabled_connection(
    store: MessageStore, tmp_path: Path
) -> None:
    """``_reconcile_schedule`` called start_inbound/start_outbound without consulting auto_start, so a
    scheduled + start-disabled connection came up on its first IN-WINDOW tick — the boot gate defeated
    by the scheduler seconds later. A scheduler tick is the ENGINE, not an operator."""
    schedule = Schedule(
        windows=[
            ActiveWindow(
                days=frozenset({0, 1, 2, 3, 4}), start=time(8), end=time(17), timezone="UTC"
            )
        ]
    )
    inside = datetime(2026, 7, 13, 9, tzinfo=UTC)  # Monday 09:00 — inside the window
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "in_off", MLLP(port=_free_port()), router="r", auto_start=False, schedule=schedule
        )
    )
    reg.add_router("r", lambda m: [])
    reg.add_outbound(
        build_outbound_connection(
            "out_off",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(tmp_path), "filename": "{MSH-10}.hl7"}
            ),
            auto_start=False,
            schedule=schedule,
        )
    )
    runner = RegistryRunner(reg, store, poll_interval=0.02, schedule_clock=lambda: inside)
    await runner.start()
    try:
        await runner._reconcile_schedule("in_off", "inbound", schedule)
        await runner._reconcile_schedule("out_off", "outbound", schedule)
        assert not runner.inbound_running("in_off")  # the in-window tick used to start it
        assert not runner.outbound_running("out_off")
        assert runner.outbound_status("out_off") == "stopped"
    finally:
        await runner.stop()
