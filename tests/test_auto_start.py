# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-connection auto-start (#115): a persisted ``auto_start=False`` flag makes the RegistryRunner NOT
bind that inbound listener / build that outbound connector at engine start (it reports status:"stopped",
distinct from DR "filtered" and ADR-0031 "failed"), while an operator can still start it at runtime. The
default (``auto_start=True``) is byte-identical — every connection starts as before this seam."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


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
