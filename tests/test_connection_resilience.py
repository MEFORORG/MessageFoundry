# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #37 (runtime + restart half) — a problem connection must not crash the engine or block
its restart. The startup-isolation half lives in test_startup_fault_isolation.py (ADR 0031); this
covers the two remaining runtime modes:

- an outbound that **hangs** in send() must not block a graceful stop (cooperative cancellation);
- a problem (hung) connection must not block a clean **stop → restart** cycle (no wedged teardown).

(Connector-construction failure + inbound-bind failure: test_startup_fault_isolation.py. Listener
decode failure: test_wiring_engine.py::test_inbound_decode_error_records_error_and_naks.)"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports.mllp import MLLPDestination

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "resilience.db")
    yield s
    await s.close()


class _HangingDestination:
    """A connector whose send() hangs forever (until the delivery worker task is cancelled). Models
    a wedged downstream — the worst case for graceful stop."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()  # set the moment send() is first called
        self.closed = False

    async def send(self, payload: str) -> None:
        self.entered.set()
        await asyncio.Event().wait()  # never returns; only a task cancellation unblocks it

    async def aclose(self) -> None:
        self.closed = True


def _mllp_client(port: int) -> MLLPDestination:
    return MLLPDestination(
        Destination(
            name="c",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": port, "timeout_seconds": 5},
        )
    )


def _file_in_reg(inbox: Path, outdir: Path) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out", m))
    return reg


def _mllp_in_reg(outdir: Path) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "mllp_in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("out", m))
    return reg


async def test_hung_outbound_does_not_block_graceful_stop(
    store: MessageStore, tmp_path: Path
) -> None:
    # An outbound stuck in send() must not wedge stop(): the supervised delivery worker is cancelled,
    # which unblocks the hung await, so teardown completes promptly (no leaked/hung task).
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    runner = RegistryRunner(_file_in_reg(inbox, outdir), store, poll_interval=0.02)
    await runner.start()
    hung = _HangingDestination()
    runner._destinations["out"] = hung  # swap in the wedged connector (worker re-resolves per item)
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
    await asyncio.wait_for(hung.entered.wait(), timeout=3.0)  # send() is now hung mid-delivery
    # The hung send must NOT block graceful stop — bounded so a regression (a swallowed cancellation)
    # fails loud as a timeout instead of hanging the suite.
    await asyncio.wait_for(runner.stop(), timeout=5.0)
    assert not runner.running
    assert runner._workers == {} and runner._sources == {}  # no leaked tasks/sources
    assert hung.closed  # the connector was closed during teardown


async def test_problem_connection_does_not_block_engine_restart(
    store: MessageStore, tmp_path: Path
) -> None:
    # A wedged outbound during a live MLLP session must not block a clean stop, nor a fresh restart of
    # the same graph (the listener rebinds, workers respawn) — "doesn't block its restart" (#37).
    outdir = tmp_path / "out"
    reg = _mllp_in_reg(outdir)
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    port = runner._sources["mllp_in"].sockport  # type: ignore[attr-defined]
    hung = _HangingDestination()
    runner._destinations["out"] = hung
    await _mllp_client(port).send(ADT)  # AA at ingress; routes to the hung lane → in-flight send
    await asyncio.wait_for(hung.entered.wait(), timeout=3.0)

    await asyncio.wait_for(runner.stop(), timeout=5.0)  # clean stop despite the wedged connection
    assert not runner.running and runner._sources == {} and runner._workers == {}

    runner2 = RegistryRunner(reg, store, poll_interval=0.02)  # fresh start of the same graph
    await asyncio.wait_for(runner2.start(), timeout=5.0)
    try:
        assert runner2.running and runner2.inbound_running("mllp_in")
        assert runner2.degraded_connections() == {}  # nothing carried over as failed
    finally:
        await runner2.stop()
