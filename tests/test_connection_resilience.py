# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #37 (runtime + restart half) — a problem connection must not crash the engine or block
its restart. The startup-isolation half lives in test_startup_fault_isolation.py (ADR 0031); this
covers the two remaining runtime modes:

- an outbound that **hangs** in send() must not block a graceful stop (cooperative cancellation);
- a problem (hung) connection must not block a clean **stop → restart** cycle (no wedged teardown).

(Connector-construction failure + inbound-bind failure: test_startup_fault_isolation.py. Listener
decode failure: test_wiring_engine.py::test_inbound_decode_error_records_error_and_naks.)"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports.base import DestinationConnector
from messagefoundry.transports.mllp import MLLPDestination

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "resilience.db")
    yield s
    await s.close()


# A ceiling on a wait whose normal case ends far sooner, so a passing run never sleeps on it. It is
# not a speed assertion: it turns one hang into a failure at its own line, well under the per-test
# watchdog (pytest-timeout; the --timeout note in pyproject.toml says where each leg's is set). A
# run starved at every step at once can still reach the watchdog first, which fails it all the
# same. The 3s it replaces was a speed assertion by accident: a windows-2025 runner under a full
# parallel suite took longer than that to carry one file into send() (BACKLOG #3456).
_HANG_CEILING_SECONDS = 20.0


async def _bounded_stop(runner: RegistryRunner) -> None:
    """``runner.stop()``, failed at the ceiling. Not ``wait_for``: since Python 3.12 it waits for
    the cancelled stop to finish, so a send that swallows its cancellation would hang it anyway.
    The stop task is left running on a timeout, because nothing can end it."""
    stop = asyncio.create_task(runner.stop())
    done, _pending = await asyncio.wait({stop}, timeout=_HANG_CEILING_SECONDS)
    if not done:
        raise AssertionError(f"runner.stop() did not finish within {_HANG_CEILING_SECONDS:g}s")
    stop.result()


class _HangingDestination(DestinationConnector):
    """A connector whose send() hangs forever (until the delivery worker task is cancelled). Models
    a wedged downstream — the worst case for graceful stop."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()  # set the moment send() is first called
        self.closed = False
        self.cancelled = False  # send() saw its CancelledError
        self.task: asyncio.Task[object] | None = None  # the task send() ran on

    async def send(self, payload: str, *, metadata: Mapping[str, str] | None = None) -> None:
        self.task = asyncio.current_task()
        self.entered.set()
        try:
            await asyncio.Event().wait()  # never returns; only a task cancellation unblocks it
        except asyncio.CancelledError:
            self.cancelled = True
            raise

    async def aclose(self) -> None:
        self.closed = True


def _mllp_client(port: int) -> MLLPDestination:
    return MLLPDestination(
        Destination(
            name="c",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": port, "timeout_seconds": _HANG_CEILING_SECONDS},
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
    runner = RegistryRunner(
        _file_in_reg(inbox, outdir),
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    hung = _HangingDestination()
    try:
        runner._destinations["out"] = hung  # swap in the wedged connector (re-resolved per item)
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        # Setup, not the property: send() is now hung mid-delivery.
        await asyncio.wait_for(hung.entered.wait(), timeout=_HANG_CEILING_SECONDS)
    except BaseException:
        # A failed setup still stops the graph, or its tasks outlive the store fixture and log
        # against a closed database, as the 2026-10-12 failure's teardown did.
        await _bounded_stop(runner)
        raise
    # The hung send must NOT block graceful stop. A regression (a swallowed or missing
    # cancellation) hangs here for good, and the ceiling turns that into a failure.
    await _bounded_stop(runner)
    assert not runner.running
    assert runner._workers == {} and runner._sources == {}  # no leaked tasks/sources
    assert hung.closed  # the connector was closed during teardown
    # Stop cancelled the hung send rather than abandoning it, and the task it ran on is finished.
    assert hung.cancelled
    assert hung.task is not None and hung.task.done()


async def test_problem_connection_does_not_block_engine_restart(
    store: MessageStore, tmp_path: Path
) -> None:
    # A wedged outbound during a live MLLP session must not block a clean stop, nor a fresh restart of
    # the same graph (the listener rebinds, workers respawn) — "doesn't block its restart" (#37).
    outdir = tmp_path / "out"
    reg = _mllp_in_reg(outdir)
    runner = RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    await runner.start()
    hung = _HangingDestination()
    try:
        port = runner._sources["mllp_in"].sockport  # type: ignore[attr-defined]
        runner._destinations["out"] = hung
        # AA at ingress; routes to the hung lane, so the send is in flight.
        await _mllp_client(port).send(ADT)
        await asyncio.wait_for(hung.entered.wait(), timeout=_HANG_CEILING_SECONDS)
    except BaseException:  # as in the test above: a failed setup still stops the graph
        await _bounded_stop(runner)
        raise
    await _bounded_stop(runner)  # clean stop despite the wedged connection
    assert not runner.running and runner._sources == {} and runner._workers == {}
    assert hung.cancelled

    runner2 = RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )  # fresh start of the same graph
    try:
        # A start cut off at the ceiling is still stopped below; stop() handles a half start.
        await asyncio.wait_for(runner2.start(), timeout=_HANG_CEILING_SECONDS)
        assert runner2.running and runner2.inbound_running("mllp_in")
        assert (
            not runner2.degraded_inbound() and not runner2.degraded_outbound()
        )  # nothing carried over as failed
    finally:
        await _bounded_stop(runner2)
