# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What ``ordering=UNORDERED`` on an outbound lane does, and what it does not.

These tests exist because four documents claimed unordered mode buys concurrency inside one outbound
connection, and it does not. If one of them reds, re-reconcile the docs it guards; do not relax the
test.

Three facts are pinned here:

* **Unordered never buys intra-lane concurrency.** One outbound connection is one serial sender in
  either claim mode. Parallelism comes from having more lanes, which the positive control shows.
  This half is unchanged by ADR 0066 D4 and its tests are untouched.
* **What unordered DOES buy is failure isolation, in both claim modes.** An unordered lane runs its
  own ``_delivery_worker``, claims a batch, and rotates past a backing-off row, so one stuck message
  does not hold the lane.
* **A FIFO lane under the default claim mode stays on the pooled OUTBOUND dispatcher**, drains at
  ``per_lane_limit`` 1, and blocks its head on failure.

THE PARTITION IS THE POINT, so both sides are pinned. A lane is drained by its own worker or by the
dispatcher, never by both: two consumers on one lane would break per-lane FIFO (ADR 0073). Each
"does this lane get a worker" assertion is paired with the matching "is this lane in the dispatcher's
lane set" assertion, so a change that hands a lane to both fails here rather than in production.

THE POSITIVE CONTROL IS NOT OPTIONAL. A concurrency gauge that can only ever read 1 proves nothing
about serialism, so ``test_three_lanes_do_send_concurrently`` runs the same gauge over three lanes
and demands it read above 1. Without it, a broken counter and a serial lane look identical.

ADR 0066 DECISION 4 said unordered outbound lanes "stay on the existing per-lane ``claim_ready``
workers", and §4's low-lane-count paragraph repeats it as "in either mode". The shipped code did not
do that until this change; now it does. The ADR is a historical record and is not rewritten. Its
residual gap: it says nothing about a lane whose ordering flips while the engine runs, and the code
refuses that handover rather than racing two consumers for a lane (see
``_resolve_lane_consumer``).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, OrderingMode
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage
from messagefoundry.transports import base as transport_base
from messagefoundry.transports.base import DeliveryError, DeliveryResponse, DestinationConnector

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)

# Each send holds the lane this long. Long enough that a second concurrent send would overlap it and
# the gauge below would read 2; short enough that six serial sends finish well inside the wait.
_SEND_HOLD_SECONDS = 0.12

_LANE = "OB_UNORD"


class _Gauge:
    """Peak simultaneous sends. Every send runs on the one event loop, so a plain counter is exact:
    the increment and the read happen with no await between them."""

    def __init__(self) -> None:
        self.live = 0
        self.peak = 0

    def enter(self) -> None:
        self.live += 1
        self.peak = max(self.peak, self.live)

    def leave(self) -> None:
        self.live -= 1


class _HoldingDestination(DestinationConnector):
    """Records (lane, payload) at send START, then holds the lane for a fixed window. Recording at
    start means the sink reads dispatch order, which is what the FIFO assertion is about."""

    def __init__(self, name: str, sink: list[tuple[str, str]], gauge: _Gauge) -> None:
        self._name = name
        self._sink = sink
        self._gauge = gauge

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:
        self._sink.append((self._name, payload))
        self._gauge.enter()
        try:
            await asyncio.sleep(_SEND_HOLD_SECONDS)
        finally:
            self._gauge.leave()
        return None


@pytest.fixture
def rig() -> Iterator[tuple[list[tuple[str, str]], _Gauge]]:
    """A shared delivery log plus concurrency gauge, wired in over the FILE destination builder for
    the duration of one test. Restores the real builder so other tests are unaffected."""
    recorded: list[tuple[str, str]] = []
    gauge = _Gauge()
    original = transport_base._DESTINATIONS.get(ConnectorType.FILE)

    def _build(config: Any) -> _HoldingDestination:
        return _HoldingDestination(config.name, recorded, gauge)

    transport_base.register_destination(ConnectorType.FILE, _build)
    try:
        yield recorded, gauge
    finally:
        if original is not None:
            transport_base.register_destination(ConnectorType.FILE, original)
        else:  # pragma: no cover - FILE is always registered in practice
            transport_base._DESTINATIONS.pop(ConnectorType.FILE, None)


class _PoisonDestination(DestinationConnector):
    """Refuses ONE nominated payload forever and delivers every other one. ``attempts`` records every
    send the lane reaches, so a test can wait for the poisoned head to be tried before asserting what
    did NOT follow it — otherwise "nothing else delivered" could just mean "nothing arrived yet".

    A refused row backs off for the default 5 s, far longer than any wait in this file. So inside a
    test window a FIFO lane delivers nothing at all behind its poisoned head, and an unordered lane
    delivers every other row. That gap is the whole discriminator."""

    def __init__(
        self, name: str, sink: list[tuple[str, str]], attempts: list[str], poison: str
    ) -> None:
        self._name = name
        self._sink = sink
        self._attempts = attempts
        self._poison = poison

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:
        self._attempts.append(payload)
        if payload == self._poison:
            raise DeliveryError(f"partner refused {payload}")
        self._sink.append((self._name, payload))
        return None


@pytest.fixture
def poison_rig() -> Iterator[tuple[list[tuple[str, str]], list[str]]]:
    """Delivery log plus attempt log, wired in over the FILE destination builder. ``p0`` is the
    poisoned payload, which is the FIRST row every lane in this file enqueues — so it is the head."""
    recorded: list[tuple[str, str]] = []
    attempts: list[str] = []
    original = transport_base._DESTINATIONS.get(ConnectorType.FILE)

    def _build(config: Any) -> _PoisonDestination:
        return _PoisonDestination(config.name, recorded, attempts, "p0")

    transport_base.register_destination(ConnectorType.FILE, _build)
    try:
        yield recorded, attempts
    finally:
        if original is not None:
            transport_base.register_destination(ConnectorType.FILE, original)
        else:  # pragma: no cover - FILE is always registered in practice
            transport_base._DESTINATIONS.pop(ConnectorType.FILE, None)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _dest(name: str, ordering: OrderingMode) -> OutboundConnection:
    """An outbound that explicitly declares its ordering mode. Settings are valid FILE settings; the
    builders above ignore them."""
    return OutboundConnection(
        name,
        ConnectionSpec(ConnectorType.FILE, {"directory": ".", "filename": "{MSH-10}.hl7"}),
        ordering=ordering,
    )


def _registry(
    inbox: Path, lanes: list[str], ordering: OrderingMode = OrderingMode.UNORDERED
) -> Registry:
    """One inbound message routed to ``len(lanes)`` handlers. Handler i sends payload ``p{i}`` to
    ``lanes[i]``, so the caller chooses how the rows spread across outbound connections."""
    reg = Registry()
    for lane in dict.fromkeys(lanes):
        reg.add_outbound(_dest(lane, ordering))
    for i, lane in enumerate(lanes):
        reg.add_handler(f"h{i}", (lambda ln, pl: lambda m: Send(ln, pl))(lane, f"p{i}"))
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [f"h{i}" for i in range(len(lanes))])
    return reg


def _drop(inbox: Path, control_id: str = "MSG1") -> None:
    inbox.mkdir(exist_ok=True)
    (inbox / f"{control_id}.hl7").write_bytes(ADT.replace("MSG1", control_id).encode("utf-8"))


async def _wait_until(pred: Any, timeout: float = 10.0, tick: float = 0.02) -> None:
    elapsed = 0.0
    while not pred():
        await asyncio.sleep(tick)
        elapsed += tick
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


def _runner(reg: Registry, store: MessageStore, *, claim_mode: str | None) -> RegistryRunner:
    """``claim_mode=None`` means "take the constructor default", which is the shipped default the
    inertness claim is about. Naming it would let a default flip pass unnoticed."""
    # fifo_claim_batch=8 lets the ROUTED stage co-claim the sibling rows, so all the outbound rows
    # exist within a few milliseconds. Without it the rows trickle out one transform at a time and the
    # positive control could read a low peak for a reason that has nothing to do with ordering.
    if claim_mode is None:
        return RegistryRunner(reg, store, poll_interval=0.02, fifo_claim_batch=8)
    return RegistryRunner(reg, store, poll_interval=0.02, fifo_claim_batch=8, claim_mode=claim_mode)


@dataclass(frozen=True)
class _Snapshot:
    """Runner wiring read WHILE the engine is live. Teardown clears ``_workers`` and ``_dispatchers``,
    so reading them after ``stop()`` returns empty for every mode and proves nothing."""

    claim_mode: str
    per_lane_workers: frozenset[str]
    outbound_lanes: frozenset[str] | None  # None = no pooled OUTBOUND dispatcher in this mode
    outbound_per_lane_limit: int | None


async def _deliver(
    reg: Registry,
    store: MessageStore,
    sink: list[tuple[str, str]],
    *,
    want: int,
    claim_mode: str | None,
) -> _Snapshot:
    runner = _runner(reg, store, claim_mode=claim_mode)
    await runner.start()
    try:
        await _wait_until(lambda: len(sink) >= want)
        # A beat so an overlapping send that started late still registers on the gauge before we read
        # it, and so a stray extra delivery shows up in the sink.
        await asyncio.sleep(_SEND_HOLD_SECONDS)
        # Assert the count rather than waiting on `== want`: a redelivery would make that predicate
        # never true, and the test would fail with a timeout message that names the wrong problem.
        assert len(sink) == want, f"expected {want} deliveries, got {sink}"
        dispatcher = runner._dispatchers.get(Stage.OUTBOUND)
        return _Snapshot(
            claim_mode=runner._claim_mode,
            per_lane_workers=frozenset(runner._workers),
            outbound_lanes=None if dispatcher is None else frozenset(dispatcher._lane_provider()),
            outbound_per_lane_limit=None if dispatcher is None else dispatcher._per_lane_limit,
        )
    finally:
        await runner.stop()


# --- the shipped default: an unordered lane gets its own worker (ADR 0066 D4) -------------------


async def test_pooled_default_spawns_a_per_lane_worker_for_an_unordered_lane(
    store: MessageStore, rig: tuple[list[tuple[str, str]], _Gauge], tmp_path: Path
) -> None:
    """Under the shipped default claim mode an unordered lane gets its OWN delivery worker and is
    held OUT of the pooled OUTBOUND lane set. Both halves matter: the second is what keeps the
    dispatcher from becoming a second claimer of a lane the worker already drains."""
    sink, _ = rig
    inbox = tmp_path / "in"
    _drop(inbox)
    reg = _registry(inbox, [_LANE] * 6)

    seen = await _deliver(reg, store, sink, want=6, claim_mode=None)

    assert seen.claim_mode == "pooled"  # the default this test is about
    assert _LANE in seen.per_lane_workers  # it has its own delivery worker
    assert seen.outbound_lanes is not None  # the dispatcher exists…
    assert _LANE not in seen.outbound_lanes  # …and this lane is not its to claim


async def test_pooled_default_rotates_past_a_backing_off_head_on_an_unordered_lane(
    store: MessageStore, poison_rig: tuple[list[tuple[str, str]], list[str]], tmp_path: Path
) -> None:
    """The setting now does something under the default. ``p0`` is refused and backs off for 5 s; the
    lane passes over it and delivers p1 through p5 instead of waiting on the head."""
    sink, attempts = poison_rig
    inbox = tmp_path / "in"
    _drop(inbox)
    reg = _registry(inbox, [_LANE] * 6)

    runner = _runner(reg, store, claim_mode=None)
    await runner.start()
    try:
        await _wait_until(lambda: len(sink) >= 5)
        assert "p0" in attempts  # the head WAS tried, so its absence below is a pass-over
        assert sorted(payload for _, payload in sink) == [f"p{i}" for i in range(1, 6)]
        assert all(payload != "p0" for _, payload in sink)
    finally:
        await runner.stop()


async def test_pooled_default_keeps_a_fifo_lane_on_the_dispatcher_and_blocks_its_head(
    store: MessageStore, poison_rig: tuple[list[tuple[str, str]], list[str]], tmp_path: Path
) -> None:
    """THE OTHER SIDE OF THE PARTITION. The same six rows on a FIFO lane get no per-lane worker, sit
    in the pooled OUTBOUND lane set, and stop dead behind the refused head — which is what pinning
    only the unordered side would let a change quietly break."""
    sink, attempts = poison_rig
    inbox = tmp_path / "in"
    _drop(inbox)
    reg = _registry(inbox, [_LANE] * 6, ordering=OrderingMode.FIFO)

    runner = _runner(reg, store, claim_mode=None)
    await runner.start()
    try:
        await _wait_until(lambda: "p0" in attempts)
        # A beat longer than the whole unordered test needs to deliver five rows. The head's backoff
        # is 5 s, so nothing behind it may move in that window.
        await asyncio.sleep(_SEND_HOLD_SECONDS * 4)
        assert sink == [], f"a FIFO lane delivered past its blocked head: {sink}"
        dispatcher = runner._dispatchers.get(Stage.OUTBOUND)
        assert _LANE not in runner._workers  # no per-lane worker for a FIFO lane
        assert dispatcher is not None and _LANE in dispatcher._lane_provider()
        assert dispatcher._per_lane_limit == 1  # one row in flight per lane, hard-set for OUTBOUND
    finally:
        await runner.stop()


async def test_one_unordered_lane_sends_one_at_a_time_under_the_default(
    store: MessageStore, rig: tuple[list[tuple[str, str]], _Gauge], tmp_path: Path
) -> None:
    """One outbound connection is one serial sender. Read this beside the positive control below."""
    sink, gauge = rig
    inbox = tmp_path / "in"
    _drop(inbox)
    reg = _registry(inbox, [_LANE] * 6)

    await _deliver(reg, store, sink, want=6, claim_mode=None)

    assert gauge.peak == 1


# --- the opt-out: per_lane does spawn a worker, and it is still serial ---------------------------


async def test_per_lane_mode_spawns_a_worker_for_an_unordered_lane(
    store: MessageStore, rig: tuple[list[tuple[str, str]], _Gauge], tmp_path: Path
) -> None:
    """``claim_mode="per_lane"`` is the only mode that runs ``_delivery_worker``, which is the only
    place the ordering mode is read. Order is deliberately not asserted here: a batch claim may
    rotate past a backing-off row, so the delivered order is not pinned."""
    sink, _ = rig
    inbox = tmp_path / "in"
    _drop(inbox)
    reg = _registry(inbox, [_LANE] * 6)

    seen = await _deliver(reg, store, sink, want=6, claim_mode="per_lane")

    assert _LANE in seen.per_lane_workers
    assert seen.outbound_lanes is None  # no pooled OUTBOUND dispatcher in this mode


async def test_one_unordered_lane_sends_one_at_a_time_under_per_lane(
    store: MessageStore, rig: tuple[list[tuple[str, str]], _Gauge], tmp_path: Path
) -> None:
    """The opt-out does not change the answer either. A batch claim still sends the batch one row at
    a time, so relaxing ordering buys failure isolation, never intra-lane concurrency."""
    sink, gauge = rig
    inbox = tmp_path / "in"
    _drop(inbox)
    reg = _registry(inbox, [_LANE] * 6)

    await _deliver(reg, store, sink, want=6, claim_mode="per_lane")

    assert gauge.peak == 1


# --- POSITIVE CONTROL: the gauge can read above 1, so the 1 above is real ------------------------


@pytest.mark.parametrize("claim_mode", [None, "per_lane"])
async def test_three_lanes_do_send_concurrently(
    store: MessageStore,
    rig: tuple[list[tuple[str, str]], _Gauge],
    tmp_path: Path,
    claim_mode: str | None,
) -> None:
    """THE CONTROL. Same gauge, same hold, same six rows, spread over THREE outbound lanes instead of
    one. The peak reads above 1 in both claim modes, so the serial readings above measure serialism
    rather than a broken counter. It also shows where parallelism actually comes from: more lanes."""
    sink, gauge = rig
    inbox = tmp_path / "in"
    _drop(inbox)
    lanes = [f"OB_{i % 3}" for i in range(6)]  # round-robin, so the first three hit distinct lanes
    reg = _registry(inbox, lanes)

    await _deliver(reg, store, sink, want=6, claim_mode=claim_mode)

    assert gauge.peak > 1
    assert {lane for lane, _ in sink} == {"OB_0", "OB_1", "OB_2"}
