# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""X12 through the FULL staged engine (P2 X12-15).

The X12 transport is proven at the socket level (``test_x12_transport``) and the codec in isolation, but
no test drives an X12 interchange the whole way through a real :class:`RegistryRunner` — listener →
ingress commit → router worker → transform worker → delivery worker → store finalizer. These do: a real
socket carries a synthetic ``ISA…IEA`` interchange into an ``IB_X12``-style graph and we assert the
count-and-log disposition the finalizer records for each of the three routing outcomes:

* a **270** eligibility interchange routes and delivers → ``PROCESSED`` (and the outbound sees it verbatim);
* an **837** (other transaction) the router declines → ``UNROUTED`` (logged, never an error, never delivered);
* an ISA-framed but **malformed** header the Router's peek can't parse → ``ERROR`` (dead-letter, not delivered).

Everything is pure-Python synthetic X12 (no PHI) over real loopback sockets on ``127.0.0.1:0``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Destination
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import RawMessage
from messagefoundry.parsing.x12 import X12Peek
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus
from messagefoundry.transports.x12 import X12Destination

# --- synthetic X12 corpus (mirrors test_x12_transport's ISA builder) ---------


def _isa(*, control: str = "000000001") -> str:
    """A fixed-length (106-char) ISA header with delimiters ``* ^ : ~``, version 00501."""
    el = "*"
    segment = (
        "ISA"
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "ZZ"
        + el
        + "SENDERID".ljust(15)
        + el
        + "ZZ"
        + el
        + "RECEIVERID".ljust(15)
        + el
        + "240101"
        + el
        + "1200"
        + el
        + "^"
        + el
        + "00501"
        + el
        + control
        + el
        + "0"
        + el
        + "P"
        + el
        + ":"
    )
    assert len(segment) == 105, f"ISA pre-terminator length {len(segment)} (want 105)"
    return segment + "~"


def _interchange(transaction: str = "270") -> str:
    """A complete, synthetic, PHI-free interchange whose single ST set carries ``transaction``."""
    return (
        _isa()
        + "GS*HS*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
        + f"ST*{transaction}*0001~"
        + "BHT*0022*13*10001234*20240101*1200~"
        + "SE*3*0001~"
        + "GE*1*1~"
        + "IEA*1*000000001~"
    )


#: An ISA-framed but malformed interchange: byte +6 (a fixed ISA element-separator position) is
#: corrupted, so the interchange still FRAMES (terminator at +105 intact, IEA present) and reaches the
#: router, but ``X12Peek.parse`` fails ``discover_delimiters``' sanity gate — the Router-side parse error.
def _malformed_interchange() -> str:
    good = _interchange("270")
    return good[:6] + "X" + good[7:]  # clobber the element separator at ISA offset 6


# --- routing logic under test ------------------------------------------------


def _route(msg: RawMessage) -> list[str]:
    """Route a 270 to the handler; decline anything else. ``X12Peek.parse`` raises ``X12PeekError``
    (a ``ValueError``) on a malformed ISA, which the router worker dead-letters as ``ERROR``."""
    if not msg.raw.lstrip().startswith("ISA"):
        return []
    peek = X12Peek.parse(msg.raw)  # raises on a malformed ISA -> dead-letter
    return ["handler"] if "270" in peek.transaction_ids() else []


def _handler(msg: RawMessage) -> Send:
    return Send("OB_X12", msg)  # verbatim pass-through to the outbound


class _Recorder:
    """A stand-in outbound connector that records each delivered payload (like ``_NeverSends`` in
    ``test_wiring_engine``) so we can drive real inbound traffic without a second listener/egress hop."""

    def __init__(self) -> None:
        self.payloads: list[str] = []

    async def send(self, payload: str, *, metadata: Mapping[str, str] | None = None) -> None:
        self.payloads.append(payload)

    async def aclose(self) -> None:
        return None


# --- harness -----------------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "x12engine.db")
    yield s
    await s.close()


def _registry() -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_X12",
            ConnectionSpec(ConnectorType.X12, {"host": "127.0.0.1", "port": 0}),
            router="r",
            content_type=ContentType.X12,
        )
    )
    # A loopback X12 outbound: build-checks cleanly (loopback is exempt from the cleartext-hop guard,
    # empty egress allowlist is unrestricted) and is swapped for the recorder before any traffic.
    reg.add_outbound(
        OutboundConnection(
            "OB_X12", ConnectionSpec(ConnectorType.X12, {"host": "127.0.0.1", "port": 9})
        )
    )
    reg.add_router("r", _route)
    reg.add_handler("handler", _handler)
    return reg


async def _start(store: MessageStore) -> tuple[RegistryRunner, _Recorder]:
    runner = RegistryRunner(_registry(), store, poll_interval=0.02)
    await runner.start()
    recorder = _Recorder()
    runner._destinations["OB_X12"] = recorder  # swap in before any inbound traffic
    return runner, recorder


def _client(port: int) -> X12Destination:
    return X12Destination(
        Destination(
            name="drive",
            type=ConnectorType.X12,
            settings={"host": "127.0.0.1", "port": port, "timeout_seconds": 5},
        )
    )


async def _until_message(store: MessageStore, status: str, *, timeout: float = 3.0) -> None:
    elapsed = 0.0
    while not await store.list_messages(channel_id="IB_X12", status=status):
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"no {status} message within timeout")


# --- the three routing outcomes ----------------------------------------------


async def test_x12_interchange_routes_processed(store: MessageStore) -> None:
    runner, recorder = await _start(store)
    edi = _interchange("270")
    try:
        port = runner._sources["IB_X12"].sockport  # type: ignore[attr-defined]
        await _client(port).send(edi)
        await _until_message(store, MessageStatus.PROCESSED.value)
    finally:
        await runner.stop()
    assert recorder.payloads == [edi]  # delivered verbatim, exactly once
    assert (await store.stats()).get(OutboxStatus.DONE.value) == 1


async def test_x12_other_transaction_unrouted(store: MessageStore) -> None:
    runner, recorder = await _start(store)
    try:
        port = runner._sources["IB_X12"].sockport  # type: ignore[attr-defined]
        await _client(port).send(_interchange("837"))  # router declines a non-270
        await _until_message(store, MessageStatus.UNROUTED.value)
    finally:
        await runner.stop()
    assert recorder.payloads == []  # count-and-log: recorded UNROUTED, never delivered
    # UNROUTED is not an error and never enqueues an outbound row.
    assert (await store.stats()).get(OutboxStatus.DONE.value) is None
    assert not await store.list_messages(channel_id="IB_X12", status=MessageStatus.ERROR.value)


async def test_x12_malformed_isa_errors(store: MessageStore) -> None:
    runner, recorder = await _start(store)
    try:
        port = runner._sources["IB_X12"].sockport  # type: ignore[attr-defined]
        await _client(port).send(
            _malformed_interchange()
        )  # frames, but the Router's peek can't parse
        await _until_message(store, MessageStatus.ERROR.value)
    finally:
        await runner.stop()
    assert recorder.payloads == []  # dead-lettered post-ingress, nothing delivered
    assert (await store.stats()).get(OutboxStatus.DONE.value) is None
