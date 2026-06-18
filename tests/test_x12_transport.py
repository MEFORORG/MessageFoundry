# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Raw-TCP X12 transport (transports/x12.py) — ISA/IEA framing over a real socket.

The headline test is the ADR 0012 **build-check**: prove a raw-TCP ``receive()`` populates a
``RawMessage`` on a real (synthetic) X12 ISA, end to end (``receive() -> RawMessage("x12") ->
X12Peek``), before relying on the connector. The rest cover verbatim relay, multi-interchange framing,
the reply paths, connect failure, the oversize guard, and registry build.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    WiringError,
    X12,
    inbound,
    outbound,
)
from messagefoundry.parsing.message import RawMessage
from messagefoundry.parsing.x12 import X12Peek
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    _source_config,
    check_egress_allowed,
)
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.x12 import X12Destination, X12Source


def _isa(
    *, sender: str = "SENDERID", receiver: str = "RECEIVERID", control: str = "000000001"
) -> str:
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
        + sender.ljust(15)
        + el
        + "ZZ"
        + el
        + receiver.ljust(15)
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


def _interchange(*, sender: str = "SENDERID", receiver: str = "RECEIVERID") -> str:
    """A complete, synthetic, PHI-free 270 eligibility interchange (one GS, one ST)."""
    return (
        _isa(sender=sender, receiver=receiver)
        + "GS*HS*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
        + "ST*270*0001~"
        + "BHT*0022*13*10001234*20240101*1200~"
        + "HL*1**20*1~"
        + "SE*4*0001~"
        + "GE*1*1~"
        + "IEA*1*000000001~"
    )


EDI = _interchange()


def _source(**settings: object) -> X12Source:
    base: dict[str, object] = {"host": "127.0.0.1", "port": 0}
    base.update(settings)
    return X12Source(Source(type=ConnectorType.X12, settings=base))


def _dest(port: int, **settings: object) -> X12Destination:
    base: dict[str, object] = {"host": "127.0.0.1", "port": port, "timeout_seconds": 5}
    base.update(settings)
    return X12Destination(Destination(name="out", type=ConnectorType.X12, settings=base))


async def _receive_one(
    source: X12Source, payload: str, dest_kwargs: dict[str, object] | None = None
) -> list[bytes]:
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)
        return None

    await source.start(handler)
    try:
        await _dest(source.sockport, **(dest_kwargs or {})).send(payload)
        for _ in range(100):
            if received:
                break
            await asyncio.sleep(0.01)
    finally:
        await source.stop()
    return received


# --- the ADR 0012 build-check ------------------------------------------------


async def test_build_check_receive_to_rawmessage_to_peek() -> None:
    """receive() frames exactly one verbatim interchange -> RawMessage('x12') -> X12Peek routing."""
    received = await _receive_one(_source(), EDI)

    # 1. The raw-TCP receive framed exactly one complete interchange, verbatim (ISA delimiters intact).
    assert received == [EDI.encode("utf-8")]

    # 2. The payload-agnostic path (ADR 0004) builds a RawMessage the engine would hand a Router.
    rm = RawMessage(received[0].decode("utf-8"), ContentType.X12.value)
    assert rm.content_type == "x12"
    assert rm.raw == EDI
    assert rm.encode() == EDI  # pass-through Send round-trips

    # 3. Routing works without forcing a full parse.
    peek = X12Peek.parse(rm.raw)
    assert peek.sender_id == "SENDERID"
    assert peek.receiver_id == "RECEIVERID"
    assert peek.version == "00501"
    assert peek.transaction_ids() == ["270"]


# --- relay + framing ---------------------------------------------------------


async def test_round_trip_verbatim_relay() -> None:
    assert await _receive_one(_source(), EDI) == [EDI.encode("utf-8")]


async def test_two_interchanges_in_one_connection() -> None:
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)
        return None

    a = _interchange(sender="PARTNERA")
    b = _interchange(sender="PARTNERB")
    source = _source()
    await source.start(handler)
    try:
        # Both interchanges sent back-to-back on one connection must frame as two separate messages.
        await _dest(source.sockport).send(a + b)
        for _ in range(100):
            if len(received) >= 2:
                break
            await asyncio.sleep(0.01)
    finally:
        await source.stop()
    assert received == [a.encode("utf-8"), b.encode("utf-8")]


async def test_destination_no_reply_returns_when_not_expecting_one() -> None:
    async def handler(raw: bytes) -> None:
        return None

    source = _source()
    await source.start(handler)
    try:
        await _dest(source.sockport).send(EDI)  # expect_reply defaults False → returns after write
    finally:
        await source.stop()


async def test_destination_expect_reply_reads_returned_interchange() -> None:
    reply = _interchange(sender="ACK")

    async def handler(raw: bytes) -> str:
        return reply  # written back verbatim on the same connection

    source = _source()
    await source.start(handler)
    try:
        await _dest(source.sockport, expect_reply=True).send(EDI)
    finally:
        await source.stop()


async def test_destination_expect_reply_times_out_when_none_sent() -> None:
    async def handler(raw: bytes) -> None:
        return None

    source = _source()
    await source.start(handler)
    try:
        with pytest.raises(DeliveryError):
            await _dest(source.sockport, expect_reply=True, timeout_seconds=0.3).send(EDI)
    finally:
        await source.stop()


async def test_destination_connect_failure_raises_delivery_error() -> None:
    with pytest.raises(DeliveryError):
        await _dest(1).send(EDI)  # nothing listening on port 1


async def test_source_drops_oversize_interchange() -> None:
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)
        return None

    source = _source(max_interchange_bytes=64)  # smaller than the ISA+body
    await source.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        writer.write(EDI.encode("utf-8"))
        await writer.drain()
        assert await reader.read(1) == b""  # connection dropped, nothing delivered
        writer.close()
    finally:
        await source.stop()
    assert received == []


# --- registry build ----------------------------------------------------------


def test_build_source_and_destination_via_registry() -> None:
    src = build_source(Source(type=ConnectorType.X12, settings={"host": "127.0.0.1", "port": 0}))
    assert isinstance(src, X12Source)
    dest = build_destination(
        Destination(name="o", type=ConnectorType.X12, settings={"host": "127.0.0.1", "port": 9})
    )
    assert isinstance(dest, X12Destination)


# --- factory + wiring guards -------------------------------------------------


def test_x12_factory_inbound_omits_host_and_framing_knobs() -> None:
    spec = X12(port=2700)
    assert spec.type is ConnectorType.X12
    assert spec.settings["host"] is None  # inbound binds [inbound].bind_host
    # Delimiters are discovered from the ISA — no framing knobs on the factory.
    assert "framing" not in spec.settings and "start" not in spec.settings


def test_x12_inbound_rejects_host() -> None:
    reg = Registry()
    import messagefoundry.config.wiring as w

    w._active = reg
    try:
        with pytest.raises(WiringError, match="takes no host"):
            inbound("IB_X12", X12(host="203.0.113.1", port=2700), router="r")
    finally:
        w._active = None


def test_x12_outbound_requires_host() -> None:
    reg = Registry()
    import messagefoundry.config.wiring as w

    w._active = reg
    try:
        with pytest.raises(WiringError, match="requires a host"):
            outbound("OB_X12", X12(port=2700))
    finally:
        w._active = None


def _x12_dest(host: str, port: int) -> Destination:
    return Destination(name="OB", type=ConnectorType.X12, settings={"host": host, "port": port})


def test_x12_egress_shares_allowed_tcp_allowlist() -> None:
    egress = EgressSettings(allowed_tcp=["payer.example:5000", "10.0.0.9"])
    check_egress_allowed(_x12_dest("payer.example", 5000), egress)  # exact host:port
    check_egress_allowed(_x12_dest("10.0.0.9", 7777), egress)  # host-only entry → any port
    with pytest.raises(WiringError, match="allowed_tcp"):
        check_egress_allowed(_x12_dest("evil.example", 5000), egress)


def test_x12_egress_empty_allowlist_is_unrestricted() -> None:
    check_egress_allowed(_x12_dest("anywhere.example", 1234), EgressSettings())  # no raise


def test_x12_source_config_injects_bind_host() -> None:
    ic = InboundConnection(
        "IB_X12",
        ConnectionSpec(ConnectorType.X12, {"port": 2700}),
        router="r",
        content_type=ContentType.X12,
    )
    src = _source_config(ic, "10.0.0.5", {})
    assert src.settings["host"] == "10.0.0.5"  # service bind interface injected (bind-guard parity)


async def test_x12_inbound_listener_not_connect_gated(tmp_path: Path) -> None:
    # An X12 source is a local listener (binds bind_host), so it build-checks cleanly even with an
    # allowed_tcp list — that list governs only X12/TCP destinations.
    store = await MessageStore.open(tmp_path / "x.db")
    try:
        reg = Registry()
        reg.add_inbound(
            InboundConnection(
                "IB_X12",
                ConnectionSpec(ConnectorType.X12, {"port": 2700}),
                router="r",
                content_type=ContentType.X12,
            )
        )
        reg.add_router("r", lambda m: [])
        reg.add_outbound(
            OutboundConnection(
                "OB_X12", ConnectionSpec(ConnectorType.X12, {"host": "ok.org", "port": 5000})
            )
        )
        runner = RegistryRunner(reg, store, egress=EgressSettings(allowed_tcp=["ok.org:5000"]))
        runner.build_check(runner.registry)  # no raise — listener not gated, dest allowed
    finally:
        await store.close()


async def test_x12_egress_denied_fails_build_check(tmp_path: Path) -> None:
    # An X12 destination not in [egress].allowed_tcp must fail-closed at build_check (the security path
    # end to end, not just the direct check_egress_allowed unit test).
    store = await MessageStore.open(tmp_path / "x.db")
    try:
        reg = Registry()
        reg.add_inbound(
            InboundConnection(
                "IB_X12",
                ConnectionSpec(ConnectorType.X12, {"port": 2710}),
                router="r",
                content_type=ContentType.X12,
            )
        )
        reg.add_router("r", lambda m: [])
        reg.add_outbound(
            OutboundConnection(
                "OB_X12", ConnectionSpec(ConnectorType.X12, {"host": "evil.example", "port": 5000})
            )
        )
        runner = RegistryRunner(reg, store, egress=EgressSettings(allowed_tcp=["ok.org:5000"]))
        with pytest.raises(WiringError, match="allowed_tcp"):
            runner.build_check(runner.registry)
    finally:
        await store.close()
