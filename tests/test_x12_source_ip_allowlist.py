# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Peer-IP allowlist for the X12 inbound LISTEN connector (SEC-011, CWE-306).

Regression intent: an X12 inbound must accept a ``source_ip_allowlist`` (wiring previously rejected
the field for X12, so an X12 listener bound to a NIC for a known partner could NOT be IP-restricted),
thread it into the connector settings, and have ``X12Source`` refuse a non-listed peer at accept —
exactly like ``TcpSource``/``MLLPSource``. Combined with SEC-002 (X12 has no TLS), this closes the
last binding LISTEN type that had neither an IP gate, nor TLS, nor an off-loopback refusal.
"""

from __future__ import annotations

import asyncio

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import WiringError, X12, build_inbound_connection
from messagefoundry.pipeline.wiring_runner import _source_config
from messagefoundry.transports.x12 import X12Source

# --- a synthetic, PHI-free 270 eligibility interchange (ISA…IEA) -------------


def _isa(*, control: str = "000000001") -> str:
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


EDI = (
    _isa()
    + "GS*HS*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
    + "ST*270*0001~"
    + "BHT*0022*13*10001234*20240101*1200~"
    + "HL*1**20*1~"
    + "SE*4*0001~"
    + "GE*1*1~"
    + "IEA*1*000000001~"
)


# --- wiring half (SEC-011 part a/b) ------------------------------------------


def test_x12_allowlist_accepted() -> None:
    """An X12 inbound now accepts source_ip_allowlist (previously raised WiringError)."""
    ic = build_inbound_connection(
        "IB", X12(port=2575), router="r", source_ip_allowlist=["10.0.0.0/8"]
    )
    assert ic.source_ip_allowlist == ("10.0.0.0/8",)


def test_x12_source_config_threads_allowlist() -> None:
    """_source_config threads the allowlist into the connector settings for X12."""
    ic = build_inbound_connection(
        "IB", X12(port=2575), router="r", source_ip_allowlist=["10.0.0.0/8"]
    )
    cfg = _source_config(ic, "0.0.0.0", {})
    assert cfg.settings["source_ip_allowlist"] == ["10.0.0.0/8"]


def test_x12_invalid_entry_still_rejected() -> None:
    """A malformed allowlist entry still fails loud at wiring."""
    with pytest.raises(WiringError, match="not a valid IP"):
        build_inbound_connection(
            "IB", X12(port=2575), router="r", source_ip_allowlist=["not-an-ip"]
        )


# --- connector half (SEC-011 part c) -----------------------------------------


def _source(allowlist: list[str]) -> X12Source:
    return X12Source(
        Source(
            type=ConnectorType.X12,
            settings={"host": "127.0.0.1", "port": 0, "source_ip_allowlist": allowlist},
        )
    )


async def _send(port: int) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(EDI.encode("utf-8"))
    await writer.drain()
    try:
        await asyncio.wait_for(reader.read(100), 0.5)  # drain any reply / EOF
    except (asyncio.TimeoutError, OSError):
        pass
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


async def test_x12_allowlisted_peer_accepted() -> None:
    handled: list[bytes] = []

    async def handler(raw: bytes) -> None:
        handled.append(raw)
        return None

    src = _source(["127.0.0.1"])
    await src.start(handler)
    try:
        await _send(src.sockport)
        for _ in range(100):
            if handled:
                break
            await asyncio.sleep(0.01)
    finally:
        await src.stop()
    assert handled == [EDI.encode("utf-8")]  # loopback peer is allowlisted -> delivered


async def test_x12_non_allowlisted_peer_refused() -> None:
    handled: list[bytes] = []

    async def handler(raw: bytes) -> None:
        handled.append(raw)
        return None

    src = _source(["10.0.0.1"])  # the loopback test peer (127.0.0.1) is NOT listed
    await src.start(handler)
    try:
        await _send(src.sockport)
        # give the (refused) connection a chance to be (not) handed up
        for _ in range(20):
            await asyncio.sleep(0.01)
    finally:
        await src.stop()
    assert handled == []  # peer not in the allowlist -> interchange never reached the handler
