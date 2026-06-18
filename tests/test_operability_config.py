# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-connection operability config (Tier 4): ``metadata``, ``bind_address`` override, and
``source_ip_allowlist``.

Covers the wiring validation + threading, the ``connections.toml`` round-trip, the ``_source_config``
bind precedence + allowlist injection, the ``peer_ip_allowed`` helper, and end-to-end accept-time
rejection on the MLLP and TCP listen sources."""

from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import (
    MLLP,
    File,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
    load_config,
)
from messagefoundry.pipeline.wiring_runner import _source_config
from messagefoundry.transports.base import peer_ip_allowed
from messagefoundry.transports.framing import STX_ETX_CODEC
from messagefoundry.transports.mllp import MLLPSource, build_ack, frame
from messagefoundry.transports.tcp import TcpSource

MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\r"


# --- peer_ip_allowed helper --------------------------------------------------


def test_peer_ip_allowed_empty_permits_all() -> None:
    assert peer_ip_allowed(("203.0.113.5", 5000), None) is True
    assert peer_ip_allowed(("203.0.113.5", 5000), []) is True


def test_peer_ip_allowed_exact_ipv4() -> None:
    assert peer_ip_allowed(("127.0.0.1", 1), ["127.0.0.1"]) is True
    assert peer_ip_allowed(("10.0.0.9", 1), ["127.0.0.1"]) is False


def test_peer_ip_allowed_cidr() -> None:
    assert peer_ip_allowed(("192.168.1.50", 1), ["192.168.1.0/24"]) is True
    assert peer_ip_allowed(("192.168.2.50", 1), ["192.168.1.0/24"]) is False


def test_peer_ip_allowed_ipv6() -> None:
    assert peer_ip_allowed(("::1", 1, 0, 0), ["::1"]) is True
    assert peer_ip_allowed(("2001:db8::5", 1, 0, 0), ["2001:db8::/32"]) is True


def test_peer_ip_allowed_ipv4_mapped_ipv6_matches_v4_entry() -> None:
    # A dual-stack socket reports the peer as ::ffff:a.b.c.d — it must still match an IPv4 entry.
    assert peer_ip_allowed(("::ffff:127.0.0.1", 1, 0, 0), ["127.0.0.1"]) is True


def test_peer_ip_allowed_zone_id_is_stripped() -> None:
    assert peer_ip_allowed(("fe80::1%eth0", 1, 0, 0), ["fe80::1"]) is True


def test_peer_ip_allowed_unresolvable_peer_denied_when_restricted() -> None:
    assert peer_ip_allowed(None, ["127.0.0.1"]) is False  # UNIX socket / no peer
    assert peer_ip_allowed(("not-an-ip", 1), ["127.0.0.1"]) is False


def test_peer_ip_allowed_skips_malformed_entry() -> None:
    assert peer_ip_allowed(("127.0.0.1", 1), ["nonsense", "127.0.0.1"]) is True
    assert peer_ip_allowed(("127.0.0.1", 1), ["nonsense"]) is False


# --- wiring validation + storage ---------------------------------------------


def test_bind_address_rejected_on_non_listen_source() -> None:
    with pytest.raises(WiringError, match="bind_address is only valid"):
        build_inbound_connection("IB", File(directory="x"), router="r", bind_address="0.0.0.0")


def test_bind_address_accepted_on_mllp() -> None:
    ic = build_inbound_connection("IB", MLLP(port=2575), router="r", bind_address="0.0.0.0")
    assert ic.bind_address == "0.0.0.0"


def test_bind_address_blank_rejected_at_wiring() -> None:
    # A whitespace-only bind_address would crash asyncio.start_server at boot — fail loud at wiring.
    with pytest.raises(WiringError, match="bind_address must be a non-empty"):
        build_inbound_connection("IB", MLLP(port=2575), router="r", bind_address="   ")


def test_source_ip_allowlist_rejected_on_non_listen_source() -> None:
    with pytest.raises(WiringError, match="source_ip_allowlist is only valid"):
        build_inbound_connection(
            "IB", File(directory="x"), router="r", source_ip_allowlist=["127.0.0.1"]
        )


def test_source_ip_allowlist_invalid_entry_rejected() -> None:
    with pytest.raises(WiringError, match="not a valid IP address or CIDR"):
        build_inbound_connection(
            "IB", MLLP(port=2575), router="r", source_ip_allowlist=["999.1.1.1"]
        )


def test_source_ip_allowlist_valid_frozen_to_tuple() -> None:
    ic = build_inbound_connection(
        "IB", MLLP(port=2575), router="r", source_ip_allowlist=["127.0.0.1", "10.0.0.0/8"]
    )
    assert ic.source_ip_allowlist == ("127.0.0.1", "10.0.0.0/8")


def test_source_ip_allowlist_empty_is_no_restriction() -> None:
    ic = build_inbound_connection("IB", MLLP(port=2575), router="r", source_ip_allowlist=[])
    assert ic.source_ip_allowlist is None


def test_metadata_non_table_rejected() -> None:
    with pytest.raises(WiringError, match="metadata must be a table"):
        build_inbound_connection("IB", MLLP(port=2575), router="r", metadata=["not", "a", "table"])


def test_metadata_stored_on_inbound_and_outbound() -> None:
    ic = build_inbound_connection("IB", MLLP(port=2575), router="r", metadata={"owner": "team-x"})
    assert ic.metadata == {"owner": "team-x"}
    oc = build_outbound_connection(
        "OB", MLLP(host="epic.example", port=2700), metadata={"tier": "g"}
    )
    assert oc.metadata == {"tier": "g"}


# --- _source_config: bind precedence + allowlist injection -------------------


def test_source_config_bind_address_overrides_service_host() -> None:
    ic = build_inbound_connection("IB", MLLP(port=2575), router="r", bind_address="0.0.0.0")
    assert _source_config(ic, "127.0.0.1", {}).settings["host"] == "0.0.0.0"


def test_source_config_falls_back_to_service_bind_host() -> None:
    ic = build_inbound_connection("IB", MLLP(port=2575), router="r")
    assert _source_config(ic, "10.1.2.3", {}).settings["host"] == "10.1.2.3"


def test_source_config_injects_allowlist_for_mllp() -> None:
    ic = build_inbound_connection(
        "IB", MLLP(port=2575), router="r", source_ip_allowlist=["127.0.0.1"]
    )
    assert _source_config(ic, "127.0.0.1", {}).settings["source_ip_allowlist"] == ["127.0.0.1"]


def test_source_config_file_ignores_host_and_allowlist() -> None:
    ic = build_inbound_connection("IB", File(directory="x"), router="r")
    settings = _source_config(ic, "127.0.0.1", {}).settings
    assert "host" not in settings
    assert "source_ip_allowlist" not in settings


# --- connections.toml round-trip ---------------------------------------------

_LOGIC_PY = textwrap.dedent(
    """
    from messagefoundry import Send, handler, router

    @router("r")
    def route(msg):
        return ["h"]

    @handler("h")
    def handle(msg):
        return Send("OB", msg)
    """
)


def _load(tmp_path: Path, toml: str):
    (tmp_path / "logic.py").write_text(_LOGIC_PY, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(textwrap.dedent(toml), encoding="utf-8")
    return load_config(tmp_path)


def test_toml_inbound_operability_fields(tmp_path: Path) -> None:
    reg = _load(
        tmp_path,
        """
        [[inbound]]
        name = "IB"
        transport = "mllp"
        router = "r"
        bind_address = "0.0.0.0"
        source_ip_allowlist = ["127.0.0.1", "10.0.0.0/8"]
          [inbound.settings]
          port = 2575
          [inbound.metadata]
          owner = "team-x"
          runbook = "https://wiki/rb"

        [[outbound]]
        name = "OB"
        transport = "mllp"
          [outbound.settings]
          host = "epic.example"
          port = 2700
          [outbound.metadata]
          tier = "gold"
        """,
    )
    ib = reg.inbound["IB"]
    assert ib.bind_address == "0.0.0.0"
    assert ib.source_ip_allowlist == ("127.0.0.1", "10.0.0.0/8")
    assert ib.metadata == {"owner": "team-x", "runbook": "https://wiki/rb"}
    assert reg.outbound["OB"].metadata == {"tier": "gold"}


def test_toml_invalid_allowlist_type_fails_loud(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="source_ip_allowlist.*array of strings"):
        _load(
            tmp_path,
            """
            [[inbound]]
            name = "IB"
            transport = "mllp"
            router = "r"
            source_ip_allowlist = "127.0.0.1"
              [inbound.settings]
              port = 2575
            """,
        )


def test_toml_invalid_metadata_type_fails_loud(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="metadata.*must be a table"):
        _load(
            tmp_path,
            """
            [[inbound]]
            name = "IB"
            transport = "mllp"
            router = "r"
            metadata = "not-a-table"
              [inbound.settings]
              port = 2575
            """,
        )


# --- end-to-end: accept-time rejection on the listen sources -----------------


async def test_mllp_source_refuses_non_allowlisted_peer() -> None:
    handled: list[bytes] = []

    async def handler(raw: bytes) -> str:
        handled.append(raw)
        return build_ack(raw, code="AA")

    src = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0, "source_ip_allowlist": ["10.0.0.1"]},
        )
    )
    await src.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
        writer.write(frame(MSG))
        await writer.drain()
        await _refused(reader)
        writer.close()
    finally:
        await src.stop()
    assert handled == []  # loopback peer not in the allowlist -> never delivered


async def test_mllp_source_accepts_allowlisted_peer() -> None:
    handled: list[bytes] = []

    async def handler(raw: bytes) -> str:
        handled.append(raw)
        return build_ack(raw, code="AA")

    src = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0, "source_ip_allowlist": ["127.0.0.1"]},
        )
    )
    await src.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
        writer.write(frame(MSG))
        await writer.drain()
        assert await asyncio.wait_for(reader.read(100), 2.0)  # got an ACK frame, not EOF
        writer.close()
    finally:
        await src.stop()
    assert handled == [MSG.encode()]


async def test_tcp_source_refuses_non_allowlisted_peer() -> None:
    handled: list[bytes] = []

    async def handler(raw: bytes) -> None:
        handled.append(raw)

    src = TcpSource(
        Source(
            type=ConnectorType.TCP,
            settings={
                "host": "127.0.0.1",
                "port": 0,
                "framing": "stx_etx",
                "source_ip_allowlist": ["10.0.0.1"],
            },
        )
    )
    await src.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
        writer.write(STX_ETX_CODEC.frame("HELLO"))
        await writer.drain()
        await _refused(reader)
        writer.close()
    finally:
        await src.stop()
    assert handled == []


async def test_tcp_source_accepts_allowlisted_peer() -> None:
    handled: list[bytes] = []

    async def handler(raw: bytes) -> None:
        handled.append(raw)

    src = TcpSource(
        Source(
            type=ConnectorType.TCP,
            settings={
                "host": "127.0.0.1",
                "port": 0,
                "framing": "stx_etx",
                "source_ip_allowlist": ["127.0.0.1"],
            },
        )
    )
    await src.start(handler)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
        writer.write(STX_ETX_CODEC.frame("HELLO"))
        await writer.drain()
        await _until(lambda: bool(handled))
        writer.close()
    finally:
        await src.stop()
    assert handled == [b"HELLO"]


# --- helpers -----------------------------------------------------------------


async def _refused(reader: asyncio.StreamReader) -> None:
    """A refused connection is closed from the server side. That surfaces as a clean EOF, or — on
    Windows, when the client already wrote bytes the server never read — a connection reset. Either
    confirms the peer was not accepted."""
    try:
        assert await asyncio.wait_for(reader.read(), 2.0) == b""
    except (ConnectionResetError, ConnectionAbortedError):
        pass


async def _until(cond, timeout: float = 2.0) -> None:
    elapsed = 0.0
    while not cond():
        await asyncio.sleep(0.01)
        elapsed += 0.01
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")
