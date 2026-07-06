# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection metadata + reachability-test API (operability Tier 4, PR C).

Covers the per-connector ``test_connection()`` probes (socket connect, dir writability, the
not-supported default for listen sources / timer), the ``redacted_settings`` secret scrub, and the
``GET /connections/{name}/metadata`` + ``POST /connections/{name}/test`` endpoints (reachable /
unreachable / not-supported / 404 / audit)."""

from __future__ import annotations

import asyncio
import urllib.error
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    env,
    redacted_settings,
)
from messagefoundry.pipeline import Engine
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports.base import (
    DeliveryError,
    TestNotSupportedError,
    probe_tcp_reachable,
)
from messagefoundry.transports.mllp import MLLPSource
from messagefoundry.transports.rest import RestDestination
from messagefoundry.transports.soap import SoapDestination
from messagefoundry.transports.tcp import TcpSource


# --- a throwaway loopback TCP server to probe against -------------------------


async def _listening_port() -> tuple[asyncio.AbstractServer, int]:
    async def _accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(_accept, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _dead_port() -> int:
    """A port nothing listens on: bind one, read its number, close it."""
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    return port


# --- probe_tcp_reachable + socket-destination test_connection ----------------


async def test_probe_tcp_reachable_connects() -> None:
    server, port = await _listening_port()
    try:
        await probe_tcp_reachable("127.0.0.1", port, 5.0, "TEST")  # no raise = reachable
    finally:
        server.close()
        await server.wait_closed()


async def test_probe_tcp_reachable_refused() -> None:
    port = await _dead_port()
    with pytest.raises(DeliveryError, match="connect to"):
        await probe_tcp_reachable("127.0.0.1", port, 5.0, "TEST")


@pytest.mark.parametrize("conn_type", [ConnectorType.MLLP, ConnectorType.TCP, ConnectorType.X12])
async def test_socket_destination_test_connection(conn_type: ConnectorType) -> None:
    server, port = await _listening_port()
    settings = {"host": "127.0.0.1", "port": port, "connect_timeout": 5.0}
    if conn_type is ConnectorType.TCP:
        settings["framing"] = "stx_etx"
    dest = build_destination(Destination(name="OB", type=conn_type, settings=settings))
    try:
        await dest.test_connection()  # reachable → no raise
    finally:
        server.close()
        await server.wait_closed()
    # ...and a dead port fails closed.
    dead = await _dead_port()
    bad = {**settings, "port": dead}
    dest2 = build_destination(Destination(name="OB", type=conn_type, settings=bad))
    with pytest.raises(DeliveryError):
        await dest2.test_connection()


# --- file connectors ---------------------------------------------------------


async def test_file_connectors_test_connection_writable(tmp_path: Path) -> None:
    d = tmp_path / "out"
    dest = build_destination(
        Destination(name="OB", type=ConnectorType.FILE, settings={"directory": str(d)})
    )
    await dest.test_connection()  # creates the dir + probes a write
    assert d.is_dir()
    src = build_source(
        Source(type=ConnectorType.FILE, settings={"directory": str(tmp_path / "in")})
    )
    await src.test_connection()


async def test_file_destination_test_connection_unwritable(tmp_path: Path) -> None:
    # A path whose parent is a regular file can't be created → the probe fails closed.
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    dest = build_destination(
        Destination(
            name="OB", type=ConnectorType.FILE, settings={"directory": str(blocker / "sub")}
        )
    )
    with pytest.raises(DeliveryError, match="not writable"):
        await dest.test_connection()


# --- not-supported default (listen sources + timer + base) -------------------


async def test_listen_sources_test_connection_not_supported() -> None:
    mllp = MLLPSource(Source(type=ConnectorType.MLLP, settings={"port": 0}))
    tcp = TcpSource(Source(type=ConnectorType.TCP, settings={"port": 0, "framing": "stx_etx"}))
    timer = build_source(Source(type=ConnectorType.TIMER, settings={"body": "x", "run_once": True}))
    for src in (mllp, tcp, timer):
        with pytest.raises(TestNotSupportedError):
            await src.test_connection()


# --- redacted_settings -------------------------------------------------------


def test_redacted_settings_scrubs_secrets_and_env_refs() -> None:
    out = redacted_settings(
        {
            "host": "epic.example",
            "port": 2575,
            "password": "hunter2",  # inline credential → redacted
            "username": "svc-acct",  # DB user (PII / privileged identity) → redacted
            "private_key": "-----BEGIN KEY-----",  # SFTP key material → redacted
            "bearer_token": env("tok"),  # secret env ref → key only, no default
            "url": env("epic_url", default="https://x"),  # non-secret env ref → key + default
            "headers": {"Authorization": "Bearer abc", "X-Trace": "ok"},  # nested credential header
        }
    )
    assert out["host"] == "epic.example"
    assert out["port"] == 2575
    assert out["password"] == "***"
    assert out["username"] == "***"
    assert out["private_key"] == "***"
    assert out["bearer_token"] == {"env": "tok"}
    assert out["url"] == {"env": "epic_url", "default": "https://x"}
    assert out["headers"] == {"Authorization": "***", "X-Trace": "ok"}  # only the credential header


# --- REST/SOAP probe: auth failure vs reachable ------------------------------


class _RaisingOpener:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def open(self, req: object, timeout: float | None = None) -> object:
        raise self._exc


def _http_dest(cls: type, exc: Exception):
    ctype = ConnectorType.REST if cls is RestDestination else ConnectorType.SOAP
    dest = cls(Destination(name="OB", type=ctype, settings={"url": "https://x.example/api"}))
    dest._opener = _RaisingOpener(exc)  # type: ignore[attr-defined]
    return dest


@pytest.mark.parametrize("cls", [RestDestination, SoapDestination])
@pytest.mark.parametrize(
    ("code", "should_fail"), [(401, True), (403, True), (404, False), (405, False)]
)
async def test_http_probe_auth_failure_vs_reachable(
    cls: type, code: int, should_fail: bool
) -> None:
    dest = _http_dest(cls, urllib.error.HTTPError("https://x.example/api", code, "x", {}, None))  # type: ignore[arg-type]
    if should_fail:
        with pytest.raises(DeliveryError, match="check credentials"):
            await dest.test_connection()
    else:
        await dest.test_connection()  # host answered (e.g. 405 on HEAD) → reachable


@pytest.mark.parametrize("cls", [RestDestination, SoapDestination])
async def test_http_probe_unreachable(cls: type) -> None:
    dest = _http_dest(cls, urllib.error.URLError("connection refused"))
    with pytest.raises(DeliveryError, match="unreachable"):
        await dest.test_connection()


# --- API: fixtures -----------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path):
    eng = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine):
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


def _registry(*, outbound_port: int | None = None, out_dir: str | None = None) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_MLLP",
            ConnectionSpec(ConnectorType.MLLP, {"port": 2575}),
            router="r",
            metadata={"owner": "team-x", "runbook": "https://wiki/rb"},
        )
    )
    if outbound_port is not None:
        spec = ConnectionSpec(
            ConnectorType.MLLP, {"host": "127.0.0.1", "port": outbound_port, "connect_timeout": 5.0}
        )
    else:
        spec = ConnectionSpec(ConnectorType.FILE, {"directory": out_dir or "./out"})
    reg.add_outbound(OutboundConnection("OB", spec, metadata={"tier": "gold"}))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB", m))
    return reg


# --- API: metadata -----------------------------------------------------------


async def test_metadata_inbound(engine: Engine, client: httpx.AsyncClient, tmp_path: Path) -> None:
    engine.add_registry(_registry(out_dir=str(tmp_path / "out")))
    r = await client.get("/connections/IB_MLLP/metadata")
    assert r.status_code == 200
    body = r.json()
    assert body["direction"] == "in"
    assert body["method"] == "mllp"
    assert body["router"] == "r"
    assert body["metadata"] == {"owner": "team-x", "runbook": "https://wiki/rb"}
    assert body["settings"]["port"] == 2575


async def test_metadata_outbound(engine: Engine, client: httpx.AsyncClient, tmp_path: Path) -> None:
    engine.add_registry(_registry(out_dir=str(tmp_path / "out")))
    r = await client.get("/connections/OB/metadata")
    assert r.status_code == 200
    body = r.json()
    assert body["direction"] == "out"
    assert body["metadata"] == {"tier": "gold"}
    assert (
        body["simulated"] is False
    )  # not a shadow lane (baseline; keeps the True case non-vacuous)


async def test_metadata_outbound_simulated(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # A simulate=True outbound is surfaced as simulated in the metadata API (#15).
    reg = Registry()
    reg.add_inbound(
        InboundConnection("IB_MLLP", ConnectionSpec(ConnectorType.MLLP, {"port": 2575}), router="r")
    )
    reg.add_outbound(
        OutboundConnection(
            "OB_SIM",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "out")}),
            simulate=True,
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_SIM", m))
    engine.add_registry(reg)
    body = (await client.get("/connections/OB_SIM/metadata")).json()
    assert body["direction"] == "out"
    assert body["simulated"] is True


async def test_metadata_404(engine: Engine, client: httpx.AsyncClient, tmp_path: Path) -> None:
    engine.add_registry(_registry(out_dir=str(tmp_path / "out")))
    assert (await client.get("/connections/nope/metadata")).status_code == 404


async def test_metadata_redacts_env_secret(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "OB_REST",
            ConnectionSpec(
                ConnectorType.REST, {"url": "https://x.example/api", "bearer_token": env("tok")}
            ),
        )
    )
    engine.add_registry(reg)
    body = (await client.get("/connections/OB_REST/metadata")).json()
    assert body["settings"]["bearer_token"] == {"env": "tok"}  # never the resolved value


# --- API: test ---------------------------------------------------------------


async def test_post_test_outbound_reachable(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    server, port = await _listening_port()
    try:
        engine.add_registry(_registry(outbound_port=port))
        r = await client.post("/connections/OB/test")
        assert r.status_code == 200
        body = r.json()
        assert body["supported"] is True
        assert body["success"] is True
        assert body["direction"] == "out"
    finally:
        server.close()
        await server.wait_closed()


async def test_post_test_outbound_unreachable(engine: Engine, client: httpx.AsyncClient) -> None:
    port = await _dead_port()
    engine.add_registry(_registry(outbound_port=port))
    body = (await client.post("/connections/OB/test")).json()
    assert body["supported"] is True
    assert body["success"] is False
    assert body["detail"]  # carries the connect failure


async def test_post_test_listen_source_not_supported(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    engine.add_registry(_registry(out_dir=str(tmp_path / "out")))
    body = (await client.post("/connections/IB_MLLP/test")).json()
    assert body["supported"] is False
    assert body["success"] is False


async def test_post_test_404(engine: Engine, client: httpx.AsyncClient, tmp_path: Path) -> None:
    engine.add_registry(_registry(out_dir=str(tmp_path / "out")))
    assert (await client.post("/connections/nope/test")).status_code == 404


async def test_post_test_is_audited(
    engine: Engine, client: httpx.AsyncClient, tmp_path: Path
) -> None:
    engine.add_registry(_registry(out_dir=str(tmp_path / "out")))
    await client.post("/connections/IB_MLLP/test")
    rows = await engine.store.list_audit(limit=20)
    assert any(row["action"] == "connection_test" for row in rows)
