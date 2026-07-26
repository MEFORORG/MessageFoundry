# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection metadata + reachability-test API (operability Tier 4, PR C).

Covers the per-connector ``test_connection()`` probes (socket connect, dir writability, the
not-supported default for listen sources / timer), the ``redacted_settings`` secret scrub, and the
``GET /connections/{name}/metadata`` + ``POST /connections/{name}/test`` endpoints (reachable /
unreachable / not-supported / 404 / audit)."""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import urllib.error
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

import messagefoundry
from messagefoundry.api import create_app
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    _is_secret_setting,
    display_settings,
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


def test_redacted_settings_scrubs_every_secret_key_and_header_exhaustively() -> None:
    """Iterate the actual frozensets: every listed secret key/header is scrubbed, and not one sentinel
    survives anywhere in the serialized output.

    NOTE this proves the frozensets are *applied* — it cannot prove they are *complete*, because it
    derives its own sentinels from them. That gap is what
    :func:`test_every_credential_shaped_factory_param_is_classified` closes; the two are a pair."""
    from messagefoundry.config.wiring import _SECRET_HEADER_NAMES, _SECRET_SETTING_KEYS

    # A unique plaintext sentinel per secret setting key + per secret header. If any leaks, the
    # substring scan below catches it regardless of which key it leaked through.
    settings: dict[str, object] = {k: f"SEKRET-{k}" for k in _SECRET_SETTING_KEYS}
    settings["url"] = "https://benign.example"  # a non-secret carried through verbatim
    headers: dict[str, str] = {}
    for i, h in enumerate(_SECRET_HEADER_NAMES):
        # Alternate case per header to prove the case-insensitive compare (guard lowercases k).
        cased = h.upper() if i % 2 == 0 else h.title()
        headers[cased] = f"HDRSEKRET-{h}"
    headers["X-Trace"] = "benign-ok"  # a benign header must survive untouched
    settings["headers"] = headers

    out = redacted_settings(settings)

    # Every secret setting key is replaced with the redaction token.
    for k in _SECRET_SETTING_KEYS:
        assert out[k] == "***", f"secret setting {k!r} was not redacted"
    # Every secret header (whatever its casing) is redacted; the benign one is untouched.
    for i, h in enumerate(_SECRET_HEADER_NAMES):
        cased = h.upper() if i % 2 == 0 else h.title()
        assert out["headers"][cased] == "***", f"secret header {cased!r} was not redacted"
    assert out["headers"]["X-Trace"] == "benign-ok"
    assert out["url"] == "https://benign.example"

    # Strong negative: NOT ONE sentinel substring may appear anywhere in the serialized output.
    serialized = json.dumps(out)
    for k in _SECRET_SETTING_KEYS:
        assert f"SEKRET-{k}" not in serialized, f"plaintext for {k!r} leaked into metadata"
    for h in _SECRET_HEADER_NAMES:
        assert f"HDRSEKRET-{h}" not in serialized, f"header plaintext for {h!r} leaked"


# --- the secret-key set is COMPLETE, not merely applied ----------------------

#: A settings key whose *name* trips the credential scan below but which carries no credential. Each
#: entry states why. A path to a key is not the key; the ODBC keyword a password is emitted *under*
#: is not the password. Adding to this list is a deliberate act, and the tests below keep it honest.
_NOT_A_SECRET: dict[str, str] = {
    "tls_key_file": "filesystem path to the TLS key — not the key material",
    "client_key_file": "filesystem path to the mTLS client key — not the key material",
    "signing_key": "filesystem path to the Direct S/MIME signing key — not the key material",
    "ws_password_type": "WS-Security password *mode*: 'text' | 'digest'",
    "odbc_user_key": "the ODBC keyword the username is emitted under (e.g. 'UID')",
    "odbc_password_key": "the ODBC keyword the password is emitted under (e.g. 'PWD')",
    # This IS secret-carrying, but the Soap() factory desugars it into flat body_secret_value_<i>
    # settings (ADR 0015 amendment, #236); the param name itself never becomes a settings key, and the
    # hoisted body_secret_value_* keys ARE redacted (via _is_secret_setting's prefix match).
    "body_secrets": "desugared to body_secret_value_<i> keys, which are the redacted secrets",
    # ADR 0132 (#111) — the File alt-credential AD domain name (e.g. 'CORP'), not a secret. The paired
    # credential_username + credential_password ARE redacted (in _SECRET_SETTING_KEYS).
    "credential_domain": "an AD domain name (e.g. 'CORP'), not a secret",
}

#: Names that look like a credential. Deliberately broad — a false positive costs one line in
#: ``_NOT_A_SECRET``; a false negative costs a plaintext credential on a Role.VIEWER-readable route.
_CREDENTIAL_SHAPED = re.compile(r"pass|secret|token|credential|key|user", re.IGNORECASE)


def _connection_factories() -> list[tuple[str, Callable[..., Any]]]:
    """Every public connector factory, discovered by its ``ConnectionSpec`` return annotation — so a
    NEW connector is scanned automatically, rather than relying on someone remembering to add it."""
    out: list[tuple[str, Callable[..., Any]]] = []
    for name in sorted(messagefoundry.__all__):
        factory = getattr(messagefoundry, name)
        if not callable(factory):
            continue
        try:
            returns = inspect.signature(factory).return_annotation
        except (TypeError, ValueError):  # not introspectable — not a factory
            continue
        if "ConnectionSpec" in str(returns):
            out.append((name, factory))
    return out


def test_every_credential_shaped_factory_param_is_classified() -> None:
    """The completeness half of the pair — and the guard that was missing.

    Its predecessor built its sentinels *from* ``_SECRET_SETTING_KEYS``, so a credential setting that
    was never added to the frozenset could not fail it. Four did exactly that — ``ws_password``,
    ``ws_username``, ``client_key_password`` (ADR 0015) and ``signing_key_password`` (ADR 0085) — and
    were served in plaintext by ``GET /connections/{name}/metadata`` to ``Role.VIEWER``, the
    lowest-privilege authenticated role, past green CI.

    So this one reads the *connector factories* instead: every parameter whose NAME looks like a
    credential must be either redacted or explicitly, and reasonedly, declared not-a-secret. It cannot
    pass by construction — a new connector with a ``password=`` parameter fails it until classified."""
    factories = _connection_factories()
    assert len(factories) >= 15, "factory discovery broke — the scan below would pass vacuously"

    scanned = 0
    unclassified: list[str] = []
    for fname, factory in factories:
        for param in inspect.signature(factory).parameters:
            if not _CREDENTIAL_SHAPED.search(param):
                continue
            scanned += 1
            if not _is_secret_setting(param) and param not in _NOT_A_SECRET:
                unclassified.append(f"{fname}({param}=...)")

    assert scanned >= 20, (
        "the credential scan matched almost nothing — discovery or the regex broke"
    )
    assert not unclassified, (
        "credential-shaped connector settings are neither redacted nor declared not-a-secret, so an "
        "inline value would be served in plaintext by GET /connections/{name}/metadata and printed by "
        "`graph --json`: " + ", ".join(sorted(unclassified))
    )


def test_not_a_secret_allowlist_does_not_rot() -> None:
    """The allow-list is load-bearing, so it must not decay: every entry must still be a real
    parameter of some connector, and none may name a key that IS redacted (the two lists must never
    contradict each other)."""
    params = {p for _, f in _connection_factories() for p in inspect.signature(f).parameters}
    for name in _NOT_A_SECRET:
        assert name in params, f"_NOT_A_SECRET names {name!r}, which no connector factory takes"
        assert not _is_secret_setting(name), f"{name!r} is both redacted AND declared not-a-secret"


def test_ws_security_and_direct_credentials_are_redacted() -> None:
    """The specific disclosure these fixes close. A mode ('digest') and a path must survive — proving
    the fix redacts the credential, not merely everything whose name contains 'key'."""
    out = redacted_settings(
        {
            "ws_username": "iis-svc-acct",
            "ws_password": "SEKRET-WS-PW",
            "client_key_password": "SEKRET-KEYPASS",
            "signing_key_password": "SEKRET-SIGNPASS",
            "ws_password_type": "digest",
            "client_key_file": "/etc/mf/client.key",
        }
    )
    assert out["ws_username"] == "***"
    assert out["ws_password"] == "***"
    assert out["client_key_password"] == "***"
    assert out["signing_key_password"] == "***"
    assert out["ws_password_type"] == "digest"  # a mode, not a credential
    assert out["client_key_file"] == "/etc/mf/client.key"  # a path, not the key
    assert "SEKRET" not in json.dumps(out)


def test_display_settings_scrubs_secrets_and_fallback_secrets() -> None:
    """``display_settings`` feeds ``messagefoundry graph --json`` → stdout, CI logs and the IDE graph
    view, and it used to apply NO secret check at all: an inline credential was printed verbatim and
    an ``env()`` *fallback* secret was printed alongside its key. It now scrubs exactly as the API
    ``/metadata`` view does — the two serializers must never disagree about what a secret is."""
    out = display_settings(
        {
            "host": "registry.example",
            "ws_password": "SEKRET-INLINE",
            "bearer_token": env("tok", default="SEKRET-FALLBACK"),
            "url": env("registry_url", default="https://x"),
        }
    )
    assert out["host"] == "registry.example"
    assert out["ws_password"] == "***"
    assert out["bearer_token"] == {"env": "tok"}  # the fallback secret is suppressed
    assert out["url"] == {"env": "registry_url", "default": "https://x"}  # non-secret keeps it
    assert "SEKRET" not in json.dumps(out)


def test_redacted_settings_drops_env_default_for_a_credential_field() -> None:
    """Negative for wiring.py:639 — an ``env()`` *default* on a credential field is suppressed so a
    fallback secret can never leak, while a non-secret field keeps its default."""
    import json

    out = redacted_settings(
        {
            # A secret env ref WITH a default: the default is a fallback credential and must be dropped.
            "password": env("db_pw", default="FALLBACK-SEKRET"),
            # Contrast: a non-secret env ref retains its default.
            "url": env("epic_url", default="https://fallback.example"),
        }
    )

    # The credential env ref shows the key only — no "default" key at all.
    assert out["password"] == {"env": "db_pw"}
    assert "default" not in out["password"]
    # The non-secret env ref keeps its default.
    assert out["url"] == {"env": "epic_url", "default": "https://fallback.example"}
    # The fallback secret must not survive anywhere in the serialized output.
    assert "FALLBACK-SEKRET" not in json.dumps(out)


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


async def test_post_test_not_deployed_outbound_short_circuits(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    """A not-deployed outbound (#233, ADR 0111) must not be probed: the guard short-circuits before
    ``build_test_connector`` would resolve ``env()`` / build a connector / dial the peer.

    The outbound's ``host`` is an ``env()`` ref that is ABSENT from the (empty) test environment. WITHOUT
    the guard, ``build_test_connector`` -> ``resolve_env_settings`` raises ``WiringError``, which the route
    reports as ``supported=True`` with the env error in ``detail``. So ``supported is False`` here can only
    mean the short-circuit ran first — i.e. ``env()`` was never resolved. This assertion fails if the guard
    is removed."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection("IB_MLLP", ConnectionSpec(ConnectorType.MLLP, {"port": 2575}), router="r")
    )
    reg.add_outbound(
        OutboundConnection(
            "OB_ND",
            ConnectionSpec(ConnectorType.MLLP, {"host": env("nd_host"), "port": 6000}),
            deployed=False,
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_ND", m))
    engine.add_registry(reg)

    r = await client.post("/connections/OB_ND/test")
    assert r.status_code == 200
    body = r.json()
    assert body["supported"] is False  # nothing to probe — NOT "probed and failed"
    assert body["success"] is False
    assert body["direction"] == "out"
    assert "not deployed" in body["detail"]


async def test_post_test_not_deployed_inbound_reports_not_deployed(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    """A live listen-source probe is "not supported" even when deployed, so ``supported=False`` alone does
    not distinguish not-deployed from not-supported — the ``detail`` does. The guard must still fire (and
    skip ``env()`` resolution) for a not-deployed inbound whose ``port`` is an absent ``env()`` ref."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_ND",
            ConnectionSpec(ConnectorType.MLLP, {"port": env("nd_port")}),
            router="r",
            deployed=False,
        )
    )
    reg.add_outbound(
        OutboundConnection("OB", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB", m))
    engine.add_registry(reg)

    body = (await client.post("/connections/IB_ND/test")).json()
    assert body["supported"] is False
    assert "not deployed" in body["detail"]
