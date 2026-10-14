# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``FhirLookup`` refused at start is isolated like a lane (vault BACKLOG #3008).

``serve`` adds the registry and starts the runner with no ``build_check`` in between, so on a first
load the live builders are where a posture refusal fires. Before #3008 the two kinds did not behave
alike (measured for #2193):

* an **outbound** is built inside ``_start_outbound``, which isolates a failure to that one lane
  (ADR 0031). The lane is recorded failed and the rest of the graph starts;
* the **lookup executor** was built once for the whole graph, outside that isolation, so a refused
  lookup reached the start's backstop, which unwound everything and re-raised.

Owner ruling R3 of 2026-10-05 chose "Isolate it like a lane": a refused lookup is recorded failed,
the Handlers that use it fail closed, and the other feeds start. It applies on **every** start, not
only the first, matching how a lane is isolated. That scope is a Manager decision under the owner's
standing driver rules, 2026-10-11, not an owner ruling.

How each kind of start treats a refused lookup, matched to a lane:

* a first start and a restart run ``RegistryRunner.start()``: the lookup is isolated, as a lane is;
* a clustered node runs the same ``start()`` from its graph supervisor on promotion, so it reads the
  same. Before #3008 the supervisor caught the refusal, logged "will retry" and never ran the graph;
* a reload build-checks the whole new graph first, so a lookup still refused refuses the reload and
  leaves the running graph alone, as a lane still refused does. A reload whose lookup now builds
  brings it back, as a reload heals a failed lane. So does a restart once the cause is fixed.

Nothing here dials. Construction reads settings only, the keys are synthetic, and the ``dials``
fixture fails any HTTP connection attempt and records it. The attested control shows the instrument
fires.
"""

from __future__ import annotations

import asyncio
import http.client
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from messagefoundry.config.fhir_lookup import FhirLookupError, fhir_lookup
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import TLS_REVOCATION_ATTESTED_ENV, HopPosture
from messagefoundry.config.wiring import (
    ConnectionSpec,
    FhirLookupSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    WiringError,
    build_outbound_connection,
)
from messagefoundry.parsing import Message, RawMessage
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.cluster import NullCoordinator
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore

ENFORCING = HopPosture(enforcing=True)
REMOTE = "10.0.0.5"  # non-loopback, never dialled
LOOPBACK = "127.0.0.1"
ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture(autouse=True)
def _no_blanket_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)


@pytest.fixture(autouse=True)
def dials(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Every HTTP(S) connection attempt, refused before a socket opens. Each test asserts the list
    is empty, except the control that shows a real read attempt lands here."""
    seen: list[str] = []

    def refuse(self: http.client.HTTPConnection) -> None:
        seen.append(f"{self.host}:{self.port}")
        raise OSError("dial refused by the test")

    monkeypatch.setattr(http.client.HTTPConnection, "connect", refuse)
    yield seen


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "first_start.db")
    yield s
    await s.close()


@pytest.fixture(scope="module")
def smart_key() -> str:
    """An EC private key PEM for the SMART signer. Synthetic, never leaves the process."""
    return (
        ec.generate_private_key(ec.SECP384R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


class _Alerts(LoggingAlertSink):
    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))


def _file_out(name: str, directory: Path) -> OutboundConnection:
    """A healthy outbound that starts in any posture: the control for 'the rest of the graph'."""
    return build_outbound_connection(
        name,
        ConnectionSpec(
            ConnectorType.FILE, {"directory": str(directory), "filename": "{MSH-10}.hl7"}
        ),
    )


def _unattested_lookup() -> FhirLookupSpec:
    return FhirLookupSpec("epic", {"url": f"https://{REMOTE}/fhir"})


def _attested_lookup() -> FhirLookupSpec:
    return FhirLookupSpec(
        "epic",
        {"url": f"https://{REMOTE}/fhir"},
        tls_revocation_attested=True,
        tls_revocation_attested_reason="partner PKI runs OCSP at the site edge",
    )


def _runner(
    registry: Registry, store: MessageStore, alerts: _Alerts | None = None
) -> RegistryRunner:
    return RegistryRunner(
        registry,
        store,
        poll_interval=0.02,
        env_values={},
        egress=EgressSettings(deny_by_default=False),
        hop_posture=ENFORCING,
        alert_sink=alerts,
    )


def _assert_lookup_isolated(runner: RegistryRunner, match: str) -> None:
    assert runner.running
    reason = runner.fhir_lookup_failed("epic")
    assert reason is not None and match in reason
    assert runner.degraded_fhir_lookups() == {"epic": reason}
    # The executor still exists, so fhir_lookup() stays activated and refuses rather than reading
    # as "no lookup is declared", and the ADR 0057 inline path stays off for the graph.
    assert runner._fhir_lookup_executor is not None


async def test_an_unattested_fhir_lookup_read_hop_is_isolated_and_the_start_continues(
    store: MessageStore, tmp_path: Path, dials: list[str]
) -> None:
    registry = Registry()
    registry.add_outbound(_file_out("OB_FILE", tmp_path))
    registry.add_fhir_lookup(_unattested_lookup())
    alerts = _Alerts()
    runner = _runner(registry, store, alerts)
    await runner.start()
    try:
        _assert_lookup_isolated(runner, "revocation")
        assert "OB_FILE" in runner._destinations  # the rest of the graph came up
        assert runner.outbound_failed("OB_FILE") is None
        # Recorded where an operator sees it: an alert addressed to the lookup's record name.
        assert [name for name, _ in alerts.stopped] == ["fhir_lookup:epic"]
        assert "failed to start" in alerts.stopped[0][1]
        with pytest.raises(FhirLookupError, match="failed to start and is isolated"):
            await runner._fhir_lookup_executor.read("epic", "Patient/1")  # type: ignore[union-attr]
    finally:
        await runner.stop()
    assert dials == []


async def test_an_unattested_smart_token_hop_on_a_lookup_is_isolated_the_same_way(
    store: MessageStore, tmp_path: Path, smart_key: str, dials: list[str]
) -> None:
    """The token-hop refusal that predates #2193 takes the same isolation. The read here is on
    loopback, so the read-hop guard crosses and the refusal can only be the token hop's."""
    registry = Registry()
    registry.add_outbound(_file_out("OB_FILE", tmp_path))
    registry.add_fhir_lookup(
        FhirLookupSpec(
            "epic",
            {
                "url": f"https://{LOOPBACK}:8443/fhir",
                "smart_token_url": f"https://{REMOTE}/token",
                "smart_client_id": "cid",
                "smart_private_key": smart_key,
                "smart_algorithm": "ES384",
            },
        )
    )
    runner = _runner(registry, store)
    await runner.start()
    try:
        _assert_lookup_isolated(runner, "token endpoint")
        assert "OB_FILE" in runner._destinations
    finally:
        await runner.stop()
    assert dials == []


def _file_in(name: str, inbox: Path, router: str) -> InboundConnection:
    inbox.mkdir(exist_ok=True)
    return InboundConnection(
        name,
        ConnectionSpec(
            ConnectorType.FILE,
            {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
        ),
        router=router,
    )


def _send_after_lookup(m: Message | RawMessage) -> Send:
    fhir_lookup("epic", "Patient/1")
    return Send("OB_A", m)


def _two_feeds(tmp_path: Path, lookup: FhirLookupSpec) -> Registry:
    """Feed A's Handler reads the lookup before it sends; feed B's never calls it."""
    reg = Registry()
    reg.add_outbound(_file_out("OB_A", tmp_path / "out_a"))
    reg.add_outbound(_file_out("OB_B", tmp_path / "out_b"))
    reg.add_inbound(_file_in("IB_A", tmp_path / "in_a", "r_a"))
    reg.add_inbound(_file_in("IB_B", tmp_path / "in_b", "r_b"))
    reg.add_router("r_a", lambda m: ["h_a"])
    reg.add_router("r_b", lambda m: ["h_b"])
    reg.add_handler("h_a", _send_after_lookup)
    reg.add_handler("h_b", lambda m: Send("OB_B", m))
    reg.add_fhir_lookup(lookup)
    return reg


async def _wait_status(store: MessageStore, channel: str, status: MessageStatus) -> dict[str, Any]:
    for _ in range(500):
        rows = await store.list_messages(
            channel_id=channel, status=status.value, allowed_channels=None
        )
        if rows:
            return rows[0]
        await asyncio.sleep(0.02)
    raise AssertionError(f"no {status.value} message on {channel!r} within the wait")


async def test_a_handler_calling_the_failed_lookup_fails_closed_and_the_other_feed_delivers(
    store: MessageStore, tmp_path: Path, dials: list[str]
) -> None:
    runner = _runner(_two_feeds(tmp_path, _unattested_lookup()), store)
    await runner.start()
    try:
        _assert_lookup_isolated(runner, "revocation")
        (tmp_path / "in_a" / "a.hl7").write_bytes(ADT.encode())
        (tmp_path / "in_b" / "b.hl7").write_bytes(ADT.encode())
        # The feed that never calls the lookup starts and delivers.
        await _wait_status(store, "IB_B", MessageStatus.PROCESSED)
        assert (tmp_path / "out_b" / "MSG1.hl7").exists()
        # The feed whose Handler needs the lookup takes the logged error path, and is never sent on
        # without it.
        await _wait_status(store, "IB_A", MessageStatus.ERROR)
        out_a = tmp_path / "out_a"
        assert not (out_a.exists() and any(out_a.iterdir()))
        assert not await store.list_messages(
            channel_id="IB_A", status=MessageStatus.PROCESSED.value, allowed_channels=None
        )
    finally:
        await runner.stop()
    assert dials == []


async def test_a_failed_lookup_comes_back_by_reload_or_restart_once_the_cause_is_fixed(
    store: MessageStore, tmp_path: Path, dials: list[str]
) -> None:
    alerts = _Alerts()
    runner = _runner(_two_feeds(tmp_path, _unattested_lookup()), store, alerts)
    await runner.start()
    try:
        _assert_lookup_isolated(runner, "revocation")
        # A reload whose lookup is still refused is refused whole, before anything changes, as a
        # reload whose lane is still refused is. The lookup stays failed.
        with pytest.raises(WiringError):
            await runner.reload(_two_feeds(tmp_path, _unattested_lookup()))
        _assert_lookup_isolated(runner, "revocation")
        # A reload with the cause fixed brings it back, as a reload heals a failed lane.
        await runner.reload(_two_feeds(tmp_path, _attested_lookup()))
        assert runner.fhir_lookup_failed("epic") is None
        assert runner.degraded_fhir_lookups() == {}
        # A restart on the refused config isolates it again, and alerts again, as a lane's would.
        await runner.stop()
        runner.registry = _two_feeds(tmp_path, _unattested_lookup())
        await runner.start()
        _assert_lookup_isolated(runner, "revocation")
        assert [name for name, _ in alerts.stopped] == ["fhir_lookup:epic"] * 2
        # A restart once the cause is fixed brings it back too.
        await runner.stop()
        runner.registry = _two_feeds(tmp_path, _attested_lookup())
        await runner.start()
        assert runner.running and runner.fhir_lookup_failed("epic") is None
    finally:
        await runner.stop()
    assert dials == []


async def test_the_lookup_alert_fires_after_the_record_and_a_stop_clears_it(
    store: MessageStore, tmp_path: Path, dials: list[str]
) -> None:
    """A sink that reads /status when the alert lands sees the lookup it names. Once the graph
    stops, the runner no longer names its failures, since teardown keeps the last executor."""
    runner: RegistryRunner

    class _Reading(_Alerts):
        def __init__(self) -> None:
            super().__init__()
            self.seen: list[dict[str, str]] = []

        def connection_stopped(self, name: str, *, detail: str) -> None:
            super().connection_stopped(name, detail=detail)
            self.seen.append(runner.degraded_fhir_lookups())

    alerts = _Reading()
    runner = _runner(_two_feeds(tmp_path, _unattested_lookup()), store, alerts)
    await runner.start()
    try:
        _assert_lookup_isolated(runner, "revocation")
        assert len(alerts.seen) == 1 and list(alerts.seen[0]) == ["epic"]
    finally:
        await runner.stop()
    assert runner.degraded_fhir_lookups() == {}
    assert runner.fhir_lookup_failed("epic") is None
    assert dials == []


async def test_a_start_that_unwinds_after_isolating_a_lookup_sends_no_lookup_alert(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    dials: list[str],
) -> None:
    """The lookup alert says the engine continues. A later graph-wide failure unwinds the start,
    so that alert would be false, and none is sent. The refusal is still logged, so a retry that
    unwinds again does not hide it."""
    alerts = _Alerts()
    runner = _runner(_two_feeds(tmp_path, _unattested_lookup()), store, alerts)

    def boom() -> None:
        raise RuntimeError("a later graph-wide start failure")

    monkeypatch.setattr(runner, "_recompute_inline_ok", boom)
    with caplog.at_level("ERROR"), pytest.raises(RuntimeError, match="later graph-wide"):
        await runner.start()
    assert not runner.running
    assert alerts.stopped == []
    assert any("fhir lookup 'epic' also failed to build" in r.getMessage() for r in caplog.records)
    assert runner.degraded_fhir_lookups() == {}
    assert dials == []


async def test_an_unattested_dicom_tls_outbound_costs_one_lane_and_the_start_continues(
    store: MessageStore, tmp_path: Path, dials: list[str]
) -> None:
    """The lane the lookup is now isolated like. The same refusal on an outbound: the lane is
    recorded failed and the healthy outbound beside it still comes up."""
    registry = Registry()
    registry.add_outbound(_file_out("OB_FILE", tmp_path))
    registry.add_outbound(
        build_outbound_connection(
            "OB_PACS",
            ConnectionSpec(
                ConnectorType.DIMSE,
                {"ae_title": "MF_SCU", "host": REMOTE, "port": 11112, "tls": True},
            ),
        )
    )
    runner = _runner(registry, store)
    await runner.start()
    try:
        assert runner.running
        reason = runner.outbound_failed("OB_PACS")
        assert reason is not None and "revocation" in reason
        assert "OB_PACS" not in runner._destinations  # never dialled: no connector was built
        assert runner.outbound_failed("OB_FILE") is None
        assert "OB_FILE" in runner._destinations
    finally:
        await runner.stop()
    assert dials == []


async def test_an_attested_fhir_lookup_starts_healthy_and_the_dial_instrument_fires(
    store: MessageStore, tmp_path: Path, dials: list[str]
) -> None:
    # CONTROL for the arms above: the same graph with the declaration starts with no failed lookup,
    # so their failure is the guard's refusal and not some other fault in building a lookup here.
    registry = Registry()
    registry.add_outbound(_file_out("OB_FILE", tmp_path))
    registry.add_fhir_lookup(_attested_lookup())
    runner = _runner(registry, store)
    await runner.start()
    try:
        assert runner.running
        assert runner.fhir_lookup_failed("epic") is None
        assert "OB_FILE" in runner._destinations
        assert dials == []
        # The instrument's positive control: a real read on the admitted lookup tries to connect,
        # and the fixture catches it. So an empty list in the arms above means nothing tried.
        with pytest.raises(FhirLookupError):
            await runner._fhir_lookup_executor.read("epic", "Patient/1")  # type: ignore[union-attr]
        assert dials == [f"{REMOTE}:443"]
    finally:
        await runner.stop()


class _Clustered(NullCoordinator):
    """A clustered coordinator whose leadership a test flips, as tests/test_cluster_graph_gating.py
    drives it."""

    def __init__(self, *, leader: bool) -> None:
        super().__init__(node_id="b3008")
        self.leader = leader

    def is_leader(self) -> bool:
        return self.leader

    def is_clustered(self) -> bool:
        return True


@pytest.mark.parametrize("clustered", [False, True], ids=["single-node", "clustered"])
async def test_an_engine_start_isolates_the_lookup_on_a_single_node_and_on_a_cluster_leader(
    tmp_path: Path, clustered: bool, dials: list[str]
) -> None:
    """Through ``Engine.start``. A single node starts the graph directly. A clustered node starts it
    from the graph supervisor on promotion, which before #3008 caught the refusal, logged "will
    retry" and never ran the graph. Both now start it with the lookup isolated, and a clustered
    node does so again on each re-promotion."""
    registry = Registry()
    registry.add_outbound(_file_out("OB_FILE", tmp_path / "out"))
    registry.add_fhir_lookup(_unattested_lookup())
    coord = _Clustered(leader=True) if clustered else None
    eng = await Engine.create(
        tmp_path / "engine.db",
        poll_interval=0.05,
        coordinator=coord,
        egress_settings=EgressSettings(deny_by_default=False),
        hop_posture=ENFORCING,
    )
    eng.add_registry(registry)
    try:
        # Inside the try: a start that raised would otherwise leave the engine's tasks running.
        await eng.start()
        runner = eng._registry_runner
        assert runner is not None
        _assert_lookup_isolated(runner, "revocation")
        assert "OB_FILE" in runner._destinations
        if coord is not None:
            coord.leader = False
            await eng._reconcile_graph()
            assert not runner.running
            coord.leader = True
            await eng._reconcile_graph()
            _assert_lookup_isolated(runner, "revocation")
    finally:
        await eng.stop()
    assert dials == []


async def test_status_names_the_failed_lookup(tmp_path: Path, dials: list[str]) -> None:
    """Where an operator sees it besides the log and the alert: ``/status`` names the isolated
    lookup, without its reason, to an estate-wide caller only."""
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.auth import Role
    from messagefoundry.auth.identity import ALL_CHANNELS
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.settings import AuthSettings
    from tests._admin_account import create_local_user_chosen

    registry = Registry()
    registry.add_outbound(_file_out("OB_FILE", tmp_path / "out"))
    registry.add_fhir_lookup(_unattested_lookup())
    eng = await Engine.create(
        tmp_path / "status.db",
        poll_interval=0.05,
        egress_settings=EgressSettings(deny_by_default=False),
        hop_posture=ENFORCING,
    )
    eng.add_registry(registry)
    pw = "a-strong-test-passphrase"
    try:
        service = AuthService(eng.store, AuthSettings(require_mfa=False))
        await service.initialize()
        # 'vw' sees the whole estate; 'narrow' is scoped to one channel, and a lookup belongs to none.
        for username, channels in (("vw", [ALL_CHANNELS]), ("narrow", ["IB_X"])):
            uid = await create_local_user_chosen(
                service,
                username=username,
                password=pw,
                display_name=None,
                email=None,
                roles=[Role.VIEWER.value],
                actor="test",
            )
            await service.set_channel_scope(uid, channels, actor="test")
            u = await service.store.get_user(uid)
            assert u is not None and u.password_hash is not None
            await service.store.set_password(
                uid,
                password_hash=u.password_hash,
                must_change_password=False,
                password_generated=False,
            )
        await eng.start()
        transport = httpx.ASGITransport(app=create_app(eng, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

            async def failed_lookups(username: str) -> object:
                r = await c.post(
                    "/auth/login", json={"username": username, "password": pw, "provider": "local"}
                )
                headers = {"Authorization": f"Bearer {r.json()['token']}"}
                return (await c.get("/status", headers=headers)).json()["engine"][
                    "fhir_lookups_failed"
                ]

            assert await failed_lookups("vw") == ["epic"]
            assert await failed_lookups("narrow") == []
    finally:
        await eng.stop()
    assert dials == []
