# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0031 — a connection that fails to build/bind at startup is ISOLATED, never fatal.

The engine starts the rest of the graph and serves the API; a failed outbound retries the rows
routed to it (never drops them) and self-heals on reload; a fully-valid graph is unaffected.
Complements the per-method coverage in test_wiring_engine.py (inbound bind isolation + the fatal
backstop) and test_response_capture.py (capture/backend isolation)."""

from __future__ import annotations

import asyncio
import logging
import socket
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.config.models import ConnectorType, RetryPolicy
from messagefoundry.config.wiring import (
    API_LISTENER_LABEL,
    MLLP,
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    build_inbound_connection,
    env,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, Stage

if TYPE_CHECKING:  # the API rig below imports these lazily, inside the tests that use them
    import httpx

    from messagefoundry.auth.service import AuthService

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "fault.db")
    yield s
    await s.close()


class _RecordingAlertSink:
    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []
        self.buildups: list[tuple[str, int, float]] = []
        self.errors: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        self.buildups.append((name, depth, oldest_age_seconds))

    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None:
        self.errors.append((name, kind))


async def _until(predicate, timeout: float = 10.0) -> None:  # type: ignore[no-untyped-def]
    elapsed = 0.0
    while not predicate():
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


async def _wait_pending(store: MessageStore, name: str, timeout: float = 10.0) -> int:
    elapsed = 0.0
    while True:
        depth, _ = await store.pending_depth(name, stage=Stage.OUTBOUND.value)
        if depth >= 1:
            return depth
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"no pending outbound row for {name!r} within timeout")


async def _wait_processed(store: MessageStore, channel_id: str, timeout: float = 10.0) -> None:
    # The finalizer flips a message to PROCESSED just AFTER the outbound delivery writes its file, so a
    # file-existence wait can win the race while the store has not finalized yet. Poll the store for the
    # asserted disposition instead of checking it the instant the file appears (slow-runner flake).
    elapsed = 0.0
    while not await store.list_messages(
        channel_id=channel_id, status=MessageStatus.PROCESSED.value
    ):
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"no PROCESSED message for channel {channel_id!r} within timeout")


def _file_inbound(inbox: Path, name: str = "file_in") -> InboundConnection:
    return InboundConnection(
        name,
        ConnectionSpec(
            ConnectorType.FILE,
            {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
        ),
        router="r",
    )


def _env_broken_outbound(
    name: str = "bad_out", *, retry: RetryPolicy | None = None, **settings: object
) -> OutboundConnection:
    """An outbound whose ``env()`` cannot resolve, so it fails to BUILD at start (the real-world
    unresolved-SOAP-cert shape). The ADR 0031 isolation fixture this file turns on."""
    return OutboundConnection(
        name,
        ConnectionSpec(ConnectorType.FILE, {"directory": env("out_dir"), **settings}),
        retry=retry,
    )


_VIEWER_PW = "a-strong-test-passphrase"


async def _provision_viewer(service: AuthService) -> None:
    """Create the viewer the two API tests below log in as, scoped to the whole estate."""
    from messagefoundry.auth import Role

    uid = await service.create_local_user(
        username="vw",
        password=_VIEWER_PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this fixture
    # still stands for an operator who has been provisioned; the channel axis itself is exercised in
    # tests/test_channel_rbac.py.
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    u = await service.store.get_user(uid)
    assert u is not None and u.password_hash is not None
    await service.store.set_password(uid, password_hash=u.password_hash, must_change_password=False)


async def _viewer_headers(client: httpx.AsyncClient) -> dict[str, str]:
    """Log the provisioned viewer in over the ASGI transport and return its bearer header."""
    r = await client.post(
        "/auth/login", json={"username": "vw", "password": _VIEWER_PW, "provider": "local"}
    )
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


async def test_duplicate_inbound_port_isolates_the_loser(store: MessageStore) -> None:
    # Two MLLP listeners declared on the SAME (host, port): the first binds, the second is refused
    # BEFORE its bind and ISOLATED with a clear reason (ADR 0031, low-13) — the engine stays up and the
    # first keeps listening, rather than a bare OSError aborting the inbound.
    port = _free_port()
    reg = Registry()
    reg.add_inbound(build_inbound_connection("a", MLLP(port=port), router="r"))
    reg.add_inbound(build_inbound_connection("b", MLLP(port=port), router="r"))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        assert runner.running
        assert set(runner.degraded_inbound()) == {"b"}  # 'a' bound first; 'b' is the loser
        assert "already bound by 'a'" in (runner.inbound_failed("b") or "")
        assert runner.inbound_running("a") and not runner.inbound_running("b")
    finally:
        await runner.stop()


async def test_inbound_on_reserved_api_port_isolated(store: MessageStore) -> None:
    # An inbound wired onto the engine's reserved API listener port is refused before the bind and
    # isolated (it would otherwise collide with uvicorn) — the engine still comes up DEGRADED.
    port = _free_port()
    reg = Registry()
    reg.add_inbound(build_inbound_connection("a", MLLP(port=port), router="r"))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        reserved_bindings=((API_LISTENER_LABEL, "127.0.0.1", port),),
    )
    await runner.start()
    try:
        assert runner.running
        assert "a" in runner.degraded_inbound()
        assert "reserved for" in (runner.inbound_failed("a") or "")
        assert not runner.inbound_running("a")
    finally:
        await runner.stop()


async def test_failed_outbound_isolated_retries_and_recovers(
    store: MessageStore, tmp_path: Path
) -> None:
    # An outbound whose env() can't resolve (the real-world SOAP-cert scenario) fails to build. ADR
    # 0031: the engine still starts, the lane is reported failed + alerted, a message routed to it is
    # RETRIED (never dropped), and a reload once the cause is fixed self-heals the lane.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(_file_inbound(inbox))
    # short backoff, so the stuck row redelivers fast once the lane recovers
    reg.add_outbound(
        _env_broken_outbound(retry=RetryPolicy(backoff_seconds=0.05), filename="{MSH-10}.hl7")
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("bad_out", m))
    sink = _RecordingAlertSink()
    runner = RegistryRunner(reg, store, poll_interval=0.02, alert_sink=sink, env_values={})
    await runner.start()
    try:
        # Engine is up despite the broken outbound.
        assert runner.running
        reason = runner.outbound_failed("bad_out")
        assert reason and "out_dir" in reason  # the unresolved env key is named in the reason
        assert "bad_out" not in runner._destinations  # no live connector
        assert sink.stopped and sink.stopped[0][0] == "bad_out"  # alerted at start

        # A message routed to the failed lane is retried (a pending outbound row), NOT delivered/dropped.
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _wait_pending(store, "bad_out")
        assert not (outdir.exists() and any(outdir.iterdir()))  # nothing written — never dropped
        assert not await store.list_messages(
            channel_id="file_in", status=MessageStatus.PROCESSED.value
        )  # the message is not finalized PROCESSED — it's stuck retrying, recoverable

        # Fix the cause (a concrete directory, no env) and reload → the lane self-heals.
        good = Registry()
        good.add_inbound(_file_inbound(inbox))
        good.add_outbound(
            OutboundConnection(
                "bad_out",
                ConnectionSpec(
                    ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
                ),
                retry=RetryPolicy(backoff_seconds=0.05),
            )
        )
        good.add_router("r", lambda m: ["h"])
        good.add_handler("h", lambda m: Send("bad_out", m))
        await runner.reload(good)
        assert runner.outbound_failed("bad_out") is None  # marker cleared
        assert not runner.degraded_inbound() and not runner.degraded_outbound()
        assert "bad_out" in runner._destinations  # connector built in place

        # The previously-stuck message now DELIVERS — proving the queued row was retried, not lost. The
        # store finalizes to PROCESSED just AFTER delivery writes the file, so poll the store for the
        # asserted disposition rather than checking it the instant the file appears (slow-runner race).
        await _until(lambda: (outdir / "MSG1.hl7").exists())
        await _wait_processed(
            store, "file_in"
        )  # finalized PROCESSED once the recovered lane delivered
    finally:
        await runner.stop()


def _file_inbound_validate(inbox: Path, *, validate: bool) -> InboundConnection:
    return InboundConnection(
        "file_in",
        ConnectionSpec(
            ConnectorType.FILE,
            {
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.02,
                "validate_directory": validate,
            },
        ),
        router="r",
    )


async def test_file_validate_directory_isolates_missing_dir(
    store: MessageStore, tmp_path: Path
) -> None:
    # #114 (ADR 0031 amendment): an inbound File source with validate_directory=true, pointed at a
    # MISSING directory, is reported `failed` at start (isolated) — the engine stays up, the source
    # never binds, and the probe never fabricates the dir. The opt-in fail-fast alternative to deferral.
    missing = tmp_path / "nope"
    reg = Registry()
    reg.add_inbound(_file_inbound_validate(missing, validate=True))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        assert runner.running  # isolated, not fatal
        assert "file_in" in runner.degraded_inbound()
        assert "SourceStartupError" in (runner.inbound_failed("file_in") or "")
        assert not runner.inbound_running("file_in")
        assert not missing.exists()  # the no-mkdir probe never created it
    finally:
        await runner.stop()


async def test_file_validate_directory_off_defers_missing_dir(
    store: MessageStore, tmp_path: Path
) -> None:
    # Default off: a missing directory does NOT fail startup — the source binds and defers to run time,
    # byte-identical to before #114 (start() creates the poll dir via its .processed/.error mkdir).
    missing = tmp_path / "nope"
    reg = Registry()
    reg.add_inbound(_file_inbound_validate(missing, validate=False))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        assert runner.running
        assert not runner.degraded_inbound() and not runner.degraded_outbound()
        assert runner.inbound_running("file_in")  # bound; validation deferred to run time
    finally:
        await runner.stop()


def _file_outbound_validate(outdir: Path, *, validate: bool) -> OutboundConnection:
    settings: dict[str, object] = {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
    if validate:
        settings["validate_directory"] = True
    return OutboundConnection(
        "file_out",
        ConnectionSpec(ConnectorType.FILE, settings),
        retry=RetryPolicy(backoff_seconds=0.05),
    )


async def test_file_outbound_validate_directory_isolates_missing_dir(
    store: MessageStore, tmp_path: Path
) -> None:
    # #114 remainder: an OUTBOUND File connection with validate_directory=true, pointed at a typo'd
    # (missing) directory, is REFUSED at start — the lane is reported `failed` with no live connector
    # while the engine stays up, and the directory is never fabricated. "Invalid means not-started" on
    # an outbound IS the ADR-0031 degraded-lane state: the delivery worker still runs, so a message
    # routed there is RETAINED pending and retried rather than delivered into an invented path.
    inbox, missing = tmp_path / "in", tmp_path / "typo"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(_file_inbound(inbox))
    reg.add_outbound(_file_outbound_validate(missing, validate=True))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    sink = _RecordingAlertSink()
    runner = RegistryRunner(reg, store, poll_interval=0.02, alert_sink=sink)
    await runner.start()
    try:
        assert runner.running  # isolated, not fatal
        assert "file_out" in runner.degraded_outbound()
        assert "DestinationStartupError" in (runner.outbound_failed("file_out") or "")
        assert "file_out" not in runner._destinations  # no live connector
        assert sink.stopped and sink.stopped[0][0] == "file_out"  # alerted at start
        assert not missing.exists()  # the no-mkdir probe never fabricated it
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _wait_pending(store, "file_out")  # retained + retried, never dropped
        assert not missing.exists()  # and nothing was written into an invented directory
    finally:
        await runner.stop()


async def test_file_outbound_validate_directory_off_defers_missing_dir(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The default, and the item's ACTUAL trigger: a target directory that is not there at start must NOT
    # fail startup. The lane comes up clean and the first delivery creates the directory — unchanged
    # behaviour — except that the creation now emits a WARNING naming the path, so it is
    # distinguishable from a normal delivery.
    inbox, outdir = tmp_path / "in", tmp_path / "late"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(_file_inbound(inbox))
    reg.add_outbound(_file_outbound_validate(outdir, validate=False))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.file"):
        await runner.start()
        try:
            assert (
                not runner.degraded_inbound() and not runner.degraded_outbound()
            )  # validation deferred — the lane is clean
            assert "file_out" in runner._destinations
            (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
            await _until(lambda: (outdir / "MSG1.hl7").exists())
            await _wait_processed(store, "file_in")
        finally:
            await runner.stop()
    assert "CREATED missing directory" in caplog.text


async def test_valid_graph_starts_without_degradation(store: MessageStore, tmp_path: Path) -> None:
    # Regression: a fully-valid graph is unaffected — no degraded connections, and it delivers.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(_file_inbound(inbox))
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        assert runner.running
        assert not runner.degraded_inbound() and not runner.degraded_outbound()
        assert runner.outbound_failed("file_out") is None
        (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))
        await _until(lambda: (outdir / "MSG1.hl7").exists())
    finally:
        await runner.stop()


async def test_connections_api_reports_degraded_outbound(tmp_path: Path) -> None:
    # The /connections dashboard surfaces a failed outbound that has no traffic edge yet (the
    # standalone-row path), with status "failed" + the reason — so a degraded lane is never hidden.
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.pipeline import Engine

    inbox = tmp_path / "in"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(_file_inbound(inbox))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(_env_broken_outbound())

    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    engine.add_registry(reg)
    try:
        service = AuthService(engine.store, AuthSettings(require_mfa=False))
        await service.initialize()
        await _provision_viewer(service)
        await engine.start()  # degraded — does NOT raise (ADR 0031)
        assert engine.registry_runner is not None
        assert "bad_out" in engine.registry_runner.degraded_outbound()

        transport = httpx.ASGITransport(app=create_app(engine, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            headers = await _viewer_headers(c)
            rows = (await c.get("/connections", headers=headers)).json()
        failed = [row for row in rows if row["status"] == "failed" and "bad_out" in row["name"]]
        assert failed, f"no failed bad_out row in {rows}"
        assert failed[0]["direction"] == "out"
        assert "out_dir" in (failed[0]["error"] or "")
    finally:
        await engine.stop()


async def test_same_name_inbound_and_outbound_do_not_alias_the_failure(
    store: MessageStore, tmp_path: Path
) -> None:
    # Registry._add enforces name uniqueness PER TABLE, so one name may legitimately be both an inbound
    # and an outbound (_dual_role_control already disambiguates the pair with role=). The ADR 0031
    # failure map must therefore key by DIRECTION. Keyed by bare name it aliased, and start() makes the
    # erasure the default case: every outbound is built BEFORE any inbound, so the inbound's
    # bound-successfully pop silently deleted its outbound namesake's real start failure and the engine
    # reported itself healthy. This is the regression guard for that erasure.
    inbox = tmp_path / "in"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(_file_inbound(inbox, "SHARED"))
    reg.add_outbound(_env_broken_outbound("SHARED"))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02, env_values={})
    await runner.start()
    try:
        assert runner.running
        # The inbound bound AFTER the outbound failed, and did not erase it.
        assert runner.inbound_running("SHARED")
        reason = runner.outbound_failed("SHARED")
        assert reason and "out_dir" in reason
        assert runner.degraded_outbound() == {"SHARED": reason}
        # And the inverse: the outbound's failure must not answer for the healthy inbound. This is the
        # direction a status reader trips over — an inbound-only counter built on the direction-blind
        # accessor would report this engine's listening inbound as failed.
        assert runner.inbound_failed("SHARED") is None
    finally:
        await runner.stop()


async def test_connections_api_does_not_report_a_healthy_inbound_as_failed(tmp_path: Path) -> None:
    # The same collision as seen through /connections: the destination row is "failed" with the reason,
    # while the source row of the SAME name reports the live inbound honestly. Keyed by bare name the
    # dashboard could not tell the two halves apart in either direction.
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.pipeline import Engine

    inbox = tmp_path / "in"
    inbox.mkdir()
    reg = Registry()
    reg.add_inbound(_file_inbound(inbox, "SHARED"))
    reg.add_outbound(_env_broken_outbound("SHARED"))
    reg.add_router("r", lambda m: [])

    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    engine.add_registry(reg)
    try:
        service = AuthService(engine.store, AuthSettings(require_mfa=False))
        await service.initialize()
        await _provision_viewer(service)
        await engine.start()  # degraded on the outbound half — does NOT raise (ADR 0031)
        transport = httpx.ASGITransport(app=create_app(engine, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            headers = await _viewer_headers(c)
            rows = (await c.get("/connections", headers=headers)).json()
            graph = (await c.get("/graph/edges", headers=headers)).json()
            engine_info = (await c.get("/status", headers=headers)).json()["engine"]
        sources = [row for row in rows if row["direction"] == "in"]
        dests = [row for row in rows if row["direction"] == "out"]
        assert len(sources) == 1 and sources[0]["status"] != "failed", sources
        assert sources[0]["error"] is None
        assert len(dests) == 1 and dests[0]["status"] == "failed", dests
        assert "out_dir" in (dests[0]["error"] or "")
        # /graph/edges keys its nodes by (kind, name) already; its two status helpers must agree.
        by_kind = {(n["kind"], n["name"]): n["status"] for n in graph["nodes"]}
        assert by_kind[("inbound", "SHARED")] != "failed"
        assert by_kind[("outbound", "SHARED")] == "failed"
        # /status counts failed INBOUNDS for the nav heart (#1741). The failed half here is the
        # outbound, so the listening inbound of the same name must not be counted or named.
        assert engine_info["channels_failed"] == 0, engine_info
        assert engine_info["channels_failed_names"] == []
    finally:
        await engine.stop()


async def test_status_reports_failed_inbounds_and_scopes_their_names(tmp_path: Path) -> None:
    """BACKLOG #1741: /status carries the DEPLOYED inbounds that failed to start, so the console's
    nav heart can stop reporting ok over an engine listening on nothing.

    The count is estate-wide; the NAMES are the caller-visible subset, because /connections already
    hides an out-of-scope inbound's name from a channel-scoped operator and this must not be a side
    channel around that. Both identities are exercised against ONE engine, so the two answers are
    read off the same degraded graph rather than two independently-built ones.
    """
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.auth import Role
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.pipeline import Engine

    port = _free_port()
    reg = Registry()
    # Same (host, port) twice: 'winner' binds, 'loser' is isolated (ADR 0031) — the row's measured
    # case, an MLLP inbound that never got its port.
    reg.add_inbound(build_inbound_connection("winner", MLLP(port=port), router="r"))
    reg.add_inbound(build_inbound_connection("loser", MLLP(port=port), router="r"))
    reg.add_router("r", lambda m: [])

    pw = "a-strong-test-passphrase"
    engine = await Engine.create(tmp_path / "status.db", poll_interval=0.02)
    engine.add_registry(reg)
    try:
        service = AuthService(engine.store, AuthSettings(require_mfa=False))
        await service.initialize()
        # 'wide' sees the whole estate; 'narrow' is scoped to 'winner' only, so the FAILED inbound
        # is out of its scope.
        for username, channels in (("wide", [ALL_CHANNELS]), ("narrow", ["winner"])):
            uid = await service.create_local_user(
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
                uid, password_hash=u.password_hash, must_change_password=False
            )

        await engine.start()  # degraded — does NOT raise (ADR 0031)
        assert engine.registry_runner is not None
        assert set(engine.registry_runner.degraded_inbound()) == {"loser"}
        assert not engine.registry_runner.degraded_outbound()

        transport = httpx.ASGITransport(app=create_app(engine, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

            async def _engine_info(username: str) -> dict[str, object]:
                r = await c.post(
                    "/auth/login",
                    json={"username": username, "password": pw, "provider": "local"},
                )
                auth_header = {"Authorization": f"Bearer {r.json()['token']}"}
                body = (await c.get("/status", headers=auth_header)).json()
                assert isinstance(body, dict), body
                return dict(body["engine"])

            wide = await _engine_info("wide")
            narrow = await _engine_info("narrow")

        # Both inbounds are deployed, so the estate-wide counters agree for either caller.
        assert wide["channels_total"] == narrow["channels_total"] == 2
        assert wide["channels_failed"] == narrow["channels_failed"] == 1
        # Only the unscoped caller learns WHICH one. 'narrow' is scoped to 'winner', so the failed
        # 'loser' is out of its scope and is not named — the count alone still warns its heart.
        assert wide["channels_failed_names"] == ["loser"]
        assert narrow["channels_failed_names"] == []
    finally:
        await engine.stop()
