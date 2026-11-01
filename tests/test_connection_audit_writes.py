# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Audit writes on the two connection routes that had no success-arm test (BACKLOG #1643).

``connection_flag_set`` (``POST /connections/{name}/flag``) and ``connection_credential_test``
(``POST /connections/{name}/test-credential``) each write their row only on the success path, and
every pre-existing test of either route stopped short of that point: the credential-test arms in
``tests/test_channel_rbac.py`` all short-circuit at 403 / 400 / 404. The flag's row now commits in
the store with the flag (BACKLOG #2623), and this test still pins the actor the route hands it.

These two tests reach the success arm and assert the row is there under the acting user.

Kept apart from ``tests/test_connection_flag.py`` (engine-level, no API or auth imports) and from
``tests/test_channel_rbac.py`` (the refusal arms) because both tests here need the same API + auth
scaffolding that neither of those files carries.
"""

from __future__ import annotations

import logging
import textwrap
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    Registry,
    load_config,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import AuditAppend
from tests._admin_account import create_local_user_chosen
from tests._operator_audit_atomic_contract import failing_append

PW = "Correct-Horse-Battery-Staple-9"

# Loopback MLLP hosts so build_check's cleartext-hop guard never refuses, and no File dirs to create.
LOGIC_PY = textwrap.dedent(
    """
    from messagefoundry import MLLP, Send, handler, outbound, router

    @router("r")
    def route(msg):
        return ["h"]

    @handler("h")
    def handle(msg):
        return Send("OB_TOML", msg)
    """
)

CONNECTIONS_TOML = textwrap.dedent(
    """
    [[inbound]]
    name = "IB_TOML"
    transport = "mllp"
    router = "r"
    [inbound.settings]
    port = 2610

    [[outbound]]
    name = "OB_TOML"
    transport = "mllp"
    [outbound.settings]
    host = "127.0.0.1"
    port = 2710
    """
)


async def _deployer(engine: Engine, *channels: str) -> AuthService:
    """A DEPLOYMENT user -- the built-in role holding BOTH ``config:deploy`` (the flag route) and
    ``connections:test`` (the credential route), and nothing else these routes read.

    ``require_mfa=False``: these are audit-write tests, not MFA tests, and the BACKLOG #187 secure
    default would otherwise refuse before the route body ever runs.
    """
    service = AuthService(
        engine.store, AuthSettings(admin_write_min_interval_seconds=0, require_mfa=False)
    )
    await service.initialize()
    uid = await create_local_user_chosen(
        service,
        username="deployer",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.DEPLOYMENT.value],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope DENIES, so grant explicitly.
    await service.set_channel_scope(uid, list(channels) or [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    return service


async def _login(c: httpx.AsyncClient) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": "deployer", "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture
async def toml_engine(tmp_path: Path) -> AsyncIterator[Engine]:
    """An engine with a graph, the flag route's precondition: an unknown name is refused 409 before
    the audit write is reached."""
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "logic.py").write_text(LOGIC_PY, encoding="utf-8")
    (cfg / "connections.toml").write_text(CONNECTIONS_TOML, encoding="utf-8")
    eng = await Engine.create(
        tmp_path / "flag.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    # Attach the graph WITHOUT starting listeners -- no socket binds needed here.
    eng.add_registry(load_config(cfg))
    try:
        yield eng
    finally:
        await eng.stop()


async def test_flag_route_audits_connection_flag_set_under_the_acting_user(
    toml_engine: Engine,
) -> None:
    """BACKLOG #1643: a successful flag write leaves a ``connection_flag_set`` row naming the caller.

    RED when the audit argument in ``Engine.set_connection_flag`` is renamed or dropped, or when the
    route stops passing ``actor=identity.username`` to it.

    The 409 arm below is the negative control: it proves the row is written by the SUCCESS path and
    not unconditionally on entry, which a write hoisted above the ``set_connection_flag`` call would
    be. Without it a route that audits a refused write would pass the presence assertion.
    """
    service = await _deployer(toml_engine)
    transport = httpx.ASGITransport(app=create_app(toml_engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c)
        r = await c.post(
            "/connections/OB_TOML/flag",
            json={"direction": "outbound", "flagged": True},
            headers=h,
        )
        assert r.status_code == 200, r.text
        assert r.json() == {"name": "OB_TOML", "direction": "outbound", "flagged": True}

        # Negative control: an unknown name is refused 409 and must audit nothing.
        refused = await c.post(
            "/connections/OB_NOPE/flag",
            json={"direction": "outbound", "flagged": True},
            headers=h,
        )
        assert refused.status_code == 409, refused.text

    rows = await toml_engine.store.list_audit(action="connection_flag_set")
    assert rows, "a successful flag write must leave a connection_flag_set audit row"
    assert [row["actor"] for row in rows] == ["deployer"]
    assert len(rows) == 1, "the refused 409 write must not be audited as a flag set"
    assert "OB_TOML" in str(rows[0]["detail"])


async def test_flag_route_answers_503_when_the_audit_row_fails(toml_engine: Engine) -> None:
    """BACKLOG #2623: the flag and its ``connection_flag_set`` row are one transaction, so a row that
    fails leaves the flag as it was, and the route answers 503, the store being at fault, not the
    request. The fault's own text stays in the log."""
    service = await _deployer(toml_engine)
    transport = httpx.ASGITransport(app=create_app(toml_engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c)
        with failing_append(toml_engine.store, "connection_flag_set"):
            r = await c.post(
                "/connections/OB_TOML/flag",
                json={"direction": "outbound", "flagged": True},
                headers=h,
            )
    assert r.status_code == 503, r.text
    assert r.json()["detail"].startswith("the store did not confirm this toggle")
    # A commit whose answer was lost lands, so the refusal never tells a caller to just repeat it.
    assert "may or may not have changed" in r.json()["detail"]
    assert "try again" not in r.json()["detail"].lower()
    assert await toml_engine.store.list_connection_flags() == set()


async def test_the_dashboard_shows_the_flag_on_each_direction_and_a_code_first_row(
    toml_engine: Engine,
) -> None:
    """``GET /connections`` joins the store's flags to its rows by direction and name. RED if the
    join reads the wrong side: a source row and a destination row are told apart here."""
    service = await _deployer(toml_engine)
    transport = httpx.ASGITransport(app=create_app(toml_engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c)
        for name, direction in (("OB_TOML", "outbound"), ("IB_TOML", "inbound")):
            r = await c.post(
                f"/connections/{name}/flag",
                json={"direction": direction, "flagged": True},
                headers=h,
            )
            assert r.status_code == 200, r.text
        rows = (await c.get("/connections", headers=h)).json()
    flagged = {
        (row["role"], row["channel_id"], row["destination"]) for row in rows if row["flagged"]
    }
    assert ("source", "IB_TOML", None) in flagged
    assert any(role == "destination" and dest == "OB_TOML" for role, _, dest in flagged)
    assert rows, "control: the page has rows"
    assert all("toml_managed" not in row for row in rows)


async def _plant_an_unreadable_row(engine: Engine) -> None:
    db = engine.store._db  # type: ignore[attr-defined]
    await db.execute(
        "INSERT INTO connection_flag (connection, direction) VALUES (CAST(X'FF' AS TEXT), 'inbound')"
    )
    await db.commit()


async def test_a_row_the_driver_cannot_read_costs_the_markers_and_not_the_page(
    toml_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """A database writer with no key can plant bytes that are not text. No engine path reads the
    flag, so the page still answers, with a WARNING, and every row's flag reads ``None``: unknown,
    and not unflagged, so a console cannot act on a failed read as though it were an answer. RED
    without the read's guard: a 500 on the dashboard, from a value that was never allowed to refuse
    anything."""
    service = await _deployer(toml_engine)
    await toml_engine.store.set_connection_flag(
        "OB_TOML", "outbound", flagged=True, audit=AuditAppend("connection_flag_set")
    )
    await _plant_an_unreadable_row(toml_engine)
    transport = httpx.ASGITransport(app=create_app(toml_engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c)
        with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
            r = await c.get("/connections", headers=h)
            again = await c.get("/connections", headers=h)
    assert r.status_code == again.status_code == 200, r.text
    assert r.json(), "control: the page has rows"
    assert all(row["flagged"] is None for row in r.json())
    # Once, however many frames read it: the stats socket reads this every second per console.
    assert caplog.text.count("the connection flags could not be read") == 1


async def test_each_app_keeps_its_own_run_of_failed_flag_reads(
    toml_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The run lives on ``app.state``. RED on a module global: the first app leaves it set, so the
    second app's first failure logs nothing, and a rerun in one process fails the test above."""
    service = await _deployer(toml_engine)
    await _plant_an_unreadable_row(toml_engine)
    apps = [create_app(toml_engine, auth=service) for _ in range(2)]
    # One sign-in: both apps share the auth service, so the first app's token opens the second.
    first = httpx.ASGITransport(app=apps[0])
    async with httpx.AsyncClient(transport=first, base_url="http://t") as c:
        h = await _login(c)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
        for app in apps:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                r = await c.get("/connections", headers=h)
            assert r.status_code == 200, r.text
    assert caplog.text.count("the connection flags could not be read") == 2


async def test_flags_read_again_once_the_store_answers(
    toml_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """Recovery ends the run: the rows answer again, and the next failure is a new run that logs."""
    service = await _deployer(toml_engine)
    await _plant_an_unreadable_row(toml_engine)
    transport = httpx.ASGITransport(app=create_app(toml_engine, auth=service))
    db = toml_engine.store._db  # type: ignore[attr-defined]
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c)
        with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
            await c.get("/connections", headers=h)
            await db.execute("DELETE FROM connection_flag")
            await db.commit()
            recovered = await c.get("/connections", headers=h)
            await _plant_an_unreadable_row(toml_engine)
            await c.get("/connections", headers=h)
    assert all(row["flagged"] is False for row in recovered.json())
    assert caplog.text.count("the connection flags could not be read") == 2


async def test_credential_test_route_audits_under_the_acting_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1643: a probe that reaches the success arm leaves a ``connection_credential_test`` row.

    RED when the ``connection_credential_test`` ``record_audit`` call in ``api/app.py`` is deleted.
    The arms in ``tests/test_channel_rbac.py`` all stop at 403 / 400 / 404, every one of them ABOVE
    this write, so none of them can see it go.

    PORTABILITY, and why the credential context is stubbed. The route's 400-guard reads
    ``credential_username`` off the registry SPEC, so the spec must really carry one -- but building a
    File connector from that spec constructs a real Win32 ``CredentialContext``, which raises
    ``CredentialUnsupportedError`` off Windows. That is a ``ValueError``, and ``build_test_connector``
    catches only ``WiringError``, so on a Linux runner the route would 500 and write no row at all.
    Stubbing the context to ``None`` leaves the connector byte-identical to an uncredentialed File
    endpoint while the SPEC -- which is what every guard on the route reads -- is untouched. So the
    whole route body under test is real; only the impersonation the test cannot perform is not.

    ``supported`` / ``success`` are deliberately NOT asserted: the write is unconditional once the
    probe returns, and pinning a probe outcome would make this a test about the filesystem.
    """
    import messagefoundry.transports.file as file_transport

    monkeypatch.setattr(file_transport, "_build_credential_context", lambda _settings: None)

    share = tmp_path / "share"
    share.mkdir()
    eng = await Engine.create(
        tmp_path / "cred.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        reg = Registry()
        reg.add_inbound(
            InboundConnection(
                "IB_CRED",
                ConnectionSpec(
                    ConnectorType.FILE,
                    {
                        "directory": str(share),
                        "pattern": "*.hl7",
                        "credential_username": "svc",
                        "credential_password": "pw",
                    },
                ),
                router="r",
            )
        )
        reg.add_router("r", lambda m: [])
        eng.add_registry(reg)

        service = await _deployer(eng, "IB_CRED")  # in scope, so _control_guard passes
        transport = httpx.ASGITransport(app=create_app(eng, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            h = await _login(c)
            r = await c.post("/connections/IB_CRED/test-credential", headers=h)
            assert r.status_code == 200, r.text
            assert r.json()["name"] == "IB_CRED"

        rows = await eng.store.list_audit(action="connection_credential_test")
        assert rows, "a completed credential probe must leave a connection_credential_test row"
        assert [row["actor"] for row in rows] == ["deployer"]
        # channel_id is set for an INBOUND probe, which is what scopes the row to a channel-scoped
        # reader; an outbound spans channels and deliberately records None.
        assert rows[0]["channel_id"] == "IB_CRED"
    finally:
        await eng.stop()
