# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Audit writes on the two connection routes that had no success-arm test (BACKLOG #1643).

``connection_flag_set`` (``POST /connections/{name}/flag``) and ``connection_credential_test``
(``POST /connections/{name}/test-credential``) each call ``record_audit`` only AFTER their route
body succeeds, and every pre-existing test of either route stops short of that point -- the flag
tests drive ``Engine.set_connection_flag`` directly (no API, so no audit), and the credential-test
arms in ``tests/test_channel_rbac.py`` all short-circuit at 403 / 400 / 404. So both writes could be
deleted with the suite staying green.

These two tests reach the success arm and assert the row is there under the acting user.

Kept apart from ``tests/test_connection_flag.py`` (engine-level, no API or auth imports) and from
``tests/test_channel_rbac.py`` (the refusal arms) because both tests here need the same API + auth
scaffolding that neither of those files carries.
"""

from __future__ import annotations

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
from messagefoundry.config.settings import AuthSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    Registry,
    load_config,
)
from messagefoundry.pipeline import Engine

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
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    uid = await service.create_local_user(
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
        uid, password_hash=user.password_hash, must_change_password=False
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
    """An engine whose graph is connections.toml-managed -- the flag route's precondition. A
    code-first connection has no TOML home and is refused 409 before the audit write is reached."""
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "logic.py").write_text(LOGIC_PY, encoding="utf-8")
    (cfg / "connections.toml").write_text(CONNECTIONS_TOML, encoding="utf-8")
    eng = await Engine.create(tmp_path / "flag.db", poll_interval=0.02, config_dir=cfg)
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

    RED when the ``connection_flag_set`` ``record_audit`` call in ``api/app.py`` is deleted, or when
    it stops passing ``actor=identity.username``. Unobservable before this test: every existing flag
    test calls ``Engine.set_connection_flag`` directly, and the audit write lives in the ROUTE, above
    the engine method -- so the whole of ``tests/test_connection_flag.py`` stays green without it.

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

        # Negative control: an unknown / non-TOML-managed name is refused 409 and must audit nothing.
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
    eng = await Engine.create(tmp_path / "cred.db", poll_interval=0.02)
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
