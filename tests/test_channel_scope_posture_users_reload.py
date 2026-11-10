# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Channel scope on the three routes BACKLOG #3189 found on no backlog row.

* ``GET /security/posture`` shows a channel-scoped reader a per-connection entry only for an inbound
  in its own scope, and says the reading is narrowed.
* ``GET /users`` sends every account's channel scope, and who wrote it, only to a ``users:manage``
  holder. ``users:read`` can be minted into a custom role, which can be channel-scoped.
* ``POST /config/reload`` refuses a channel-scoped caller, a dry run included, and the approval gate
  refuses to release a held reload whose requester has since been scoped.

Each scoped measurement has an all-channels caller with the same roles as its positive control, so a
fixture that showed nobody anything could not pass. NOT-DEPLOYED beta: the gap these close is one a
first deployment would have carried, not a live exposure.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.models import POSTURE_NARROWED_TO_SCOPE, RELOAD_REFUSED_CHANNEL_SCOPED
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS, AuthProvider, Identity
from messagefoundry.auth.permissions import permissions_for_roles
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import (
    ApprovalsSettings,
    AuthSettings,
    EgressSettings,
    SecuritySettings,
)
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    Registry,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen
from tests._approval_queue import release_blocked as _release_blocked
from tests._bound_proof import reproving_transport
from tests.test_dual_control_reload import _write_valid_config

PW = "a-strong-test-passphrase"

#: The scoped reader's inbound, another channel's inbound, and an outbound, which spans channels.
MINE, THEIRS, SHARED = "IB_MINE", "IB_THEIRS", "OB_SHARED"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "cfg_in", tmp_path / "cfg_out")
    eng = await Engine.create(
        tmp_path / "scope3189.db",
        poll_interval=0.02,
        config_dir=cfg,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, admin_write_min_interval_seconds=0)
    )
    await service.initialize()
    return service


async def _user(
    service: AuthService, username: str, roles: list[str], scope: list[str] | None
) -> str:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=roles,
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    if scope is not None:
        await service.set_channel_scope(user_id, scope, actor="test")
    return user_id


async def _login(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _client(engine: Engine, service: AuthService, **kwargs: object) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, **kwargs)  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=reproving_transport(PW, app=app), base_url="http://t")


async def _denials(engine: Engine, actor: str) -> list[str | None]:
    rows = await engine.store.list_audit(limit=200, actor=actor, action="auth.channel_denied")
    return [r["channel_id"] for r in rows]


# --- GET /security/posture -----------------------------------------------------------------------


def _mtls_listener(name: str, port: int) -> InboundConnection:
    return build_inbound_connection(
        name,
        ConnectionSpec(
            type=ConnectorType.MLLP,
            settings={
                "port": port,
                "tls": True,
                "tls_cert_file": "c.pem",
                "tls_key_file": "k.pem",
                "tls_ca_file": "ca.pem",
            },
        ),
        router="r",
        tls_revocation_attested=True,
        tls_revocation_attested_reason="the site CA publishes a CRL the edge enforces",
    )


async def test_posture_names_only_the_scoped_readers_own_inbounds(engine: Engine) -> None:
    reg = Registry()
    reg.add_inbound(_mtls_listener(MINE, 25901))
    reg.add_inbound(_mtls_listener(THEIRS, 25902))
    reg.add_outbound(
        build_outbound_connection(
            SHARED,
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={
                    "host": "partner.example.invalid",
                    "port": 6100,
                    "tls_allow_expired": True,
                },
            ),
        )
    )
    engine.add_registry(reg)
    # Opt-outs naming each kind of hop, so the [security] dump has a connection-keyed value to narrow.
    # A settings: name is a service-settings hop, which names no connection, so everyone sees it.
    security = SecuritySettings(
        require_nonstatic_credentials=True,
        static_credential_accepted={
            SHARED: "the partner offers nothing else",
            f"inbound:{MINE}": "a synthetic opt-out on the reader's own inbound",
            f"inbound:{THEIRS}": "a synthetic opt-out on another channel",
            "settings:alerts.webhook": "a synthetic settings opt-out",
        },
    )
    service = await _service(engine)
    await _user(service, "scoped", [Role.VIEWER.value], [MINE])
    await _user(service, "wide", [Role.VIEWER.value], [ALL_CHANNELS])
    async with _client(engine, service, security_settings=security) as c:
        scoped = await c.get("/security/posture", headers=await _login(c, "scoped"))
        wide = await c.get("/security/posture", headers=await _login(c, "wide"))
    assert scoped.status_code == 200, scoped.text
    assert wide.status_code == 200, wide.text

    # The control: the all-channels reader sees all three connections, and a complete list.
    for name in (MINE, THEIRS, SHARED):
        assert name in wide.text, name
    assert wide.json()["loosenings_scope"] is None
    assert POSTURE_NARROWED_TO_SCOPE not in wide.json()["static_credential_hops_scope"]

    body = scoped.json()
    assert THEIRS not in scoped.text and SHARED not in scoped.text
    assert f"inbound:{MINE}" in scoped.text
    switches = {e["switch"]: e["risk"] for e in body["loosenings"]}
    # The reader's own inbound, counted as one; the outbound-only entry is gone, not emptied.
    assert "1 connection(s)" in switches["tls_revocation_attested"]
    assert "tls_allow_expired" not in switches
    assert body["security"]["static_credential_accepted"] == {
        f"inbound:{MINE}": "a synthetic opt-out on the reader's own inbound",
        "settings:alerts.webhook": "a synthetic settings opt-out",
    }
    # The control reader is shown the outbound's hop; the scoped reader is not.
    assert SHARED in {hop["name"] for hop in wide.json()["static_credential_hops"]}
    assert SHARED not in {hop["name"] for hop in body["static_credential_hops"]}
    # The narrowing is declared, never silent.
    assert body["loosenings_scope"] == POSTURE_NARROWED_TO_SCOPE
    assert POSTURE_NARROWED_TO_SCOPE in body["static_credential_hops_scope"]

    # The audit row records what the response reported, for each reader.
    rows = {
        r["actor"]: json.loads(r["detail"])
        for r in await engine.store.list_audit(limit=50, action="security.posture_view")
    }
    assert "tls_allow_expired" in rows["wide"]["loosenings"]
    assert "tls_allow_expired" not in rows["scoped"]["loosenings"]
    # And it says which of the two lists was narrowed.
    assert rows["wide"]["loosenings_scope"] is None
    assert rows["scoped"]["loosenings_scope"] == POSTURE_NARROWED_TO_SCOPE


async def test_posture_with_no_graph_still_says_it_is_narrowed(engine: Engine) -> None:
    # No registry: the opt-outs keyed by connection are still withheld from a scoped reader, so the
    # settings-only reading must say that too, not only that no graph is loaded.
    assert engine.registry_runner is None
    security = SecuritySettings(
        require_nonstatic_credentials=True,
        static_credential_accepted={f"inbound:{THEIRS}": "a synthetic opt-out on another channel"},
    )
    service = await _service(engine)
    await _user(service, "scoped", [Role.VIEWER.value], [MINE])
    await _user(service, "wide", [Role.VIEWER.value], [ALL_CHANNELS])
    async with _client(engine, service, security_settings=security) as c:
        scoped = await c.get("/security/posture", headers=await _login(c, "scoped"))
        wide = await c.get("/security/posture", headers=await _login(c, "wide"))
    assert scoped.status_code == 200 and wide.status_code == 200
    assert THEIRS in wide.text and THEIRS not in scoped.text
    assert POSTURE_NARROWED_TO_SCOPE not in wide.json()["loosenings_scope"]
    assert POSTURE_NARROWED_TO_SCOPE in scoped.json()["loosenings_scope"]
    assert POSTURE_NARROWED_TO_SCOPE in scoped.json()["static_credential_hops_scope"]
    assert POSTURE_NARROWED_TO_SCOPE not in wide.json()["static_credential_hops_scope"]


# --- GET /users ----------------------------------------------------------------------------------


async def test_users_list_shows_scopes_only_to_a_users_manage_holder(engine: Engine) -> None:
    service = await _service(engine)
    reader_role = await service.create_custom_role(
        display_name="User reader", description=None, permissions=["users:read"], actor="test"
    )
    await _user(service, "scoped-reader", [reader_role.id], [MINE])
    await _user(service, "wide-reader", [reader_role.id], [ALL_CHANNELS])
    await _user(service, "other", [Role.OPERATOR.value], [THEIRS])
    await _user(service, "boss", [Role.ADMINISTRATOR.value], None)
    async with _client(engine, service) as c:
        by_reader = {
            who: await c.get("/users", headers=await _login(c, who))
            for who in ("scoped-reader", "wide-reader", "boss")
        }
    for who, r in by_reader.items():
        assert r.status_code == 200, (who, r.text)
    # The control: the administrator is shown every account's scope and its writer.
    rows = {u["username"]: u for u in by_reader["boss"].json()}
    assert rows["other"]["channel_scope"] == [THEIRS]
    assert rows["other"]["channel_scope_source"] == "manual"
    # The flag says the values are the stored ones, so the administrator's own null scope denies.
    assert all(u["channel_scope_withheld"] is False for u in rows.values())
    assert rows["boss"]["channel_scope"] is None
    # A users:read holder is shown none, scoped or not: the rule is the permission, not the scope.
    for who in ("scoped-reader", "wide-reader"):
        listed = by_reader[who].json()
        assert {u["username"] for u in listed} >= {"other", "boss", who}
        assert all(u["channel_scope"] is None for u in listed), who
        assert all(u["channel_scope_source"] is None for u in listed), who
        # And says so, so a reader never re-derives which null this is.
        assert all(u["channel_scope_withheld"] is True for u in listed), who
        assert THEIRS not in by_reader[who].text


async def test_a_user_summary_withholds_the_scope_unless_asked(engine: Engine) -> None:
    """Vault BACKLOG #3748 item 5: ``_user_summary`` withholds the channel scope and its source
    by default, so a new caller that forgets the argument discloses nothing. It defaulted to
    disclosing, and so failed open."""
    from messagefoundry.api.auth_routes import _user_summary

    service = await _service(engine)
    user_id = await _user(service, "other", [Role.OPERATOR.value], [THEIRS])
    user = await service.store.get_user(user_id)
    assert user is not None
    default = _user_summary(user, [])
    assert default.channel_scope is None and default.channel_scope_source is None
    assert default.channel_scope_withheld is True
    # The control: asking for it discloses the stored scope.
    shown = _user_summary(user, [], show_scope=True)
    assert shown.channel_scope == [THEIRS] and shown.channel_scope_source == "manual"
    assert shown.channel_scope_withheld is False


async def test_the_console_seam_user_summary_needs_show_scope(engine: Engine) -> None:
    """Vault BACKLOG #3748 item 5: the seam digest records no parameter, so a console from before
    the flip still mounts. Its call without ``show_scope`` raises rather than reading a real scope
    as deny-all, and a call that names it gets what it asked for."""
    from fastapi import FastAPI

    from messagefoundry.api.auth_routes import add_auth_routes
    from messagefoundry.api.security import AuthenticatedBeforeBodyRoute

    service = await _service(engine)
    user_id = await _user(service, "other", [Role.OPERATOR.value], [THEIRS])
    user = await service.store.get_user(user_id)
    assert user is not None
    app = FastAPI()
    app.router.route_class = AuthenticatedBeforeBodyRoute
    summary = add_auth_routes(app).user_summary_scoped
    with pytest.raises(TypeError):
        summary(user, [])
    shown = summary(user, [], show_scope=True)
    assert shown.channel_scope == [THEIRS] and shown.channel_scope_withheld is False
    assert summary(user, [], show_scope=False).channel_scope_withheld is True


async def test_the_users_manage_create_routes_still_show_the_scope(engine: Engine) -> None:
    """Vault BACKLOG #3748 item 5: the ``users:manage`` routes that build a summary pass
    ``show_scope=True`` now that the default withholds, so their answer says the scope is shown."""
    service = await _service(engine)
    await _user(service, "boss", [Role.ADMINISTRATOR.value], None)
    async with _client(engine, service) as c:
        r = await c.post(
            "/users",
            json={
                "username": "newbie",
                "email": "newbie@example.test",
                "roles": [Role.OPERATOR.value],
            },
            headers=await _login(c, "boss"),
        )
    assert r.status_code == 201, r.text
    assert r.json()["channel_scope_withheld"] is False


async def test_a_scope_change_row_withholds_its_channels_from_a_reader_without_users_manage(
    engine: Engine,
) -> None:
    """Vault BACKLOG #3748 item 6: a ``user.channel_scope_changed`` row named every account's
    channels to any ``audit:read`` holder. A reader without ``users:manage`` now reads the row with
    its list withheld, on ``GET /audit`` and the CSV export; an administrator reads it whole."""
    service = await _service(engine)
    await _user(service, "other", [Role.OPERATOR.value], [THEIRS])  # writes the row
    await _user(service, "auditor", [Role.AUDITOR.value], None)
    await _user(service, "boss", [Role.ADMINISTRATOR.value], None)
    query = {"action": "user.channel_scope_changed"}
    async with _client(engine, service) as c:
        auditor = await _login(c, "auditor")
        by_auditor = await c.get("/audit", params=query, headers=auditor)
        exported = await c.get("/audit/export", params=query, headers=auditor)
        by_boss = await c.get("/audit", params=query, headers=await _login(c, "boss"))
    for r in (by_auditor, exported, by_boss):
        assert r.status_code == 200, r.text
    (seen,) = by_auditor.json()["entries"]
    assert json.loads(seen["detail"])["channels"] == "withheld"
    assert "user_id" in json.loads(seen["detail"]), "the row itself stays readable"
    assert THEIRS not in by_auditor.text and THEIRS not in exported.text
    assert "user.channel_scope_changed" in exported.text, "control: the export holds the row"
    # The control: users:manage reads the list.
    (whole,) = by_boss.json()["entries"]
    assert json.loads(whole["detail"])["channels"] == [THEIRS]


def test_a_withheld_scope_row_has_one_shape_whatever_it_held() -> None:
    """Vault BACKLOG #3748 item 6: a withheld row keeps only the keys known to hold no scope, so a
    withdraw, which adds ``withdrawn``, reads as a set does, a key a later writer adds is withheld,
    and a detail that is not an object reads as withheld, never as a stored null."""
    from messagefoundry.auth.audit_visibility import audit_detail_for
    from messagefoundry.auth.identity import AuthProvider, Identity
    from messagefoundry.auth.permissions import permissions_for_roles

    reader = Identity(
        user_id="u",
        username="auditor",
        auth_provider=AuthProvider.LOCAL,
        roles=frozenset({Role.AUDITOR}),
        permissions=permissions_for_roles([Role.AUDITOR]),
    )
    withheld = {"channels": "withheld"}
    withdraw = json.dumps({"channels": None, "withdrawn": [THEIRS]})
    set_one = json.dumps({"channels": [THEIRS]})
    too_deep = "[" * 100_000 + "]" * 100_000  # json's depth limit raises RecursionError
    for detail in (withdraw, set_one, "[1]", "not json", too_deep):
        shown = audit_detail_for(reader, "auth.ad_scope_resynced", detail)
        assert shown is not None and json.loads(shown) == withheld, detail
    added = json.dumps({"user_id": "x", "channels": [THEIRS], "previous": [THEIRS]})
    shown = audit_detail_for(reader, "user.channel_scope_changed", added)
    assert shown is not None and json.loads(shown) == {"user_id": "x", **withheld}
    assert audit_detail_for(reader, "auth.login_failed", "not json") == "not json"


def _auditor_identity() -> Identity:
    return Identity(
        user_id="u",
        username="auditor",
        auth_provider=AuthProvider.LOCAL,
        roles=frozenset({Role.AUDITOR}),
        permissions=permissions_for_roles([Role.AUDITOR]),
    )


def test_a_reconciler_revocation_row_withholds_its_scope_delta() -> None:
    """Vault BACKLOG #3748 item 6: the reconciler's ``auth.ad_session_revoked`` row carries
    ``scope_from`` and ``scope_to`` on a scope delta. A reader without ``users:manage`` reads both
    withheld and keeps ``scope_changed``, so the row still says a scope moved. A row with no delta
    is unchanged in what it shows."""
    from messagefoundry.auth.audit_visibility import audit_detail_for

    reader = _auditor_identity()
    delta = json.dumps(
        {
            "reason": "scope_changed",
            "sessions": 2,
            "roles": ["operator"],
            "scope_changed": True,
            "scope_from": [THEIRS],
            "scope_to": [],
        }
    )
    shown = audit_detail_for(reader, "auth.ad_session_revoked", delta)
    assert shown is not None and THEIRS not in shown
    assert json.loads(shown) == {
        "reason": "scope_changed",
        "sessions": 2,
        "roles": ["operator"],
        "scope_changed": True,
        "scope_from": "withheld",
        "scope_to": "withheld",
    }
    plain = {"reason": "disabled", "sessions": 1}
    shown = audit_detail_for(reader, "auth.ad_session_revoked", json.dumps(plain))
    assert shown is not None and json.loads(shown) == plain


async def test_a_refused_scope_save_withholds_the_scope_owner(engine: Engine) -> None:
    """Vault BACKLOG #3748 item 6: a ``user.channel_scope_change_refused`` row names who owns the
    account's scope (``owner``, ``read_source``, ``expected_source``). A reader without
    ``users:manage`` reads those withheld on ``GET /audit``; an administrator reads them whole."""
    from messagefoundry.auth.service import ChannelScopeSourceConflict

    service = await _service(engine)
    target = await _user(service, "other", [Role.OPERATOR.value], [THEIRS])
    await _user(service, "auditor", [Role.AUDITOR.value], None)
    await _user(service, "boss", [Role.ADMINISTRATOR.value], None)
    with pytest.raises(ChannelScopeSourceConflict):
        await service.set_channel_scope(target, [THEIRS], actor="boss", expected_source="ad")
    query = {"action": "user.channel_scope_change_refused"}
    async with _client(engine, service) as c:
        by_auditor = await c.get("/audit", params=query, headers=await _login(c, "auditor"))
        by_boss = await c.get("/audit", params=query, headers=await _login(c, "boss"))
    assert by_auditor.status_code == 200 and by_boss.status_code == 200
    (seen,) = by_auditor.json()["entries"]
    (whole,) = by_boss.json()["entries"]
    stored = json.loads(whole["detail"])
    assert stored["owner"] not in (None, "withheld"), "control: the row names an owner"
    shown = json.loads(seen["detail"])
    assert shown["user_id"] == target and shown["username"] == "other"
    for key in ("owner", "read_source", "expected_source", "reason"):
        if key in stored:
            assert shown[key] == "withheld", key
    assert set(shown) <= {
        "user_id",
        "username",
        "owner",
        "read_source",
        "expected_source",
        "reason",
    }


# --- POST /config/reload -------------------------------------------------------------------------


@pytest.mark.parametrize("dry_run", [False, True])
async def test_reload_refuses_a_channel_scoped_caller(engine: Engine, dry_run: bool) -> None:
    service = await _service(engine)
    await _user(service, "scoped-deployer", [Role.DEPLOYMENT.value], ["IB_T_ADT"])
    await _user(service, "wide-deployer", [Role.DEPLOYMENT.value], [ALL_CHANNELS])
    async with _client(engine, service) as c:
        r = await c.post(
            "/config/reload",
            json={"dry_run": dry_run},
            headers=await _login(c, "scoped-deployer"),
        )
        assert r.status_code == 403, r.text
        assert r.json() == {"detail": "channel-scoped users cannot reload the configuration"}
        # The control: the same request from an all-channels deployer is not refused for scope.
        ok = await c.post(
            "/config/reload", json={"dry_run": dry_run}, headers=await _login(c, "wide-deployer")
        )
        assert ok.status_code == 200, ok.text
    # One denial row, naming no channel, and the refused reload attempted nothing.
    assert await _denials(engine, "scoped-deployer") == [None]
    attempted = await engine.store.list_audit(limit=50, action="config_reload_attempted")
    assert all(row["actor"] != "scoped-deployer" for row in attempted)


async def test_a_held_reload_is_not_released_once_its_requester_is_scoped(
    engine: Engine,
) -> None:
    """The approval gate re-checks the requester at release (BACKLOG #289). A reload filed while the
    requester held every channel must not run once that requester is channel-scoped."""
    gated = ApprovalsSettings(enabled=True, operations=["config_reload"], min_dwell_seconds=0.0)
    service = await _service(engine)
    maker = await _user(service, "maker", [Role.DEPLOYMENT.value], [ALL_CHANNELS])
    await _user(service, "checker", [Role.ADMINISTRATOR.value], None)
    async with _client(engine, service, approvals=gated) as c:
        held = await c.post("/config/reload", json={}, headers=await _login(c, "maker"))
        assert held.status_code == 202, held.text
        approval_id = held.json()["approval_id"]
        checker = await _login(c, "checker")
        # The control for the prediction below: while the requester holds every channel, nothing
        # is predicted.
        assert await _release_blocked(c, approval_id, checker) is None
        await service.set_channel_scope(maker, ["IB_T_ADT"], actor="test")
        # The queue now predicts the refusal, so the Approvals page offers only the reject rather
        # than an Approve every approver is refused (BACKLOG #3189, #3192).
        assert await _release_blocked(c, approval_id, checker) == "requester_not_authorized"
        r = await c.post(f"/approvals/{approval_id}/approve", headers=checker)
        assert r.status_code == 409, r.text
    stale = await engine.store.list_audit(limit=50, action="approval.stale_requester")
    assert [json.loads(row["detail"])["reason"] for row in stale] == ["requester_out_of_scope"]


async def test_a_held_purge_is_predicted_refused_once_its_requester_is_scoped(
    tmp_path: Path,
) -> None:
    """The same gap on the purge, the other operation no channel scope can confine. A purge held
    while the requester held every channel is predicted refused once the requester is scoped."""
    out = tmp_path / "purge_out"
    out.mkdir()
    eng = await Engine.create(
        tmp_path / "purge3189.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        reg = Registry()
        reg.add_outbound(
            build_outbound_connection(
                SHARED, ConnectionSpec(type=ConnectorType.FILE, settings={"directory": str(out)})
            )
        )
        eng.add_registry(reg)
        await eng.start()
        rr = eng.registry_runner
        assert rr is not None
        await rr.stop_outbound(SHARED)  # a purge needs a quiesced outbound before it is held
        for _ in range(200):
            if rr.outbound_quiesced(SHARED):
                break
            await asyncio.sleep(0.02)
        assert rr.outbound_quiesced(SHARED)
        gated = ApprovalsSettings(
            enabled=True, operations=["connection_purge"], min_dwell_seconds=0.0
        )
        service = await _service(eng)
        maker = await _user(service, "maker", [Role.OPERATOR.value], [ALL_CHANNELS])
        await _user(service, "checker", [Role.ADMINISTRATOR.value], None)
        async with _client(eng, service, approvals=gated) as c:
            held = await c.post(f"/connections/{SHARED}/purge", headers=await _login(c, "maker"))
            assert held.status_code == 202, held.text
            approval_id = held.json()["approval_id"]
            checker = await _login(c, "checker")
            assert await _release_blocked(c, approval_id, checker) is None
            await service.set_channel_scope(maker, [MINE], actor="test")
            assert await _release_blocked(c, approval_id, checker) == "requester_not_authorized"
            r = await c.post(f"/approvals/{approval_id}/approve", headers=checker)
            assert r.status_code == 409, r.text
    finally:
        await eng.stop()


# --- GET /config/provenance: the console's Reload form follows the engine -------------------------


async def test_provenance_names_the_reload_refusal_the_route_gives(engine: Engine) -> None:
    """BACKLOG #3189: ``reload_refused`` is read off the rule the reload refuses on, so a page can
    stop offering a reload that would cost a step-up and then answer 403. A deployer with no scope
    set at all is channel-scoped too: an empty scope is a scope (Manager decision)."""
    service = await _service(engine)
    await _user(service, "scoped-deployer", [Role.DEPLOYMENT.value], ["IB_T_ADT"])
    await _user(service, "unset-deployer", [Role.DEPLOYMENT.value], None)
    await _user(service, "wide-deployer", [Role.DEPLOYMENT.value], [ALL_CHANNELS])
    async with _client(engine, service) as c:
        seen = {}
        for who in ("scoped-deployer", "unset-deployer", "wide-deployer"):
            headers = await _login(c, who)
            prov = await c.get("/config/provenance", headers=headers)
            assert prov.status_code == 200, prov.text
            reload = await c.post("/config/reload", json={"dry_run": True}, headers=headers)
            seen[who] = (prov.json()["reload_refused"], reload.status_code)
    assert seen == {
        "scoped-deployer": (RELOAD_REFUSED_CHANNEL_SCOPED, 403),
        "unset-deployer": (RELOAD_REFUSED_CHANNEL_SCOPED, 403),
        # The control: the field is not always set.
        "wide-deployer": (None, 200),
    }


# --- the channel-denied audit bounds the name it records ---------------------------------------------------


async def test_the_engine_refusal_audits_no_malformed_name(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3031: the console checks a bulk selection's name before it calls in, and the JSON
    routes bound it on the path, but the core handlers take any string. So the engine's
    ``audit_channel_denied`` bounds it too: a name that fails the connection-name rule is audited
    with no channel, and the caller is still refused. The control: a well-formed out-of-scope name
    is audited by name."""
    from fastapi import HTTPException

    import messagefoundry_webconsole
    from messagefoundry.api._ui_seam import UiDeps
    from messagefoundry.auth import AuthProvider, Identity

    captured: list[UiDeps] = []
    monkeypatch.setattr(
        messagefoundry_webconsole, "mount_ui", lambda _app, deps: captured.append(deps)
    )
    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)
    [deps] = captured
    actor = "direct-caller"
    scoped = Identity.build(
        user_id="direct-caller-id",
        username=actor,
        auth_provider=AuthProvider.LOCAL,
        roles=[Role.OPERATOR],
        allowed_channels=frozenset({MINE}),
    )
    for name in ("A" * 5000, "IB_BAD/NAME", THEIRS):
        with pytest.raises(HTTPException) as refused:
            await deps.core.dual_role_control(engine, scoped, name, "start", role="source")
        assert refused.value.status_code == 403, name
    assert sorted(await _denials(engine, actor), key=str) == sorted([None, None, THEIRS], key=str)
    # The bound is in the audit helper itself, so every refusal that writes the row holds it,
    # whichever branch or handler called it: here the seam's own callback, as a console route and
    # a core handler such as the purge call it.
    other = "helper-caller"
    helper_scoped = Identity.build(
        user_id="helper-caller-id",
        username=other,
        auth_provider=AuthProvider.LOCAL,
        roles=[Role.OPERATOR],
        allowed_channels=frozenset({MINE}),
    )
    for name in ("A" * 5000, "IB_BAD/NAME", THEIRS):
        await deps.core.audit_channel_denied(engine, helper_scoped, name, None)
    rows = await engine.store.list_audit(limit=50, action="auth.channel_denied", actor=other)
    assert sorted((r["channel_id"] for r in rows), key=str) == sorted([None, None, THEIRS], key=str)
    # The detail carries no copy of the refused name either, and marks the two malformed ones,
    # so a probe is told apart from a refusal that names no channel by design.
    assert all("A" * 64 not in str(r["detail"]) for r in rows)
    marked = [json.loads(str(r["detail"])).get("malformed_name", False) for r in rows]
    assert sorted(marked) == [False, True, True]
