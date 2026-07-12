# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0041 D2 — dual-control config:deploy / POST /config/reload (BACKLOG #53).

WHERE ``config_reload`` is in ``[approvals].operations`` and ``[approvals].enabled``, a non-dry-run
reload is held (202) for a *distinct* second approver — the requester can never self-approve, and both
identities land in the hash-chained audit. Deny-by-default: when ``config_reload`` is NOT gated (the
shipping posture), a reload executes inline exactly as before.

Covers AC-5 (held 202, graph not swapped), AC-6 (self-approval refused 403), AC-7 (released by a
distinct approver; both identities + the fingerprint-bearing config_reload row audited), AC-8 (inline
when not gated).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import ApprovalsSettings, AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"
GATED = ApprovalsSettings(enabled=True, operations=["config_reload"])
NOT_GATED = ApprovalsSettings(enabled=True, operations=["dead_letter_replay"])  # reload NOT held


def _write_valid_config(cfg: Path, inbox: Path, outdir: Path) -> None:
    cfg.mkdir(parents=True, exist_ok=True)
    inbox.mkdir(parents=True, exist_ok=True)
    outdir.mkdir(parents=True, exist_ok=True)
    (cfg / "cfg.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        f"inbound('IB_T_ADT', File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=1.0), router='r')\n"
        f"outbound('FILE-OUT_T_ADT', File(directory={str(outdir)!r}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('FILE-OUT_T_ADT', msg)\n",
        encoding="utf-8",
    )


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    # The engine's startup --config dir is the default (and only allowed) reload root, so the held
    # request can omit config_dir and the approver replays the same on-disk bundle.
    cfg = tmp_path / "cfg"
    _write_valid_config(cfg, tmp_path / "in", tmp_path / "out")
    eng = await Engine.create(tmp_path / "dc.db", poll_interval=0.02, config_dir=cfg)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    # Dual-control reload is a step-up admin flow, not an MFA test: pin require_mfa=False so the
    # BACKLOG #187 secure default (require_mfa now ON) doesn't 403 the reload before the approval path.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(
    engine: Engine, service: AuthService, approvals: ApprovalsSettings
) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, approvals=approvals)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    uid = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(uid)  # clear forced first-login rotation
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )


async def _token(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return {"Authorization": f"Bearer {r.json()['token']}"}


# --- AC-5: a gated reload is held (202) and the live graph is not swapped ------


async def test_config_reload_is_held_for_approval(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)  # holds config:deploy
    async with _client(engine, service, GATED) as c:
        r = await c.post("/config/reload", json={}, headers=await _token(c, "deployer"))
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["status"] == "pending_approval" and body["operation"] == "config_reload"
        # the reload was NOT applied inline — no config_reload row yet (only the request)
        actions = [a["action"] for a in await engine.store.list_audit(limit=50)]
        assert "config_reload" not in actions
        assert "approval.requested" in actions


# --- AC-6: the requester cannot approve their own reload (403) -----------------


async def test_config_reload_requires_distinct_second_approver(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "admin1", Role.ADMINISTRATOR)
    await _add(service, "admin2", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        a1 = await _token(c, "admin1")
        approval_id = (await c.post("/config/reload", json={}, headers=a1)).json()["approval_id"]
        # the requester is not a valid second approver
        assert (await c.post(f"/approvals/{approval_id}/approve", headers=a1)).status_code == 403
        # ...and the reload has still not executed
        assert "config_reload" not in [a["action"] for a in await engine.store.list_audit(limit=50)]
        # a distinct approver releases it; the captured reload now runs
        a2 = await _token(c, "admin2")
        ok = await c.post(f"/approvals/{approval_id}/approve", headers=a2)
        assert ok.status_code == 200, ok.text
        out = ok.json()
        assert out["requested_by"] == "admin1" and out["approved_by"] == "admin2"
        assert out["result"]["inbound"] == 1  # the held reload executed on release


# --- AC-7: release re-executes + audits both identities + the fingerprint -------


async def test_config_reload_audits_both_identities(engine: Engine) -> None:
    import json

    service = await _service(engine)
    await _add(service, "op", Role.ADMINISTRATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        approval_id = (
            await c.post("/config/reload", json={}, headers=await _token(c, "op"))
        ).json()["approval_id"]
        admin = await _token(c, "approver")
        assert (await c.post(f"/approvals/{approval_id}/approve", headers=admin)).status_code == 200
    rows = await engine.store.list_audit(limit=50)
    audited = {(str(r["action"]), str(r["actor"])) for r in rows}
    assert ("approval.requested", "op") in audited  # the maker
    assert ("approval.approved", "approver") in audited  # the distinct checker
    # the released reload recorded the ADR 0041 D1 fingerprint-bearing config_reload row
    reload_rows = [r for r in rows if r["action"] == "config_reload"]
    assert reload_rows, "expected a config_reload audit row from the released reload"
    detail = json.loads(reload_rows[-1]["detail"])
    assert "fingerprint" in detail and detail["dry_run"] is False


# --- AC-8: ungated reload executes inline (deny-by-default) --------------------


async def test_config_reload_inline_when_not_gated(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)
    async with _client(engine, service, NOT_GATED) as c:
        r = await c.post("/config/reload", json={}, headers=await _token(c, "deployer"))
        assert r.status_code == 200, r.text  # executed inline, not held
        assert r.json()["inbound"] == 1
    assert "config_reload" in [a["action"] for a in await engine.store.list_audit(limit=50)]


# --- a dry-run is never held (it swaps nothing) -------------------------------


async def test_dry_run_reload_is_never_held(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "deployer", Role.ADMINISTRATOR)
    async with _client(engine, service, GATED) as c:
        r = await c.post(
            "/config/reload", json={"dry_run": True}, headers=await _token(c, "deployer")
        )
        assert r.status_code == 200, r.text  # dry-run pre-flight is read-only, never held
        assert r.json()["dry_run"] is True
