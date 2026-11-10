# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0207 at the engine API and the host: the issue and revoke routes, the reset reply, and the
``issue-enrolment-code`` host command (AC-8, AC-9, AC-11, AC-12, AC-17). Synthetic accounts only;
the codes are minted by the engine under test."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.__main__ import main
from messagefoundry.auth import Role
from messagefoundry.auth.service import (
    STEP_UP_ACTION_ADMIN_ENROLMENT_CODE_ISSUE,
    STEP_UP_ACTION_ADMIN_ENROLMENT_CODE_REVOKE,
    STEP_UP_ACTION_ADMIN_RESET_MFA,
    AuthService,
)
from messagefoundry.auth.tokens import enrolment_code_digest
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_local_user_chosen
from tests._phi_gate_provisions import setenv_at_rest_opt_out
from tests.test_api_auth import _auth, _client, _login, _reauth

PW = "a-strong-test-passphrase"
#: Account ids, in the 32-hex shape the API's ResourceId takes.
_DIR = "d1" * 16
_OFF = "0f" * 16
_NOBODY = "0" * 32


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "codes_api.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _setup(engine: Engine) -> tuple[AuthService, str, str]:
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            require_mfa=False,
            mfa_verify_min_elapsed_seconds=0,
            login_rate_limit_enabled=False,
        ),
    )
    await service.initialize()
    root = await create_local_user_chosen(
        service,
        username="root",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    user = await service.store.get_user(root)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        root,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    await service.store.create_user(
        user_id=_DIR,
        username="dirperson",
        auth_provider="ad",
        password_generated=False,
        audits=(),
    )
    return service, root, _DIR


async def _granted(c: httpx.AsyncClient, token: str, action: str) -> str:
    r, token = await _reauth(c, token, purpose=action)
    assert r.status_code == 200, r.text
    return token


async def test_ac8_the_issue_route_returns_the_code_once_and_refuses_what_it_must(
    engine: Engine,
) -> None:
    service, root, target = await _setup(engine)
    await service.store.create_user(
        user_id=_OFF,
        username="offperson",
        auth_provider="ad",
        password_generated=False,
        audits=(),
    )
    await service.store.set_user_disabled(_OFF, disabled=True)
    async with _client(engine, service) as c:
        tok = (await _login(c, "root")).json()["token"]
        # No grant bound to the issue action: the gate refuses before the body runs.
        refused = await c.post(f"/users/{target}/enrolment-code", headers=_auth(tok))
        assert refused.status_code in (401, 403)

        tok = await _granted(c, tok, STEP_UP_ACTION_ADMIN_ENROLMENT_CODE_ISSUE)
        issued = await c.post(f"/users/{target}/enrolment-code", headers=_auth(tok))
        assert issued.status_code == 200, issued.text
        assert "no-store" in issued.headers.get("cache-control", "")
        body = issued.json()
        user = await service.store.get_user(target)
        assert user is not None
        assert user.enrolment_code_digest == enrolment_code_digest(body["code"])
        assert user.enrolment_code_issuer == root
        assert body["code"] not in json.dumps(
            [dict(r) for r in await service.store.list_audit()], default=str
        )

        for path, status in (
            (f"/users/{root}/enrolment-code", 400),  # the caller's own account
            (f"/users/{_NOBODY}/enrolment-code", 404),  # unknown
            (f"/users/{_OFF}/enrolment-code", 400),  # disabled
        ):
            tok = await _granted(c, tok, STEP_UP_ACTION_ADMIN_ENROLMENT_CODE_ISSUE)
            r = await c.post(path, headers=_auth(tok))
            assert r.status_code == status, (path, r.text)
            assert "code" not in r.json()


async def test_ac8_the_issue_route_refuses_a_local_account(engine: Engine) -> None:
    service, root, _ = await _setup(engine)
    local = await create_local_user_chosen(
        service,
        username="localperson",
        password=PW,
        display_name=None,
        email=None,
        roles=["viewer"],
        actor="test",
    )
    async with _client(engine, service) as c:
        tok = (await _login(c, "root")).json()["token"]
        tok = await _granted(c, tok, STEP_UP_ACTION_ADMIN_ENROLMENT_CODE_ISSUE)
        r = await c.post(f"/users/{local}/enrolment-code", headers=_auth(tok))
        assert r.status_code == 400
        assert "directory account" in r.json()["detail"]


async def test_ac9_the_revoke_route_takes_its_own_grant_and_clears_the_code(
    engine: Engine,
) -> None:
    service, _, target = await _setup(engine)
    async with _client(engine, service) as c:
        tok = (await _login(c, "root")).json()["token"]
        tok = await _granted(c, tok, STEP_UP_ACTION_ADMIN_ENROLMENT_CODE_ISSUE)
        assert (
            await c.post(f"/users/{target}/enrolment-code", headers=_auth(tok))
        ).status_code == 200
        # An issue grant is not a revoke grant.
        tok = await _granted(c, tok, STEP_UP_ACTION_ADMIN_ENROLMENT_CODE_ISSUE)
        wrong = await c.delete(f"/users/{target}/enrolment-code", headers=_auth(tok))
        assert wrong.status_code in (401, 403)
        tok = await _granted(c, tok, STEP_UP_ACTION_ADMIN_ENROLMENT_CODE_REVOKE)
        revoked = await c.delete(f"/users/{target}/enrolment-code", headers=_auth(tok))
        assert revoked.status_code == 200 and revoked.json() == {"revoked": True}
    user = await service.store.get_user(target)
    assert user is not None and user.enrolment_code_digest is None
    assert len(await service.store.list_audit(action="auth.enrolment_code_revoked")) == 1


async def test_ac12_the_reset_reply_carries_a_directory_accounts_code(engine: Engine) -> None:
    service, _, target = await _setup(engine)
    async with _client(engine, service) as c:
        tok = (await _login(c, "root")).json()["token"]
        tok = await _granted(c, tok, STEP_UP_ACTION_ADMIN_RESET_MFA)
        r = await c.post(f"/users/{target}/reset-mfa", headers=_auth(tok))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["temp_password"] is None and body["enrolment_code"]
        assert "no-store" in r.headers.get("cache-control", "")
    user = await service.store.get_user(target)
    assert user is not None
    assert user.enrolment_code_digest == enrolment_code_digest(body["enrolment_code"])


# --- the host command (AC-11, AC-17) ---------------------------------------------------------------


def _seed(db: Path, *, provider: str = "ad", username: str = "hostperson") -> None:
    async def seed() -> None:
        s = await MessageStore.open(db)
        try:
            await s.create_user(
                user_id="host-1",
                username=username,
                auth_provider=provider,
                password_hash=None if provider == "ad" else "not-a-real-hash",
                password_generated=False,
                audits=(),
            )
        finally:
            await s.close()

    asyncio.run(seed())


def _read(db: Path) -> tuple[str | None, list[dict[str, object]]]:
    async def read() -> tuple[str | None, list[dict[str, object]]]:
        s = await MessageStore.open(db)
        try:
            user = await s.get_user("host-1")
            rows = await s.list_audit(action="auth.enrolment_code_issued")
            return (None if user is None else user.enrolment_code_digest), [dict(r) for r in rows]
        finally:
            await s.close()

    return asyncio.run(read())


def test_ac11_the_host_command_prints_the_code_once_and_audits_the_os_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "host.db"
    _seed(db)
    assert (
        main(["issue-enrolment-code", "--username", "hostperson", "--db", str(db), "--json"]) == 0
    )
    out = json.loads(capsys.readouterr().out)
    digest, rows = _read(db)
    assert digest == enrolment_code_digest(out["code"])
    assert len(rows) == 1 and str(rows[0]["actor"]).startswith("cli:")
    detail = json.loads(str(rows[0]["detail"]))
    assert detail["via"] == "host" and out["code"] not in str(rows[0])


def test_ac11_the_host_command_refuses_a_store_that_does_not_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "absent.db"
    assert main(["issue-enrolment-code", "--username", "x", "--db", str(db)]) == 2
    assert not db.exists()


def test_the_host_command_refuses_a_local_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "local.db"
    _seed(db, provider="local")
    assert main(["issue-enrolment-code", "--username", "hostperson", "--db", str(db)]) == 1
    digest, rows = _read(db)
    assert digest is None and rows == []


def test_ac17_the_host_command_refuses_a_store_another_connection_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "held.db"
    _seed(db)

    async def held() -> int:
        s = await MessageStore.open(db)
        try:
            await s.get_user("host-1")  # a read: the WAL connection holds its SHARED lock
            return main(["issue-enrolment-code", "--username", "hostperson", "--db", str(db)])
        finally:
            await s.close()

    assert asyncio.run(held()) == 2
    digest, rows = _read(db)
    assert digest is None and rows == []


@pytest.mark.parametrize("content", [b"", b"this is not a sqlite database at all, by design"])
def test_ac17_the_host_command_refuses_a_file_that_is_not_a_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes
) -> None:
    monkeypatch.chdir(tmp_path)
    setenv_at_rest_opt_out(monkeypatch)
    db = tmp_path / "notastore.db"
    db.write_bytes(content)
    assert main(["issue-enrolment-code", "--username", "x", "--db", str(db)]) == 2
    assert db.read_bytes() == content  # left as it was
