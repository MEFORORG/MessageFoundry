# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The vault_transit AES-GCM bound attestation (BACKLOG #2337, owner rulings 2026-10-07).

On ``vault_transit`` the engine counts no AES-GCM invocations, so ``serve`` needs a recorded, audited
attestation naming the configured Transit data key. These tests run the SQLite store over the fake
Transit from ``tests/test_crypto_transit.py``; the SQL Server and Postgres twins run in
``tests/test_transit_bound_attestation_server_backends.py`` on the CI legs that have those servers.
"""

from __future__ import annotations

import getpass
import json
import logging
import sqlite3
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.__main__ import main
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    AiSettings,
    AuthSettings,
    EgressSettings,
    SecurityEnforcement,
    SecuritySettings,
    StoreSettings,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store.base import open_store
from messagefoundry.store.store import AuditAppend, MessageStore
from messagefoundry.store.transit_attestation import (
    TRANSIT_BOUND_ATTESTED_ACTION,
    TRANSIT_BOUND_WITHDRAWN_ACTION,
    TransitBoundAttestation,
    TransitBoundUnattestedError,
)
from tests._admin_account import create_local_user_chosen
from tests.test_crypto_transit import _KEY_NAME, _use_fake

PW = "a-strong-test-passphrase"


async def _transit_store(db: Path) -> MessageStore:
    store = await open_store(
        StoreSettings(path=str(db), cipher_provider="vault_transit"),
        create=True,
        keyless_chain_refusal=None,
    )
    assert isinstance(store, MessageStore)
    return store


@pytest.fixture
async def store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> AsyncIterator[MessageStore]:
    _use_fake(monkeypatch)
    s = await _transit_store(tmp_path / "transit.db")
    try:
        yield s
    finally:
        await s.close()


async def _attest(store: MessageStore, key_name: str = _KEY_NAME) -> TransitBoundAttestation:
    return await store.record_transit_bound_attestation(
        key_name=key_name,
        reason="Transit auto-rotates this key every 30 days",
        audit=AuditAppend(TRANSIT_BOUND_ATTESTED_ACTION, actor="cli:tester"),
    )


async def _withdraw(store: MessageStore) -> TransitBoundAttestation | None:
    return await store.withdraw_transit_bound_attestation(
        audit=lambda w: AuditAppend(TRANSIT_BOUND_WITHDRAWN_ACTION, actor="cli:tester")
    )


async def _start(store: MessageStore, enforcement: SecurityEnforcement) -> None:
    engine = Engine(
        store,
        security_enforcement=enforcement,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await engine.start()
    finally:
        await engine.stop()


# --- the start gate ------------------------------------------------------------------------------


async def test_enforce_refuses_a_transit_store_with_no_attestation(store: MessageStore) -> None:
    with pytest.raises(TransitBoundUnattestedError, match="attest-transit-bound"):
        await _start(store, SecurityEnforcement.ENFORCE)


async def test_warn_starts_with_a_warning(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.transit_attestation"):
        await _start(store, SecurityEnforcement.WARN)
    warned = [r for r in caplog.records if "vault_transit" in r.getMessage()]
    assert warned and warned[0].levelno == logging.WARNING
    assert "no attestation is recorded" in warned[0].getMessage()


async def test_an_attestation_naming_the_configured_key_lets_enforce_start(
    store: MessageStore,
) -> None:
    await _attest(store)
    await _start(store, SecurityEnforcement.ENFORCE)  # no raise


async def test_an_attestation_for_another_key_name_does_not_satisfy(store: MessageStore) -> None:
    await _attest(store, key_name="mefor-store-old")
    with pytest.raises(TransitBoundUnattestedError, match="mefor-store-old"):
        await _start(store, SecurityEnforcement.ENFORCE)


async def test_withdraw_re_arms_the_refusal(store: MessageStore, tmp_path: Path) -> None:
    await _attest(store)
    await _start(store, SecurityEnforcement.ENFORCE)  # stopping the engine closes the store
    again = await _transit_store(tmp_path / "transit.db")
    withdrawn = await _withdraw(again)
    assert withdrawn is not None and withdrawn.key_name == _KEY_NAME
    with pytest.raises(TransitBoundUnattestedError):
        await _start(again, SecurityEnforcement.ENFORCE)


async def test_a_non_transit_store_is_not_gated(tmp_path: Path) -> None:
    keyless = await MessageStore.open(tmp_path / "plain.db")
    await _start(keyless, SecurityEnforcement.ENFORCE)  # no raise: the engine counts the bound


# --- the store rows ------------------------------------------------------------------------------


def _audit_rows(db: Path, action: str) -> list[sqlite3.Row]:
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        return con.execute(
            "SELECT actor, ts, detail FROM audit_log WHERE action = ? ORDER BY id", (action,)
        ).fetchall()
    finally:
        con.close()


async def test_record_replaces_and_withdraw_of_nothing_writes_no_audit_row(
    store: MessageStore, tmp_path: Path
) -> None:
    assert await _withdraw(store) is None
    assert _audit_rows(tmp_path / "transit.db", TRANSIT_BOUND_WITHDRAWN_ACTION) == []
    await _attest(store, key_name="first")
    await _attest(store, key_name=_KEY_NAME)
    current = await store.get_transit_bound_attestation()
    assert current is not None and current.key_name == _KEY_NAME and current.actor == "cli:tester"


async def test_a_refused_audit_append_records_no_attestation(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refuse(*_a: object, **_k: object) -> object:
        raise RuntimeError("audit append refused")

    monkeypatch.setattr(store, "_append_audit_row", refuse)
    with pytest.raises(RuntimeError, match="audit append refused"):
        await _attest(store)
    monkeypatch.undo()
    assert await store.get_transit_bound_attestation() is None


# --- the CLI -------------------------------------------------------------------------------------


@pytest.fixture
def transit_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A SQLite store on fake Transit, closed, with the CLI's environment pointed at it."""
    import asyncio

    _use_fake(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "vault_transit")
    db = tmp_path / "cli.db"

    async def make() -> None:
        await (await _transit_store(db)).close()

    asyncio.run(make())
    return db


def _read(db: Path) -> TransitBoundAttestation | None:
    import asyncio

    async def read() -> TransitBoundAttestation | None:
        s = await _transit_store(db)
        try:
            return await s.get_transit_bound_attestation()
        finally:
            await s.close()

    return asyncio.run(read())


def test_cli_record_and_withdraw_write_audit_rows_with_actor_and_time(
    transit_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = time.time()
    reason = "Transit auto_rotate_period is 720h"
    rc = main(
        ["store", "attest-transit-bound", "--reason", reason, "--db", str(transit_db), "--json"]
    )
    assert rc == 0, capsys.readouterr()
    out = json.loads(capsys.readouterr().out)
    actor = f"cli:{getpass.getuser()}"
    assert out["action"] == "attested" and out["attestation"]["key_name"] == _KEY_NAME

    recorded = _read(transit_db)
    assert recorded is not None
    assert (recorded.key_name, recorded.reason, recorded.actor) == (_KEY_NAME, reason, actor)
    assert recorded.attested_at >= before

    [attested] = _audit_rows(transit_db, TRANSIT_BOUND_ATTESTED_ACTION)
    assert attested["actor"] == actor and attested["ts"] >= before
    assert json.loads(attested["detail"]) == {"key_name": _KEY_NAME, "reason": reason}

    assert main(["store", "withdraw-transit-bound", "--db", str(transit_db)]) == 0
    assert "withdrew" in capsys.readouterr().out
    assert _read(transit_db) is None
    [withdrawn] = _audit_rows(transit_db, TRANSIT_BOUND_WITHDRAWN_ACTION)
    assert withdrawn["actor"] == actor and withdrawn["ts"] >= attested["ts"]
    detail = json.loads(withdrawn["detail"])
    assert detail["key_name"] == _KEY_NAME and detail["attested_by"] == actor


def test_cli_record_refuses_a_blank_reason(
    transit_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["store", "attest-transit-bound", "--reason", "  ", "--db", str(transit_db)])
    assert rc == 1
    assert "--reason" in capsys.readouterr().err
    assert _read(transit_db) is None


def test_cli_record_refuses_a_store_not_on_vault_transit(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "aesgcm")
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    assert rc == 1
    assert "vault_transit" in capsys.readouterr().err


# --- GET /security/posture -----------------------------------------------------------------------


async def _posture(store: MessageStore) -> dict[str, object]:
    engine = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
    service = AuthService(store, AuthSettings(require_mfa=False))
    await service.initialize()
    if await store.get_user_by_username("vw") is None:
        await _add_viewer(service, store)
    app = create_app(
        engine,
        auth=service,
        ai_settings=AiSettings(environment="dev"),
        store_settings=StoreSettings(cipher_provider="vault_transit"),
        security_settings=SecuritySettings(require_mfa=False),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        login = await c.post(
            "/auth/login", json={"username": "vw", "password": PW, "provider": "local"}
        )
        headers = {"Authorization": f"Bearer {login.json()['token']}"}
        body: dict[str, object] = (await c.get("/security/posture", headers=headers)).json()
    return body


async def _add_viewer(service: AuthService, store: MessageStore) -> None:
    user_id = await create_local_user_chosen(
        service,
        username="vw",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="test",
    )
    user = await store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


async def test_posture_reports_the_attestation(store: MessageStore) -> None:
    unattested = await _posture(store)
    assert unattested["transit_bound_attestation"] == {
        "key_name": _KEY_NAME,
        "attested": False,
        "attested_key_name": None,
        "attested_by": None,
        "attested_at": None,
        "reason": None,
    }
    recorded = await _attest(store)
    view = (await _posture(store))["transit_bound_attestation"]
    assert isinstance(view, dict)
    assert view["attested"] is True and view["attested_by"] == "cli:tester"
    assert view["attested_at"] == recorded.attested_at


async def test_posture_reports_no_attestation_off_vault_transit(tmp_path: Path) -> None:
    keyless = await MessageStore.open(tmp_path / "plain.db")
    try:
        assert (await _posture(keyless))["transit_bound_attestation"] is None
    finally:
        await keyless.close()
