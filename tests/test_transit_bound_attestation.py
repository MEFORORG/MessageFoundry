# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The vault_transit AES-GCM bound attestation (BACKLOG #2337, owner rulings 2026-10-07).

On ``vault_transit`` the engine counts no AES-GCM invocations, so ``serve`` needs a recorded, audited
attestation naming the configured Transit data key. These tests run the SQLite store over the fake
Transit from ``tests/test_crypto_transit.py``; the SQL Server and Postgres twins run in
``tests/test_transit_bound_attestation_server_backends.py`` on the CI legs that have those servers.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import logging
import sqlite3
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

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
from messagefoundry.store.crypto import CipherError
from messagefoundry.store.store import MessageStore
from messagefoundry.store.transit_attestation import (
    TRANSIT_BOUND_ATTESTED_ACTION,
    TRANSIT_BOUND_WITHDRAWN_ACTION,
    TransitBoundAttestation,
    TransitBoundUnattestedError,
)
from tests._admin_account import create_local_user_chosen
from tests.test_crypto_transit import _KEY_NAME, _FakeTransit, _use_fake

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
        actor="cli:tester",
    )


async def _withdraw(store: MessageStore) -> TransitBoundAttestation | None:
    return await store.withdraw_transit_bound_attestation(actor="cli:tester")


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


# --- the row is bound to its audit row (DML alone forges nothing) --------------------------------


def _dml(db: Path, sql: str, params: tuple[object, ...] = ()) -> None:
    """Write the store file directly, as someone with DML on the table and no audit key would."""
    con = sqlite3.connect(db)
    try:
        con.execute(sql, params)
        con.commit()
    finally:
        con.close()


def _attestation_row(db: Path) -> tuple[object, ...]:
    con = sqlite3.connect(db)
    try:
        row = con.execute(
            "SELECT key_name, reason, actor, attested_at, audit_seq, audit_hash"
            " FROM transit_bound_attestation WHERE id = 1"
        ).fetchone()
    finally:
        con.close()
    assert row is not None
    return tuple(row)


_INSERT = (
    "INSERT OR REPLACE INTO transit_bound_attestation"
    " (id, key_name, reason, actor, attested_at, audit_seq, audit_hash)"
    " VALUES (1, ?, ?, ?, ?, ?, ?)"
)


async def _refused_with(db: Path, needle: str) -> None:
    store = await _transit_store(db)
    got = await store.get_transit_bound_attestation()
    assert got is not None and got.audit_gap is not None and needle in got.audit_gap, got
    with pytest.raises(TransitBoundUnattestedError, match="not backed by its audit row"):
        await _start(store, SecurityEnforcement.ENFORCE)


async def test_a_row_inserted_by_dml_with_no_audit_row_does_not_count(
    store: MessageStore, tmp_path: Path
) -> None:
    await store.close()
    db = tmp_path / "transit.db"
    _dml(db, _INSERT, (_KEY_NAME, "forged", "cli:tester", time.time(), 9999, "0" * 64))
    await _refused_with(db, "not in the audit log")


async def test_a_dml_edit_of_the_key_name_does_not_count(
    store: MessageStore, tmp_path: Path
) -> None:
    await _attest(store, key_name="mefor-store-old")
    await store.close()
    db = tmp_path / "transit.db"
    _dml(db, "UPDATE transit_bound_attestation SET key_name = ? WHERE id = 1", (_KEY_NAME,))
    await _refused_with(db, "different key, reason, actor or time")


async def test_a_row_replayed_after_a_withdraw_does_not_count(
    store: MessageStore, tmp_path: Path
) -> None:
    await _attest(store)
    db = tmp_path / "transit.db"
    saved = _attestation_row(db)
    assert await _withdraw(store) is not None
    await store.close()
    _dml(db, _INSERT, saved)  # the old row, byte for byte, pointing at its real audit row
    await _refused_with(db, "supersedes")


async def test_a_forged_audit_row_does_not_verify(store: MessageStore, tmp_path: Path) -> None:
    """A writer who also appends an audit row cannot seal it: the MAC is computed in Transit."""
    await _attest(store, key_name="mefor-store-old")
    await store.close()
    db = tmp_path / "transit.db"
    con = sqlite3.connect(db)
    try:
        seq, prev = con.execute("SELECT seq, row_hash FROM audit_log ORDER BY seq DESC").fetchone()
        ts = time.time()
        detail = json.dumps({"key_name": _KEY_NAME, "reason": "forged"})
        con.execute(
            "INSERT INTO audit_log (seq, ts, actor, action, channel_id, detail, client, row_hash)"
            " VALUES (?, ?, ?, ?, NULL, ?, NULL, ?)",
            (seq + 1, ts, "cli:tester", TRANSIT_BOUND_ATTESTED_ACTION, detail, "f" * 64),
        )
        con.execute(
            _INSERT.replace("INSERT OR REPLACE", "REPLACE"),
            (_KEY_NAME, "forged", "cli:tester", ts, seq + 1, "f" * 64),
        )
        con.commit()
    finally:
        con.close()
    assert prev  # the chain had a head to forge after
    await _refused_with(db, "MAC does not verify")


class _RotatingTransit(_FakeTransit):
    """Fake Transit with key versions: ``generate_hmac`` uses the latest unless ``key_version`` pins
    one, as the real engine does, and each version MACs under its own secret."""

    def __init__(self) -> None:
        super().__init__()
        self.latest = 1
        self.pinned: list[int | None] = []

    def generate_hmac(
        self,
        *,
        name: str,
        hash_input: str,
        algorithm: str = "sha2-256",
        key_version: int | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        self.pinned.append(key_version)
        version = self.latest if key_version is None else key_version
        secret = self._hmac_secret[name] + version.to_bytes(4, "big")
        digest = hmac.new(secret, base64.b64decode(hash_input), hashlib.sha256).digest()
        return {"data": {"hmac": f"vault:v{version}:" + base64.b64encode(digest).decode("ascii")}}


async def test_rotating_the_transit_key_keeps_the_attestation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The operator attests that they rotate the key, so a rotation must not read as a forgery: the
    check recomputes the audit row's MAC under the version that row names, not Transit's latest."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "rotating.db"
    store = await _transit_store(db)
    await _attest(store)
    await store.close()
    transit.latest = 2  # Transit rotated the key; new MACs are vault:v2:
    again = await _transit_store(db)
    try:
        got = await again.get_transit_bound_attestation()
        # The audit chain walk pins the same way, so the rotation reads as no break there either.
        chain_ok, chain_msg = await again.verify_audit_chain()
    except BaseException:
        await again.close()
        raise
    assert got is not None and got.audit_gap is None, got
    assert chain_ok, chain_msg
    assert 1 in transit.pinned
    await _start(again, SecurityEnforcement.ENFORCE)  # no raise; stopping closes the store


async def test_a_transit_refusal_of_a_forged_key_version_is_a_gap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A DML writer sets both hashes to a key version Transit does not hold. Transit refuses the
    pinned recompute; that must read as unattested, so a warn start still starts."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "forged-version.db"
    store = await _transit_store(db)
    recorded = await _attest(store)
    await store.close()
    forged = "vault:v9999999:AAAA"
    _dml(db, "UPDATE transit_bound_attestation SET audit_hash = ? WHERE id = 1", (forged,))
    _dml(db, "UPDATE audit_log SET row_hash = ? WHERE seq = ?", (forged, recorded.audit_seq))

    real = transit.generate_hmac

    def refuse_unknown(**kw: Any) -> dict[str, Any]:
        if kw.get("key_version") == 9999999:
            raise RuntimeError("key version does not exist")
        return real(**kw)

    monkeypatch.setattr(transit, "generate_hmac", refuse_unknown)
    again = await _transit_store(db)
    try:
        got = await again.get_transit_bound_attestation()
    except BaseException:
        await again.close()
        raise
    assert got is not None and got.audit_gap is not None and "Transit refused" in got.audit_gap
    await _start(again, SecurityEnforcement.WARN)  # no raise


async def test_a_non_numeric_attested_at_is_a_gap_not_a_crash(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """SQLite's REAL affinity keeps text. The row must read as unattested, warn must still start,
    and the withdraw must still remove it."""
    await _attest(store)
    await store.close()
    db = tmp_path / "transit.db"
    _dml(db, "UPDATE transit_bound_attestation SET attested_at = 'x' WHERE id = 1")
    again = await _transit_store(db)
    got = await again.get_transit_bound_attestation()
    assert got is not None and got.audit_gap is not None and "finite" in got.audit_gap
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.transit_attestation"):
        await _start(again, SecurityEnforcement.WARN)  # no raise
    third = await _transit_store(db)
    try:
        assert await _withdraw(third) is not None
        assert await third.get_transit_bound_attestation() is None
        [withdrawn] = _audit_rows(db, TRANSIT_BOUND_WITHDRAWN_ACTION)
        assert json.loads(withdrawn["detail"])["attested_at"] is None
    finally:
        await third.close()


async def test_warn_names_the_audit_gap(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    await store.close()
    db = tmp_path / "transit.db"
    _dml(db, _INSERT, (_KEY_NAME, "forged", "cli:tester", time.time(), 9999, "0" * 64))
    again = await _transit_store(db)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.transit_attestation"):
        await _start(again, SecurityEnforcement.WARN)
    assert any("not backed by its audit row" in r.getMessage() for r in caplog.records)


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
    commits = store.committed_txns
    assert await _withdraw(store) is None
    assert store.committed_txns == commits  # rolled back, not an empty commit
    assert _audit_rows(tmp_path / "transit.db", TRANSIT_BOUND_WITHDRAWN_ACTION) == []
    await _attest(store, key_name="first")
    recorded = await _attest(store, key_name=_KEY_NAME)
    current = await store.get_transit_bound_attestation()
    assert current == recorded and current.audit_gap is None
    assert current.key_name == _KEY_NAME and current.actor == "cli:tester"
    [_, newest] = _audit_rows(tmp_path / "transit.db", TRANSIT_BOUND_ATTESTED_ACTION)
    assert json.loads(newest["detail"])["key_name"] == _KEY_NAME


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


def test_cli_reason_is_bounded_in_utf16_code_units(
    transit_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """600 characters outside the Basic Multilingual Plane are 1200 UTF-16 code units, which SQL
    Server's NVARCHAR(1000) cannot hold, although a code-point count would pass them."""
    reason = "\U0001f512" * 600
    rc = main(["store", "attest-transit-bound", "--reason", reason, "--db", str(transit_db)])
    assert rc == 1
    assert "UTF-16" in capsys.readouterr().err
    assert _read(transit_db) is None


def test_cli_a_write_the_store_refuses_is_exit_1_not_a_failed_open(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A SQLite error from the WRITE, such as a locked file, is a refused write (exit 1), not
    "cannot open the store" (exit 2), although both are sqlite3.DatabaseError."""

    async def locked(*_a: object, **_k: object) -> object:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(MessageStore, "record_transit_bound_attestation", locked)
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    err = capsys.readouterr().err
    assert rc == 1, err
    assert "refused the write" in err and "database is locked" in err
    assert "cannot open" not in err


def test_cli_a_file_that_is_not_a_database_is_exit_2(
    transit_db: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"this is not a SQLite database, just some bytes" * 100)
    rc = main(["store", "withdraw-transit-bound", "--db", str(junk)])
    assert rc == 2
    assert "cannot open the store" in capsys.readouterr().err


def test_cli_a_store_that_cannot_be_reached_is_exit_2(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A server backend refusing the connection fails in the OPEN: exit 2, not a refused write."""
    import messagefoundry.store.base as store_base

    async def unreachable(*_a: object, **_k: object) -> object:
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(store_base, "open_store", unreachable)
    rc = main(["store", "withdraw-transit-bound", "--db", str(transit_db)])
    err = capsys.readouterr().err
    assert rc == 2, err
    assert "could not open the store" in err and "refused the write" not in err


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
        "gap": f"no attestation is recorded for the Transit data key {_KEY_NAME!r}",
        "attested_key_name": None,
        "attested_by": None,
        "attested_at": None,
        "reason": None,
    }
    recorded = await _attest(store)
    view = (await _posture(store))["transit_bound_attestation"]
    assert isinstance(view, dict)
    assert view["attested"] is True and view["gap"] is None
    assert view["attested_by"] == "cli:tester"
    assert view["attested_at"] == recorded.attested_at


async def test_posture_shows_no_attribution_from_an_unbacked_row(
    store: MessageStore, tmp_path: Path
) -> None:
    """A DML-forged row names whoever the forger chose. The posture must not repeat it."""
    await store.close()
    db = tmp_path / "transit.db"
    _dml(db, _INSERT, (_KEY_NAME, "forged", "cli:officer", time.time(), 9999, "0" * 64))
    again = await _transit_store(db)
    try:
        view = (await _posture(again))["transit_bound_attestation"]
    finally:
        await again.close()
    assert isinstance(view, dict)
    assert view["attested"] is False and "not backed" in str(view["gap"])
    assert view["attested_by"] is None and view["reason"] is None
    assert view["attested_key_name"] is None and view["attested_at"] is None


async def test_posture_survives_a_transit_failure(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Vault outage during the MAC check reads as not attested; the rest of the posture still
    answers."""
    import messagefoundry.store.store as store_module

    await _attest(store)

    def boom(*_a: object, **_k: object) -> str | None:
        raise CipherError("Transit audit HMAC failed (key='mefor-store'): ConnectionError")

    # The attestation's MAC check is the only caller of _audit_row_mac on this path; appends
    # (the login's audit rows) hash through audit_row_hash directly.
    monkeypatch.setattr(store_module, "_audit_row_mac", boom)
    view = (await _posture(store))["transit_bound_attestation"]
    assert isinstance(view, dict)
    assert view["attested"] is False and "Transit refused" in str(view["gap"])


async def test_posture_reports_no_attestation_off_vault_transit(tmp_path: Path) -> None:
    keyless = await MessageStore.open(tmp_path / "plain.db")
    try:
        assert (await _posture(keyless))["transit_bound_attestation"] is None
    finally:
        await keyless.close()
