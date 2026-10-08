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
from messagefoundry.pipeline.alerts import LoggingAlertSink
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
    one, as the real engine does, and each version MACs under its own secret. A version above the
    latest is refused with HTTP 400, as real Transit refuses it."""

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
        if key_version is not None and key_version > self.latest:
            # The [vault] extra's class, which the cipher classifies on. Only a test that pins an
            # unheld version reaches this, and _needs_hvac() skips those without the extra.
            from hvac.exceptions import InvalidRequest  # type: ignore[import-untyped]

            raise InvalidRequest("cannot generate HMAC: invalid key version")
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


#: A Transit key version the fake does not hold, as a DML writer would plant it.
_UNHELD_VERSION = 9999999
_PLANTED = f"vault:v{_UNHELD_VERSION}:AAAA"


def _needs_hvac() -> None:
    """Skip without the [vault] extra: the cipher tells a refused version by hvac's own class."""
    pytest.importorskip("hvac.exceptions")


async def test_a_transit_refusal_of_a_forged_key_version_is_a_gap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A DML writer sets both hashes to a key version Transit does not hold. Transit refuses the
    pinned recompute; that must read as unattested, so a warn start still starts."""
    _needs_hvac()
    _use_fake(monkeypatch, _RotatingTransit())
    db = tmp_path / "forged-version.db"
    store = await _transit_store(db)
    recorded = await _attest(store)
    await store.close()
    _dml(db, "UPDATE transit_bound_attestation SET audit_hash = ? WHERE id = 1", (_PLANTED,))
    _dml(db, "UPDATE audit_log SET row_hash = ? WHERE seq = ?", (_PLANTED, recorded.audit_seq))
    again = await _transit_store(db)
    try:
        got = await again.get_transit_bound_attestation()
    except BaseException:
        await again.close()
        raise
    assert got is not None and got.audit_gap is not None and "Transit refused" in got.audit_gap
    await _start(again, SecurityEnforcement.WARN)  # no raise


# --- a planted key version on the audit chain is a break, not a walk that could not run ----------


class _StartupSink(LoggingAlertSink):
    """Records every ``integrity_drift`` the startup audit walk fires."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        self.events.append((name, reason))


async def _chain_with_a_planted_version(db: Path) -> int:
    """A Transit store whose audit chain has one middle row naming a key version Transit does not
    hold, as a DML writer would plant it. Returns that row's sequence number."""
    _needs_hvac()
    store = await _transit_store(db)
    try:
        await store.record_audit("test.planted", actor="cli:tester")
        await store.record_audit("test.after", actor="cli:tester")
    finally:
        await store.close()
    con = sqlite3.connect(db)
    try:
        (seq,) = con.execute("SELECT seq FROM audit_log WHERE action = 'test.planted'").fetchone()
    finally:
        con.close()
    _dml(db, "UPDATE audit_log SET row_hash = ? WHERE seq = ?", (_PLANTED, seq))
    return int(seq)


async def _walk_on_start(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> tuple[_StartupSink, list[str]]:
    """Run only the engine's startup audit check, returning the alerts and the engine's log lines."""
    sink = _StartupSink()
    engine = Engine(
        store,
        alert_sink=sink,
        audit_verify_on_start=True,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.engine"):
        await engine._verify_audit_chain_on_start()
    lines = [r.getMessage() for r in caplog.records if r.name == "messagefoundry.pipeline.engine"]
    # Proves the capture saw the walk at all, so an absent "could not run" line means something.
    assert any("startup audit-chain verification" in line for line in lines), lines
    return sink, lines


async def test_a_planted_unheld_key_version_is_a_chain_break_on_the_startup_walk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A DML writer names a Transit key version Transit does not hold. Transit refuses the pinned
    recompute, and that is the row's own evidence: the startup walk must raise the tamper alert at
    that row, never stop with "could not run" and no alert (the sixth defect on PR 2167)."""
    _use_fake(monkeypatch, _RotatingTransit())
    db = tmp_path / "planted.db"
    seq = await _chain_with_a_planted_version(db)
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert not ok and f"seq={seq}," in str(msg), msg
    assert f"key version {_UNHELD_VERSION}" in str(msg), msg
    assert [name for name, _ in sink.events] == ["audit-chain"], sink.events
    assert f"seq={seq}," in sink.events[0][1], sink.events
    assert not any("could not run" in line for line in lines), lines


async def test_a_planted_unheld_key_version_on_the_genesis_row_opens_and_reads_as_a_break(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The open MACs the genesis row too. A planted version there must not stop the open; the
    walk reports the break at row 1."""
    _use_fake(monkeypatch, _RotatingTransit())
    db = tmp_path / "planted-genesis.db"
    await _chain_with_a_planted_version(db)
    _dml(db, "UPDATE audit_log SET row_hash = ? WHERE seq = 1", (_PLANTED,))
    store = await _transit_store(db)
    try:
        ok, msg = await store.verify_audit_chain()
    finally:
        await store.close()
    assert not ok and "seq=1," in str(msg), msg


async def test_a_transit_outage_on_the_startup_walk_still_could_not_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Transit unreachable is not evidence about any row: the walk could not run, and no tamper
    alert fires."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "outage.db"
    await _chain_with_a_planted_version(db)
    store = await _transit_store(db)

    def unreachable(**_kw: Any) -> dict[str, Any]:
        raise httpx.ConnectError("Vault is unreachable")

    monkeypatch.setattr(transit, "generate_hmac", unreachable)
    try:
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert sink.events == []
    assert any("could not run" in line for line in lines), lines


async def test_a_transient_failure_of_a_pinned_call_is_not_a_planted_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A dropped connection on a pinned call, while the latest version still answers, must not
    read as a refused key version. Only Transit's 400 for the version is that; anything else is a
    check that could not run, so a clean row is never reported as tampered."""
    transit = _RotatingTransit()
    _use_fake(monkeypatch, transit)
    db = tmp_path / "transient.db"
    store = await _transit_store(db)
    await store.record_audit("test.clean", actor="cli:tester")
    real = transit.generate_hmac

    def drop_pinned(**kw: Any) -> dict[str, Any]:
        if kw.get("key_version") is not None:
            raise httpx.ConnectError("connection reset")
        return real(**kw)

    monkeypatch.setattr(transit, "generate_hmac", drop_pinned)
    try:
        sink, lines = await _walk_on_start(store, caplog)
    finally:
        await store.close()
    assert sink.events == []
    assert any("could not run" in line for line in lines), lines


def _pinned_refusal(answer: Any) -> CipherError:
    """What the cipher raises when a pinned call gets Transit's 400 and the probe gets ``answer``
    (a reply, or an exception to raise)."""
    _needs_hvac()
    from hvac.exceptions import InvalidRequest

    from messagefoundry.store.crypto_transit import TransitCipher
    from tests.test_crypto_transit import _FakeClient

    class _Transit(_FakeTransit):
        def generate_hmac(self, **kw: Any) -> dict[str, Any]:
            if kw.get("key_version") is not None:
                raise InvalidRequest("bad request")
            if isinstance(answer, Exception):
                raise answer
            return {"data": {"hmac": answer}}

    cipher = TransitCipher(_FakeClient(_Transit()), _KEY_NAME)
    with pytest.raises(CipherError) as caught:
        cipher.audit_hmac(b"row", key_version=3)
    return caught.value


def test_a_pinned_400_with_a_working_probe_is_a_refused_version() -> None:
    from messagefoundry.store.crypto import AuditKeyVersionRefusedError

    assert isinstance(_pinned_refusal("vault:v2:AAAA"), AuditKeyVersionRefusedError)


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(RuntimeError("key not found"), id="probe-fails"),
        pytest.param("vault:v3:AAAA", id="probe-names-the-same-version"),
    ],
)
def test_a_pinned_400_the_probe_does_not_clear_is_a_plain_cipher_error(answer: Any) -> None:
    """A missing key also answers 400, and so may a refusal that has nothing to do with the version.
    Neither may read as a planted version, or a clean chain would read as tampered."""
    from messagefoundry.store.crypto import AuditKeyVersionRefusedError

    assert not isinstance(_pinned_refusal(answer), AuditKeyVersionRefusedError)


def test_a_refused_key_version_survives_a_pickle_with_its_text() -> None:
    import pickle

    from messagefoundry.store.crypto import AuditKeyVersionRefusedError

    exc = AuditKeyVersionRefusedError(7)
    again = pickle.loads(pickle.dumps(exc))
    assert isinstance(again, AuditKeyVersionRefusedError) and isinstance(again, CipherError)
    assert again.version == 7 and str(again) == str(exc)


def test_cli_audit_verify_exits_1_on_a_planted_unheld_key_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import asyncio

    _use_fake(monkeypatch, _RotatingTransit())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "vault_transit")
    db = tmp_path / "planted-cli.db"
    seq = asyncio.run(_chain_with_a_planted_version(db))
    rc = main(["audit-verify", "--db", str(db)])
    captured = capsys.readouterr()
    assert rc == 1, captured
    assert f"seq={seq}," in captured.out + captured.err, captured


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
    assert "stop it and re-run" in err  # a SQLite lock is the one case the hint is for


def test_cli_a_close_that_fails_after_the_write_does_not_report_it_refused(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The attestation has committed when the close runs, so a failed close warns and the result
    stands: exit 0, not "the store refused the write, so nothing was recorded"."""
    real_close = MessageStore.close

    async def failing_close(self: MessageStore) -> None:
        await real_close(self)
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(MessageStore, "close", failing_close)
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "refused the write" not in captured.err
    assert "closing the store failed" in captured.err
    monkeypatch.setattr(MessageStore, "close", real_close)
    assert _read(transit_db) is not None

    # The withdraw twin: its write has committed too, so the row is gone and the exit is 0.
    monkeypatch.setattr(MessageStore, "close", failing_close)
    rc = main(["store", "withdraw-transit-bound", "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "withdrew" in captured.out, captured.out
    assert "refused the write" not in captured.err
    assert "closing the store failed" in captured.err
    monkeypatch.setattr(MessageStore, "close", real_close)
    assert _read(transit_db) is None


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
    assert "cannot open the store" in err and "refused the write" not in err


# The two commands, each with what it needs to reach the store's write.
_TRANSIT_ARMS = {
    "attest": (
        ["store", "attest-transit-bound", "--reason", "r"],
        "record_transit_bound_attestation",
    ),
    "withdraw": (["store", "withdraw-transit-bound"], "withdraw_transit_bound_attestation"),
}
# A server's text can quote a stored value. Each error below carries this marker in its text, and
# no line the commands print may carry it.
_ROW_TEXT = "ROWMARKER"


def _stand_in_server_drivers(monkeypatch: pytest.MonkeyPatch) -> None:
    """The stand-ins from the audit-verify tests, with pyodbc's root stand-in also read as a server
    driver's error, as the real ``pyodbc.Error`` is. pyodbc is not installed on every leg."""
    from messagefoundry.store import base as store_base
    from tests.test_keyless_chain_every_command import (
        _PyodbcError,
        _ServerDriverError,
        _stand_in_drivers,
    )

    _stand_in_drivers(monkeypatch)
    real = store_base._is_server_driver_error
    monkeypatch.setattr(
        store_base,
        "_is_server_driver_error",
        lambda exc: isinstance(exc, (_ServerDriverError, _PyodbcError)) or real(exc),
    )


def _open_error(kind: str) -> Exception:
    """Built per test, so no instance carries one test's traceback into the next."""
    from tests.test_keyless_chain_every_command import _InterfaceError, _ServerDriverError

    if kind == "login":
        return _InterfaceError(
            "28000", f"[28000] Login failed for user '{_ROW_TEXT}' (18456) (SQLDriverConnect)"
        )
    return _ServerDriverError("42P01", f'relation "{_ROW_TEXT}" does not exist')


@pytest.mark.parametrize("arm", list(_TRANSIT_ARMS))
@pytest.mark.parametrize("kind", ["login", "relation"])
def test_cli_a_server_driver_error_at_the_open_is_exit_2_and_its_text_is_not_printed(
    arm: str,
    kind: str,
    transit_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failed login (pyodbc's InterfaceError) or a missing relation at the open is "could not
    start", exit 2, in the line the audit commands print, with the error's class and SQLSTATE and
    never the server's text."""
    import messagefoundry.store.base as store_base

    _stand_in_server_drivers(monkeypatch)
    error = _open_error(kind)

    async def refusing(*_a: object, **_k: object) -> object:
        raise error

    monkeypatch.setattr(store_base, "open_store", refusing)
    argv, _ = _TRANSIT_ARMS[arm]
    rc = main([*argv, "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 2, captured.err
    assert f"cannot open the store at {transit_db}: " in captured.err, captured.err
    assert f"SQLSTATE {error.args[0]}" in captured.err, captured.err
    assert _ROW_TEXT not in captured.out + captured.err
    assert "refused the write" not in captured.err


@pytest.mark.parametrize("arm", list(_TRANSIT_ARMS))
def test_cli_a_deadlock_at_the_write_is_a_refused_write_and_its_text_is_not_printed(
    arm: str, transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """pyodbc raises its bare Error root for a deadlock victim (40001). The server rolled the
    transaction back, so it is a refused write, exit 1, rendered as its class, SQLSTATE and native
    number. The stop-the-engine hint is for a SQLite lock only."""
    from tests.test_keyless_chain_every_command import _PyodbcError

    _stand_in_server_drivers(monkeypatch)
    argv, method = _TRANSIT_ARMS[arm]

    async def refusing(*_a: object, **_k: object) -> object:
        raise _PyodbcError("40001", f"[40001] deadlock on {_ROW_TEXT} (1205) (SQLExecDirectW)")

    monkeypatch.setattr(MessageStore, method, refusing)
    rc = main([*argv, "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 1, captured.err
    assert "refused the write" in captured.err, captured.err
    assert "SQLSTATE 40001] native error 1205" in captured.err, captured.err
    assert _ROW_TEXT not in captured.out + captured.err
    assert "stop it and re-run" not in captured.err
    if arm == "withdraw":
        assert "nothing was withdrawn, and any attestation on record still stands" in captured.err


@pytest.mark.parametrize("arm", list(_TRANSIT_ARMS))
def test_cli_a_link_lost_at_the_write_reports_an_unknown_outcome(
    arm: str, transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A lost link (SQLSTATE 08S01, a DatabaseError subclass in pyodbc) may land after the server
    applied the COMMIT, so the line claims neither outcome. Exit 1, and the driver's text hidden."""
    from tests.test_keyless_chain_every_command import _ServerDriverError

    _stand_in_server_drivers(monkeypatch)
    argv, method = _TRANSIT_ARMS[arm]

    async def refusing(*_a: object, **_k: object) -> object:
        raise _ServerDriverError(
            "08S01", f"[08S01] link failure reading {_ROW_TEXT} (10054) (SQLExecDirectW)"
        )

    monkeypatch.setattr(MessageStore, method, refusing)
    rc = main([*argv, "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 1, captured.err
    assert "whether it took effect is unknown" in captured.err, captured.err
    assert "SQLSTATE 08S01] native error 10054" in captured.err, captured.err
    assert "nothing was" not in captured.err
    assert _ROW_TEXT not in captured.out + captured.err


@pytest.mark.parametrize("arm", list(_TRANSIT_ARMS))
def test_cli_pyodbcs_bare_error_root_at_the_write_is_a_defect_not_a_refused_write(
    arm: str,
    transit_db: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """pyodbc raises its bare ``Error`` root for a SQLSTATE it does not map, such as 07002, a bind
    count that does not match the statement: a defect in the code. The write arm counts the root as
    a refusal only with a transient SQLSTATE, so the dispatch floor reports this one."""
    from tests.test_keyless_chain_every_command import _PyodbcError

    _stand_in_server_drivers(monkeypatch)
    argv, method = _TRANSIT_ARMS[arm]

    async def defect(*_a: object, **_k: object) -> object:
        raise _PyodbcError("07002", f"[07002] COUNT field incorrect near {_ROW_TEXT}")

    monkeypatch.setattr(MessageStore, method, defect)
    rc = main([*argv, "--db", str(transit_db), "--json"])
    captured = capsys.readouterr()
    assert rc == 1, captured.err
    assert "refused the write" not in captured.out + captured.err
    # The dispatch floor's line names the defect by class and SQLSTATE, never the server's text.
    assert "_StoreDefect: _PyodbcError [SQLSTATE 07002]" in captured.out, captured.out
    assert _ROW_TEXT not in captured.out + captured.err + caplog.text


def test_cli_a_sqlite_bind_count_error_at_the_write_is_a_defect(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """SQLite's own bind-count error is a ProgrammingError, a DatabaseError subclass, but a defect
    in the code all the same: the dispatch floor reports it, not "refused the write"."""

    async def defect(*_a: object, **_k: object) -> object:
        raise sqlite3.ProgrammingError("Incorrect number of bindings supplied")

    monkeypatch.setattr(MessageStore, "record_transit_bound_attestation", defect)
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    captured = capsys.readouterr()
    assert rc == 1, captured.err
    assert "refused the write" not in captured.out + captured.err


def test_cli_a_schema_not_provisioned_refusal_prints_its_remedy_in_full(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An engine refusal at the open is printed whole: ``SchemaNotProvisionedError`` is longer
    than ``safe_exc``'s cap, and its remedy, the provision-schema command, comes late in it. This
    build moves the schema hash, so it is the expected first run of either command on a server
    store."""
    import messagefoundry.store.base as store_base
    from messagefoundry.config.settings import StoreBackend

    refusal = store_base.SchemaNotProvisionedError(StoreBackend.SQLSERVER, "mefor", "a" * 64)
    assert len(str(refusal)) > 200  # the control: safe_exc would have cut it

    async def refusing(*_a: object, **_k: object) -> object:
        raise refusal

    monkeypatch.setattr(store_base, "open_store", refusing)
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    err = capsys.readouterr().err
    assert rc == 2, err
    assert f"cannot open the store at {transit_db}: {refusal}" in err, err
    assert f"run `{store_base.PROVISION_SCHEMA_COMMAND}`" in err


async def _real_rcsi_refusal(monkeypatch: pytest.MonkeyPatch, driver: Exception) -> RuntimeError:
    """The refusal ``SqlServerStore._ensure_database_options`` itself raises when the RCSI ALTER
    fails with ``driver`` and no peer turned RCSI on, over an ``aioodbc`` stand-in, so the test
    reads the production message rather than a copy of its format string."""
    import sys
    import types

    import messagefoundry.store.sqlserver as sqlserver_module
    from messagefoundry.config.settings import SchemaManagement, StoreBackend
    from messagefoundry.store.sqlserver import SqlServerStore

    class Cursor:
        async def execute(self, sql: str, *_params: object) -> None:
            if sql.startswith("ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT"):
                raise driver

        async def fetchone(self) -> tuple[int, int]:
            return (0, 0)  # RCSI off, on every read

    class Conn:
        async def cursor(self) -> Cursor:
            return Cursor()

        async def close(self) -> None:
            return None

    async def connect(**_kwargs: object) -> Conn:
        return Conn()

    module = types.ModuleType("aioodbc")
    module.connect = connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    monkeypatch.setattr(sqlserver_module, "_RCSI_REREAD_DELAY_S", 0.0)
    settings = StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="localhost",
        database="mefor",
        username="sa",
        schema_management=SchemaManagement.AUTO,
    )
    with pytest.raises(RuntimeError, match="READ_COMMITTED_SNAPSHOT is OFF") as info:
        await SqlServerStore._ensure_database_options(settings)
    return info.value


def test_cli_an_engine_refusal_quoting_a_driver_error_prints_the_remedy_not_the_driver_text(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The SQL Server open's READ_COMMITTED_SNAPSHOT refusal quotes the driver error it was raised
    from. Its remedy prints; the quoted driver text is replaced by the error's class, SQLSTATE and
    native number."""
    import asyncio

    import messagefoundry.store.base as store_base
    from messagefoundry.store.sqlserver import _rcsi_remedy
    from tests.test_keyless_chain_every_command import _ServerDriverError

    _stand_in_server_drivers(monkeypatch)
    driver = _ServerDriverError(
        "42000", f"[42000] permission denied on {_ROW_TEXT} (5011) (SQLExecDirectW)"
    )
    refusal = asyncio.run(_real_rcsi_refusal(monkeypatch, driver))
    assert _ROW_TEXT in str(refusal)  # the control: the refusal does quote the driver's text

    async def refusing(*_a: object, **_k: object) -> object:
        raise refusal

    monkeypatch.setattr(store_base, "open_store", refusing)
    rc = main(["store", "withdraw-transit-bound", "--db", str(transit_db)])
    err = capsys.readouterr().err
    assert rc == 2, err
    assert _rcsi_remedy("mefor") in err, err
    assert "(_ServerDriverError [SQLSTATE 42000] native error 5011)" in err, err
    assert _ROW_TEXT not in err


def test_cli_record_refuses_a_store_not_on_vault_transit(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "aesgcm")
    rc = main(["store", "attest-transit-bound", "--reason", "r", "--db", str(transit_db)])
    assert rc == 1
    assert "vault_transit" in capsys.readouterr().err


def test_cli_a_runtime_error_the_engine_did_not_write_is_rendered_safely(
    transit_db: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only the engine's own refusals print whole. A RuntimeError subclass from elsewhere, such as
    ``NotImplementedError``, and a plain RuntimeError raised outside engine code (here, by this
    test, standing in for a library) go through ``safe_exc``, which bounds its length."""
    import messagefoundry.store.base as store_base

    for error in (NotImplementedError("x" * 400), RuntimeError("x" * 400)):

        async def refusing(*_a: object, _error: Exception = error, **_k: object) -> object:
            raise _error

        monkeypatch.setattr(store_base, "open_store", refusing)
        rc = main(["store", "withdraw-transit-bound", "--db", str(transit_db)])
        err = capsys.readouterr().err
        assert rc == 2, err
        assert type(error).__name__ in err and "x" * 400 not in err, err


def test_a_refusal_quoting_its_cause_by_repr_renders_the_cause_once() -> None:
    """A refusal that quotes its cause with ``!r`` gets one rendering, not a rendering nested in
    another, and the remedy after it survives."""
    from messagefoundry.__main__ import _engine_refusal_text

    try:
        try:
            raise OSError("reset by peer")
        except OSError as exc:
            raise RuntimeError(f"could not connect: {exc!r}; ask a DBA") from exc
    except RuntimeError as refusal:
        text = _engine_refusal_text(refusal)
    assert text.count("reset by peer") == 1, text
    assert text.endswith("; ask a DBA"), text


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
