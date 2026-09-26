# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1905 -- a keyless audit chain on a keyed store must never be silent.

The defect, reproduced at engine ``fcbe2f93a`` with synthetic data: ``provision-admin`` opened the
store with ``create=True`` and no key check, so with no key in the shell running it the store came up
under the identity cipher. ``_load_audit_chain_meta`` wrote no keying watermark, the provisioning
audit row was keyless SHA-256, and a later keyed open auto-keys only an EMPTY ``audit_log``. The chain
therefore stayed keyless for good, nothing reported it, and a forged row verified clean. The
documented install order (``docs/SECURITY.md``, ``docs/DEPLOYMENT.md``) runs ``provision-admin``
before the first ``serve``, and the service key lives in the NSSM environment, not the admin's shell.

Two layers, both pinned here:

1. ``provision-admin`` applies the same no-key refusal ``serve`` applies, before it opens anything.
2. A keyed-capable store that opens onto a keyless chain with rows logs a WARNING naming
   ``rekey-audit`` and reports the state through ``security_loosenings()`` and
   ``GET /security/posture``. It does NOT re-key the rows at open: the existing docstring forbids
   silent re-keying, because a forged row would be blessed into a keyed chain.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a first deployment
following the documented order would have inherited.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecretRotationSettings,
    SecuritySettings,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore, audit_row_hash
from tests.test_provision_first_administrator import _tty

_PASSWORD = "a-long-enough-operator-passphrase"

#: At least the at-rest variables that decide these tests, cleared so a developer's own shell cannot.
_AT_REST_ENV = (
    "MEFOR_STORE_ENCRYPTION_KEY",
    "MEFOR_STORE_ENCRYPTION_KEY_FILE",
    "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
    "MEFOR_STORE_KEY_PROVIDER",
    "MEFOR_STORE_CIPHER_PROVIDER",
    "MEFOR_STORE_ALLOW_UNENCRYPTED_PHI",
    "MEFOR_STORE_REQUIRE_ENCRYPTION",
    "MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI",
    "MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI_UNDER_STRICT_ENFORCEMENT",
    "MEFOR_SECURITY_ENCRYPT_STORED_DATA",
    "MEFOR_SECURITY_ENFORCEMENT",
)


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    return tmp_path


# --- layer 1: provision-admin refuses a keyless open, as serve does ---------------------------------


def test_provision_admin_refuses_with_no_key_in_the_shell(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The documented order with the key only in the service environment. It must refuse, say that
    the key belongs in THIS shell, and create nothing -- a store left behind would be keyless."""
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = shell / "provision.db"
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    assert rc != 0
    error = json.loads(capsys.readouterr().out)["error"]
    assert "MEFOR_STORE_ENCRYPTION_KEY" in error
    assert "shell" in error, "the refusal must say where the key has to be"
    assert "gen-key" not in error, "the service already holds a key; a new one would not match it"
    assert not db.exists(), "a refused provision must not leave a keyless store behind"


def test_provision_admin_honours_the_same_audited_opt_out_serve_does(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Same gate, same override -- but never quietly. A stale opt-out left in a shell is exactly how a
    keyed store would get a keyless first row, so proceeding keyless says so."""
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI", "true")
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI_UNDER_STRICT_ENFORCEMENT", "true")
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = shell / "optout.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"]) == 0
    assert "KEYLESS" in capsys.readouterr().err


def test_the_documented_order_with_the_key_in_the_shell_keys_the_chain_from_row_1(
    shell: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The closing test the item names: provision first, then open as serve would. Row 1 -- the
    provisioning audit row -- is an HMAC, not the forgeable keyless SHA-256."""
    key = generate_key()
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = shell / "keyed.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"]) == 0

    async def check() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        try:
            assert store._audit_keyed_from == 1
            assert store.audit_chain_unkeyed() is False
            ok, msg = await store.verify_audit_chain()
            assert ok, msg
            cur = await store._db.execute(
                "SELECT ts, actor, action, channel_id, detail, client, row_hash"
                " FROM audit_log ORDER BY id LIMIT 1"
            )
            row = await cur.fetchone()
            assert row is not None
            keyless = audit_row_hash(
                "",
                ts=row["ts"],
                actor=row["actor"],
                action=row["action"],
                channel_id=row["channel_id"],
                detail=row["detail"],
                client=row["client"],
            )
            assert row["row_hash"] != keyless
        finally:
            await store.close()

    asyncio.run(check())


# --- layer 2: a keyless chain on a keyed store is reported, never silently re-keyed ------------------


async def _keyless_rows(path: Path, n: int) -> None:
    store = await MessageStore.open(path)
    try:
        for i in range(n):
            await store.record_audit("legacy", actor="u", detail=f'{{"n":{i}}}')
    finally:
        await store.close()


async def test_a_keyless_chain_on_a_keyed_store_warns_and_is_reported(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "flag.db"
    await _keyless_rows(path, 2)
    cipher = make_cipher(generate_key())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        store = await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
    try:
        assert store._audit_keyed_from is None, "open must not re-key existing rows"
        assert store.audit_chain_unkeyed() is True
        warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("rekey-audit" in m and "keyless" in m.lower() for m in warned), warned

        # The operator's documented remedy clears it, and nothing else does.
        ok, msg = await store.rekey_audit_chain()
        assert ok, msg
        assert store.audit_chain_unkeyed() is False
    finally:
        await store.close()


async def test_the_flag_discriminates_keyless_by_choice_and_keyed_from_fresh(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Two controls that must stay quiet, so the flag above is not firing on everything."""
    # A keyless store with no key at all: keyless by the operator's (audited) choice, not a gap the
    # key would close -- the at-rest loosening already reports that state.
    plain = tmp_path / "plain.db"
    await _keyless_rows(plain, 2)
    store = await MessageStore.open(plain)
    try:
        assert store.audit_chain_unkeyed() is False
    finally:
        await store.close()
    # A fresh keyed store auto-keys from row 1 and has nothing to report.
    cipher = make_cipher(generate_key())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        fresh = await MessageStore.open(
            tmp_path / "fresh.db", cipher=cipher, audit_mac_key=cipher.audit_mac_key()
        )
    try:
        assert fresh.audit_chain_unkeyed() is False
        assert not [r for r in caplog.records if "rekey-audit" in r.getMessage()]
    finally:
        await fresh.close()


def _loosening_names(audit_chain_unkeyed: bool | None) -> set[str]:
    return {
        name
        for name, _ in security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            store_privilege=None,
            audit_chain_unkeyed=audit_chain_unkeyed,
        )
    }


def test_security_loosenings_reports_the_keyless_chain_only_when_observed() -> None:
    assert "audit_chain_unkeyed" in _loosening_names(True)
    assert "audit_chain_unkeyed" not in _loosening_names(False)
    assert "audit_chain_unkeyed" not in _loosening_names(None)


async def test_the_posture_route_reports_what_the_open_store_observed(tmp_path: Path) -> None:
    """GET /security/posture reads the observation off the LIVE store, not off settings: the
    settings alone cannot know what the audit_log already holds."""
    from messagefoundry.config.settings import AiSettings
    from messagefoundry.pipeline import Engine
    from tests.test_api_security_posture import _add_viewer, _app_and_client, _service, _token

    engine = await Engine.create(tmp_path / "posture.db", poll_interval=0.02)
    try:
        service = await _service(engine)
        await _add_viewer(service, "vw")
        ai = AiSettings(environment="prod")

        async def switches() -> set[str]:
            _app, client = _app_and_client(
                engine, service, ai_settings=ai, security_settings=SecuritySettings()
            )
            async with client as c:
                body = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()
            return {row["switch"] for row in body["loosenings"]}

        assert "audit_chain_unkeyed" not in await switches()
        # Stand in for the open-time observation; the store-side detection is pinned above.
        engine.store._audit_chain_unkeyed = True  # type: ignore[attr-defined]
        assert "audit_chain_unkeyed" in await switches()
    finally:
        await engine.stop()


@pytest.mark.parametrize(
    ("backend", "rows"), [(b, n) for b in ("postgres", "sqlserver") for n in (0, 3)]
)
async def test_both_server_backends_report_a_keyless_chain_on_a_keyed_store(
    backend: str, rows: int, caplog: pytest.LogCaptureFixture
) -> None:
    """The server twins, offline, through the same bare-instance seam the Transit rider uses. The
    live-database legs of these backends run only on a hosted runner."""
    import contextlib
    from typing import Any

    from tests.test_asvs_transit_audit_mac_server_backends import _bare

    store = _bare(backend, mac_key=b"k" * 32)
    store._audit_chain_unkeyed = False
    written: list[str] = []

    async def _fetchone(sql: str, *_a: Any, **_kw: Any) -> Any:
        return {"keyed_from_id": None} if "keyed_from_id" in sql else {"n": rows}

    class _Conn:
        async def fetchrow(self, sql: str, *_a: Any) -> Any:
            return await _fetchone(sql)

        async def execute(self, sql: str, *_a: Any) -> None:
            written.append(sql)

    @contextlib.asynccontextmanager
    async def _conn() -> Any:
        yield _Conn()

    @contextlib.asynccontextmanager
    async def _cursor(conn: Any) -> Any:
        yield conn

    async def _commit(_conn: Any) -> None:
        return None

    store._fetchone = _fetchone
    store._timed_acquire = _conn
    store._acquire = _conn
    store._cursor = _cursor
    store._commit = _commit
    with caplog.at_level(logging.WARNING):
        await store._load_audit_chain_meta()
    warned = any("rekey-audit" in r.getMessage() for r in caplog.records)
    if rows == 0:
        # The control arm: a fresh keyed store still auto-keys from row 1 and reports nothing.
        assert store._audit_keyed_from == 1, f"{backend}: a fresh keyed store must key from row 1"
        assert any("audit_chain_meta" in s for s in written)
        assert store.audit_chain_unkeyed() is False and not warned
    else:
        assert store._audit_keyed_from is None, f"{backend}: open must not re-key existing rows"
        assert written == [], f"{backend}: nothing may be written at open"
        assert store.audit_chain_unkeyed() is True and warned


def test_provision_admin_refuses_a_configured_key_the_provider_did_not_resolve(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The gate reads settings; the store resolves its key through ``[store].key_provider``. A pinned
    ``env`` provider ignores a configured key FILE, so the settings say "keyed" while the store opens
    keyless. The command must refuse before the first audit row, not provision into that chain."""
    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", "env")
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY_FILE", str(shell / "service.key"))
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = shell / "mismatch.db"
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    out = capsys.readouterr().out
    assert rc != 0, out
    assert "resolved no key" in json.loads(out)["error"]

    async def no_audit_rows() -> int:
        store = await MessageStore.open(db)
        try:
            cur = await store._db.execute("SELECT COUNT(*) AS n FROM audit_log")
            row = await cur.fetchone()
            return int(row["n"]) if row is not None else -1
        finally:
            await store.close()

    assert asyncio.run(no_audit_rows()) == 0
