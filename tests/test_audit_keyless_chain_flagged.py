# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1905 -- a keyless audit chain on a keyed store must never be silent.

The defect, reproduced at engine ``fcbe2f93a`` with synthetic data: ``provision-admin`` opened the
store with ``create=True`` and no key check, so with no key in the shell running it the store came up
under the identity cipher. The provisioning audit row was keyless SHA-256, and a later keyed open
starts a keyed chain only in an EMPTY ``audit_log``. The chain
therefore stayed keyless for good, nothing reported it, and a forged row verified clean. The
documented install order (``docs/SECURITY.md``, ``docs/DEPLOYMENT.md``) runs ``provision-admin``
before the first ``serve``, and the service key lives in the NSSM environment, not the admin's shell.

Two layers, both pinned here:

1. ``provision-admin`` applies the same no-key refusal ``serve`` applies, before it opens anything.
2. A keyed-capable store that opens onto a chain that holds keyless rows logs an ERROR and reports
   the state through ``security_loosenings()`` and ``GET /security/posture``. It does NOT re-key
   the rows, at open or by any command: a forged row would be blessed into a keyed chain. Since
   vault BACKLOG #2594 a store that holds a key requires every audit row keyed, so that chain is
   also one ``audit-verify`` reports as broken.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a first deployment
following the documented order would have inherited.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import pytest

from messagefoundry.__main__ import _keyless_store_gate, _store_key_configured, main
from messagefoundry.config.settings import (
    KEYLESS_REFUSED_BY_UNREAD_KEY,
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    EgressSettings,
    SecretRotationSettings,
    SecuritySettings,
    ServiceSettings,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.store.base import open_store, resolve_active_key
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.keyprovider import (
    _EXTERNAL_PROVIDERS,
    KeyProviderError,
    unread_key_refusal,
)
from messagefoundry.store.store import (
    AUDIT_KEY_EPOCH_ACTION,
    MessageStore,
    audit_row_hash,
    load_audit_chain,
)
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
    """The closing test the item names: provision first, then open as serve would. Row 1 is the
    genesis row, and the provisioning audit row after it is an HMAC, not the forgeable keyless
    SHA-256."""
    key = generate_key()
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = shell / "keyed.db"
    assert main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"]) == 0

    async def check() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        try:
            assert store._audit_chain_keyed is True
            assert store.audit_chain_unkeyed() is False
            ok, msg = await store.verify_audit_chain()
            assert ok, msg
            cur = await store._db.execute(
                "SELECT seq, ts, actor, action, channel_id, detail, client, row_hash"
                " FROM audit_log ORDER BY seq LIMIT 2"
            )
            genesis, row = list(await cur.fetchall())
            assert genesis["seq"] == 1 and genesis["action"] == AUDIT_KEY_EPOCH_ACTION
            assert row["seq"] == 2
            keyless = audit_row_hash(
                genesis["row_hash"],
                seq=2,
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


async def test_a_keyless_chain_on_a_keyed_store_is_logged_and_reported(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "flag.db"
    await _keyless_rows(path, 2)
    cipher = make_cipher(generate_key())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        store = await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
    try:
        assert store._audit_chain_keyed is False, "open must not re-key existing rows"
        assert store.audit_chain_unkeyed() is True
        logged = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
        assert any("genesis row" in m and "audit-verify" in m for m in logged), logged
        # The text names no command that would key the rows in place: none exists.
        assert not any("rekey-audit" in m for m in logged), logged

        # Nothing clears it on this store: the chain is a reported break, and stays one.
        ok, msg = await store.verify_audit_chain()
        assert not ok and "genesis row" in (msg or ""), msg
        await store.record_audit("after", actor="u")
        assert store.audit_chain_unkeyed() is True
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
    # A fresh keyed store writes its genesis row and has nothing to report.
    cipher = make_cipher(generate_key())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
        fresh = await MessageStore.open(
            tmp_path / "fresh.db", cipher=cipher, audit_mac_key=cipher.audit_mac_key()
        )
    try:
        assert fresh.audit_chain_unkeyed() is False
        assert not [r for r in caplog.records if "genesis row" in r.getMessage()]
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
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            cert_monitor=CertMonitorSettings(),
            backup=BackupSettings(),
            store_privilege=None,
            audit_chain_unkeyed=audit_chain_unkeyed,
            remote_debug=None,
            startup=None,
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

    engine = await Engine.create(
        tmp_path / "posture.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
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
    from tests.test_asvs_transit_audit_mac_server_backends import _bare, chained_rows, serve_rows

    store = _bare(backend, mac_key=b"k" * 32)
    held = chained_rows([("legacy", None)] * rows)  # written with no key
    before = [dict(r) for r in held]
    serve_rows(store, held)
    with caplog.at_level(logging.WARNING):
        await load_audit_chain(store, read_only=False)
    logged = any("genesis row" in r.getMessage() for r in caplog.records)
    if rows == 0:
        # The control arm: a fresh keyed store writes its genesis row and reports nothing.
        assert store._audit_chain_keyed is True, f"{backend}: a fresh keyed store must be keyed"
        assert [r["action"] for r in held] == [AUDIT_KEY_EPOCH_ACTION]
        assert store.audit_chain_unkeyed() is False and not logged
    else:
        assert store._audit_chain_keyed is False, f"{backend}: open must not re-key existing rows"
        assert held == before, f"{backend}: nothing may be written at open"
        assert store.audit_chain_unkeyed() is True and logged
        ok, message = await store.verify_audit_chain()
        assert not ok and "genesis row" in (message or ""), f"{backend}: {message}"


@pytest.mark.parametrize(
    ("provider", "variable", "reads"),
    [
        ("env", "MEFOR_STORE_ENCRYPTION_KEY_FILE", "MEFOR_STORE_ENCRYPTION_KEY"),
        ("dpapi", "MEFOR_STORE_ENCRYPTION_KEY", "[store].encryption_key_file"),
    ],
)
def test_provision_admin_refuses_a_configured_key_the_provider_did_not_resolve(
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    provider: str,
    variable: str,
    reads: str,
) -> None:
    """A pinned provider ignores the other local key source. Before BACKLOG #2077 the gate read that
    as "keyed", the store opened keyless, and (for ``provision-admin`` only) a check after the open
    refused. The gate now knows which source the provider reads, so it refuses before the password
    prompt and before the open, and leaves no store behind."""
    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", provider)
    value = str(shell / "service.key") if variable.endswith("_FILE") else generate_key()
    monkeypatch.setenv(variable, value)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = shell / "mismatch.db"
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    out = capsys.readouterr().out
    assert rc == 2, out  # BACKLOG #1916: every keyless refusal is "could not start"
    error = json.loads(out)["error"]
    assert f"key_provider={provider!r} reads only {reads}" in error, error
    assert not db.exists(), "the refusal comes before the open, so nothing is created"


# --- BACKLOG #1998: an external key provider is a configured key ------------------------------------
#
# The gate reads settings; it runs before `open_store` and must not need the network, so "keyed" is
# decided by what is CONFIGURED, not by whether the provider resolves. A provider that cannot resolve
# is not waved through keyless: `open_store` raises KeyProviderError before any file exists. The last
# test below pins that half, because the first half is only safe while it holds.

#: The environment the ``vault`` provider reads, cleared so a developer's own Vault wiring cannot
#: turn the fail-closed arm into a live unwrap.
_VAULT_ENV = (
    "MEFOR_STORE_VAULT_ADDR",
    "MEFOR_STORE_VAULT_TOKEN",
    "MEFOR_STORE_VAULT_TRANSIT_KEY",
    "MEFOR_STORE_VAULT_WRAPPED_DEK",
    "MEFOR_STORE_VAULT_CA_FILE",
)


@pytest.mark.parametrize("provider", sorted(_EXTERNAL_PROVIDERS))
def test_an_external_key_provider_counts_as_a_configured_key(provider: str) -> None:
    """``vault`` with no local key used to read as keyless, so the default posture refused to start
    and the only way past was an opt-out that misdescribed a keyed store."""
    assert _store_key_configured(ServiceSettings(store=StoreSettings(key_provider=provider)))


@pytest.mark.parametrize("provider", ["auto", "env", "dpapi"])
def test_a_builtin_provider_with_no_local_key_is_still_keyless(provider: str) -> None:
    """The control arm: a built-in provider sources the key from ``encryption_key`` or its file, so
    with neither set the store is still keyless."""
    assert not _store_key_configured(ServiceSettings(store=StoreSettings(key_provider=provider)))


def test_provision_admin_with_a_vault_provider_is_not_refused_as_keyless(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Through a real command. The keyless refusal must not fire, and with the Vault wiring absent
    from this shell the open must still fail closed and leave no store behind."""
    for name in _VAULT_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", "vault")
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = shell / "vault.db"
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    error = json.loads(capsys.readouterr().out)["error"]
    assert rc != 0, error
    assert "no store key is set in this shell" not in error, "a Vault key is a configured key"
    # The refusal is the Vault one -- not some unrelated failure that also leaves no store.
    assert "MEFOR_STORE_VAULT_TRANSIT_KEY" in error, error
    assert not db.exists(), "a refused open must not leave a store behind"


@pytest.mark.parametrize("provider", sorted(_EXTERNAL_PROVIDERS))
async def test_an_external_provider_that_cannot_resolve_fails_closed_at_open(
    shell: Path, monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    """Counting a provider as keyed before it resolves is safe only because a provider that cannot
    resolve refuses the open, rather than returning no key and opening under the identity cipher."""
    for name in _VAULT_ENV:
        monkeypatch.delenv(name, raising=False)
    db = shell / f"{provider}.db"
    with pytest.raises(KeyProviderError, match=provider):
        await open_store(StoreSettings(key_provider=provider, path=str(db)), create=True)
    assert not db.exists(), "a refused open must not leave a store behind"


# --- BACKLOG #2077: a key counts only when the configured provider reads it ----------------------------
#
# A pinned built-in provider reads one local source. `dpapi` with only MEFOR_STORE_ENCRYPTION_KEY, or
# `env` with only a key file, passed the gate as keyed and then resolved no key, so the store opened
# under the identity (plaintext) cipher. Measured on the source before this item: a fresh store under
# the audited opt-out, and an existing keyed store, both opened with `encrypts` False.

#: The two mismatched pairs: the provider, and the one local key setting that is set.
_UNREAD_PAIRS = [
    pytest.param("dpapi", "encryption_key", id="dpapi-with-only-a-key"),
    pytest.param("env", "encryption_key_file", id="env-with-only-a-key-file"),
]


def _unread(provider: str, source: str, **extra: object) -> StoreSettings:
    value = generate_key() if source == "encryption_key" else "C:/nowhere/service.key"
    return StoreSettings(key_provider=provider, **{source: value}, **extra)  # type: ignore[arg-type]


@pytest.mark.parametrize(("provider", "source"), _UNREAD_PAIRS)
def test_a_key_the_pinned_provider_does_not_read_is_not_a_configured_key(
    provider: str, source: str
) -> None:
    store = _unread(provider, source)
    assert not _store_key_configured(ServiceSettings(store=store))
    refusal = unread_key_refusal(store)
    assert refusal is not None and f"key_provider={provider!r} reads only" in refusal


@pytest.mark.parametrize(
    ("provider", "source"),
    [
        ("env", "encryption_key"),
        ("dpapi", "encryption_key_file"),
        ("auto", "encryption_key"),
        ("auto", "encryption_key_file"),
    ],
)
def test_a_key_the_provider_does_read_is_a_configured_key(provider: str, source: str) -> None:
    """The control arm: each provider with the source it reads is keyed, and nothing is refused."""
    store = _unread(provider, source)
    assert _store_key_configured(ServiceSettings(store=store))
    assert unread_key_refusal(store) is None


@pytest.mark.parametrize(("provider", "source"), _UNREAD_PAIRS)
def test_no_opt_out_waives_a_key_the_provider_does_not_read(provider: str, source: str) -> None:
    """The opt-out is for running with NO key. Here a key is named, so running keyless is not what
    was configured, and the gate refuses on its own verdict even with both acknowledgments set."""
    opted_out = SecuritySettings(
        allow_unencrypted_phi=True, allow_unencrypted_phi_under_strict_enforcement=True
    )
    for security in (SecuritySettings(), opted_out):
        settings = ServiceSettings(store=_unread(provider, source), security=security)
        assert _keyless_store_gate(settings) == KEYLESS_REFUSED_BY_UNREAD_KEY


@pytest.mark.parametrize(("provider", "source"), _UNREAD_PAIRS)
def test_under_vault_transit_the_gate_still_counts_an_ignored_local_key(
    provider: str, source: str
) -> None:
    """Transit holds the store key, so the store's cipher never resolves ``key_provider`` and an
    ignored local key cannot make it open plaintext. The gate keeps its pre-#2077 answer there. The
    DR backup path does resolve the key, and refuses the ignored one."""
    store = _unread(provider, source, cipher_provider="vault_transit")
    settings = ServiceSettings(store=store)
    assert _store_key_configured(settings)
    assert _keyless_store_gate(settings) is None
    with pytest.raises(KeyProviderError, match="reads only"):
        resolve_active_key(store)


@pytest.mark.parametrize(("provider", "source"), _UNREAD_PAIRS)
async def test_open_store_refuses_a_key_the_provider_does_not_read(
    shell: Path, provider: str, source: str
) -> None:
    """The seam no command skips. A fresh store under the opt-out and an existing keyed store both
    opened under the identity cipher before this item; both now refuse before the backend opens."""
    fresh = shell / "fresh.db"
    with pytest.raises(KeyProviderError, match="reads only"):
        await open_store(
            _unread(provider, source, path=str(fresh)), create=True, keyless_chain_refusal=None
        )
    assert not fresh.exists(), "a refused open must not leave a store behind"

    keyed = shell / "keyed.db"
    store = await open_store(
        StoreSettings(encryption_key=generate_key(), path=str(keyed)), create=True
    )
    await store.record_audit("seed", actor="test")
    await store.close()
    with pytest.raises(KeyProviderError, match="reads only"):
        await open_store(_unread(provider, source, path=str(keyed)), keyless_chain_refusal=None)


@pytest.mark.parametrize(("provider", "source"), _UNREAD_PAIRS)
def test_serve_refuses_a_key_the_provider_does_not_read_under_the_opt_out(
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    provider: str,
    source: str,
) -> None:
    """Through ``serve``, with the audited opt-out set so nothing else would stop a keyless start."""
    from tests.test_cli import SAMPLES_CONFIG

    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", provider)
    if source == "encryption_key":
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    else:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY_FILE", str(shell / "service.key"))
    (shell / "messagefoundry.toml").write_text(
        'security.enforcement = "warn"\nsecurity.allow_unencrypted_phi = true\n', encoding="utf-8"
    )
    started: list[object] = []
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: started.append(kw))
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: started.append(a))
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 2
    err = capsys.readouterr().err
    assert f"key_provider={provider!r} reads only" in err, err
    assert "key_provider" in err and "'auto'" in err, "the refusal names the remedy"
    assert not started
