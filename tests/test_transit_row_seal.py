# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Row seals under ``vault_transit``: Transit's own HMAC, checked through a cache (BACKLOG #2592,
ADR-draft decision D14).

Before this, a ``vault_transit`` store had no sealer at all, so a database writer with no key could
insert an administrator session, a role grant or a channel scope and have it honored. Each seal
contract the in-process store key runs is run here on a store whose only key is in (a stand-in for)
Transit, and a control shows the contract fails when the Transit check is switched off.

The live PostgreSQL and SQL Server legs run the same contracts: ``test_postgres_store.py`` and
``test_sqlserver_transit_row_seal.py``.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import pickle  # nosec B403 -- round-trips an exception this test builds, never stored data
import sqlite3
import threading
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.service import (
    AUTHORITY_SEAL_FAILED_ACTION,
    AUTHORITY_SEAL_UNVERIFIABLE_ACTION,
    DIRECTORY_MAP_UNVERIFIABLE,
    DIRECTORY_ROLE_MAP_UNSEALED,
    AdMapUnverifiableError,
    AuthService,
    CustomRoleUnverifiableError,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.cli_common import run_cli
from messagefoundry.config.settings import AuthSettings, EgressSettings, SecurityEnforcement
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import (
    TRANSIT_SEAL_SUBJECT,
    TRANSIT_SEAL_UNVERIFIABLE_SUBJECT,
    LoggingAlertSink,
    transit_seal_alert,
)
from messagefoundry.store import row_seal
from messagefoundry.store.crypto import RowSealUnverifiableError, generate_key, make_cipher
from messagefoundry.store.row_seal import (
    SEAL_PREFIX,
    SESSION_KIND,
    RowSealer,
    TransitRowSealer,
    TransitSealStartRefusedError,
    TransitSealUnavailableError,
    TransitSealUnverifiableError,
    transit_seal_key_id,
)
from messagefoundry.store.store import AD_ROLE_MAP, AD_SCOPE_MAP, MessageStore
from tests._approval_seal_contract import _Harness as ApprovalHarness
from tests._approval_seal_contract import assert_approval_seal_contract
from tests._role_seal_contract import assert_role_seal_contract
from tests._session_seal_contract import _mint, _user, assert_session_seal_contract
from tests._transit_seal_fake import (
    AUDIT_KEY,
    FakeTransit,
    assert_a_forged_session_needs_the_transit_check,
    transit_cipher,
)
from tests._user_seal_contract import assert_user_seal_contract
from tests.test_alert_sinks import _drain, _RecordingTransport

Opened = tuple[MessageStore, Path, FakeTransit]


@pytest.fixture
async def transit_store(tmp_path: Path) -> AsyncIterator[Opened]:
    transit = FakeTransit()
    cipher = transit_cipher(transit)
    path = tmp_path / "transit-sealed.db"
    store = await MessageStore.open(path, cipher=cipher, audit_mac_fn=cipher.audit_mac_fn())
    try:
        yield store, path, transit
    finally:
        await store.close()


def _raw_for(path: Path) -> Any:
    """Runs one statement on its own stdlib connection, which holds no key and calls no Transit."""

    async def raw(sql: str, params: tuple[Any, ...]) -> None:
        conn = sqlite3.connect(path)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    return raw


def _seal_failures(path: Path, action: str = AUTHORITY_SEAL_FAILED_ACTION) -> int:
    conn = sqlite3.connect(path)
    try:
        row = conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = ?", (action,)).fetchone()
        return int(row[0])
    finally:
        conn.close()


# --- the store gets a Transit sealer, and no key -----------------------------------------------


async def test_a_transit_store_seals_with_transit_and_holds_no_key(
    transit_store: Opened,
) -> None:
    store, _path, _transit = transit_store
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    assert store._cipher.authz_root() is None  # no seal key in the engine's memory
    await _user(store, "seal-u1")
    token = await _mint(store)
    row = await store.get_session(hash_token(token))
    assert row is not None
    # The stored form: the Transit key's id, then Transit's own string, which names its version.
    assert row.seal.startswith(f"{SEAL_PREFIX}{transit_seal_key_id(AUDIT_KEY)}:vault:v1:")
    # Control: a store on an in-process key keeps the local sealer and its 64-hex MAC.
    assert isinstance(RowSealer.for_cipher(make_cipher(generate_key())), RowSealer)


# --- the four seal contracts, on vault_transit --------------------------------------------------


async def test_the_session_seal_contract_holds_under_transit(transit_store: Opened) -> None:
    store, path, _transit = transit_store
    await assert_session_seal_contract(store, _raw_for(path))


async def test_the_user_seal_contract_holds_under_transit(transit_store: Opened) -> None:
    store, path, _transit = transit_store
    await assert_user_seal_contract(store, _raw_for(path))


async def test_the_role_seal_contract_holds_under_transit(transit_store: Opened) -> None:
    store, path, _transit = transit_store
    await assert_role_seal_contract(store, _raw_for(path))


async def test_the_approval_seal_contract_holds_under_transit(transit_store: Opened) -> None:
    store, path, _transit = transit_store
    await assert_approval_seal_contract(store, _raw_for(path))


async def test_the_contract_fails_when_the_transit_check_is_switched_off(
    transit_store: Opened, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: with Transit's check answering yes to everything, a forged row resolves, so
    the contract above is evidence that the check runs."""
    store, path, _transit = transit_store

    async def accepts_everything(*_: Any) -> bool:
        return True

    monkeypatch.setattr(TransitRowSealer, "verify_async", accepts_everything)
    with pytest.raises(AssertionError):
        await assert_session_seal_contract(store, _raw_for(path))


async def test_the_server_suites_control_holds_on_sqlite(
    transit_store: Opened, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control the PostgreSQL and SQL Server suites run, run here too so it is seen to work."""
    store, path, _transit = transit_store
    await assert_a_forged_session_needs_the_transit_check(store, _raw_for(path), monkeypatch)


# --- the seam: no Transit call on the event loop ------------------------------------------------


async def test_no_seal_call_runs_on_the_event_loop_thread(transit_store: Opened) -> None:
    store, _path, transit = transit_store
    await _user(store, "seal-u1")
    token = await _mint(store)
    transit.threads.clear()
    identity = await AuthService(store, AuthSettings()).identity_for_token(token)
    assert identity is not None
    assert transit.threads, "the check made no Transit call, so this proves nothing"
    assert threading.get_ident() not in transit.threads


# --- the cache ---------------------------------------------------------------------------------


async def test_a_checked_session_is_served_from_the_cache(transit_store: Opened) -> None:
    store, _path, transit = transit_store
    service = AuthService(store, AuthSettings())
    await _user(store, "seal-u1")
    token = await _mint(store)
    assert await service.identity_for_token(token) is not None
    # The first request checked the session and the user through Transit; the next checks none.
    seen = transit.verify_calls
    assert seen > 0
    assert await service.identity_for_token(token) is not None
    assert transit.verify_calls == seen
    # Control: once the entry's lifetime has passed, the next request goes back to Transit.
    # Each entry is aged past its lifetime in place, rather than by moving the process clock, which
    # the event loop itself reads.
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer) and sealer._cache
    horizon = time.monotonic() + row_seal.TRANSIT_SEAL_CACHE_TTL_SECONDS
    assert all(expires <= horizon for expires in sealer._cache.values())
    for entry in sealer._cache:
        sealer._cache[entry] = time.monotonic() - 1
    assert await service.identity_for_token(token) is not None
    assert transit.verify_calls > seen


async def test_the_cache_holds_no_failure_and_no_changed_row(transit_store: Opened) -> None:
    store, path, transit = transit_store
    service = AuthService(store, AuthSettings())
    await _user(store, "seal-u1")
    token = await _mint(store)
    assert await service.identity_for_token(token) is not None
    # A sealed column changed outside the store is a different input, so no cached yes covers it.
    await _raw_for(path)(
        "UPDATE sessions SET client = ? WHERE token_hash = ?", ("192.0.2.99", hash_token(token))
    )
    before = transit.verify_calls
    assert await service.identity_for_token(token) is None
    assert transit.verify_calls == before + 1


async def test_after_a_rotation_older_seals_still_verify_at_their_own_version(
    transit_store: Opened,
) -> None:
    store, _path, transit = transit_store
    service = AuthService(store, AuthSettings())
    await _user(store, "seal-u1")
    old = await _mint(store)
    assert await service.identity_for_token(old) is not None
    transit.rotate()
    # A seal made after the rotation names v2.
    await _user(store, "seal-u2")
    new_row = await store.get_session(hash_token(await _mint(store, "seal-u2")))
    assert new_row is not None and ":vault:v2:" in new_row.seal
    # Once the cached yes has lapsed, the v1 session is checked again at the version it names, so
    # it still verifies. Regenerating under the latest version and comparing would refuse it.
    _lapse_cache(store)
    before = transit.verify_calls
    assert await service.identity_for_token(old) is not None
    assert transit.verify_calls > before


# --- what an outage does ------------------------------------------------------------------------


async def test_an_outage_denies_without_a_seal_failure_and_recovers(
    transit_store: Opened, caplog: pytest.LogCaptureFixture
) -> None:
    store, path, transit = transit_store
    service = AuthService(store, AuthSettings())
    await _user(store, "seal-u1")
    token = await _mint(store)
    transit.down = True
    with pytest.raises(TransitSealUnavailableError):
        await service.identity_for_token(token)
    assert "could not be made or checked through Vault transit" in caplog.text  # the ERROR line
    # An outage is not a forgery: no seal-failure audit row, and the session was not ended.
    assert _seal_failures(path) == 0
    row = await store.get_session(hash_token(token))
    assert row is not None and row.revoked_at is None
    # A write that needs a seal is refused too, and leaves nothing behind.
    with pytest.raises(TransitSealUnavailableError):
        await _mint(store)
    transit.down = False
    assert await service.identity_for_token(token) is not None
    # Control: a forged row IS a seal failure, and is recorded as one.
    await _raw_for(path)(
        "UPDATE sessions SET client = ? WHERE token_hash = ?", ("192.0.2.98", hash_token(token))
    )
    assert await service.identity_for_token(token) is None
    assert _seal_failures(path) == 1


async def test_a_refused_check_is_unverifiable_and_read_from_no_version_range(
    transit_store: Opened,
) -> None:
    """Transit's own answers decide (BACKLOG #2592): a wrong MAC under a held version is HTTP 200
    ``valid: false``, a failed seal; a well-formed seal it refuses with HTTP 400 while its key
    answers is unverifiable, whatever version it names; a 400 the key probe cannot clear is an
    outage. No key metadata is read, so no version arithmetic can place a refusal."""
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, _path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest

    def no_metadata(**_: Any) -> dict[str, Any]:
        raise AssertionError("the sealer read key metadata")

    transit.read_key = no_metadata  # type: ignore[method-assign]
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    fields = [("token_hash", "synthetic")]
    good = await sealer.seal_async(SESSION_KIND, fields)
    assert await sealer.verify_async(SESSION_KIND, fields, good) is True
    # valid: false under a version Transit holds: a failed seal.
    assert await sealer.verify_async(SESSION_KIND, [("token_hash", "other")], good) is False
    # One newer than this node holds (a lagging node) and a planted giant read the same way.
    for version in ("v2", "v999999"):
        ahead = good.replace(":vault:v1:", f":vault:{version}:")
        with pytest.raises(TransitSealUnverifiableError):
            await sealer.verify_async(SESSION_KIND, fields, ahead)

    # A 400 while the key itself does not answer (a missing or renamed key) is an outage.
    def key_gone(**_: Any) -> dict[str, Any]:
        raise hvac_exceptions.InvalidRequest("synthetic: no such key")

    transit.generate_hmac = key_gone  # type: ignore[method-assign]
    with pytest.raises(TransitSealUnavailableError):
        await sealer.verify_async(SESSION_KIND, fields, good.replace(":vault:v1:", ":vault:v2:"))


async def test_a_seal_transit_refuses_to_check_is_denied_revoked_audited_and_alerted(
    transit_store: Opened,
) -> None:
    """Raising ``min_decryption_version`` past a version that sealed live rows makes those rows
    unverifiable (BACKLOG #2592). Each is treated as a failed seal under its own audit action: the
    session is ended and the account is refused. The page comes from the sealer, once per row."""
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    alerts: list[str] = []
    service = AuthService(store, AuthSettings(), integrity_alert=alerts.append)
    await _user(store, "seal-u1")
    token = await _mint(store)
    assert await service.identity_for_token(token) is not None
    transit.rotate()
    transit.min_decryption = 2
    await _user(store, "seal-u2")
    await _mint(store, "seal-u2")
    _lapse_cache(store)
    assert await service.identity_for_token(token) is None
    assert _seal_failures(path, AUTHORITY_SEAL_UNVERIFIABLE_ACTION) == 1
    assert _seal_failures(path) == 0  # not filed as a forgery
    assert alerts == []  # the forgery subject is never paged for it
    row = await store.get_session(hash_token(token))
    assert row is not None and row.revoked_at is not None  # ended, as a failed seal is
    # A scan skips the account rather than aborting, and reports it.
    assert [u.username for u in await service._load_users()] == ["seal-u2"]
    assert _seal_failures(path, AUTHORITY_SEAL_UNVERIFIABLE_ACTION) == 2
    # Control: lowering the minimum again makes the account verify, so the refusal was Transit's.
    transit.min_decryption = 1
    assert await service._load_user_by_username("seal-u1") is not None


async def test_a_genuine_seal_refused_by_a_lagging_node_is_unverifiable_and_signs_in_again(
    transit_store: Opened,
) -> None:
    """A session sealed under v2, refused by a verify node that lags the rotation while the key
    probe names v2 as latest, reads as unverifiable, as any 400 the probe clears does: denied,
    ended and audited, never a 503 (BACKLOG #2592). No version number is compared. Once the node
    catches up the user signs in again; the ended session stays ended."""
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    service = AuthService(store, AuthSettings())
    await _user(store, "seal-u1")
    transit.rotate()
    token = await _mint(store)  # sealed under v2, the version the probe names
    _lapse_cache(store)
    real_verify = transit.verify_signed_data

    def lagging_verify(**_: Any) -> dict[str, Any]:
        raise hvac_exceptions.InvalidRequest("synthetic: this node does not hold v2 yet")

    transit.verify_signed_data = lagging_verify  # type: ignore[method-assign]
    assert await service.identity_for_token(token) is None
    assert _seal_failures(path, AUTHORITY_SEAL_UNVERIFIABLE_ACTION) == 1
    row = await store.get_session(hash_token(token))
    assert row is not None and row.revoked_at is not None
    transit.verify_signed_data = real_verify  # type: ignore[method-assign]  # the node catches up
    assert await service.identity_for_token(token) is None  # ended, so the user signs in again
    assert await service.identity_for_token(await _mint(store)) is not None


@pytest.mark.parametrize("offset", [-1, 0, 1])
async def test_a_refused_seal_at_any_version_is_unverifiable_while_the_probe_answers(
    transit_store: Opened, offset: int
) -> None:
    """Below, at and above the version the key probe names as latest, a seal Vault answers with a
    400 while the probe works is unverifiable, from a long-lived sealer and a fresh one alike, so
    no answer depends on what this process saw before (BACKLOG #2592)."""
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, _path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    for _ in range(4):
        transit.rotate()
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    fields = [("token_hash", "any-version")]
    seal = await sealer.seal_async(SESSION_KIND, fields)
    assert ":vault:v5:" in seal
    seal = seal.replace(":vault:v5:", f":vault:v{5 + offset}:")
    transit.min_decryption = 5  # v4 is retired, and the fake refuses v6 as not yet held
    if offset == 0:  # the fake holds v5, so a lagging node stands in for the refusal

        def lagging_verify(**_: Any) -> dict[str, Any]:
            raise hvac_exceptions.InvalidRequest("synthetic: this node does not hold v5 yet")

        transit.verify_signed_data = lagging_verify  # type: ignore[method-assign]
    fresh = TransitRowSealer(transit_cipher(transit))
    for checker in (sealer, fresh):
        for _ in range(2):  # the same answer every time
            with pytest.raises(TransitSealUnverifiableError):
                await checker.verify_async(SESSION_KIND, fields, seal)

    # Control: the probe failing too turns the same refusal into an outage.
    def key_gone(**_: Any) -> dict[str, Any]:
        raise hvac_exceptions.InvalidRequest("synthetic: no such key")

    transit.generate_hmac = key_gone  # type: ignore[method-assign]
    with pytest.raises(TransitSealUnavailableError):
        await fresh.verify_async(SESSION_KIND, fields, seal)


async def test_a_retirement_this_process_never_sealed_past_is_unverifiable_not_an_outage(
    transit_store: Opened,
) -> None:
    """Vault rotates and raises the minimum while this process seals nothing new, so the newest
    version it has seen is the retired one. The refusal reads as unverifiable, never as a 503
    loop."""
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    service = AuthService(store, AuthSettings())
    await _user(store, "seal-u1")
    token = await _mint(store)  # sealed under v1, the newest this process has seen
    assert await service.identity_for_token(token) is not None
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    sealer._cache.clear()
    transit.rotate()
    transit.min_decryption = 2  # retired outside the engine; nothing re-sealed meanwhile
    assert await service.identity_for_token(token) is None
    assert _seal_failures(path, AUTHORITY_SEAL_UNVERIFIABLE_ACTION) == 1
    row = await store.get_session(hash_token(token))
    assert row is not None and row.revoked_at is not None


async def test_a_planted_well_formed_seal_is_unverifiable_and_alerted(
    transit_store: Opened, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A planted seal with a giant version but a well-formed body reaches Transit, which refuses
    it: the session is ended and audited as unverifiable, and one page fires, under the
    unverifiable subject with the row's own kind and id appended. No key-level page goes with it."""
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    raised = _armed(store, monkeypatch)
    service = AuthService(store, AuthSettings(), integrity_alert=lambda _reason: None)
    await _user(store, "seal-u1")
    token = await _mint(store)
    row = await store.get_session(hash_token(token))
    assert row is not None
    await _raw_for(path)(
        "UPDATE sessions SET seal = ? WHERE token_hash = ?",
        (row.seal.replace(":vault:v1:", ":vault:v999999:"), hash_token(token)),
    )
    before = transit.verify_calls
    assert await service.identity_for_token(token) is None
    assert transit.verify_calls > before  # well-formed, so Transit was asked
    ref = hash_token(token)[:12]
    assert raised == [f"{TRANSIT_SEAL_UNVERIFIABLE_SUBJECT}:{SESSION_KIND}:{ref}"]
    assert _seal_failures(path, AUTHORITY_SEAL_UNVERIFIABLE_ACTION) == 1
    ended = await store.get_session(hash_token(token))
    assert ended is not None and ended.revoked_at is not None


async def test_two_unverifiable_rows_each_page_through_the_production_notifier(
    transit_store: Opened,
) -> None:
    """Two sessions whose genuine seals are rewritten to a version Transit does not hold each page
    through the real notifier, inside one realert window: its throttle keys on the subject, and
    each row's subject is its own (BACKLOG #2592). Both stay denied, ended and audited."""
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    transport = _RecordingTransport("t")
    notifier = NotifierAlertSink([transport], realert_seconds=3600.0)
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    sealer.set_alert_hook(transit_seal_alert(notifier))
    forgery_pages: list[str] = []
    service = AuthService(store, AuthSettings(), integrity_alert=forgery_pages.append)
    tokens = []
    for name in ("seal-u1", "seal-u2"):
        await _user(store, name)
        token = await _mint(store, name)
        row = await store.get_session(hash_token(token))
        assert row is not None
        await _raw_for(path)(
            "UPDATE sessions SET seal = ? WHERE token_hash = ?",
            (row.seal.replace(":vault:v1:", ":vault:v7:"), hash_token(token)),
        )
        tokens.append(token)
    for token in tokens:
        assert await service.identity_for_token(token) is None
    # Control: the same row paged again inside the window IS throttled, so the two pages below
    # are evidence that the subjects differ, not that the notifier throttles nothing.
    row_seal.alert_unverifiable_row(sealer, f"{SESSION_KIND}:{hash_token(tokens[0])[:12]}", "again")
    await _drain(notifier)
    subjects = [event["connection"] for event in transport.events]
    assert subjects == [
        f"{TRANSIT_SEAL_UNVERIFIABLE_SUBJECT}:{SESSION_KIND}:{hash_token(t)[:12]}" for t in tokens
    ]
    assert forgery_pages == []  # the forgery subject stays apart
    assert _seal_failures(path, AUTHORITY_SEAL_UNVERIFIABLE_ACTION) == 2
    for token in tokens:
        ended = await store.get_session(hash_token(token))
        assert ended is not None and ended.revoked_at is not None


async def test_a_service_with_no_integrity_alert_never_pages_through_the_sealer(
    transit_store: Opened, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An AuthService built with ``integrity_alert=None`` pages nothing for an unverifiable row,
    even with the sealer's hook armed; the row is still denied, ended and audited."""
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    raised = _armed(store, monkeypatch)
    tokens = []
    for name in ("seal-u1", "seal-u2"):
        await _user(store, name)
        tokens.append(await _mint(store, name))
    await _retire_old_versions(store, transit)
    assert await AuthService(store, AuthSettings()).identity_for_token(tokens[0]) is None
    assert raised == []
    assert _seal_failures(path, AUTHORITY_SEAL_UNVERIFIABLE_ACTION) == 1
    # Control: the same refusal, from a service that has an integrity alert, pages.
    paged = AuthService(store, AuthSettings(), integrity_alert=lambda _reason: None)
    assert await paged.identity_for_token(tokens[1]) is None
    assert len(raised) == 1


def _armed(store: MessageStore, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Arm the sealer's alert hook on a recording sink; returns the subjects it pages."""
    raised: list[str] = []
    sink = LoggingAlertSink()
    monkeypatch.setattr(
        sink, "integrity_drift", lambda name, *, reason, drift_count: raised.append(name)
    )
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    sealer.set_alert_hook(transit_seal_alert(sink))
    return raised


def _lapse_cache(store: MessageStore) -> None:
    """Drop the sealer's cached successes, standing in for their one-minute lifetime passing."""
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    sealer._cache.clear()


async def _retire_old_versions(store: MessageStore, transit: FakeTransit) -> None:
    """Rotate, raise the minimum to the new version, retiring every older one, and let the
    sealer's cached answers lapse."""
    transit.rotate()
    transit.min_decryption = transit.latest
    _lapse_cache(store)


async def test_an_unverifiable_directory_map_is_skipped_and_only_narrows(
    transit_store: Opened, monkeypatch: pytest.MonkeyPatch
) -> None:
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    raised = _armed(store, monkeypatch)
    service = AuthService(store, AuthSettings(), integrity_alert=lambda _reason: None)
    await service.initialize()  # seeds the built-in roles the map's foreign key names
    await store.set_ad_group_role_map([("grp", "viewer")])
    assert await service._ad_roles_for_groups(["grp"]) == {"viewer"}  # control
    await _retire_old_versions(store, transit)
    # Grants nothing, and a step-up reads it as a failing map, never as roles kept.
    assert await service._ad_roles_for_groups(["grp"]) == set()
    assert await service._sealed_ad_map(AD_ROLE_MAP) is None
    assert await service._directory_roles_lost(["viewer"], ["grp"]) == DIRECTORY_ROLE_MAP_UNSEALED
    assert _seal_failures(path, AUTHORITY_SEAL_UNVERIFIABLE_ACTION) == 1
    assert raised == [f"{TRANSIT_SEAL_UNVERIFIABLE_SUBJECT}:adset:{AD_ROLE_MAP}"]  # the map's own


@pytest.mark.parametrize(
    ("name", "pair"),
    [(AD_ROLE_MAP, ("grp", "viewer")), (AD_SCOPE_MAP, ("grp", "chan-a"))],
)
async def test_an_unverifiable_directory_map_refuses_a_listing_and_a_replace(
    transit_store: Opened, name: str, pair: tuple[str, str]
) -> None:
    """An administrator never sees an unverifiable map as empty, so never saves from that view:
    the listing and a replacement are refused with the recovery named, the stored pairs survive,
    and a role or channel lookup through the map still grants nothing (BACKLOG #2592). Clearing
    the map, the named recovery, goes through, as deleting a role does."""
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, _path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    service = AuthService(store, AuthSettings())
    await service.initialize()
    roles = name == AD_ROLE_MAP
    listing = service.list_ad_group_role_map if roles else service.list_ad_group_scope_map
    replace = service.set_ad_group_map if roles else service.set_ad_group_scope_map
    await replace([pair], actor="t")
    assert await listing() == [pair]  # control
    await _retire_old_versions(store, transit)
    with pytest.raises(AdMapUnverifiableError, match="clear the map"):
        await listing()
    with pytest.raises(AdMapUnverifiableError, match="clear the map"):
        await replace([("other", pair[1])], actor="t")
    assert (await store.get_ad_map(name)).pairs == (pair,)  # no pair lost
    lookup = service._ad_roles_for_groups if roles else service._ad_channels_for_groups
    assert not await lookup(["grp"])  # the decision stays narrowed
    # Control: once the map verifies again, the listing and the replace go through.
    transit.min_decryption = 1
    assert await listing() == [pair]
    await _retire_old_versions(store, transit)
    await replace([], actor="t")  # the recovery: clear it, then enter the pairs again
    assert await listing() == []
    await replace([pair], actor="t")
    assert await listing() == [pair]


async def test_a_refusal_whose_probe_mac_is_malformed_is_an_outage(
    transit_store: Opened, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A key probe that answers with a MAC of an unexpected shape did not show the key answers, so
    the refusal is an outage, as a malformed seal reply is (BACKLOG #2592)."""
    store, _path, _transit = transit_store
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    fields = [("token_hash", "probe-shape")]
    seal = await sealer.seal_async(SESSION_KIND, fields)
    sealer._cache.clear()

    def refused(_data: bytes, _mac: str) -> bool:
        raise RowSealUnverifiableError("not a transit mac")

    monkeypatch.setattr(sealer._backend, "verify_seal_hmac", refused)
    with pytest.raises(TransitSealUnavailableError):
        await sealer.verify_async(SESSION_KIND, fields, seal)


def test_an_unverifiable_directory_map_is_a_409_naming_the_recovery() -> None:
    """The routes answer the refusal with HTTP 409 and the fixed recovery text, as the custom-role
    edit does."""
    from fastapi import HTTPException

    from messagefoundry.api.auth_routes import _ad_map_unverifiable_is_409

    with pytest.raises(HTTPException) as caught, _ad_map_unverifiable_is_409():
        raise AdMapUnverifiableError(AD_ROLE_MAP)
    assert caught.value.status_code == 409
    assert "clear the map" in str(caught.value.detail)
    assert "ad_group_role_map" in str(caught.value.detail)


async def test_an_unverifiable_custom_role_is_listed_empty_refuses_an_edit_and_deletes(
    transit_store: Opened,
) -> None:
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    service = AuthService(store, AuthSettings())
    await service.initialize()
    role = await service.create_custom_role(
        display_name="r", description=None, permissions=["messages:replay"], actor="t"
    )
    await _retire_old_versions(store, transit)
    assert await service._load_role(role.id) is None
    [listed] = [r for r in await service.list_custom_roles() if r.id == role.id]
    assert listed.permissions == frozenset()
    with pytest.raises(CustomRoleUnverifiableError, match="delete the role"):
        await service.update_custom_role(
            role.id, display_name="r", description=None, permissions=["messages:read"], actor="t"
        )
    found = await store.get_role(role.id)
    assert found is not None and "messages:replay" in str(found["permissions"])  # untouched
    assert _seal_failures(path, AUTHORITY_SEAL_UNVERIFIABLE_ACTION) >= 1
    # Control: once the role verifies again, the same edit saves.
    transit.min_decryption = 1
    await service.update_custom_role(
        role.id, display_name="r", description=None, permissions=["messages:read"], actor="t"
    )
    # Deleting is the recovery path, even with a holder and an AD map pair that are themselves
    # unverifiable: each falls back to deleting its own row of the role.
    await _user(store, "holder")
    await store.set_user_roles("holder", [role.id])
    await store.set_ad_group_role_map([("grp", role.id)])
    await _retire_old_versions(store, transit)
    assert await service._load_role(role.id) is None  # control: the role is unverifiable now
    await service.delete_custom_role(role.id, actor="t")
    assert await store.get_role(role.id) is None
    assert role.id not in await store.get_user_role_ids("holder")


async def test_an_unverifiable_approval_is_skipped_with_audit_and_alert(
    transit_store: Opened, monkeypatch: pytest.MonkeyPatch
) -> None:
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    raised = _armed(store, monkeypatch)
    harness = ApprovalHarness(store, _raw_for(path))
    approval_id = await harness.request(contract_nonce="repeat")
    assert await harness.listed(approval_id)  # control
    await _retire_old_versions(store, transit)
    assert not await harness.listed(approval_id)  # skipped, the read did not abort
    assert harness.alerted(approval_id) == 0  # the forgery subject is not paged for it
    assert raised == [f"{TRANSIT_SEAL_UNVERIFIABLE_SUBJECT}:approval:{approval_id}"]
    assert _seal_failures(path, AUTHORITY_SEAL_UNVERIFIABLE_ACTION) == 1
    # A repeat request is filed on its own rather than joining the row nobody can check.
    assert await harness.request(contract_nonce="repeat") != approval_id


# --- a check held open across a refusal (Greptile P2 on PR 2565) ----------------------------------


async def _held_check(sealer: TransitRowSealer, transit: FakeTransit, *, refuse: bool) -> bool:
    """Run one v1 check that Transit holds open, optionally have another check refused meanwhile,
    then release it. Returns whether the v1 answer was left in the cache."""
    fields = [("token_hash", "held")]
    seal = await sealer.seal_async(SESSION_KIND, fields)
    sealer._cache.clear()
    entered, release = threading.Event(), threading.Event()
    real_verify = transit.verify_signed_data

    def held_verify(**kwargs: Any) -> dict[str, Any]:
        entered.set()
        assert release.wait(10), "the test never released the held check"
        return real_verify(**kwargs)

    transit.verify_signed_data = held_verify  # type: ignore[method-assign]
    check = asyncio.create_task(sealer.verify_async(SESSION_KIND, fields, seal))
    assert await asyncio.to_thread(entered.wait, 10)
    transit.verify_signed_data = real_verify  # type: ignore[method-assign]
    if refuse:
        other = [("token_hash", "other")]
        planted = (await sealer.seal_async(SESSION_KIND, other)).replace(":vault:v1:", ":vault:v9:")
        with pytest.raises(TransitSealUnverifiableError):
            await sealer.verify_async(SESSION_KIND, other, planted)
    release.set()
    assert await check is True  # the answer stands for its own caller either way
    before = transit.verify_calls
    assert await sealer.verify_async(SESSION_KIND, fields, seal) is True
    return transit.verify_calls == before


async def test_a_check_held_open_across_a_refusal_does_not_refill_the_cache(
    transit_store: Opened,
) -> None:
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, _path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    # Control first: with no refusal meanwhile, the held check's answer IS cached.
    assert await _held_check(sealer, transit, refuse=False) is True
    # A refusal seen while the v1 check waited empties the cache, and the check does not refill it.
    assert await _held_check(sealer, transit, refuse=True) is False


async def test_a_row_that_stays_unverifiable_never_empties_the_cache_again(
    transit_store: Opened,
) -> None:
    """Only a key probe naming a different latest version empties the cache, so one row read on
    every request while it stays unverifiable never sends every other row back to Transit."""
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, _path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    good = [("token_hash", "good")]
    seal = await sealer.seal_async(SESSION_KIND, good)
    bad = [("token_hash", "bad")]
    planted = (await sealer.seal_async(SESSION_KIND, bad)).replace(":vault:v1:", ":vault:v9:")
    with pytest.raises(TransitSealUnverifiableError):  # the first refusal learns the probe's v1
        await sealer.verify_async(SESSION_KIND, bad, planted)
    assert await sealer.verify_async(SESSION_KIND, good, seal) is True
    for _ in range(3):
        with pytest.raises(TransitSealUnverifiableError):
            await sealer.verify_async(SESSION_KIND, bad, planted)
    before = transit.verify_calls
    assert await sealer.verify_async(SESSION_KIND, good, seal) is True
    assert transit.verify_calls == before  # still served from the cache
    # Control: a refusal whose probe names a new latest version does empty it.
    transit.rotate()
    with pytest.raises(TransitSealUnverifiableError):
        await sealer.verify_async(SESSION_KIND, bad, planted)
    assert await sealer.verify_async(SESSION_KIND, good, seal) is True
    assert transit.verify_calls > before + 1


# --- the alert, the start probe and the CLI line -------------------------------------------------


async def test_an_outage_alerts_once_per_window(
    transit_store: Opened, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _path, transit = transit_store
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    raised: list[tuple[str, str]] = []
    sink = LoggingAlertSink()
    monkeypatch.setattr(
        sink,
        "integrity_drift",
        lambda name, *, reason, drift_count: raised.append((name, reason)),
    )
    sealer.set_alert_hook(transit_seal_alert(sink))
    transit.down = True
    for _ in range(3):
        with pytest.raises(TransitSealUnavailableError):
            await sealer.seal_async(SESSION_KIND, [("token_hash", "x")])
    assert len(raised) == 1 and raised[0][0] == TRANSIT_SEAL_SUBJECT
    # An unverifiable seal is logged by the sealer but paged only per row, under its own cause,
    # so the outage's alert does not throttle it away. alerts.py spells the cause itself to import
    # nothing from the store; this ties the two.
    assert row_seal.TRANSIT_UNVERIFIABLE_CAUSE == "transit-unverifiable"
    transit.down = False
    with pytest.raises(TransitSealUnverifiableError):
        raise sealer._unverifiable(RowSealUnverifiableError("vault:v1:probe"))
    assert [name for name, _ in raised] == [TRANSIT_SEAL_SUBJECT]
    row_seal.alert_unverifiable_row(sealer, "session:abc", "a row")
    assert [name for name, _ in raised] == [
        TRANSIT_SEAL_SUBJECT,
        f"{TRANSIT_SEAL_UNVERIFIABLE_SUBJECT}:session:abc",
    ]
    assert "synthetic Vault outage" not in raised[0][1]  # a fixed sentence, never Vault's text


async def _start(store: MessageStore) -> None:
    engine = Engine(
        store,
        security_enforcement=SecurityEnforcement.WARN,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await engine.start()
    finally:
        await engine.stop()


async def test_serve_refuses_to_start_when_the_token_cannot_verify(tmp_path: Path) -> None:
    transit = FakeTransit()
    cipher = transit_cipher(transit)
    path = tmp_path / "probe.db"
    store = await MessageStore.open(path, cipher=cipher, audit_mac_fn=cipher.audit_mac_fn())
    transit.verify_denied = True
    with pytest.raises(TransitSealStartRefusedError, match="verify"):
        await _start(store)
    # Control: the same store, with the capability granted, starts.
    transit.verify_denied = False
    again = await MessageStore.open(path, cipher=cipher, audit_mac_fn=cipher.audit_mac_fn())
    await _start(again)


def test_the_cli_prints_one_error_line_for_a_transit_outage(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from messagefoundry.__main__ import _refusal_text

    def build() -> Any:
        import argparse

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command", required=True)
        sub.add_parser("probe").add_argument("--json", action="store_true")

        def run(_args: argparse.Namespace) -> int:
            raise TransitSealUnavailableError("Transit row seal unavailable: synthetic outage")

        return parser, {"probe": run}

    assert run_cli(["probe"], build, refusal_text=_refusal_text) == 1
    err = capsys.readouterr().err
    assert err.startswith("error: the command was refused") and "synthetic outage" in err
    assert "last-resort" not in err and "Traceback" not in err
    # A seal Transit refused to check is a refusal too, and is not called a non-failure.
    unverifiable = _refusal_text(TransitSealUnverifiableError("Transit row seal unverifiable: x"))
    assert unverifiable is not None and "nothing was recorded" not in unverifiable
    # Control: an exception that is not a seal refusal still takes the last-resort floor.
    assert _refusal_text(RuntimeError("x")) is None


# --- the stored form --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stored",
    [
        None,
        "",
        "mfseal:v1:",
        "mfseal:v1:0123456789abcdef:" + "a" * 64,  # a local seal: wrong key id and shape
        "mfseal:v1:{kid}:vault:v1:",  # no MAC body
        "mfseal:v1:{kid}:vault:vX:abc",  # no version number
        "mfseal:v1:{kid}:vault:v1:" + "A" * 200,  # longer than any Transit HMAC
        "mfseal:v1:{kid}:vault:v1:é",  # not ASCII: refused, never an encode error
        "mfseal:v1:{kid}:vault:v01:abc",  # a leading zero, which Transit never writes
        "mfseal:v1:{kid}:vault:v0:abc",
        "mfseal:v1:{kid}:mac",
        # Base64, but 31 bytes rather than a SHA-256 digest's 32: refused locally.
        "mfseal:v1:{kid}:vault:v1:" + base64.b64encode(b"\x00" * 31).decode("ascii"),
        "mfseal:v1:{kid}:vault:v1:" + "!" * 44,  # 44 characters, none of them base64
        "mfseal:v1:{kid}:vault:v1:" + "A" * 43,  # bad padding
    ],
)
async def test_a_malformed_seal_fails_with_no_transit_call(
    transit_store: Opened, stored: str | None
) -> None:
    store, _path, transit = transit_store
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    if stored is not None:
        stored = stored.replace("{kid}", sealer.key_id)
    assert await sealer.verify_async(SESSION_KIND, [("a", 1)], stored) is False
    assert not sealer.is_active(stored)
    assert transit.verify_calls == 0


def test_the_unverifiable_errors_survive_copy_and_pickle() -> None:
    """Each rebuilds from its ``args`` (BACKLOG #2592): copy and pickle call ``cls(*args)``, which
    raised TypeError while ``__init__`` passed nothing on."""
    for error in (
        RowSealUnverifiableError("vault:v3:probe"),
        AdMapUnverifiableError(AD_SCOPE_MAP),
        CustomRoleUnverifiableError(),
    ):
        for clone in (pickle.loads(pickle.dumps(error)), copy.copy(error)):
            assert type(clone) is type(error)
            assert str(clone) == str(error)
    clone = pickle.loads(pickle.dumps(RowSealUnverifiableError("vault:v3:probe")))
    assert clone.probe_mac == "vault:v3:probe"


def test_the_transit_key_id_is_fixed_width_and_names_the_key() -> None:
    kid = transit_seal_key_id(AUDIT_KEY)
    assert len(kid) == 16 and all(c in "0123456789abcdef" for c in kid)
    assert kid == transit_seal_key_id(AUDIT_KEY)
    assert kid != transit_seal_key_id("another-key")


async def test_a_seal_under_another_store_id_does_not_verify() -> None:
    transit = FakeTransit()
    cipher = transit_cipher(transit)
    here = TransitRowSealer(cipher, store_id=b"store-a")
    there = TransitRowSealer(cipher, store_id=b"store-b")
    fields = [("token_hash", "synthetic")]
    seal = await here.seal_async(SESSION_KIND, fields)
    assert await here.verify_async(SESSION_KIND, fields, seal)
    assert not await there.verify_async(SESSION_KIND, fields, seal)


def test_the_awaited_local_forms_answer_like_the_sync_ones() -> None:
    sealer = RowSealer(b"\x01" * 32)
    fields = [("token_hash", "synthetic")]

    async def run() -> None:
        seal = await sealer.seal_async(SESSION_KIND, fields)
        assert seal == sealer.seal(SESSION_KIND, fields)
        assert await sealer.verify_async(SESSION_KIND, fields, seal)
        assert await sealer.verify_held_async(SESSION_KIND, fields, seal)
        assert not await sealer.verify_async(SESSION_KIND, [("token_hash", "x")], seal)

    asyncio.run(run())


# --- a directory decision that writes holds on an unverifiable map (BACKLOG #2592) ---------------

_OPS = "cn=mf-ops,dc=test,dc=invalid"
_CHANS = "cn=mf-chan,dc=test,dc=invalid"


async def _set_map_version(path: Path, name: str, *, planted: bool) -> None:
    """Rewrite map ``name``'s genuine seal to name a version Transit does not hold, or back, so
    only that map is unverifiable while every other row still verifies."""
    old, new = (":vault:v1:", ":vault:v7:") if planted else (":vault:v7:", ":vault:v1:")
    await _raw_for(path)(
        "UPDATE authority_set_seal SET seal = replace(seal, ?, ?) WHERE name = ?",
        (old, new, name),
    )


def _login_refusals(path: Path, reason: str) -> int:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'auth.login_failed'"
        ).fetchall()
        return sum(1 for (detail,) in rows if f'"reason": "{reason}"' in str(detail))
    finally:
        conn.close()


async def _directory_service(store: MessageStore, ldap: Any) -> AuthService:
    from tests.test_ad_session_reconcile import _ad_settings

    service = AuthService(store, _ad_settings(), ldap=ldap, integrity_alert=lambda _r: None)
    await service.initialize()
    return service


@pytest.mark.parametrize("unverifiable", [AD_ROLE_MAP, AD_SCOPE_MAP])
async def test_a_directory_sign_in_meeting_an_unverifiable_map_is_refused_and_writes_nothing(
    transit_store: Opened, monkeypatch: pytest.MonkeyPatch, unverifiable: str
) -> None:
    """Before this, the sign-in read an unverifiable role map as empty and wrote no roles onto the
    account, stripping its genuine ones while Vault might only lag a rotation. Now it refuses,
    audited, and writes neither roles nor scope; the map pages under its own subject. The
    federated sign-in ends in the same method, so it is refused the same way."""
    from tests.test_ad_session_reconcile import _FakeLdap, _principal

    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    raised = _armed(store, monkeypatch)
    ldap = _FakeLdap({"jdoe": _principal("jdoe", _CHANS, _OPS)})
    service = await _directory_service(store, ldap)
    await service.set_ad_group_map([(_OPS, "operator")], actor="t")
    await service.set_ad_group_scope_map([(_CHANS, "chan-a")], actor="t")
    principal = ldap.present["jdoe"]
    assert (await service._complete_ad_login(principal, None, mfa_verified=True)).ok  # control
    user = await store.get_user_by_username("jdoe")
    assert user is not None and user.channel_scope is not None
    scope_before = user.channel_scope
    await _set_map_version(path, unverifiable, planted=True)
    _lapse_cache(store)
    refused = await service._complete_ad_login(principal, None, mfa_verified=True)
    assert not refused.ok and refused.token is None
    assert _login_refusals(path, DIRECTORY_MAP_UNVERIFIABLE) == 1
    after = await store.get_user_by_username("jdoe")
    assert after is not None
    assert await store.get_user_role_ids(after.id) == ["operator"]  # the genuine role is kept
    assert after.channel_scope == scope_before  # and so is the scope
    assert raised == [f"{TRANSIT_SEAL_UNVERIFIABLE_SUBJECT}:adset:{unverifiable}"]
    # Control: once the map verifies again, the same sign-in goes through.
    await _set_map_version(path, unverifiable, planted=False)
    assert (await service._complete_ad_login(principal, None, mfa_verified=True)).ok


async def test_a_failing_role_map_still_signs_in_with_nothing(transit_store: Opened) -> None:
    """The forgery control: a map whose seal FAILS, a pair added outside the store, grants
    nothing, as before. Only a map Transit refused to check holds the write."""
    from tests.test_ad_session_reconcile import _FakeLdap, _principal

    store, path, _transit = transit_store
    ldap = _FakeLdap({"jdoe": _principal("jdoe", _OPS)})
    service = await _directory_service(store, ldap)
    await service.set_ad_group_map([(_OPS, "operator")], actor="t")
    principal = ldap.present["jdoe"]
    assert (await service._complete_ad_login(principal, None, mfa_verified=True)).ok
    await _raw_for(path)(
        "INSERT INTO ad_group_role_map (ad_group, role_id) VALUES (?, ?)",
        ("cn=planted,dc=test,dc=invalid", "administrator"),
    )
    await service._complete_ad_login(principal, None, mfa_verified=True)
    user = await store.get_user_by_username("jdoe")
    assert user is not None and await store.get_user_role_ids(user.id) == []
    assert _login_refusals(path, DIRECTORY_MAP_UNVERIFIABLE) == 0
    assert _seal_failures(path) >= 1


async def test_a_local_administrator_can_clear_an_unverifiable_map(
    transit_store: Opened,
) -> None:
    """The recovery the refusal names needs an account that can sign in while the map is
    unverifiable. A directory account cannot; a local Administrator can, and can clear it."""
    from tests._admin_account import login_admin

    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    service = AuthService(store, AuthSettings())
    await service.initialize()
    await service.set_ad_group_map([(_OPS, "operator")], actor="t")
    await _set_map_version(path, AD_ROLE_MAP, planted=True)
    _lapse_cache(store)
    with pytest.raises(AdMapUnverifiableError):
        await service.list_ad_group_role_map()  # control: the map is unverifiable
    identity, _token, _password = await login_admin(service)
    await service.set_ad_group_map([], actor=identity.username)
    assert await service.list_ad_group_role_map() == []
