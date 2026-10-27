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
import sqlite3
import threading
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.service import AUTHORITY_SEAL_FAILED_ACTION, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store import row_seal
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import (
    SEAL_PREFIX,
    SESSION_KIND,
    RowSealer,
    TransitRowSealer,
    TransitSealUnavailableError,
    transit_seal_key_id,
)
from messagefoundry.store.store import MessageStore
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


def _seal_failures(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = ?", (AUTHORITY_SEAL_FAILED_ACTION,)
        ).fetchone()
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


async def test_a_new_key_version_empties_the_cache_and_older_seals_still_verify(
    transit_store: Opened,
) -> None:
    store, _path, transit = transit_store
    service = AuthService(store, AuthSettings())
    await _user(store, "seal-u1")
    old = await _mint(store)
    assert await service.identity_for_token(old) is not None
    transit.rotate()
    # A seal made after the rotation names v2, and the sealer learns of the new version.
    await _user(store, "seal-u2")
    new_row = await store.get_session(hash_token(await _mint(store, "seal-u2")))
    assert new_row is not None and ":vault:v2:" in new_row.seal
    # The v1 session is checked again (its cached yes was dropped) at the version it names, so it
    # still verifies. Regenerating under the latest version and comparing would refuse it.
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
    assert "Vault Transit did not answer" in caplog.text  # the provider alert
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


async def test_a_version_transit_refuses_does_not_verify(transit_store: Opened) -> None:
    hvac_exceptions = pytest.importorskip("hvac.exceptions")
    store, _path, transit = transit_store
    transit.refusal = hvac_exceptions.InvalidRequest
    sealer = store.row_sealer()
    assert isinstance(sealer, TransitRowSealer)
    fields = [("token_hash", "synthetic")]
    good = await sealer.seal_async(SESSION_KIND, fields)
    # A seal naming a version Transit does not hold is Transit's HTTP 400: not verified, no outage.
    forged = good.replace(":vault:v1:", ":vault:v9:")
    assert await sealer.verify_async(SESSION_KIND, fields, forged) is False
    # Control: the honest seal verifies, and a different field fails.
    assert await sealer.verify_async(SESSION_KIND, fields, good) is True
    assert await sealer.verify_async(SESSION_KIND, [("token_hash", "other")], good) is False


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
        "mfseal:v1:{kid}:mac",
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
