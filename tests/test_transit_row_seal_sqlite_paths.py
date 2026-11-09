# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The rest of the SQLite store's sealed paths, and the service and gate readers, run under the
Transit sealer with an in-memory Transit stand-in (ADR 0217 slice 1b-i). Synthetic data only.

Two kinds of test. Each path is first shown to run through the awaitable seam, so none reaches a
sync-only sealer method under Transit. Then, where a stored seal Transit cannot check reaches a
catch that names only ``RowSealError``, the test pins what happens TODAY: the new type escapes it.
That handling decides what is revoked, refused or audited, so it is behind the owner gate (vault
#4739 step 6) and slice 1b-iv's catch census; these pins say what that census starts from, and a
change to one is a decision, not a refactor.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest

from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import (
    AUTHORITY_SEAL_FAILED_ACTION,
    AuthService,
    _RotationStoreError,
)
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.crypto import CipherError, generate_key, make_cipher
from messagefoundry.store.row_seal import (
    RowSealError,
    RowSealUnverifiableError,
    TransitRowSealer,
    TransitSealUnavailableError,
    TransitSealUnverifiableError,
)
from messagefoundry.store.store import (
    AD_ROLE_MAP,
    AdminRemoval,
    ApprovalRow,
    MessageStore,
    RoleRow,
    WebAuthnCredential,
    ad_map_seal_ok_async,
    approval_seal_ok_async,
    role_seal_ok_async,
    session_seal_ok_async,
    user_seal_ok_async,
)
from tests._transit_seal_fake import RETIRED, FakeBackend, with_version

ADMIN = Role.ADMINISTRATOR.value
VIEWER = Role.VIEWER.value
CUSTOM = "custom:transit-probe"


@pytest.fixture
async def transit(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, FakeBackend, Path]]:
    path = tmp_path / "transit.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    backend = FakeBackend()
    store._row_sealer = TransitRowSealer(backend)
    try:
        yield store, backend, path
    finally:
        await store.close()


def _sql(path: Path, sql: str, params: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(sql, params).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def _plant(path: Path, table: str, column: str, key: str, value: str) -> None:
    """Rewrite one stored seal to name version 5, which the stand-in does not hold: a well-formed
    seal Transit answers with a 400 while its probe works, the Unverifiable answer."""
    (seal,) = _sql(path, f"SELECT {column} FROM {table} WHERE {key}=?", (value,))[0]
    _sql(
        path,
        f"UPDATE {table} SET {column}=? WHERE {key}=?",
        (with_version(str(seal), "5"), value),
    )


async def _user(store: MessageStore, user_id: str, *roles: str) -> None:
    await store.create_user(
        user_id=user_id,
        username=f"name-{user_id}",
        auth_provider="local",
        password_hash="synthetic-hash",
        password_generated=False,
        audits=(),
    )
    if roles:
        await store.set_user_roles(user_id, list(roles))


async def _session(store: MessageStore, user_id: str) -> str:
    token = mint_token()
    assert await store.create_session(
        token_hash=hash_token(token), user_id=user_id, expires_at=time.time() + 3600
    )
    return token


async def _roles(store: MessageStore) -> None:
    for role in (ADMIN, VIEWER):
        await store.upsert_role(role_id=role, display_name=role, builtin=True)
    await store.upsert_role(role_id=CUSTOM, display_name="probe", builtin=False, permissions="[]")


async def _approval(store: MessageStore, approval_id: str, nonce: str = "n") -> str:
    return await store.create_pending_approval(
        approval_id=approval_id,
        operation="op",
        params=f'{{"n": "{nonce}"}}',
        requester="r",
        requester_user_id="r-id",
        requested_at=1.0,
        expires_at=None,
    )


# --- each path runs through the awaitable seam -----------------------------------------------------


async def test_every_awaitable_read_check_answers_through_transit(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    """Holds, then an Outage raised as itself, for each record kind the readers check, each kind
    on its own fresh sealer so no cached Holds answer stands in for Transit's."""
    store, backend, _ = transit
    await _roles(store)
    await _user(store, "u-1", VIEWER)
    token = await _session(store, "u-1")
    await store.set_ad_group_role_map([("g", VIEWER)])
    await _approval(store, "a-1")
    record = await store._read_user_record("u-1")
    session = await store._read_session_row(hash_token(token))
    role = await store.get_role(CUSTOM)
    approval = await store.get_pending_approval("a-1")
    ad_map = await store.get_ad_map(AD_ROLE_MAP)
    assert record and session and role and approval and ad_map.pairs

    def kinds(sealer: TransitRowSealer) -> list[Callable[[], Awaitable[bool]]]:
        assert record and session and role and approval
        return [
            lambda: user_seal_ok_async(sealer, record),
            lambda: session_seal_ok_async(sealer, session),
            lambda: role_seal_ok_async(sealer, RoleRow.from_mapping(role)),
            lambda: ad_map_seal_ok_async(sealer, ad_map),
            lambda: approval_seal_ok_async(sealer, ApprovalRow.from_mapping(approval)),
        ]

    for index in range(5):
        assert await kinds(TransitRowSealer(backend))[index]() is True
        before = backend.verify_calls
        backend.down = True
        try:
            with pytest.raises(TransitSealUnavailableError):
                await kinds(TransitRowSealer(backend))[index]()
        finally:
            backend.down = False
        assert backend.verify_calls == before + 1, index  # this kind's own Transit call


async def test_the_planted_check_of_every_kind_raises_unverifiable(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    """One kind planted at a time, so every reader is shown to reach Transit on its own row."""
    store, _, path = transit
    await _roles(store)
    await _user(store, "u-1", VIEWER)
    token = await _session(store, "u-1")
    await store.set_ad_group_role_map([("g", VIEWER)])
    await _approval(store, "a-1")
    sealer = store._row_sealer
    _plant(path, "users", "authz_seal", "id", "u-1")
    record = await store._read_user_record("u-1")
    assert record is not None
    with pytest.raises(TransitSealUnverifiableError):
        await user_seal_ok_async(sealer, record)
    _plant(path, "sessions", "seal", "token_hash", hash_token(token))
    session = await store._read_session_row(hash_token(token))
    assert session is not None
    with pytest.raises(TransitSealUnverifiableError):
        await session_seal_ok_async(sealer, session)
    _plant(path, "roles", "seal", "id", CUSTOM)
    role = await store.get_role(CUSTOM)
    assert role is not None
    with pytest.raises(TransitSealUnverifiableError):
        await role_seal_ok_async(sealer, RoleRow.from_mapping(role))
    _plant(path, "authority_set_seal", "seal", "name", AD_ROLE_MAP)
    with pytest.raises(TransitSealUnverifiableError):
        await ad_map_seal_ok_async(sealer, await store.get_ad_map(AD_ROLE_MAP))
    _plant(path, "pending_approvals", "seal", "id", "a-1")
    approval = await store.get_pending_approval("a-1")
    assert approval is not None
    with pytest.raises(TransitSealUnverifiableError):
        await approval_seal_ok_async(sealer, ApprovalRow.from_mapping(approval))


async def test_a_factor_binding_check_runs_through_transit(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    store, _, path = transit
    await _user(store, "u-1")
    token = await _session(store, "u-1")
    cred = WebAuthnCredential(
        credential_id_hash="h-1",
        credential_id="cred-1",
        user_id="u-1",
        rp_id="t",
        public_key="cose-public-key-b64url",
        sign_count=0,
        transports=None,
        device_type="multi_device",
        backed_up=True,
        label="first",
        aaguid="aaguid-0000",
        created_at=1.0,
        last_used_at=None,
        discoverable=False,
    )
    # An account with no factor binds its first from a pending session; the record is re-sealed.
    assert await store.add_webauthn_credential(cred, for_session=hash_token(token))
    second = WebAuthnCredential(**{**cred.__dict__, "credential_id_hash": "h-2", "label": "2nd"})
    # The account now holds a factor this pending session has not proven.
    assert not await store.add_webauthn_credential(second, for_session=hash_token(token))
    # Census pin (1b-iv): an Unverifiable session escapes the check as itself.
    _plant(path, "sessions", "seal", "token_hash", hash_token(token))
    with pytest.raises(TransitSealUnverifiableError):
        await store.add_webauthn_credential(second, for_session=hash_token(token))
    assert len(await store.list_webauthn_credentials("u-1")) == 1


async def test_the_last_administrator_guard_runs_through_transit(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    store, _, path = transit
    await _roles(store)
    await _user(store, "a", ADMIN)
    await _user(store, "b", ADMIN)

    async def removable(target: str) -> bool:
        return await store.remove_unless_last_admin(
            target, AdminRemoval.SET_ROLES, admin_role_id=ADMIN, role_ids=[VIEWER]
        )

    _sql(path, "UPDATE users SET display_name=? WHERE id=?", ("bent", "b"))
    assert not await removable("a")  # b is Forged, so a is the last usable administrator
    await _user(store, "c", ADMIN)
    assert await removable("a")  # control: c is a sealed administrator
    # Census pin (slice 2, "other readers never propagate Unverifiable"): today an Unverifiable
    # other administrator escapes the guard, and the removal writes nothing.
    await _user(store, "d", ADMIN)
    _plant(path, "users", "authz_seal", "id", "c")
    with pytest.raises(TransitSealUnverifiableError):
        await removable("d")
    assert ADMIN in await store.get_user_role_ids("d")


async def test_a_map_edit_and_a_role_delete_run_through_transit(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    store, _, path = transit
    await _roles(store)
    await _user(store, "u-1", CUSTOM)
    await store.set_ad_group_role_map([("g", CUSTOM), ("h", VIEWER)])
    before = (await store.get_ad_map(AD_ROLE_MAP)).seal
    assert await store.delete_custom_role(CUSTOM)  # the map edit and the holder's write both seal
    after = await store.get_ad_map(AD_ROLE_MAP)
    assert after.pairs == (("h", VIEWER),) and after.seal != before
    assert await ad_map_seal_ok_async(store._row_sealer, after)
    assert await store.get_user_role_ids("u-1") == []


async def test_role_delete_census_an_unverifiable_map_escapes(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    """Census pin (1b-iv, ADR 0217 (d)): ``delete_custom_role``'s map catch names RowSealError
    only, so an Unverifiable map escapes it and the whole delete rolls back."""
    store, _, path = transit
    await _roles(store)
    await store.set_ad_group_role_map([("g", CUSTOM)])
    _plant(path, "authority_set_seal", "seal", "name", AD_ROLE_MAP)
    with pytest.raises(RowSealUnverifiableError):
        await store.delete_custom_role(CUSTOM)
    assert await store.get_role(CUSTOM) is not None
    # Control: a Forged map takes main's path, losing the role's pairs, and the delete lands.
    _sql(path, "UPDATE authority_set_seal SET seal=? WHERE name=?", ("forged", AD_ROLE_MAP))
    assert await store.delete_custom_role(CUSTOM)


async def test_role_delete_census_an_unverifiable_holder_escapes(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    """Census pin (1b-iv): the holder catch names RowSealError only, so an Unverifiable holder
    escapes it and the delete rolls back with the holder's row kept."""
    store, _, path = transit
    await _roles(store)
    await _user(store, "u-1", CUSTOM)
    _plant(path, "users", "authz_seal", "id", "u-1")
    with pytest.raises(RowSealUnverifiableError):
        await store.delete_custom_role(CUSTOM)
    assert await store.get_role(CUSTOM) is not None
    assert _sql(path, "SELECT role_id FROM user_roles WHERE user_id=?", ("u-1",)) == [(CUSTOM,)]


async def test_the_approval_paths_run_through_transit(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    store, _, path = transit
    assert await _approval(store, "a-1") == "a-1"
    joined = await store.create_pending_approval(
        approval_id="a-2",
        operation="op",
        params='{"n": "n"}',
        requester="r",
        requester_user_id="r-id",
        requested_at=1.0,
        expires_at=None,
        on_repeat=lambda held: None,  # type: ignore[arg-type,return-value]
    )
    assert joined == "a-1"  # a repeat joins the open request whose seal holds
    assert await store.decide_pending_approval(
        "a-1", status="rejected", approver="ap", decided_at=2.0
    )
    found = await store.get_pending_approval("a-1")
    assert found is not None and found["status"] == "rejected"
    assert await approval_seal_ok_async(store._row_sealer, ApprovalRow.from_mapping(found))
    # A request that fails its seal is moved to rejected under a tombstone, sealed through Transit.
    await _approval(store, "a-3", nonce="other")
    _sql(path, "UPDATE pending_approvals SET params=? WHERE id=?", ('{"n": "bent"}', "a-3"))
    (seal_read,) = _sql(path, "SELECT seal FROM pending_approvals WHERE id=?", ("a-3",))[0]
    assert await store.reject_seal_failed_approval(
        "a-3", approver="ap", decided_at=3.0, seal_read=seal_read, audits=()
    )
    assert _sql(path, "SELECT status FROM pending_approvals WHERE id=?", ("a-3",)) == [
        ("rejected",)
    ]
    assert await store.reseal_approval_records() == (0, 0)  # every row is under the active key


async def test_approval_decide_census_an_unverifiable_row_escapes(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    """Census pin (1b-iv): the gate's decide catches name RowSealError only; an Unverifiable row
    reaches them as its sibling type, and nothing is written."""
    store, _, path = transit
    await _approval(store, "a-1")
    _plant(path, "pending_approvals", "seal", "id", "a-1")
    with pytest.raises(RowSealUnverifiableError):
        await store.decide_pending_approval("a-1", status="rejected", approver="ap", decided_at=2.0)
    assert _sql(path, "SELECT status FROM pending_approvals WHERE id=?", ("a-1",)) == [("pending",)]
    # And the seal-failed reject reads it through the awaitable check, which raises as itself.
    (seal_read,) = _sql(path, "SELECT seal FROM pending_approvals WHERE id=?", ("a-1",))[0]
    with pytest.raises(TransitSealUnverifiableError):
        await store.reject_seal_failed_approval(
            "a-1", approver="ap", decided_at=3.0, seal_read=seal_read, audits=()
        )


async def test_the_role_and_user_reseals_run_through_transit(
    tmp_path: Path,
) -> None:
    """``rotate-key``'s re-seal passes reach only awaitable sealer methods under Transit. A row
    under a listed retired key is moved to the active key; one whose retired-key seal Transit
    cannot check escapes the pass's RowSealError catch (census pin, 1b-iv)."""
    path = tmp_path / "reseal.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        store._row_sealer = TransitRowSealer(FakeBackend(active=RETIRED))
        await _roles(store)
        await _user(store, "u-1", VIEWER)
        await store.set_ad_group_role_map([("g", VIEWER)])
        store._row_sealer = TransitRowSealer(FakeBackend(), retired_key_names=[RETIRED])
        resealed, refused = await store.reseal_role_records()
        assert (resealed, refused) == (4, 0)  # three role rows and the map
        assert await store.reseal_user_records() == (1, 0)
        assert await store.reseal_role_records() == (0, 0)  # control: nothing left to move
        store._row_sealer = TransitRowSealer(FakeBackend(active=RETIRED))
        await _user(store, "u-2")
        store._row_sealer = TransitRowSealer(FakeBackend(), retired_key_names=[RETIRED])
        _plant(path, "users", "authz_seal", "id", "u-2")
        with pytest.raises(RowSealUnverifiableError):
            await store.reseal_user_records()
    finally:
        await store.close()


# --- the session sweeps and stamps: census pins ---------------------------------------------------


async def test_epoch_raise_census_an_unverifiable_account_keeps_its_sessions(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    """Census pin (1b-iv): ``_bump_session_epoch`` catches RowSealError only. On main a Forged
    account's sessions end anyway; an Unverifiable one's raise escapes and the sweep rolls back,
    so its sessions stay live. The control is the Forged account, whose sessions end."""
    store, _, path = transit
    await _user(store, "u-1")
    await _user(store, "u-2")
    planted = await _session(store, "u-1")
    forged = await _session(store, "u-2")
    _plant(path, "users", "authz_seal", "id", "u-1")
    with pytest.raises(RowSealUnverifiableError):
        await store.revoke_user_sessions("u-1")
    assert _sql(
        path, "SELECT revoked_at FROM sessions WHERE token_hash=?", (hash_token(planted),)
    ) == [(None,)]
    _sql(path, "UPDATE users SET display_name=? WHERE id=?", ("bent", "u-2"))
    result = await store.revoke_user_sessions("u-2")
    assert result.count == 1
    (revoked_at,) = _sql(
        path, "SELECT revoked_at FROM sessions WHERE token_hash=?", (hash_token(forged),)
    )[0]
    assert revoked_at is not None


async def test_kept_session_census_an_unverifiable_kept_session_escapes(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    """Census pin (1b-iv): ``_keep_or_end_session`` restamps through the session writer, whose
    Unverifiable answer escapes ``revoke_other_sessions``' and ``revoke_every_session``'s
    RowSealError catches; the sweep rolls back, ending no other session."""
    store, _, path = transit
    await _user(store, "u-1")
    kept = await _session(store, "u-1")
    other = await _session(store, "u-1")
    _plant(path, "sessions", "seal", "token_hash", hash_token(kept))
    with pytest.raises(RowSealUnverifiableError):
        await store.revoke_user_sessions("u-1", except_token_hash=hash_token(kept))
    with pytest.raises(RowSealUnverifiableError):
        await store.revoke_all_sessions(except_token_hash=hash_token(kept))
    assert _sql(
        path, "SELECT revoked_at FROM sessions WHERE token_hash=?", (hash_token(other),)
    ) == [(None,)]


async def test_session_stamp_census_an_unverifiable_session_escapes(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    """Census pin (1b-iv): ``_sealed_stamp`` and ``_rotate_session_hash`` in the service catch
    RowSealError only; the store's stamp and rotation raise the sibling type for an Unverifiable
    session, and write nothing. A Forged one stays RowSealError, as on main."""
    store, _, path = transit
    await _user(store, "u-1")
    token = await _session(store, "u-1")
    _plant(path, "sessions", "seal", "token_hash", hash_token(token))
    with pytest.raises(RowSealUnverifiableError):
        await store.mark_session_reauthed(hash_token(token), now=5.0)
    with pytest.raises(RowSealUnverifiableError):
        await store.rotate_session(hash_token(token), new_token_hash=hash_token(mint_token()))
    assert _sql(
        path, "SELECT reauth_at FROM sessions WHERE token_hash=?", (hash_token(token),)
    ) != [(5.0,)]
    _sql(path, "UPDATE sessions SET seal=? WHERE token_hash=?", ("forged", hash_token(token)))
    with pytest.raises(RowSealError):
        await store.mark_session_reauthed(hash_token(token), now=5.0)


# --- the service readers ----------------------------------------------------------------------------


async def test_the_service_readers_run_through_transit(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    """The service's session, user, role and map loaders await the seam: a sealed session
    resolves, a Forged one is ended as on main, and an Unverifiable one escapes the loader as
    itself (census pin, slice 2: the unverifiable action and its report are not built here)."""
    store, _, path = transit
    service = AuthService(store, AuthSettings())
    await _roles(store)
    await _user(store, "u-1", VIEWER)
    await store.set_ad_group_role_map([("g", CUSTOM)])
    token = await _session(store, "u-1")
    identity = await service.identity_for_token(token)
    assert identity is not None and identity.user_id == "u-1"
    assert await service._load_role(CUSTOM) is not None
    assert (await service._ad_map(AD_ROLE_MAP)).pairs == (("g", CUSTOM),)
    forged = await _session(store, "u-1")
    _sql(path, "UPDATE sessions SET client=? WHERE token_hash=?", ("192.0.2.9", hash_token(forged)))
    assert await service.identity_for_token(forged) is None
    (revoked_at,) = _sql(
        path, "SELECT revoked_at FROM sessions WHERE token_hash=?", (hash_token(forged),)
    )[0]
    assert revoked_at is not None
    _plant(path, "sessions", "seal", "token_hash", hash_token(token))
    with pytest.raises(TransitSealUnverifiableError):
        await service.identity_for_token(token)
    _plant(path, "roles", "seal", "id", CUSTOM)
    with pytest.raises(TransitSealUnverifiableError):
        await service._load_role(CUSTOM)


async def test_a_tombstone_under_a_retired_key_is_resealed_through_transit(tmp_path: Path) -> None:
    """``rotate-key``'s approval pass moves a rejected row's tombstone seal to the active key
    through the awaitable tombstone check and seal, never through a sync-only sealer method."""
    path = tmp_path / "tombstone.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        store._row_sealer = TransitRowSealer(FakeBackend(active=RETIRED))
        await _approval(store, "a-1")
        _sql(path, "UPDATE pending_approvals SET params=? WHERE id=?", ('{"n": "bent"}', "a-1"))
        (seal_read,) = _sql(path, "SELECT seal FROM pending_approvals WHERE id=?", ("a-1",))[0]
        assert await store.reject_seal_failed_approval(
            "a-1", approver="ap", decided_at=3.0, seal_read=seal_read, audits=()
        )
        (old,) = _sql(path, "SELECT seal FROM pending_approvals WHERE id=?", ("a-1",))[0]
        sealer = TransitRowSealer(FakeBackend(), retired_key_names=[RETIRED])
        store._row_sealer = sealer
        assert await store.reseal_approval_records() == (1, 0)
        (new,) = _sql(path, "SELECT seal FROM pending_approvals WHERE id=?", ("a-1",))[0]
        assert new != old and sealer.is_active(str(new))
        assert await store.reseal_approval_records() == (0, 0)  # control: nothing left to move
    finally:
        await store.close()


async def test_a_refused_retired_key_lookup_still_ends_and_reports_the_session(
    tmp_path: Path,
) -> None:
    """Owner ruling 2026-11-08 ("Revoke, then report"): ``_session_row_holds`` asks whether a
    failed session was sealed under a retired key. Under Transit that is a Transit call; when a
    403 on the retired key makes it raise, the row is still ended, then reported as an integrity
    failure. The control is the same row with the retired key answering: ended quietly."""
    path = tmp_path / "retired-session.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        store._row_sealer = TransitRowSealer(FakeBackend(active=RETIRED))
        await _user(store, "u-1")
        refused = await _session(store, "u-1")
        quiet = await _session(store, "u-1")
        backend = FakeBackend()
        store._row_sealer = TransitRowSealer(backend, retired_key_names=[RETIRED])
        service = AuthService(store, AuthSettings())
        backend.forbid = {RETIRED}
        assert await service.identity_for_token(refused) is None
        assert _revoked(path, refused)
        assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1
        backend.forbid = set()
        store._row_sealer = TransitRowSealer(backend, retired_key_names=[RETIRED])
        assert await AuthService(store, AuthSettings()).identity_for_token(quiet) is None
        assert _revoked(path, quiet)
        assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1
    finally:
        await store.close()


def _revoked(path: Path, token: str) -> bool:
    (revoked_at,) = _sql(
        path, "SELECT revoked_at FROM sessions WHERE token_hash=?", (hash_token(token),)
    )[0]
    return revoked_at is not None


async def test_an_outage_at_rotation_revokes_the_session(
    transit: tuple[MessageStore, FakeBackend, Path],
) -> None:
    """Owner ruling 2026-11-08 ("Revoke both"): a Transit Outage at the rotation's load or at the
    store's re-key revokes the session, as BACKLOG #3023 does for a store refusal, and raises the
    rotation-store error. The control is a rotation with Transit up, which re-keys the row."""
    store, backend, path = transit
    await _user(store, "u-1")
    service = AuthService(store, AuthSettings())
    control = await _session(store, "u-1")
    new = await service._rotate_session_hash(hash_token(control))
    assert new is not None and not _revoked(path, new)
    assert _sql(path, "SELECT 1 FROM sessions WHERE token_hash=?", (hash_token(control),)) == []
    # The load: a fresh sealer has nothing cached, so the load's check meets the Outage.
    at_load = await _session(store, "u-1")
    store._row_sealer = TransitRowSealer(backend)
    backend.down = True
    try:
        with pytest.raises(_RotationStoreError):
            await service._rotate_session_hash(hash_token(at_load))
    finally:
        backend.down = False
    assert _revoked(path, at_load)
    # The re-key: the load's Holds answer is cached, and the new seal's hmac meets the Outage.
    at_rekey = await _session(store, "u-1")
    store._row_sealer = TransitRowSealer(backend)
    assert await service.identity_for_token(at_rekey) is not None
    hmac_down = backend.seal_hmac

    def refused(digest: bytes) -> str:
        raise CipherError("synthetic outage")

    backend.seal_hmac = refused  # type: ignore[method-assign]
    try:
        with pytest.raises(_RotationStoreError):
            await service._rotate_session_hash(hash_token(at_rekey))
    finally:
        backend.seal_hmac = hmac_down  # type: ignore[method-assign]
    assert _revoked(path, at_rekey)
