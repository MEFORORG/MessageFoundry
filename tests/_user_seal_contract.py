# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for the sealed user record (BACKLOG #2592).

Deliberately **extra-free**, as ``tests/_session_seal_contract.py`` is: it imports nothing optional,
so the live Postgres and SQL Server suites import it inside their test functions and run the same
assertions on legs that install only their own driver extra.

The caller passes a store opened with a store key, and ``raw``: a way to run one SQL statement
against the same database without going through the store's helpers. ``raw`` takes SQL written
with ``?`` placeholders and its parameters; each backend's adapter respells the placeholders for
its driver and commits.

Every refusal below has a control beside it: the same account resolves before the change, or the
same change made through the store keeps it resolving. A seal that refused everything, or accepted
everything, fails this contract.
"""

from __future__ import annotations

import json
import time
from dataclasses import fields
from typing import Any

from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AUTHORITY_SEAL_FAILED_ACTION, AuthService
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.row_seal import SEAL_PREFIX, RowSealError
from messagefoundry.store.store import (
    RoleGrant,
    UnknownRoleError,
    UserAuthzRecord,
    UserRow,
    WebAuthnCredential,
    new_user_record,
    user_seal_ok,
)
from tests._session_seal_contract import RawSql

#: The one password every contract account is created with.
_PASSWORD = "contract-password-1"

#: Each sealed ``users`` column, and a value that differs from what ``_account`` writes. Booleans
#: are Python ``bool`` so every driver binds them to its own type.
_USER_SEALED_CHANGES: tuple[tuple[str, Any], ...] = (
    ("username", "seal-renamed"),
    ("auth_provider", "ad"),
    ("display_name", "Someone Else"),
    ("email", "other@example.test"),
    ("notify_email", "other@example.test"),
    ("disabled", True),
    ("created_at", 1.0),
    ("updated_at", 1.0),
    ("last_login_at", 1.0),
    ("password_hash", "not-the-hash"),
    ("password_changed_at", 1.0),
    ("must_change_password", True),
    ("failed_attempts", 3),
    ("locked_until", 1.0),
    ("channel_scope", '["*"]'),
    ("totp_enabled", True),
    ("totp_enrolled_at", 1.0),
    ("totp_recovery_codes", '["x"]'),
    ("last_totp_step", 5),
    ("oidc_issuer", "https://idp.example.test"),
    ("directory_object_id", "guid-other"),
    ("password_claimed_at", 1.0),
    ("channel_scope_source", "ad"),
    ("lock_cycles", 2),
    ("second_step_failed_attempts", 2),
    ("second_step_locked_until", 1.0),
    ("second_step_lock_cycles", 2),
    ("password_generated", True),
    ("session_epoch", 9),
    ("cred_digest", "not-the-digest"),
)


def assert_user_columns(columns: set[str]) -> None:
    """The ``users`` table has exactly :class:`UserRow`'s fields, so a column added to one and not
    the other cannot sit outside the seal unnoticed (BACKLOG #2592)."""
    assert {c.lower() for c in columns} == {f.name for f in fields(UserRow)}


class _Harness:
    def __init__(self, store: Any, raw: RawSql) -> None:
        self.store = store
        self.raw = raw
        self.alerts: list[str] = []
        self.service = AuthService(store, AuthSettings(), integrity_alert=self.alerts.append)
        self._n = 0

    async def account(self, name: str, *, roles: tuple[str, ...] = (Role.VIEWER.value,)) -> str:
        self._n += 1
        user_id = f"seal-{name}-{self._n}"
        await self.store.create_user(
            user_id=user_id,
            username=user_id,
            auth_provider="local",
            password_hash=hash_password(_PASSWORD),
            must_change_password=False,
            password_generated=False,
        )
        await self.store.set_user_roles(user_id, list(roles), assigned_by="contract")
        await self.store.set_user_channel_scope(user_id, '["IB_A"]', source="manual")
        return user_id

    async def token(self, user_id: str) -> str:
        token = mint_token()
        await self.store.create_session(
            token_hash=hash_token(token),
            user_id=user_id,
            expires_at=time.time() + 3600,
            client="192.0.2.10",
            auth_mechanism="password",
        )
        return token

    async def seal_failures(self) -> int:
        return len(await self.store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION))


async def _record(store: Any, user_id: str) -> UserAuthzRecord:
    user = await store.get_user(user_id)
    assert user is not None and user.row is not None
    return UserAuthzRecord.of(user.row, await store.get_user_role_grants(user_id))


async def assert_user_seal_contract(store: Any, raw: RawSql) -> None:
    """Drive the sealed user record through its whole contract on ``store``'s backend."""
    sealer = store.row_sealer()
    assert sealer is not None, "the contract needs a store opened with a store key"
    h = _Harness(store, raw)
    await h.service.initialize()

    # --- an account the store wrote carries a seal and resolves --------------------------------
    viewer = await h.account("viewer")
    record = await _record(store, viewer)
    assert record.row.authz_seal.startswith(SEAL_PREFIX)
    assert user_seal_ok(sealer, record)
    token = await h.token(viewer)
    identity = await h.service.identity_for_token(token)
    assert identity is not None and Role.ADMINISTRATOR not in identity.roles
    assert identity.allowed_channels == frozenset({"IB_A"})
    assert h.alerts == []  # control: a sealed record raises nothing

    # --- a role row inserted outside the store grants nothing, and is reported ----------------
    await raw(
        "INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by) VALUES (?,?,?,?)",
        (viewer, Role.ADMINISTRATOR.value, 1.0, None),
    )
    assert await h.service.identity_for_token(token) is None
    assert len(h.alerts) == 1 and viewer in h.alerts[0]
    assert await h.seal_failures() == 1
    # Control: the same grant through the store takes effect.
    granted = await h.account("granted")
    await store.set_user_roles(
        granted, [Role.VIEWER.value, Role.ADMINISTRATOR.value], assigned_by="contract"
    )
    promoted = await h.service.identity_for_token(await h.token(granted))
    assert promoted is not None and Role.ADMINISTRATOR in promoted.roles

    # --- a role row deleted outside the store fails the record too ----------------------------
    demoted = await h.account("demoted", roles=(Role.VIEWER.value, Role.OPERATOR.value))
    demoted_token = await h.token(demoted)
    assert await h.service.identity_for_token(demoted_token) is not None  # control
    await raw(
        "DELETE FROM user_roles WHERE user_id=? AND role_id=?", (demoted, Role.OPERATOR.value)
    )
    assert await h.service.identity_for_token(demoted_token) is None

    # --- every sealed column changed outside the store resolves to nothing --------------------
    for column, value in _USER_SEALED_CHANGES:
        changed = await h.account(column.replace("_", "-"))
        changed_token = await h.token(changed)
        assert await h.service.identity_for_token(changed_token) is not None, column  # control
        if column == "username":
            value = f"{changed}-renamed"
        await raw(f"UPDATE users SET {column}=? WHERE id=?", (value, changed))
        assert await h.service.identity_for_token(changed_token) is None, column
        assert await h.service._load_user(changed) is None, column

    # --- the scope widened outside the store grants nothing; through the store it does --------
    scoped = await h.account("scoped")
    await store.set_user_channel_scope(scoped, '["*"]', source="manual")
    wide = await h.service.identity_for_token(await h.token(scoped))
    assert wide is not None and wide.allowed_channels is None

    # --- a password hash written outside the store proves nothing at a step-up ----------------
    proven = await h.account("proven")
    proven_token = await h.token(proven)
    proven_identity = await h.service.identity_for_token(proven_token)
    assert proven_identity is not None
    chosen = "chosen-password-2"
    await raw("UPDATE users SET password_hash=? WHERE id=?", (hash_password(chosen), proven))
    assert not (await h.service.reauth(proven_identity, chosen, token=proven_token)).ok
    # Control: the same password set through the store re-proves a fresh session.
    rotated = await h.account("rotated")
    await store.set_password(
        rotated,
        password_hash=hash_password(chosen),
        password_generated=False,
        must_change_password=False,
    )
    rotated_token = await h.token(rotated)
    rotated_identity = await h.service.identity_for_token(rotated_token)
    assert rotated_identity is not None
    assert (await h.service.reauth(rotated_identity, chosen, token=rotated_token)).ok

    # --- the TOTP secret's stored bytes are sealed: an earlier value put back is refused ------
    enrolled = await h.account("enrolled")
    await store.set_totp_secret(enrolled, secret="JBSWY3DPEHPK3PXP")
    earlier = (await _record(store, enrolled)).row.totp_secret
    await store.set_totp_secret(enrolled, secret="AAAAAAAAAAAAAAAA")
    assert await h.service._load_user(enrolled) is not None  # control: the store's own write
    await raw("UPDATE users SET totp_secret=? WHERE id=?", (earlier, enrolled))
    assert await h.service._load_user(enrolled) is None
    cleared = await h.account("cleared")
    await store.set_totp_secret(cleared, secret="JBSWY3DPEHPK3PXP")
    await raw("UPDATE users SET totp_secret=NULL WHERE id=?", (cleared,))
    assert await h.service._load_user(cleared) is None

    # --- a passkey row inserted outside the store fails the account's passkeys ----------------
    keyed = await h.account("keyed")
    await store.add_webauthn_credential(_credential(keyed, "pk-store"))
    keyed_user = await h.service._load_user(keyed)
    assert keyed_user is not None and keyed_user.has_passkeys
    held = await h.service._verified_passkeys(keyed_user)
    assert held is not None and [c.credential_id_hash for c in held] == [f"{keyed}-pk-store"]
    planted = _credential(keyed, "pk-planted")
    await raw(
        "INSERT INTO webauthn_credentials (credential_id_hash, credential_id, user_id, rp_id,"
        " public_key, sign_count, transports, device_type, backed_up, label, aaguid, created_at,"
        " last_used_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            planted.credential_id_hash,
            planted.credential_id,
            keyed,
            planted.rp_id,
            planted.public_key,
            0,
            None,
            planted.device_type,
            False,
            planted.label,
            None,
            planted.created_at,
            None,
        ),
    )
    keyed_user = await h.service._load_user(keyed)
    assert keyed_user is not None  # the record itself still holds; its passkey set does not
    assert await h.service._verified_passkeys(keyed_user) is None
    # A passkey write over a set that fails is refused, and does not seal the planted row in.
    try:
        await store.add_webauthn_credential(_credential(keyed, "pk-later"))
    except RowSealError:
        pass
    else:
        raise AssertionError("a passkey write over a set that fails its digest was not refused")
    # The sign count is outside the digest: a counter moved through the store keeps the set whole.
    counted = await h.account("counted")
    await store.add_webauthn_credential(_credential(counted, "pk-count"))
    assert (
        await store.update_webauthn_sign_count(
            f"{counted}-pk-count", expected=0, new=7, used_at=time.time()
        )
        == "moved"
    )
    counted_user = await h.service._load_user(counted)
    assert counted_user is not None
    assert await h.service._verified_passkeys(counted_user) is not None
    # Clearing every passkey needs no check, so an administrator's reset still clears a bad set.
    assert await store.delete_all_webauthn_credentials(keyed) == 2
    reset = await h.service._load_user(keyed)
    assert reset is not None and not reset.has_passkeys
    assert await h.service._verified_passkeys(reset) == []

    # --- the write helper refuses a record whose seal fails, and does not re-seal it ----------
    bent = await h.account("bent")
    await raw("UPDATE users SET display_name=? WHERE id=?", ("Bent", bent))
    before = await _record(store, bent)
    for write in (
        lambda: store.set_user_disabled(bent, disabled=False),
        lambda: store.set_user_roles(bent, [Role.VIEWER.value]),
        lambda: store.set_user_channel_scope(bent, '["IB_A"]', source="manual"),
        lambda: store.record_login_success(bent),
        lambda: store.set_password(
            bent, password_hash="h", password_generated=False, must_change_password=False
        ),
    ):
        try:
            await write()
        except RowSealError:
            pass
        else:
            raise AssertionError("a write over a record that fails its seal was not refused")
    assert await _record(store, bent) == before  # nothing written, so the bad seal stands
    assert await h.service._load_user(bent) is None

    # --- a valid seal copied from another account does not carry over -------------------------
    donor = await _record(store, await h.account("donor"))
    taker = await h.account("taker")
    await raw("UPDATE users SET authz_seal=? WHERE id=?", (donor.row.authz_seal, taker))
    assert await h.service._load_user(taker) is None

    # --- ending every session raises the sealed epoch through the helper ----------------------
    epoch = await h.account("epoch")
    first = await h.token(epoch)
    await store.revoke_user_sessions(epoch)
    after_revoke = await _record(store, epoch)
    assert after_revoke.row.session_epoch == 1 and user_seal_ok(sealer, after_revoke)
    assert await h.service.identity_for_token(first) is None
    assert await h.service.identity_for_token(await h.token(epoch)) is not None

    # --- a custom role deleted for every holder re-seals each holder --------------------------
    custom = await h.service.create_custom_role(
        display_name="contract-role",
        description=None,
        permissions=["monitoring:read"],
        actor="contract",
    )
    holder = await h.account("holder", roles=(Role.VIEWER.value, custom.id))
    assert await store.delete_custom_role(custom.id)
    kept = await h.service._load_user(holder)
    assert kept is not None and kept.role_ids == (Role.VIEWER.value,)

    # --- a grant of a role deleted before the write is refused, and seals nothing --------------
    # A caller that checked the role, then lost it to a delete, reaches the store with a stale id.
    gone = await _custom_role(h, "contract-gone")
    assert await store.delete_custom_role(gone)
    late = await h.account("late")
    before_late = await _record(store, late)
    try:
        await store.set_user_roles(late, [Role.VIEWER.value, gone], assigned_by="contract")
    except UnknownRoleError as exc:
        assert exc.role_ids == (gone,)
    else:
        raise AssertionError("a grant of a role with no roles row was not refused")
    assert await _record(store, late) == before_late  # nothing written, seal and all
    assert await h.service._load_user(late) is not None
    # Control: the same write naming a role that exists grants it, sealed.
    live = await _custom_role(h, "contract-live")
    await store.set_user_roles(late, [Role.VIEWER.value, live], assigned_by="contract")
    granted_late = await h.service._load_user(late)
    assert granted_late is not None
    assert granted_late.role_ids == tuple(sorted((Role.VIEWER.value, live)))


async def _custom_role(h: _Harness, name: str) -> str:
    role = await h.service.create_custom_role(
        display_name=name, description=None, permissions=["monitoring:read"], actor="contract"
    )
    return role.id


async def assert_role_delete_race_refused(
    store: Any, foreign_key_error: type[BaseException]
) -> None:
    """A grant that commits while its custom role is being deleted leaves no role row with no role
    behind it (BACKLOG #2592). Server backends only: SQLite runs one writer at a time, so the grant
    cannot land inside the delete there.

    The grant is made on a second connection after the delete has read the role's holders and
    before it deletes the role, which is the order a holder read cannot see. The ``user_roles``
    foreign key then fails the delete, which rolls back whole; ``foreign_key_error`` is what the
    backend's driver raises for it."""
    h = _Harness(store, _no_raw)
    await h.service.initialize()
    role = await _custom_role(h, "contract-race")
    holder = await h.account("race-holder", roles=(Role.VIEWER.value, role))
    granted = await h.account("race-granted")

    real_write = store._write_user
    fired = False

    async def grant_mid_delete(*args: Any, **kwargs: Any) -> Any:
        nonlocal fired
        if not fired:
            fired = True
            await store.set_user_roles(granted, [Role.VIEWER.value, role], assigned_by="contract")
        return await real_write(*args, **kwargs)

    store._write_user = grant_mid_delete
    try:
        await store.delete_custom_role(role)
    except foreign_key_error:
        pass
    else:
        raise AssertionError("a role delete that raced a committed grant was not refused")
    finally:
        del store._write_user  # back to the class's method
    assert fired, "the grant never ran inside the delete, so nothing was raced"
    # The delete rolled back whole: the role stands, and both holders keep it, sealed.
    assert await store.get_role(role) is not None
    for user_id in (holder, granted):
        user = await h.service._load_user(user_id)
        assert user is not None and role in user.role_ids, user_id
    # Control: run again with no grant in flight, the delete takes the role from both, re-sealed.
    assert await store.delete_custom_role(role)
    for user_id in (holder, granted):
        user = await h.service._load_user(user_id)
        assert user is not None and user.role_ids == (Role.VIEWER.value,), user_id


async def _no_raw(sql: str, params: tuple[Any, ...]) -> None:
    raise AssertionError("the race contract runs no raw SQL")


async def assert_user_record_round_trips(store: Any) -> None:
    """AC-19: what the store reads back seals the same as the record it was asked to write, so the
    canonical bytes are one value on every backend (BACKLOG #2592)."""
    await AuthService(store, AuthSettings()).initialize()  # the built-in roles
    now = 1_700_000_000.25
    await store.create_user(
        user_id="seal-fixed",
        username="seal-fixed",
        auth_provider="local",
        display_name="Fixed Name",
        email="fixed@example.test",
        password_hash="fixed-hash",
        must_change_password=False,
        password_generated=False,
        directory_object_id="guid-fixed",
        now=now,
    )
    await store.set_user_roles(
        "seal-fixed", [Role.VIEWER.value], assigned_by="contract", now=now + 1
    )
    expected = UserAuthzRecord.of(
        new_user_record(
            user_id="seal-fixed",
            username="seal-fixed",
            auth_provider="local",
            display_name="Fixed Name",
            email="fixed@example.test",
            notify_email="fixed@example.test",
            password_hash="fixed-hash",
            must_change_password=False,
            password_generated=False,
            directory_object_id="guid-fixed",
            now=now,
        ).row,
        [RoleGrant(Role.VIEWER.value, now + 1, "contract")],
    )
    got = await _record(store, "seal-fixed")
    assert got.seal_fields() == expected.seal_fields()
    assert json.dumps([list(p) for p in got.seal_fields()]) == json.dumps(
        [list(p) for p in expected.seal_fields()]
    )


def _credential(user_id: str, name: str) -> WebAuthnCredential:
    return WebAuthnCredential(
        credential_id_hash=f"{user_id}-{name}",
        credential_id=f"cid-{user_id}-{name}",
        user_id=user_id,
        rp_id="console.example.test",
        public_key="cGs",
        sign_count=0,
        transports=["usb"],
        device_type="single_device",
        backed_up=False,
        label=name,
        aaguid=None,
        created_at=1_700_000_000.0,
    )
