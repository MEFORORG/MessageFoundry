# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0197 Amendment A, wave 2 (option N-G, BACKLOG #3373): a discoverable passkey is a way past
the sign-in lock.

Wave 1 counted TOTP alone, so a holder under ``[security].require_mfa`` had to enrol TOTP even if
they wanted only a passkey, and could never remove it. Wave 2 records whether each passkey was
registered as a discoverable credential, counts such a passkey as a way past in the rotation gate,
the last-factor guards and the census, and gives it a usernameless combined sign-in. Every ceremony
here is real: the in-repo soft authenticator drives py_webauthn's own verify functions.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("webauthn")

from webauthn.helpers import base64url_to_bytes  # noqa: E402

from messagefoundry.auth.identity import Identity  # noqa: E402
from messagefoundry.auth.service import (  # noqa: E402
    PASSKEY_NOT_DISCOVERABLE,
    PASSKEY_REMOVAL_REFUSED,
    TOTP_REMOVAL_REFUSED,
    AuthService,
    FactorEnrolmentRequired,
    lockable_account_census,
)
from messagefoundry.config.settings import AuthSettings  # noqa: E402
from messagefoundry.store.store import MessageStore  # noqa: E402
from tests._admin_account import login_admin  # noqa: E402
from tests._soft_webauthn import SoftAuthenticator  # noqa: E402

RP = "t"
ORIGIN = "http://t"
_NEW_PASSWORD = "a-brand-new-chosen-passphrase-9"


def _service(store: MessageStore, **settings: Any) -> AuthService:
    """``require_mfa`` stays at its shipped default (on) unless an arm says otherwise, so the test
    administrator is covered by the requirement."""
    settings.setdefault("mfa_verify_min_elapsed_seconds", 0)
    settings.setdefault("login_rate_limit_enabled", False)
    return AuthService(store, AuthSettings(**settings))


async def _register(
    service: AuthService,
    identity: Identity,
    token: str,
    *,
    resident_key: bool | None = None,
    label: str = "key",
) -> tuple[SoftAuthenticator, str]:
    """One real registration ceremony. ``resident_key`` is the ``credProps.rk`` the client reports;
    ``None`` reports none. Returns the authenticator and the token to use next."""
    auth = SoftAuthenticator(rp_id=RP, origin=ORIGIN, user_handle=identity.user_id.encode())
    options = json.loads(
        await service.begin_webauthn_registration(identity, token=token, rp_id=RP, rp_name="MF")
    )
    elevation = await service.finish_webauthn_registration(
        identity,
        auth.create_response(base64url_to_bytes(options["challenge"]), resident_key=resident_key),
        label=label,
        token=token,
        rp_id=RP,
        origin=ORIGIN,
    )
    assert elevation.ok and elevation.token is not None
    return auth, elevation.token


# --- part 1: registration asks for, and records, a discoverable credential ------------------------


async def test_registration_requires_a_discoverable_credential_and_asks_for_cred_props() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        options = json.loads(
            await service.begin_webauthn_registration(identity, token=token, rp_id=RP, rp_name="M")
        )
        selection = options["authenticatorSelection"]
        assert selection["residentKey"] == "required" and selection["requireResidentKey"] is True
        assert options["extensions"] == {"credProps": True}
    finally:
        await store.close()


@pytest.mark.parametrize(("reported", "recorded"), [(None, True), (True, True), (False, False)])
async def test_registration_records_what_the_client_reported_or_the_requirement(
    reported: bool | None, recorded: bool
) -> None:
    """The column records ``credProps.rk`` where the client reports it, and the ``required``
    request otherwise. Registered with the requirement off, so the not-discoverable arm stores."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store, require_mfa=False)
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token, resident_key=reported)
        (cred,) = await store.list_webauthn_credentials(identity.user_id)
        assert cred.discoverable is recorded
    finally:
        await store.close()


async def test_a_covered_first_factor_the_client_says_is_not_discoverable_is_refused() -> None:
    """AC-A3: a covered account with no way past may take only a factor with one as its first. The
    refusal is at the finish, after the verify, and stores nothing."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        auth = SoftAuthenticator(rp_id=RP, origin=ORIGIN)
        options = json.loads(
            await service.begin_webauthn_registration(identity, token=token, rp_id=RP, rp_name="M")
        )
        with pytest.raises(ValueError) as refused:
            await service.finish_webauthn_registration(
                identity,
                auth.create_response(base64url_to_bytes(options["challenge"]), resident_key=False),
                label="key",
                token=token,
                rp_id=RP,
                origin=ORIGIN,
            )
        assert str(refused.value) == PASSKEY_NOT_DISCOVERABLE
        assert await store.list_webauthn_credentials(identity.user_id) == []
    finally:
        await store.close()


# --- part 4: the rotation gate and the last-factor guards count a discoverable passkey -------------


async def test_a_discoverable_passkey_opens_the_rotation_gate() -> None:
    """AC-A3, wave 2: a covered account whose first factor is a discoverable passkey may rotate,
    which wave 1 refused until TOTP existed."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        assert await service.must_enrol_before_rotating(identity)
        with pytest.raises(FactorEnrolmentRequired):
            await service.change_password(identity, _NEW_PASSWORD)
        await _register(service, identity, token)
        assert not await service.must_enrol_before_rotating(identity)
        assert await service.change_password(identity, _NEW_PASSWORD) == []
        row = await store.get_user(identity.user_id)
        assert row is not None and not row.password_generated and not row.totp_enabled
    finally:
        await store.close()


async def test_a_passkey_that_is_not_discoverable_leaves_the_rotation_gate_shut() -> None:
    store = await MessageStore.open(":memory:")
    try:
        setup = _service(store, require_mfa=False)
        identity, token, _ = await login_admin(setup)
        await _register(setup, identity, token, resident_key=False)
        service = _service(store)
        assert await service.must_enrol_before_rotating(identity)
        with pytest.raises(FactorEnrolmentRequired):
            await service.change_password(identity, _NEW_PASSWORD)
    finally:
        await store.close()


async def test_the_last_discoverable_passkey_cannot_be_removed_while_covered() -> None:
    """AC-A3a, wave 2: removing the account's last way past is refused; a passkey that is not
    discoverable can always go on this ground, and a second discoverable passkey frees the first."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        _, token = await _register(service, identity, token, label="first")
        _, token = await _register(service, identity, token, resident_key=False, label="plain")
        by_label = {c.label: c for c in await store.list_webauthn_credentials(identity.user_id)}

        with pytest.raises(ValueError) as refused:
            await service.delete_webauthn_credential(identity, by_label["first"].credential_id_hash)
        assert str(refused.value) == PASSKEY_REMOVAL_REFUSED
        assert await service.delete_webauthn_credential(
            identity, by_label["plain"].credential_id_hash
        )

        _, token = await _register(service, identity, token, label="second")
        assert await service.delete_webauthn_credential(
            identity, by_label["first"].credential_id_hash
        )
        (left,) = await store.list_webauthn_credentials(identity.user_id)
        assert left.label == "second" and left.discoverable
    finally:
        await store.close()


async def test_totp_can_be_removed_while_a_discoverable_passkey_remains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-A3a, wave 2: the twin of the passkey guard. TOTP goes while a discoverable passkey stays
    as the way past; beside a passkey that is not discoverable it stays refused, as in wave 1."""
    from messagefoundry.auth import totp
    from tests._totp_clock import pin_totp_clock

    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        enroll = await service.begin_mfa_enrollment(identity)
        pin_totp_clock(monkeypatch, 1_000_000.0)
        confirmed = await service.confirm_mfa_enrollment(
            identity, totp.totp(enroll.secret, now=1_000_000.0), token=token
        )
        assert confirmed.ok and confirmed.token is not None
        token = confirmed.token
        _, token = await _register(service, identity, token, resident_key=False, label="plain")
        with pytest.raises(ValueError) as refused:
            await service.disable_mfa(identity)
        assert str(refused.value) == TOTP_REMOVAL_REFUSED

        _, token = await _register(service, identity, token, label="resident")
        await service.disable_mfa(identity)
        row = await store.get_user(identity.user_id)
        assert row is not None and not row.totp_enabled
    finally:
        await store.close()


async def test_the_census_counts_a_discoverable_passkey_as_a_way_past() -> None:
    """AC-A9 with wave 2: a covered account with a chosen password and only a discoverable passkey
    is not named as lockable; it is named as passkey-only, which is informational."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token)
        await service.change_password(identity, _NEW_PASSWORD)
        census = await lockable_account_census(store, AuthSettings())
        assert census.no_way_past == () and census.clean
        assert census.passkey_only == (identity.username,)
    finally:
        await store.close()


async def test_the_census_names_an_account_whose_only_passkey_is_not_discoverable() -> None:
    store = await MessageStore.open(":memory:")
    try:
        setup = _service(store, require_mfa=False)
        identity, token, _ = await login_admin(setup)
        await _register(setup, identity, token, resident_key=False)
        await setup.change_password(identity, _NEW_PASSWORD)
        census = await lockable_account_census(store, AuthSettings())
        assert census.no_way_past == (identity.username,) and census.passkey_only == ()
    finally:
        await store.close()


async def test_a_passkey_flipped_to_discoverable_outside_the_store_opens_nothing(
    tmp_path: Any,
) -> None:
    """The discoverable flag is covered by the account's seal, through the passkey digest. A row
    flipped by hand fails the set, so neither the service's gate nor the store's conditional write
    counts it as a way past."""
    from messagefoundry.store.crypto import generate_key, make_cipher

    store = await MessageStore.open(
        tmp_path / "keyed.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    try:
        assert store.row_sealer() is not None, "the arm needs a keyed store"
        setup = _service(store, require_mfa=False)
        identity, token, _ = await login_admin(setup)
        await _register(setup, identity, token, resident_key=False)
        await store._db.execute("UPDATE webauthn_credentials SET discoverable = 1")
        await store._db.commit()
        service = _service(store)
        assert await service.must_enrol_before_rotating(identity)
        assert not await store.set_password(
            identity.user_id,
            password_hash="h-chosen",
            password_generated=False,
            must_change_password=False,
            require_way_past=True,
        )
        census = await lockable_account_census(store, AuthSettings())
        assert census.no_way_past == (identity.username,)
    finally:
        await store.close()
