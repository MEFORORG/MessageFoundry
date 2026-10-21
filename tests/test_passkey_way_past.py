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
import time
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
    PasskeyProof,
    _opened_totp_usable,
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
        failed = [
            json.loads(r["detail"])
            for r in await store.list_audit(limit=100, action="auth.webauthn_failed")
        ]
        assert {"phase": "enroll", "reason": "not_discoverable"} in failed, (
            "the refusal is unaudited"
        )
    finally:
        await store.close()


async def test_a_second_delete_of_the_same_passkey_is_not_called_a_way_past_refusal() -> None:
    """A conditional delete that matched no row because the same passkey was already removed (two
    tabs, a double click) answers "not removed", never the last-way-past refusal."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        _, token = await _register(service, identity, token, label="one")
        _, token = await _register(service, identity, token, label="two")
        target = (await store.list_webauthn_credentials(identity.user_id))[0]
        real_delete = store.delete_webauthn_credential

        async def already_gone(
            user_id: str,
            credential_id_hash: str,
            *,
            require_way_past: bool = False,
            totp_usable: Any = None,
        ) -> bool:
            assert await real_delete(user_id, credential_id_hash)  # the other tab wins first
            return await real_delete(
                user_id,
                credential_id_hash,
                require_way_past=require_way_past,
                totp_usable=totp_usable,
            )

        store.delete_webauthn_credential = already_gone  # type: ignore[method-assign]
        assert (
            await service.delete_webauthn_credential(identity, target.credential_id_hash) is False
        )
    finally:
        await store.close()


async def test_a_sign_in_lock_notice_tells_a_passkey_owner_the_way_past() -> None:
    """The ``ACCOUNT_LOCKED`` notice of a sign-in lock on an account whose way past is a
    discoverable passkey names the combined passkey sign-in, as a TOTP account's names the code."""
    from messagefoundry.auth.notifications import ACCOUNT_LOCKED, SecurityEvent

    events: list[SecurityEvent] = []

    class _Notifier:
        async def notify(self, event: SecurityEvent) -> bool:
            events.append(event)
            return True

    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store,
            AuthSettings(
                mfa_verify_min_elapsed_seconds=0,
                login_rate_limit_enabled=False,
                lockout_threshold=3,
            ),
            security_notifier=_Notifier(),
        )
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token)
        for i in range(3):
            assert not (await service.login(identity.username, f"wrong-{i}")).ok
        locks = [e for e in events if e.event_type == ACCOUNT_LOCKED]
        assert locks and locks[-1].detail.get("combined_passkey_sign_in") is True, locks
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


async def test_two_concurrent_removals_cannot_take_the_last_way_past() -> None:
    """AC-A3a under a race: both removals of an account's only two discoverable passkeys pass the
    service's check made before either wrote, so the store asks again in each write. Exactly one
    lands; the other is refused and the account keeps a way past."""
    import asyncio

    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        _, token = await _register(service, identity, token, label="one")
        _, token = await _register(service, identity, token, label="two")
        hashes = [
            c.credential_id_hash for c in await store.list_webauthn_credentials(identity.user_id)
        ]
        results = await asyncio.gather(
            *(service.delete_webauthn_credential(identity, h) for h in hashes),
            return_exceptions=True,
        )
        assert sum(r is True for r in results) == 1, results
        refused = [r for r in results if isinstance(r, ValueError)]
        assert len(refused) == 1 and str(refused[0]) == PASSKEY_REMOVAL_REFUSED, results
        (left,) = await store.list_webauthn_credentials(identity.user_id)
        assert left.discoverable
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
            totp_usable=_opened_totp_usable,
        )
        census = await lockable_account_census(store, AuthSettings())
        assert census.no_way_past == (identity.username,)
    finally:
        await store.close()


# --- parts 2 and 3: the usernameless begin leg and the combined passkey sign-in ---------------------

_LOCK_THRESHOLD = 3


def _lock_service(store: MessageStore, **settings: Any) -> AuthService:
    settings.setdefault("lockout_threshold", _LOCK_THRESHOLD)
    settings.setdefault("lockout_minutes", 15)
    return _service(store, **settings)


def _columns(user: Any) -> tuple[Any, ...]:
    return (
        user.failed_attempts,
        user.locked_until,
        user.lock_cycles,
        user.second_step_failed_attempts,
        user.second_step_locked_until,
        user.second_step_lock_cycles,
    )


async def _set_sign_in_lock(store: MessageStore, user_id: str) -> None:
    """A live sign-in lock a quarter hour out, as a caller who knows only the username sets it."""
    await store.record_login_failure(user_id, failed_attempts=3, locked_until=time.time() + 900)


async def _passkey_owner(
    store: MessageStore, **settings: Any
) -> tuple[AuthService, Identity, str, SoftAuthenticator]:
    """A covered local Administrator whose only factor is a discoverable passkey. Returns the
    service, the identity, the password and the authenticator."""
    service = _lock_service(store, **settings)
    identity, token, password = await login_admin(service)
    auth, _ = await _register(service, identity, token)
    return service, identity, password, auth


def _proof(service: AuthService, auth: SoftAuthenticator) -> PasskeyProof:
    """Run the begin leg, then the browser's get() against what it staged."""
    begun = service.begin_passkey_sign_in(rp_id=RP, client="192.0.2.10")
    assert begun is not None
    handle, options = begun
    challenge = base64url_to_bytes(json.loads(options)["challenge"])
    return PasskeyProof(
        handle=handle, response_json=auth.get_response(challenge), rp_id=RP, origin=ORIGIN
    )


async def _audit_rows(store: MessageStore, after: int) -> list[tuple[str, Any]]:
    """Every audit row past the first ``after``, as ``(action, detail)``, oldest first."""
    rows = await store.list_audit(limit=500)
    ordered = sorted(rows, key=lambda r: r["id"])
    return [(str(r["action"]), r["detail"]) for r in ordered[after:]]


async def test_AC_A7_the_begin_leg_takes_no_username_and_names_no_credential() -> None:
    """AC-A7: the challenge is staged with no username and an empty credential list, so the
    options are the same shape for every caller."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        first = service.begin_passkey_sign_in(rp_id=RP, client="192.0.2.10")
        second = service.begin_passkey_sign_in(rp_id=RP, client="192.0.2.11")
        assert first is not None and second is not None
        a, b = json.loads(first[1]), json.loads(second[1])
        assert a["allowCredentials"] == [] and b["allowCredentials"] == []
        assert sorted(a) == sorted(b) and a["rpId"] == RP
        assert a["challenge"] != b["challenge"] and first[0] != second[0]
        assert "user" not in a
    finally:
        await store.close()


async def test_AC_A7_the_begin_leg_charges_the_sign_in_limiter_first() -> None:
    """AC-A7: control 2 is charged before anything is staged. Its per-address budget is the one the
    sign-in spends, and once spent the begin leg stages nothing and answers None (a 429)."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store, login_rate_limit_enabled=True, login_rate_limit_per_ip=2)
        assert service.begin_passkey_sign_in(rp_id=RP, client="192.0.2.20") is not None
        assert service.begin_passkey_sign_in(rp_id=RP, client="192.0.2.20") is not None
        assert service.begin_passkey_sign_in(rp_id=RP, client="192.0.2.20") is None
        assert len(service._preauth_challenges) == 2
        assert not service.allow_login_attempt("192.0.2.20"), "the begin leg did not charge it"
    finally:
        await store.close()


async def test_AC_A6_a_passkey_owner_signs_in_with_password_and_assertion_under_a_live_lock() -> (
    None
):
    """AC-A6, first half: the way past. The full authentication satisfies the second factor and
    clears both counters, as option E's combined sign-in does."""
    store = await MessageStore.open(":memory:")
    try:
        service, identity, password, auth = await _passkey_owner(store)
        await _set_sign_in_lock(store, identity.user_id)
        assert not (await service.login(identity.username, password)).ok, "the lock is not live"

        out = await service.login(identity.username, password, passkey=_proof(service, auth))
        assert out.ok and out.token is not None, "the combined passkey sign-in was refused"
        assert out.mfa_required is False
        assert await service.mfa_satisfied(out.token) is True
        user = await store.get_user(identity.user_id)
        assert user is not None and _columns(user) == (0, None, 0, 0, None, 0)
        success = [d for a, d in await _audit_rows(store, 0) if a == "auth.login_success"]
        assert json.loads(success[-1])["second_factor"] == "webauthn"
    finally:
        await store.close()


async def test_AC_A6_right_invalid_is_recorded_exactly_as_wrong_invalid() -> None:
    """AC-A6, second half: "right password, invalid assertion" and "wrong password, invalid
    assertion" leave identical counters and identical audit rows, so no record tells a reader which
    password was right. Run on two identical owners, one cell each."""
    seen: list[tuple[tuple[Any, ...], list[tuple[str, Any]]]] = []
    for right in (True, False):
        store = await MessageStore.open(":memory:")
        try:
            service, identity, password, _auth = await _passkey_owner(store)
            stranger = SoftAuthenticator(
                rp_id=RP, origin=ORIGIN, user_handle=identity.user_id.encode()
            )
            await _set_sign_in_lock(store, identity.user_id)
            before = await store.get_user(identity.user_id)
            assert before is not None
            marker = len(await store.list_audit(limit=500))
            out = await service.login(
                identity.username,
                password if right else "not-the-passphrase",
                passkey=_proof(service, stranger),
            )
            assert not out.ok
            after = await store.get_user(identity.user_id)
            assert after is not None
            delta = (
                after.failed_attempts - before.failed_attempts,
                after.locked_until == before.locked_until,
                after.second_step_failed_attempts - before.second_step_failed_attempts,
                after.second_step_locked_until,
            )
            seen.append((delta, await _audit_rows(store, marker)))
        finally:
            await store.close()
    (right_delta, right_rows), (wrong_delta, wrong_rows) = seen
    assert right_delta == wrong_delta == (1, True, 0, None), seen
    assert right_rows == wrong_rows and right_rows, seen
    assert [a for a, _ in right_rows] == ["auth.login_failed"]
    assert json.loads(right_rows[0][1]) == {
        "provider": "local",
        "reason": "bad_credentials",
        "combined": True,
    }


async def test_a_valid_assertion_beside_a_wrong_password_counts_on_the_second_step() -> None:
    """The "wrong, valid" cell: a device holder guessing passwords. Counted on the second-step
    counter, and its lock refuses even the owner's full combined sign-in, as option E's does."""
    store = await MessageStore.open(":memory:")
    try:
        service, identity, password, auth = await _passkey_owner(store)
        for i in range(_LOCK_THRESHOLD):
            out = await service.login(
                identity.username, f"wrong-{i}", passkey=_proof(service, auth)
            )
            assert not out.ok
        user = await store.get_user(identity.user_id)
        assert user is not None and user.failed_attempts == 0
        assert user.second_step_failed_attempts == _LOCK_THRESHOLD
        assert user.second_step_locked_until is not None
        out = await service.login(identity.username, password, passkey=_proof(service, auth))
        assert not out.ok, "the second-step lock did not refuse the combined passkey sign-in"
    finally:
        await store.close()


async def test_a_user_handle_for_another_account_is_an_invalid_assertion() -> None:
    """The ``userHandle`` binds the usernameless assertion to the named account. A valid signature
    from this account's own credential that carries another account's handle counts as invalid."""
    store = await MessageStore.open(":memory:")
    try:
        service, identity, password, auth = await _passkey_owner(store)
        await _set_sign_in_lock(store, identity.user_id)
        auth.user_handle = b"another-account-id"
        out = await service.login(identity.username, password, passkey=_proof(service, auth))
        assert not out.ok
        user = await store.get_user(identity.user_id)
        assert user is not None and user.second_step_failed_attempts == 0
        assert user.failed_attempts == 4, "an invalid assertion counts on the sign-in counter"
    finally:
        await store.close()


async def test_an_assertion_on_an_account_with_no_discoverable_passkey_is_refused_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The twin of AC-2a: on an account whose only passkey is not discoverable an assertion changes
    nothing, so a live sign-in lock refuses it before the password is verified."""
    store = await MessageStore.open(":memory:")
    try:
        setup = _lock_service(store, require_mfa=False)
        identity, token, password = await login_admin(setup)
        auth, _ = await _register(setup, identity, token, resident_key=False)
        service = _lock_service(store)
        await _set_sign_in_lock(store, identity.user_id)
        before = await store.get_user(identity.user_id)
        assert before is not None and before.password_hash is not None
        seen: list[str] = []
        real = service._argon2

        async def spy(fn: Any, *args: Any) -> Any:
            if args and isinstance(args[0], str) and args[0].startswith("$argon2"):
                seen.append(args[0])
            return await real(fn, *args)

        monkeypatch.setattr(service, "_argon2", spy)
        out = await service.login(identity.username, password, passkey=_proof(service, auth))
        assert not out.ok
        assert before.password_hash not in seen, "the stored password was verified under the lock"
        after = await store.get_user(identity.user_id)
        assert after is not None and _columns(after) == _columns(before)
    finally:
        await store.close()


async def test_an_older_passkey_answers_where_the_account_also_holds_a_discoverable_one() -> None:
    """The path exists because the account holds a discoverable passkey, and then any of its own
    passkeys under the relying party may answer: a browser can offer one recorded as not
    discoverable. And a new registration excludes only discoverable passkeys, so such an
    authenticator can be registered again as discoverable."""
    store = await MessageStore.open(":memory:")
    try:
        service = _lock_service(store)
        identity, token, password = await login_admin(service)
        _, token = await _register(service, identity, token, label="resident")
        older, _ = await _register(service, identity, token, resident_key=False, label="older")
        options = json.loads(
            await service.begin_webauthn_registration(
                identity, token="unused-token", rp_id=RP, rp_name="MF"
            )
        )
        excluded = {c["id"] for c in options["excludeCredentials"]}
        assert older.credential_id_b64 not in excluded and len(excluded) == 1
        await _set_sign_in_lock(store, identity.user_id)
        out = await service.login(identity.username, password, passkey=_proof(service, older))
        assert out.ok, "an assertion from the account's older passkey was refused"
    finally:
        await store.close()


async def test_a_challenge_is_single_use() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service, identity, password, auth = await _passkey_owner(store)
        proof = _proof(service, auth)
        assert (await service.login(identity.username, password, passkey=proof)).ok
        await _set_sign_in_lock(store, identity.user_id)
        replay = await service.login(identity.username, password, passkey=proof)
        assert not replay.ok, "a spent challenge was accepted again"
    finally:
        await store.close()


async def test_a_challenge_expires() -> None:
    from messagefoundry.auth import webauthn as wa

    store = await MessageStore.open(":memory:")
    try:
        service, identity, password, auth = await _passkey_owner(store)
        clock = [1_000.0]
        service._preauth_challenges = wa.PreAuthChallengePool(clock=lambda: clock[0])
        proof = _proof(service, auth)
        clock[0] += wa.CHALLENGE_TTL_SECONDS + 1
        await _set_sign_in_lock(store, identity.user_id)
        out = await service.login(identity.username, password, passkey=proof)
        assert not out.ok, "an expired challenge was accepted"
    finally:
        await store.close()


def test_the_pre_auth_pool_evicts_its_oldest_rather_than_refusing() -> None:
    """A full pool never refuses a new challenge; it drops the oldest. Expired entries answer
    nothing, and a pop is single use."""
    from messagefoundry.auth import webauthn as wa

    clock = [0.0]
    pool = wa.PreAuthChallengePool(ttl_seconds=10.0, cap=3, clock=lambda: clock[0])
    for i in range(3):
        clock[0] += 1
        pool.put(f"k{i}", bytes([i]))
    pool.put("k3", b"\x03")
    assert len(pool) == 3
    assert pool.pop("k0") is None and pool.pop("k1") == b"\x01"
    assert pool.pop("k1") is None
    clock[0] += 10
    assert pool.pop("k2") is None and pool.pop("k3") is None


async def test_every_refused_passkey_outcome_is_padded_into_the_first_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-A8, against ``_FAILURE_BUDGET_SECONDS``: every refused shape of the combined passkey
    sign-in reaches the failure pad once and is held to its first slot. The pad's sleep is replaced
    so the arm reads the slot each attempt was given; the budget is widened for this arm only, so a
    loaded host cannot push one branch into a later slot."""
    from messagefoundry.auth import service as service_module

    monkeypatch.setattr(service_module, "_FAILURE_BUDGET_SECONDS", 5.0)
    store = await MessageStore.open(":memory:")
    try:
        service, identity, password, auth = await _passkey_owner(store, lockout_threshold=50)
        stranger = SoftAuthenticator(rp_id=RP, origin=ORIGIN, user_handle=b"nobody")
        slots: list[int] = []
        real_deadline = service_module._failure_deadline

        def spy(started: float, now: float, budget: float | None = None) -> float:
            deadline = real_deadline(started, now, budget)
            slots.append(round((deadline - started) / 5.0))
            return deadline

        async def no_sleep(_deadline: float) -> None:
            return None

        monkeypatch.setattr(service_module, "_failure_deadline", spy)
        monkeypatch.setattr(service_module, "_sleep_until", no_sleep)
        shapes = [
            ("unknown user", "nobody-by-this-name", password, auth),
            ("right password, invalid assertion", identity.username, password, stranger),
            ("wrong password, invalid assertion", identity.username, "wrong", stranger),
            ("wrong password, valid assertion", identity.username, "wrong", auth),
        ]
        for label, username, pw, key in shapes:
            out = await service.login(username, pw, passkey=_proof(service, key))
            assert not out.ok, label
        await _set_sign_in_lock(store, identity.user_id)
        out = await service.login(identity.username, "wrong", passkey=_proof(service, stranger))
        assert not out.ok
        assert slots == [1] * (len(shapes) + 1), slots
    finally:
        await store.close()


# --- BACKLOG #3422 beside wave 2: a TOTP enrolment this release refuses is no way past ------------

_TOTP_SECRET = "JBSWY3DPEHPK3PXP"
#: An enrolment whose marker this release does not compile in: no code ever matches it.
_REFUSED_TOTP = f"totp1:SHA1:6:30:{_TOTP_SECRET}"
#: A usable enrolment, the control arm.
_USABLE_TOTP = f"totp1:SHA256:6:30:{_TOTP_SECRET}"


async def _enable_totp(store: MessageStore, user_id: str, secret: str) -> None:
    cell = await store.set_totp_secret(user_id, secret=secret)
    assert await store.enable_totp(user_id, recovery_code_hashes=[], expected_secret_cell=cell)


def test_the_way_past_rule_reads_an_opened_totp_as_the_census_does() -> None:
    """One rule for the census and the gates: a refused marker, a non-base32 value and nothing at
    all are no way past; a usable enrolment, marked or bare, is."""
    assert not _opened_totp_usable(_REFUSED_TOTP)
    assert not _opened_totp_usable("not base32 at all!")
    assert not _opened_totp_usable(None) and not _opened_totp_usable("")
    assert _opened_totp_usable(_USABLE_TOTP) and _opened_totp_usable(_TOTP_SECRET)


@pytest.mark.parametrize(("secret", "removable"), [(_REFUSED_TOTP, False), (_USABLE_TOTP, True)])
async def test_a_refused_totp_does_not_free_the_last_discoverable_passkey(
    secret: str, removable: bool
) -> None:
    """Passkey removal, in the service and in the store's own re-check: an account holding a
    refused-marker TOTP and one discoverable passkey cannot delete the passkey, since the TOTP is
    no way past. The control: a usable TOTP frees it."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token)
        await _enable_totp(store, identity.user_id, secret)
        (cred,) = await store.list_webauthn_credentials(identity.user_id)
        if removable:
            assert await service.delete_webauthn_credential(identity, cred.credential_id_hash)
            return
        with pytest.raises(ValueError) as refused:
            await service.delete_webauthn_credential(identity, cred.credential_id_hash)
        assert str(refused.value) == PASSKEY_REMOVAL_REFUSED
        # The in-store re-check on its own, with the service's rule.
        assert not await store.delete_webauthn_credential(
            identity.user_id,
            cred.credential_id_hash,
            require_way_past=True,
            totp_usable=_opened_totp_usable,
        )
        assert len(await store.list_webauthn_credentials(identity.user_id)) == 1
    finally:
        await store.close()


@pytest.mark.parametrize(("secret", "rotates"), [(_REFUSED_TOTP, False), (_USABLE_TOTP, True)])
async def test_a_refused_totp_does_not_open_the_rotation_gate(secret: str, rotates: bool) -> None:
    """Rotation, in the service and in the store's conditional write: an account whose only factor
    is a refused-marker TOTP cannot rotate into a chosen password with no working way past. The
    control: a usable TOTP opens the gate."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, _token, _ = await login_admin(service)
        await _enable_totp(store, identity.user_id, secret)
        assert await service.must_enrol_before_rotating(identity) is not rotates
        if rotates:
            assert await service.change_password(identity, _NEW_PASSWORD) == []
            return
        with pytest.raises(FactorEnrolmentRequired):
            await service.change_password(identity, _NEW_PASSWORD)
        assert not await store.set_password(
            identity.user_id,
            password_hash="h-chosen",
            password_generated=False,
            must_change_password=False,
            require_way_past=True,
            totp_usable=_opened_totp_usable,
        )
        row = await store.get_user(identity.user_id)
        assert row is not None and row.password_hash != "h-chosen"
    finally:
        await store.close()


async def test_a_refused_totp_may_go_while_a_discoverable_passkey_remains() -> None:
    """``disable_mfa``: removing a refused TOTP is allowed while a discoverable passkey stays as
    the account's working way past, the same rule as a usable TOTP."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token)
        await _enable_totp(store, identity.user_id, _REFUSED_TOTP)
        await service.disable_mfa(identity)
        row = await store.get_user(identity.user_id)
        assert row is not None and not row.totp_enabled
    finally:
        await store.close()


async def test_the_census_warns_that_a_reset_would_remove_a_working_passkey() -> None:
    """An account with a refused TOTP and a working discoverable passkey: the TOTP is named as
    unusable, the account as relying on its passkey, and the census says a factor reset would
    remove that passkey. It is not named as having no way past."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token)
        await service.change_password(identity, _NEW_PASSWORD)
        await _enable_totp(store, identity.user_id, _REFUSED_TOTP)
        census = await lockable_account_census(store, AuthSettings())
        assert census.undecryptable_totp == (identity.username,)
        assert census.passkey_only == (identity.username,)
        assert census.reset_would_remove_a_passkey == (identity.username,)
        assert census.no_way_past == ()
    finally:
        await store.close()


async def test_a_refused_totp_can_be_removed_to_enrol_again() -> None:
    """``disable_mfa``: a TOTP this release refuses is no way past, so the way-past refusal does not
    keep it; removing it is the first step of enrolling again. Beside a passkey that is not
    discoverable, so the last-factor rule (ADR 0068 decision 5) does not answer first."""
    store = await MessageStore.open(":memory:")
    try:
        setup = _service(store, require_mfa=False)
        identity, token, _ = await login_admin(setup)
        await _register(setup, identity, token, resident_key=False)
        await _enable_totp(store, identity.user_id, _REFUSED_TOTP)
        await _service(store).disable_mfa(identity)
        row = await store.get_user(identity.user_id)
        assert row is not None and not row.totp_enabled
    finally:
        await store.close()


async def test_a_lock_notice_names_the_passkey_way_past_beside_a_refused_totp() -> None:
    """The sign-in lock notice asks the same rule: beside a refused TOTP it names the combined
    passkey sign-in, never the code sign-in that cannot pass."""
    from messagefoundry.auth.notifications import ACCOUNT_LOCKED, SecurityEvent

    events: list[SecurityEvent] = []

    class _Notifier:
        async def notify(self, event: SecurityEvent) -> bool:
            events.append(event)
            return True

    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store,
            AuthSettings(
                mfa_verify_min_elapsed_seconds=0,
                login_rate_limit_enabled=False,
                lockout_threshold=3,
            ),
            security_notifier=_Notifier(),
        )
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token)
        await _enable_totp(store, identity.user_id, _REFUSED_TOTP)
        for i in range(3):
            assert not (await service.login(identity.username, f"wrong-{i}")).ok
        (lock,) = [e for e in events if e.event_type == ACCOUNT_LOCKED]
        assert lock.detail.get("combined_passkey_sign_in") is True
        assert "combined_sign_in" not in lock.detail
    finally:
        await store.close()


async def test_the_scheme_rehash_keeps_a_passkey_discoverable_and_sealed(tmp_path: Any) -> None:
    """BACKLOG #3423 beside wave 2: moving a passkey stored under the bare digest to today's tagged
    hash keeps its ``discoverable`` record, the moved set still verifies against the account's
    seal, and it still opens the rotation gate; a flip after the move still fails the seal."""
    import base64
    import hashlib
    import secrets as _secrets

    from messagefoundry.auth.tokens import credential_id_hash
    from messagefoundry.store.crypto import generate_key, make_cipher
    from tests._webauthn_store_contract import _cred

    store = await MessageStore.open(
        tmp_path / "keyed.db", cipher=make_cipher(generate_key(), write_v2=True)
    )
    try:
        service = _service(store)
        identity, _token, _ = await login_admin(service)
        raw = _secrets.token_bytes(32)
        raw_b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        await store.add_webauthn_credential(
            _cred(
                identity.user_id,
                "legacy",
                id_hash=hashlib.sha256(raw).hexdigest(),
                credential_id=raw_b64,
                rp_id=RP,
                discoverable=True,
            )
        )
        # Under the bare digest it cannot sign in, so it is no way past until it is moved.
        assert await service.must_enrol_before_rotating(identity)
        assert await service.rehash_webauthn_credentials() == (1, 0)
        (moved,) = await store.list_webauthn_credentials(identity.user_id)
        assert moved.credential_id_hash == credential_id_hash(raw) and moved.discoverable
        assert not await service.must_enrol_before_rotating(identity)
        await store._db.execute("UPDATE webauthn_credentials SET discoverable = 0")
        await store._db.commit()
        assert await service.must_enrol_before_rotating(identity), "a flip passed the seal"
    finally:
        await store.close()


async def test_a_passkey_under_a_refused_hash_scheme_is_no_way_past() -> None:
    """A discoverable passkey whose stored hash names a scheme this release refuses can never be
    found by the sign-in, so it is no way past: the rotation gate stays shut, the census names the
    account as having none, and the store's conditional write refuses."""
    from tests._webauthn_store_contract import _cred

    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, _token, _ = await login_admin(service)
        await store.add_webauthn_credential(
            _cred(identity.user_id, "future", id_hash="wc9:" + "0" * 64, discoverable=True)
        )
        assert await service.must_enrol_before_rotating(identity)
        assert not await store.set_password(
            identity.user_id,
            password_hash="h-chosen",
            password_generated=False,
            must_change_password=False,
            require_way_past=True,
            totp_usable=_opened_totp_usable,
        )
        census = await lockable_account_census(store, AuthSettings())
        assert census.no_way_past == (identity.username,) and census.passkey_only == ()
    finally:
        await store.close()
