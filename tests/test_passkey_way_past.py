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
import types
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
    _opened_totp_state,
    lockable_account_census,
)
from messagefoundry.config.settings import AuthSettings  # noqa: E402
from messagefoundry.store.store import MessageStore  # noqa: E402
from tests._admin_account import login_admin  # noqa: E402
from tests._soft_webauthn import SoftAuthenticator  # noqa: E402

RP = "t"
ORIGIN = "http://t"
_NEW_PASSWORD = "a-brand-new-chosen-passphrase-9"


def _service(
    store: MessageStore, *, way_past_rp_id: str | None = RP, **settings: Any
) -> AuthService:
    """``require_mfa`` stays at its shipped default (on) unless an arm says otherwise, so the test
    administrator is covered by the requirement."""
    settings.setdefault("mfa_verify_min_elapsed_seconds", 0)
    settings.setdefault("login_rate_limit_enabled", False)
    return AuthService(store, AuthSettings(**settings), way_past_rp_id=way_past_rp_id)


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
            passkey_counts: Any = None,
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
            way_past_rp_id=RP,
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
        census = await lockable_account_census(store, AuthSettings(), way_past_rp_id=RP)
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
        census = await lockable_account_census(store, AuthSettings(), way_past_rp_id=RP)
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
            totp_usable=_opened_totp_state,
        )
        census = await lockable_account_census(store, AuthSettings(), way_past_rp_id=RP)
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
    assert pool.pop("k0") is None and pool.pop("k1") == (b"\x01", None)  # (challenge, charge)
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
    """One rule for the census and the gates, pinned state by state: a refused marker and nothing at
    all are a KNOWN refusal; a non-base32 value cannot be judged, so it is unknown and the plain
    enabled-TOTP rule applies; a usable enrolment, marked or bare, is usable."""
    assert _opened_totp_state(_REFUSED_TOTP) == "refused"
    assert _opened_totp_state(None) == "refused" and _opened_totp_state("") == "refused"
    assert _opened_totp_state("not base32 at all!") == "unknown"
    assert _opened_totp_state(_USABLE_TOTP) == "usable"
    assert _opened_totp_state(_TOTP_SECRET) == "usable"


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
        # Refused by the service: the last-factor rule answers first, since a refused TOTP is no
        # factor the holder can use either (ADR 0068 decision 5).
        with pytest.raises(ValueError, match="last second factor"):
            await service.delete_webauthn_credential(identity, cred.credential_id_hash)
        # The in-store way-past re-check on its own, with the service's rule.
        assert not await store.delete_webauthn_credential(
            identity.user_id,
            cred.credential_id_hash,
            require_way_past=True,
            totp_usable=_opened_totp_state,
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
            totp_usable=_opened_totp_state,
        )
        row = await store.get_user(identity.user_id)
        assert row is not None and row.password_hash != "h-chosen"
    finally:
        await store.close()


async def test_the_way_past_refusal_answers_beside_a_refused_totp_and_two_passkeys() -> None:
    """Two passkeys, so the last-factor rule does not answer: the service's way-past refusal
    (through the store's re-check) does. A refused TOTP and a passkey that is not discoverable leave
    no way past once the discoverable one goes, so its removal is refused."""
    store = await MessageStore.open(":memory:")
    try:
        setup = _service(store, require_mfa=False)
        identity, token, _ = await login_admin(setup)
        _, token = await _register(setup, identity, token, label="resident")
        await _register(setup, identity, token, resident_key=False, label="plain")
        await _enable_totp(store, identity.user_id, _REFUSED_TOTP)
        by_label = {c.label: c for c in await store.list_webauthn_credentials(identity.user_id)}
        with pytest.raises(ValueError) as refused:
            await _service(store).delete_webauthn_credential(
                identity, by_label["resident"].credential_id_hash
            )
        assert str(refused.value) == PASSKEY_REMOVAL_REFUSED
        assert len(await store.list_webauthn_credentials(identity.user_id)) == 2
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
        census = await lockable_account_census(store, AuthSettings(), way_past_rp_id=RP)
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
            way_past_rp_id=RP,
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
            totp_usable=_opened_totp_state,
        )
        census = await lockable_account_census(store, AuthSettings(), way_past_rp_id=RP)
        assert census.no_way_past == (identity.username,) and census.passkey_only == ()
    finally:
        await store.close()


# --- the refused-TOTP rule at the remaining sites, and off the event loop ---------------------------


def test_a_keyless_open_ciphertext_cell_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    """A keyless open hands the stored ciphertext through unchanged; that is no TOTP the engine can
    judge, so it is unknown, never usable. The compute check is stubbed to pass, so only the
    ciphertext guard can answer."""
    from messagefoundry.auth import service as service_module
    from messagefoundry.store.crypto import MARKER_PREFIX

    monkeypatch.setattr(service_module, "_totp_unusable_reason", lambda _secret: None)
    assert _opened_totp_state(MARKER_PREFIX + "v2:opaque-ciphertext") == "unknown"
    assert _opened_totp_state(_TOTP_SECRET) == "usable", (
        "the stub should let a plain secret through"
    )


@pytest.mark.parametrize(("secret", "escalates"), [(_REFUSED_TOTP, False), (_USABLE_TOTP, True)])
async def test_the_sign_in_lock_escalates_only_beside_a_usable_totp(
    secret: str, escalates: bool
) -> None:
    """ADR 0197 escalates the sign-in lock only where the owner has a way past it. A refused TOTP
    is none, so its account keeps the fixed length on the second cycle; the usable control
    doubles."""
    store = await MessageStore.open(":memory:")
    try:
        service = _lock_service(store)
        identity, _token, _ = await login_admin(service)
        await _enable_totp(store, identity.user_id, secret)
        user = await service._load_user(identity.user_id)
        assert user is not None
        start = 1_000_000.0
        for cycle in range(2):
            at = start + cycle * 10_000.0
            for i in range(_LOCK_THRESHOLD):
                await service._register_failure(user, at + i, counter="sign_in")
        row = await store.get_user(identity.user_id)
        assert row is not None and row.locked_until is not None
        length = row.locked_until - (start + 10_000.0 + _LOCK_THRESHOLD - 1)
        assert length == (1800.0 if escalates else 900.0), length
    finally:
        await store.close()


async def test_a_refused_totp_as_the_only_factor_is_no_way_out_but_the_admin_reset() -> None:
    """The refused TOTP as the account's only factor: no way past, so the rotation waits; and the
    last-factor rule keeps it, so the holder cannot remove it either. An administrator's factor
    reset is the documented way out."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, _token, _ = await login_admin(service)
        await _enable_totp(store, identity.user_id, _REFUSED_TOTP)
        assert await service.must_enrol_before_rotating(identity)
        with pytest.raises(FactorEnrolmentRequired):
            await service.change_password(identity, _NEW_PASSWORD)
        with pytest.raises(ValueError, match="last second factor"):
            await service.disable_mfa(identity)
        issued = await service.admin_reset_mfa(identity.user_id, actor="another-admin")
        assert issued is not None
        row = await store.get_user(identity.user_id)
        assert row is not None and not row.totp_enabled and row.password_generated
    finally:
        await store.close()


@pytest.mark.parametrize(("secret", "removable"), [(_REFUSED_TOTP, False), (_USABLE_TOTP, True)])
async def test_the_last_passkey_beside_a_refused_totp_is_the_last_factor(
    secret: str, removable: bool
) -> None:
    """ADR 0068 decision 5 under ``require_mfa``: a TOTP this release refuses is no factor the
    holder can use, so the passkey beside it is the last one and its removal is refused, as for a
    sole usable factor. The control: beside a usable TOTP it may go."""
    store = await MessageStore.open(":memory:")
    try:
        setup = _service(store, require_mfa=False)
        identity, token, _ = await login_admin(setup)
        await _register(setup, identity, token, resident_key=False)
        await _enable_totp(store, identity.user_id, secret)
        (cred,) = await store.list_webauthn_credentials(identity.user_id)
        service = _service(store)
        if removable:
            assert await service.delete_webauthn_credential(identity, cred.credential_id_hash)
            return
        with pytest.raises(ValueError, match="last second factor"):
            await service.delete_webauthn_credential(identity, cred.credential_id_hash)
        assert len(await store.list_webauthn_credentials(identity.user_id)) == 1
    finally:
        await store.close()


async def test_the_way_past_gates_open_the_totp_cell_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLAUDE.md section 6: a Transit cipher's decrypt is a blocking HTTP call, so the service gate
    and the store's in-transaction re-check open the TOTP cell in a worker thread, never on the
    thread that runs the event loop."""
    import threading

    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, _token, _ = await login_admin(service)
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)
        loop_thread = threading.current_thread()
        threads: list[threading.Thread] = []
        real_open = store.open_totp_secret

        def spy(user_id: str, cell: str | None) -> str | None:
            threads.append(threading.current_thread())
            return real_open(user_id, cell)

        monkeypatch.setattr(store, "open_totp_secret", spy)
        assert not await service.must_enrol_before_rotating(identity)
        assert await service.change_password(identity, _NEW_PASSWORD) == []
        assert len(threads) >= 2, "the gate and the store re-check should each open the cell"
        assert loop_thread not in threads, "a TOTP cell was opened on the event loop"
    finally:
        await store.close()


async def test_a_totp_enabled_after_it_was_judged_is_not_removed() -> None:
    """The store judges the TOTP before it takes its lock and confirms the cell under it. A usable
    TOTP enabled between the two is declined by the conditional removal, never wiped as if it
    counted for nothing; for the rotation a moved cell counts for nothing, the closed direction."""
    from messagefoundry.store.store import judge_totp, password_change, totp_removal

    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, _token, _ = await login_admin(service)
        before = await store.get_user(identity.user_id)  # TOTP off: the judged cell is None
        judgement = await judge_totp(store.open_totp_secret, _opened_totp_state, before)
        assert judgement is not None
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)  # lands after the judgement
        record = await store._read_user_record(identity.user_id)
        assert record is not None
        removal = totp_removal(1.0, require_way_past=True, totp_counts=judgement)
        assert removal(record) is None, "a TOTP enabled after the judgement was removed"
        rotation = password_change(
            password_hash="h",
            password_generated=False,
            must_change_password=False,
            require_way_past=True,
            now=1.0,
            totp_counts=judgement,
        )
        assert rotation(record) is None, "a TOTP nobody judged opened the rotation"
    finally:
        await store.close()


async def test_a_totp_cell_that_does_not_open_is_judged_unknown_and_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A cell that does not open (a store-key or cipher-service fault) is judged UNKNOWN, never a
    refusal, so it counts as the plain enabled-TOTP rule counts it; the account is named once in a
    WARNING, never the cell."""
    import logging

    from messagefoundry.store import store as store_module
    from messagefoundry.store.crypto import CipherError
    from messagefoundry.store.store import TotpJudgement, judge_totp

    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, _token, _ = await login_admin(service)
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)
        user = await store.get_user(identity.user_id)
        record = await store._read_user_record(identity.user_id)
        assert user is not None and record is not None

        def refuse(_user_id: str, _cell: str | None) -> str | None:
            raise CipherError("the cell did not open")

        store_module._UNOPENED_TOTP_LOGGED.pop(identity.user_id, None)
        with caplog.at_level(logging.WARNING, logger="messagefoundry.store.store"):
            judgement = await judge_totp(refuse, _opened_totp_state, user)
            again = await judge_totp(refuse, _opened_totp_state, user)
        assert isinstance(judgement, TotpJudgement) and isinstance(again, TotpJudgement)
        assert judgement.state == "unknown" and again.state == "unknown"
        # Unknown counts as the plain enabled-TOTP rule counts it, and is never a refusal.
        assert judgement(record) and not judgement.refuses(record)
        warned = [r.getMessage() for r in caplog.records if "did not open" in r.getMessage()]
        assert len(warned) == 1 and identity.user_id in warned[0], warned
        assert _TOTP_SECRET not in warned[0]
    finally:
        await store.close()


async def test_a_rule_that_answers_a_bool_is_refused_not_read_as_usable() -> None:
    """The rule answers a :data:`TotpState`. A rule of the old bool shape would make ``False`` read
    as "not refused", which fails open, so the judgement refuses any answer outside the tri-state."""
    from messagefoundry.store.store import judge_totp

    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, _token, _ = await login_admin(service)
        await _enable_totp(store, identity.user_id, _REFUSED_TOTP)
        user = await store.get_user(identity.user_id)
        bool_rule: Any = lambda _secret: False  # noqa: E731
        with pytest.raises(TypeError, match="TotpState"):
            await judge_totp(store.open_totp_secret, bool_rule, user)
    finally:
        await store.close()


async def test_the_escalation_rule_cannot_be_omitted() -> None:
    """``increment_login_failure`` takes the TOTP rule as a REQUIRED keyword, never ``None``, so no
    caller can omit it and silently lose the refused-TOTP rule. mypy refuses the
    omission statically (the store protocol in ``base.py``); this is the runtime half."""
    import inspect

    store = await MessageStore.open(":memory:")
    try:
        param = inspect.signature(store.increment_login_failure).parameters["totp_usable"]
        assert param.default is inspect.Parameter.empty
        with pytest.raises(TypeError, match="totp_usable"):
            await store.increment_login_failure(  # type: ignore[call-arg]
                "nobody",
                counter="sign_in",
                threshold=3,
                lockout_seconds=900.0,
                max_lockout_seconds=86_400.0,
            )
        # An explicit None from a caller typed ``Any`` is refused too, never read as "no rule".
        none: Any = None
        with pytest.raises(TypeError, match="totp_usable"):
            await store.increment_login_failure(
                "nobody",
                counter="sign_in",
                threshold=3,
                lockout_seconds=900.0,
                max_lockout_seconds=86_400.0,
                totp_usable=none,
            )
    finally:
        await store.close()


# --- an UNKNOWN TOTP (a cell that does not open, as in a Transit outage) behaves as before #3422 ----


def _cipher_outage(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, kind: str = "outage"
) -> list[str]:
    """A stub cipher for the TOTP cell. ``"outage"``: every open raises ``CipherError``, as a Transit
    outage does. ``"keyless"``: every open hands the stored ciphertext back unchanged, as a store
    opened without its key does. Returns the list each open appends its account id to, so a test can
    show the stub was reached rather than a judgement skipped."""
    from messagefoundry.store.crypto import MARKER_PREFIX, CipherError

    opened: list[str] = []

    def unjudgeable(user_id: str, _cell: str | None) -> str | None:
        opened.append(user_id)
        if kind == "outage":
            raise CipherError("the cipher service did not answer")
        return MARKER_PREFIX + "v2:opaque-ciphertext"

    async def outage_read(user_id: str) -> str | None:
        return unjudgeable(user_id, None)

    monkeypatch.setattr(store, "open_totp_secret", unjudgeable)
    monkeypatch.setattr(store, "get_totp_secret", outage_read)
    return opened


_UNJUDGEABLE = pytest.mark.parametrize("kind", ["outage", "keyless"])


@_UNJUDGEABLE
async def test_an_unknown_totp_is_not_removed_beside_a_passkey_that_is_not_discoverable(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """During the outage, or on a keyless open, a covered account holding a non-discoverable
    passkey cannot remove its TOTP, exactly as the plain enabled-TOTP rule refused it before
    BACKLOG #3422."""
    store = await MessageStore.open(":memory:")
    try:
        setup = _service(store, require_mfa=False)
        identity, token, _ = await login_admin(setup)
        await _register(setup, identity, token, resident_key=False)
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)
        opened = _cipher_outage(store, monkeypatch, kind)
        with pytest.raises(ValueError) as refused:
            await _service(store).disable_mfa(identity)
        assert str(refused.value) == TOTP_REMOVAL_REFUSED
        assert opened, "the removal judged nothing, so the stub measured nothing"
        row = await store.get_user(identity.user_id)
        assert row is not None and row.totp_enabled
    finally:
        await store.close()


@_UNJUDGEABLE
async def test_an_unknown_totp_still_escalates_the_sign_in_lock(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """During the outage, or on a keyless open, the sign-in lock still doubles on the second
    cycle, as before; the crossing failure of that cycle opened the stubbed cell."""
    store = await MessageStore.open(":memory:")
    try:
        service = _lock_service(store)
        identity, _token, _ = await login_admin(service)
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)
        user = await service._load_user(identity.user_id)
        assert user is not None
        opened = _cipher_outage(store, monkeypatch, kind)
        start = 1_000_000.0
        for cycle in range(2):
            at = start + cycle * 10_000.0
            for i in range(_LOCK_THRESHOLD):
                await service._register_failure(user, at + i, counter="sign_in")
        assert opened, "the escalation judged nothing, so the stub measured nothing"
        row = await store.get_user(identity.user_id)
        assert row is not None and row.locked_until is not None
        assert row.locked_until - (start + 10_000.0 + _LOCK_THRESHOLD - 1) == 1800.0
    finally:
        await store.close()


async def test_a_first_passkey_that_is_not_discoverable_is_taken_beside_an_unknown_totp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-A3 during the outage: the registration refusal asks the way-past rule, and an enabled
    TOTP it cannot judge counts as the plain rule counts it, so a covered account may register a
    passkey that is not discoverable, as before BACKLOG #3422. The control: where the same cell
    opens to an enrolment this release refuses, the same registration is refused."""
    from tests._totp_clock import fresh_totp

    for outage in (True, False):
        store = await MessageStore.open(":memory:")
        try:
            service = _service(store)
            identity, token, _ = await login_admin(service)
            enroll = await service.begin_mfa_enrollment(identity)
            confirmed = await service.confirm_mfa_enrollment(
                identity, fresh_totp(enroll.secret), token=token
            )
            assert confirmed.ok and confirmed.token is not None
            token = confirmed.token
            if outage:
                opened = _cipher_outage(store, monkeypatch)
            else:
                opened = []

                def refused(
                    user_id: str, _cell: str | None, seen: list[str] = opened
                ) -> str | None:
                    seen.append(user_id)
                    return _REFUSED_TOTP

                monkeypatch.setattr(store, "open_totp_secret", refused)
            auth = SoftAuthenticator(rp_id=RP, origin=ORIGIN)
            options = json.loads(
                await service.begin_webauthn_registration(
                    identity, token=token, rp_id=RP, rp_name="M"
                )
            )
            finish = service.finish_webauthn_registration(
                identity,
                auth.create_response(base64url_to_bytes(options["challenge"]), resident_key=False),
                label="key",
                token=token,
                rp_id=RP,
                origin=ORIGIN,
            )
            if outage:
                assert (await finish).ok
                assert len(await store.list_webauthn_credentials(identity.user_id)) == 1
            else:
                with pytest.raises(ValueError) as refusal:
                    await finish
                assert str(refusal.value) == PASSKEY_NOT_DISCOVERABLE
            assert opened, "the registration judged nothing, so the stub measured nothing"
        finally:
            monkeypatch.undo()
            await store.close()


async def test_the_last_discoverable_passkey_can_go_beside_an_unknown_totp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-A3a during the outage: the removal refusal asks the way-past rule in the service and
    again in the store's conditional delete, and an enabled TOTP neither can judge counts as the
    plain rule counts it, so the account's only discoverable passkey may go, as before BACKLOG
    #3422."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token)
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)
        (cred,) = await store.list_webauthn_credentials(identity.user_id)
        assert cred.discoverable
        opened = _cipher_outage(store, monkeypatch)
        assert await service.delete_webauthn_credential(identity, cred.credential_id_hash)
        assert len(opened) >= 2, "the service gate and the store re-check should each judge"
        assert await store.list_webauthn_credentials(identity.user_id) == []
    finally:
        await store.close()


async def test_the_last_passkey_can_go_beside_an_unknown_totp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """During the outage the enabled TOTP still counts as a factor, so the passkey beside it is not
    the last one and may be removed, as before. This is the false last-factor refusal that review
    finding 15 named."""
    store = await MessageStore.open(":memory:")
    try:
        setup = _service(store, require_mfa=False)
        identity, token, _ = await login_admin(setup)
        await _register(setup, identity, token, resident_key=False)
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)
        (cred,) = await store.list_webauthn_credentials(identity.user_id)
        _cipher_outage(store, monkeypatch)
        assert await _service(store).delete_webauthn_credential(identity, cred.credential_id_hash)
    finally:
        await store.close()


async def test_the_census_names_an_unknown_totp_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The census reports a TOTP it could not judge as unknown: named in ``unknown_totp`` (and, as
    before, among the TOTP secrets it cannot decrypt), never as a refusal with a passkey way past
    (``passkey_only``), and never as an account with no way past. The discoverable passkey beside it
    is still named as one a factor reset would remove."""
    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token)
        await service.change_password(identity, _NEW_PASSWORD)
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)
        _cipher_outage(store, monkeypatch)
        census = await lockable_account_census(store, AuthSettings(), way_past_rp_id=RP)
        assert census.unknown_totp == (identity.username,)
        assert census.undecryptable_totp == (identity.username,)
        assert census.passkey_only == () and census.no_way_past == ()
        assert census.unknown_beside_a_passkey == (identity.username,)
        assert census.reset_would_remove_a_passkey == (identity.username,)
    finally:
        await store.close()


async def test_a_lock_notice_beside_an_unknown_totp_says_so_and_names_the_passkey(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """During the outage the sign-in lock notice offers the code sign-in as the plain rule did,
    reports the TOTP as unknown, and also names the passkey sign-in, which needs no TOTP cell; the
    rendered lines carry all three."""
    from messagefoundry.auth.notifications import ACCOUNT_LOCKED, SecurityEvent
    from messagefoundry.pipeline.security_notify import _lock_lines

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
            way_past_rp_id=RP,
        )
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token)
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)
        _cipher_outage(store, monkeypatch)
        for i in range(3):
            assert not (await service.login(identity.username, f"wrong-{i}")).ok
        (lock,) = [e for e in events if e.event_type == ACCOUNT_LOCKED]
        assert lock.detail.get("combined_sign_in") is True
        assert lock.detail.get("totp_state") == "unknown"
        assert lock.detail.get("combined_passkey_sign_in") is True
        _description, lines, _closing = _lock_lines(lock)
        text = " ".join(lines)
        assert "authenticator code" in text and "could not check" in text and "passkey" in text
    finally:
        await store.close()


# --- BACKLOG #3937: a passkey counts at a factor-drop gate only under the configured rp_id ---------


def _gate_service(store: MessageStore, configured: str | None) -> AuthService:
    """The service a deployment builds: ``configured`` is ``[api].public_origin``'s host, or None
    when it is unset and each request names its own rp_id."""
    return AuthService(
        store,
        AuthSettings(mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False),
        way_past_rp_id=configured,
    )


@pytest.mark.parametrize("configured", ["elsewhere.example", None])
async def test_a_passkey_under_another_rp_id_does_not_free_totp(configured: str | None) -> None:
    """Item 1: the sign-in keeps only the passkeys under the request's rp_id, so a passkey under
    another one is no way past. ``disable_mfa`` refuses, in the service and in the store's own
    write, and so does the ambiguous configuration (no public_origin), which counts none. The
    control: under the configured rp_id the same account drops TOTP."""
    store = await MessageStore.open(":memory:")
    try:
        setup = _service(store)
        identity, token, _ = await login_admin(setup)
        await _register(setup, identity, token)  # discoverable, under RP
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)
        gate = _gate_service(store, configured)
        with pytest.raises(ValueError) as refused:
            await gate.disable_mfa(identity)
        assert str(refused.value) == TOTP_REMOVAL_REFUSED
        assert not await store.disable_totp(
            identity.user_id,
            require_way_past=True,
            totp_usable=_opened_totp_state,
            passkey_counts=gate._gate_counts,
        ), "the store's write counted a passkey the gate does not"
        row = await store.get_user(identity.user_id)
        assert row is not None and row.totp_enabled

        await _gate_service(store, RP).disable_mfa(identity)  # control
        row = await store.get_user(identity.user_id)
        assert row is not None and not row.totp_enabled
    finally:
        await store.close()


@pytest.mark.parametrize("configured", ["elsewhere.example", None])
async def test_a_passkey_under_another_rp_id_does_not_open_the_rotation_gate(
    configured: str | None,
) -> None:
    """Item 1: the rotation gate, its store write and the census count no passkey outside the
    configured rp_id, so a passkey-only account must enrol first and is named as having no way
    past. The control: under the configured rp_id it rotates and is named passkey-only."""
    store = await MessageStore.open(":memory:")
    try:
        setup = _service(store)
        identity, token, _ = await login_admin(setup)
        await _register(setup, identity, token)
        gate = _gate_service(store, configured)
        assert await gate.must_enrol_before_rotating(identity)
        with pytest.raises(FactorEnrolmentRequired):
            await gate.change_password(identity, _NEW_PASSWORD)
        census = await lockable_account_census(store, AuthSettings(), way_past_rp_id=configured)
        assert census.no_way_past == (identity.username,)
        # The reset warning's question, which passkey may sign the holder in: with no configured
        # rp_id the request's rp_id may still take this one; under another configured one it never
        # can.
        expected = (identity.username,) if configured is None else ()
        assert census.passkey_only == expected

        control = _gate_service(store, RP)
        assert not await control.must_enrol_before_rotating(identity)
        census = await lockable_account_census(store, AuthSettings(), way_past_rp_id=RP)
        assert census.passkey_only == (identity.username,) and census.no_way_past == ()
        assert await control.change_password(identity, _NEW_PASSWORD) == []
    finally:
        await store.close()


async def test_the_last_passkey_under_the_configured_rp_id_cannot_go_beside_a_foreign_one() -> None:
    """Item 1, the removal gate: an account whose only passkey under the configured rp_id sits
    beside a discoverable one under another rp_id keeps the first, since the second could never
    sign it in. The foreign one may go: it is no way past, so its removal is not refused for it."""
    from messagefoundry.auth.tokens import credential_id_hash
    from tests._webauthn_store_contract import _cred

    store = await MessageStore.open(":memory:")
    try:
        service = _service(store)
        identity, token, _ = await login_admin(service)
        await _register(service, identity, token, label="here")
        foreign = _cred(
            identity.user_id,
            "there",
            id_hash=credential_id_hash(b"foreign-credential"),
            rp_id="elsewhere.example",
            discoverable=True,
        )
        await store.add_webauthn_credential(foreign)
        by_label = {c.label: c for c in await store.list_webauthn_credentials(identity.user_id)}
        with pytest.raises(ValueError) as refused:
            await service.delete_webauthn_credential(identity, by_label["here"].credential_id_hash)
        assert str(refused.value) == PASSKEY_REMOVAL_REFUSED
        assert await service.delete_webauthn_credential(identity, foreign.credential_id_hash)
        (left,) = await store.list_webauthn_credentials(identity.user_id)
        assert left.label == "here"
    finally:
        await store.close()


@pytest.mark.parametrize("holds_one", [False, True])
async def test_a_seal_refusal_calls_a_passkey_sign_in_combined_only_where_it_was(
    monkeypatch: pytest.MonkeyPatch, holds_one: bool
) -> None:
    """Item 3: the seal refusal's ``auth.login_failed`` row says ``combined`` only where the
    account held a discoverable passkey under the request's rp_id, as the row a wrong credential
    writes would. An assertion sent to an account with none is the password sign-in."""
    from messagefoundry.store.row_seal import USER_KIND, RowSealError

    store = await MessageStore.open(":memory:")
    try:
        service = _lock_service(store)
        identity, token, password = await login_admin(service)
        auth = SoftAuthenticator(rp_id=RP, origin=ORIGIN, user_handle=identity.user_id.encode())
        if holds_one:
            auth, _ = await _register(service, identity, token)

        async def refuse(*_a: object, **_k: object) -> object:
            raise RowSealError(USER_KIND)

        monkeypatch.setattr(service, "_register_failure", refuse)
        out = await service.login(
            identity.username, "wrong-" + password, passkey=_proof(service, auth)
        )
        assert not out.ok and out.error == "invalid credentials"
        (row,) = await store.list_audit(action="auth.login_failed")
        assert json.loads(row["detail"]).get("combined", False) is holds_one
    finally:
        await store.close()


async def test_a_staged_challenge_renews_its_charge_and_cannot_be_banked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Item 2: taking a staged challenge MOVES the begin leg's control-2 hit to now rather than
    skipping a charge, so a begin leg's budget cannot be spent in a later window. A challenge
    lives longer than the window: one whose hit has aged out is not ``paid`` and the sign-in
    charges afresh. A forged handle finds nothing."""
    from messagefoundry.auth import webauthn as wa

    clock = [1_000.0]
    # The limiter module's own clock only: the event loop keeps the real one.
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", types.SimpleNamespace(monotonic=lambda: clock[0])
    )
    store = await MessageStore.open(":memory:")
    try:
        service = _service(
            store,
            login_rate_limit_enabled=True,
            login_rate_limit_per_ip=2,
            login_rate_limit_window_seconds=60.0,
        )
        service._preauth_challenges = wa.PreAuthChallengePool(clock=lambda: clock[0])
        first = service.begin_passkey_sign_in(rp_id=RP, client="192.0.2.30")
        second = service.begin_passkey_sign_in(rp_id=RP, client="192.0.2.30")
        assert first is not None and second is not None
        clock[0] += 59
        taken = service.take_passkey_challenge(first[0])
        assert taken is not None and taken.paid  # its hit now stands at t=59
        clock[0] += 2  # t=61: the second begin's hit (t=0) has aged out; the challenge has not
        taken = service.take_passkey_challenge(second[0])
        assert taken is not None and not taken.paid
        assert service.allow_login_attempt("192.0.2.30"), "the renewed hit was counted twice"
        assert not service.allow_login_attempt("192.0.2.30"), "a banked charge was spent"
        assert service.take_passkey_challenge(second[0]) is None, "a challenge was taken twice"
        assert service.take_passkey_challenge("forged") is None
    finally:
        await store.close()


def test_the_limiter_renews_only_a_hit_still_in_its_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """``SlidingWindowRateLimiter.renew`` moves a live hit to now and counts nothing new; an aged
    or unknown hit is not renewed."""
    from messagefoundry.auth import ratelimit

    clock = [0.0]
    # The limiter module's own clock only: the event loop keeps the real one.
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", types.SimpleNamespace(monotonic=lambda: clock[0])
    )
    limiter = ratelimit.SlidingWindowRateLimiter(per_key=1, glob=5, window_seconds=10.0)
    stamp = limiter.allow_stamped("a")
    assert stamp == 0.0 and not limiter.allow("a")
    clock[0] = 9.0
    assert limiter.renew("a", stamp)
    assert not limiter.renew("a", stamp), "a renewed hit was renewed again"
    clock[0] = 12.0  # the original stamp would have aged out; the renewed hit (t=9) has not
    assert not limiter.allow("a")
    clock[0] = 19.5
    assert limiter.allow("a")
    assert not limiter.renew("b", 19.5)


def test_the_configured_rp_id_is_the_public_origin_host() -> None:
    """Item 1: the one derivation the engine, ``verify`` and the console share."""
    from messagefoundry.auth.webauthn import configured_rp_id

    assert configured_rp_id("https://Ops.Example:8443") == "ops.example"
    assert configured_rp_id(None) is None and configured_rp_id("") is None


async def test_with_no_configured_rp_id_the_last_discoverable_passkey_still_needs_totp() -> None:
    """Item 1, the removal gate with no configured rp_id: any discoverable passkey may be the way
    past the sign-in uses, so removing one is guarded, and no other passkey counts as what remains.
    Beside a passkey that is not discoverable it is refused; beside a usable TOTP it may go."""
    store = await MessageStore.open(":memory:")
    try:
        setup = _service(store)
        identity, token, _ = await login_admin(setup)
        _, token = await _register(setup, identity, token, label="resident")
        _, token = await _register(setup, identity, token, resident_key=False, label="plain")
        gate = _gate_service(store, None)
        by_label = {c.label: c for c in await store.list_webauthn_credentials(identity.user_id)}
        with pytest.raises(ValueError) as refused:
            await gate.delete_webauthn_credential(identity, by_label["resident"].credential_id_hash)
        assert str(refused.value) == PASSKEY_REMOVAL_REFUSED
        await _enable_totp(store, identity.user_id, _USABLE_TOTP)
        assert await gate.delete_webauthn_credential(
            identity, by_label["resident"].credential_id_hash
        )
    finally:
        await store.close()


# --- BACKLOG #3937 item 8: the sign-in lock escalates beside a discoverable passkey ---------------


async def _two_sign_in_cycles(service: AuthService, user_id: str) -> float:
    """Lock the sign-in counter twice through the service's failure seam; return the second lock's
    length."""
    user = await service._load_user(user_id)
    assert user is not None
    start = 1_000_000.0
    for cycle in range(2):
        at = start + cycle * 10_000.0
        for i in range(_LOCK_THRESHOLD):
            await service._register_failure(user, at + i, counter="sign_in")
    row = await service._store.get_user(user_id)
    assert row is not None and row.locked_until is not None and row.lock_cycles == 2
    return float(row.locked_until - (start + 10_000.0 + _LOCK_THRESHOLD - 1))


@pytest.mark.parametrize(
    ("configured", "escalates"), [(RP, True), (None, True), ("elsewhere.example", False)]
)
async def test_the_sign_in_lock_escalates_beside_a_discoverable_passkey(
    configured: str | None, escalates: bool
) -> None:
    """A passkey-only account's sign-in lock doubles per cycle as a TOTP account's does, because
    the combined passkey sign-in passes it. Which passkey counts is the lock notice's rule: under
    the configured relying party where there is one, any discoverable one where there is none. A
    passkey under another relying party is no way past, so its lock keeps the fixed length."""
    store = await MessageStore.open(":memory:")
    try:
        _, identity, _, _ = await _passkey_owner(store)
        service = _lock_service(store, way_past_rp_id=configured)
        length = await _two_sign_in_cycles(service, identity.user_id)
        assert length == (1800.0 if escalates else 900.0), length
    finally:
        await store.close()


async def test_a_password_only_account_keeps_the_fixed_sign_in_lock() -> None:
    """The control: no TOTP and no passkey, so no way past, and the second lock is the base."""
    store = await MessageStore.open(":memory:")
    try:
        service = _lock_service(store)
        identity, _token, _ = await login_admin(service)
        assert await _two_sign_in_cycles(service, identity.user_id) == 900.0
    finally:
        await store.close()


async def test_without_the_webauthn_extra_a_passkey_does_not_escalate_the_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the extra no passkey can sign in, so none is a way past, and the lock keeps the
    fixed length beside one."""
    from messagefoundry.auth import webauthn as wa

    store = await MessageStore.open(":memory:")
    try:
        service, identity, _, _ = await _passkey_owner(store)
        monkeypatch.setattr(wa, "available", lambda: False)
        assert await _two_sign_in_cycles(service, identity.user_id) == 900.0
    finally:
        await store.close()
