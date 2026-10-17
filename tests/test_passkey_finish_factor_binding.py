# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``finish_webauthn_registration`` asks ``_factor_binding_is_blocked`` again at finish time.

BACKLOG #3014. The begin gate asks it when the ceremony is staged. The web console's finish route,
``/ui/account/webauthn/verify``, rides the action-less ``require_ui_reauth_only``, which never asks,
and no JSON route finishes a registration, so the service is the one place left to ask. Without
it, a ceremony staged while the account had no factor still finished after a TOTP was enrolled on
another session, binding a passkey and promoting a session that never proved the existing factor.

The account here is a directory account, the case ADR 0207 Context item 3 names under the shipped
posture: its Kerberos session mints unstamped, and ``begin_webauthn_registration`` accepts it with no
factor. A local sign-in that owes nothing mints stamped, so it does not reach this gap. All directory
data is synthetic.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator

import pytest

pytest.importorskip("webauthn")

from webauthn.helpers import base64url_to_bytes  # noqa: E402

from messagefoundry.auth import reconcile, totp  # noqa: E402
from messagefoundry.auth.identity import Identity  # noqa: E402
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryProbe  # noqa: E402
from messagefoundry.auth.service import AuthService, Elevation  # noqa: E402
from messagefoundry.auth.tokens import hash_token  # noqa: E402
from messagefoundry.config.settings import AuthSettings  # noqa: E402
from messagefoundry.store.store import MessageStore, UserRecord  # noqa: E402
from tests._admin_account import login_admin  # noqa: E402
from tests._soft_webauthn import SoftAuthenticator  # noqa: E402
from tests._totp_clock import pin_totp_clock  # noqa: E402

_RP, _ORIGIN = "t", "http://t"

_PRINCIPAL = AdPrincipal(
    username="rlopez",
    display_name="R Lopez",
    email="rlopez@test.invalid",
    dn="CN=rlopez,OU=Staff,DC=test,DC=invalid",
    groups=frozenset(),
    directory_object_id="9c41d2e8-7a3b-4f60-b5e1-2d8f0a6c4b17",
)


class _Directory:
    """A directory that always confirms the synthetic principal."""

    def probe_principal(self, username: str, *, object_id: str | None = None) -> DirectoryProbe:
        return DirectoryProbe(DirectoryAnswer.FOUND, _PRINCIPAL)


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    yield s
    await s.close()


async def _service(store: MessageStore, *, require_mfa: bool) -> AuthService:
    service = AuthService(
        store,
        AuthSettings(
            require_mfa=require_mfa,
            mfa_verify_min_elapsed_seconds=0,
            ad_enabled=True,
            ad_server="ldaps://dc.test.invalid",
            ad_user_search_base="OU=Staff,DC=test,DC=invalid",
            ad_bind_dn="CN=svc-mefor,OU=Service,DC=test,DC=invalid",
            ad_bind_password="synthetic",
        ),
        ldap=_Directory(),  # type: ignore[arg-type]
    )
    await service.initialize()
    return service


async def _sign_in(service: AuthService) -> tuple[Identity, str]:
    out = await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=False)
    assert out.token is not None and out.identity is not None
    return out.identity, out.token


async def _stage_passkey(service: AuthService, identity: Identity, token: str) -> str:
    """Stage a registration ceremony; return an attestation answering it."""
    options = json.loads(
        await service.begin_webauthn_registration(
            identity, token=token, rp_id=_RP, rp_name="MessageFoundry"
        )
    )
    key = SoftAuthenticator(rp_id=_RP, origin=_ORIGIN)
    return key.create_response(base64url_to_bytes(options["challenge"]))


async def _enrol_totp_elsewhere(service: AuthService, at: float) -> str:
    """Enrol TOTP on a SECOND session, which ``confirm_mfa_enrollment`` stamps; return the secret."""
    identity, token = await _sign_in(service)
    enrollment = await service.begin_mfa_enrollment(identity)
    code = totp.totp(enrollment.secret, now=at)
    assert (await service.confirm_mfa_enrollment(identity, code, token=token)).ok
    return enrollment.secret


async def _finish(service: AuthService, identity: Identity, token: str, response: str) -> Elevation:
    return await service.finish_webauthn_registration(
        identity, response, label="key", token=token, rp_id=_RP, origin=_ORIGIN
    )


@pytest.mark.parametrize("require_mfa", (True, False), ids=("require_mfa", "mfa-optional"))
async def test_a_ceremony_staged_before_totp_enrolment_cannot_finish_after_it(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, require_mfa: bool
) -> None:
    """RED when: ``finish_webauthn_registration`` does not ask ``_factor_binding_is_blocked``,
    asks it before the "ceremony expired" answer, leaves the stale ceremony in flight, or persists
    anything on the refusal."""
    t0 = time.time()
    pin_totp_clock(monkeypatch, t0)
    service = await _service(store, require_mfa=require_mfa)
    identity, token = await _sign_in(service)
    response = await _stage_passkey(service, identity, token)
    await _enrol_totp_elsewhere(service, t0)
    assert await service.mfa_satisfied(token) is False  # the staging session never proved it

    with pytest.raises(ValueError, match="already has a second factor"):
        await _finish(service, identity, token, response)

    assert await store.list_webauthn_credentials(identity.user_id) == []
    assert await service.mfa_satisfied(token) is False
    session = await store.get_session(hash_token(token))
    assert session is not None and session.mfa_verified_at is None
    # Audited as the begin gate's refusal of a pending session is.
    rows = await store.list_audit(action="auth.mfa_denied")
    assert {"path": "finish_webauthn_registration"} in [json.loads(r["detail"]) for r in rows]
    # The refusal took the challenge, so the stale ceremony is dead, not waiting for a retry.
    with pytest.raises(ValueError, match="ceremony expired"):
        await _finish(service, identity, token, response)
    # "Ceremony expired" still answers first: a second pending session that staged nothing gets it,
    # not the factor refusal, so the refusal cannot be had without a staged ceremony.
    other_identity, other = await _sign_in(service)
    with pytest.raises(ValueError, match="ceremony expired"):
        await _finish(service, other_identity, other, response)


async def test_a_session_revoked_mid_ceremony_is_answered_as_lost_not_as_owing_a_factor(
    store: MessageStore,
) -> None:
    """The factor check fails closed on a dead session. RED when: that fail-closed answer reaches
    the caller as "already has a second factor" for an account that holds none."""
    service = await _service(store, require_mfa=True)
    identity, token = await _sign_in(service)
    response = await _stage_passkey(service, identity, token)
    await store.revoke_session(hash_token(token))

    lost = await _finish(service, identity, token, response)

    assert lost.session_lost is True and lost.ok is False
    assert await store.list_webauthn_credentials(identity.user_id) == []
    assert await store.list_audit(action="auth.mfa_denied") == []


async def test_a_session_that_proves_the_existing_factor_first_still_finishes(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the check must not refuse a session that verified the factor it owes."""
    t0 = time.time()
    pin_totp_clock(monkeypatch, t0)
    service = await _service(store, require_mfa=True)
    identity, token = await _sign_in(service)
    response = await _stage_passkey(service, identity, token)
    secret = await _enrol_totp_elsewhere(service, t0)

    # Enrolment consumed t0's step (BACKLOG #1021), so the verify lands in the next one.
    t1 = t0 + totp.DEFAULT_PERIOD
    pin_totp_clock(monkeypatch, t1)
    verified = await service.verify_mfa(token, totp.totp(secret, now=t1))
    assert verified.ok and verified.token is not None  # rotated; the ceremony is re-keyed with it

    enrolled = await _finish(service, identity, verified.token, response)

    assert enrolled.ok is True
    assert len(await store.list_webauthn_credentials(identity.user_id)) == 1


async def test_a_totp_bound_during_the_directory_lookup_stops_the_passkey_finish(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3061: the directory lookup at finish is a network round trip, AFTER the factor
    check above. A TOTP confirmed on another session during it must still stop the registration.
    RED when: ``finish_webauthn_registration`` does not ask ``_factor_binding_is_blocked`` again
    once the lookup returns, so the passkey binds and the session is promoted without proving the
    factor the account now holds."""
    t0 = time.time()
    pin_totp_clock(monkeypatch, t0)
    service = await _service(store, require_mfa=False)
    identity, token = await _sign_in(service)
    response = await _stage_passkey(service, identity, token)
    real_probe = service._probe_principal
    confirmed: list[str] = []

    async def _probe_while_totp_confirms(user: UserRecord) -> reconcile.Probe:
        # Restored first: the confirm below runs its own lookup through the same seam.
        monkeypatch.setattr(service, "_probe_principal", real_probe)
        confirmed.append(await _enrol_totp_elsewhere(service, t0))
        return await real_probe(user)

    monkeypatch.setattr(service, "_probe_principal", _probe_while_totp_confirms)

    with pytest.raises(ValueError, match="already has a second factor"):
        await _finish(service, identity, token, response)

    assert len(confirmed) == 1  # the injection ran inside the lookup, not before it
    assert await store.list_webauthn_credentials(identity.user_id) == []
    session = await store.get_session(hash_token(token))
    assert session is not None and session.mfa_verified_at is None
    assert await service.mfa_satisfied(token) is False
    rows = await store.list_audit(action="auth.mfa_denied")
    assert {"path": "finish_webauthn_registration"} in [json.loads(r["detail"]) for r in rows]
    # Refused as the earlier check refuses: the ceremony is ended, not left for a retry.
    assert service._webauthn_challenges.peek((hash_token(token), "register")) is None


async def test_a_session_revoked_between_the_two_asks_is_lost_not_owing_a_factor(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second ask fails closed on a dead session, as the first does, so it carries the same
    session guard. RED when: a session revoked after the first ask is told the account "already
    has a second factor" (it holds none) and an ``auth.mfa_denied`` row is written for it. A LOCAL
    account, because a directory account's lookup re-reads the session and answers it lost first."""
    service = await _service(store, require_mfa=False)
    identity, token, _password = await login_admin(service)
    response = await _stage_passkey(service, identity, token)
    real_floor = service._enrolment_too_early

    async def _floor_while_revoked(*args: object, **kwargs: object) -> bool:
        await store.revoke_session(hash_token(token))
        return await real_floor(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(service, "_enrolment_too_early", _floor_while_revoked)

    lost = await _finish(service, identity, token, response)

    assert lost.session_lost is True and lost.ok is False
    assert await store.list_webauthn_credentials(identity.user_id) == []
    assert await store.list_audit(action="auth.mfa_denied") == []
    # A dead session can never finish the ceremony, so the lost answer ends it.
    assert service._webauthn_challenges.peek((hash_token(token), "register")) is None
