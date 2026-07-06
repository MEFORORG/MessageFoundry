# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""AuthService-level WebAuthn passkey tests (WP-14b, ADR 0068) — real ceremonies throughout.

Every registration/assertion here drives py_webauthn's REAL ``verify_*`` functions via the
in-repo soft authenticator (``tests/_soft_webauthn.py``), matching the live-TOTP convention of
``tests/test_mfa.py``. Gated on the ``[webauthn]`` extra (CI installs it via the ci.yml extras
line; the extra-free store parity contract lives in ``tests/_webauthn_store_contract.py``).
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("webauthn")

from webauthn.helpers import base64url_to_bytes  # noqa: E402

from messagefoundry.auth import webauthn as wa  # noqa: E402
from messagefoundry.auth.identity import Identity  # noqa: E402
from messagefoundry.auth.notifications import MFA_DISABLED, SecurityEvent  # noqa: E402
from messagefoundry.auth.service import AuthService  # noqa: E402
from messagefoundry.config.settings import AuthSettings  # noqa: E402
from messagefoundry.store.store import MessageStore  # noqa: E402

from tests._soft_webauthn import SoftAuthenticator  # noqa: E402

RP = "t"
ORIGIN = "http://t"


class _FakeNotifier:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _service(
    store: MessageStore, *, notifier: _FakeNotifier | None = None, **settings: object
) -> AuthService:
    service = AuthService(store, AuthSettings(**settings), security_notifier=notifier)
    return service


async def _bootstrap_login(service: AuthService) -> tuple[Identity, str, str]:
    boot = await service.initialize()
    assert boot is not None
    out = await service.login("admin", boot.password)
    assert out.ok and out.identity is not None and out.token is not None
    return out.identity, out.token, boot.password


async def _enroll(
    service: AuthService,
    identity: Identity,
    token: str,
    *,
    label: str = "test key",
    auth: SoftAuthenticator | None = None,
) -> SoftAuthenticator:
    """Run a full real registration ceremony; returns the enrolled soft authenticator."""
    auth = auth or SoftAuthenticator(rp_id=RP, origin=ORIGIN)
    opts = json.loads(
        await service.begin_webauthn_registration(
            identity, token=token, rp_id=RP, rp_name="MessageFoundry"
        )
    )
    challenge = base64url_to_bytes(opts["challenge"])
    ok = await service.finish_webauthn_registration(
        identity,
        auth.create_response(challenge, transports=["usb"]),
        label=label,
        token=token,
        rp_id=RP,
        origin=ORIGIN,
    )
    assert ok is True
    return auth


async def _assert_once(
    service: AuthService, token: str, auth: SoftAuthenticator, *, sign_count: int | None = None
) -> bool:
    options = await service.begin_webauthn_assertion(token, rp_id=RP)
    assert options is not None
    challenge = base64url_to_bytes(json.loads(options)["challenge"])
    return await service.finish_webauthn_assertion(
        token, auth.get_response(challenge, sign_count=sign_count), rp_id=RP, origin=ORIGIN
    )


async def _events(service: AuthService, username: str) -> list[str]:
    return [e["action"] for e in await service.security_events_for(username)]


# --- E2E ceremonies -------------------------------------------------------------


async def test_register_then_assert_e2e() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, _ = await _bootstrap_login(service)

        status = await service.mfa_status(identity)
        assert status.webauthn_enrolled is False and status.required is False

        auth = await _enroll(service, identity, token)
        # Registration options exclude the enrolled credential on the next ceremony.
        opts = json.loads(
            await service.begin_webauthn_registration(
                identity, token=token, rp_id=RP, rp_name="MessageFoundry"
            )
        )
        assert opts["excludeCredentials"][0]["id"] == auth.credential_id_b64

        status = await service.mfa_status(identity)
        # enabled stays == TOTP on the wire; webauthn_enrolled is the additive field; a
        # WebAuthn-enrolled user is ALWAYS MFA-required (enrolled-any-factor ⇒ required).
        assert status.enabled is False and status.webauthn_enrolled is True
        assert status.required is True

        # The enrolling session was marked MFA-verified (confirm_mfa_enrollment parity).
        assert await service.mfa_satisfied(token) is True

        assert await _assert_once(service, token, auth) is True
        actions = await _events(service, identity.username)
        assert "auth.webauthn_enrolled" in actions and "auth.webauthn_verified" in actions
    finally:
        await store.close()


async def test_fresh_session_is_mfa_pending_until_assertion() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, password = await _bootstrap_login(service)
        auth = await _enroll(service, identity, token)

        out = await service.login("admin", password)
        assert out.ok and out.token is not None
        fresh = out.token
        assert await service.mfa_satisfied(fresh) is False  # webauthn-enrolled ⇒ required
        assert await _assert_once(service, fresh, auth) is True
        assert await service.mfa_satisfied(fresh) is True
    finally:
        await store.close()


async def test_assertion_stamps_mfa_only_never_reauth() -> None:
    """ADR 0068 decision 1: the assertion satisfies ONLY the MFA leg — reauth_at stays untouched
    (the password leg of /ui/reauth re-anchors; skipping that here is the loop-class defense)."""
    from messagefoundry.auth.tokens import hash_token

    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, password = await _bootstrap_login(service)
        auth = await _enroll(service, identity, token)

        out = await service.login("admin", password)
        fresh = out.token
        assert fresh is not None
        before = await store.get_session(hash_token(fresh))
        assert before is not None and before.reauth_at is None  # MFA-pending: no seeded step-up
        assert await _assert_once(service, fresh, auth) is True
        after = await store.get_session(hash_token(fresh))
        assert after is not None
        assert after.mfa_verified_at is not None
        assert after.reauth_at is None  # NEVER stamped by the assertion
    finally:
        await store.close()


async def test_registration_rejects_wrong_origin() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, _ = await _bootstrap_login(service)
        opts = json.loads(
            await service.begin_webauthn_registration(
                identity, token=token, rp_id=RP, rp_name="MessageFoundry"
            )
        )
        challenge = base64url_to_bytes(opts["challenge"])
        evil = SoftAuthenticator(rp_id=RP, origin="http://evil")
        ok = await service.finish_webauthn_registration(
            identity,
            evil.create_response(challenge),
            label="evil",
            token=token,
            rp_id=RP,
            origin=ORIGIN,
        )
        assert ok is False  # origin binding — the phishing-resistance property
        assert "auth.webauthn_failed" in await _events(service, identity.username)
        assert (await service.mfa_status(identity)).webauthn_enrolled is False
    finally:
        await store.close()


# --- sign-count clone detection ---------------------------------------------------


async def test_sign_count_cas_clone_detection_nonzero() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, _ = await _bootstrap_login(service)
        auth = SoftAuthenticator(rp_id=RP, origin=ORIGIN, sign_count=5)
        await _enroll(service, identity, token, auth=auth)

        assert await _assert_once(service, token, auth, sign_count=6) is True
        # A cloned authenticator replays a non-advancing counter: py_webauthn rejects it and the
        # service audits the clone signal.
        assert await _assert_once(service, token, auth, sign_count=6) is False
        assert "auth.webauthn_clone_suspected" in await _events(service, identity.username)
        assert await _assert_once(service, token, auth, sign_count=5) is False
        # The genuine key advancing again is fine.
        assert await _assert_once(service, token, auth, sign_count=7) is True
    finally:
        await store.close()


async def test_sign_count_zero_synced_passkey_accepted_repeatedly() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, _ = await _bootstrap_login(service)
        auth = await _enroll(service, identity, token)  # sign_count stays 0 (synced passkey)
        for _ in range(3):
            assert await _assert_once(service, token, auth, sign_count=0) is True
        creds = await store.list_webauthn_credentials(identity.user_id)
        assert creds[0].sign_count == 0 and creds[0].last_used_at is not None
    finally:
        await store.close()


# --- challenge lifecycle ------------------------------------------------------------


async def test_challenge_single_use_ttl_and_per_user_bound() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, _ = await _bootstrap_login(service)
        auth = await _enroll(service, identity, token)

        # Single-use: the replay of an already-consumed challenge fails (covered E2E above); an
        # expired challenge fails legibly. Swap in a controllable clock.
        clock = [0.0]
        service._webauthn_challenges = wa.ChallengeCache(clock=lambda: clock[0])
        options = await service.begin_webauthn_assertion(token, rp_id=RP)
        assert options is not None
        challenge = base64url_to_bytes(json.loads(options)["challenge"])
        clock[0] = wa.CHALLENGE_TTL_SECONDS + 1  # expire it
        ok = await service.finish_webauthn_assertion(
            token, auth.get_response(challenge, sign_count=0), rp_id=RP, origin=ORIGIN
        )
        assert ok is False
        assert "auth.webauthn_failed" in await _events(service, identity.username)

        # A new ceremony overwrites the session's pending one: the FIRST challenge dies.
        clock[0] = 0.0
        o1 = await service.begin_webauthn_assertion(token, rp_id=RP)
        o2 = await service.begin_webauthn_assertion(token, rp_id=RP)
        assert o1 is not None and o2 is not None
        c1 = base64url_to_bytes(json.loads(o1)["challenge"])
        assert (
            await service.finish_webauthn_assertion(
                token, auth.get_response(c1, sign_count=0), rp_id=RP, origin=ORIGIN
            )
            is False
        )

        # Per-user cap evicts the user's OWN oldest — never another principal's (two-user
        # interleave); the global safety bound refuses with a cause-naming error.
        cache = wa.ChallengeCache(per_user_cap=2, global_cap=3, clock=lambda: clock[0])
        clock[0] = 0.0
        cache.put(("a1", "assert"), "alice", b"a1")
        clock[0] = 1.0
        cache.put(("b1", "assert"), "bob", b"b1")
        clock[0] = 2.0
        cache.put(("a2", "assert"), "alice", b"a2")
        clock[0] = 3.0
        cache.put(("a3", "assert"), "alice", b"a3")  # alice at cap: evicts a1, not bob's b1
        assert cache.pop(("a1", "assert")) is None
        assert cache.pop(("b1", "assert")) is not None
        with pytest.raises(wa.ChallengeCacheFullError, match="safety bound"):
            full = wa.ChallengeCache(per_user_cap=9, global_cap=1, clock=lambda: clock[0])
            full.put(("x1", "assert"), "u1", b"x")
            full.put(("x2", "assert"), "u2", b"y")
    finally:
        await store.close()


# --- lifecycle + factor generalization -------------------------------------------


async def test_ad_user_cannot_enroll_passkey() -> None:
    from messagefoundry.auth.ldap import AdPrincipal

    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        await _bootstrap_login(service)
        principal = AdPrincipal(
            username="aduser",
            display_name="AD User",
            email=None,
            dn="CN=aduser,DC=x",
            groups=frozenset(),
        )
        out = await service._complete_ad_login(principal, None)
        assert out.ok and out.identity is not None and out.token is not None
        with pytest.raises(ValueError, match="only local users"):
            await service.begin_webauthn_registration(
                out.identity, token=out.token, rp_id=RP, rp_name="MessageFoundry"
            )
    finally:
        await store.close()


async def test_duplicate_label_and_duplicate_credential_rejected() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, _ = await _bootstrap_login(service)
        auth = await _enroll(service, identity, token, label="mykey")

        # Same label again (different authenticator) → legible refusal via the integrity path.
        opts = json.loads(
            await service.begin_webauthn_registration(
                identity, token=token, rp_id=RP, rp_name="MessageFoundry"
            )
        )
        other = SoftAuthenticator(rp_id=RP, origin=ORIGIN)
        with pytest.raises(ValueError, match="label already in use"):
            await service.finish_webauthn_registration(
                identity,
                other.create_response(base64url_to_bytes(opts["challenge"])),
                label="mykey",
                token=token,
                rp_id=RP,
                origin=ORIGIN,
            )

        # The SAME authenticator re-registered under a new label → already enrolled.
        opts = json.loads(
            await service.begin_webauthn_registration(
                identity, token=token, rp_id=RP, rp_name="MessageFoundry"
            )
        )
        with pytest.raises(ValueError, match="already enrolled"):
            await service.finish_webauthn_registration(
                identity,
                auth.create_response(base64url_to_bytes(opts["challenge"])),
                label="another name",
                token=token,
                rp_id=RP,
                origin=ORIGIN,
            )
    finally:
        await store.close()


async def test_last_factor_delete_refused_while_required() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        # require_mfa targets local Administrators — the bootstrap admin qualifies.
        service = await _service(store, notifier=notifier, require_mfa=True)
        identity, token, _ = await _bootstrap_login(service)
        await _enroll(service, identity, token)
        creds = await store.list_webauthn_credentials(identity.user_id)
        with pytest.raises(ValueError, match="enroll another factor first"):
            await service.delete_webauthn_credential(identity, creds[0].credential_id_hash)
        assert await store.has_webauthn_credentials(identity.user_id) is True
    finally:
        await store.close()


async def test_last_factor_delete_notifies_when_not_required() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier=notifier)  # require_mfa off
        identity, token, _ = await _bootstrap_login(service)
        await _enroll(service, identity, token)
        creds = await store.list_webauthn_credentials(identity.user_id)

        # Self-scoped: a foreign/unknown hash removes nothing.
        assert await service.delete_webauthn_credential(identity, "not-a-hash") is False

        assert (
            await service.delete_webauthn_credential(identity, creds[0].credential_id_hash) is True
        )
        assert await store.has_webauthn_credentials(identity.user_id) is False
        assert any(e.event_type == MFA_DISABLED for e in notifier.events)
        assert "auth.webauthn_removed" in await _events(service, identity.username)
    finally:
        await store.close()


async def test_admin_reset_mfa_clears_webauthn_credentials() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, _ = await _bootstrap_login(service)
        await _enroll(service, identity, token)
        await service.admin_reset_mfa(identity.user_id, actor="boss")
        assert await store.has_webauthn_credentials(identity.user_id) is False
        # Sessions were revoked (existing semantics unchanged).
        assert await service.mfa_satisfied(token) is False
    finally:
        await store.close()


async def test_assertion_failures_never_lock_the_account() -> None:
    """The recorded lockout divergence (ADR 0068): garbage assertions are audited but do NOT feed
    _register_failure — a flaky authenticator must not lock the account."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, _ = await _bootstrap_login(service)
        await _enroll(service, identity, token)
        for _ in range(10):
            assert (
                await service.finish_webauthn_assertion(
                    token, '{"rawId": "garbage"}', rp_id=RP, origin=ORIGIN
                )
                is False
            )
        user = await store.get_user(identity.user_id)
        assert user is not None
        assert user.locked_until is None and user.failed_attempts == 0
    finally:
        await store.close()


async def test_verify_mfa_stays_totp_specific() -> None:
    """A WebAuthn-only user submitting a TOTP code gets a plain refusal — no lockout attempt is
    burned on an unanswerable factor (verify_mfa's totp_enabled check is untouched)."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, _ = await _bootstrap_login(service)
        await _enroll(service, identity, token)
        assert await service.verify_mfa(token, "123456") is False
        user = await store.get_user(identity.user_id)
        assert user is not None and user.failed_attempts == 0
    finally:
        await store.close()


async def test_rp_mismatch_makes_credentials_unusable() -> None:
    """Credentials are pinned to their mint-time rp_id (ADR 0068 §7): after an origin migration
    the assertion options come back empty (None) — visibly unusable, never a silent failure."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store)
        identity, token, _ = await _bootstrap_login(service)
        await _enroll(service, identity, token)
        assert await service.begin_webauthn_assertion(token, rp_id="other.example") is None
    finally:
        await store.close()


async def test_extra_less_install_raises_legibly(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the [webauthn] extra absent, available() is False and ceremony wrappers raise the
    install-hint RuntimeError (the UI renders it as a notice; the startup advisory is PR-B)."""
    import builtins

    real_import = builtins.__import__

    def _no_webauthn(name: str, *args: object, **kwargs: object) -> object:
        if name == "webauthn" or name.startswith("webauthn."):
            raise ImportError("No module named 'webauthn'")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", _no_webauthn)
    assert wa.available() is False
    with pytest.raises(RuntimeError, match=r"\[webauthn\] extra"):
        wa.registration_options(
            rp_id=RP, rp_name="MF", user_id="u", user_name="u", challenge=b"x" * 64
        )
