# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The first-seen login-address signal (BACKLOG #288, ASVS 8.2.4).

At every session mint the engine compares the sign-in's client address with the account's
known-address record (vault BACKLOG #2145), which holds the addresses of sign-ins that finished every
factor they owed. A first-seen address writes ``auth.login_new_ip``, sends the ``login_new_ip``
notice, and mints the session WITHOUT step-up freshness. That is a challenge only: the login itself
always succeeds. With nothing to compare against -- the account's first sign-in ever, or no client
address at all -- the signal fails open and audits ``auth.login_address_unevaluated`` with the reason.

Synthetic accounts and RFC 5737 / RFC 1918 addresses only.
"""

from __future__ import annotations

import json
import time
import urllib.parse
from typing import Any

import pytest
from _totp_clock import fresh_totp, pin_totp_clock
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import Role, totp
from messagefoundry.auth import service as service_module
from messagefoundry.auth.identity import ALL_CHANNELS, Identity
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryProbe
from messagefoundry.auth.notifications import LOGIN_NEW_IP, SecurityEvent
from messagefoundry.auth.service import AuthService, LoginOutcome
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_local_user_chosen
from tests.test_auth_oidc_service import (
    AUTH_CODE,
    DEFAULT_SUB,
    _bind,
    _claims,
    _mint,
    _stub_exchange,
)
from tests.test_auth_oidc_service import _service as _oidc_service

PW = "a-strong-test-passphrase"  # >= 15, no app/vendor terms: satisfies the ASVS policy (WP-3)


class _FakeNotifier:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


class _RaisingNotifier:
    """A notifier that always fails, to prove a broken channel cannot refuse a login."""

    async def notify(self, event: SecurityEvent) -> None:
        raise OSError("synthetic relay failure")


async def _service(
    store: MessageStore, notifier: object | None = None, **over: object
) -> AuthService:
    settings = AuthSettings(require_mfa=False, **over)  # type: ignore[arg-type]
    service = AuthService(store, settings, security_notifier=notifier)  # type: ignore[arg-type]
    await service.initialize()
    return service


async def _operator(service: AuthService, username: str = "oper") -> str:
    uid = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=f"{username}@example.org",
        roles=[Role.OPERATOR.value],
        actor="t",
    )
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="t")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    return uid


async def _actions(store: MessageStore, username: str) -> list[str]:
    """This account's audit actions, oldest first."""
    rows = await store.list_audit(actor=username, limit=500)
    return [str(r["action"]) for r in reversed(rows)]


async def _seeded(store: MessageStore, token: str | None) -> bool:
    assert token is not None
    session = await store.get_session(hash_token(token))
    assert session is not None
    return session.reauth_at is not None


def _new_ip_notices(notifier: _FakeNotifier) -> list[SecurityEvent]:
    return [e for e in notifier.events if e.event_type == LOGIN_NEW_IP]


async def _no_sleep(deadline: float) -> None:
    """Stands in for the real-time pad on a failed federated sign-in (BACKLOG #1947)."""
    return None


async def _enrol_totp(
    service: AuthService,
    identity: Identity,
    token: str,
    *,
    client: str,
    now: float | None = None,
) -> str:
    """Confirm a real TOTP enrolment from ``client``; returns the shared secret. Pass ``now`` with
    the TOTP clock pinned there when the test verifies a later code, since enrolment consumes its
    step."""
    enroll = await service.begin_mfa_enrollment(identity)
    code = totp.totp(enroll.secret, now=now) if now is not None else fresh_totp(enroll.secret)
    elevation = await service.confirm_mfa_enrollment(identity, code, token=token, client=client)
    assert elevation.ok, "the enrolment confirm was refused"
    return enroll.secret


async def test_first_login_ever_fails_open_and_audits_no_baseline() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        out = await service.login("oper", PW, client="10.1.1.1")
        assert out.ok
        assert await _seeded(store, out.token)
        assert _new_ip_notices(notifier) == []
        rows = await store.list_audit(actor="oper", action="auth.login_address_unevaluated")
        assert len(rows) == 1
        assert '"reason": "no_baseline"' in str(rows[0]["detail"])
        assert "auth.login_new_ip" not in await _actions(store, "oper")
        # The login's own row stays the newest one for it.
        assert (await _actions(store, "oper"))[-1] == "auth.login_success"
    finally:
        await store.close()


async def test_a_known_address_writes_nothing_and_keeps_the_seed() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        before = await _actions(store, "oper")
        out = await service.login("oper", PW, client="10.1.1.1")
        assert out.ok
        assert await _seeded(store, out.token)
        added = (await _actions(store, "oper"))[len(before) :]
        assert added == ["auth.login_success"]
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()


async def test_a_first_seen_address_is_audited_notified_and_unseeded() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        out = await service.login("oper", PW, client="198.51.100.7")
        assert out.ok and out.token is not None and out.identity is not None
        # The challenge: no step-up freshness, so the first sensitive action re-proves a credential.
        assert not await _seeded(store, out.token)
        rows = await store.list_audit(actor="oper", action="auth.login_new_ip")
        assert len(rows) == 1
        assert rows[0]["client"] == "198.51.100.7"
        # The local leg names no mechanism: only the directory leg needs one (vault BACKLOG #2156).
        assert json.loads(str(rows[0]["detail"])) == {"provider": "local"}
        notices = _new_ip_notices(notifier)
        assert len(notices) == 1
        assert notices[0].client_ip == "198.51.100.7"
        assert notices[0].email == "oper@example.org"
        assert notices[0].detail == {"provider": "local"}
        assert (await _actions(store, "oper"))[-1] == "auth.login_success"
        # vault BACKLOG #2145: signing in again does NOT pass the challenge. The audit baseline this
        # replaced counted the challenged login's own row, so the second sign-in was seeded.
        again = await service.login("oper", PW, client="198.51.100.7")
        assert again.ok and again.token is not None and again.identity is not None
        assert not await _seeded(store, again.token)
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 2
        # A step-up from that address passes it: the next sign-in is seeded, and writes no row.
        stepped = await service.reauth(again.identity, PW, token=again.token, client="198.51.100.7")
        assert stepped.ok
        third = await service.login("oper", PW, client="198.51.100.7")
        assert third.ok and await _seeded(store, third.token)
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 2
        # The audit row is written every time; the notice is debounced per account and address.
        assert len(_new_ip_notices(notifier)) == 1
    finally:
        await store.close()


async def test_loopback_forms_are_one_host() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="127.0.0.1")).ok
        out = await service.login("oper", PW, client="::1")
        assert out.ok and await _seeded(store, out.token)
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()


async def test_no_client_address_fails_open_and_audits_unknown_address() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        out = await service.login("oper", PW, client=None)
        assert out.ok and await _seeded(store, out.token)
        rows = await store.list_audit(actor="oper", action="auth.login_address_unevaluated")
        assert any('"reason": "unknown_address"' in str(r["detail"]) for r in rows)
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()


async def test_an_address_outside_the_lookback_reads_as_new(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A returning account whose known address aged out is NOT the first-login case: it has signed in
    before (``last_login_at`` is set), so an unrecognised address is NEW, not unevaluated."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        monkeypatch.setattr(service_module, "_LOGIN_ADDRESS_LOOKBACK_SECONDS", -3600)
        out = await service.login("oper", PW, client="10.1.1.1")
        assert out.ok and not await _seeded(store, out.token)
        assert len(_new_ip_notices(notifier)) == 1
    finally:
        await store.close()


async def test_a_failing_notifier_never_refuses_the_login() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, _RaisingNotifier())
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        out = await service.login("oper", PW, client="203.0.113.9")
        assert out.ok and out.token is not None
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 1
    finally:
        await store.close()


async def test_a_wrong_password_from_a_new_address_writes_no_signal_row() -> None:
    """The signal runs only after the credential verified, so a failed guess cannot feed it."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        assert not (await service.login("oper", "wrong-" + PW, client="203.0.113.9")).ok
        assert await store.list_audit(actor="oper", action="auth.login_new_ip") == []
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()


# --- the directory leg (Kerberos and OIDC share _complete_ad_login) ---------------------------


class _FakeLdap:
    def authenticate(self, username: str, password: str, **_: object) -> AdPrincipal | None:
        return None

    def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
        return None


def _principal(username: str) -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name=f"{username} Example",
        email=f"{username}@example.org",
        dn=f"CN={username},DC=x",
        groups=frozenset({"cn=mf-ops,dc=x"}),
        directory_object_id="12345678-1234-1234-1234-56789abcdef0",
    )


async def test_the_directory_leg_audits_and_notifies_a_first_seen_address() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        settings = AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
        service = AuthService(
            store,
            settings,
            ldap=_FakeLdap(),  # type: ignore[arg-type]
            security_notifier=notifier,
        )
        await service.initialize()
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")
        first = await service._complete_ad_login(
            _principal("jsmith"), "10.2.2.2", mfa_verified=True
        )
        assert first.ok
        unevaluated = await store.list_audit(
            actor="jsmith", action="auth.login_address_unevaluated"
        )
        assert len(unevaluated) == 1
        known = await service._complete_ad_login(
            _principal("jsmith"), "10.2.2.2", mfa_verified=True
        )
        assert known.ok
        assert _new_ip_notices(notifier) == []
        new = await service._complete_ad_login(
            _principal("jsmith"), "198.51.100.44", mfa_verified=True
        )
        assert new.ok
        rows = await store.list_audit(actor="jsmith", action="auth.login_new_ip")
        # vault BACKLOG #2156: the row names the mechanism, since ``provider`` is ``ad`` for OIDC too.
        assert len(rows) == 1
        assert json.loads(str(rows[0]["detail"])) == {"provider": "ad", "mech": "kerberos"}
        assert [e.client_ip for e in _new_ip_notices(notifier)] == ["198.51.100.44"]
        assert _new_ip_notices(notifier)[0].detail == {"provider": "ad", "mech": "kerberos"}
        # Every directory login is already born unseeded; the signal does not change that.
        assert not await _seeded(store, new.token)
    finally:
        await store.close()


class _ResolvingLdap(_FakeLdap):
    """Resolves the ticket's principal, as the Windows-SSO leg needs."""

    def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
        return _principal(username)

    def probe_principal(self, username: str, **_: object) -> DirectoryProbe:
        """``verify_mfa`` asks the directory to vouch for a directory account (BACKLOG #2023)."""
        return DirectoryProbe(DirectoryAnswer.FOUND, _principal(username))


async def test_the_windows_sso_entry_point_records_the_kerberos_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The test above calls ``_complete_ad_login`` directly and so takes its Kerberos default. This
    one goes through ``authenticate_kerberos``, so the mechanism comes from the Kerberos caller."""
    monkeypatch.setattr(service_module, "kerberos_principal", lambda token, settings: "jsmith")
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        # require_mfa off: a Kerberos session asserts no factor, so under the default it would owe
        # one, and a sign-in that owes a factor seeds no baseline (vault BACKLOG #2145).
        settings = AuthSettings(
            require_mfa=False,
            ad_enabled=True,
            kerberos_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
        service = AuthService(
            store,
            settings,
            ldap=_ResolvingLdap(),  # type: ignore[arg-type]
            security_notifier=notifier,
        )
        await service.initialize()
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")
        assert (await service.authenticate_kerberos(b"ticket", client="10.2.2.2")).ok
        [unevaluated] = await store.list_audit(
            actor="jsmith", action="auth.login_address_unevaluated"
        )
        assert json.loads(str(unevaluated["detail"])) == {
            "provider": "ad",
            "mech": "kerberos",
            "reason": "no_baseline",
        }
        assert (await service.authenticate_kerberos(b"ticket", client="198.51.100.47")).ok
        [row] = await store.list_audit(actor="jsmith", action="auth.login_new_ip")
        assert json.loads(str(row["detail"])) == {"provider": "ad", "mech": "kerberos"}
        [notice] = _new_ip_notices(notifier)
        assert notice.detail == {"provider": "ad", "mech": "kerberos"}
    finally:
        await store.close()


async def test_kerberos_under_the_default_require_mfa_builds_its_baseline_at_the_factor_leg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default path, which the test above steps around. Under the shipped ``require_mfa`` every
    Kerberos session owes a factor, so no Kerberos SIGN-IN writes the record. The factor legs do:
    the first sign-in finishes at enrolment, and each later one at ``verify_mfa``. Every sign-in
    is unjudged until one finishes: a sign-in abandoned at the factor prompt leaves no baseline.
    After the first one finishes, a sign-in from the same host is KNOWN and one from another host
    is NEW. Each is classified before its own ``verify_mfa`` runs."""
    monkeypatch.setattr(service_module, "kerberos_principal", lambda token, settings: "jsmith")
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        settings = AuthSettings(
            ad_enabled=True,
            kerberos_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
            mfa_verify_min_elapsed_seconds=0,
            mfa_recovery_code_count=1,
        )
        assert settings.require_mfa, "this test is about the shipped default"
        service = AuthService(
            store,
            settings,
            ldap=_ResolvingLdap(),  # type: ignore[arg-type]
            security_notifier=notifier,
        )
        await service.initialize()
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")

        def _reasons() -> Any:
            return store.list_audit(actor="jsmith", action="auth.login_address_unevaluated")

        async def _new_ip_rows() -> list[str]:
            rows = await store.list_audit(actor="jsmith", action="auth.login_new_ip")
            return [str(r["client"]) for r in reversed(rows)]

        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        first = await service.authenticate_kerberos(b"ticket", client="10.2.2.2")
        assert first.ok and first.mfa_required
        assert first.identity is not None and first.token is not None
        uid = first.identity.user_id
        # The sign-in that owes a factor wrote nothing.
        assert await store.list_known_login_addresses(uid, since=0.0) == []
        [unevaluated] = await _reasons()
        assert json.loads(str(unevaluated["detail"]))["reason"] == "no_baseline"
        # A second sign-in, abandoned at the factor prompt, is unjudged too: nothing finished yet.
        abandoned = await service.authenticate_kerberos(b"ticket", client="203.0.113.61")
        assert abandoned.ok and abandoned.mfa_required
        assert len(await _reasons()) == 2
        secret = await _enrol_totp(service, first.identity, first.token, client="10.2.2.2", now=t0)
        assert await store.list_known_login_addresses(uid, since=0.0) == ["10.2.2.2"]

        for step, client in enumerate(("10.2.2.2", "198.51.100.48"), start=1):
            out = await service.authenticate_kerberos(b"ticket", client=client)
            assert out.ok and out.mfa_required and out.token is not None
            t = t0 + step * totp.DEFAULT_PERIOD
            pin_totp_clock(monkeypatch, t)
            assert (await service.verify_mfa(out.token, totp.totp(secret, now=t), client=client)).ok

        # The first after enrolment was KNOWN and the next NEW; neither failed open.
        assert len(await _reasons()) == 2
        assert await _new_ip_rows() == ["198.51.100.48"]
        assert [e.client_ip for e in _new_ip_notices(notifier)] == ["198.51.100.48"]
        assert sorted(await store.list_known_login_addresses(uid, since=0.0)) == [
            "10.2.2.2",
            "198.51.100.48",
        ]
    finally:
        await store.close()


# --- the federated leg: a real OIDC mint through the callback seam (vault BACKLOG #2156) --------


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    """Local: a fixture resolves by name in the module that requests it."""
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


async def _oidc_callback_from(
    service: AuthService,
    monkeypatch: pytest.MonkeyPatch,
    rsa_key: rsa.RSAPrivateKey,
    client: str,
) -> LoginOutcome:
    """One federated sign-in for the bound ``jdoe`` through the seam ``GET /ui/oidc/callback``
    calls: stage a flow from ``client``, then redeem it from the same address. The id_token
    carries the nonce the start leg minted, read back from the authorization URL."""
    flow_id, url = await service.begin_oidc_login(
        client=client, public_origin="https://ops.example"
    )
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    _stub_exchange(monkeypatch, _mint(rsa_key, _claims(nonce=query["nonce"])))
    return await service.complete_oidc_login(
        flow_id=flow_id,
        state=query["state"],
        code=AUTH_CODE,
        client=client,
        public_origin="https://ops.example",
    )


async def test_an_oidc_mint_from_a_first_seen_address_records_the_oidc_mechanism(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through ``complete_oidc_login``, the seam the callback route calls, so the mechanism comes
    from the OIDC caller and not from ``_complete_ad_login``'s default, and the client address
    must reach the signal along the route's own path."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _oidc_service(store, rsa_key, notifier=notifier)
        first = await _oidc_callback_from(service, monkeypatch, rsa_key, "10.3.3.3")
        assert first.ok
        [unevaluated] = await store.list_audit(
            actor="jdoe", action="auth.login_address_unevaluated"
        )
        assert json.loads(str(unevaluated["detail"])) == {
            "provider": "ad",
            "mech": "oidc",
            "reason": "no_baseline",
        }
        new = await _oidc_callback_from(service, monkeypatch, rsa_key, "198.51.100.45")
        assert new.ok
        [row] = await store.list_audit(actor="jdoe", action="auth.login_new_ip")
        assert json.loads(str(row["detail"])) == {"provider": "ad", "mech": "oidc"}
        [notice] = _new_ip_notices(notifier)
        assert notice.client_ip == "198.51.100.45"
        assert notice.detail == {"provider": "ad", "mech": "oidc"}
    finally:
        await store.close()


async def test_a_binding_withdrawn_at_the_oidc_mint_leaves_no_new_address_row(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_record_login_address`` runs AFTER the mint, so a federated login the mint refuses -- an
    administrator withdrew the binding between the login's checks and its session insert -- leaves
    no row claiming a sign-in happened.

    The CONTROL is the last login: the same address, unwedged after a re-bind, does write the row.
    So the zero above it is the ordering, not an address that had stopped reading as new."""
    monkeypatch.setattr(service_module, "_sleep_until", _no_sleep)
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _oidc_service(store, rsa_key, notifier=notifier)
        assert (await _oidc_callback_from(service, monkeypatch, rsa_key, "10.3.3.3")).ok
        account = await store.get_user_by_username("jdoe")
        assert account is not None and account.oidc_subject is not None

        real_create = store.create_session
        fired = False

        async def unbinding_create_session(**kw: Any) -> bool:
            nonlocal fired
            if not fired:
                fired = True
                await service.unbind_federated_subject(
                    account.id,
                    expected_issuer=account.oidc_issuer,
                    expected_subject=account.oidc_subject,
                    actor="admin",
                )
            return await real_create(**kw)

        monkeypatch.setattr(store, "create_session", unbinding_create_session)
        raced = await _oidc_callback_from(service, monkeypatch, rsa_key, "198.51.100.46")
        monkeypatch.setattr(store, "create_session", real_create)

        assert fired, "the wedge never ran, so no unbind raced this login"
        assert not raced.ok and raced.reason == "federated_subject_unbound"
        assert await store.list_audit(actor="jdoe", action="auth.login_new_ip") == []
        assert _new_ip_notices(notifier) == []

        await _bind(service, store, DEFAULT_SUB)
        control = await _oidc_callback_from(service, monkeypatch, rsa_key, "198.51.100.46")
        assert control.ok
        assert len(await store.list_audit(actor="jdoe", action="auth.login_new_ip")) == 1
        assert [e.client_ip for e in _new_ip_notices(notifier)] == ["198.51.100.46"]
    finally:
        await store.close()


async def test_a_sign_in_that_still_owed_a_factor_marks_nothing_known() -> None:
    """Review finding, BACKLOG #288: a sign-in that stops at the MFA prompt has proved only the
    password. A holder of the password alone must not be able to plant an address as known that way,
    so the local leg writes the known-address record only once nothing more is owed (vault BACKLOG
    #2145). The factor leg writes it instead."""
    store = await MessageStore.open(":memory:")
    try:
        baseline = await _service(store)
        await _operator(baseline)
        assert (await baseline.login("oper", PW, client="10.1.1.1")).ok
        notifier = _FakeNotifier()
        # The floor is off: the enrolment below runs at once on the session it signed in, which the
        # login-to-MFA floor covers (BACKLOG #2389).
        owed = AuthService(
            store,
            AuthSettings(require_mfa=True, mfa_verify_min_elapsed_seconds=0),
            security_notifier=notifier,
        )
        await owed.initialize()
        first = await owed.login("oper", PW, client="203.0.113.5")
        assert first.ok and first.mfa_required
        second = await owed.login("oper", PW, client="203.0.113.5")
        assert second.ok and second.mfa_required
        # Both read as NEW: the first one, which stopped at the factor, did not make it known.
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 2
        # The audit row is written every time; the notice is debounced per account and address.
        assert len(_new_ip_notices(notifier)) == 1
        # vault BACKLOG #2145: nor does enrolling a factor from it. ADR 0197 Amendment A lets a
        # holder of the password alone enrol an authenticator they control, so an enrolment from a
        # NEW address proves nothing about the address and writes nothing.
        assert second.identity is not None and second.token is not None
        await _enrol_totp(owed, second.identity, second.token, client="203.0.113.5")
        assert (await owed.login("oper", PW, client="203.0.113.5")).ok
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 3
    finally:
        await store.close()


async def test_a_failed_record_read_fails_open(monkeypatch: pytest.MonkeyPatch) -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok

        async def _broken(*_a: object, **_kw: object) -> list[str]:
            raise RuntimeError("synthetic store fault")

        real = store.list_known_login_addresses
        monkeypatch.setattr(store, "list_known_login_addresses", _broken)
        out = await service.login("oper", PW, client="203.0.113.9")
        monkeypatch.setattr(store, "list_known_login_addresses", real)
        assert out.ok and await _seeded(store, out.token)
        rows = await store.list_audit(actor="oper", action="auth.login_address_unevaluated")
        assert any('"reason": "read_failed"' in str(r["detail"]) for r in rows)
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()


async def test_a_second_new_address_inside_the_debounce_window_is_still_notified() -> None:
    """The debounce is per (account, address): a second, different first-seen address must not
    hide behind the first one's notice."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        owed = AuthService(store, AuthSettings(require_mfa=True), security_notifier=notifier)
        await owed.initialize()
        uid = await _operator(owed)
        # A known address that is neither of the two below, so both read as NEW.
        await store.remember_login_address(uid, "10.1.1.1", now=time.time())
        assert (await owed.login("oper", PW, client="203.0.113.5")).ok
        assert (await owed.login("oper", PW, client="203.0.113.6")).ok
        assert [e.client_ip for e in _new_ip_notices(notifier)] == ["203.0.113.5", "203.0.113.6"]
    finally:
        await store.close()


async def test_an_ipv4_mapped_form_matches_its_known_ipv4_address() -> None:
    """A bind change between 0.0.0.0 and :: renders one client both ways; it is one host."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        out = await service.login("oper", PW, client="::ffff:10.1.1.1")
        assert out.ok and await _seeded(store, out.token)
        assert _new_ip_notices(notifier) == []
    finally:
        await store.close()


# --- the known-address record (vault BACKLOG #2145): one test per gap the audit baseline left ---


async def test_a_directory_sign_in_that_still_owes_a_factor_marks_nothing_known() -> None:
    """Gap 1, and the #2156 review's R1-1. A directory ``auth.login_success`` row carries no
    ``mfa_required`` marker, so the audit baseline counted a directory sign-in that stopped short of
    its factor. The record is written only once nothing more is owed."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        settings = AuthSettings(
            require_mfa=True,
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
        service = AuthService(
            store,
            settings,
            ldap=_FakeLdap(),  # type: ignore[arg-type]
            security_notifier=notifier,
        )
        await service.initialize()
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")
        # A sign-in that owes nothing (the factor was asserted) seeds the baseline.
        assert (
            await service._complete_ad_login(_principal("jsmith"), "10.2.2.2", mfa_verified=True)
        ).ok
        for _ in range(2):
            owed = await service._complete_ad_login(
                _principal("jsmith"), "198.51.100.50", mfa_verified=False
            )
            assert owed.ok and owed.mfa_required
        # Both read as NEW: the first one, which still owed its factor, did not make it known.
        assert len(await store.list_audit(actor="jsmith", action="auth.login_new_ip")) == 2
        account = await store.get_user_by_username("jsmith")
        assert account is not None
        assert await store.list_known_login_addresses(account.id, since=0.0) == ["10.2.2.2"]
    finally:
        await store.close()


async def test_a_second_factor_proved_from_a_new_address_makes_it_known(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The factor leg writes the record: ``verify_mfa`` from a first-seen address makes it known, so
    the next sign-in from it is not reported again."""
    store = await MessageStore.open(":memory:")
    try:
        owed = AuthService(
            store,
            AuthSettings(
                require_mfa=True, mfa_verify_min_elapsed_seconds=0, mfa_recovery_code_count=1
            ),
            security_notifier=_FakeNotifier(),
        )
        await owed.initialize()
        await _operator(owed)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        first = await owed.login("oper", PW, client="10.1.1.1")
        assert first.ok and first.identity is not None and first.token is not None
        secret = await _enrol_totp(owed, first.identity, first.token, client="10.1.1.1", now=t0)
        new = await owed.login("oper", PW, client="203.0.113.8")
        assert new.ok and new.mfa_required and new.token is not None
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 1
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        assert (
            await owed.verify_mfa(new.token, totp.totp(secret, now=t1), client="203.0.113.8")
        ).ok
        assert (await owed.login("oper", PW, client="203.0.113.8")).ok
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 1
    finally:
        await store.close()


async def test_the_record_is_keyed_on_the_account_not_the_username() -> None:
    """Gap 4. The audit actor is a username, so the old read had to bound a re-created namesake by
    ``created_at``. The record is keyed on the account id and deleted with the account."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, _FakeNotifier())
        first = await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        assert await store.list_known_login_addresses(first, since=0.0) == ["10.1.1.1"]
        await service.delete_user(first, actor="t")
        assert await store.list_known_login_addresses(first, since=0.0) == []
        await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        reasons = [
            json.loads(str(r["detail"]))["reason"]
            for r in await store.list_audit(actor="oper", action="auth.login_address_unevaluated")
        ]
        # Both accounts' first sign-ins fail open; the namesake inherits no baseline.
        assert reasons == ["no_baseline", "no_baseline"]
    finally:
        await store.close()


async def test_the_signal_never_reads_the_audit_log(monkeypatch: pytest.MonkeyPatch) -> None:
    """Gap 5. The baseline read is one primary-key lookup on the record; ``audit_log``, which has
    no actor index, is not read at all. A ``list_audit`` that raises cannot change the verdict."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = await _service(store, notifier)
        await _operator(service)

        async def _refused(*_a: object, **_kw: object) -> list[object]:
            raise AssertionError("the first-seen signal read audit_log")

        monkeypatch.setattr(store, "list_audit", _refused)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        known = await service.login("oper", PW, client="10.1.1.1")
        new = await service.login("oper", PW, client="203.0.113.9")
        monkeypatch.undo()
        assert known.ok and await _seeded(store, known.token)
        assert new.ok and not await _seeded(store, new.token)
        assert [e.client_ip for e in _new_ip_notices(notifier)] == ["203.0.113.9"]
    finally:
        await store.close()


async def test_an_address_too_long_to_key_is_never_remembered() -> None:
    """A client string longer than the record's key column is not written, so it reads as NEW at
    every sign-in rather than failing the write."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, _FakeNotifier())
        uid = await _operator(service)
        client = "h" * (service_module._LOGIN_ADDRESS_KEY_MAX + 1)
        assert (await service.login("oper", PW, client=client)).ok
        again = await service.login("oper", PW, client=client)
        assert again.ok and not await _seeded(store, again.token)
        assert await store.list_known_login_addresses(uid, since=0.0) == []
    finally:
        await store.close()


async def test_a_directory_sign_in_that_owes_nothing_records_even_a_new_address() -> None:
    """No directory session is seeded, so a NEW verdict there challenges nothing. Holding the
    write back would only repeat the notice at every sign-in from an address its owner uses."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        settings = AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
        service = AuthService(
            store,
            settings,
            ldap=_FakeLdap(),  # type: ignore[arg-type]
            security_notifier=notifier,
        )
        await service.initialize()
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")
        for client in ("10.2.2.2", "198.51.100.60", "198.51.100.60"):
            out = await service._complete_ad_login(_principal("jsmith"), client, mfa_verified=True)
            assert out.ok and not out.mfa_required
        assert len(await store.list_audit(actor="jsmith", action="auth.login_new_ip")) == 1
    finally:
        await store.close()


async def test_a_combined_sign_in_from_a_new_address_records_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A combined sign-in proved its TOTP code in the same request, as ``verify_mfa`` would have,
    so its address is recorded even when the verdict was NEW."""
    store = await MessageStore.open(":memory:")
    try:
        owed = AuthService(
            store,
            AuthSettings(
                require_mfa=True, mfa_verify_min_elapsed_seconds=0, mfa_recovery_code_count=1
            ),
            security_notifier=_FakeNotifier(),
        )
        await owed.initialize()
        uid = await _operator(owed)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        first = await owed.login("oper", PW, client="10.1.1.1")
        assert first.ok and first.identity is not None and first.token is not None
        secret = await _enrol_totp(owed, first.identity, first.token, client="10.1.1.1", now=t0)
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        combined = await owed.login(
            "oper", PW, client="203.0.113.21", totp_code=totp.totp(secret, now=t1)
        )
        assert combined.ok and not combined.mfa_required
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 1
        assert sorted(await store.list_known_login_addresses(uid, since=0.0)) == [
            "10.1.1.1",
            "203.0.113.21",
        ]
    finally:
        await store.close()


async def test_an_enrolment_baseline_outlives_the_lookback(monkeypatch: pytest.MonkeyPatch) -> None:
    """A first sign-in finished through enrolment writes a row but never stamps ``last_login_at``.
    Once that row ages out of the lookback the account still HAS a baseline, so its next sign-in from
    another address is judged NEW, not failed open as a first sign-in."""
    store = await MessageStore.open(":memory:")
    try:
        # The floor is off: the enrolment below runs at once on the session it signed in, which the
        # login-to-MFA floor covers (BACKLOG #2389).
        owed = AuthService(
            store,
            AuthSettings(
                require_mfa=True, mfa_verify_min_elapsed_seconds=0, mfa_recovery_code_count=1
            ),
            security_notifier=_FakeNotifier(),
        )
        await owed.initialize()
        await _operator(owed)
        first = await owed.login("oper", PW, client="10.1.1.1")
        assert first.ok and first.identity is not None and first.token is not None
        await _enrol_totp(owed, first.identity, first.token, client="10.1.1.1")
        monkeypatch.setattr(service_module, "_LOGIN_ADDRESS_LOOKBACK_SECONDS", -3600)
        assert (await owed.login("oper", PW, client="203.0.113.30")).ok
        assert len(await store.list_audit(actor="oper", action="auth.login_new_ip")) == 1
    finally:
        await store.close()


async def test_a_failed_read_in_the_step_up_gate_does_not_break_the_step_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The step-up asks whether the account owes a factor before it records the address. A store
    fault in that read is the record's to swallow: the step-up itself still succeeds."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, _FakeNotifier())
        uid = await _operator(service)
        assert (await service.login("oper", PW, client="10.1.1.1")).ok
        out = await service.login("oper", PW, client="198.51.100.70")
        assert out.ok and out.identity is not None and out.token is not None

        calls = 0

        async def _broken(user: object) -> bool:
            nonlocal calls
            calls += 1
            raise RuntimeError("synthetic store fault")

        monkeypatch.setattr(service, "_unverified_session_owes_factor", _broken)
        stepped = await service.reauth(out.identity, PW, token=out.token, client="198.51.100.70")
        assert stepped.ok
        assert calls == 1
        assert await store.list_known_login_addresses(uid, since=0.0) == ["10.1.1.1"]
    finally:
        await store.close()


async def test_a_password_step_up_on_an_account_that_owes_a_factor_records_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session whose factor was proved at one address, then used from another, steps up there with
    the password alone. That proves no factor from the new address, so it must not plant it: the
    account owes a factor, and only a factor leg records its addresses."""
    store = await MessageStore.open(":memory:")
    try:
        owed = AuthService(
            store,
            AuthSettings(
                require_mfa=True, mfa_verify_min_elapsed_seconds=0, mfa_recovery_code_count=1
            ),
            security_notifier=_FakeNotifier(),
        )
        await owed.initialize()
        uid = await _operator(owed)
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        first = await owed.login("oper", PW, client="10.1.1.1")
        assert first.ok and first.identity is not None and first.token is not None
        secret = await _enrol_totp(owed, first.identity, first.token, client="10.1.1.1", now=t0)
        signed = await owed.login("oper", PW, client="10.1.1.1")
        assert signed.ok and signed.token is not None and signed.identity is not None
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        verified = await owed.verify_mfa(signed.token, totp.totp(secret, now=t1), client="10.1.1.1")
        assert verified.ok and verified.token is not None
        stepped = await owed.reauth(
            signed.identity, PW, token=verified.token, client="203.0.113.40"
        )
        assert stepped.ok
        assert await store.list_known_login_addresses(uid, since=0.0) == ["10.1.1.1"]
    finally:
        await store.close()


async def test_a_step_up_from_a_roamed_address_records_it_and_moves_the_anchor() -> None:
    """A session minted at one address and used from another steps up there. On an account that
    owes no factor the password is the whole credential, so the step-up proves as much from the new
    address as a sign-in from it would: the address joins the record. ``reauth`` also re-anchors the
    session, so after a password step-up the two address signals agree. A passkey assertion does
    not re-anchor, and tests/test_webauthn.py pins that leg."""
    store = await MessageStore.open(":memory:")
    try:
        service = await _service(store, _FakeNotifier())
        uid = await _operator(service)
        out = await service.login("oper", PW, client="10.1.1.1")
        assert out.ok and out.identity is not None and out.token is not None
        # The mid-session signal reports the roamed address before the step-up.
        assert await service.flag_new_client_ip(out.token, "198.51.100.80", path="/ui/x")

        stepped = await service.reauth(out.identity, PW, token=out.token, client="198.51.100.80")

        assert stepped.ok and stepped.token is not None
        assert sorted(await store.list_known_login_addresses(uid, since=0.0)) == [
            "10.1.1.1",
            "198.51.100.80",
        ]
        assert not await service.flag_new_client_ip(stepped.token, "198.51.100.80", path="/ui/x")
        again = await service.login("oper", PW, client="198.51.100.80")
        assert again.ok and await _seeded(store, again.token)
        assert await store.list_audit(actor="oper", action="auth.login_new_ip") == []
        # KNOWN, not failed open: only the first sign-in ever wrote an unevaluated row.
        unevaluated = await store.list_audit(actor="oper", action="auth.login_address_unevaluated")
        assert len(unevaluated) == 1
    finally:
        await store.close()
