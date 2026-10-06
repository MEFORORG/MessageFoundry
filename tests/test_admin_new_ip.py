# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Admin-interface defense-in-depth: the new-client-IP contextual-risk signal (WP-L3-13, ASVS 8.4.2).

When ``[auth].admin_new_ip_step_up`` is on, a step-up (sensitive admin) request arriving from a client
address the session has not verified from is treated as higher-risk: it audits + notifies and FORCES a
fresh step-up, which a successful ``POST /me/reauth`` from that address clears (re-anchoring the
session). It is step-up-forcing only — it never changes an RBAC decision. Since vault BACKLOG #2620
the PHI reads and the paced writes refuse on it too; the base gate, which the monitoring polls ride,
never asks. It defaults ON since BACKLOG #288; turning it off, and a single-host loopback deployment,
are no-ops (the request and the session share one address).
"""

from __future__ import annotations

import ast
import inspect
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _totp_clock import pin_totp_clock

from messagefoundry.api import create_app
from messagefoundry.auth import Role, totp
from messagefoundry.auth.identity import ALL_CHANNELS, Identity
from messagefoundry.auth.notifications import ADMIN_NEW_IP, SecurityEvent
from messagefoundry.auth.service import _NEW_IP_PER_SESSION_MAX, AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_admin, create_local_user_chosen

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)
NEW_USER = {
    "username": "newbie",
    "roles": ["viewer"],
    "email": "newbie@example.org",
}


class _FakeNotifier:
    """Captures the out-of-band security events instead of emailing them."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _enabled_admin(service: AuthService, *, client: str) -> tuple[str, Identity]:
    """Create an enabled admin (no forced first-login rotation) + a live session from ``client``."""
    uid = await create_local_user_chosen(
        service,
        username="boss",
        password=PW,
        display_name=None,
        email="boss@example.test",
        roles=[Role.ADMINISTRATOR.value],
        actor="t",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    out = await service.login("boss", PW, client=client)
    assert out.ok and out.token is not None and out.identity is not None
    return out.token, out.identity


# --- service / store unit ----------------------------------------------------
def test_on_by_default() -> None:
    """BACKLOG #288 (owner ruling 2026-09-26): the signal ships ON; off is a named loosening."""
    assert AuthSettings().admin_new_ip_step_up is True


async def test_explicitly_disabled_is_a_noop() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=False), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        notifier.events.clear()  # setup's ACCOUNT_CREATED notice (BACKLOG #315), not under test
        # Even a wildly different address is a no-op while the feature is off.
        assert await service.flag_new_client_ip(token, "10.9.9.9", path="/users") is False
        assert notifier.events == []
    finally:
        await store.close()


async def test_new_ip_flags_audits_and_notifies() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        notifier.events.clear()  # setup's ACCOUNT_CREATED notice (BACKLOG #315), not under test
        # Same address → not new; no side effects.
        assert await service.flag_new_client_ip(token, "10.1.1.1", path="/users") is False
        assert notifier.events == []
        # A different address → flagged, audited, and notified.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert any(
            e.event_type == ADMIN_NEW_IP and e.client_ip == "10.2.2.2" for e in notifier.events
        )
        rows = await store.list_audit(limit=20)
        assert any(r["action"] == "auth.admin_action_new_ip" for r in rows)
    finally:
        await store.close()


async def test_missing_baseline_and_bad_tokens_not_flagged() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        uid = await create_local_user_chosen(
            service,
            username="x",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.VIEWER.value],
            actor="t",
        )
        # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
        # fixture still stands for an operator who has been provisioned; the channel axis itself
        # is exercised in tests/test_channel_rbac.py.
        await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
        # A session with no recorded login address is never penalized (avoids spurious friction).
        await store.create_session(
            token_hash=hash_token("noip"), user_id=uid, expires_at=2e12, client=None
        )
        assert await service.flag_new_client_ip("noip", "10.2.2.2", path="/x") is False
        # Missing / unknown tokens are never flagged.
        assert await service.flag_new_client_ip(None, "10.2.2.2", path="/x") is False
        assert await service.flag_new_client_ip("nope", "10.2.2.2", path="/x") is False
    finally:
        await store.close()


async def test_reauth_reanchors_session_to_the_new_ip() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Re-verifying from the new address re-anchors the session, clearing the signal. The
        # re-auth also re-keys the session (ASVS 7.2.4), and `_rekey_token_state` carries the
        # new-IP dedupe across — so the follow-up checks run on the ROTATED token.
        reauthed = await service.reauth(identity, PW, token=token, client="10.2.2.2")
        assert reauthed.ok is True and reauthed.token is not None
        token = reauthed.token
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is False
        # The original address is now the unexpected one.
        assert await service.flag_new_client_ip(token, "10.1.1.1", path="/users") is True
    finally:
        await store.close()


async def test_repeat_from_same_new_ip_is_deduped() -> None:
    """The step-up is forced on every hit, but the audit row + out-of-band notice fire only once per
    (session, new-IP) — a replayed token can't inflate the audit log / notifications. A genuinely
    different address re-emits."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        # First hit from a new address → flagged, audited, notified.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Repeat from the SAME address → still forces step-up, but no new audit row / notice.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        actions = [r["action"] for r in await store.list_audit(limit=50)]
        assert actions.count("auth.admin_action_new_ip") == 1
        assert sum(1 for e in notifier.events if e.event_type == ADMIN_NEW_IP) == 1
        # A DIFFERENT new address is a distinct event → re-emits.
        assert await service.flag_new_client_ip(token, "10.3.3.3", path="/users") is True
        actions = [r["action"] for r in await store.list_audit(limit=50)]
        assert actions.count("auth.admin_action_new_ip") == 2
        assert sum(1 for e in notifier.events if e.event_type == ADMIN_NEW_IP) == 2
    finally:
        await store.close()


async def _new_ip_rows(store: MessageStore) -> list[str]:
    """The ``seen_ip`` of every ``auth.admin_action_new_ip`` row, oldest first."""
    rows = await store.list_audit(action="auth.admin_action_new_ip", limit=100)
    return [json.loads(str(r["detail"]))["seen_ip"] for r in reversed(rows)]


async def test_alternating_new_addresses_audit_once_each() -> None:
    """BACKLOG #2159: the dedupe holds a SET per session, not the last address. Alternating between
    two new addresses used to write a row and a notice on every switch."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        for seen in ("10.2.2.2", "10.3.3.3", "10.2.2.2", "10.3.3.3", "10.2.2.2"):
            assert await service.flag_new_client_ip(token, seen, path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2", "10.3.3.3"]
        assert sum(1 for e in notifier.events if e.event_type == ADMIN_NEW_IP) == 2
    finally:
        await store.close()


async def test_a_reanchor_starts_the_dedupe_over() -> None:
    """BACKLOG #2159: after a re-verification moves the anchor, an address flagged before it is a new
    event again. It used to stay suppressed, so the forced step-up left no audit row."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Re-verify from a THIRD address: the session is now anchored there.
        reauthed = await service.reauth(identity, PW, token=token, client="10.3.3.3")
        assert reauthed.ok is True and reauthed.token is not None
        token = reauthed.token
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2", "10.2.2.2"]
    finally:
        await store.close()


async def test_a_reanchor_back_to_the_same_address_still_starts_over() -> None:
    """The anchor includes ``reauth_at``, not the address alone. Anchored at A, flag B, re-verify from
    B, then from A again: the anchor ADDRESS is A both times, but B was re-verified in between, so a
    later request from B is a new event and writes a row."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        for client in ("10.2.2.2", "10.1.1.1"):
            reauthed = await service.reauth(identity, PW, token=token, client=client)
            assert reauthed.ok is True and reauthed.token is not None
            token = reauthed.token
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2", "10.2.2.2"]
    finally:
        await store.close()


async def test_ipv4_mapped_ipv6_is_the_same_host() -> None:
    """BACKLOG #2159: ``_same_host`` folds ``::ffff:a.b.c.d`` to ``a.b.c.d``, as the sign-in signal
    already did. A bind change between ``0.0.0.0`` and ``::`` must not trip the signal, and one new
    host seen in both forms is one audit row."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.0.0.5")
        assert await service.flag_new_client_ip(token, "::ffff:10.0.0.5", path="/users") is False
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert await service.flag_new_client_ip(token, "::ffff:10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2"]
    finally:
        await store.close()


def test_same_host_folds_mapped_loopback_and_case() -> None:
    assert AuthService._same_host("::ffff:10.0.0.5", "10.0.0.5")
    assert AuthService._same_host("::ffff:127.0.0.1", "::1")
    assert AuthService._same_host("2001:DB8::1", "2001:db8::1")
    assert AuthService._same_host("not-an-address", "not-an-address")
    assert not AuthService._same_host("10.0.0.5", "10.0.0.6")
    assert not AuthService._same_host("::ffff:10.0.0.5", "::ffff:10.0.0.6")
    assert not AuthService._same_host("not-an-address", "::1")


async def test_one_epoch_audits_at_most_the_per_session_cap() -> None:
    """The signal runs on every sensitive request, so one session audits at most
    ``_NEW_IP_PER_SESSION_MAX`` addresses between re-verifications, plus ONE row carrying
    ``cap_reached`` that names the first address past the cap. After that the step-up is still
    forced; only the row and the notice are held back. A re-verification gives the cap back."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        addresses = [f"10.9.0.{n}" for n in range(1, _NEW_IP_PER_SESSION_MAX + 3)]
        for _ in range(2):
            for seen in addresses:
                assert await service.flag_new_client_ip(token, seen, path="/users") is True
        reported = addresses[: _NEW_IP_PER_SESSION_MAX + 1]
        assert await _new_ip_rows(store) == reported
        assert sum(1 for e in notifier.events if e.event_type == ADMIN_NEW_IP) == len(reported)
        details = [
            json.loads(str(r["detail"]))
            for r in await store.list_audit(action="auth.admin_action_new_ip", limit=100)
        ]
        capped = [d for d in details if "cap_reached" in d]
        assert [d["seen_ip"] for d in capped] == [addresses[_NEW_IP_PER_SESSION_MAX]]
        assert capped[0]["cap_reached"] == _NEW_IP_PER_SESSION_MAX
        # The holder's notice for that address says so too; the eight before it do not.
        sent = [e for e in notifier.events if e.event_type == ADMIN_NEW_IP]
        assert [e.client_ip for e in sent if e.detail.get("cap_reached")] == [
            addresses[_NEW_IP_PER_SESSION_MAX]
        ]
        # Re-verifying from the anchor opens a new epoch with a fresh cap.
        reauthed = await service.reauth(identity, PW, token=token, client="10.1.1.1")
        assert reauthed.ok is True and reauthed.token is not None
        assert await service.flag_new_client_ip(reauthed.token, addresses[-1], path="/users")
        assert await _new_ip_rows(store) == [*reported, addresses[-1]]
    finally:
        await store.close()


def test_every_reanchor_restarts_the_dedupe() -> None:
    """Each function that re-anchors a session (``mark_session_reauthed``) also restarts the
    new-address dedupe. A new re-verification leg that forgot would leave addresses reported
    before it suppressed after it, which is the gap BACKLOG #2159 closed."""
    source = Path(inspect.getfile(AuthService)).read_text(encoding="utf-8")
    tree = ast.parse(source)
    anchoring: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            called = {
                n.func.attr
                for n in ast.walk(node)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            }
            if "mark_session_reauthed" in called:
                anchoring[node.name] = called
    assert len(anchoring) >= 3, sorted(anchoring)  # control: the probe finds the known legs
    missing = sorted(
        name for name, called in anchoring.items() if "_restart_new_ip_dedupe" not in called
    )
    assert missing == [], missing


def test_the_per_session_cap_is_the_value_security_md_states() -> None:
    """SECURITY.md item 6 gives the cap as a number an operator can read. Move both together."""
    assert _NEW_IP_PER_SESSION_MAX == 8
    text = (Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md").read_text("utf-8")
    assert "at most **eight** addresses (`_NEW_IP_PER_SESSION_MAX`" in " ".join(text.split())


async def test_a_rotation_without_a_reverification_keeps_the_dedupe() -> None:
    """A rotation that proves nothing (a passkey assertion, an enrolment confirm) leaves
    ``reauth_at`` alone, so the epoch and its flags carry across to the new token."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        rotated = await service._rotate_session_token(token)
        assert rotated is not None
        assert await service.flag_new_client_ip(rotated, "10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2"]
    finally:
        await store.close()


async def test_a_failed_audit_write_does_not_mark_the_address_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the row is not written, the next request from that address must try again rather than
    be suppressed for the rest of the epoch."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        real_audit = service._audit

        async def failing_audit(*args: object, **kwargs: object) -> None:
            raise RuntimeError("transient store fault")

        monkeypatch.setattr(service, "_audit", failing_audit)
        with pytest.raises(RuntimeError):
            await service.flag_new_client_ip(token, "10.2.2.2", path="/users")
        monkeypatch.setattr(service, "_audit", real_audit)
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2"]
    finally:
        await store.close()


async def test_a_reanchor_resets_without_reading_the_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reset rides the re-anchor call, not ``reauth_at``: a wall clock stepped BACK between two
    re-verifications must still start the dedupe over."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        real_time = time.time
        for client, skew in (("10.2.2.2", -100.0), ("10.1.1.1", -50.0)):
            monkeypatch.setattr(time, "time", lambda skew=skew: real_time() + skew)
            reauthed = await service.reauth(identity, PW, token=token, client=client)
            assert reauthed.ok is True and reauthed.token is not None
            token = reauthed.token
        monkeypatch.setattr(time, "time", real_time)
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2", "10.2.2.2"]
    finally:
        await store.close()


async def test_the_sign_in_notice_debounce_folds_ipv4_mapped() -> None:
    """The sign-in signal's notice debounce keys on the host, as its comparison does, so one host
    seen as ``::ffff:a.b.c.d`` and then ``a.b.c.d`` gets one notice per window, not two."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        assert service._login_new_ip_notice_due("u1", "::ffff:10.9.9.9") is True
        assert service._login_new_ip_notice_due("u1", "10.9.9.9") is False
        assert service._login_new_ip_notice_due("u1", "10.9.9.8") is True
    finally:
        await store.close()


async def test_loopback_addresses_treated_as_same_host() -> None:
    """A dual-stack loopback box (session anchored at ::1, a later request from 127.0.0.1) is one host
    — the feature stays a true no-op on loopback even when enabled. A real address is still new."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        uid = await create_local_user_chosen(
            service,
            username="x",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.ADMINISTRATOR.value],
            actor="t",
        )
        # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
        # fixture still stands for an operator who has been provisioned; the channel axis itself
        # is exercised in tests/test_channel_rbac.py.
        await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
        await store.create_session(
            token_hash=hash_token("lb"), user_id=uid, expires_at=2e12, client="::1"
        )
        assert await service.flag_new_client_ip("lb", "127.0.0.1", path="/users") is False
        assert await service.flag_new_client_ip("lb", "::1", path="/users") is False
        # A genuine non-loopback address is still flagged.
        assert await service.flag_new_client_ip("lb", "10.0.0.5", path="/users") is True
    finally:
        await store.close()


async def test_verify_mfa_reanchors_session_to_the_new_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Completing the second factor (TOTP) from a new address re-anchors the session, like reauth — so
    an MFA-required admin who roamed clears the new-IP signal with one credential proof, not two."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        admin = await create_admin(service)
        out = await service.login(admin.username, admin.password, client="10.1.1.1")
        assert out.ok and out.identity is not None and out.token is not None
        identity, token = out.identity, out.token
        enroll = await service.begin_mfa_enrollment(identity)
        # Pin the TOTP clock so the enrollment confirm and the later verify_mfa sit in distinct steps
        # (enrollment now consumes the activating step, BACKLOG #1021).
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        enrolled = await service.confirm_mfa_enrollment(
            identity, totp.totp(enroll.secret, now=t0), token=token, client="10.1.1.1"
        )
        assert enrolled.ok and enrolled.token is not None
        token = enrolled.token  # the confirm re-keyed the session (ASVS 7.2.4)
        # Roam to a new address → flagged.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Completing MFA from the new address re-anchors the session (parity with reauth), using a code
        # in a strictly later step than enrollment consumed.
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        code = totp.totp(enroll.secret, now=t1)
        verified = await service.verify_mfa(token, code, client="10.2.2.2")
        assert verified.ok is True and verified.token is not None
        token = verified.token
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is False
    finally:
        await store.close()


# --- API enforcement ---------------------------------------------------------
@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "newip.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


def _client_at(engine: Engine, service: AuthService, ip: str) -> httpx.AsyncClient:
    """An API client whose requests originate from ``ip`` (set on the ASGI scope)."""
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=(ip, 12345))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _add_admin(service: AuthService, username: str) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


async def _login_token(c: httpx.AsyncClient, username: str = "boss") -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def test_admin_route_from_new_ip_forces_step_up_then_clears(engine: Engine) -> None:
    # New-client-IP step-up test (admin route), not an MFA test: pin require_mfa=False so the admin's
    # step-up op isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0, admin_new_ip_step_up=True, require_mfa=False
        ),
    )
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        # From the SAME address the fresh login may act (network-location + step-up freshness hold).
        assert (await a.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201
    # Same token, a DIFFERENT client address → forced step-up.
    n2 = {"username": "n2", "roles": ["viewer"], "email": "n2@example.org"}
    async with _client_at(engine, service, "10.9.9.9") as b:
        blocked = await b.post("/users", headers=_auth(token), json=n2)
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"
        # A non-sensitive route from the new address is NOT blocked (advisory + admin-scope only).
        assert (await b.get("/auth/me", headers=_auth(token))).status_code == 200
        # Re-verifying from the new address re-anchors the session; the admin op then succeeds.
        ok = await b.post("/me/reauth", headers=_auth(token), json={"password": PW})
        assert ok.status_code == 200
        token = str(ok.json()["token"])  # the re-auth re-keyed the session (ASVS 7.2.4)
        assert (await b.post("/users", headers=_auth(token), json=n2)).status_code == 201


async def test_known_ip_with_feature_on_is_unobtrusive(engine: Engine) -> None:
    # New-client-IP step-up test (admin route), not an MFA test: pin require_mfa=False so the admin's
    # step-up op isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(engine.store, AuthSettings(admin_new_ip_step_up=True, require_mfa=False))
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        # Same address throughout → no extra friction beyond the normal login step-up freshness.
        assert (await a.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201


async def test_explicitly_disabled_new_ip_does_not_force_step_up(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings(admin_new_ip_step_up=False, require_mfa=False))
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
    async with _client_at(engine, service, "10.9.9.9") as b:
        # Feature off → the new address is irrelevant; the fresh login's step-up still holds → 201.
        assert (await b.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201


async def test_new_ip_never_overrides_rbac(engine: Engine) -> None:
    """A viewer lacking ``users:manage`` is denied for *permission* — RBAC runs before the step-up /
    IP logic, so the IP signal neither grants nor is even consulted (it never changes an authz
    decision)."""
    # New-client-IP step-up test (admin route), not an MFA test: pin require_mfa=False so the admin's
    # step-up op isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(engine.store, AuthSettings(admin_new_ip_step_up=True, require_mfa=False))
    await service.initialize()
    uid = await create_local_user_chosen(
        service,
        username="viewer1",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="t",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a, "viewer1")
    async with _client_at(engine, service, "10.9.9.9") as b:
        denied = await b.post("/users", headers=_auth(token), json=NEW_USER)
        assert denied.status_code == 403
        # Missing permission — NOT a step-up / MFA prompt.
        assert denied.headers.get("X-Step-Up-Required") is None
        assert denied.headers.get("X-MFA-Required") is None


# --- vault BACKLOG #2620: the PHI reads and the paced writes ask too ---------------------------


def _new_ip_service(engine: Engine, **over: object) -> AuthService:
    settings: dict[str, object] = {
        "admin_write_min_interval_seconds": 0,
        "admin_new_ip_step_up": True,
        "require_mfa": False,
    }
    settings.update(over)
    return AuthService(engine.store, AuthSettings(**settings))  # type: ignore[arg-type]


_ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
#: The paced write's body: resetting every counter touches no message.
_RESET_ALL: dict[str, object] = {"all": True}


async def _seed_message(engine: Engine) -> str:
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=_ADT,
        deliveries=[("archive", _ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
    )


def _replayed(mid: str) -> tuple[tuple[str, str, dict[str, object] | None], ...]:
    """The architecture review's probe, widened: the message list, a raw body, the dead-letter
    list, the log tail, and two paced writes. The connection name names no connection, so the
    control's 404 proves the gate let the request through to the handler."""
    return (
        ("GET", "/messages", None),
        ("GET", f"/messages/{mid}/raw", None),
        ("GET", "/dead-letters", None),
        ("GET", "/logs/tail", None),
        ("POST", "/connections/IB_NONE/start", None),
        ("POST", "/statistics/reset", _RESET_ALL),
    )


async def test_a_token_replayed_from_a_second_address_is_refused_on_phi_and_paced(
    engine: Engine,
) -> None:
    """RED when: a bearer token signed in at one address reads a message body, lists messages or
    calls a paced write from another with no step-up (vault BACKLOG #2620, the architecture
    review's probe). The same token from the sign-in address is the control: it is never refused
    with the step-up header. A base-gate route from the new address still answers, because the
    monitoring polls ride it."""
    service = _new_ip_service(engine)
    await service.initialize()
    await _add_admin(service, "boss")
    mid = await _seed_message(engine)
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        for method, path, body in _replayed(mid):
            r = await a.request(method, path, headers=_auth(token), json=body)
            assert r.headers.get("X-Step-Up-Required") is None, (method, path, r.status_code)
    async with _client_at(engine, service, "10.9.9.9") as b:
        for method, path, body in _replayed(mid):
            r = await b.request(method, path, headers=_auth(token), json=body)
            assert r.status_code == 403, (method, path, r.status_code)
            assert r.headers.get("X-Step-Up-Required") == "1", (method, path)
        assert (await b.get("/connections", headers=_auth(token))).status_code == 200
        # One row for the address, whichever gate saw it first (BACKLOG #2159's dedupe).
        assert isinstance(engine.store, MessageStore)
        assert await _new_ip_rows(engine.store) == ["10.9.9.9"]
        # A re-verification from the new address re-anchors the session, and the reads pass.
        ok = await b.post("/me/reauth", headers=_auth(token), json={"password": PW})
        assert ok.status_code == 200
        token = str(ok.json()["token"])
        assert (await b.get("/messages", headers=_auth(token))).status_code == 200
        raw = await b.get(f"/messages/{mid}/raw", headers=_auth(token))
        assert raw.status_code == 200 and raw.json()["raw"]


async def test_a_refusal_for_a_new_address_charges_no_budget(engine: Engine) -> None:
    """RED when: the new-address refusal runs after the PHI-read or admin-write charge, so a stolen
    token refused in a loop spends the holder's budget (vault BACKLOG #2620, the BACKLOG #1973
    rule). With a budget of one, the holder still reads and writes once after the refusals."""
    service = _new_ip_service(
        engine, phi_read_rate_limit_per_actor=1, admin_write_rate_limit_per_actor=1
    )
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
    async with _client_at(engine, service, "10.9.9.9") as b:
        for _ in range(3):
            assert (await b.get("/messages", headers=_auth(token))).status_code == 403
            assert (
                await b.post("/statistics/reset", headers=_auth(token), json=_RESET_ALL)
            ).status_code == 403
    async with _client_at(engine, service, "10.0.0.1") as a:
        assert (await a.get("/messages", headers=_auth(token))).status_code == 200
        assert (
            await a.post("/statistics/reset", headers=_auth(token), json=_RESET_ALL)
        ).status_code == 200


async def test_the_phi_and_paced_gates_ask_nothing_with_the_signal_off(engine: Engine) -> None:
    """The named loosening still turns the whole check off: ``admin_new_ip_step_up = false``."""
    service = _new_ip_service(engine, admin_new_ip_step_up=False)
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
    async with _client_at(engine, service, "10.9.9.9") as b:
        assert (await b.get("/messages", headers=_auth(token))).status_code == 200
        r = await b.post("/statistics/reset", headers=_auth(token), json=_RESET_ALL)
        assert r.status_code == 200
    assert isinstance(engine.store, MessageStore)
    assert await _new_ip_rows(engine.store) == []


async def test_an_http_reveal_from_a_second_address_is_refused(engine: Engine) -> None:
    """RED when: a ``reveal`` on a monitoring list route, a PHI read admitted by ``_admit_reveal``
    rather than ``require_phi_read``, answers a token replayed from a new address (vault BACKLOG
    #2620, review round 1). The same list without ``reveal`` still answers: it rides the base gate."""
    service = _new_ip_service(engine)
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        control = await a.get("/events", params={"reveal": 1}, headers=_auth(token))
        assert control.headers.get("X-Step-Up-Required") is None, control.status_code
    async with _client_at(engine, service, "10.9.9.9") as b:
        for path in ("/events", "/alerts/active"):
            r = await b.get(path, params={"reveal": 1}, headers=_auth(token))
            assert (r.status_code, r.headers.get("X-Step-Up-Required")) == (403, "1"), path
        assert (await b.get("/events", headers=_auth(token))).status_code == 200
