# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1020: a PHI instance must not start when its security notices reach nobody.

The serve gate in ``messagefoundry/__main__.py`` proves a TRANSPORT exists -- it computes readiness
from ``notify_security_events`` + ``email_smtp_host`` + ``email_from``. It never asks whether any
notice is DELIVERABLE, and on a first run the only account that exists is the bootstrap
administrator, created with no address. So the gate reports green while every notice about the
account holding ``frozenset(Permission)`` silently no-ops.

These drive the lifespan assertion directly rather than through ``create_managed_app``: the unit
under test is the predicate, and a full app spin-up would put a dozen unrelated failure modes
between the assertion and the assert.
"""

from __future__ import annotations

import pytest

from messagefoundry.api.app import _assert_security_notice_is_deliverable
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    AiSettings,
    AlertsSettings,
    AuthSettings,
    SecurityEnforcement,
    SecuritySettings,
)
from messagefoundry.store.store import MessageStore

_PHI = AiSettings(data_class="phi")
_ENFORCE = SecuritySettings(enforcement=SecurityEnforcement.ENFORCE)
_WARN = SecuritySettings(enforcement=SecurityEnforcement.WARN)


async def _store_with_admin(*, email: str | None, disabled: bool = False) -> MessageStore:
    """A store holding exactly one Administrator, with or without an address.

    Built through ``AuthService.initialize()`` rather than a raw ``create_user`` + ``set_user_roles``.
    Two reasons, the second learned the hard way:

    1. It mints the REAL first-run bootstrap administrator -- which is created with NO email, so the
       unaddressed case here is the genuine #1020 state rather than a synthetic row that resembles it.
    2. ``set_user_roles`` on a bare store raises ``FOREIGN KEY constraint failed``, because the roles
       table is seeded by ``initialize()`` and not by ``MessageStore.open()``. **That failure HANGS
       rather than reporting**: the exception escapes before ``store.close()``, aiosqlite's
       non-daemon connection-worker thread stays alive, and the process never exits -- so pytest
       produced zero output and no traceback until the call was driven outside the runner.
    """
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        boot = await service.initialize()
        assert boot is not None
        admin = await store.get_user_by_username("admin")
        assert admin is not None and admin.email is None  # the defect's own starting state
        if email is not None:
            await store.update_user_profile(admin.id, display_name=None, email=email)
        if disabled:
            await store.set_user_disabled(admin.id, disabled=True)
    except BaseException:
        # Never leave the store open on an error path -- see (2) above; an unclosed store turns a
        # legible failure into a silent hang.
        await store.close()
        raise
    return store


async def _call(
    store: MessageStore,
    *,
    security: SecuritySettings = _ENFORCE,
    ai: AiSettings = _PHI,
    auth: AuthSettings | None = None,
    alerts: AlertsSettings | None = None,
) -> None:
    await _assert_security_notice_is_deliverable(
        store,
        auth_settings=auth or AuthSettings(notify_security_events=True),
        alerts_settings=alerts or AlertsSettings(security_notifications_required=True),
        ai_settings=ai,
        security_settings=security,
    )


async def test_phi_enforce_refuses_when_no_admin_has_an_address() -> None:
    # The #1020 scenario exactly: first run, bootstrap administrator created with no email, SMTP
    # transport perfectly configured. The transport gate passes; nothing is deliverable.
    store = await _store_with_admin(email=None)
    try:
        with pytest.raises(RuntimeError) as exc:
            await _call(store)
        assert "refusing to start" in str(exc.value)
        assert "no enabled Administrator has an email address" in str(exc.value)
    finally:
        await store.close()


async def test_phi_enforce_starts_when_an_admin_is_reachable() -> None:
    # POSITIVE CONTROL. Without this, the refusal above is equally consistent with a predicate that
    # refuses unconditionally -- which would pass the test above and break every deployment.
    store = await _store_with_admin(email="ops@example.test")
    try:
        await _call(store)  # must not raise
    finally:
        await store.close()


async def test_a_DISABLED_admin_with_an_address_does_not_count() -> None:
    # A disabled account receives nothing, so counting it would be the same class of defect as
    # counting the transport: a check that looks at the wrong thing and reports green.
    store = await _store_with_admin(email="ops@example.test", disabled=True)
    try:
        with pytest.raises(RuntimeError):
            await _call(store)
    finally:
        await store.close()


async def test_a_NON_admin_with_an_address_does_not_count() -> None:
    # The item is about the account holding frozenset(Permission). An addressable operator does not
    # make an administrator's lockout notice deliverable.
    store = await _store_with_admin(email=None)
    try:
        service = AuthService(store, AuthSettings())
        viewer_id = await service.create_local_user(
            username="viewer",
            password="another-long-passphrase",
            display_name=None,
            email="viewer@example.test",
            roles=[Role.VIEWER.value],
            actor="test",
        )
        seeded = await store.get_user(viewer_id)
        # POSITIVE CONTROL on the fixture: the addressable non-admin really exists, so the refusal
        # below is about the ROLE and not about an empty table.
        assert seeded is not None and seeded.email == "viewer@example.test"
        with pytest.raises(RuntimeError):
            await _call(store)
    finally:
        await store.close()


async def test_warn_enforcement_does_not_refuse() -> None:
    # Parity with the transport gate's own shape: enforcement=warn downgrades a refusal to a log
    # line. Refusing under warn would be a stricter posture than the dial asks for.
    store = await _store_with_admin(email=None)
    try:
        await _call(store, security=_WARN)  # must not raise
    finally:
        await store.close()


@pytest.mark.parametrize(
    ("label", "kwargs"),
    [
        ("not a PHI instance", {"ai": AiSettings(data_class="synthetic")}),
        (
            "notices switched off",
            {"auth": AuthSettings(notify_security_events=False)},
        ),
        (
            "audited opt-out in writing",
            {"alerts": AlertsSettings(security_notifications_required=False)},
        ),
    ],
)
async def test_the_gate_is_silent_outside_its_three_preconditions(
    label: str, kwargs: dict[str, object]
) -> None:
    # Each precondition is a separate reason the question does not arise. Asserted individually
    # rather than as one combined case, because a single case cannot tell which arm did the work.
    store = await _store_with_admin(email=None)
    try:
        await _call(store, **kwargs)  # type: ignore[arg-type]
    finally:
        await store.close()
