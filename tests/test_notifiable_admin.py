# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1020: an ENABLED administrator with a deliverable address, as a predicate.

The PHI startup gate computes notification readiness from the SMTP transport alone
(``notify_security_events`` + ``email_smtp_host`` + ``email_from``). That answers *"is a transport
configured"* and never *"can the account that matters actually receive"* -- and the two come apart on
exactly the instance the gate is meant to protect: ``_ensure_bootstrap_admin`` creates the account
holding ``frozenset(Permission)`` with no ``email=``, so every notice about it no-ops while the gate
reports a healthy channel.

``has_notifiable_admin`` is the missing half of that question. These arms are deliberately
ASYMMETRIC -- a control that failed on everything would not distinguish *"the predicate keys on a
deliverable admin"* from *"the predicate is just hard to satisfy"*:

* the REAL bootstrap path yields False (the defect, reproduced rather than described);
* an administrator WITH an address yields True;
* a non-administrator with an address still yields False -- so the predicate keys on the ROLE, not
  on "some mailbox exists somewhere", which is the scope the item asks for (``email`` is optional
  for any Administrator, so a hand-created privileged account has the identical hole).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "notifiable_admin.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _admin_session(c: httpx.AsyncClient, service: AuthService) -> dict[str, str]:
    """Bootstrap the first admin exactly as a first run does, and clear its must-change flag."""
    boot = await service.initialize()
    assert boot is not None
    tok = (
        await c.post(
            "/auth/login",
            json={"username": "admin", "password": boot.password, "provider": "local"},
        )
    ).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    await c.post(
        "/me/password",
        headers=h,
        json={"current_password": boot.password, "new_password": "a-rotated-passphrase-99"},
    )
    tok = (
        await c.post(
            "/auth/login",
            json={"username": "admin", "password": "a-rotated-passphrase-99", "provider": "local"},
        )
    ).json()["token"]
    return {"Authorization": f"Bearer {tok}"}


async def test_the_bootstrap_admin_alone_is_not_notifiable(engine: Engine) -> None:
    """The defect, on the REAL first-run path rather than a hand-built fixture.

    This is the state a deploying site is in at the moment the SMTP-only gate passes: one account,
    holding every permission, with no address any notice could reach.
    """
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    async with _client(engine, service) as c:
        await _admin_session(c, service)
        assert await service.has_notifiable_admin() is False


async def test_an_administrator_with_an_address_is_notifiable(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    async with _client(engine, service) as c:
        h = await _admin_session(c, service)
        r = await c.post(
            "/users",
            headers=h,
            json={
                "username": "root2",
                "password": PW,
                "roles": ["administrator"],
                "email": "ops@example.org",
            },
        )
        assert r.status_code == 201, r.text
        assert await service.has_notifiable_admin() is True


async def test_a_non_administrator_with_an_address_is_not_enough(engine: Engine) -> None:
    """The asymmetric arm: an address on a NON-privileged account must not satisfy the predicate.

    Without this, a predicate that merely asked *"does any user have an email"* would pass every
    other arm here -- and would report a healthy channel on exactly the instance #1020 describes.
    """
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    async with _client(engine, service) as c:
        h = await _admin_session(c, service)
        r = await c.post(
            "/users",
            headers=h,
            json={
                "username": "viewer1",
                "password": PW,
                "roles": ["viewer"],
                "email": "viewer@example.org",
            },
        )
        assert r.status_code == 201, r.text
        assert await service.has_notifiable_admin() is False
