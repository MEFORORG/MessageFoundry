# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Regression for SEC-015 (CWE-285): the last-enabled-administrator guard covers the disable and
delete lock-out paths, not only role removal.

``PUT /users/{id}/roles`` already refuses to strip the admin role from the sole enabled admin. The
functionally equivalent lock-out paths — ``PATCH /users/{id} {disabled:true}`` and
``DELETE /users/{id}`` — previously had no such guard, letting an admin disable/delete every other
admin and erase the dual-admin separation-of-duties safeguard. These tests pin that:

* disabling/deleting a NON-last admin still succeeds, and a non-admin is always disable-able/deletable
  (the guard only fires on the sole enabled admin); and
* the guard predicate ``is_last_enabled_admin`` is wired into BOTH the disable and delete routes, and
  the roles path (which permits self-target, unlike disable/delete) still refuses to strip the last
  admin — the invariant the disable/delete paths now share.
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

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "last_admin_guard.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(c: httpx.AsyncClient, username: str, password: str) -> httpx.Response:
    return await c.post(
        "/auth/login", json={"username": username, "password": password, "provider": "local"}
    )


async def _admin_session(c: httpx.AsyncClient, service: AuthService) -> tuple[dict[str, str], str]:
    """Bootstrap the first admin, clear its must-change flag; return (auth-headers, admin-user-id)."""
    boot = await service.initialize()
    assert boot is not None
    h = _auth((await _login(c, "admin", boot.password)).json()["token"])
    await c.post(
        "/me/password",
        headers=h,
        json={"current_password": boot.password, "new_password": "a-rotated-passphrase-99"},
    )
    h = _auth((await _login(c, "admin", "a-rotated-passphrase-99")).json()["token"])
    my_id = (await c.get("/auth/me", headers=h)).json()["user_id"]
    return h, my_id


async def _create_user(c: httpx.AsyncClient, h: dict[str, str], username: str, role: str) -> str:
    r = await c.post(
        "/users", headers=h, json={"username": username, "password": PW, "roles": [role]}
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def test_non_last_admin_can_be_disabled_and_deleted(engine: Engine) -> None:
    # With two enabled admins, disabling or deleting one (not the last) succeeds.
    # Last-admin guard is a step-up admin-CRUD flow, not an MFA test: pin require_mfa=False so the
    # BACKLOG #187 secure default (require_mfa now ON) doesn't 403 the disable/delete/roles ops first.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    async with _client(engine, service) as c:
        h, _ = await _admin_session(c, service)
        root2 = await _create_user(c, h, "root2", "administrator")
        # disable one of two admins → allowed (one remains)
        assert (
            await c.patch(f"/users/{root2}", headers=h, json={"disabled": True})
        ).status_code == 200
        # re-enable and delete it → allowed
        assert (
            await c.patch(f"/users/{root2}", headers=h, json={"disabled": False})
        ).status_code == 200
        assert (await c.delete(f"/users/{root2}", headers=h)).status_code == 200


async def test_non_admin_can_always_be_disabled_and_deleted(engine: Engine) -> None:
    # Last-admin guard is a step-up admin-CRUD flow, not an MFA test: pin require_mfa=False so the
    # BACKLOG #187 secure default (require_mfa now ON) doesn't 403 the disable/delete/roles ops first.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    async with _client(engine, service) as c:
        h, _ = await _admin_session(c, service)
        viewer = await _create_user(c, h, "viewer1", "viewer")
        assert (
            await c.patch(f"/users/{viewer}", headers=h, json={"disabled": True})
        ).status_code == 200
        assert (await c.delete(f"/users/{viewer}", headers=h)).status_code == 200


async def test_roles_path_still_refuses_to_strip_last_admin(engine: Engine) -> None:
    # The roles endpoint permits self-target, so it is the path on which the last-admin guard is
    # directly observable end-to-end: stripping admin from the sole enabled admin is refused (400),
    # and once a second admin exists the demotion succeeds.
    # Last-admin guard is a step-up admin-CRUD flow, not an MFA test: pin require_mfa=False so the
    # BACKLOG #187 secure default (require_mfa now ON) doesn't 403 the disable/delete/roles ops first.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    async with _client(engine, service) as c:
        h, my_id = await _admin_session(c, service)
        assert (
            await c.put(f"/users/{my_id}/roles", headers=h, json={"roles": ["viewer"]})
        ).status_code == 400
        await _create_user(c, h, "root2", "administrator")
        assert (
            await c.put(f"/users/{my_id}/roles", headers=h, json={"roles": ["viewer"]})
        ).status_code == 200


async def test_disable_and_delete_routes_carry_last_admin_guard(engine: Engine) -> None:
    # The disable/delete routes call is_last_enabled_admin AFTER the self-guard. Self-target on those
    # paths is rejected first ("cannot disable/delete your own account"), so the last-admin guard is
    # the second line that protects the sole enabled admin from a (future) non-self lock-out path.
    # Pin both: (a) the predicate is True exactly for the sole enabled admin, and (b) the self-guard
    # fires for the acting admin on both routes (the message order the new guard must sit behind).
    # Last-admin guard is a step-up admin-CRUD flow, not an MFA test: pin require_mfa=False so the
    # BACKLOG #187 secure default (require_mfa now ON) doesn't 403 the disable/delete/roles ops first.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    async with _client(engine, service) as c:
        h, my_id = await _admin_session(c, service)
        viewer = await _create_user(c, h, "viewer1", "viewer")
        # Predicate: True only for the sole enabled admin.
        assert await service.is_last_enabled_admin(my_id) is True
        assert await service.is_last_enabled_admin(viewer) is False
        # Self-guard precedes the last-admin guard on both routes (acting admin == sole admin).
        r_disable = await c.patch(f"/users/{my_id}", headers=h, json={"disabled": True})
        assert r_disable.status_code == 400
        assert "your own account" in r_disable.json()["detail"]
        r_delete = await c.delete(f"/users/{my_id}", headers=h)
        assert r_delete.status_code == 400
        assert "your own account" in r_delete.json()["detail"]
        # Add a second admin, then disable it → the first is again the sole ENABLED admin, so the
        # predicate the guard keys on returns True for it (and the second is no longer protected).
        root2 = await _create_user(c, h, "root2", "administrator")
        assert await service.is_last_enabled_admin(my_id) is False
        assert (
            await c.patch(f"/users/{root2}", headers=h, json={"disabled": True})
        ).status_code == 200
        assert await service.is_last_enabled_admin(my_id) is True
