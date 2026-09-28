# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The read-only lock-state surface on the admin user API (BACKLOG #1131, ASVS 6.1.1).

The owner's ruling R1 held 6.1.1 at partial partly because no API or console surface reported
whether an account is locked. ``GET /users`` now carries each account's two ADR 0197 locks, the
sign-in lock and the second-step lock, as ``lock_state``: whether each is live, when it ends, the
failed-attempt count and the lock-cycle count.

Who sees it is the point of these tests. ``GET /users`` needs only ``users:read``, which a custom
role can grant. Lock state and attempt counts are a target list (which accounts are under attack,
and how close each is to its next lock), so they go only to a ``users:manage`` holder, which is
Administrator-only by ADR 0045. Everyone else gets ``lock_state: null``, which means "not shown to
you" and never "not locked". ``/auth/me`` shows the caller none of it.

The surface is read-only. It adds no unlock route; recovery stays with the administrator password
reset and the host-gated ``messagefoundry admin-unlock`` (ADR 0171).
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"  # >=15 characters, no app or vendor terms (WP-3)

#: Every lock-state key the surface carries. The /auth/me leak test checks none of them appears.
LOCK_KEYS = (
    "sign_in_locked",
    "locked_until",
    "failed_attempts",
    "lock_cycles",
    "second_step_locked",
    "second_step_locked_until",
    "second_step_failed_attempts",
    "second_step_lock_cycles",
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "lock_state.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    # MFA off: these tests measure who may read lock state, not the MFA gate.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 123))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add(service: AuthService, username: str, roles: list[str]) -> str:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=roles,
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    return user_id


async def _seed_locks(
    engine: Engine,
    user_id: str,
    *,
    locked_until: float | None,
    failed_attempts: int,
    lock_cycles: int,
    second_step_locked_until: float | None,
    second_step_failed_attempts: int,
    second_step_lock_cycles: int,
) -> None:
    """Write both ADR 0197 counters directly, so a test names the exact values it expects back."""
    store = engine.store
    assert isinstance(store, MessageStore)  # a SQLite-specific reach-in
    await store._db.execute(
        "UPDATE users SET failed_attempts=?, locked_until=?, lock_cycles=?,"
        " second_step_failed_attempts=?, second_step_locked_until=?, second_step_lock_cycles=?"
        " WHERE id=?",
        (
            failed_attempts,
            locked_until,
            lock_cycles,
            second_step_failed_attempts,
            second_step_locked_until,
            second_step_lock_cycles,
            user_id,
        ),
    )
    await store._db.commit()


async def _bearer(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post("/auth/login", json={"username": username, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _row(users: list[dict[str, Any]], user_id: str) -> dict[str, Any]:
    return next(u for u in users if u["id"] == user_id)


async def test_an_administrator_reads_both_locks_live_state_and_counts(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "root", [Role.ADMINISTRATOR.value])
    target = await _add(service, "target", [Role.VIEWER.value])
    quiet = await _add(service, "quiet", [Role.VIEWER.value])
    now = time.time()
    await _seed_locks(
        engine,
        target,
        locked_until=now + 600,
        failed_attempts=5,
        lock_cycles=2,
        second_step_locked_until=now + 300,
        second_step_failed_attempts=3,
        second_step_lock_cycles=1,
    )
    async with _client(engine, service) as c:
        r = await c.get("/users", headers=await _bearer(c, "root"))
    assert r.status_code == 200
    locked = _row(r.json(), target)["lock_state"]
    assert locked == {
        "sign_in_locked": True,
        "locked_until": pytest.approx(now + 600),
        "failed_attempts": 5,
        "lock_cycles": 2,
        "second_step_locked": True,
        "second_step_locked_until": pytest.approx(now + 300),
        "second_step_failed_attempts": 3,
        "second_step_lock_cycles": 1,
    }
    # An account with nothing against it still gets a lock_state object, so to a users:manage
    # caller a null can only ever mean "not disclosed", never "not locked".
    assert _row(r.json(), quiet)["lock_state"] == {
        "sign_in_locked": False,
        "locked_until": None,
        "failed_attempts": 0,
        "lock_cycles": 0,
        "second_step_locked": False,
        "second_step_locked_until": None,
        "second_step_failed_attempts": 0,
        "second_step_lock_cycles": 0,
    }


async def test_a_users_read_holder_without_users_manage_sees_no_lock_state(
    engine: Engine,
) -> None:
    """``users:read`` is grantable by a custom role; lock state is not for it (ADR 0045 D1)."""
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="Directory reader",
        description=None,
        permissions=["users:read"],
        actor="test",
    )
    await _add(service, "reader", [role.id])
    target = await _add(service, "target", [Role.VIEWER.value])
    now = time.time()
    await _seed_locks(
        engine,
        target,
        locked_until=now + 600,
        failed_attempts=5,
        lock_cycles=2,
        second_step_locked_until=now + 300,
        second_step_failed_attempts=3,
        second_step_lock_cycles=1,
    )
    async with _client(engine, service) as c:
        r = await c.get("/users", headers=await _bearer(c, "reader"))
    assert r.status_code == 200
    assert _row(r.json(), target)["lock_state"] is None  # the locked account is listed, undisclosed
    for row in r.json():
        # The key is present and null: the documented "not shown to you" value.
        assert "lock_state" in row and row["lock_state"] is None, row


async def test_the_create_user_response_carries_lock_state(engine: Engine) -> None:
    """``POST /users`` is users:manage, so its summary discloses lock state like the list does."""
    service = await _service(engine)
    await _add(service, "root", [Role.ADMINISTRATOR.value])
    async with _client(engine, service) as c:
        created = await c.post(
            "/users",
            headers=await _bearer(c, "root"),
            json={"username": "newbie", "password": PW, "roles": ["viewer"], "email": "n@x.org"},
        )
    assert created.status_code == 201, created.text
    assert created.json()["lock_state"] == {
        "sign_in_locked": False,
        "locked_until": None,
        "failed_attempts": 0,
        "lock_cycles": 0,
        "second_step_locked": False,
        "second_step_locked_until": None,
        "second_step_failed_attempts": 0,
        "second_step_lock_cycles": 0,
    }


async def test_auth_me_carries_no_lock_state_or_attempt_counts(engine: Engine) -> None:
    """/auth/me shows the caller nothing about their own locks.

    The owner learns of a lock out of band (the ACCOUNT_LOCKED notice). A flag here would give a
    stolen session that holds no audit read a way to watch its own guessing trip the lock and
    lapse. An Administrator's session sees its own row on ``GET /users``, and that is no new
    oracle: it already reads every lock event in the audit trail."""
    service = await _service(engine)
    me = await _add(service, "self", [Role.ADMINISTRATOR.value])
    async with _client(engine, service) as c:
        headers = await _bearer(c, "self")
        # Counts and a second-step lock accrued AFTER sign-in, which a live session can carry.
        await _seed_locks(
            engine,
            me,
            locked_until=None,
            failed_attempts=3,
            lock_cycles=1,
            second_step_locked_until=time.time() + 300,
            second_step_failed_attempts=4,
            second_step_lock_cycles=2,
        )
        r = await c.get("/auth/me", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"user_id", "username", "auth_provider", "roles", "permissions"}
    for key in (*LOCK_KEYS, "lock_state"):
        assert key not in r.text, key


async def test_live_flips_off_when_the_lock_expires(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``live`` is computed on the server at read time, so it lapses with no write.

    Each step lands EXACTLY on an expiry, because the login gate treats ``now == locked_until`` as
    no longer locked (``now < locked_until``); the surface must agree with the gate there."""

    class _Clock:
        def __init__(self, start: float) -> None:
            self.now = start

        def __call__(self) -> float:
            return self.now

    clock = _Clock(time.time())
    start = clock.now
    monkeypatch.setattr(time, "time", clock)
    service = await _service(engine)
    await _add(service, "root", [Role.ADMINISTRATOR.value])
    target = await _add(service, "target", [Role.VIEWER.value])
    await _seed_locks(
        engine,
        target,
        locked_until=start + 60,
        failed_attempts=5,
        lock_cycles=1,
        second_step_locked_until=start + 30,
        second_step_failed_attempts=3,
        second_step_lock_cycles=1,
    )
    async with _client(engine, service) as c:
        headers = await _bearer(c, "root")
        before = _row((await c.get("/users", headers=headers)).json(), target)["lock_state"]
        clock.now = start + 30  # the second-step lock's own expiry, inside the sign-in lock
        middle = _row((await c.get("/users", headers=headers)).json(), target)["lock_state"]
        clock.now = start + 60  # the sign-in lock's own expiry
        after = _row((await c.get("/users", headers=headers)).json(), target)["lock_state"]
    assert before["sign_in_locked"] is True and before["second_step_locked"] is True
    assert middle["sign_in_locked"] is True and middle["second_step_locked"] is False
    assert after["sign_in_locked"] is False and after["second_step_locked"] is False
    # The stored expiry and counts are still reported after the lock lapses: nothing cleared them.
    assert after["failed_attempts"] == 5 and after["locked_until"] is not None
