# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The console's read-only lock-state surface (BACKLOG #1131, ASVS 6.1.1).

The users list and the user page show an administrator each account's two ADR 0197 locks, with a
"Locked until" badge while one is live, and name the two ways to end a lock early. Neither page
offers a button that unlocks: the surface reports, it does not act. A ``users:read`` holder who is
not an administrator sees the list without any of it.
"""

from __future__ import annotations

import html
import time
from collections.abc import AsyncIterator

import httpx
import pytest
from _ui_clients import cookie_login, provision, ui_client

from messagefoundry.api.auth_models import UserLockState, UserSummary
from messagefoundry.auth import Role
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from messagefoundry_webconsole.pages.admin import _lock_card

BADGE = "Locked until"


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _lock(
    engine: Engine, user_id: str, *, sign_in: float | None, second: float | None
) -> None:
    store = engine.store
    assert isinstance(store, MessageStore)  # a SQLite-specific reach-in
    await store._db.execute(
        "UPDATE users SET failed_attempts=5, locked_until=?, lock_cycles=2,"
        " second_step_failed_attempts=3, second_step_locked_until=?, second_step_lock_cycles=1"
        " WHERE id=?",
        (sign_in, second, user_id),
    )
    await store._db.commit()


@pytest.fixture
async def boss(engine: Engine) -> AsyncIterator[tuple[httpx.AsyncClient, AuthService]]:
    service = await _service(engine)
    await provision(service, "root", [Role.ADMINISTRATOR.value])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "root")
        yield c, service


async def test_the_users_list_badges_a_locked_account_and_no_other(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, service = boss
    locked = await provision(service, "locked-one", [Role.VIEWER.value])
    await provision(service, "free-one", [Role.VIEWER.value])
    await _lock(engine, locked, sign_in=time.time() + 600, second=None)

    r = await c.get("/ui/users")
    assert r.status_code == 200
    assert "<th>Lock</th>" in r.text
    rows = {
        name: next(line for line in r.text.split("<tr>") if f">{name}</a>" in line)
        for name in ("locked-one", "free-one", "root")
    }
    assert BADGE in rows["locked-one"]
    assert BADGE not in rows["free-one"]
    assert BADGE not in rows["root"]


async def test_the_user_page_shows_both_locks_counts_and_the_recovery_path(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, service = boss
    target = await provision(service, "target", [Role.VIEWER.value])
    await _lock(engine, target, sign_in=time.time() + 600, second=time.time() + 300)

    r = await c.get(f"/ui/users/{target}")
    assert r.status_code == 200
    text = r.text
    assert "Sign-in lock: Locked until " in text
    assert "Second-step lock: Locked until " in text
    assert "5 failed attempts, 2 lock cycles" in text
    assert "3 failed attempts, 1 lock cycle" in text
    # The recovery path is text, and neither of its two routes is a button here.
    assert "reset this user&#x27;s password" in text or "reset this user's password" in text
    assert "messagefoundry admin-unlock" in text
    assert "/unlock" not in text
    assert ">Unlock" not in text


async def test_an_unlocked_account_page_carries_no_badge(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, service = boss
    target = await provision(service, "calm", [Role.VIEWER.value])
    r = await c.get(f"/ui/users/{target}")
    assert r.status_code == 200
    assert BADGE not in r.text
    assert "Sign-in lock: not locked" in r.text
    assert "Second-step lock: not locked" in r.text


async def test_an_expired_lock_is_not_badged(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, service = boss
    target = await provision(service, "lapsed", [Role.VIEWER.value])
    await _lock(engine, target, sign_in=time.time() - 5, second=time.time() - 5)
    detail = (await c.get(f"/ui/users/{target}")).text
    assert BADGE not in detail
    # A lapsed lock's counts are history, and the page says so rather than implying the account
    # is one failure from a new lock.
    assert "Sign-in lock: not locked (the last lock ended at " in detail
    assert "The attempt count restarts at the next failure" in detail
    listed = await c.get("/ui/users")
    row = next(line for line in listed.text.split("<tr>") if ">lapsed</a>" in line)
    assert BADGE not in row


async def test_a_users_read_holder_sees_the_list_without_lock_state(engine: Engine) -> None:
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="Directory reader",
        description=None,
        permissions=["users:read"],
        actor="test",
    )
    await provision(service, "reader", [role.id])
    locked = await provision(service, "locked-one", [Role.VIEWER.value])
    await _lock(engine, locked, sign_in=time.time() + 600, second=time.time() + 300)
    async with ui_client(engine, service) as c:
        await cookie_login(c, "reader")
        r = await c.get("/ui/users")
    assert r.status_code == 200
    assert ">locked-one</a>" in r.text
    assert "<th>Lock</th>" not in r.text
    assert BADGE not in r.text
    assert "failed attempt" not in r.text


# --- the lock card's recovery text, by account kind (BACKLOG #2292) ---------------------------
# Rendered from a constructed UserSummary, so the directory branch needs no AD fixture. The page
# tests above cover only a local account. The provider comes from AuthProvider, so a renamed value
# fails here rather than sending a directory account to the local text.

_DIRECTORY_RECOVERY = (
    "A lock ends on its own at the time shown. To end one early, run "
    "messagefoundry admin-unlock on the engine host."
)
_PASSWORD_RESET = "reset this user's password"


def _card_text(auth_provider: AuthProvider) -> str:
    user = UserSummary(
        id="u-1",
        username="locked-one",
        auth_provider=auth_provider.value,
        disabled=False,
        roles=[Role.VIEWER.value],
        lock_state=UserLockState(
            sign_in_locked=True,
            locked_until=time.time() + 600,
            failed_attempts=5,
            lock_cycles=1,
            second_step_locked=False,
        ),
    )
    return html.unescape(str(_lock_card(user)))


def test_a_directory_account_lock_card_names_only_the_host_unlock() -> None:
    text = _card_text(AuthProvider.AD)
    assert "Sign-in locks" in text  # the card rendered, so the absences below mean something
    assert _DIRECTORY_RECOVERY in text
    assert _PASSWORD_RESET not in text
    assert "authenticator app" not in text


def test_a_local_account_lock_card_names_the_password_reset_too() -> None:
    # The control arm: the same card for a local account does carry the reset route.
    text = _card_text(AuthProvider.LOCAL)
    assert "Sign-in locks" in text
    assert _PASSWORD_RESET in text
    assert "authenticator app" in text  # so the directory arm's absence check can fail
    assert "messagefoundry admin-unlock on the engine host" in text
    assert _DIRECTORY_RECOVERY not in text
