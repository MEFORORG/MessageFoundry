# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for ``enforce_session_cap`` (AUTH-SESS-CAP, BACKLOG #1900).

Deliberately **extra-free**, on the ``_session_rotation_contract`` precedent: nothing optional is
imported here, so the live Postgres / SQL Server suites import it *inside* their test functions and
run the same contract on legs that install only ``.[dev,postgres]`` / ``.[dev,sqlserver]``.

The defect it pins: the cap counted every UNREVOKED row, including rows the validator already
refuses. A newer lapsed row outranked an older live one, so the cap would sign a live device out on
first deployment to make room for a dead session.

The contract: only rows ``AuthService.identity_for_token`` would accept compete for the ``keep``
places, and every other unrevoked row is revoked, as the validator would revoke it on presentation.
The boundary cases sit ON each of the validator's comparisons, so a backend that writes ``<`` where
the validator means ``<=`` fails here.

Every timestamp is an integer-valued float, so ``now - last_used_at`` is exact on all three
backends' double columns and the boundary cases test the comparison, not rounding.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

IDLE = 1800.0
FAR = 10_000.0


async def _session(
    store: Any, user_id: str, *, created: float, expires: float, last_used: float | None = None
) -> str:
    """Create one session row and return its hash (64 hex chars, SQL Server's PK width)."""
    h = secrets.token_hex(32)
    await store.create_session(token_hash=h, user_id=user_id, expires_at=expires, now=created)
    if last_used is not None:
        await store.touch_session(h, now=last_used)
    return h


async def _revoked(store: Any, h: str) -> bool:
    row = await store.get_session(h)
    assert row is not None, "the cap revokes; it must never delete a row"
    return row.revoked_at is not None


async def _user(store: Any, user_id: str, now: float) -> None:
    await store.create_user(
        user_id=user_id,
        username=f"cap-{user_id}",
        auth_provider="local",
        display_name=None,
        email=None,
        password_hash="h",
        now=now,
    )


async def assert_session_cap_contract(store: Any, *, user_id: str = "cap-u1") -> None:
    """Drive ``enforce_session_cap`` through its contract on any backend. Creates its own users."""
    now = float(int(time.time()))

    # --- the defect: newer lapsed rows must not cost an older live device its session ----------
    await _user(store, user_id, now)
    live_device = await _session(
        store, user_id, created=now - 3000, last_used=now - 10, expires=now + FAR
    )
    idle_lapsed = await _session(store, user_id, created=now - 2500, expires=now + FAR)
    abs_lapsed = await _session(
        store, user_id, created=now - 2000, last_used=now - 5, expires=now - 1
    )
    new_login = await _session(store, user_id, created=now, expires=now + FAR)

    await store.enforce_session_cap(user_id, keep=2, idle_seconds=IDLE, now=now)

    assert not await _revoked(store, live_device), (
        "a live device was signed out to make room for lapsed rows -- the cap counted sessions the "
        "validator would refuse (BACKLOG #1900)"
    )
    assert not await _revoked(store, new_login)
    # Lapsed rows are revoked, not skipped: skipped, a later idle-setting raise or clock step would
    # revive them uncounted and the user would hold more than `keep` sessions that validate.
    assert await _revoked(store, idle_lapsed), "an idle-lapsed row must be revoked, not skipped"
    assert await _revoked(store, abs_lapsed), "an expired row must be revoked, not skipped"

    # --- the cap still binds among live sessions, oldest-created first ------------------------
    await store.enforce_session_cap(user_id, keep=1, idle_seconds=IDLE, now=now)
    assert await _revoked(store, live_device), "the older live session must go once over the cap"
    assert not await _revoked(store, new_login), "the newest session always survives the cap"

    # --- boundaries: exactly on each lapse test is still LIVE, as it is to the validator ------
    # `keep` leaves room for every live row, so a row is revoked here only if the cap thinks it is
    # lapsed.
    edge = f"{user_id}-edge"
    await _user(store, edge, now)
    on_idle = await _session(
        store, edge, created=now - 1900, last_used=now - IDLE, expires=now + FAR
    )
    on_abs = await _session(store, edge, created=now - 1700, expires=now)
    past_idle = await _session(
        store, edge, created=now - 1850, last_used=now - IDLE - 1, expires=now + FAR
    )
    past_abs = await _session(store, edge, created=now - 1600, expires=now - 1)
    newest = await _session(store, edge, created=now, expires=now + FAR)

    await store.enforce_session_cap(edge, keep=3, idle_seconds=IDLE, now=now)

    assert not await _revoked(store, on_idle), (
        "now - last_used_at == idle is live to the validator, so the cap must keep it"
    )
    assert not await _revoked(store, on_abs), (
        "expires_at == now is live to the validator, so the cap must keep it"
    )
    assert not await _revoked(store, newest)
    assert await _revoked(store, past_idle), "one second past idle is lapsed"
    assert await _revoked(store, past_abs), "one second past expiry is lapsed"

    # --- a row stamped AHEAD of `now` is neither ranked nor revoked ---------------------------
    # Usually it is a write that committed after the cap read its clock: a concurrent sign-in, or a
    # touch from a device in use. Revoked, that device would be signed out. Ranked, it would sort
    # newest and push out an older live device.
    fut = f"{user_id}-fut"
    await _user(store, fut, now)
    older = await _session(store, fut, created=now - 50, expires=now + FAR)
    current = await _session(store, fut, created=now, expires=now + FAR)
    future = await _session(store, fut, created=now + 100, expires=now + FAR)
    used_ahead = await _session(
        store, fut, created=now - 40, last_used=now + 100, expires=now + FAR
    )

    await store.enforce_session_cap(fut, keep=2, idle_seconds=IDLE, now=now)

    assert not await _revoked(store, older), "a row created ahead of now took a live device's place"
    assert not await _revoked(store, current)
    assert not await _revoked(store, future), (
        "a row created after the cap read its clock was revoked"
    )
    assert not await _revoked(store, used_ahead), (
        "a device touched after the cap read its clock was signed out"
    )
