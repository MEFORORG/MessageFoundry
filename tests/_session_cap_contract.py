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

BACKLOG #2076 adds the MFA-pending split: when the caller says an unstamped session still owes a
second factor, stamped and unstamped rows rank as two groups that each keep ``keep``, and a row
ranks from when it completed its second factor rather than from its sign-in.

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

    await store.enforce_session_cap(
        user_id, keep=2, idle_seconds=IDLE, split_mfa_pending=False, now=now
    )

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
    await store.enforce_session_cap(
        user_id, keep=1, idle_seconds=IDLE, split_mfa_pending=False, now=now
    )
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

    await store.enforce_session_cap(
        edge, keep=3, idle_seconds=IDLE, split_mfa_pending=False, now=now
    )

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

    await store.enforce_session_cap(
        fut, keep=2, idle_seconds=IDLE, split_mfa_pending=False, now=now
    )

    assert not await _revoked(store, older), "a row created ahead of now took a live device's place"
    assert not await _revoked(store, current)
    assert not await _revoked(store, future), (
        "a row created after the cap read its clock was revoked"
    )
    assert not await _revoked(store, used_ahead), (
        "a device touched after the cap read its clock was signed out"
    )

    await _assert_mfa_pending_split(store, user_id, now)
    await _assert_idle_rows_hidden_and_purged(store, user_id)


async def _assert_idle_rows_hidden_and_purged(store: Any, user_id: str) -> None:
    """BACKLOG #2096: with ``idle_seconds`` given, ``list_sessions`` hides idle-expired rows and
    ``purge_expired_sessions`` deletes them. Without it, both behave as before.

    Every stamp sits near a fixed instant far in the past, so the purge (which spans every user)
    cannot reach the rows another test on a shared live database is still using: their
    ``last_used_at`` is later than ``base``, so ``base - last_used_at`` is negative."""
    base = 1_000_000.0
    u = f"{user_id}-idle"
    await _user(store, u, base)
    fresh = await _session(store, u, created=base - 100, expires=base + FAR)
    on_idle = await _session(store, u, created=base - IDLE, expires=base + FAR)
    idle = await _session(store, u, created=base - IDLE - 1, expires=base + FAR)

    hidden = {s.token_hash for s in await store.list_sessions(u, now=base, idle_seconds=IDLE)}
    assert hidden == {fresh, on_idle}, "the inventory listed a session the validator refuses"
    unfiltered = {s.token_hash for s in await store.list_sessions(u, now=base)}
    assert unfiltered == {fresh, on_idle, idle}, "no idle_seconds must mean no idle filter"

    assert await store.purge_expired_sessions(now=base) >= 0
    assert await store.get_session(idle) is not None, "no idle_seconds must mean no idle purge"
    assert await store.purge_expired_sessions(now=base, idle_seconds=IDLE) >= 1
    assert await store.get_session(idle) is None, "an idle-expired row survived the purge"
    assert await store.get_session(on_idle) is not None, "idle == timeout is still live"
    assert await store.get_session(fresh) is not None


async def _full_session(store: Any, user_id: str, *, created: float, verified: float) -> str:
    """A session that completed its second factor at ``verified``. Every caller creates it inside
    the last ``FAR`` seconds, so ``created + 2 * FAR`` is always in the future."""
    h = await _session(store, user_id, created=created, expires=created + 2 * FAR)
    await store.mark_session_mfa_verified(h, now=verified)
    return h


async def _assert_mfa_pending_split(store: Any, user_id: str, now: float) -> None:
    """BACKLOG #2076: a sign-in still waiting for its second factor must not evict a full session.

    Each shape runs twice where the flag decides the outcome, once split and once not, so the
    unsplit run is the control: it shows the rows WOULD be evicted if they competed in one group.
    """
    for split in (True, False):
        u = f"{user_id}-split-{split}"
        await _user(store, u, now)
        full_old = await _full_session(store, u, created=now - 300, verified=now - 290)
        full_new = await _full_session(store, u, created=now - 200, verified=now - 190)
        # Three password-only sign-ins, every one newer than both full sessions.
        pending = [
            await _session(store, u, created=now - age, expires=now + FAR) for age in (100, 50, 10)
        ]

        await store.enforce_session_cap(
            u, keep=2, idle_seconds=IDLE, split_mfa_pending=split, now=now
        )

        if split:
            assert not await _revoked(store, full_old), (
                "a sign-in still owing its second factor evicted a full session (BACKLOG #2076)"
            )
            assert not await _revoked(store, full_new)
            # The pending group is bounded by its own `keep`, oldest first.
            assert await _revoked(store, pending[0]), "pending sign-ins must stay bounded"
            assert not await _revoked(store, pending[1])
            assert not await _revoked(store, pending[2])
        else:
            # Unsplit is one group, as before: the two newest rows win whatever their stamp.
            assert await _revoked(store, full_old)
            assert await _revoked(store, full_new)
            assert await _revoked(store, pending[0])
            assert not await _revoked(store, pending[1])
            assert not await _revoked(store, pending[2])

    # A session ranks from when it completed its second factor, not from its sign-in. Completion
    # keeps `created_at`, so ranking by creation would evict a session the moment it finished MFA
    # whenever it had waited longer than a sibling.
    for split in (True, False):
        late = f"{user_id}-late-{split}"
        await _user(store, late, now)
        finished_late = await _full_session(store, late, created=now - 600, verified=now - 100)
        finished_early = await _full_session(store, late, created=now - 500, verified=now - 400)
        finished_mid = await _full_session(store, late, created=now - 300, verified=now - 250)

        await store.enforce_session_cap(
            late, keep=2, idle_seconds=IDLE, split_mfa_pending=split, now=now
        )

        assert not await _revoked(store, finished_late), (
            "the session that completed MFA last was evicted because it signed in first"
        )
        assert not await _revoked(store, finished_mid)
        assert await _revoked(store, finished_early)

    # A second-factor stamp AHEAD of `now` is an ahead stamp like any other: neither ranked nor
    # revoked. Ranked, it would sort newest and evict the sign-in that is running the cap.
    for split in (True, False):
        ahead = f"{user_id}-mfa-ahead-{split}"
        await _user(store, ahead, now)
        stamped_ahead = await _full_session(store, ahead, created=now - 100, verified=now + 50)
        signing_in = await _full_session(store, ahead, created=now, verified=now)

        await store.enforce_session_cap(
            ahead, keep=1, idle_seconds=IDLE, split_mfa_pending=split, now=now
        )

        assert not await _revoked(store, signing_in), (
            "a second-factor stamp ahead of now took the place of the sign-in running the cap"
        )
        assert not await _revoked(store, stamped_ahead), (
            "a row whose second-factor stamp is ahead of now was revoked"
        )
