# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The offset-and-total paging contract every store backend must meet (BACKLOG #2438).

One body, run against SQLite in ``tests/test_audit_event_paging.py`` and against the live servers
in ``tests/test_postgres_store.py`` and ``tests/test_sqlserver_store.py``, so the three backends
are held to the same assertions rather than three copies that can drift.

What each check guards:

* The audit exclusion (BACKLOG #1131) applies BEFORE ``limit`` and ``offset``. If the offset ran
  first, walking the pages of an excluded listing would skip or repeat a row; if the total were
  counted without the exclusion, it would promise rows the reader can never reach.
* Walking every page with a small ``limit`` yields exactly the one-shot listing: nothing skipped,
  nothing repeated, the same order.
* Each total honours the same filters as its page, the event total its channel scope included.
"""

from __future__ import annotations

from typing import Any

from messagefoundry.store.audit_exclusion import AuditExclusion

_EXCLUDE = AuditExclusion(
    actions=frozenset({"auth.account_locked"}),
    rows=frozenset({("auth.mfa_failed", '{"reason": "locked"}')}),
)


async def _walk(read: Any, page: int) -> list[Any]:
    """Every row ``read(limit=, offset=)`` returns, one page at a time."""
    out: list[Any] = []
    offset = 0
    while True:
        rows = list(await read(limit=page, offset=offset))
        out += rows
        if len(rows) < page:
            return out
        offset += page


async def check_audit_paging(store: Any, tag: str) -> None:
    """``list_audit`` with ``offset`` against ``count_audit(limit=None)``, filtered and excluded."""
    who = f"p2438-{tag}"
    # Eleven rows: seven the exclusion keeps, four it hides, interleaved so a page boundary falls
    # between hidden and visible rows.
    shapes = [
        ("auth.mfa_failed", '{"reason": "expired"}'),
        ("auth.account_locked", '{"provider": "local"}'),
        ("auth.login_failed", '{"reason": "locked"}'),
        ("auth.mfa_failed", '{"reason": "locked"}'),
        ("auth.mfa_failed", None),
    ]
    for i in range(11):
        action, detail = shapes[i % len(shapes)]
        await store.record_audit(action, actor=who, detail=detail)
    # A row under another actor, which the actor filter must leave out of every page and the total.
    await store.record_audit("auth.mfa_failed", actor=f"{who}-other", detail=None)

    whole = await store.list_audit(actor=who, exclude=_EXCLUDE, limit=100)
    assert len(whole) == 7
    total = await store.count_audit(actor=who, exclude=_EXCLUDE, limit=None)
    assert total == 7

    async def read(*, limit: int, offset: int) -> Any:
        return await store.list_audit(actor=who, exclude=_EXCLUDE, limit=limit, offset=offset)

    for page in (1, 2, 3, 7):
        walked = await _walk(read, page)
        assert [r["id"] for r in walked] == [r["id"] for r in whole], page
    # A page past the end is empty, and the total does not move with the offset.
    assert list(await read(limit=3, offset=7)) == []
    # Unexcluded, the same reader would see all eleven: the exclusion is what the total honours.
    assert await store.count_audit(actor=who, limit=None) == 11
    # The capped count the export uses still caps.
    assert await store.count_audit(actor=who, exclude=_EXCLUDE, limit=4) == 4

    # Pinned below the first page's newest id, a page and the total ignore a row written later.
    pin = int(whole[0]["id"]) + 1
    await store.record_audit("auth.mfa_failed", actor=who, detail=None)
    assert await store.count_audit(actor=who, exclude=_EXCLUDE, limit=None, before_id=pin) == 7
    pinned = await store.list_audit(actor=who, exclude=_EXCLUDE, limit=2, offset=2, before_id=pin)
    assert [r["id"] for r in pinned] == [r["id"] for r in whole[2:4]]


async def check_security_events_paging(store: Any, tag: str) -> None:
    """``security_events_for_user`` with ``offset`` against ``count_security_events_for_user``."""
    who = f"s2438-{tag}"
    # BACKLOG #1152: the feed starts at the account's created_at, and a name no account holds has
    # no feed. A failed sign-in is recorded under the name tried, so these two rows stand for one
    # written before the account existed and one under a name no account holds. Neither may show.
    await store.record_audit("auth.login_failed", actor=who, detail='{"n": "before"}', now=1.0)
    await store.create_user(
        user_id=f"u-{who}", username=who, auth_provider="local", password_generated=False, now=2.0
    )
    await store.record_audit("auth.login_failed", actor=f"{who}-nobody", detail=None)
    assert await store.count_security_events_for_user(f"{who}-nobody") == 0
    assert list(await store.security_events_for_user(f"{who}-nobody")) == []
    for i in range(5):
        await store.record_audit("auth.login_success", actor=who, detail=f'{{"n": {i}}}')
    # Neither is in the self view: another action family, and another actor.
    await store.record_audit("user.updated", actor=who, detail=None)
    await store.record_audit("auth.login_success", actor=f"{who}-other", detail=None)

    whole = list(await store.security_events_for_user(who, limit=100))
    assert len(whole) == 5
    assert await store.count_security_events_for_user(who) == 5

    async def read(*, limit: int, offset: int) -> Any:
        return await store.security_events_for_user(who, limit=limit, offset=offset)

    for page in (1, 2, 5):
        walked = await _walk(read, page)
        assert [r["detail"] for r in walked] == [r["detail"] for r in whole], page

    # The snapshot pin: rows written after the first page stay out of the later pages and the
    # total, so a walk that started before them neither repeats a row nor moves its count.
    # The pin is a ts and not an id (an audit id would count other accounts' rows), and the
    # late row is written one second later so the clock's resolution cannot tie it to the pin.
    pin = max(float(r["ts"]) for r in whole)
    await store.record_audit("auth.login_success", actor=who, detail='{"n": "late"}', now=pin + 1.0)
    assert await store.count_security_events_for_user(who, until=pin) == 5
    assert await store.count_security_events_for_user(who) == 6
    pinned = await store.security_events_for_user(who, limit=2, offset=2, until=pin)
    assert [r["detail"] for r in pinned] == [r["detail"] for r in whole[2:4]]
    # The feed hands out no row id to pin on.
    assert "id" not in dict(whole[0])


def _event(connection: str, direction: str, kind: str, now: float) -> dict[str, Any]:
    return {
        "connection": connection,
        "transport": "mllp",
        "direction": direction,
        "kind": kind,
        "peer_host": None,
        "message_id": None,
        "reason": None,
        "now": now,
    }


async def check_connection_event_paging(store: Any, tag: str) -> None:
    """``list_connection_events`` with ``offset`` against ``connection_event_extent``, filtered by
    kind and scoped to a channel set."""
    mine, theirs, out = f"IB_{tag}_A", f"IB_{tag}_B", f"OB_{tag}_C"
    # Far in the future, so ``since`` isolates these rows from any a shared server database holds.
    base = 4_000_000_000.0
    burst = []
    for i in range(9):
        burst.append(_event(mine, "inbound", "established" if i % 3 else "closed", base + i))
        burst.append(_event(theirs, "inbound", "established", base + i + 0.5))
    burst.append(_event(out, "outbound", "connection_lost", base + 20))
    await store.record_connection_events(burst)

    since = base - 1
    # A channel-scoped reader sees its own inbound events only: not the other channel, not the
    # outbound one, and the total counts the same set.
    scoped = await store.list_connection_events(since=since, limit=100, allowed_channels=[mine])
    assert len(scoped) == 9 and {e.connection for e in scoped} == {mine}
    total, newest = await store.connection_event_extent(since=since, allowed_channels=[mine])
    assert total == 9 and newest == max(e.id for e in scoped)
    assert (await store.connection_event_extent(since=since, allowed_channels=None))[0] == 19

    filtered = await store.list_connection_events(
        connection=mine, kinds=["established"], since=since, limit=100, allowed_channels=None
    )
    assert len(filtered) == 6
    assert (
        await store.connection_event_extent(
            connection=mine, kinds=["established"], since=since, allowed_channels=None
        )
    )[0] == 6

    async def read(*, limit: int, offset: int) -> Any:
        return await store.list_connection_events(
            since=since, limit=limit, offset=offset, allowed_channels=[mine]
        )

    for page in (1, 2, 4, 9):
        walked = await _walk(read, page)
        assert [e.id for e in walked] == [e.id for e in scoped], page
    assert await read(limit=5, offset=9) == []

    # The snapshot pin holds even against a late event whose ts lands mid-list, the shape a burst
    # flush writes: the order is by ts, but the pin is by id, and a later insert has a larger id.
    pin = newest + 1
    await store.record_connection_events([_event(mine, "inbound", "closed", base + 4.25)])
    assert (
        await store.connection_event_extent(since=since, before_id=pin, allowed_channels=[mine])
    ) == (9, newest)
    pinned = await store.list_connection_events(
        since=since, limit=3, offset=3, before_id=pin, allowed_channels=[mine]
    )
    assert [e.id for e in pinned] == [e.id for e in scoped[3:6]]
    # The empty set reports no newest id, so a pager has nothing to pin.
    assert await store.connection_event_extent(
        connection=f"IB_{tag}_none", since=since, allowed_channels=None
    ) == (0, 0)
