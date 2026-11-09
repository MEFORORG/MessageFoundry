# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for the federated unbind and its session guard (BACKLOG #1474).

``clear_user_federated_subject`` NULLs an account's federated ``(issuer, sub)`` pair, revokes its
live sessions, and reports the pair it cleared -- all in one transaction.
``create_session(require_federated_subject=...)`` is the other half: it makes a session insert
conditional on that pair still being there, so a login already in flight cannot outrun the unbind.
One shared body each, run by the SQLite, PostgreSQL and SQL Server suites, so "the three backends
agree" is an assertion rather than a reading of three separately-worded tests. The two server legs
run only in CI, so that is where their bodies first execute. The bind-versus-delete lock-order body
runs on the two server legs only: the SQLite store runs one writer at a time, so it has no lock
order to test.

Driven against the REAL store object on every leg. A fake would move in lockstep with a broken
implementation and the test would see nothing.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

ISSUER = "https://idp.example/tenant"
#: The subject the first account starts bound to, and the one a re-bind must be free to replace.
FIRST_SUB = "S-1-unbind-first"
#: The second account's subject, so its binding surviving is separable from "nothing was bound".
SECOND_SUB = "S-1-unbind-second"
#: The subject presented after the unbind, standing for a new person on the same account.
REBOUND_SUB = "S-1-unbind-rebound"

#: Far enough ahead that no session in this module expires while the test runs.
_EXPIRES = 9_999_999_999.0


async def _assert_federated_unbind_contract(store: Any) -> None:
    """The behaviour every backend owes ``clear_user_federated_subject``.

    Three AD accounts: two bound to different subjects, one never bound. The first holds two live
    sessions and one already revoked; the second holds one live session.
    """
    for uid in ("fed-first", "fed-second", "fed-never"):
        await store.create_user(
            user_id=uid,
            username=uid,
            auth_provider="ad",
            now=1_000.0,
            password_generated=False,
            audits=(),
        )
    await store.set_user_federated_subject("fed-first", ISSUER, FIRST_SUB, now=1_000.0)
    await store.set_user_federated_subject("fed-second", ISSUER, SECOND_SUB, now=1_000.0)
    for token, uid in (("t-first-1", "fed-first"), ("t-first-2", "fed-first")):
        await store.create_session(token_hash=token, user_id=uid, expires_at=_EXPIRES, now=1_000.0)
    await store.create_session(
        token_hash="t-first-old", user_id="fed-first", expires_at=_EXPIRES, now=1_000.0
    )
    await store.revoke_session("t-first-old", now=1_500.0)
    await store.create_session(
        token_hash="t-second", user_id="fed-second", expires_at=_EXPIRES, now=1_000.0
    )

    # Precondition: the pair really was written, or every NULL below would be asserting against a
    # column nothing ever set.
    first = await store.get_user("fed-first")
    assert first is not None and (first.oidc_issuer, first.oidc_subject) == (ISSUER, FIRST_SUB)

    # 1. The unbind reports what its OWN transaction saw and did: the pair it cleared, the account
    #    it cleared it from, and the two live sessions it revoked -- not the one already revoked.
    #    The pair matters as much as the count: the caller audits it, and reading it out here rather
    #    than from a separate get_user is what stops a concurrent rebind renaming the audit row.
    outcome = await store.clear_user_federated_subject(
        "fed-first", expected_issuer=ISSUER, expected_subject=FIRST_SUB, now=2_000.0
    )
    assert outcome is not None
    assert outcome.sessions_revoked == 2, f"expected two live sessions revoked, got {outcome}"
    assert (outcome.issuer, outcome.subject) == (ISSUER, FIRST_SUB)
    assert outcome.username == "fed-first"
    assert outcome.changed is False

    # 2. Both halves go NULL together, and the account is still the directory account it was.
    #    A half-NULL pair would sit outside the unique index's filter while still reading as bound
    #    to the #1015 guard, which keys on the subject alone.
    after = await store.get_user("fed-first")
    assert after is not None
    assert after.oidc_issuer is None and after.oidc_subject is None
    assert after.auth_provider == "ad", "an unbind must not change who the account authenticates as"
    assert after.updated_at == 2_000.0
    assert await store.get_user_by_federated_subject(ISSUER, FIRST_SUB) is None

    # 3. Only this account's LIVE sessions were revoked, stamped with this call's instant. The one
    #    revoked earlier keeps its own stamp: the UPDATE must not rewrite history.
    for token in ("t-first-1", "t-first-2"):
        session = await store.get_session(token)
        assert session is not None and session.revoked_at == 2_000.0, token
    old = await store.get_session("t-first-old")
    assert old is not None and old.revoked_at == 1_500.0

    # 4. The other account is untouched: still bound, and its session still live.
    second = await store.get_user("fed-second")
    assert second is not None and second.oidc_subject == SECOND_SUB
    other = await store.get_session("t-second")
    assert other is not None and other.revoked_at is None

    # 4b. BACKLOG #2026. A clear whose expected pair is not the stored one writes NOTHING: the pair
    #     stays, the live session stays, updated_at stays, and the result says ``changed`` and names
    #     the pair the row really holds. Two stale shapes: another subject, and "saw it unbound".
    #     Step 6 below clears this same account with the right pair, which is the control that the
    #     refusal came from the comparison and not from anything else about the row.
    for stale in ((ISSUER, "S-1-stale"), (None, None), (ISSUER, None)):
        refused = await store.clear_user_federated_subject(
            "fed-second", expected_issuer=stale[0], expected_subject=stale[1], now=1_800.0
        )
        assert refused is not None and refused.changed is True, stale
        assert (refused.issuer, refused.subject, refused.sessions_revoked) == (
            ISSUER,
            SECOND_SUB,
            0,
        ), stale
        kept = await store.get_user("fed-second")
        assert kept is not None and kept.oidc_subject == SECOND_SUB, stale
        assert kept.updated_at == 1_000.0, stale
        live = await store.get_session("t-second")
        assert live is not None and live.revoked_at is None, stale

    # 5. A second unbind of the same account writes NOTHING. The account is given a LIVE session
    #    first, because "revoked 0" is what a call that revoked nothing AND a call that had nothing
    #    to revoke both report -- only a session that survives tells them apart. An unbind of
    #    nothing must not sign anybody out, and the untouched updated_at says nothing was written.
    await store.create_session(
        token_hash="t-first-after", user_id="fed-first", expires_at=_EXPIRES, now=2_500.0
    )
    noop = await store.clear_user_federated_subject(
        "fed-first", expected_issuer=None, expected_subject=None, now=3_000.0
    )
    assert noop is not None
    assert (noop.issuer, noop.subject, noop.sessions_revoked) == (None, None, 0)
    assert noop.username == "fed-first"
    survivor = await store.get_session("t-first-after")
    assert survivor is not None and survivor.revoked_at is None, (
        "an unbind of an already-unbound account revoked a live session"
    )
    still = await store.get_user("fed-first")
    assert still is not None and still.updated_at == 2_000.0
    assert noop.changed is False

    # 5a. BACKLOG #2026, the stale unlink: a caller that still expects the pair already removed is
    #     told the row changed, with the NULL pair it now holds, rather than "nothing to unbind".
    gone = await store.clear_user_federated_subject(
        "fed-first", expected_issuer=ISSUER, expected_subject=FIRST_SUB, now=3_000.0
    )
    assert gone is not None and gone.changed is True
    assert (gone.issuer, gone.subject, gone.sessions_revoked) == (None, None, 0)
    survivor = await store.get_session("t-first-after")
    assert survivor is not None and survivor.revoked_at is None

    # 5b. An unknown user is reported as such rather than as an account with no binding, so the
    #     caller can tell "no such user" from "nothing to unbind" without a second read.
    assert (
        await store.clear_user_federated_subject(
            "fed-nobody", expected_issuer=None, expected_subject=None, now=3_000.0
        )
        is None
    )

    # 6. Two unbound rows coexist with a never-bound one under ux_users_federated_subject. The
    #    filtered index admits any number of NULL pairs; an unfiltered one on SQL Server would
    #    refuse the second. Step 8 is the control that makes this more than an absence of errors.
    second_unbind = await store.clear_user_federated_subject(
        "fed-second", expected_issuer=ISSUER, expected_subject=SECOND_SUB, now=2_000.0
    )
    assert second_unbind is not None and second_unbind.sessions_revoked == 1
    assert (second_unbind.issuer, second_unbind.subject) == (ISSUER, SECOND_SUB)
    for uid in ("fed-first", "fed-second", "fed-never"):
        row = await store.get_user(uid)
        assert row is not None and row.oidc_issuer is None and row.oidc_subject is None, uid

    # 7. A re-bind after the unbind succeeds, to a DIFFERENT subject: the account is free again.
    await store.set_user_federated_subject("fed-first", ISSUER, REBOUND_SUB, now=4_000.0)
    rebound = await store.get_user_by_federated_subject(ISSUER, REBOUND_SUB)
    assert rebound is not None and rebound.id == "fed-first"

    # 8. POSITIVE CONTROL. The index is live on this backend: a second account taking a bound pair
    #    is refused with the backend's own integrity class. It was placed last because on SQLite a
    #    refused bind used to leave the writer connection inside an implicit transaction, so the
    #    next writer to open its own failed on BEGIN. BACKLOG #1801 fixed that, and
    #    tests/test_backlog1801_refused_bind_rolls_back.py pins it; the order no longer matters.
    try:
        await store.set_user_federated_subject("fed-second", ISSUER, REBOUND_SUB, now=5_000.0)
    except Exception as exc:  # noqa: BLE001 - each backend raises its own integrity class
        name = "".join(t.__name__ for t in type(exc).__mro__)
        assert "Integrity" in name or "UniqueViolation" in name, (
            f"a duplicate bound pair raised {type(exc).__name__}, not an integrity violation"
        )
    else:
        raise AssertionError(
            "a second account took a bound pair; ux_users_federated_subject is not in force, so"
            " step 6 proved nothing about it"
        )


#: The account used by the session-guard contract below, kept apart from the unbind body's rows so
#: the two can run in either order against one store.
GUARD_USER = "fed-guard"
GUARD_SUB = "S-1-guard"


async def _guarded_session(
    store: Any, token: str, pair: tuple[str | None, str | None] | None, *, user: str = GUARD_USER
) -> bool:
    """One ``create_session`` for the guard contract. ``pair`` of ``None`` passes NO guard at all,
    which is the control arm, not a guard that matches nothing."""
    guard = {} if pair is None else {"require_federated_subject": pair}
    written = await store.create_session(
        token_hash=token, user_id=user, expires_at=_EXPIRES, now=3.0, **guard
    )
    # The bool and the row must agree; a call that reported False and inserted anyway is the one
    # failure this contract exists to catch, so it is asserted on every arm rather than per step.
    assert (await store.get_session(token) is not None) is written, token
    return bool(written)


async def _assert_session_binding_guard_contract(store: Any) -> None:
    """``create_session(require_federated_subject=...)`` on this backend (BACKLOG #1474).

    The guard exists so an unbind cannot be outrun by a login already in flight: the insert is
    conditional on the account STILL carrying the pair the login verified, decided inside the
    store's own transaction. What is checked here is the decision, sequentially -- the interleaving
    itself is a backend-level lock property (the SQLite writer lock, ``FOR UPDATE`` on PostgreSQL,
    ``UPDLOCK, ROWLOCK`` on SQL Server) and is asserted in the per-backend suites.
    """
    await store.create_user(
        user_id=GUARD_USER,
        username=GUARD_USER,
        auth_provider="ad",
        now=1.0,
        password_generated=False,
        audits=(),
    )
    await store.set_user_federated_subject(GUARD_USER, ISSUER, GUARD_SUB, now=1.0)

    # 1. Bound to the pair the caller verified: the row is written and the call says so.
    assert await _guarded_session(store, "g-ok", (ISSUER, GUARD_SUB)) is True

    # 2. CONTROL. A pair that does not match is refused, and nothing is written. Without this a
    #    guard that always returned True would still pass step 1.
    assert await _guarded_session(store, "g-wrong", (ISSUER, "S-1-somebody-else")) is False

    # 3. THE CASE THE GUARD EXISTS FOR. After the unbind the same verified pair no longer names this
    #    account, so the login that was carrying it cannot mint a session the unbind's revocation
    #    never saw.
    assert (
        await store.clear_user_federated_subject(
            GUARD_USER, expected_issuer=ISSUER, expected_subject=GUARD_SUB, now=2.0
        )
        is not None
    )
    assert await _guarded_session(store, "g-after-unbind", (ISSUER, GUARD_SUB)) is False

    # 4. A user that does not exist is refused rather than inserted against a missing row.
    assert (
        await _guarded_session(store, "g-nobody", (ISSUER, GUARD_SUB), user="fed-guard-nobody")
        is False
    )

    # 5. CONTROL for step 3. With no guard requested the SAME unbound account still takes a session,
    #    so the refusals above came from the guard and not from anything else about the row.
    assert await _guarded_session(store, "g-unguarded", None) is True


#: A second account for the bind's sweep, so "every session of THAT account" has a control.
GUARD_BYSTANDER = "fed-guard-bystander"
#: The pair a Windows SSO mint requires: an unbound row.
UNBOUND: tuple[None, None] = (None, None)


async def _live(store: Any, token: str) -> bool:
    session = await store.get_session(token)
    return session is not None and session.revoked_at is None


async def _assert_bind_sweeps_and_unbound_guard_contract(store: Any) -> None:
    """``set_user_federated_subject`` and ``create_session(require_federated_subject=(None, None))``
    on this backend (vault BACKLOG #2609).

    Two decisions. A bind ends every live session of the account it binds, in its own transaction,
    and reports the count. And a session insert that requires an unbound row is refused once the row
    is bound. As in the contract above, what is checked is the decision, sequentially: the
    interleaving is a backend lock property.
    """
    for user in (GUARD_USER + "-2", GUARD_BYSTANDER):
        await store.create_user(
            user_id=user,
            username=user,
            auth_provider="ad",
            now=1.0,
            password_generated=False,
            audits=(),
        )
    account = GUARD_USER + "-2"

    # 1. Unbound: the guarded insert is written. CONTROL for step 4.
    assert await _guarded_session(store, "b-unbound", UNBOUND, user=account) is True
    assert await _guarded_session(store, "b-plain", None, user=account) is True
    assert await _guarded_session(store, "b-bystander", None, user=GUARD_BYSTANDER) is True

    # 2. A write that changes nothing revokes nothing and answers None. The user is unknown.
    assert (
        await store.set_user_federated_subject("fed-guard-nobody-2", ISSUER, "S-1-none", now=2.0)
        is None
    )
    assert await _live(store, "b-unbound") and await _live(store, "b-plain")

    # 3. THE BIND. Both of the account's sessions end, the count says two, and the other account's
    #    session is untouched.
    swept = await store.set_user_federated_subject(
        account, ISSUER, "S-1-guard-2", now=3.0, expect_unbound=True
    )
    assert swept == 2, swept
    assert not await _live(store, "b-unbound") and not await _live(store, "b-plain")
    assert await _live(store, "b-bystander"), "the sweep reached another account"

    # 4. THE CASE THE GUARD EXISTS FOR. The row is bound, so an insert that requires it unbound is
    #    refused and writes nothing.
    assert await _guarded_session(store, "b-after-bind", UNBOUND, user=account) is False

    # 5. A conditional write on a row that is already bound writes nothing, so it revokes nothing:
    #    the session minted under the binding stays live, and the answer is None and not 0.
    assert await _guarded_session(store, "b-bound", (ISSUER, "S-1-guard-2"), user=account) is True
    again = await store.set_user_federated_subject(
        account, ISSUER, "S-1-other", now=4.0, expect_unbound=True
    )
    assert again is None, again
    assert await _live(store, "b-bound")

    # 6. A bind that finds no session still wrote: it answers 0, which is not None.
    await store.create_user(
        user_id="fed-guard-quiet",
        username="fed-guard-quiet",
        auth_provider="ad",
        now=1.0,
        password_generated=False,
        audits=(),
    )
    assert (
        await store.set_user_federated_subject("fed-guard-quiet", ISSUER, "S-1-quiet", now=5.0) == 0
    )


#: How long the lock-wait probe looks for the delete to queue behind the bind, in polls.
_PROBE_POLLS = 400
_PROBE_INTERVAL = 0.025
#: A bound on each awaited step, so a hang fails the test rather than the leg's timeout.
_STEP_TIMEOUT = 30.0


async def _assert_bind_and_user_delete_take_one_lock_order(
    store: Any,
    *,
    holder_of: Callable[[Any], Awaitable[object]],
    is_blocking: Callable[[object], Awaitable[bool]],
) -> None:
    """A bind and ``delete_user`` against one account, interleaved on a server store (BACKLOG #2738).

    Both must take the account's ``users`` row before its ``sessions`` rows. The bind is paused
    right after its user write, holding the row, and ``delete_user`` is started. A delete that took
    the sessions first holds the live session's row by the time it queues on ``users``. The bind's
    sweep, released, then waits on that session row: a deadlock, and the server ends one of the two.
    A delete that takes ``users`` first holds nothing yet, so the bind finishes and the delete
    follows it.

    ``holder_of`` names the bind's server session from the handle its user write was given.
    ``is_blocking`` says whether a lock request is waiting on that session right now: the probe that
    the delete really queued behind the bind. No timing decides it, so a pass is not a lucky
    schedule. The interleaving is hooked rather than raced.
    """
    account = "fed-bind-delete"
    await store.create_user(
        user_id=account,
        username=account,
        auth_provider="ad",
        now=1.0,
        password_generated=False,
        audits=(),
    )
    await store.create_session(token_hash="bd-live", user_id=account, expires_at=_EXPIRES, now=1.0)

    swept, _ = await _hold_then_race(
        store,
        attr="_write_user",
        key=account,
        first=(
            "the bind",
            lambda: store.set_user_federated_subject(account, ISSUER, "S-1-bind-delete", now=2.0),
        ),
        second=("delete_user", lambda: store.delete_user(account)),
        holder_of=holder_of,
        is_blocking=is_blocking,
    )

    # Neither was ended by the server: the bind swept the one live session, and the delete then
    # removed the account and every session row, the revoked one included.
    assert swept == 1, swept
    assert await store.get_user(account) is None
    assert await store.get_session("bd-live") is None


#: A labelled store call: the label names it in a failure message.
_Step = tuple[str, Callable[[], Coroutine[Any, Any, Any]]]


async def _hold_then_race(
    store: Any,
    *,
    attr: str,
    key: str,
    first: _Step,
    second: _Step,
    holder_of: Callable[[Any], Awaitable[object]],
    is_blocking: Callable[[object], Awaitable[bool]],
    pause_before: str | None = None,
) -> tuple[Any, Any]:
    """Run ``first`` until its call to ``store.<attr>`` for ``key`` has landed, and hold it there
    with its locks; start ``second``; require that ``second`` really waits on ``first``'s server
    session; then release ``first`` and return both results, ``first``'s first.

    ``attr`` names a write helper called ``(handle, key, change)``: ``_write_user`` or
    ``_write_session``. Only the first call for ``key`` pauses. With ``pause_before``, the pause
    comes inside that call instead, just before the handle runs the first statement starting with
    that text, so ``first`` holds what the helper's locked read took and has written nothing yet.
    The race is hooked, not timed: without the probe a pass could come from a ``second`` that never
    met ``first``, which proves nothing about the order.
    """
    (first_name, start_first), (second_name, start_second) = first, second
    real_write = getattr(store, attr)
    holding = asyncio.Event()
    release = asyncio.Event()
    holder: list[object] = []

    async def _hold(handle: Any) -> None:
        holder.append(await holder_of(handle))
        holding.set()
        await release.wait()

    class _PausingHandle:
        """``handle`` with its ``execute`` paused once, before the ``pause_before`` statement."""

        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def __getattr__(self, name: str) -> Any:
            return getattr(self._handle, name)

        async def execute(self, sql: str, *args: Any) -> Any:
            if not holder and pause_before is not None and sql.startswith(pause_before):
                await _hold(self._handle)
            return await self._handle.execute(sql, *args)

    async def _paused_write(handle: Any, written_key: str, change: Any) -> Any:
        if written_key != key or holder:
            return await real_write(handle, written_key, change)
        if pause_before is not None:
            return await real_write(_PausingHandle(handle), written_key, change)
        written = await real_write(handle, written_key, change)
        await _hold(handle)
        return written

    setattr(store, attr, _paused_write)
    tasks: list[asyncio.Task[Any]] = []
    try:
        running = asyncio.create_task(start_first())
        held = asyncio.create_task(holding.wait())
        tasks += [running, held]
        await asyncio.wait(
            {running, held}, timeout=_STEP_TIMEOUT, return_when=asyncio.FIRST_COMPLETED
        )
        if running.done():
            running.result()  # a call that failed before its pause raises its own error here
        assert holding.is_set(), f"{first_name} never reached {attr}"

        waiting = asyncio.create_task(start_second())
        tasks.append(waiting)
        queued = False
        for _ in range(_PROBE_POLLS):
            if waiting.done():
                break
            if await is_blocking(holder[0]):
                queued = True
                break
            await asyncio.sleep(_PROBE_INTERVAL)
        if waiting.done():
            waiting.result()  # a call that failed fast raises its own error here
            raise AssertionError(f"{second_name} finished while {first_name} held its row")
        assert queued, f"{second_name} never queued behind {first_name}, so the race did not run"

        release.set()
        first_result = await asyncio.wait_for(running, timeout=_STEP_TIMEOUT)
        second_result = await asyncio.wait_for(waiting, timeout=_STEP_TIMEOUT)
    finally:
        release.set()
        delattr(store, attr)  # the instance attribute only; the class method is untouched
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return first_result, second_result


async def _sweep_by_bind(store: Any, account: str) -> int:
    return int(await store.set_user_federated_subject(account, ISSUER, f"S-1-{account}", now=3.0))


async def _sweep_by_unbind(store: Any, account: str) -> int:
    outcome = await store.clear_user_federated_subject(
        account, expected_issuer=ISSUER, expected_subject=f"S-1-{account}", now=3.0
    )
    assert outcome is not None
    return int(outcome.sessions_revoked)


async def _sweep_by_revoke(store: Any, account: str) -> int:
    return int((await store.revoke_user_sessions(account, now=3.0)).count)


async def _sweep_every_account(store: Any, account: str) -> int:
    """The every-account revoke. It ends every live session in the store, so it runs last, when
    the earlier cases have ended theirs and the rotated session is the only one left."""
    return int((await store.revoke_all_sessions(now=3.0)).count)


#: Each sweep the race is replayed against, and whether its account starts bound.
_SWEEPS: tuple[tuple[str, Callable[[Any, str], Coroutine[Any, Any, int]], bool], ...] = (
    ("bind", _sweep_by_bind, False),
    ("unbind", _sweep_by_unbind, True),
    ("revoke", _sweep_by_revoke, False),
    ("revoke-all", _sweep_every_account, False),
)


async def _new_account(store: Any, account: str, *, bound: bool) -> None:
    await store.create_user(
        user_id=account,
        username=account,
        auth_provider="ad",
        now=1.0,
        password_generated=False,
        audits=(),
    )
    if bound:
        await store.set_user_federated_subject(account, ISSUER, f"S-1-{account}", now=1.0)


async def _assert_rotation_racing_a_sweep_is_swept(
    store: Any,
    *,
    holder_of: Callable[[Any], Awaitable[object]],
    is_blocking: Callable[[object], Awaitable[bool]],
) -> None:
    """A session rotated while a sweep runs is swept too (BACKLOG #4974, #2738).

    The rotation is paused after its locked read of the session row and before its re-key, so it
    holds the row under its OLD hash and has moved nothing yet. The sweep is started, and the probe
    requires that it really waits on the rotation. Released, the rotation re-keys and commits, and
    the sweep must end the session under its NEW hash. On SQL Server the re-key moves the row to a
    new clustered key, so a sweep waiting on the old key could find it gone and the new one outside
    its read; the new hash sorts before the old one, so a scan in key order has passed it too. On
    SQL Server the rotation takes the account row first, so the sweep waits there, before it reads
    any session. On Postgres the sweep waits on the session row and then follows the row to its new
    version. The bind, the unbind, a revoke of the user's sessions and the every-account revoke are
    each replayed. By the reading in ``rotate_session``, SQL Server without the account row first
    could count 0 and leave the new hash live, or deadlock, depending on the plan; that was not
    run.

    ``holder_of`` and ``is_blocking`` are the lock-order test's: no timing decides the race.
    """
    for name, sweep, bound in _SWEEPS:
        await _assert_one_sweep_takes_a_rotated_session(
            store, name, sweep, bound=bound, holder_of=holder_of, is_blocking=is_blocking
        )


async def _assert_one_sweep_takes_a_rotated_session(
    store: Any,
    name: str,
    sweep: Callable[[Any, str], Coroutine[Any, Any, int]],
    *,
    bound: bool,
    holder_of: Callable[[Any], Awaitable[object]],
    is_blocking: Callable[[object], Awaitable[bool]],
) -> None:
    account = f"fed-rotate-{name}"
    old, new = f"rs-z-{name}-old", f"rs-a-{name}-new"
    await _new_account(store, account, bound=bound)
    await store.create_session(token_hash=old, user_id=account, expires_at=_EXPIRES, now=2.0)

    rotated, swept = await _hold_then_race(
        store,
        attr="_write_session",
        key=old,
        first=(f"{name}: the rotation", lambda: store.rotate_session(old, new_token_hash=new)),
        second=(f"{name}: the sweep", lambda: sweep(store, account)),
        holder_of=holder_of,
        is_blocking=is_blocking,
        pause_before="UPDATE sessions",  # after the locked read, before the re-key moves the row
    )

    assert rotated is True, f"{name}: the rotation did not land"
    assert swept == 1, f"{name}: the sweep counted {swept}, not the rotated session"
    assert await store.get_session(old) is None, f"{name}: the old hash still has a row"
    assert not await _live(store, new), f"{name}: the rotated session outlived the sweep"


async def _assert_rotation_waits_for_a_bind(
    store: Any,
    *,
    holder_of: Callable[[Any], Awaitable[object]],
    is_blocking: Callable[[object], Awaitable[bool]],
) -> None:
    """The other order (BACKLOG #4974), on the store whose rotation takes the account row: a bind
    holds that row, and a rotation of one of its sessions waits for it, then re-keys nothing,
    because the bind ended the session."""
    account = "fed-rotate-after-bind"
    old, new = "rb-z-old", "rb-a-new"
    await _new_account(store, account, bound=False)
    await store.create_session(token_hash=old, user_id=account, expires_at=_EXPIRES, now=2.0)

    swept, rotated = await _hold_then_race(
        store,
        attr="_write_user",
        key=account,
        first=("the bind", lambda: _sweep_by_bind(store, account)),
        second=("the rotation", lambda: store.rotate_session(old, new_token_hash=new)),
        holder_of=holder_of,
        is_blocking=is_blocking,
    )

    assert swept == 1, swept
    assert rotated is False, "the rotation re-keyed a session the bind had ended"
    assert await store.get_session(new) is None
    assert not await _live(store, old)
