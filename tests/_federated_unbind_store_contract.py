# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for the federated unbind and its session guard (BACKLOG #1474).

``clear_user_federated_subject`` NULLs an account's federated ``(issuer, sub)`` pair, revokes its
live sessions, and reports the pair it cleared -- all in one transaction.
``create_session(require_federated_subject=...)`` is the other half: it makes a session insert
conditional on that pair still being there, so a login already in flight cannot outrun the unbind.
One shared body each, run by the SQLite, PostgreSQL and SQL Server suites, so "the three backends
agree" is an assertion rather than a reading of three separately-worded tests. The two server legs
run only in CI, so that is where their bodies first execute.

Driven against the REAL store object on every leg. A fake would move in lockstep with a broken
implementation and the test would see nothing.
"""

from __future__ import annotations

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
        await store.create_user(user_id=uid, username=uid, auth_provider="ad", now=1_000.0)
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
    outcome = await store.clear_user_federated_subject("fed-first", now=2_000.0)
    assert outcome is not None
    assert outcome.sessions_revoked == 2, f"expected two live sessions revoked, got {outcome}"
    assert (outcome.issuer, outcome.subject) == (ISSUER, FIRST_SUB)
    assert outcome.username == "fed-first"

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

    # 5. A second unbind of the same account writes NOTHING. The account is given a LIVE session
    #    first, because "revoked 0" is what a call that revoked nothing AND a call that had nothing
    #    to revoke both report -- only a session that survives tells them apart. An unbind of
    #    nothing must not sign anybody out, and the untouched updated_at says nothing was written.
    await store.create_session(
        token_hash="t-first-after", user_id="fed-first", expires_at=_EXPIRES, now=2_500.0
    )
    noop = await store.clear_user_federated_subject("fed-first", now=3_000.0)
    assert noop is not None
    assert (noop.issuer, noop.subject, noop.sessions_revoked) == (None, None, 0)
    assert noop.username == "fed-first"
    survivor = await store.get_session("t-first-after")
    assert survivor is not None and survivor.revoked_at is None, (
        "an unbind of an already-unbound account revoked a live session"
    )
    still = await store.get_user("fed-first")
    assert still is not None and still.updated_at == 2_000.0

    # 5b. An unknown user is reported as such rather than as an account with no binding, so the
    #     caller can tell "no such user" from "nothing to unbind" without a second read.
    assert await store.clear_user_federated_subject("fed-nobody", now=3_000.0) is None

    # 6. Two unbound rows coexist with a never-bound one under ux_users_federated_subject. The
    #    filtered index admits any number of NULL pairs; an unfiltered one on SQL Server would
    #    refuse the second. Step 8 is the control that makes this more than an absence of errors.
    second_unbind = await store.clear_user_federated_subject("fed-second", now=2_000.0)
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
    store: Any, token: str, pair: tuple[str, str] | None, *, user: str = GUARD_USER
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
    await store.create_user(user_id=GUARD_USER, username=GUARD_USER, auth_provider="ad", now=1.0)
    await store.set_user_federated_subject(GUARD_USER, ISSUER, GUARD_SUB, now=1.0)

    # 1. Bound to the pair the caller verified: the row is written and the call says so.
    assert await _guarded_session(store, "g-ok", (ISSUER, GUARD_SUB)) is True

    # 2. CONTROL. A pair that does not match is refused, and nothing is written. Without this a
    #    guard that always returned True would still pass step 1.
    assert await _guarded_session(store, "g-wrong", (ISSUER, "S-1-somebody-else")) is False

    # 3. THE CASE THE GUARD EXISTS FOR. After the unbind the same verified pair no longer names this
    #    account, so the login that was carrying it cannot mint a session the unbind's revocation
    #    never saw.
    assert await store.clear_user_federated_subject(GUARD_USER, now=2.0) is not None
    assert await _guarded_session(store, "g-after-unbind", (ISSUER, GUARD_SUB)) is False

    # 4. A user that does not exist is refused rather than inserted against a missing row.
    assert (
        await _guarded_session(store, "g-nobody", (ISSUER, GUARD_SUB), user="fed-guard-nobody")
        is False
    )

    # 5. CONTROL for step 3. With no guard requested the SAME unbound account still takes a session,
    #    so the refusals above came from the guard and not from anything else about the row.
    assert await _guarded_session(store, "g-unguarded", None) is True
