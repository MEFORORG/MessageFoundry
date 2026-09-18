# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for ``clear_user_federated_subject`` (BACKLOG #1474).

The method NULLs an account's federated ``(issuer, sub)`` pair and revokes its live sessions in one
transaction. One shared body, run by the SQLite, PostgreSQL and SQL Server suites, so "the three
backends agree" is an assertion rather than a reading of three separately-worded tests. The two
server legs run only in CI, so that is where their bodies first execute.

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

    # 1. The unbind returns the count it revoked: the two live sessions, not the revoked one.
    revoked = await store.clear_user_federated_subject("fed-first", now=2_000.0)
    assert revoked == 2, f"expected the two live sessions revoked, got {revoked}"

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

    # 5. A second unbind of the same account revokes nothing more.
    assert await store.clear_user_federated_subject("fed-first", now=3_000.0) == 0

    # 6. Two unbound rows coexist with a never-bound one under ux_users_federated_subject. The
    #    filtered index admits any number of NULL pairs; an unfiltered one on SQL Server would
    #    refuse the second. Step 8 is the control that makes this more than an absence of errors.
    assert await store.clear_user_federated_subject("fed-second", now=2_000.0) == 1
    for uid in ("fed-first", "fed-second", "fed-never"):
        row = await store.get_user(uid)
        assert row is not None and row.oidc_issuer is None and row.oidc_subject is None, uid

    # 7. A re-bind after the unbind succeeds, to a DIFFERENT subject: the account is free again.
    await store.set_user_federated_subject("fed-first", ISSUER, REBOUND_SUB, now=4_000.0)
    rebound = await store.get_user_by_federated_subject(ISSUER, REBOUND_SUB)
    assert rebound is not None and rebound.id == "fed-first"

    # 8. POSITIVE CONTROL, and LAST on purpose. The index is live on this backend: a second account
    #    taking a bound pair is refused with the backend's own integrity class. Last because on
    #    SQLite a refused bind leaves the writer connection inside an implicit transaction, and the
    #    next writer that opens its own would fail on BEGIN.
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
