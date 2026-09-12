# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for ``get_user_by_directory_object_id`` (BACKLOG #1471).

**This is the lookup the whole name-recycle defence resolves through**, and it shipped with no
backend-level test on any of the three stores: SQLite's coverage was incidental (service-level
tests in ``tests/test_ad_directory_identity.py`` that happen to call it), and neither live suite
mentioned it at all. One shared body, invoked from all three suites, is what makes "the backends
agree" an assertion rather than a reading of three separately-worded tests.

Driven against the REAL store object on every leg. A fake implementing the same lookup would move
in lockstep with a broken one, so breaking the production code would change nothing the test sees.

**The case-comparison split is deliberate and is a real divergence.** The contract helper holds the
part all three backends agree on. ``_assert_directory_id_compare_is_byte_exact`` is called by SQLite
and PostgreSQL only: both compare the column byte-for-byte, so an id differing only in case resolves
to nothing. SQL Server delegates the comparison to the database collation and under a ``_CI_``
default would match, so that suite pins its own behaviour against the collation the server actually
reports. See ``store/sqlserver.py``'s note on the method.

Case is the divergence this module pins; it is not a claim that it is the only one. SQL Server's
``=`` is also trailing-space-insensitive where SQLite and PostgreSQL are not, which is unmeasured
here and unreachable through the normaliser for the same reason case is.
"""

from __future__ import annotations

from typing import Any

#: A bound account's directory id, in the ONE spelling ``auth/ldap.py``'s normaliser emits
#: (``str(uuid.UUID(...))`` -- lower-case, hyphenated, unbraced).
BOUND_GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
#: A second bound account, so "found by ITS id" is separable from "found the first bound row".
OTHER_GUID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
#: Bound to nobody. The lookup must return nothing rather than raising.
ABSENT_GUID = "00000000-0000-4000-8000-000000000000"
#: The case-comparison probe's own binding, so the two helpers stay independent of each other even
#: where a suite runs both against one store handle.
CASE_GUID = "7d444840-9dc0-11d1-b245-5ffdce74fad2"


async def _assert_directory_identity_contract(store: Any) -> None:
    """The behaviour every backend owes ``get_user_by_directory_object_id``.

    Three users: two bound to different directory ids, one with the column left NULL (an account
    created before the binding existed, or a local account that never had one).
    """
    await store.create_user(
        user_id="dir-bound",
        username="bound",
        auth_provider="ad",
        directory_object_id=BOUND_GUID,
        now=1_000.0,
    )
    await store.create_user(
        user_id="dir-other",
        username="other",
        auth_provider="ad",
        directory_object_id=OTHER_GUID,
        now=1_000.0,
    )
    await store.create_user(
        user_id="dir-unbound",
        username="unbound",
        auth_provider="local",
        password_hash="h",
        now=1_000.0,
    )

    # Precondition, not decoration: if the INSERT dropped the value the lookup below would be
    # asserting against a column nothing ever wrote, and every id query would correctly find
    # nothing. The round-trip has to be established before absence means anything.
    bound = await store.get_user("dir-bound")
    assert bound is not None and bound.directory_object_id == BOUND_GUID
    unbound = await store.get_user("dir-unbound")
    assert unbound is not None and unbound.directory_object_id is None

    # 1. A bound row is found by its own id -- and by ITS id, not merely by being bound. A lookup
    #    that ignored its argument would satisfy the first row's assertion and fail the second's.
    found = await store.get_user_by_directory_object_id(BOUND_GUID)
    assert found is not None and found.id == "dir-bound"
    other = await store.get_user_by_directory_object_id(OTHER_GUID)
    assert other is not None and other.id == "dir-other"

    # 2. An id bound to no row returns None. It must RETURN, not raise: this runs on the sign-in
    #    path for every directory account the engine has not seen before, which is the ordinary
    #    case on a first login, not an error.
    assert await store.get_user_by_directory_object_id(ABSENT_GUID) is None

    # 3. A NULL binding is never adopted, and the empty string is the spelling that would do it.
    #    SQL's three-valued logic makes `directory_object_id = ''` miss a NULL row on all three
    #    backends -- but a lookup rewritten to fold NULL to a match (COALESCE, IS NOT DISTINCT
    #    FROM, an OR on a falsy argument) would hand the unbound row to whoever asked for it.
    #    Every one of these must find nothing; none of them may find "dir-unbound".
    for falsy in ("", " ", "None", "null", "NULL"):
        assert await store.get_user_by_directory_object_id(falsy) is None, (
            f"an id lookup for {falsy!r} resolved to a row; a NULL binding is never adopted"
        )


async def _assert_directory_id_compare_is_byte_exact(store: Any) -> None:
    """SQLite and PostgreSQL compare this column byte-for-byte, so case is significant.

    Called by those two suites only. SQL Server takes the database's collation instead and pins its
    own behaviour; that divergence is recorded at ``store/sqlserver.py``'s copy of the method.

    Not reachable through the login path today -- ``auth/ldap.py`` normalises every ``objectGUID``
    to one case before it reaches the store -- so this pins the property a reader would assume of
    the store, and the normaliser stays the reason the divergence cannot be exercised.
    """
    await store.create_user(
        user_id="dir-case",
        username="case",
        auth_provider="ad",
        directory_object_id=CASE_GUID,
        now=1_000.0,
    )
    # The control is what makes the miss below a fact about CASE rather than about the row being
    # absent, the column being unwritten, or the id being misspelt in this file.
    exact = await store.get_user_by_directory_object_id(CASE_GUID)
    assert exact is not None and exact.id == "dir-case"
    assert await store.get_user_by_directory_object_id(CASE_GUID.upper()) is None


async def _assert_the_binding_column_is_unconstrained_and_username_is_not(store: Any) -> None:
    """The layer UNDER the lookup: what refuses a racing double-bind, and what does not.

    ``directory_object_id`` carries **no uniqueness constraint on any backend**, unlike its
    federated sibling ``(oidc_issuer, oidc_subject)``, which all three back with
    ``ux_users_federated_subject``. That asymmetry is deliberate and the schema comments state the
    reason: the resolver never writes a second row for an id it has already seen, and
    ``UNIQUE(username)`` is what refuses a racing double-create.

    Nothing asserted either half. This pins both, because a compensating control nobody tests is
    one nobody notices losing -- and a unique index added to ONE backend's schema and not the other
    two would split the three stores silently, which is the drift this module exists to catch.
    """
    await store.create_user(
        user_id="dup-first",
        username="first",
        auth_provider="ad",
        directory_object_id=BOUND_GUID,
        now=1_000.0,
    )

    # 1. The column itself permits a second row on the same id. Asserting this is not endorsing the
    #    state -- no shipped path produces it -- it is pinning that the refusal below is the ONLY
    #    thing standing there, so a future index becomes a deliberate change to this test.
    await store.create_user(
        user_id="dup-second",
        username="second",
        auth_provider="ad",
        directory_object_id=BOUND_GUID,
        now=1_000.0,
    )

    # 2. The control that IS in force: a repeated username violates UNIQUE(username) with the
    #    backend's native integrity error (sqlite3.IntegrityError / asyncpg UniqueViolationError /
    #    pyodbc.IntegrityError). Two concurrent first logins for one directory object present the
    #    same sAMAccountName, so this is what refuses the second INSERT.
    try:
        await store.create_user(
            user_id="dup-third",
            username="first",
            auth_provider="ad",
            directory_object_id=OTHER_GUID,
            now=1_000.0,
        )
    except Exception as exc:  # noqa: BLE001 - each backend raises its own integrity class
        name = type(exc).__name__ + "".join(t.__name__ for t in type(exc).__mro__)
        assert "Integrity" in name or "UniqueViolation" in name, (
            f"a duplicate username raised {type(exc).__name__}, not an integrity violation"
        )
    else:
        raise AssertionError(
            "a duplicate username was accepted; UNIQUE(username) is the documented reason"
            " directory_object_id needs no uniqueness constraint of its own"
        )
