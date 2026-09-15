# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for ``increment_login_failure`` -- the account-lockout counter.

The counter used to be read in the auth service, incremented in Python and written back through
``record_login_failure``, with the argon2 verify sitting between the read and the write. Failures
submitted in parallel therefore all read the same pre-increment count, the account never crossed
``lockout_threshold``, and an attacker who parallelizes would evade the lockout entirely on a first
deployment. The read, the lapsed-window reset, the increment and the lock decision now happen inside
ONE store call per backend: SQLite under its store lock, PostgreSQL under ``SELECT ... FOR UPDATE``,
SQL Server under ``UPDLOCK``.

**Three separate SQL bodies implement one security policy, which is what this module is for.** One
shared body, invoked from all three suites, makes "the backends agree" an assertion rather than a
reading of three separately-worded tests -- and it is the only thing that executes the PostgreSQL and
SQL Server row-lock paths at all, exactly the gap ``_assert_totp_contract`` was written to close for
the TOTP methods.

**WHAT THIS DOES NOT ASSERT, stated because the name invites the wrong reading.** It is SEQUENTIAL. It
pins the POLICY each backend's atomic call must implement; it does not drive concurrent connections
at a live server, so it cannot by itself prove the ``FOR UPDATE`` / ``UPDLOCK`` clause is doing its
job. The concurrency proof is
``tests/test_mfa.py::test_parallel_wrong_credentials_cannot_evade_the_account_lockout``, which runs
parallel wrong passwords and parallel wrong TOTP codes through the real service on SQLite. A future
multi-connection arm against a live backend would be a strict addition here, not a replacement.

Deliberately **extra-free**: it imports nothing outside ``AuthStore``, so the live PostgreSQL and SQL
Server legs can import it inside their test functions and run it on CI legs that install neither the
webauthn nor the harness extra.
"""

from __future__ import annotations

from typing import Any

#: Small so the arithmetic below is readable; the shipped default is 5.
THRESHOLD = 3
#: Seconds a lock lasts in this contract. Long enough that "now" during the test is inside it.
LOCKOUT_SECONDS = 900.0


async def _assert_lockout_contract(store: Any) -> None:
    """The behaviour every backend owes ``increment_login_failure``.

    Returns ``(failed_attempts, just_locked)``. ``just_locked`` is True only for the attempt that
    takes the account from unlocked to locked, so a caller can fire exactly one ACCOUNT_LOCKED notice
    per lockout even when a burst arrives past its own locked-account pre-check.
    """
    await store.create_user(
        user_id="lock-u1", username="lock-alice", auth_provider="local", password_hash="h", now=1.0
    )
    t0 = 1_000.0

    # --- climbing to the threshold: each call counts, and only the crossing one reports True -------
    assert await store.increment_login_failure(
        "lock-u1", threshold=THRESHOLD, lockout_seconds=LOCKOUT_SECONDS, now=t0
    ) == (1, False)
    assert await store.increment_login_failure(
        "lock-u1", threshold=THRESHOLD, lockout_seconds=LOCKOUT_SECONDS, now=t0 + 1.0
    ) == (2, False)
    assert await store.increment_login_failure(
        "lock-u1", threshold=THRESHOLD, lockout_seconds=LOCKOUT_SECONDS, now=t0 + 2.0
    ) == (3, True)
    user = await store.get_user("lock-u1")
    assert user is not None and user.failed_attempts == 3
    # The lock is PERSISTED, not merely counted: a run that reaches the threshold while
    # `locked_until` stays NULL admits the very next guess, so the count alone cannot discriminate.
    assert user.locked_until == t0 + 2.0 + LOCKOUT_SECONDS

    # --- an attempt landing INSIDE a live lock extends it and must NOT re-report the crossing ------
    # This is the burst case: past the threshold every further attempt arrives while the lock is set,
    # and a second True here would be a second lockout notification for one lockout.
    assert await store.increment_login_failure(
        "lock-u1", threshold=THRESHOLD, lockout_seconds=LOCKOUT_SECONDS, now=t0 + 3.0
    ) == (4, False)
    user = await store.get_user("lock-u1")
    assert user is not None and user.locked_until == t0 + 3.0 + LOCKOUT_SECONDS

    # --- a LAPSED window restarts the counter and clears the stale lock ----------------------------
    # One post-lockout failure must not re-lock immediately, and the expired `locked_until` must go
    # rather than linger on a row whose count is back below the threshold.
    lapsed = t0 + 3.0 + LOCKOUT_SECONDS + 1.0
    assert await store.increment_login_failure(
        "lock-u1", threshold=THRESHOLD, lockout_seconds=LOCKOUT_SECONDS, now=lapsed
    ) == (1, False)
    user = await store.get_user("lock-u1")
    assert user is not None and user.failed_attempts == 1 and user.locked_until is None

    # --- a successful login clears both columns, so the next run starts from zero ------------------
    await store.record_login_success("lock-u1", now=lapsed + 1.0)
    assert await store.increment_login_failure(
        "lock-u1", threshold=THRESHOLD, lockout_seconds=LOCKOUT_SECONDS, now=lapsed + 2.0
    ) == (1, False)

    # --- threshold 1 locks on the FIRST failure, which is why the doc says it is not an off switch -
    await store.record_login_success("lock-u1", now=lapsed + 3.0)
    assert await store.increment_login_failure(
        "lock-u1", threshold=1, lockout_seconds=LOCKOUT_SECONDS, now=lapsed + 4.0
    ) == (1, True)

    # --- an unknown user counts nothing and raises nothing -----------------------------------------
    assert await store.increment_login_failure(
        "no-such-user", threshold=THRESHOLD, lockout_seconds=LOCKOUT_SECONDS, now=t0
    ) == (0, False)

    await store.delete_user("lock-u1")
