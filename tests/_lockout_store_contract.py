# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for the account-lockout counters (ADR 0197, BACKLOG #1131).

The counter used to be read in the auth service, incremented in Python and written back through
``record_login_failure``, with the argon2 verify sitting between the read and the write. Failures
submitted in parallel therefore all read the same pre-increment count, the account never crossed
``lockout_threshold``, and an attacker who parallelizes would evade the lockout entirely on a first
deployment. The read, the lapsed-window reset, the increment and the lock decision now happen inside
ONE store call per backend: SQLite under its store lock, PostgreSQL under ``SELECT ... FOR UPDATE``,
SQL Server under ``UPDLOCK``.

**ADR 0197 split that one counter in two and made the lock length escalate per cycle.** The sign-in
counter counts wrong passwords from a caller who has proved nothing. The second-step counter counts
failures from a caller who has already proved one factor. Each carries its own lock and its own cycle
count, and each lock doubles per cycle up to a ceiling only where the ADR says the owner has a way
past it: the second-step lock on a local account, and the sign-in lock on a local account with TOTP
enrolled. Every other lock keeps the fixed ``lockout_seconds``. The store decides which, from
``auth_provider`` and ``totp_enabled`` read in the same locked ``SELECT`` as the count.

**Three separate SQL bodies implement one security policy, which is what this module is for.** One
shared body, invoked from all three suites, makes "the backends agree" an assertion rather than a
reading of three separately-worded tests -- and it is the only thing that executes the PostgreSQL and
SQL Server row-lock paths at all, exactly the gap ``_assert_totp_contract`` was written to close for
the TOTP methods.

**WHAT THIS DOES NOT ASSERT, stated because the name invites the wrong reading.** It is SEQUENTIAL. It
pins the POLICY each backend's atomic call must implement; it does not drive concurrent connections
at a live server, so it cannot by itself prove the ``FOR UPDATE`` / ``UPDLOCK`` clause is doing its
job. The concurrency proof is
``tests/test_mfa.py::test_parallel_store_increments_each_land_and_lock_once``, which drives
parallel calls into the SQLite store directly. The service-level burst,
``tests/test_mfa.py::test_parallel_wrong_credentials_cannot_evade_the_account_lockout``, no longer
reaches the store concurrently: since BACKLOG #1943 the service queues attempts on one account. A
future multi-connection arm against a live backend would be a strict addition here, not a
replacement.

Every arm that checks a lock also reads the OTHER counter back, because a lock test that only asserts
a refusal passes against a store that never counted, and a split that leaks one counter into the
other passes every single-counter assertion.

Deliberately **extra-free**: it imports nothing outside ``AuthStore``, so the live PostgreSQL and SQL
Server legs can import it inside their test functions and run it on CI legs that install neither the
webauthn nor the harness extra.
"""

from __future__ import annotations

from typing import Any

#: Small so the arithmetic below is readable; the shipped default is 5.
THRESHOLD = 3
#: Seconds a first lock lasts in this contract. Long enough that "now" during the test is inside it.
LOCKOUT_SECONDS = 900.0
#: The escalation ceiling in this contract: 8 x the base, so four doublings reach it.
MAX_LOCKOUT_SECONDS = 7_200.0


def _lockout_columns(user: Any) -> tuple[Any, ...]:
    """Every lockout column on a user row, in one tuple, so an arm can assert "nothing else moved"."""
    return (
        user.failed_attempts,
        user.locked_until,
        user.lock_cycles,
        user.second_step_failed_attempts,
        user.second_step_locked_until,
        user.second_step_lock_cycles,
    )


async def _fail(
    store: Any,
    user_id: str,
    *,
    now: float,
    counter: str = "sign_in",
    threshold: int = THRESHOLD,
    lockout_seconds: float = LOCKOUT_SECONDS,
) -> tuple[int, bool, int]:
    result = await store.increment_login_failure(
        user_id,
        counter=counter,
        threshold=threshold,
        lockout_seconds=lockout_seconds,
        max_lockout_seconds=MAX_LOCKOUT_SECONDS,
        now=now,
    )
    return (result.attempts, result.just_locked, result.cycles)


async def _lock_cycle(store: Any, user_id: str, *, start: float, counter: str) -> float:
    """Run one full cycle: THRESHOLD failures from ``start``. Returns the new ``locked_until``."""
    for i in range(THRESHOLD):
        await _fail(store, user_id, now=start + i, counter=counter)
    user = await store.get_user(user_id)
    assert user is not None
    locked = user.locked_until if counter == "sign_in" else user.second_step_locked_until
    assert locked is not None, f"a full run of {counter} failures set no lock"
    return float(locked)


async def _assert_lockout_contract(store: Any) -> None:
    """The behaviour every backend owes ``increment_login_failure`` and the lockout writers."""
    await _assert_single_counter_policy(store)
    await _assert_escalation(store)
    await _assert_counters_stay_apart_and_clear(store)
    await _assert_generated_credential(store)
    await _assert_conditional_rotation(store)


async def _assert_single_counter_policy(store: Any) -> None:
    """The per-cycle policy, on the sign-in counter of an account that does NOT escalate."""
    await store.create_user(
        user_id="lock-u1",
        username="lock-alice",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )
    t0 = 1_000.0

    # --- climbing to the threshold: each call counts, and only the crossing one reports True -------
    assert await _fail(store, "lock-u1", now=t0) == (1, False, 0)
    assert await _fail(store, "lock-u1", now=t0 + 1.0) == (2, False, 0)
    assert await _fail(store, "lock-u1", now=t0 + 2.0) == (3, True, 1)
    user = await store.get_user("lock-u1")
    assert user is not None and user.failed_attempts == 3 and user.lock_cycles == 1
    # The lock is PERSISTED, not merely counted: a run that reaches the threshold while
    # `locked_until` stays NULL admits the very next guess, so the count alone cannot discriminate.
    assert user.locked_until == t0 + 2.0 + LOCKOUT_SECONDS

    # --- AC-10a: an attempt landing INSIDE a live lock COUNTS but moves neither expiry nor cycles --
    # This is the burst case: past the threshold every further attempt arrives while the lock is set.
    # A second True here would be a second notice for one lockout, and an extended expiry would let
    # a caller who knows only the username keep pushing the lock out one attempt at a time.
    assert await _fail(store, "lock-u1", now=t0 + 3.0) == (4, False, 1)
    user = await store.get_user("lock-u1")
    assert user is not None and user.locked_until == t0 + 2.0 + LOCKOUT_SECONDS
    assert user.lock_cycles == 1

    # --- a LAPSED window restarts the counter and clears the stale lock, and keeps the cycle -------
    lapsed = t0 + 2.0 + LOCKOUT_SECONDS + 1.0
    assert await _fail(store, "lock-u1", now=lapsed) == (1, False, 1)
    user = await store.get_user("lock-u1")
    assert user is not None and user.failed_attempts == 1 and user.locked_until is None
    assert user.lock_cycles == 1

    # --- no TOTP enrolled: the sign-in lock keeps the FIXED length on every cycle -------------------
    # The failure at ``lapsed`` was attempt 1, so this cycle's second call is the crossing one.
    second = await _lock_cycle(store, "lock-u1", start=lapsed + 1.0, counter="sign_in")
    assert second == lapsed + 2.0 + LOCKOUT_SECONDS
    user = await store.get_user("lock-u1")
    assert user is not None and user.lock_cycles == 2

    # --- a successful login clears every lockout column, cycles included (AC-8) --------------------
    await store.record_login_success("lock-u1", now=second + 1.0)
    user = await store.get_user("lock-u1")
    assert user is not None and _lockout_columns(user) == (0, None, 0, 0, None, 0)
    assert await _fail(store, "lock-u1", now=second + 2.0) == (1, False, 0)

    # --- threshold 1 locks on the FIRST failure, which is why the doc says it is not an off switch -
    await store.record_login_success("lock-u1", now=second + 3.0)
    assert await _fail(store, "lock-u1", now=second + 4.0, threshold=1) == (1, True, 1)

    # --- lockout_minutes = 0 still means "the lock expires at once", escalated or not --------------
    await store.record_login_success("lock-u1", now=second + 5.0)
    assert await _fail(store, "lock-u1", now=second + 6.0, threshold=1, lockout_seconds=0.0) == (
        1,
        True,
        1,
    )
    user = await store.get_user("lock-u1")
    assert user is not None and user.locked_until == second + 6.0

    # --- an unknown user counts nothing and raises nothing -----------------------------------------
    assert await _fail(store, "no-such-user", now=t0) == (0, False, 0)
    assert await _fail(store, "no-such-user", now=t0, counter="second_step") == (0, False, 0)

    await store.delete_user("lock-u1")


async def _assert_escalation(store: Any) -> None:
    """AC-7: which locks double per cycle up to the ceiling, and which keep the fixed length."""
    # A local account with TOTP enrolled: BOTH locks escalate.
    await store.create_user(
        user_id="lock-totp",
        username="lock-totp",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )
    await store.set_totp_secret("lock-totp", secret="JBSWY3DPEHPK3PXP", now=1.0)
    await store.enable_totp("lock-totp", recovery_code_hashes=[], now=1.0)
    # A directory account, with TOTP enrolled too: NEITHER lock escalates (ADR 0197 Decision 5).
    await store.create_user(
        user_id="lock-ad", username="lock-ad", auth_provider="ad", now=1.0, password_generated=False
    )
    await store.set_totp_secret("lock-ad", secret="JBSWY3DPEHPK3PXP", now=1.0)
    await store.enable_totp("lock-ad", recovery_code_hashes=[], now=1.0)
    # A local account with no TOTP: only the second-step lock escalates.
    await store.create_user(
        user_id="lock-plain",
        username="lock-plain",
        auth_provider="local",
        password_hash="h",
        password_generated=False,
    )

    expected_escalated = [LOCKOUT_SECONDS * 2**k for k in range(4)] + [MAX_LOCKOUT_SECONDS] * 2
    cases = (
        ("lock-totp", "sign_in", expected_escalated),
        ("lock-totp", "second_step", expected_escalated),
        ("lock-plain", "second_step", expected_escalated),
        ("lock-plain", "sign_in", [LOCKOUT_SECONDS] * 6),
        ("lock-ad", "sign_in", [LOCKOUT_SECONDS] * 6),
        ("lock-ad", "second_step", [LOCKOUT_SECONDS] * 6),
    )
    for user_id, counter, lengths in cases:
        start = 10_000.0
        for cycle, length in enumerate(lengths, start=1):
            locked = await _lock_cycle(store, user_id, start=start, counter=counter)
            crossing = start + THRESHOLD - 1
            assert locked - crossing == length, (
                f"{user_id} {counter} cycle {cycle}: lock of {locked - crossing}s, expected {length}s"
            )
            user = await store.get_user(user_id)
            assert user is not None
            cycles = user.lock_cycles if counter == "sign_in" else user.second_step_lock_cycles
            assert cycles == cycle
            start = locked + 1.0  # the next cycle starts after this lock lapses
        await store.record_login_success(user_id, now=start)

    # --- the exponent is capped before it is computed, so a huge stored count cannot overflow -----
    start = 20_000.0
    for _ in range(80):
        locked = await _lock_cycle(store, "lock-totp", start=start, counter="second_step")
        start = locked + 1.0
    user = await store.get_user("lock-totp")
    assert user is not None and user.second_step_lock_cycles == 80
    assert user.second_step_locked_until == start - 1.0

    for user_id in ("lock-totp", "lock-ad", "lock-plain"):
        await store.delete_user(user_id)


async def _assert_counters_stay_apart_and_clear(store: Any) -> None:
    """The two counters never write each other's columns, and each writer clears what the ADR says."""
    await store.create_user(
        user_id="lock-u2",
        username="lock-bob",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )
    t0 = 30_000.0
    # Two cycles of the sign-in lock, then two of the second-step lock, on one row.
    first = await _lock_cycle(store, "lock-u2", start=t0, counter="sign_in")
    signed = await _lock_cycle(store, "lock-u2", start=first + 1.0, counter="sign_in")
    user = await store.get_user("lock-u2")
    assert user is not None
    assert (user.second_step_failed_attempts, user.second_step_locked_until) == (0, None)
    assert user.second_step_lock_cycles == 0

    step_start = signed + 1.0
    step_first = await _lock_cycle(store, "lock-u2", start=step_start, counter="second_step")
    step_until = await _lock_cycle(store, "lock-u2", start=step_first + 1.0, counter="second_step")
    user = await store.get_user("lock-u2")
    assert user is not None
    # The sign-in columns are exactly as the sign-in cycles left them.
    assert (user.failed_attempts, user.locked_until, user.lock_cycles) == (THRESHOLD, signed, 2)
    assert (user.second_step_failed_attempts, user.second_step_lock_cycles) == (THRESHOLD, 2)
    assert user.second_step_locked_until == step_until

    # --- AC-10b: the hash-only write the login-time rehash uses touches no lockout column ----------
    before = _lockout_columns(user)
    await store.set_password_hash("lock-u2", password_hash="h2", now=step_until - 1.0)
    user = await store.get_user("lock-u2")
    assert user is not None and user.password_hash == "h2"
    assert _lockout_columns(user) == before

    # --- AC-9: clear_lockout clears both locks and both counts, and KEEPS both cycle counts --------
    await store.clear_lockout("lock-u2", now=step_until - 1.0)
    user = await store.get_user("lock-u2")
    assert user is not None and _lockout_columns(user) == (0, None, 2, 0, None, 2)
    assert user.password_hash == "h2", "an unlock must never touch the credential"
    # ... and zeroes them too when the operator says the campaign is over.
    await store.clear_lockout("lock-u2", reset_cycles=True, now=step_until)
    user = await store.get_user("lock-u2")
    assert user is not None and _lockout_columns(user) == (0, None, 0, 0, None, 0)

    # --- a password change clears both locks and the SECOND-STEP cycles, and keeps sign-in cycles --
    await _lock_cycle(store, "lock-u2", start=step_until + 1.0, counter="sign_in")
    await _lock_cycle(store, "lock-u2", start=step_until + 10.0, counter="second_step")
    await store.set_password(
        "lock-u2",
        password_hash="h3",
        must_change_password=True,
        now=step_until + 20.0,
        password_generated=False,
    )
    user = await store.get_user("lock-u2")
    assert user is not None and _lockout_columns(user) == (0, None, 1, 0, None, 0)

    await store.delete_user("lock-u2")


async def _assert_generated_credential(store: Any) -> None:
    """ADR 0197 Amendment A, AC-A1: while the credential in force is engine-generated, sign-in
    failures COUNT and never set the sign-in lock; the second-step lock still arms; each writer of a
    hash stores exactly the flag its caller states, and the login-time rehash leaves it alone."""
    await store.create_user(
        user_id="gen-u1",
        username="gen-alice",
        auth_provider="local",
        password_hash="h",
        must_change_password=True,
        password_generated=True,
        now=1.0,
    )
    user = await store.get_user("gen-u1")
    assert user is not None and user.password_generated is True, "create_user dropped the flag"

    # --- AC-A1: hammered far past the threshold, the sign-in lock is never set ----------------------
    t0 = 40_000.0
    for i in range(THRESHOLD * 4):
        assert await _fail(store, "gen-u1", now=t0 + i) == (i + 1, False, 0)
    user = await store.get_user("gen-u1")
    assert user is not None
    # Every attempt counted, and nothing locked: the count is the lock-state surface's signal.
    assert (user.failed_attempts, user.locked_until, user.lock_cycles) == (THRESHOLD * 4, None, 0)

    # --- the second-step counter is unchanged: whoever feeds it already proved a factor -------------
    locked = await _lock_cycle(store, "gen-u1", start=t0 + 100.0, counter="second_step")
    user = await store.get_user("gen-u1")
    assert user is not None and user.second_step_locked_until == locked
    assert user.locked_until is None, "a second-step lock leaked into the sign-in columns"

    # --- the rehash write leaves the flag alone ----------------------------------------------------
    await store.set_password_hash("gen-u1", password_hash="h-rehashed", now=t0 + 200.0)
    user = await store.get_user("gen-u1")
    assert user is not None and user.password_generated is True

    # --- set_password stores what its caller states, both ways --------------------------------------
    assert await store.set_password(
        "gen-u1", password_hash="h-chosen", password_generated=False, must_change_password=False
    )
    user = await store.get_user("gen-u1")
    assert user is not None and user.password_generated is False
    # ... and a chosen credential is lockable again, at the shipped policy.
    start = t0 + 300.0
    for i in range(THRESHOLD - 1):
        await _fail(store, "gen-u1", now=start + i)
    assert (await _fail(store, "gen-u1", now=start + THRESHOLD))[1] is True
    assert await store.set_password(
        "gen-u1", password_hash="h-issued", password_generated=True, must_change_password=True
    )
    user = await store.get_user("gen-u1")
    assert user is not None and user.password_generated is True
    # A generated credential's write also clears the lock the chosen one had (the password change
    # clear), so the issued credential starts unlocked.
    assert user.locked_until is None

    # --- create_user stores False when told False, and refuses a flagged row with no hash ----------
    await store.create_user(
        user_id="gen-u2",
        username="gen-bob",
        auth_provider="local",
        password_hash="h",
        password_generated=False,
        now=1.0,
    )
    user = await store.get_user("gen-u2")
    assert user is not None and user.password_generated is False
    try:
        await store.create_user(
            user_id="gen-u3",
            username="gen-carol",
            auth_provider="local",
            password_hash=None,
            password_generated=True,
            now=1.0,
        )
    except ValueError:
        pass
    else:  # pragma: no cover - the assertion is the failure
        raise AssertionError("a generated flag on a hashless row was accepted")
    assert await store.get_user("gen-u3") is None

    for user_id in ("gen-u1", "gen-u2"):
        await store.delete_user(user_id)


async def _assert_conditional_rotation(store: Any) -> None:
    """ADR 0197 Amendment A, N-B2 part 4: a rotation that requires TOTP carries the condition in its
    own UPDATE, so TOTP cleared between the caller's check and the write makes the write match no
    row -- and the credential in force is left exactly as it was."""
    await store.create_user(
        user_id="rot-u1",
        username="rot-alice",
        auth_provider="local",
        password_hash="h-issued",
        must_change_password=True,
        password_generated=True,
        now=1.0,
    )
    # No TOTP: the conditional write is refused and changes nothing.
    assert not await store.set_password(
        "rot-u1",
        password_hash="h-chosen",
        password_generated=False,
        must_change_password=False,
        require_totp=True,
    )
    user = await store.get_user("rot-u1")
    assert user is not None
    assert (user.password_hash, user.password_generated, user.must_change_password) == (
        "h-issued",
        True,
        True,
    )
    # TOTP on: the caller "checks" here and sees it...
    await store.set_totp_secret("rot-u1", secret="JBSWY3DPEHPK3PXP", now=2.0)
    await store.enable_totp("rot-u1", recovery_code_hashes=[], now=2.0)
    user = await store.get_user("rot-u1")
    assert user is not None and user.totp_enabled
    # ... then an administrator's factor reset lands between the check and the write ...
    await store.disable_totp("rot-u1", now=3.0)
    # ... and the write refuses, because the condition rides in the UPDATE itself.
    assert not await store.set_password(
        "rot-u1",
        password_hash="h-chosen",
        password_generated=False,
        must_change_password=False,
        require_totp=True,
    )
    user = await store.get_user("rot-u1")
    assert user is not None and user.password_hash == "h-issued" and user.password_generated
    # With TOTP standing, the same write lands.
    await store.set_totp_secret("rot-u1", secret="JBSWY3DPEHPK3PXP", now=4.0)
    await store.enable_totp("rot-u1", recovery_code_hashes=[], now=4.0)
    assert await store.set_password(
        "rot-u1",
        password_hash="h-chosen",
        password_generated=False,
        must_change_password=False,
        require_totp=True,
    )
    user = await store.get_user("rot-u1")
    assert user is not None
    assert (user.password_hash, user.password_generated, user.must_change_password) == (
        "h-chosen",
        False,
        False,
    )
    # An unknown user matches no row either way.
    assert not await store.set_password(
        "no-such-user", password_hash="x", password_generated=False, must_change_password=False
    )
    await store.delete_user("rot-u1")
