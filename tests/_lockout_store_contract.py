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
past it: the second-step lock on a local account, and the sign-in lock on a local account with a
TOTP enrolled, unless the caller's ``totp_usable`` rule KNOWS the enrolment is refused. A TOTP it
cannot judge escalates, and so does a refused one whose judgement is missing (the race arms
below). Every other lock keeps the fixed ``lockout_seconds``. The store decides which, from
``auth_provider`` read in the same locked ``SELECT`` as the count and, for the sign-in lock, a
refusal judged by the caller's rule before the lock, only for a failure whose pre-lock read says it
would set a later-cycle lock, on a cell the locked row must still hold (BACKLOG #3422). The rule is a required
argument, so no call omits it.

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

import pytest

from messagefoundry.auth.service import _opened_totp_state
from messagefoundry.auth.tokens import credential_id_hash

#: Discoverable passkeys stored under today's credential-id hash scheme (BACKLOG #3423): only such a
#: row is a way past the sign-in lock, since only it can sign in.
_PK_RESIDENT = credential_id_hash(b"rot-pk-resident")
_PK_AGAIN = credential_id_hash(b"rot-pk-again")
_RF_RESIDENT = credential_id_hash(b"rot-rf-resident")
_LOCK_PK = credential_id_hash(b"lock-pk-resident")
_LOCK_PK_PLAIN = credential_id_hash(b"lock-pk-plain")
_LOCK_PK_AD = credential_id_hash(b"lock-pk-ad-resident")

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
    passkey_escalates: Any = None,
) -> tuple[int, bool, int]:
    result = await store.increment_login_failure(
        user_id,
        counter=counter,
        threshold=threshold,
        lockout_seconds=lockout_seconds,
        max_lockout_seconds=MAX_LOCKOUT_SECONDS,
        now=now,
        # The service's rule (BACKLOG #3422), a required argument.
        totp_usable=_opened_totp_state,
        passkey_escalates=passkey_escalates,
    )
    return (result.attempts, result.just_locked, result.cycles)


async def _lock_cycle(
    store: Any, user_id: str, *, start: float, counter: str, passkey_escalates: Any = None
) -> float:
    """Run one full cycle: THRESHOLD failures from ``start``. Returns the new ``locked_until``."""
    for i in range(THRESHOLD):
        await _fail(
            store, user_id, now=start + i, counter=counter, passkey_escalates=passkey_escalates
        )
    user = await store.get_user(user_id)
    assert user is not None
    locked = user.locked_until if counter == "sign_in" else user.second_step_locked_until
    assert locked is not None, f"a full run of {counter} failures set no lock"
    return float(locked)


async def _assert_lockout_contract(store: Any) -> None:
    """The behaviour every backend owes ``increment_login_failure`` and the lockout writers."""
    await _assert_single_counter_policy(store)
    await _assert_escalation(store)
    await _assert_passkey_escalates_the_sign_in_lock(store)
    await _assert_counters_stay_apart_and_clear(store)
    await _assert_generated_credential(store)
    await _assert_conditional_rotation(store)
    await _assert_conditional_rotation_on_a_passkey(store)
    await _assert_refused_totp_is_no_way_past(store)
    await _assert_refused_totp_keeps_the_fixed_sign_in_lock(store)
    await _assert_an_unknown_totp_behaves_as_an_enabled_one(store, "outage")
    await _assert_an_unknown_totp_behaves_as_an_enabled_one(store, "keyless")
    await _assert_a_stale_pre_read_still_escalates(store)
    for race in ("enabled", "replaced", "rekeyed"):
        await _assert_no_verdict_falls_back_to_the_enabled_rule(store, race)
    await _assert_a_wrong_password_below_the_threshold_opens_no_cell(store)


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
    staged_cell = await store.set_totp_secret("lock-totp", secret="JBSWY3DPEHPK3PXP", now=1.0)
    assert await store.enable_totp(
        "lock-totp", expected_secret_cell=staged_cell, recovery_code_hashes=[], now=1.0
    )
    # A directory account, with TOTP enrolled too: NEITHER lock escalates (ADR 0197 Decision 5).
    await store.create_user(
        user_id="lock-ad", username="lock-ad", auth_provider="ad", now=1.0, password_generated=False
    )
    staged_cell = await store.set_totp_secret("lock-ad", secret="JBSWY3DPEHPK3PXP", now=1.0)
    assert await store.enable_totp(
        "lock-ad", expected_secret_cell=staged_cell, recovery_code_hashes=[], now=1.0
    )
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


async def _assert_passkey_escalates_the_sign_in_lock(store: Any) -> None:
    """BACKLOG #3937 item 8, on every backend: the sign-in lock on a local account whose way past
    is a discoverable passkey, with no TOTP, doubles per cycle exactly as a TOTP account's does,
    to the same ceiling. Only where the caller's ``passkey_escalates`` rule counts a passkey the
    write's own transaction reads: no rule, a passkey the rule does not count, and a passkey removed
    before the failure all keep the fixed length. A refused TOTP beside a counted passkey escalates,
    since the passkey is the way past. The second-step lock escalates as before."""
    from messagefoundry.store.store import passkey_is_way_past, passkey_is_way_past_under
    from tests._webauthn_store_contract import _cred

    def under(rp_id: str) -> Any:
        return lambda cred: passkey_is_way_past_under(cred, rp_id)

    expected_escalated = [LOCKOUT_SECONDS * 2**k for k in range(4)] + [MAX_LOCKOUT_SECONDS] * 2
    fixed = [LOCKOUT_SECONDS] * 4

    async def lengths_of(
        user_id: str, rule: Any, cycles: int, counter: str = "sign_in"
    ) -> list[float]:
        start, seen = 10_000.0, []
        for _ in range(cycles):
            locked = await _lock_cycle(
                store, user_id, start=start, counter=counter, passkey_escalates=rule
            )
            seen.append(locked - (start + THRESHOLD - 1))
            start = locked + 1.0
        await store.clear_lockout(user_id, reset_cycles=True, now=start)
        return seen

    await store.create_user(
        user_id="lock-pk",
        username="lock-pk",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )
    # Not discoverable: no way past under any rule, so the fixed length. Well formed in every other
    # respect (today's id-hash scheme, the relying party the rule names), so discoverable=False is
    # the only thing standing between it and an escalation, and this arm tests that check.
    await store.add_webauthn_credential(
        _cred("lock-pk", "plain", id_hash=_LOCK_PK_PLAIN, rp_id="t", discoverable=False)
    )
    assert await lengths_of("lock-pk", passkey_is_way_past, 4) == fixed, (
        "the sign-in lock escalated beside a passkey that is not discoverable"
    )
    assert await lengths_of("lock-pk", under("t"), 4) == fixed, (
        "the sign-in lock escalated beside a passkey under the rule's rp_id that is not discoverable"
    )
    await store.add_webauthn_credential(
        _cred("lock-pk", "resident", id_hash=_LOCK_PK, rp_id="t", discoverable=True)
    )
    assert await lengths_of("lock-pk", passkey_is_way_past, 6) == expected_escalated, (
        "the sign-in lock did not escalate beside a discoverable passkey"
    )
    assert await lengths_of("lock-pk", under("t"), 6) == expected_escalated
    # The same passkey under a rule that does not count it (another relying party), or no rule.
    assert await lengths_of("lock-pk", under("other"), 4) == fixed, (
        "the sign-in lock escalated beside a passkey the rule does not count"
    )
    assert await lengths_of("lock-pk", None, 4) == fixed, "no rule escalated the sign-in lock"
    # The second-step lock is unchanged: it escalated before and still does.
    assert await lengths_of("lock-pk", passkey_is_way_past, 6, "second_step") == expected_escalated

    # A refused TOTP is no way past (BACKLOG #3422), but the passkey beside it still is.
    cell = await store.set_totp_secret(
        "lock-pk", secret="totp1:SHA1:6:30:JBSWY3DPEHPK3PXP", now=2.0
    )
    assert await store.enable_totp(
        "lock-pk", expected_secret_cell=cell, recovery_code_hashes=[], now=2.0
    )
    assert await lengths_of("lock-pk", passkey_is_way_past, 6) == expected_escalated, (
        "a refused TOTP stopped a discoverable passkey's escalation"
    )
    assert await lengths_of("lock-pk", None, 3) == fixed[:3]
    await store.disable_totp("lock-pk", now=3.0)

    # Read in the failure's own write: the passkey removed after one cycle no longer escalates the
    # next, which keeps the base length on cycle 2 rather than doubling it.
    start = 10_000.0
    first = await _lock_cycle(
        store, "lock-pk", start=start, counter="sign_in", passkey_escalates=passkey_is_way_past
    )
    assert await store.delete_webauthn_credential("lock-pk", _LOCK_PK)
    second = await _lock_cycle(
        store,
        "lock-pk",
        start=first + 1.0,
        counter="sign_in",
        passkey_escalates=passkey_is_way_past,
    )
    assert second - (first + 1.0 + THRESHOLD - 1) == LOCKOUT_SECONDS, (
        "a removed passkey still escalated the sign-in lock"
    )
    user = await store.get_user("lock-pk")
    assert user is not None and user.lock_cycles == 2

    # A directory account holding a discoverable passkey keeps the fixed sign-in lock.
    await store.create_user(
        user_id="lock-pk-ad",
        username="lock-pk-ad",
        auth_provider="ad",
        now=1.0,
        password_generated=False,
    )
    await store.add_webauthn_credential(
        _cred("lock-pk-ad", "resident", id_hash=_LOCK_PK_AD, rp_id="t", discoverable=True)
    )
    assert await lengths_of("lock-pk-ad", passkey_is_way_past, 4) == fixed, (
        "a directory account's sign-in lock escalated beside a passkey"
    )

    for user_id in ("lock-pk", "lock-pk-ad"):
        await store.delete_all_webauthn_credentials(user_id)
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


async def _assert_conditional_rotation_on_a_passkey(store: Any) -> None:
    """ADR 0197 Amendment A, wave 2: a passkey recorded as discoverable is a way past, so the
    conditional rotation lands on an account holding one and no TOTP; a passkey that is not
    discoverable is not, so the write matches no row. And removing the discoverable passkey between
    the caller's check and the write refuses it, because the passkeys are read in the write's own
    transaction."""
    from tests._webauthn_store_contract import _cred

    await store.create_user(
        user_id="rot-pk1",
        username="rot-pk-alice",
        auth_provider="local",
        password_hash="h-issued",
        must_change_password=True,
        password_generated=True,
        now=1.0,
    )

    async def rotate() -> bool:
        return bool(
            await store.set_password(
                "rot-pk1",
                password_hash="h-chosen",
                password_generated=False,
                must_change_password=False,
                require_way_past=True,
                totp_usable=_opened_totp_state,
            )
        )

    await store.add_webauthn_credential(_cred("rot-pk1", "plain", id_hash="rot-pk-plain"))
    assert not await rotate(), "a passkey that is not discoverable opened the rotation"
    user = await store.get_user("rot-pk1")
    assert user is not None and user.password_hash == "h-issued" and user.password_generated
    await store.add_webauthn_credential(
        _cred("rot-pk1", "resident", id_hash=_PK_RESIDENT, created_at=2.0, discoverable=True)
    )
    # The caller "checks" here and sees it ... then the holder removes it before the write.
    assert await store.delete_webauthn_credential("rot-pk1", _PK_RESIDENT)
    assert not await rotate(), "the rotation landed after the discoverable passkey was removed"
    await store.add_webauthn_credential(
        _cred("rot-pk1", "resident", id_hash=_PK_RESIDENT, created_at=3.0, discoverable=True)
    )
    assert await rotate(), "a discoverable passkey did not open the rotation"
    user = await store.get_user("rot-pk1")
    assert user is not None and user.password_hash == "h-chosen" and not user.password_generated

    # The conditional removals (AC-A3a): the last discoverable passkey goes only while TOTP stands,
    # and TOTP goes only while a discoverable passkey stands, each judged in its own write.
    assert not await store.delete_webauthn_credential(
        "rot-pk1", _PK_RESIDENT, require_way_past=True, totp_usable=_opened_totp_state
    ), "the last way past was deleted"
    assert await store.get_webauthn_credential(_PK_RESIDENT) is not None
    assert await store.delete_webauthn_credential(
        "rot-pk1", "rot-pk-plain", require_way_past=True, totp_usable=_opened_totp_state
    )
    staged_cell = await store.set_totp_secret("rot-pk1", secret="JBSWY3DPEHPK3PXP", now=5.0)
    assert await store.enable_totp(
        "rot-pk1", expected_secret_cell=staged_cell, recovery_code_hashes=[], now=5.0
    )
    assert await store.delete_webauthn_credential(
        "rot-pk1", _PK_RESIDENT, require_way_past=True, totp_usable=_opened_totp_state
    ), "TOTP stands, so the passkey may go"
    assert not await store.disable_totp(
        "rot-pk1", now=6.0, require_way_past=True, totp_usable=_opened_totp_state
    ), "TOTP went with no discoverable passkey left"
    user = await store.get_user("rot-pk1")
    assert user is not None and user.totp_enabled
    await store.add_webauthn_credential(
        _cred("rot-pk1", "again", id_hash=_PK_AGAIN, created_at=7.0, discoverable=True)
    )
    assert await store.disable_totp(
        "rot-pk1", now=8.0, require_way_past=True, totp_usable=_opened_totp_state
    )
    user = await store.get_user("rot-pk1")
    assert user is not None and not user.totp_enabled
    await store.delete_all_webauthn_credentials("rot-pk1")
    await store.delete_user("rot-pk1")


async def _assert_an_unknown_totp_behaves_as_an_enabled_one(store: Any, kind: str) -> None:
    """BACKLOG #3422, on every backend: a TOTP the store cannot judge is UNKNOWN, and every store
    decision then follows the plain ``totp_enabled`` rule, never the refused-TOTP one. ``kind`` is
    ``"outage"``, a stub cipher raising ``CipherError`` as a Transit outage does, or ``"keyless"``,
    an open that hands the stored ciphertext back unchanged, as a store opened without its key
    does. The sign-in lock still escalates; the TOTP cannot be removed while only a passkey that is
    not discoverable would remain; and that passkey may go, because the TOTP still counts. Each
    decision opened the stubbed cell, so the stub, not a skipped judgement, is what was measured."""
    from messagefoundry.store.crypto import MARKER_PREFIX, CipherError
    from tests._webauthn_store_contract import _cred

    uid = f"lock-uk-{kind}"
    await store.create_user(
        user_id=uid,
        username=f"lock-uk-{kind}-alice",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )
    cell = await store.set_totp_secret(uid, secret="JBSWY3DPEHPK3PXP", now=1.0)
    assert await store.enable_totp(uid, expected_secret_cell=cell, recovery_code_hashes=[], now=1.0)
    plain = credential_id_hash(f"lock-uk-{kind}-plain".encode())
    await store.add_webauthn_credential(_cred(uid, "plain", id_hash=plain))
    opened: list[str] = []

    def unjudgeable(user_id: str, _cell: str | None) -> str | None:
        opened.append(user_id)
        if kind == "outage":
            raise CipherError("the cipher service did not answer")
        return MARKER_PREFIX + "v2:opaque-ciphertext"

    store.open_totp_secret = unjudgeable
    try:
        first = await _lock_cycle(store, uid, start=10_000.0, counter="sign_in")
        second = await _lock_cycle(store, uid, start=first + 1.0, counter="sign_in")
        assert opened, "the escalation judged nothing, so the stub measured nothing"
        assert second - (first + 1.0 + THRESHOLD - 1) == 2 * LOCKOUT_SECONDS, (
            f"an unknown ({kind}) TOTP lost the sign-in lock's escalation"
        )
        opened.clear()
        assert not await store.disable_totp(
            uid, now=50_000.0, require_way_past=True, totp_usable=_opened_totp_state
        ), f"an unknown ({kind}) TOTP was removed beside a passkey that is not discoverable"
        assert opened, "the removal judged nothing"
        user = await store.get_user(uid)
        assert user is not None and user.totp_enabled
        opened.clear()
        assert await store.delete_webauthn_credential(
            uid, plain, require_way_past=True, totp_usable=_opened_totp_state
        ), f"an unknown ({kind}) TOTP did not count as the account's way past"
        assert opened, "the passkey removal judged nothing"
    finally:
        del store.open_totp_secret
    await store.disable_totp(uid, now=60_000.0)
    await store.delete_user(uid)


async def _assert_a_stale_pre_read_still_escalates(store: Any) -> None:
    """The escalation verdict is judged on a read taken before the write's lock. When that read is
    stale (here it shows a live lock that a racing ``clear_lockout`` already lifted), no verdict is
    judged, and the locked write falls back to the plain ``totp_enabled`` rule on the row it holds:
    it escalates, as before BACKLOG #3422, rather than skipping the escalation."""
    import dataclasses

    await store.create_user(
        user_id="lock-st1",
        username="lock-st-alice",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )
    cell = await store.set_totp_secret("lock-st1", secret="JBSWY3DPEHPK3PXP", now=1.0)
    assert await store.enable_totp(
        "lock-st1", expected_secret_cell=cell, recovery_code_hashes=[], now=1.0
    )
    first = await _lock_cycle(store, "lock-st1", start=10_000.0, counter="sign_in")
    real_get_user = store.get_user

    async def stale(user_id: str) -> Any:
        user = await real_get_user(user_id)
        return None if user is None else dataclasses.replace(user, locked_until=1e12)

    store.get_user = stale
    try:
        for i in range(THRESHOLD):
            await _fail(store, "lock-st1", now=first + 1.0 + i, counter="sign_in")
    finally:
        del store.get_user
    user = await store.get_user("lock-st1")
    assert user is not None and user.locked_until is not None
    second = float(user.locked_until)
    assert second - (first + 1.0 + THRESHOLD - 1) == 2 * LOCKOUT_SECONDS, (
        "a stale pre-read skipped the sign-in lock's escalation"
    )
    await store.disable_totp("lock-st1", now=60_000.0)
    await store.delete_user("lock-st1")


#: Two enrolments whose marker this release refuses (SHA1), with different secrets so their cells
#: differ on a keyless store too.
_REFUSED_A = "totp1:SHA1:6:30:JBSWY3DPEHPK3PXP"
_REFUSED_B = "totp1:SHA1:6:30:KRSXG5CTMVRXEZLU"


async def _assert_no_verdict_falls_back_to_the_enabled_rule(store: Any, race: str) -> None:
    """Finding 25, each trigger that needs no burst, on every backend. The verdict is judged on a
    read taken before the write's lock, and a write that lands between the two leaves the locked
    row holding a TOTP nobody judged. Each time the locked row holds a REFUSED enrolment, so only
    the fallback to the plain ``totp_enabled`` rule escalates, which is what the store did before
    BACKLOG #3422:

    * ``"enabled"``: TOTP was off at the read (``totp_enable`` leaves the count standing), so
      :func:`escalation_verdict` judged nothing;
    * ``"replaced"``: the enrolment was removed and enrolled again with another secret, so the cell
      the verdict holds is not the locked row's (:meth:`TotpJudgement.moved`);
    * ``"rekeyed"``: the read saw the cell as it was under an earlier store key. Simulated by a read
      that carries another cell, opened by a stub to a refused enrolment."""
    import dataclasses

    uid = f"lock-nv-{race}"
    await store.create_user(
        user_id=uid,
        username=f"lock-nv-{race}-alice",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )

    async def enrol(secret: str, now: float) -> None:
        cell = await store.set_totp_secret(uid, secret=secret, now=now)
        assert await store.enable_totp(
            uid, expected_secret_cell=cell, recovery_code_hashes=[], now=now
        )

    if race != "enabled":
        await enrol(_REFUSED_A, 1.0)
    first = await _lock_cycle(store, uid, start=10_000.0, counter="sign_in")
    start = first + 1.0
    for i in range(THRESHOLD - 1):
        await _fail(store, uid, now=start + i)
    real_get_user = store.get_user
    real_open = store.open_totp_secret

    async def racing(user_id: str) -> Any:
        pre = await real_get_user(user_id)
        store.__dict__.pop("get_user", None)  # only the crossing failure's read races
        if race == "enabled":
            await enrol(_REFUSED_A, start)
        elif race == "replaced":
            assert await store.disable_totp(uid, now=start)
            await enrol(_REFUSED_B, start)
        else:
            assert pre is not None and pre.row is not None
            pre = dataclasses.replace(
                pre, row=dataclasses.replace(pre.row, totp_secret="cell-under-an-earlier-key")
            )
        return pre

    store.get_user = racing
    if race == "rekeyed":
        # Bound before the read, as the backend reads the opener when it calls the verdict.
        store.open_totp_secret = lambda _u, _c: _REFUSED_A
    try:
        await _fail(store, uid, now=start + THRESHOLD - 1)
    finally:
        store.__dict__.pop("get_user", None)
        store.__dict__.pop("open_totp_secret", None)
    assert store.open_totp_secret == real_open
    user = await store.get_user(uid)
    assert user is not None and user.locked_until is not None and user.totp_enabled
    assert user.locked_until - (start + THRESHOLD - 1) == 2 * LOCKOUT_SECONDS, (
        f"a TOTP nobody judged ({race}) skipped the sign-in lock's escalation"
    )
    await store.disable_totp(uid, now=99_999.0)
    await store.delete_user(uid)


async def _assert_a_wrong_password_below_the_threshold_opens_no_cell(store: Any) -> None:
    """The cost bound on every backend: the escalation verdict opens the TOTP cell (a Transit
    decrypt) only for the failure that sets a lock the verdict could shorten. A wrong password
    below the threshold opens nothing, nor does the crossing failure of the first cycle, whose lock
    has the base length either way; the crossing failure of a later cycle opens the cell once."""
    uid = "lock-cost1"
    await store.create_user(
        user_id=uid,
        username="lock-cost-alice",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )
    cell = await store.set_totp_secret(uid, secret="JBSWY3DPEHPK3PXP", now=1.0)
    assert await store.enable_totp(uid, expected_secret_cell=cell, recovery_code_hashes=[], now=1.0)
    real_open = store.open_totp_secret
    opened: list[str] = []

    def spy(user_id: str, stored: str | None) -> str | None:
        opened.append(user_id)
        return real_open(user_id, stored)

    store.open_totp_secret = spy
    try:
        first = await _lock_cycle(store, uid, start=10_000.0, counter="sign_in")
        assert opened == [], "the first cycle opened the TOTP cell"
        start = first + 1.0
        for i in range(THRESHOLD - 1):
            await _fail(store, uid, now=start + i)
        assert opened == [], "a wrong password below the threshold opened the TOTP cell"
        await _fail(store, uid, now=start + THRESHOLD - 1)
        assert opened == [uid], opened
    finally:
        del store.open_totp_secret
    await store.disable_totp(uid, now=99_999.0)
    await store.delete_user(uid)


async def _assert_refused_totp_keeps_the_fixed_sign_in_lock(store: Any) -> None:
    """BACKLOG #3422 beside ADR 0197, on every backend: the sign-in lock escalates only where the
    owner has a way past it, and a TOTP enrolment this release refuses is none, so its account keeps
    the fixed lock on the second cycle. Judged by the caller's rule on the locked row's cell."""
    await store.create_user(
        user_id="lock-rf1",
        username="lock-rf-alice",
        auth_provider="local",
        password_hash="h",
        now=1.0,
        password_generated=False,
    )
    cell = await store.set_totp_secret(
        "lock-rf1", secret="totp1:SHA1:6:30:JBSWY3DPEHPK3PXP", now=1.0
    )
    assert await store.enable_totp(
        "lock-rf1", expected_secret_cell=cell, recovery_code_hashes=[], now=1.0
    )
    first = await _lock_cycle(store, "lock-rf1", start=10_000.0, counter="sign_in")
    second = await _lock_cycle(store, "lock-rf1", start=first + 1.0, counter="sign_in")
    assert second - (first + 1.0 + THRESHOLD - 1) == LOCKOUT_SECONDS, (
        "the sign-in lock escalated beside a refused TOTP"
    )
    await store.disable_totp("lock-rf1", now=99_999.0)
    await store.delete_user("lock-rf1")


async def _assert_refused_totp_is_no_way_past(store: Any) -> None:
    """BACKLOG #3422 beside ADR 0197 Amendment A wave 2, on every backend: the conditional writes
    count TOTP as a way past only through the caller's rule (``totp_usable``), so an enrolment this
    release refuses does not free the last discoverable passkey, and does not open the rotation. A
    conditional write that brings no rule is refused outright, never answered by the old test."""
    from tests._webauthn_store_contract import _cred

    await store.create_user(
        user_id="rot-rf1",
        username="rot-rf-alice",
        auth_provider="local",
        password_hash="h-issued",
        must_change_password=True,
        password_generated=False,
        now=1.0,
    )
    cell = await store.set_totp_secret(
        "rot-rf1", secret="totp1:SHA1:6:30:JBSWY3DPEHPK3PXP", now=2.0
    )
    assert await store.enable_totp(
        "rot-rf1", expected_secret_cell=cell, recovery_code_hashes=[], now=2.0
    )
    await store.add_webauthn_credential(
        _cred("rot-rf1", "resident", id_hash=_RF_RESIDENT, created_at=3.0, discoverable=True)
    )
    with pytest.raises(ValueError):
        await store.delete_webauthn_credential("rot-rf1", _RF_RESIDENT, require_way_past=True)
    assert not await store.delete_webauthn_credential(
        "rot-rf1", _RF_RESIDENT, require_way_past=True, totp_usable=_opened_totp_state
    ), "a refused TOTP freed the last discoverable passkey"
    assert await store.get_webauthn_credential(_RF_RESIDENT) is not None
    await store.delete_all_webauthn_credentials("rot-rf1")
    with pytest.raises(ValueError):
        await store.set_password(
            "rot-rf1",
            password_hash="h-chosen",
            password_generated=False,
            must_change_password=False,
            require_way_past=True,
        )
    assert not await store.set_password(
        "rot-rf1",
        password_hash="h-chosen",
        password_generated=False,
        must_change_password=False,
        require_way_past=True,
        totp_usable=_opened_totp_state,
    ), "a refused TOTP opened the rotation"
    user = await store.get_user("rot-rf1")
    assert user is not None and user.password_hash == "h-issued"
    await store.disable_totp("rot-rf1", now=4.0)
    await store.delete_user("rot-rf1")


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
        require_way_past=True,
        totp_usable=_opened_totp_state,
    )
    user = await store.get_user("rot-u1")
    assert user is not None
    assert (user.password_hash, user.password_generated, user.must_change_password) == (
        "h-issued",
        True,
        True,
    )
    # TOTP on: the caller "checks" here and sees it...
    staged_cell = await store.set_totp_secret("rot-u1", secret="JBSWY3DPEHPK3PXP", now=2.0)
    assert await store.enable_totp(
        "rot-u1", expected_secret_cell=staged_cell, recovery_code_hashes=[], now=2.0
    )
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
        require_way_past=True,
        totp_usable=_opened_totp_state,
    )
    user = await store.get_user("rot-u1")
    assert user is not None and user.password_hash == "h-issued" and user.password_generated
    # With TOTP standing, the same write lands.
    staged_cell = await store.set_totp_secret("rot-u1", secret="JBSWY3DPEHPK3PXP", now=4.0)
    assert await store.enable_totp(
        "rot-u1", expected_secret_cell=staged_cell, recovery_code_hashes=[], now=4.0
    )
    assert await store.set_password(
        "rot-u1",
        password_hash="h-chosen",
        password_generated=False,
        must_change_password=False,
        require_way_past=True,
        totp_usable=_opened_totp_state,
    )
    user = await store.get_user("rot-u1")
    assert user is not None
    assert (user.password_hash, user.password_generated, user.must_change_password) == (
        "h-chosen",
        False,
        False,
    )
    # TOTP flagged on over a NULL secret is no way past (review round 2). Since BACKLOG #2224 a
    # confirm racing a factor reset cannot produce that state, because ``enable_totp`` is
    # conditional, and since BACKLOG #3025 neither can a stage: ``set_totp_secret`` has no clear and
    # writes nothing once TOTP is on, so the enabled secret is left as it was.
    before = await store.get_totp_secret("rot-u1")
    assert await store.set_totp_secret("rot-u1", secret="JBSWY3DPEHPK3PXP"[::-1], now=5.0) is None
    user = await store.get_user("rot-u1")
    assert user is not None and user.totp_enabled
    assert await store.get_totp_secret("rot-u1") == before
    # disable_totp forgets the removed secret's step high-water mark (review round 2): a new
    # secret's first code in the same 30 seconds is not refused as a replay.
    assert await store.consume_totp_step("rot-u1", 1_000)
    assert not await store.consume_totp_step("rot-u1", 1_000)
    await store.disable_totp("rot-u1", now=6.0)
    assert await store.consume_totp_step("rot-u1", 1_000)
    # An unknown user matches no row either way.
    assert not await store.set_password(
        "no-such-user", password_hash="x", password_generated=False, must_change_password=False
    )
    await store.delete_user("rot-u1")
