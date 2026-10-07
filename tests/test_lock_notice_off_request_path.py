# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2216: the ACCOUNT_LOCKED notice's throttle runs off the request path.

The throttle (``AuthService._lock_notice_due``) reads the audit log for the account's last
``auth.lock_notice`` row. Every caller is a refusal, and the sign-in refusal writes its rows inside
a fixed room of its padded slot (BACKLOG #2467). With the read there, a large audit log could push
the answer to a later slot. With a notifier wired, the read and the mail now run as one background
task the service owns, serialized per account and lock kind, and drained at shutdown.

Each test that asserts an absence carries a control showing the instrument can see the presence.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api import create_managed_app
from messagefoundry.auth import service as service_module
from messagefoundry.auth.notifications import ACCOUNT_LOCKED, SecurityEvent
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AlertsSettings, AuthSettings, EgressSettings
from messagefoundry.store import open_store, sqlite_settings
from messagefoundry.store.store import LockoutIncrement, MessageStore, UserRecord
from tests._admin_account import ADMIN_USERNAME, create_admin

_LOCK_NOTICE = "auth.lock_notice"
#: Longer than the deferred writes' room in the sign-in pad, so a read this slow on the request
#: path would move the answer to a later slot.
_SLOW = service_module._FAILURE_BUDGET_SECONDS * service_module._WRITE_ROOM_SHARE * 2.4


class _FakeNotifier:
    """Captures the out-of-band security events instead of emailing them."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)

    def locks(self) -> list[SecurityEvent]:
        return [e for e in self.events if e.event_type == ACCOUNT_LOCKED]


async def _harness(
    *, notifier: _FakeNotifier | None = None, threshold: int = 1
) -> tuple[MessageStore, AuthService, _FakeNotifier, UserRecord]:
    store = await MessageStore.open(":memory:")
    notifier = notifier if notifier is not None else _FakeNotifier()
    service = AuthService(
        store,
        AuthSettings(lockout_threshold=threshold, lockout_minutes=15, require_mfa=False),
        security_notifier=notifier,
    )
    admin = await create_admin(service)
    await store.set_user_notify_email(admin.user_id, email="owner@example.org")
    user = await store.get_user(admin.user_id)
    assert user is not None
    return store, service, notifier, user


async def _seed_other_accounts_notices(store: MessageStore, count: int) -> None:
    """``count`` recent ``auth.lock_notice`` rows for OTHER accounts, written straight to the table.

    The throttle walks every recent row of the action to find this account's, since the audit log
    has no actor index, so these are the rows that make its read slow. Inserted in one statement
    rather than through ``record_audit``, which chains each row and would take minutes. The chain is
    not under test here."""
    db = store._db
    assert db is not None
    cur = await db.execute("SELECT COALESCE(MAX(seq), 0) FROM audit_log")
    row = await cur.fetchone()
    assert row is not None
    first = int(row[0]) + 1
    now = time.time()
    detail = json.dumps({"lock": "sign_in", "mailed": True}, sort_keys=True)
    await db.executemany(
        "INSERT INTO audit_log (seq, ts, actor, action, channel_id, detail, client, row_hash)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (
            (first + i, now, f"other-{i % 997}", _LOCK_NOTICE, None, detail, None, "seeded")
            for i in range(count)
        ),
    )
    await db.commit()


@dataclass
class _Reads:
    """What the patched throttle read saw: how many reads ran, and the most in flight at once."""

    count: int = 0
    running: int = 0
    peak: int = 0


def _patch_throttle_read(
    monkeypatch: pytest.MonkeyPatch,
    store: MessageStore,
    *,
    before: Callable[[], Awaitable[object]] | None = None,
    after: Callable[[], Awaitable[object]] | None = None,
) -> _Reads:
    """Run ``before`` ahead of each throttle read, and ``after`` once it has read and before it
    answers, counting the reads in flight across both. Other ``list_audit`` calls pass through.
    The test's own later ``auth.lock_notice`` reads are counted too, so read the counts first."""
    real = store.list_audit
    reads = _Reads()

    async def held(*args: Any, **kwargs: Any) -> Any:
        if kwargs.get("action") != _LOCK_NOTICE:
            return await real(*args, **kwargs)
        reads.count += 1
        reads.running += 1
        reads.peak = max(reads.peak, reads.running)
        try:
            if before is not None:
                await before()
            rows = await real(*args, **kwargs)
            if after is not None:
                await after()
            return rows
        finally:
            reads.running -= 1

    monkeypatch.setattr(store, "list_audit", held)
    return reads


def _slow_throttle_read(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore, delay: float
) -> _Reads:
    """Make the throttle's read take at least ``delay``. For the timing tests, where the slow read
    IS the condition under test; the race tests stage their overlaps with gates instead."""
    return _patch_throttle_read(monkeypatch, store, before=lambda: asyncio.sleep(delay))


def _record_deadlines(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the answer's pad with a recorder, so the slot each refusal answers on is read back
    rather than inferred from a wall-clock measurement."""
    deadlines: list[float] = []

    async def record(deadline: float) -> None:
        deadlines.append(deadline)

    monkeypatch.setattr(service_module, "_sleep_until", record)
    return deadlines


def _cheap_wrong_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the password check instant and wrong. Under load an argon2 verify alone can outrun the
    whole budget, which moves the answer for a reason these timing tests are not about."""
    monkeypatch.setattr(service_module, "verify_password", lambda _hash, _password: False)


def _write_overruns(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if "audit writes took" in r.getMessage()]


async def _lock_notice_rows(store: MessageStore, actor: str) -> list[Any]:
    return list(await store.list_audit(actor=actor, action=_LOCK_NOTICE, limit=50))


# --- the timing property ---------------------------------------------------------------------


async def test_the_lock_setting_refusal_stays_in_its_slot_with_a_large_audit_log(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """RED when the throttle reads on the request path: the sign-in refusal that sets the lock
    writes its rows in a room of an eighth of a second, and a throttle read slower than that moved
    the answer to the next slot and fired the writes-overrun warning.

    The audit log holds many ``auth.lock_notice`` rows for other accounts, which is what makes the
    real read slow, and the read is also held past the room so the result does not depend on this
    machine's disk. The notice still goes out once the task runs, and the seeded rows of other
    accounts do not hold this account's mail back."""
    monkeypatch.setattr(service_module, "_BUDGET_OVERRUN_WARNED", set())
    _cheap_wrong_password(monkeypatch)
    store, service, notifier, user = await _harness()
    try:
        await _seed_other_accounts_notices(store, 50_000)
        reads = _slow_throttle_read(monkeypatch, store, _SLOW)
        deadlines = _record_deadlines(monkeypatch)
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            started = time.monotonic()
            out = await service.login(ADMIN_USERNAME, "wrong-passphrase")
            assert not out.ok
            refused_by = deadlines[-1] - started
            await service.drain_background()
        assert _write_overruns(caplog) == [], _write_overruns(caplog)
        assert refused_by <= service_module._FAILURE_BUDGET_SECONDS + 0.05, (
            f"the lock-setting refusal answered {refused_by:.3f}s in, past its first slot"
        )
        # The throttle did run, slowly, after the answer's deadline was fixed.
        assert reads.count == 1, reads
        assert len(notifier.locks()) == 1, "the notice never went out"
        rows = await _lock_notice_rows(store, user.username)
        assert [json.loads(r["detail"]) for r in rows] == [{"lock": "sign_in", "mailed": True}]
    finally:
        await store.close()


async def test_the_overrun_instrument_fires_for_a_slow_write_still_on_the_path(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The control for the test above. The same delay put on a write that stays on the request
    path, the ``auth.account_locked`` row, does move the answer and does warn. Without this, an
    empty warning list above would also be what a broken capture prints."""
    monkeypatch.setattr(service_module, "_BUDGET_OVERRUN_WARNED", set())
    _cheap_wrong_password(monkeypatch)
    store, service, _notifier, _user = await _harness()
    try:
        real = store.record_audit

        async def slow_lock_row(action: str, **kwargs: Any) -> Any:
            if action == "auth.account_locked":
                await asyncio.sleep(_SLOW)
            return await real(action, **kwargs)

        monkeypatch.setattr(store, "record_audit", slow_lock_row)
        deadlines = _record_deadlines(monkeypatch)
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            started = time.monotonic()
            assert not (await service.login(ADMIN_USERNAME, "wrong-passphrase")).ok
            refused_by = deadlines[-1] - started
            await service.drain_background()
        assert _write_overruns(caplog), "the overrun warning did not fire for an on-path write"
        assert refused_by > service_module._FAILURE_BUDGET_SECONDS + 0.05, refused_by
    finally:
        await store.close()


# --- the race ---------------------------------------------------------------------------------


def _lock(cycle: int) -> LockoutIncrement:
    return LockoutIncrement(attempts=1, just_locked=True, cycles=cycle)


def _parallel_reads(service: AuthService) -> None:
    """Let two throttle reads run at once, so the race tests measure the per-account queue alone
    and not the service-wide one-read-at-a-time limit, which hides part of the race."""
    service._lock_notice_read_slots = asyncio.Semaphore(2)


#: How long a :class:`_Gate` waits for its last arrival. The tests below stage their overlaps with
#: gates rather than with sleeps. A healthy interleave opens a gate within milliseconds, so a wait
#: this long means a regression, broken staging, or a runner stalled for seconds. The test then
#: fails on the gate's record, before its mail counts.
_GATE_SECONDS = 10.0


class _Gate:
    """Opens once ``needed`` tasks have arrived. Each :meth:`wait` records if it opened in time.

    A timeout is recorded rather than raised: inside a patched throttle read an exception would be
    swallowed by the read's fail-open handler, which mails, and could turn a staging failure into a
    pass. Each test asserts :attr:`waits` itself, first. Not ``asyncio.Barrier``: the queue tests
    count an arrival in one task and wait in another."""

    def __init__(self, needed: int) -> None:
        self._needed = needed
        self._arrived = 0
        self._open = asyncio.Event()
        self.waits: list[bool] = []

    def arrive(self) -> None:
        self._arrived += 1
        if self._arrived >= self._needed:
            self._open.set()

    async def wait(self) -> None:
        try:
            await asyncio.wait_for(self._open.wait(), _GATE_SECONDS)
        except TimeoutError:
            self.waits.append(False)
        else:
            self.waits.append(True)

    async def meet(self) -> None:
        """Arrive, then wait for the others."""
        self.arrive()
        await self.wait()


def _gate_on_the_notice_queue(
    monkeypatch: pytest.MonkeyPatch, service: AuthService, needed: int
) -> _Gate:
    """A gate that opens once ``needed`` lock notices have reached the per-account, per-kind queue.

    Counted where ``_send_lock_notice`` enters ``_hold_keyed_lock`` on ``_lock_notice_locks``, which
    takes the lock with no await in between, so a notice counted here is holding the queue or
    waiting on it. The race control already replaces the same helper."""
    gate = _Gate(needed)
    real_hold = service_module._hold_keyed_lock

    @asynccontextmanager
    async def arriving(table: Any, key: str) -> AsyncIterator[None]:
        if table is service._lock_notice_locks:
            gate.arrive()
        async with real_hold(table, key):
            yield

    monkeypatch.setattr(service_module, "_hold_keyed_lock", arriving)
    return gate


async def test_two_same_kind_locks_at_once_send_one_mail_and_write_one_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Off the request path, two sign-in locks on one account can land together, for example one
    set by a re-proof while a sign-in sets it too. Each task would read the throttle before the
    other wrote its row. The per-account, per-kind queue makes the second read the first's row.

    "Together" is staged, not timed: the first notice's read waits until the second notice has
    reached the queue, so the second is waiting there while the first reads. A sleep used to stand
    in for that, and on a loaded runner the second lock could arrive after the first had finished,
    which passed here without testing the race."""
    store, service, notifier, user = await _harness()
    try:
        queued = _gate_on_the_notice_queue(monkeypatch, service, 2)
        _patch_throttle_read(monkeypatch, store, before=queued.wait)
        _parallel_reads(service)
        await asyncio.gather(
            service._record_lock(user, "sign_in", _lock(1), client=None),
            service._record_lock(user, "sign_in", _lock(2), client=None),
        )
        await service.drain_background()
        assert queued.waits == [True, True], (
            "the second lock's notice never reached the per-account queue while the first read, so "
            f"this did not test the race: {queued.waits}. [False, False] means neither notice "
            "entered the queue through _hold_keyed_lock on _lock_notice_locks."
        )
        assert len(notifier.locks()) == 1, [e.detail for e in notifier.locks()]
        assert len(await _lock_notice_rows(store, user.username)) == 1
        locked = await store.list_audit(actor=user.username, action="auth.account_locked")
        assert len(locked) == 2, "each lock still writes its own auth.account_locked row"
        assert service._lock_notice_locks == {}, "the queue table kept an entry nobody holds"
    finally:
        await store.close()


async def test_the_race_is_real_without_the_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the race test: the same two locks with the per-account queue taken away mail
    twice. So the single mail above is the queue's doing.

    The race is staged, not timed: each read's answer is held until both reads have finished, so
    neither notice can write its row before the other has looked. A 0.05 s sleep used to stand in
    for that, and on a loaded runner the second notice could start after the first had read, mailed
    and written its row, so it was throttled and this mailed once (merge-queue intermittent, test
    from PR 2092)."""
    store, service, notifier, user = await _harness()
    try:
        both_read = _Gate(2)
        _patch_throttle_read(monkeypatch, store, after=both_read.meet)
        _parallel_reads(service)

        @asynccontextmanager
        async def no_queue(_table: Any, _key: str) -> AsyncIterator[None]:
            yield

        monkeypatch.setattr(service_module, "_hold_keyed_lock", no_queue)
        await asyncio.gather(
            service._record_lock(user, "sign_in", _lock(1), client=None),
            service._record_lock(user, "sign_in", _lock(2), client=None),
        )
        await service.drain_background()
        assert both_read.waits == [True, True], (
            f"the two throttle reads never overlapped, so the race was not staged: "
            f"{both_read.waits}"
        )
        assert len(notifier.locks()) == 2
        assert len(await _lock_notice_rows(store, user.username)) == 2
    finally:
        await store.close()


async def test_one_throttle_read_runs_at_a_time_across_accounts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each throttle read walks every recent ``auth.lock_notice`` row, so locks on many accounts at
    once would fill the store's read pool that sign-ins wait on. The service runs one at a time.
    Every account still gets its mail.

    Each read waits until every account's notice has reached the throttle, so all five are waiting
    for the read slot while the first reads, and a wider limit would let the others in beside it. A
    sleep used to stand in for that, and on a loaded runner the notices could start too far apart
    to overlap."""
    store, service, notifier, user = await _harness()
    try:
        users = [user]
        for n in range(4):
            await store.create_user(
                user_id=f"u-{n}",
                username=f"other-{n}",
                auth_provider="local",
                password_hash=user.password_hash,
                password_generated=False,
            )
            await store.set_user_notify_email(f"u-{n}", email=f"other-{n}@example.org")
            other = await store.get_user(f"u-{n}")
            assert other is not None
            users.append(other)
        all_due = _Gate(len(users))
        real_held_back = service._lock_notice_held_back

        async def arriving(who: UserRecord, lock: str) -> bool:
            # Counted just before the read slots are taken, with no await in between.
            all_due.arrive()
            return await real_held_back(who, lock)

        monkeypatch.setattr(service, "_lock_notice_held_back", arriving)
        reads = _patch_throttle_read(monkeypatch, store, before=all_due.wait)
        await asyncio.gather(
            *(service._record_lock(u, "sign_in", _lock(1), client=None) for u in users)
        )
        await service.drain_background()
        assert all_due.waits == [True] * len(users), (
            "the notices never all reached the throttle at once, so this did not test the limit: "
            f"{all_due.waits}. All False means no notice reached _lock_notice_held_back while the "
            "first read waited."
        )
        assert reads.peak == 1, f"{reads.peak} throttle reads ran at once"
        assert sorted(e.username for e in notifier.locks()) == sorted(u.username for u in users)
    finally:
        await store.close()


async def test_two_kinds_at_once_are_not_queued_behind_each_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The queue is per lock kind: a sign-in lock and a second-step lock landing together are two
    notices, as the time throttle has always counted them, and neither waits for the other. With
    two reads allowed at once, both kinds' reads are in flight together; a queue keyed on the
    account alone would run them one after the other.

    Each read waits at a gate until both kinds' reads have reached it, rather than sleeping and
    hoping the other arrives in time: on a loaded runner a sleep could end before the other kind's
    read began. Anything that serializes the two reads keeps the gate shut until it times out.
    The in-flight count is also the control for the test above: it shows the counter whose
    ``peak == 1`` that test reads can see two reads at once."""
    store, service, notifier, user = await _harness()
    try:
        _parallel_reads(service)
        both_in_flight = _Gate(2)
        reads = _patch_throttle_read(monkeypatch, store, before=both_in_flight.meet)
        await asyncio.gather(
            service._record_lock(user, "sign_in", _lock(1), client=None),
            service._record_lock(user, "second_step", _lock(1), client=None, factor="password"),
        )
        await service.drain_background()
        assert both_in_flight.waits == [True, True], (
            "the two kinds' reads never ran at once: a queue keyed on the account alone, or one "
            f"read slot, serializes them: {both_in_flight.waits}"
        )
        assert reads.peak == 2, "the in-flight counter did not see two reads at once"
        assert sorted(e.detail["lock"] for e in notifier.locks()) == ["second_step", "sign_in"]
    finally:
        await store.close()


# --- failure and shutdown ---------------------------------------------------------------------


#: The off-box audit tee copies every audit row into the general log by design, and
#: ``/logs/tail`` withholds those copies from a reader without ``users:manage``. Its lines are not
#: the notice's own, so the leak checks below leave them out.
_AUDIT_TEE_LOGGER = "messagefoundry.audit"


def _naming(caplog: pytest.LogCaptureFixture, user: UserRecord, *more: str) -> list[str]:
    """Log lines, other than the audit tee's copies, that name the account, its id, a lock kind,
    or any of ``more``."""
    needles = (user.username, user.id, "sign_in", "second_step", "account_locked", "lock_notice")
    return [
        f"{r.name}: {m}"
        for r in caplog.records
        if r.name != _AUDIT_TEE_LOGGER
        for m in [r.getMessage()]
        if any(n in m for n in (*needles, *more))
    ]


async def test_a_notice_cancelled_at_shutdown_logs_a_line_that_names_nothing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A task still running when the drain's bound runs out is cancelled. It leaves a line saying a
    notice may be neither mailed nor recorded, naming no account, id or lock kind, so a notice cut
    off at shutdown is on record as cut off. The drain then returns, with no task left behind."""
    store, service, notifier, user = await _harness()
    try:
        never = asyncio.Event()
        _patch_throttle_read(monkeypatch, store, before=never.wait)
        caplog.clear()
        with caplog.at_level(logging.INFO):
            await service._record_lock(user, "sign_in", _lock(1), client="10.0.0.9")
            assert service._background_tasks, "the notice did not run as a background task"
            await service.drain_background(timeout=0.05)
        cut = [r for r in caplog.records if "cancelled before it finished" in r.getMessage()]
        assert len(cut) == 1, [r.getMessage() for r in caplog.records]
        assert cut[0].levelno == logging.WARNING
        assert _naming(caplog, user, "10.0.0.9") == [], _naming(caplog, user, "10.0.0.9")
        assert service._background_tasks == set()
        assert notifier.locks() == []
        # The lock itself is recorded inline, so the cut-off notice loses no part of the audit.
        locked = await store.list_audit(actor=user.username, action="auth.account_locked")
        assert len(locked) == 1
    finally:
        await store.close()


async def test_a_notice_that_finishes_inside_the_bound_is_not_cancelled(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The control for the shutdown test: a notice that is merely slow finishes inside the drain's
    bound, writes its row, sends its mail, and logs no cancellation."""
    store, service, notifier, user = await _harness()
    try:
        _slow_throttle_read(monkeypatch, store, 0.05)
        caplog.clear()
        with caplog.at_level(logging.INFO):
            await service._record_lock(user, "sign_in", _lock(1), client=None)
            await service.drain_background(timeout=5.0)
        assert "cancelled before it finished" not in caplog.text
        assert len(notifier.locks()) == 1
        assert len(await _lock_notice_rows(store, user.username)) == 1
    finally:
        await store.close()


async def test_a_failed_row_write_still_mails_and_logs_the_class_alone(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A failed ``auth.lock_notice`` row write used to fail the request. Nobody awaits the task
    now, so it is logged, and the mail has already gone, since it goes before its row. The line
    carries the exception's class only: a driver's message can carry the bound username."""
    store, service, notifier, user = await _harness()
    try:
        real = store.record_audit

        async def failing(action: str, **kwargs: Any) -> Any:
            if action == _LOCK_NOTICE:
                raise RuntimeError(f"insert failed for {kwargs.get('actor')}")
            return await real(action, **kwargs)

        monkeypatch.setattr(store, "record_audit", failing)
        caplog.clear()
        with caplog.at_level(logging.INFO):
            await service._record_lock(user, "sign_in", _lock(1), client=None)
            await service.drain_background()
        failed = [r for r in caplog.records if "failed off the request path" in r.getMessage()]
        assert len(failed) == 1 and "RuntimeError" in failed[0].getMessage()
        assert failed[0].exc_info is None, "a traceback would carry the exception's message"
        assert _naming(caplog, user) == [], _naming(caplog, user)
        assert len(notifier.locks()) == 1, "a failed row write dropped the mail"
    finally:
        await store.close()


async def test_a_failed_throttle_read_logs_the_class_alone_and_mails(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The throttle read fails open. Its line used to carry a traceback, whose driver message can
    quote the bound username; it carries the exception's class now."""
    store, service, notifier, user = await _harness()
    try:
        real = store.list_audit

        async def failing(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("action") == _LOCK_NOTICE:
                raise RuntimeError(f"read failed for {kwargs.get('actor')}")
            return await real(*args, **kwargs)

        monkeypatch.setattr(store, "list_audit", failing)
        caplog.clear()
        with caplog.at_level(logging.INFO):
            await service._record_lock(user, "sign_in", _lock(1), client=None)
            await service.drain_background()
        failed = [r for r in caplog.records if "throttle read failed" in r.getMessage()]
        assert len(failed) == 1 and "RuntimeError" in failed[0].getMessage()
        assert failed[0].exc_info is None
        assert _naming(caplog, user) == [], _naming(caplog, user)
        assert len(notifier.locks()) == 1, "a failed read must fail open and mail"
    finally:
        await store.close()


class _RefusingNotifier(_FakeNotifier):
    """A notifier that refuses every hand-off, as a relay whose queue raised would."""

    async def notify(self, event: SecurityEvent) -> None:
        raise OSError("relay refused the hand-off")


async def test_a_refused_hand_off_does_not_hold_the_next_notice_back() -> None:
    """The row says ``mailed: true`` only when the notifier took the mail. A refused hand-off
    writes ``mailed: false``, so the next lock of the kind mails again instead of staying quiet for
    a day behind a notice that never left. The control is the first row's own detail."""
    notifier = _RefusingNotifier()
    store, service, _notifier, user = await _harness(notifier=notifier)
    try:
        await service._record_lock(user, "sign_in", _lock(1), client=None)
        await service.drain_background()
        rows = await _lock_notice_rows(store, user.username)
        assert [json.loads(r["detail"]) for r in rows] == [{"lock": "sign_in", "mailed": False}]
        attempts: list[SecurityEvent] = []

        async def took(event: SecurityEvent) -> None:
            attempts.append(event)

        notifier.notify = took  # type: ignore[method-assign]
        await service._record_lock(user, "sign_in", _lock(2), client=None)
        await service.drain_background()
        assert len(attempts) == 1, "the refused notice held the next one back"
    finally:
        await store.close()


async def test_after_a_closing_drain_a_notice_runs_inline(monkeypatch: pytest.MonkeyPatch) -> None:
    """``close_background`` is the shutdown drain. A lock that lands after it, from a
    request still finishing, runs its notice inline rather than starting a task that would outlive
    the drain and meet a closed store."""
    store, service, notifier, user = await _harness()
    try:
        await service.close_background()
        await service._record_lock(user, "sign_in", _lock(1), client=None)
        assert service._background_tasks == set()
        assert len(notifier.locks()) == 1, "the notice did not run inline after the drain"
        assert len(await _lock_notice_rows(store, user.username)) == 1
    finally:
        await store.close()


async def test_with_no_notifier_the_row_is_written_inline(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no notifier wired the throttle reads nothing and writes one ``mailed: false`` row, so
    that arm stays on the request path and starts no task."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(
            store, AuthSettings(lockout_threshold=1, require_mfa=False, notify_security_events=True)
        )
        admin = await create_admin(service)
        user = await store.get_user(admin.user_id)
        assert user is not None
        await service._record_lock(user, "sign_in", _lock(1), client=None)
        assert service._background_tasks == set()
        rows = await _lock_notice_rows(store, user.username)
        assert [json.loads(r["detail"])["reason"] for r in rows] == ["no_notifier"]
    finally:
        await store.close()


# --- the lifespan drains before the store closes ----------------------------------------------


def _managed_app(db: Path) -> Any:
    return create_managed_app(
        db_path=db,
        poll_interval=0.05,
        auth_settings=AuthSettings(notify_security_events=True, require_mfa=False),
        # The notice gate is waived in writing: the store starts with no Administrator, and the
        # test makes one inside the lifespan. The SMTP transport still wires the notifier.
        alerts_settings=AlertsSettings(
            email_smtp_host="smtp.example.invalid",
            email_from="alerts@example.invalid",
            security_notifications_required=False,
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )


async def _rows_after_shutdown(db: Path, action: str) -> list[Any]:
    """Read through a SECOND store on the same file, after the app has shut down, so the assertion
    is about what survived ``store.close()``."""
    store = await open_store(sqlite_settings(db), keyless_chain_refusal=None)
    try:
        return list(await store.list_audit(action=action))
    finally:
        await store.close()


async def _lock_in_lifespan(
    app: Any, monkeypatch: pytest.MonkeyPatch, gate: asyncio.Event
) -> AuthService:
    """Inside a running lifespan: lock an account with its throttle read held at ``gate``, so its
    notice is still pending when the lifespan exits however slow the runner is."""
    auth: AuthService = app.state.auth
    store = app.state.engine.store
    admin = await create_admin(auth)
    await store.set_user_notify_email(admin.user_id, email="owner@example.org")
    user = await store.get_user(admin.user_id)
    assert user is not None
    _patch_throttle_read(monkeypatch, store, before=gate.wait)
    await auth._record_lock(user, "sign_in", _lock(1), client=None)
    assert auth._background_tasks, "the notice did not run as a background task"
    return auth


async def test_the_lifespan_drains_a_pending_notice_before_the_store_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The notice is held until the shutdown drain is called, and released only there, so a
    lifespan that never drains would leave it pending past the store's close. A 0.2 s slow read
    used to stand in for that, and on a loaded runner the notice could finish before shutdown,
    which passed here without testing the drain."""
    monkeypatch.setattr(
        "messagefoundry.pipeline.security_notify.send_plain_email", lambda **_: None
    )
    db = tmp_path / "drain.db"
    app = _managed_app(db)
    gate = asyncio.Event()
    pending_at_drain: list[bool] = []
    async with app.router.lifespan_context(app):
        auth = await _lock_in_lifespan(app, monkeypatch, gate)
        real_drain = auth.drain_background

        async def release_then_drain(*, timeout: float | None = None, close: bool = False) -> None:
            if close:  # the shutdown drain, not the test's own join below
                pending_at_drain.append(bool(auth._background_tasks))
                gate.set()
            await real_drain(timeout=timeout, close=close)

        monkeypatch.setattr(auth, "drain_background", release_then_drain)
    # Had the lifespan skipped the drain, the held notice would still be waiting: finish it here so
    # it does not outlive the test. With the drain, there is nothing left to wait for.
    gate.set()
    await auth.drain_background()
    assert pending_at_drain == [True], (
        f"the shutdown drain did not run, or the notice was not pending at it: {pending_at_drain}"
    )
    rows = await _rows_after_shutdown(db, _LOCK_NOTICE)
    assert len(rows) == 1, f"the pending notice's row was lost at shutdown: {rows}"


async def test_the_lifespan_control_loses_the_row_without_the_drain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: neutralise the drain and the row is gone, so the test above measures it."""
    monkeypatch.setattr(
        "messagefoundry.pipeline.security_notify.send_plain_email", lambda **_: None
    )
    db = tmp_path / "nodrain.db"
    app = _managed_app(db)
    gate = asyncio.Event()
    async with app.router.lifespan_context(app):
        auth = await _lock_in_lifespan(app, monkeypatch, gate)

        async def skipped() -> None:
            return None

        monkeypatch.setattr(auth, "close_background", skipped)
    # The store is closed now. Release the held read and finish the orphaned task here, so it
    # meets the closed store deterministically and does not outlive the test.
    gate.set()
    await auth.drain_background()
    assert await _rows_after_shutdown(db, _LOCK_NOTICE) == [], (
        "the row survived with the drain neutralised, so the other test does not measure it"
    )
