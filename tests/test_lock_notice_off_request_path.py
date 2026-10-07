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
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

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
#: Longer than the deferred writes' room in the sign-in pad. A write this slow on the request path
#: moves the answer to a later slot.
_SLOW = service_module._FAILURE_BUDGET_SECONDS * service_module._WRITE_ROOM_SHARE * 2.4
#: A deadlock guard. The tests below hold a task until a peer makes progress, never until time
#: passes. If a hold can never come true, this bound ends it with a message. It is shorter than the
#: per-test watchdog's 60 seconds, which would kill the whole run instead.
_STALL_SECONDS = 20.0


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


def _in_background(service: AuthService) -> bool:
    """Whether the running task is one of the service's own background tasks."""
    return asyncio.current_task() in service._background_tasks


class _HeldRead:
    """Holds the throttle's read at ``gate`` while it runs in one of the service's background tasks.

    ``off_path`` counts those reads. A read on the request path is counted in ``on_path`` and let
    through. Holding it there would hang the refusal that waits on it, so a regression fails an
    assertion instead. The test's own reads of the rows also land in ``on_path``, so a test reads
    that count before it reads any rows."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        store: MessageStore,
        service: AuthService,
        gate: asyncio.Event,
    ) -> None:
        self.off_path = 0
        self.on_path = 0
        real = store.list_audit

        async def held(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("action") == _LOCK_NOTICE:
                if _in_background(service):
                    self.off_path += 1
                    await gate.wait()
                else:
                    self.on_path += 1
            return await real(*args, **kwargs)

        monkeypatch.setattr(store, "list_audit", held)


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
    real read slow. The read is also held at a gate until the refusal has answered. So it cannot
    finish inside the answer, and its walk of those rows cannot compete with the refusal's own
    writes. The test also checks which task ran the read, so a read on the request path fails it
    directly. The notice still goes out once the gate opens, and the seeded rows of other accounts
    do not hold this account's mail back."""
    monkeypatch.setattr(service_module, "_BUDGET_OVERRUN_WARNED", set())
    _cheap_wrong_password(monkeypatch)
    store, service, notifier, user = await _harness()
    try:
        await _seed_other_accounts_notices(store, 50_000)
        gate = asyncio.Event()
        reads = _HeldRead(monkeypatch, store, service, gate)
        deadlines = _record_deadlines(monkeypatch)
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            started = time.monotonic()
            try:
                out = await service.login(ADMIN_USERNAME, "wrong-passphrase")
            finally:
                gate.set()  # never leave a held read behind in the shared loop
            assert reads.on_path == 0, "the throttle read ran on the request path"
            assert not out.ok
            refused_by = deadlines[-1] - started
            await service.drain_background()
        assert _write_overruns(caplog) == [], _write_overruns(caplog)
        assert refused_by <= service_module._FAILURE_BUDGET_SECONDS + 0.05, (
            f"the lock-setting refusal answered {refused_by:.3f}s in, past its first slot"
        )
        # The throttle did run, in the background, after the answer's deadline was fixed.
        assert reads.off_path == 1, reads.off_path
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
#
# Every test here forces its schedule. A task is held until a peer has got as far as the code lets
# it, never until time passes. Timing alone cannot make two notices overlap. Each task starts only
# after its lock's own ``auth.account_locked`` row is written. On a slow runner the second row can
# land after the first task has finished, and then the tasks never meet. The BACKLOG #2216 control
# failed that way in the merge queue.


def _lock(cycle: int) -> LockoutIncrement:
    return LockoutIncrement(attempts=1, just_locked=True, cycles=cycle)


def _parallel_reads(service: AuthService) -> None:
    """Let two throttle reads run at once, so a test can see two kinds' reads in flight together
    rather than the service-wide one-read-at-a-time limit."""
    service._lock_notice_read_slots = asyncio.Semaphore(2)


class _Progress:
    """Counters a held task waits on. Every change wakes the waiters, which re-check their own
    condition, so a task waits for a peer's progress and never for time.

    A hold that never comes true is recorded in ``stalls`` and then let go, rather than raised.
    The holds sit inside the notice's task, which logs and swallows what it raises: a throttle read
    fails open. So each test asserts ``stalls`` is empty itself. After one stall the schedule is
    already broken, so later holds let go at once rather than add their own wait."""

    def __init__(self) -> None:
        self._changed = asyncio.Event()
        self.stalls: list[str] = []

    def changed(self) -> None:
        self._changed.set()

    async def until(self, ready: Callable[[], bool], what: str) -> None:
        try:
            async with asyncio.timeout(_STALL_SECONDS):
                while not (ready() or self.stalls):
                    self._changed.clear()
                    await self._changed.wait()
        except TimeoutError:
            self.stalls.append(what)
            self.changed()  # wake any hold already waiting, so it lets go too


class _QueueProbe(_Progress):
    """Watches the entrance to the per-account, per-kind lock-notice queue.

    ``arrived`` counts the notices that reached the queue and ``entered`` those that got through.
    A held task reads them only while every peer is suspended, and the queue's lock is the one
    place a notice can suspend between the two counts. So ``parked`` is the number of notices
    waiting in the queue. With ``queue=False`` the queue is taken away, nothing suspends there, and
    ``parked`` stays 0."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, service: AuthService, *, queue: bool = True
    ) -> None:
        super().__init__()
        self.arrived = 0
        self.entered = 0
        real = service_module._hold_keyed_lock
        notices = service._lock_notice_locks

        @asynccontextmanager
        async def no_queue(_table: Any, _key: str) -> AsyncIterator[None]:
            yield

        inner = real if queue else no_queue

        @asynccontextmanager
        async def probed(table: Any, key: str) -> AsyncIterator[None]:
            if table is not notices:
                async with real(table, key):
                    yield
                return
            self.arrived += 1
            self.changed()
            async with inner(table, key):
                self.entered += 1
                self.changed()
                yield

        monkeypatch.setattr(service_module, "_hold_keyed_lock", probed)

    @property
    def parked(self) -> int:
        return self.arrived - self.entered


class _RaceSchedule:
    """The schedule the same-kind race needs, forced: no notice writes its ``auth.lock_notice``
    row until its peer has either read the throttle too or is parked in the queue.

    Without the queue the peer is never parked, so both tasks read before either writes, which is
    the race. With the queue the peer is parked, so the first writes and the second then reads that
    row. The schedule is the same in both; only the queue differs. ``at_first_write`` records the
    counters when the first row write was let through, so a test can show which arm it took.
    ``parked_after_first_write`` is read once that write returns. With the queue held across the
    write it is still 1; a queue released before the write would have let the peer in by then."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        store: MessageStore,
        service: AuthService,
        *,
        queue: bool,
    ) -> None:
        self.probe = _QueueProbe(monkeypatch, service, queue=queue)
        self.reads = 0
        self.at_first_write: dict[str, int] | None = None
        self.parked_after_first_write: int | None = None
        real_read = store.list_audit
        real_write = service._record_lock_notice

        async def read(*args: Any, **kwargs: Any) -> Any:
            rows = await real_read(*args, **kwargs)
            if kwargs.get("action") == _LOCK_NOTICE and _in_background(service):
                self.reads += 1  # counted once the read has its answer
                self.probe.changed()
            return rows

        async def write(user: UserRecord, lock: str, *, handed: bool) -> None:
            await self.probe.until(
                lambda: self.reads == 2 or self.probe.parked > 0,
                "the peer to read the throttle or park in the queue",
            )
            first = self.at_first_write is None
            if first:
                self.at_first_write = {
                    "reads": self.reads,
                    "arrived": self.probe.arrived,
                    "parked": self.probe.parked,
                }
            await real_write(user, lock, handed=handed)
            if first:
                self.parked_after_first_write = self.probe.parked

        monkeypatch.setattr(store, "list_audit", read)
        monkeypatch.setattr(service, "_record_lock_notice", write)


async def _two_same_kind_locks(service: AuthService, user: UserRecord) -> None:
    await asyncio.gather(
        service._record_lock(user, "sign_in", _lock(1), client=None),
        service._record_lock(user, "sign_in", _lock(2), client=None),
    )
    await service.drain_background()


async def test_two_same_kind_locks_at_once_send_one_mail_and_write_one_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Off the request path, two sign-in locks on one account can land together, for example one
    set by a re-proof while a sign-in sets it too. Each task would read the throttle before the
    other wrote its row. The per-account, per-kind queue makes the second read the first's row.

    The first notice is held before its row write until the second is parked in the queue, so both
    are in flight together; the control below runs the same schedule with the queue taken away."""
    store, service, notifier, user = await _harness()
    try:
        schedule = _RaceSchedule(monkeypatch, store, service, queue=True)
        await _two_same_kind_locks(service, user)
        assert schedule.probe.stalls == [], schedule.probe.stalls
        assert schedule.at_first_write == {"reads": 1, "arrived": 2, "parked": 1}, (
            "the second notice was not waiting in the queue when the first wrote its row"
        )
        assert schedule.parked_after_first_write == 1, "the queue let go before the row was written"
        assert schedule.reads == 2, "both locks must reach the throttle for this to test the race"
        assert len(notifier.locks()) == 1, [e.detail for e in notifier.locks()]
        assert len(await _lock_notice_rows(store, user.username)) == 1
        locked = await store.list_audit(actor=user.username, action="auth.account_locked")
        assert len(locked) == 2, "each lock still writes its own auth.account_locked row"
        assert service._lock_notice_locks == {}, "the queue table kept an entry nobody holds"
    finally:
        await store.close()


async def test_the_race_is_real_without_the_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the race test: the same two locks, on the same forced schedule, with the
    per-account queue taken away. Both tasks read the throttle before either writes its row, and
    the owner gets two mails. So the single mail above is the queue's doing."""
    store, service, notifier, user = await _harness()
    try:
        schedule = _RaceSchedule(monkeypatch, store, service, queue=False)
        await _two_same_kind_locks(service, user)
        assert schedule.probe.stalls == [], schedule.probe.stalls
        assert schedule.at_first_write == {"reads": 2, "arrived": 2, "parked": 0}, (
            "both notices must have read the throttle before either wrote, or this is no race"
        )
        assert schedule.parked_after_first_write == 0
        assert len(notifier.locks()) == 2
        assert len(await _lock_notice_rows(store, user.username)) == 2
    finally:
        await store.close()


async def _peak_reads_across_accounts(
    monkeypatch: pytest.MonkeyPatch, slots: int | None
) -> tuple[int, list[str], list[str], list[str]]:
    """Lock five accounts at once and return the most throttle reads that ran together, the
    usernames mailed, the usernames locked, and any stalled hold. ``slots`` replaces the service's
    limit; ``None`` keeps it.

    The first read is held until all five reads have reached the limit, so every read is waiting
    together and the limit alone decides how many run at once."""
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
        if slots is not None:
            service._lock_notice_read_slots = asyncio.Semaphore(slots)
        limit = service._lock_notice_read_slots
        real_acquire = limit.acquire
        progress = _Progress()
        arrived = 0

        async def counting_acquire() -> Literal[True]:
            nonlocal arrived
            arrived += 1  # counted before it can wait for a slot
            progress.changed()
            return await real_acquire()

        monkeypatch.setattr(limit, "acquire", counting_acquire)
        real = store.list_audit
        running = 0
        peak = 0

        async def counted(*args: Any, **kwargs: Any) -> Any:
            nonlocal running, peak
            if kwargs.get("action") != _LOCK_NOTICE:
                return await real(*args, **kwargs)
            running += 1
            peak = max(peak, running)
            try:
                await progress.until(
                    lambda: arrived == len(users), "every account's read to reach the limit"
                )
                return await real(*args, **kwargs)
            finally:
                running -= 1

        monkeypatch.setattr(store, "list_audit", counted)
        await asyncio.gather(
            *(service._record_lock(u, "sign_in", _lock(1), client=None) for u in users)
        )
        await service.drain_background()
        return (
            peak,
            sorted(e.username for e in notifier.locks()),
            sorted(u.username for u in users),
            progress.stalls,
        )
    finally:
        await store.close()


async def test_one_throttle_read_runs_at_a_time_across_accounts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each throttle read walks every recent ``auth.lock_notice`` row, so locks on many accounts at
    once would fill the store's read pool that sign-ins wait on. The service runs one at a time.
    Every account still gets its mail."""
    peak, mailed, locked, stalls = await _peak_reads_across_accounts(monkeypatch, slots=None)
    assert stalls == [], stalls
    assert peak == 1, f"{peak} throttle reads ran at once"
    assert mailed == locked


async def test_the_read_limit_control_lets_every_read_run_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control for the test above: on the same schedule, with the limit raised to five, all
    five reads run together. So a peak of one above is the limit's doing, not reads that happened
    never to overlap."""
    peak, mailed, locked, stalls = await _peak_reads_across_accounts(monkeypatch, slots=5)
    assert stalls == [], stalls
    assert peak == 5, f"only {peak} throttle reads ran at once"
    assert mailed == locked


async def test_two_kinds_at_once_are_not_queued_behind_each_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The queue is per lock kind: a sign-in lock and a second-step lock landing together are two
    notices, as the time throttle has always counted them, and neither waits for the other. With
    two reads allowed at once, the first read is held until the other kind's notice is reading too
    or is parked in the queue. A queue keyed on the account alone would park it, and the peak
    would be one."""
    store, service, notifier, user = await _harness()
    try:
        _parallel_reads(service)
        probe = _QueueProbe(monkeypatch, service)
        real = store.list_audit
        running = 0
        peak = 0
        done = 0

        async def counted(*args: Any, **kwargs: Any) -> Any:
            nonlocal running, peak, done
            if kwargs.get("action") != _LOCK_NOTICE:
                return await real(*args, **kwargs)
            running += 1
            peak = max(peak, running)
            probe.changed()
            try:
                # A read that comes after the other kind's has finished has nobody to wait for.
                await probe.until(
                    lambda: running == 2 or probe.parked > 0 or done > 0,
                    "the other kind's notice to read too or park in the queue",
                )
                return await real(*args, **kwargs)
            finally:
                running -= 1
                done += 1

        monkeypatch.setattr(store, "list_audit", counted)
        await asyncio.gather(
            service._record_lock(user, "sign_in", _lock(1), client=None),
            service._record_lock(user, "second_step", _lock(1), client=None, factor="password"),
        )
        await service.drain_background()
        assert probe.stalls == [], probe.stalls
        assert probe.arrived == 2, "both notices must reach the queue for this to test it"
        assert peak == 2, "the two kinds' notices queued behind each other"
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
        _HeldRead(monkeypatch, store, service, asyncio.Event())  # a gate nobody opens
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
    """The control for the shutdown test: a notice still pending when the drain starts finishes
    inside the drain's bound, writes its row, sends its mail, and logs no cancellation."""
    store, service, notifier, user = await _harness()
    try:
        gate = asyncio.Event()
        _HeldRead(monkeypatch, store, service, gate)
        caplog.clear()
        with caplog.at_level(logging.INFO):
            await service._record_lock(user, "sign_in", _lock(1), client=None)
            assert service._background_tasks, "the notice was not pending when the drain started"
            gate.set()
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
    app: Any, monkeypatch: pytest.MonkeyPatch, *, gate: asyncio.Event
) -> AuthService:
    """Inside a running lifespan: lock an account with its throttle read held at ``gate``, so its
    notice is still pending when the lifespan exits, however fast or slow this machine is."""
    auth: AuthService = app.state.auth
    store = app.state.engine.store
    admin = await create_admin(auth)
    await store.set_user_notify_email(admin.user_id, email="owner@example.org")
    user = await store.get_user(admin.user_id)
    assert user is not None
    _HeldRead(monkeypatch, store, auth, gate)
    await auth._record_lock(user, "sign_in", _lock(1), client=None)
    assert auth._background_tasks, "the notice did not run as a background task"
    return auth


async def test_the_lifespan_drains_a_pending_notice_before_the_store_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "messagefoundry.pipeline.security_notify.send_plain_email", lambda **_: None
    )
    db = tmp_path / "drain.db"
    app = _managed_app(db)
    gate = asyncio.Event()
    pending_at_drain: list[bool] = []
    try:
        async with app.router.lifespan_context(app):
            auth = await _lock_in_lifespan(app, monkeypatch, gate=gate)
            real_close = auth.close_background

            async def open_gate_then_drain() -> None:
                # The notice is held until the shutdown drain starts, so it is pending there.
                pending_at_drain.append(bool(auth._background_tasks))
                gate.set()
                await real_close()

            monkeypatch.setattr(auth, "close_background", open_gate_then_drain)
    finally:
        gate.set()  # never leave a held read behind in the shared loop
    # Join anything the lifespan left running, so it cannot outlive the test.
    await auth.drain_background()
    assert pending_at_drain, "the lifespan never called close_background"
    assert pending_at_drain == [True], "the notice was not pending when the drain started"
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
        auth = await _lock_in_lifespan(app, monkeypatch, gate=gate)

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
