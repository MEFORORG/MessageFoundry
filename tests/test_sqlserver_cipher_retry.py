# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline unit tests for the SQL Server ``add_cipher_invocations`` transient-retry (audit finding B0).

No real server: a fake connection/cursor drives the retry loop deterministically to prove it recovers
from a transient write conflict (HYT00 query timeout / 1205 deadlock) and applies the increment EXACTLY
once. The counter is the AES-GCM birthday bound (:mod:`messagefoundry.store.gcm_bound`), so a
double-count would UNDER-report headroom and eventually mis-gate re-key — it must never happen on a
retry. The DB-level guarantee (a timed-out/deadlocked MERGE commits nothing, so a rollback+re-issue
cannot double-apply) is a SQL Server property exercised end-to-end by the gated
``test_cipher_invocations_upsert_is_atomic_and_additive``; here we pin the loop's control flow.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from typing import Any

import pytest

from messagefoundry.store.sqlserver import (
    _CIPHER_MERGE_ATTEMPTS,
    SqlServerStore,
    _is_transient_write_conflict,
)
from messagefoundry.store.store import AuditAppend

_HYT00 = Exception("('HYT00', '[HYT00] [Microsoft][ODBC Driver 18]Query timeout expired (0)')")
_DEADLOCK = Exception("[42000] ... (1205) ... was deadlocked ... chosen as the deadlock victim")


def test_is_transient_write_conflict_matches_hyt00_and_deadlock_only() -> None:
    assert _is_transient_write_conflict(_HYT00)
    assert _is_transient_write_conflict(_DEADLOCK)
    # A lock-request timeout (1222) is the SET LOCK_TIMEOUT 0 yield handled by claim_fifo_heads, NOT a
    # cipher-upsert conflict — it must NOT trigger this retry.
    assert not _is_transient_write_conflict(Exception("... (1222) ... lock request time out"))
    assert not _is_transient_write_conflict(Exception("some unrelated database error"))


class _FakeCursor:
    def __init__(self, outcome: BaseException | None) -> None:
        self._outcome = outcome  # raise this on execute, or None to succeed
        self.ran = False

    async def execute(self, _sql: str, _params: Any) -> None:
        if self._outcome is not None:
            raise self._outcome
        self.ran = True

    async def fetchone(self) -> tuple[int]:
        return (170,)  # the OUTPUT'd new total (value is immaterial to the loop)


class _FakeConn:
    def __init__(self, store: _FakeStore) -> None:
        self._store = store

    async def rollback(self) -> None:
        self._store.rollbacks += 1


class _FakeStore:
    """The minimum surface ``add_cipher_invocations`` touches — one execute-outcome per attempt."""

    def __init__(
        self, outcomes: list[BaseException | None], *, commit_raises: BaseException | None = None
    ) -> None:
        self._outcomes = outcomes
        self._commit_raises = commit_raises
        self.attempt = 0
        self.commits = 0
        self.rollbacks = 0
        self.merges_run = 0  # how many MERGEs actually executed (would-be double-count if > 1)
        self.held = 0  # pooled connections currently borrowed
        self.events: list[str] = []  # acquire / release / sleep, in order
        self.held_at_sleep: list[int] = []  # self.held sampled inside each backoff sleep

    @contextlib.asynccontextmanager
    async def _acquire(self) -> AsyncIterator[_FakeConn]:
        self.events.append("acquire")
        self.held += 1
        try:
            yield _FakeConn(self)
        finally:
            self.held -= 1
            self.events.append("release")

    @contextlib.asynccontextmanager
    async def _cursor(self, _conn: _FakeConn) -> AsyncIterator[_FakeCursor]:
        cur = _FakeCursor(self._outcomes[self.attempt])
        self.attempt += 1
        try:
            yield cur
        finally:
            if cur.ran:
                self.merges_run += 1

    async def _commit(self, _conn: _FakeConn) -> None:
        if self._commit_raises is not None:
            raise self._commit_raises
        self.commits += 1


async def _add(store: _FakeStore, count: int = 5) -> int:
    return await SqlServerStore.add_cipher_invocations(store, "k", count)  # type: ignore[arg-type]


async def test_retries_past_transient_then_commits_exactly_once() -> None:
    store = _FakeStore([_HYT00, _DEADLOCK, None])  # two transient conflicts, then success
    total = await _add(store)
    assert total == 170
    assert store.attempt == 3  # tried three times
    assert store.rollbacks == 2  # the two conflicted attempts rolled back
    assert store.merges_run == 1  # exactly ONE MERGE actually ran — no double-count
    assert store.commits == 1  # committed exactly once


async def test_non_transient_error_is_not_retried() -> None:
    store = _FakeStore([Exception("conversion failed"), None])
    with pytest.raises(Exception, match="conversion failed"):
        await _add(store)
    assert store.attempt == 1  # a non-transient error is surfaced immediately, never retried
    assert store.commits == 0


async def test_failure_after_the_merge_ran_is_never_retried() -> None:
    # The no-double-count guard: once the MERGE has run + OUTPUT its total, a failure (here a commit that
    # itself times out) could be an already-committed increment, so it must NOT retry — even though the
    # error string looks transient.
    store = _FakeStore([None], commit_raises=_HYT00)
    with pytest.raises(Exception, match="HYT00"):
        await _add(store)
    assert store.attempt == 1  # merged=True short-circuited the retry
    assert store.merges_run == 1  # the MERGE ran once and was NOT re-issued


async def test_exhausts_the_cap_then_raises_the_last_transient() -> None:
    store = _FakeStore([_HYT00] * _CIPHER_MERGE_ATTEMPTS)
    with pytest.raises(Exception, match="HYT00"):
        await _add(store)
    assert store.attempt == _CIPHER_MERGE_ATTEMPTS  # bounded — never spins forever
    assert store.commits == 0  # never committed, so nothing was counted


async def test_the_backoff_holds_no_pooled_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    """The backoff must sleep with the connection RELEASED.

    Engine-specific, and the reason this diverges from the vault twin it was ported from. This store's
    ``_acquire`` bounds every other caller's pool wait at ``[store].acquire_timeout`` and then raises, so
    sleeping on a borrowed connection spends a resource its peers time out on -- under exactly the
    contention the retry exists for. A cancellation arriving in the sleep would also reach ``_acquire``'s
    ``except BaseException`` and quarantine the connection, destroying it to protect a transaction the
    rollback already discarded."""
    store = _FakeStore([_HYT00, _HYT00, None])

    real_sleep = asyncio.sleep

    async def _watched_sleep(delay: float) -> None:
        store.held_at_sleep.append(store.held)
        store.events.append("sleep")
        await real_sleep(0)  # keep the test fast; the delay itself is not under test

    monkeypatch.setattr(asyncio, "sleep", _watched_sleep)
    assert await _add(store) == 170

    assert store.held_at_sleep == [0, 0]  # nothing borrowed across either backoff
    assert store.held == 0  # and nothing leaked at the end
    # Every sleep sits BETWEEN a release and the next acquire, never inside a borrow.
    assert store.events == [
        "acquire",
        "release",
        "sleep",
        "acquire",
        "release",
        "sleep",
        "acquire",
        "release",
    ]


async def test_a_raising_attempt_never_reaches_the_backoff() -> None:
    """A non-transient failure must not sleep at all -- the retry flag gates the backoff, so the
    restructured loop cannot introduce a delay on the raise path."""
    store = _FakeStore([Exception("conversion failed")])
    with pytest.raises(Exception, match="conversion failed"):
        await _add(store)
    assert store.events == ["acquire", "release"]  # no sleep
    assert store.held == 0


class _FlagStore:
    """The surface ``set_connection_flag`` touches. It holds one cursor across its retries, unlike
    ``add_cipher_invocations``, so each execute takes the next outcome. Each take of the audit
    applock takes the next of ``applock`` the same way, and an exhausted list lets it through."""

    def __init__(
        self,
        outcomes: list[BaseException | None],
        applock: list[BaseException | None] | None = None,
    ) -> None:
        self._outcomes = outcomes
        self._applock = applock or []
        self.statements: list[str] = []
        self.rollbacks = 0
        self.discards = 0
        self.audits = 0
        self.commits = 0

    async def execute(self, sql: str, _params: Any) -> None:
        self.statements.append(sql)
        outcome = self._outcomes.pop(0)
        if outcome is not None:
            raise outcome

    async def rollback(self) -> None:
        self.rollbacks += 1
        self.statements.append("ROLLBACK")

    async def _open_under_audit_applock(self, _cur: Any) -> None:
        self.statements.append("APPLOCK")
        outcome = self._applock.pop(0) if self._applock else None
        if outcome is not None:
            raise outcome

    @contextlib.asynccontextmanager
    async def _acquire(self) -> AsyncIterator[_FlagStore]:
        yield self

    @contextlib.asynccontextmanager
    async def _cursor(self, _conn: Any) -> AsyncIterator[_FlagStore]:
        yield self

    async def _append_operator_audit(self, *_args: Any) -> None:
        self.audits += 1

    async def _commit(self, _conn: Any) -> None:
        self.commits += 1

    async def _rollback_or_discard(self, _conn: Any) -> None:
        self.discards += 1


async def _set_flag(store: _FlagStore, *, flagged: bool) -> None:
    await SqlServerStore.set_connection_flag(
        store,  # type: ignore[arg-type]
        "OB_A",
        "outbound",
        flagged=flagged,
        audit=AuditAppend("connection_flag_set"),
    )


@pytest.mark.parametrize(("flagged", "statement"), [(True, "MERGE"), (False, "DELETE")])
async def test_a_flag_write_retries_past_a_conflict_and_appends_one_row(
    flagged: bool, statement: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The set and the clear each follow the audit applock, so a conflict rolls back, which releases
    the applock, and the re-run takes it again before its flag statement. The audit row lands once.
    The log names the statement that ran. RED for the clear when the helper's line says MERGE for a
    DELETE, and RED when a re-run reaches its flag statement without the applock."""
    store = _FlagStore([_DEADLOCK, None])
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.store.sqlserver"):
        await _set_flag(store, flagged=flagged)
    assert [sql.split()[0] for sql in store.statements] == [
        "APPLOCK",
        statement,
        "ROLLBACK",
        "APPLOCK",
        statement,
    ]
    assert (store.rollbacks, store.audits, store.commits, store.discards) == (1, 1, 1, 0)
    other = "DELETE" if flagged else "MERGE"
    retried = [r.getMessage() for r in caplog.records if "retrying" in r.getMessage()]
    assert len(retried) == 1
    assert statement in retried[0] and other not in retried[0]


async def test_a_flag_write_that_never_clears_commits_nothing() -> None:
    """Bounded, as the other retries are, and no audit row is appended for a write that did not
    land. The refusal reaches the caller, which is what the route answers 503 for."""
    store = _FlagStore([_HYT00] * _CIPHER_MERGE_ATTEMPTS)
    with pytest.raises(Exception, match="HYT00"):
        await _set_flag(store, flagged=False)
    retry = ["ROLLBACK", "APPLOCK", "DELETE"]
    assert [sql.split()[0] for sql in store.statements] == ["APPLOCK", "DELETE"] + retry * (
        _CIPHER_MERGE_ATTEMPTS - 1
    )
    assert (store.audits, store.commits, store.discards) == (0, 0, 1)


@pytest.mark.parametrize("retake", [False, True], ids=["first-take", "re-take"])
async def test_a_flag_write_whose_applock_wait_fails_is_not_retried(retake: bool) -> None:
    """A transient-looking failure at the audit applock, first or after a rollback, raises at once
    and writes nothing. It is the store's busiest lock, and a retry there would queue on it again;
    the append took it outside any retry before the applock moved to the front."""
    if retake:
        store = _FlagStore([_DEADLOCK, None], applock=[None, _HYT00])
    else:
        store = _FlagStore([None], applock=[_HYT00])
    with pytest.raises(RuntimeError, match="audit applock was not granted") as caught:
        await _set_flag(store, flagged=False)
    assert caught.value.__cause__ is _HYT00
    expected = ["APPLOCK", "DELETE", "ROLLBACK", "APPLOCK"] if retake else ["APPLOCK"]
    assert [sql.split()[0] for sql in store.statements] == expected
    assert (store.audits, store.commits, store.discards) == (0, 0, 1)
