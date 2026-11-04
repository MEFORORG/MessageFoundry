# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: an operator mutation and its audit row commit together (BACKLOG #2624).

Replay, dead-letter replay, purge (``cancel_queued``), resend, the edit-and-resubmit re-ingress and
the upload inject each take an :data:`~messagefoundry.store.store.OperatorAudit`. The store appends
the row it builds inside the mutation's own transaction. Before #2624 the API wrote the row in a
second transaction, so a crash between the two kept the change and lost who made it. The four
operator alert mutations (ack, resolve, suspend, resume) take one ``AuditAppend`` the same way
(vault BACKLOG #3217), and so does the connection flag (BACKLOG #2623).

Each case runs twice. First the audit append is made to fail, and the case asserts the store change
rolled back with it: neither committed. Then it runs clean and asserts both committed, the row
carrying the actor, channel and client the caller gave. The failing leg alone would also pass a store
that never called the audit at all, so the clean leg is the control that makes it mean something.

The fault is injected at ``_append_audit_row``, the one append every backend's audited writes go
through. Its action argument is matched by value, so the same wrapper fits all three signatures.

The fault helpers and :class:`TeeTap` are shared: the dual-control and TOTP-replace contracts use
them too, and :func:`failing_commit` refuses a COMMIT for them (vault BACKLOG #3324).

Deliberately **extra-free**, like ``_pending_approval_store_contract``: the live server legs import it
inside a test function. Every name it writes is unique per run, so a shared server database is safe.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager, suppress
from typing import Any
from uuid import uuid4

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import StoreBackend
from messagefoundry.store.base import (
    CONNECTION_FLAG_LOCK_TIMEOUT_SECONDS,
    ConnectionFlagLockTimeout,
)
from messagefoundry.store.store import AuditAppend, MessageOrigin

_RAW = (
    "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A01|MSG0001|P|2.5\r"
    "PID|1||12345^^^HOSP^MR||DOE^JANE\r"
)
_CLIENT = "10.0.0.24"


class AppendFailed(RuntimeError):
    """The fault this contract injects into the audit append."""


@contextmanager
def _hooked_append(
    store: Any, before: Callable[[tuple[Any, ...]], Awaitable[None]]
) -> Iterator[None]:
    """Run ``before`` with each of ``store``'s audit appends' positional arguments, ahead of the
    real append."""
    real = store._append_audit_row

    async def _append(*args: Any, **kwargs: Any) -> Any:
        await before(args)
        return await real(*args, **kwargs)

    store._append_audit_row = _append
    try:
        yield
    finally:
        del store._append_audit_row


@contextmanager
def failing_append(store: Any, action: str | None) -> Iterator[None]:
    """Make ``store``'s audit append raise for ``action``, and only for it, or for every action
    when it is ``None``."""

    async def _refuse(args: tuple[Any, ...]) -> None:
        if action is None or action in args:
            raise AppendFailed(action)

    with _hooked_append(store, _refuse):
        yield


class CommitFailed(RuntimeError):
    """The fault :func:`failing_commit` injects into a store's COMMIT."""


def commit_seam(store: Any) -> bool:
    """Whether ``store`` has a ``_commit`` method a test can fault (vault BACKLOG #3324). On SQLite
    and SQL Server the single-transaction writes these contracts fault commit through it, but not
    every write does: a SQLite grouped commit and a SQL Server fused-hop handoff do not. Postgres
    commits as asyncpg's transaction block exits, which has no such seam, so an arm that needs
    :func:`failing_commit` does not run on that leg."""
    return callable(getattr(type(store), "_commit", None))


@contextmanager
def failing_commit(store: Any) -> Iterator[None]:
    """Make ``store``'s COMMIT raise, once every statement before it has run. Only where
    :func:`commit_seam` holds."""

    async def _commit(*_args: Any, **_kwargs: Any) -> None:
        raise CommitFailed("commit refused")

    store._commit = _commit
    try:
        yield
    finally:
        del store._commit


class TeeTap(logging.Handler):
    """Read each row a store tees off-box, from the real tee's own log record.

    A handler on the ``messagefoundry.audit`` logger, so the real ``tee_audits`` path runs and
    nothing is patched. Only teed rows land here, so a row that rolled back must not appear, and a
    committed one must appear exactly once."""

    def __init__(self) -> None:
        super().__init__()
        self.teed: list[dict[str, Any]] = []
        logging.getLogger("messagefoundry.audit").addHandler(self)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            event = json.loads(record.getMessage())
        except ValueError:
            return
        if isinstance(event, dict):
            self.teed.append(event)

    def stop(self) -> None:
        logging.getLogger("messagefoundry.audit").removeHandler(self)

    def ids(self, action: str, approval_id: str | None = None) -> list[int]:
        """The row ids teed for ``action``; with ``approval_id``, only that request's."""
        found = []
        for event in self.teed:
            if event.get("action") != action:
                continue
            if approval_id is None:
                found.append(int(event["row_id"]))
                continue
            try:
                detail = json.loads(str(event.get("detail")))
            except ValueError:
                continue
            if isinstance(detail, dict) and detail.get("approval_id") == approval_id:
                found.append(int(event["row_id"]))
        return found


def _builder(action: str, channel_id: str | None) -> Callable[[Any], AuditAppend | None]:
    """An audit that records every result it is handed, so a zero is visible too."""

    def _row(result: Any) -> AuditAppend:
        return AuditAppend(
            action,
            actor="contract-op",
            channel_id=channel_id,
            detail=json.dumps({"result": str(getattr(result, "status", result))}),
            client=_CLIENT,
        )

    return _row


async def _statuses(store: Any, message_id: str) -> dict[str, str]:
    return {
        str(r["destination_name"]): str(r["status"]) for r in await store.outbox_for(message_id)
    }


async def _seed(store: Any, channel: str, dest: str, *, settle: str | None) -> str:
    """One message with one outbound row to ``dest``, left pending, dead or done."""
    mid = str(await store.enqueue_message(channel_id=channel, raw=_RAW, deliveries=[(dest, _RAW)]))
    if settle is not None:
        items = await store.claim_ready(channel_id=channel, destination_name=dest)
        assert [i.message_id for i in items] == [mid]
        if settle == "dead":
            await store.mark_failed(items[0].id, "boom", RetryPolicy(max_attempts=1))
        else:
            await store.mark_done(items[0].id)
    assert (await _statuses(store, mid)) == {dest: settle or "pending"}
    return mid


async def _rows(store: Any, action: str) -> list[Any]:
    return list(await store.list_audit(action=action, limit=10))


async def _check(
    store: Any,
    *,
    label: str,
    channel: str | None,
    run: Callable[[Callable[[Any], AuditAppend | None]], Awaitable[Any]],
    unchanged: Callable[[], Awaitable[None]],
    changed: Callable[[Any], Awaitable[None]],
) -> None:
    action = f"contract.{label}.{uuid4().hex[:8]}"
    audit = _builder(action, channel)
    with failing_append(store, action), pytest.raises(AppendFailed):
        await run(audit)
    await unchanged()
    assert await _rows(store, action) == [], f"{label}: a failed append left its row"
    result = await run(audit)
    await changed(result)
    rows = await _rows(store, action)
    assert len(rows) == 1, f"{label}: the clean run committed {len(rows)} audit rows"
    row = rows[0]
    assert (row["actor"], row["channel_id"], row["client"]) == ("contract-op", channel, _CLIENT)


async def _assert_connection_flag_atomic(store: Any, tag: str) -> None:
    """The object-of-interest flag commits with its row, and a row IS the flag (BACKLOG #2623): a
    set, a repeat that adds no second row, a clear, and a clear of nothing, which still audits."""
    conn = f"OB_F{tag}"

    async def is_clear() -> None:
        assert (conn, "outbound") not in await store.list_connection_flags()

    async def is_flagged() -> None:
        assert (conn, "outbound") in await store.list_connection_flags()

    async def was_flagged(_result: Any) -> None:
        await is_flagged()

    async def was_cleared(_result: Any) -> None:
        await is_clear()

    def setter(flagged: bool) -> Callable[[Callable[[Any], AuditAppend | None]], Awaitable[Any]]:
        async def run(audit: Callable[[Any], AuditAppend | None]) -> None:
            built = audit(flagged)
            assert built is not None
            await store.set_connection_flag(conn, "outbound", flagged=flagged, audit=built)

        return run

    await _check(
        store,
        label="flag-set",
        channel=None,
        run=setter(True),
        unchanged=is_clear,
        changed=was_flagged,
    )
    await _check(
        store,
        label="flag-repeat",
        channel=None,
        run=setter(True),
        unchanged=is_flagged,
        changed=was_flagged,
    )
    await _check(
        store,
        label="flag-clear",
        channel=None,
        run=setter(False),
        unchanged=is_flagged,
        changed=was_cleared,
    )
    await _check(
        store,
        label="flag-clear-none",
        channel=None,
        run=setter(False),
        unchanged=is_clear,
        changed=was_cleared,
    )
    # The direction is part of the key, so the same name on the other side stays unflagged.
    built = AuditAppend("contract.flag-in", actor="contract-op")
    await store.set_connection_flag(conn, "inbound", flagged=True, audit=built)
    await is_clear()
    assert (conn, "inbound") in await store.list_connection_flags()
    await store.set_connection_flag(conn, "inbound", flagged=False, audit=built)


#: How long the second toggle gets to reach its audit append while the first is held open. Under the
#: audit lock taken first it waits at the database and never gets there, whatever this is. Without
#: that lock, a server slower than this to run one statement would let the old order pass here; the
#: offline order tests in test_connection_flag.py and test_sqlserver_cipher_retry.py do not wait.
_OVERLAP_WINDOW = 1.0


@contextmanager
def _held_append(
    store: Any, action: str, reached: asyncio.Event, release: asyncio.Event
) -> Iterator[None]:
    """Hold ``store``'s first append for ``action`` until ``release`` is set, and set ``reached``
    as it starts. The flag statement has run by then and the transaction is still open."""

    async def _hold(args: tuple[Any, ...]) -> None:
        if action in args and not reached.is_set():
            reached.set()
            await release.wait()

    with _hooked_append(store, _hold):
        yield


#: (label, initial, first_sets, second_sets, second_commits_first): each a pair the old order, the
#: lock taken only at the append, let through. On Postgres at READ COMMITTED all three did; on SQL
#: Server the no-op clear did, since it locks nothing.
_OVERLAP_CASES = (
    # A set, then a clear that cannot see it: the clear deleted nothing and appended last.
    ("setclear", False, True, False, False),
    # A clear of nothing, then a set it does not block, which commits first.
    ("clearset", False, False, True, True),
    # A set of a flag already set changes no row, so a clear beside it commits first.
    ("resetclear", True, True, False, True),
)


async def _assert_overlapping_toggles_ordered(
    first: Any,
    second: Any,
    label: str,
    initial: bool,
    first_sets: bool,
    second_sets: bool,
    second_commits_first: bool,
) -> None:
    """Two store handles, standing in for two engine shards, toggle one connection. The first is
    held open between its flag statement and its commit while the second runs, then whichever
    ``second_commits_first`` names commits first. The flag must match the newest row after."""
    conn = f"OB_X{label}{uuid4().hex[:8]}"
    action = "connection_flag_set"

    async def toggle(store: Any, flagged: bool) -> None:
        detail = json.dumps({"connection": conn, "flagged": flagged})
        audit = AuditAppend(action, actor="contract-op", detail=detail, client=_CLIENT)
        await store.set_connection_flag(conn, "outbound", flagged=flagged, audit=audit)

    if initial:
        await toggle(first, True)
    a_reached, a_release, b_reached, b_release = (asyncio.Event() for _ in range(4))
    tasks: list[asyncio.Task[None]] = []
    with (
        _held_append(first, action, a_reached, a_release),
        _held_append(second, action, b_reached, b_release),
    ):
        try:
            a = asyncio.create_task(toggle(first, first_sets))
            tasks.append(a)
            await asyncio.wait_for(a_reached.wait(), 30)
            b = asyncio.create_task(toggle(second, second_sets))
            tasks.append(b)
            with suppress(TimeoutError):
                await asyncio.wait_for(b_reached.wait(), _OVERLAP_WINDOW)
            overlapped = b_reached.is_set()
            if second_commits_first:
                b_release.set()
                if overlapped:
                    await b
                a_release.set()
            else:
                a_release.set()
                await a
                b_release.set()
            await asyncio.gather(a, b)
        finally:
            a_release.set()
            b_release.set()
            await asyncio.gather(*tasks, return_exceptions=True)
    flagged = (conn, "outbound") in await first.list_connection_flags()
    rows = [
        r
        for r in await first.list_audit(action=action, limit=50)
        if json.loads(str(r["detail"]))["connection"] == conn
    ]
    newest = json.loads(str(max(rows, key=lambda r: int(r["id"]))["detail"]))["flagged"]
    assert flagged is newest, (
        f"{label}: the flag is {'set' if flagged else 'clear'} under a newest row that says"
        f" {'set' if newest else 'clear'}"
    )
    # What makes that hold: the second toggle could not reach its append, which follows its flag
    # statement, until the first had committed.
    assert not overlapped, f"{label}: the second toggle ran its flag statement beside the first"


async def assert_connection_flag_ordered_across_stores(first: Any, second: Any) -> None:
    """Two processes' toggles of one connection land one after the other (BACKLOG #2623): each
    takes the audit lock before its flag statement and holds it to the commit, so the stored flag
    always matches the newest ``connection_flag_set`` row. ``first`` and ``second`` are two handles
    on one database, so neither shares the other's in-process locks."""
    for case in _OVERLAP_CASES:
        await _assert_overlapping_toggles_ordered(first, second, *case)


#: How far past the store's bound the toggle's refusal may come: the opener, the audit lock, the
#: rollback and, on SQL Server, the reset. The driver's query timeout, 30 s by default, is well past.
_REFUSAL_SLACK = 5.0

#: How long an audit append from another handle gets once the toggle has given up, with the foreign
#: lock still held. Without the bound the toggle would still hold the audit lock here.
_APPEND_PROMPT = 5.0


@asynccontextmanager
async def _foreign_flag_lock(holder: Any, conn: str, *, stored: bool) -> AsyncIterator[None]:
    """A transaction on ``holder`` that is no toggle and holds a lock on ``conn``'s outbound flag
    row until the block exits, then rolls back: an update lock on the stored row when ``stored``,
    else an uncommitted insert of it. Raw SQL on the backend's own connection, so neither the
    audit lock nor any lock of the store's own is taken."""
    if holder.backend is StoreBackend.POSTGRES:
        async with holder._timed_acquire(record=False) as raw:
            tx = raw.transaction()
            await tx.start()
            try:
                if stored:
                    await raw.execute(
                        "SELECT 1 FROM connection_flag"
                        " WHERE connection=$1 AND direction='outbound' FOR UPDATE",
                        conn,
                    )
                else:
                    await raw.execute(
                        "INSERT INTO connection_flag (connection, direction)"
                        " VALUES ($1, 'outbound')",
                        conn,
                    )
                yield
            finally:
                await tx.rollback()
    elif holder.backend is StoreBackend.SQLSERVER:
        async with holder._acquire() as raw:
            try:
                async with holder._cursor(raw) as cur:
                    if stored:
                        await cur.execute(
                            "SELECT 1 FROM connection_flag WITH (UPDLOCK, HOLDLOCK, ROWLOCK)"
                            " WHERE connection=? AND direction='outbound'",
                            (conn,),
                        )
                        await cur.fetchall()
                    else:
                        await cur.execute(
                            "INSERT INTO connection_flag (connection, direction)"
                            " VALUES (?, 'outbound')",
                            (conn,),
                        )
                    yield
            finally:
                await raw.rollback()
    else:
        raise AssertionError(f"no foreign lock is written for {holder.backend}")


async def assert_flag_lock_wait_bounded(toggler: Any, other: Any) -> None:
    """A foreign lock on ``connection_flag`` costs the audit chain only the store's bound (BACKLOG
    #2623). The toggle holds the audit lock while its flag statement waits, so ``toggler``'s set and
    clear each meet a lock ``other`` holds outside any toggle. Each must raise the typed refusal
    within the bound, write neither the flag nor its row, and leave ``other`` free to append an
    audit row at once while that lock is still held. Server backends only."""
    for stored in (False, True):
        conn = f"OB_L{uuid4().hex[:8]}"
        action = f"contract.flag-lock.{uuid4().hex[:8]}"
        if stored:
            await toggler.set_connection_flag(
                conn, "outbound", flagged=True, audit=AuditAppend("contract.flag-lock-seed")
            )
        async with _foreign_flag_lock(other, conn, stored=stored):
            refused = toggler.set_connection_flag(
                conn, "outbound", flagged=not stored, audit=AuditAppend(action, actor="contract-op")
            )
            with pytest.raises(ConnectionFlagLockTimeout):
                await asyncio.wait_for(
                    refused, CONNECTION_FLAG_LOCK_TIMEOUT_SECONDS + _REFUSAL_SLACK
                )
            appended = f"contract.flag-lock-after.{uuid4().hex[:8]}"
            await asyncio.wait_for(
                other.record_audit(appended, actor="contract-op"), _APPEND_PROMPT
            )
        assert len(await _rows(other, appended)) == 1
        assert await _rows(toggler, action) == [], "a refused toggle left its audit row"
        flagged = (conn, "outbound") in await toggler.list_connection_flags()
        assert flagged is stored, "a refused toggle changed the flag"


async def _assert_alert_mutations_atomic(store: Any, tag: str) -> None:
    """Alert ack, resolve, suspend and resume commit their row with the change (vault BACKLOG
    #3217). Each takes one ``AuditAppend``, which the store appends only when the change applied."""
    conn = f"OB_A{tag}"
    await store.upsert_alert_instance(
        event_type="connection_error", connection=conn, severity="warning"
    )
    rows = await store.list_active_alert_instances(limit=1000, allowed_channels=None)
    [alert_id] = [r.id for r in rows if r.connection == conn]

    async def instance() -> Any:
        got = await store.get_alert_instance(alert_id, allowed_channels=None)
        assert got is not None
        return got

    async def is_open_unsuspended() -> None:
        got = await instance()
        assert (got.status, got.acked_by, got.suspended_until) == ("open", None, None)

    async def suspended() -> None:
        assert (await instance()).suspended_until == 9_999_999_999.0

    async def acked(ok: Any) -> None:
        got = await instance()
        assert ok is True and (got.status, got.acked_by) == ("acknowledged", "contract-op")

    async def was_suspended(info: Any) -> None:
        assert info is not None and info.suspended_until == 9_999_999_999.0
        await suspended()

    async def was_resumed(info: Any) -> None:
        assert info is not None and info.suspended_until is None

    async def is_acked() -> None:
        assert (await instance()).status == "acknowledged"

    async def resolved(ok: Any) -> None:
        assert ok is True and (await instance()).status == "resolved"

    await _check(
        store,
        label="alert_suspend",
        channel=None,
        run=lambda audit: store.suspend_alert_instance(
            alert_id, until=9_999_999_999.0, audit=audit(True)
        ),
        unchanged=is_open_unsuspended,
        changed=was_suspended,
    )
    await _check(
        store,
        label="alert_resume",
        channel=None,
        run=lambda audit: store.resume_alert_instance(alert_id, audit=audit(True)),
        unchanged=suspended,
        changed=was_resumed,
    )
    await _check(
        store,
        label="alert_ack",
        channel=None,
        run=lambda audit: store.ack_alert_instance(
            alert_id, actor="contract-op", audit=audit(True)
        ),
        unchanged=is_open_unsuspended,
        changed=acked,
    )
    await _check(
        store,
        label="alert_resolve",
        channel=None,
        run=lambda audit: store.resolve_alert_instance(alert_id, audit=audit(True)),
        unchanged=is_acked,
        changed=resolved,
    )
    # A mutation that changes nothing, here of a resolved instance, records nothing: the route
    # answers 404 for it, as it did before the row moved into the store.
    none_action = f"contract.alert_noop.{tag}"
    noop = _builder(none_action, None)(None)
    assert await store.ack_alert_instance(alert_id, actor="contract-op", audit=noop) is False
    assert await store.resolve_alert_instance(alert_id, audit=noop) is False
    assert await store.suspend_alert_instance(alert_id, until=1.0, audit=noop) is None
    assert await store.resume_alert_instance(alert_id, audit=noop) is None
    assert await _rows(store, none_action) == []


async def _assert_missing_audit_refused(store: Any, tag: str) -> None:
    """An explicit ``None`` in place of the audit is refused with ``TypeError`` and changes nothing
    (BACKLOG #5069), and so is an operator-origin inject with no audit (BACKLOG #5071). Each call
    would type-check only as ``Any``, which is the caller mypy cannot hold, so this is the runtime
    half. ``_check`` above is the control: the same mutations with an audit did change the store."""
    ch, dest = f"IB_N{tag}", f"OB_N{tag}"
    dead = await _seed(store, ch, dest, settle="dead")
    done_dest = f"OB_NS{tag}"
    done = await _seed(store, ch, done_dest, settle="done")
    purge_dest = f"OB_NP{tag}"
    pending = await _seed(store, ch, purge_dest, settle=None)
    refused: dict[str, Callable[[], Awaitable[Any]]] = {
        "replay": lambda: store.replay(dead, audit=None),
        "replay_dead": lambda: store.replay_dead(channel_id=ch, destination_name=dest, audit=None),
        "cancel_queued": lambda: store.cancel_queued(None, purge_dest, audit=None),
        "resend_to": lambda: store.resend_to(
            message_id=done, to=f"OB_NA{tag}", idempotency_key=f"none-{tag}", audit=None
        ),
        "reingress": lambda: store.reingress(
            origin_message_id=pending,
            raw=_RAW,
            idempotency_key=f"none-re-{tag}",
            audit=None,
            actor="contract-op",
        ),
        "replay, not callable": lambda: store.replay(dead, audit="not-a-callable"),
    }
    for label, call in refused.items():
        with pytest.raises(TypeError, match="BACKLOG #5069"):
            await call()
        assert await _statuses(store, dead) == {dest: "dead"}, label
        assert await _statuses(store, done) == {done_dest: "done"}, label
        assert await _statuses(store, pending) == {purge_dest: "pending"}, label
    assert int(await store.count_messages(channel_id=ch, allowed_channels=None)) == 3

    inject_ch = f"IB_NI{tag}"
    for origin in (MessageOrigin.OPERATOR_UPLOAD, MessageOrigin.OPERATOR_EDIT):
        with pytest.raises(TypeError, match="BACKLOG #5069"):
            await store.enqueue_ingress(
                channel_id=inject_ch, raw=_RAW, origin=origin, origin_actor="contract-op"
            )
    with pytest.raises(TypeError, match="BACKLOG #5069"):
        await store.enqueue_ingress(channel_id=inject_ch, raw=_RAW, audit="not-a-callable")
    assert int(await store.count_messages(channel_id=inject_ch, allowed_channels=None)) == 0
    # Control: a live receipt, the partner default with no audit, is still accepted.
    await store.enqueue_ingress(channel_id=inject_ch, raw=_RAW)
    assert int(await store.count_messages(channel_id=inject_ch, allowed_channels=None)) == 1

    # The alert mutations and the connection flag take an AuditAppend, which ``if_applied`` refuses
    # when it is None; the raise comes inside the write's transaction, so it rolls the change back.
    conn = f"OB_NAL{tag}"
    await store.upsert_alert_instance(
        event_type="connection_error", connection=conn, severity="warning"
    )
    [alert_id] = [
        r.id
        for r in await store.list_active_alert_instances(limit=1000, allowed_channels=None)
        if r.connection == conn
    ]
    with pytest.raises(TypeError, match="BACKLOG #5069"):
        await store.ack_alert_instance(alert_id, actor="contract-op", audit=None)
    got = await store.get_alert_instance(alert_id, allowed_channels=None)
    assert got is not None and (got.status, got.acked_by) == ("open", None)
    flag_conn = f"OB_NF{tag}"
    with pytest.raises(TypeError, match="BACKLOG #5069"):
        await store.set_connection_flag(flag_conn, "outbound", flagged=True, audit=None)
    assert (flag_conn, "outbound") not in await store.list_connection_flags()


async def assert_operator_audit_atomic(store: Any) -> None:
    """Every operator mutation commits its audit row with its change, or neither."""
    tag = uuid4().hex[:8]
    ch, dest, alt = f"IB_C{tag}", f"OB_C{tag}", f"OB_ALT{tag}"

    # --- replay: a dead row is re-pended
    mid = await _seed(store, ch, dest, settle="dead")

    async def replay_unchanged() -> None:
        assert await _statuses(store, mid) == {dest: "dead"}

    async def replay_changed(n: Any) -> None:
        assert n == 1 and await _statuses(store, mid) == {dest: "pending"}

    await _check(
        store,
        label="replay",
        channel=ch,
        run=lambda audit: store.replay(mid, audit=audit),
        unchanged=replay_unchanged,
        changed=replay_changed,
    )

    # --- replay_dead: the bulk dead-letter replay. Each seed takes its own outbound, so a claim sees
    # only the row it seeded.
    dead_dest = f"OB_D{tag}"
    dead_mid = await _seed(store, ch, dead_dest, settle="dead")

    async def dead_unchanged() -> None:
        assert await _statuses(store, dead_mid) == {dead_dest: "dead"}

    async def dead_changed(n: Any) -> None:
        assert n == 1 and await _statuses(store, dead_mid) == {dead_dest: "pending"}

    await _check(
        store,
        label="replay_dead",
        channel=ch,
        run=lambda audit: store.replay_dead(channel_id=ch, destination_name=dead_dest, audit=audit),
        unchanged=dead_unchanged,
        changed=dead_changed,
    )

    # --- cancel_queued (purge): pending rows to an outbound are cancelled
    purge_dest = f"OB_P{tag}"
    purge_mid = await _seed(store, ch, purge_dest, settle=None)

    async def purge_unchanged() -> None:
        assert await _statuses(store, purge_mid) == {purge_dest: "pending"}

    async def purge_changed(n: Any) -> None:
        assert n == 1 and await _statuses(store, purge_mid) == {purge_dest: "cancelled"}

    await _check(
        store,
        label="cancel_queued",
        channel=None,
        run=lambda audit: store.cancel_queued(None, purge_dest, audit=audit),
        unchanged=purge_unchanged,
        changed=purge_changed,
    )
    # A purge that cancels nothing still records itself (BACKLOG #1641), and still in one commit.
    zero_action = f"contract.cancel_zero.{tag}"
    assert await store.cancel_queued(None, purge_dest, audit=_builder(zero_action, None)) == 0
    assert len(await _rows(store, zero_action)) == 1

    # --- resend_to: a delivered body goes to an alternate outbound
    done_dest = f"OB_S{tag}"
    done_mid = await _seed(store, ch, done_dest, settle="done")
    key = f"contract-resend-{tag}"

    async def resend_unchanged() -> None:
        assert await _statuses(store, done_mid) == {done_dest: "done"}

    async def resend_changed(outcome: Any) -> None:
        # "resent", not "duplicate": the failed run's idempotency claim rolled back with it.
        assert outcome.status == "resent"
        assert await _statuses(store, done_mid) == {done_dest: "done", alt: "pending"}

    await _check(
        store,
        label="resend_to",
        channel=ch,
        run=lambda audit: store.resend_to(
            message_id=done_mid, to=alt, idempotency_key=key, audit=audit
        ),
        unchanged=resend_unchanged,
        changed=resend_changed,
    )

    # --- reingress: an edited body re-enters the origin channel as a new message
    origin_ch = f"IB_R{tag}"
    origin = await _seed(store, origin_ch, dest, settle=None)
    edited = _RAW.replace("DOE^JANE", "DOE^JOAN")

    async def count(channel: str) -> int:
        return int(await store.count_messages(channel_id=channel, allowed_channels=None))

    async def reingress_unchanged() -> None:
        assert await count(origin_ch) == 1

    async def reingress_changed(outcome: Any) -> None:
        assert outcome.status == "resubmitted" and await count(origin_ch) == 2
        # Vault BACKLOG #2615: the plain origin pair, on every backend. The seed is a partner's.
        child = await store.get_message(outcome.new_message_id)
        assert child is not None
        assert (child["origin"], child["origin_actor"]) == (
            MessageOrigin.OPERATOR_EDIT.value,
            "contract-op",
        )
        seeded = await store.get_message(origin)
        assert seeded is not None
        assert (seeded["origin"], seeded["origin_actor"]) == (MessageOrigin.PARTNER.value, None)

    await _check(
        store,
        label="reingress",
        channel=origin_ch,
        run=lambda audit: store.reingress(
            origin_message_id=origin,
            raw=edited,
            idempotency_key=f"contract-reingress-{tag}",
            audit=audit,
            actor="contract-op",
        ),
        unchanged=reingress_unchanged,
        changed=reingress_changed,
    )

    # --- resend_to with an edited body: a new child on the origin's channel carries the operator
    # (vault BACKLOG #2615). Its own outbound and channel, so a claim sees only what it seeded.
    direct_ch, direct_alt = f"IB_E{tag}", f"OB_E{tag}"
    direct_origin = await _seed(store, direct_ch, f"OB_F{tag}", settle="done")

    async def direct_unchanged() -> None:
        assert await count(direct_ch) == 1

    async def direct_changed(outcome: Any) -> None:
        assert outcome.status == "resent" and await count(direct_ch) == 2
        assert outcome.new_message_id is not None
        child = await store.get_message(outcome.new_message_id)
        assert child is not None
        assert (child["origin"], child["origin_actor"]) == (
            MessageOrigin.OPERATOR_EDIT.value,
            "contract-op",
        )

    await _check(
        store,
        label="resend_to_edited",
        channel=direct_ch,
        run=lambda audit: store.resend_to(
            message_id=direct_origin,
            to=direct_alt,
            idempotency_key=f"contract-direct-{tag}",
            body_override=_RAW.replace("DOE^JANE", "DOE^JUNE"),
            audit=audit,
            actor="contract-op",
        ),
        unchanged=direct_unchanged,
        changed=direct_changed,
    )

    # --- enqueue_ingress with an audit: the upload inject
    inject_ch = f"IB_I{tag}"

    async def inject_unchanged() -> None:
        assert await count(inject_ch) == 0

    async def inject_changed(new_mid: Any) -> None:
        assert await count(inject_ch) == 1
        injected = await store.get_message(new_mid)
        assert injected is not None
        assert (injected["origin"], injected["origin_actor"]) == (
            MessageOrigin.OPERATOR_UPLOAD.value,
            "contract-op",
        )

    await _check(
        store,
        label="inject",
        channel=inject_ch,
        run=lambda audit: store.enqueue_ingress(
            channel_id=inject_ch,
            raw=_RAW,
            source_type="upload",
            audit=audit,
            origin=MessageOrigin.OPERATOR_UPLOAD,
            origin_actor="contract-op",
        ),
        unchanged=inject_unchanged,
        changed=inject_changed,
    )

    await _assert_alert_mutations_atomic(store, tag)
    await _assert_connection_flag_atomic(store, tag)
    await _assert_missing_audit_refused(store, tag)

    # The rows joined the hash chain the way record_audit's do: the chain still verifies.
    ok, message = await store.verify_audit_chain()
    assert ok, message
