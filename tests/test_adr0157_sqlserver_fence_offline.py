# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0157 Inc 3 — the H1 epoch fence on SQL Server, checked WITHOUT a database.

**Deliberately NOT env-gated.** ``tests/test_adr0157_sqlserver_fence.py`` proves the T-SQL against a
real server, but it runs only on the hosted ``sqlserver-store`` legs; on a laptop it skips. This file
runs everywhere, in two halves:

1. **A structural gate** over ``store/sqlserver.py``, the twin of ``tests/test_adr0157_fence_scope.py``
   for Postgres. Every ``queue`` status write is classified, and every unguarded one carries a
   written reason. It reads the emitted SQL from the AST, for the reason that file gives.
2. **Behaviour against fake cursors**: a rejected resolve rolls back, never commits, re-pends
   through ``release_claimed`` (D1) and counts once. The unfenced path is character-identical to
   pre-Inc-3 and never reads the rowcount.

No test here cancels a statement mid-flight. That path can natively crash pyodbc on SQL Server, and
it is a separate ledger item, not this increment's.
"""

from __future__ import annotations

import ast
import asyncio
import pathlib
import re
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import OutboxStatus
from messagefoundry.store.crypto import IdentityCipher
from messagefoundry.store.sqlserver import (
    _EPOCH_GUARD_CLAIM,
    _EPOCH_GUARD_RESOLVE,
    SqlServerStore,
    _FencedWrite,
)
from tests.test_adr0157_fence_scope import _calls_self, _sql_expressions

_SOURCE = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "store" / "sqlserver.py"

#: Any statement that moves a ``queue`` row's status. SQL Server updates through a CTE (``due``,
#: ``head``) or an alias (``q``) as well as the table, so all four spellings count.
_STATUS_WRITE = re.compile(r"UPDATE (?:queue|due|head|q) SET status\s*=")

#: How a spliced guard shows up in a reconstructed statement.
_SPLICED = ("{epoch_guard}", "{guard}", "{epoch_where}")


def _observed() -> dict[str, tuple[int, int]]:
    """``{function: (status_writes, of_which_carry_a_spliced_guard)}`` over the whole module."""
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    found: dict[str, tuple[int, int]] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        # A docstring is a string expression too, and claim_next_fifo_batch's quotes a rejected UPDATE.
        doc = ast.get_docstring(fn, clean=False)
        writes = [s for s in _sql_expressions(fn) if s != doc and _STATUS_WRITE.search(s)]
        if writes:
            guarded = sum(1 for sql in writes if any(m in sql for m in _SPLICED))
            found[fn.name] = (len(writes), guarded)
    return found


#: THE PINNED CLASSIFICATION. Adding a ``queue`` status write anywhere in ``sqlserver.py`` without a
#: row here fails, which is the point: a new terminal write must not escape the fence silently.
_EXPECTED: dict[str, tuple[int, int]] = {
    # --- CLAIM paths: fail-CLOSED. ---
    "claim_ready": (1, 1),  # Inc 3 (C5). Unfenced before this increment.
    "claim_next_fifo": (2, 1),  # the guarded claim + the H2 skip-and-complete
    "claim_next_fifo_batch": (1, 1),
    # claim_fifo_heads' claim UPDATE lives in the shared renderer; the method itself holds only the
    # H2 skip-and-complete. The proc and prepared forms render through the same function.
    "_fifo_heads_steps": (1, 1),
    "claim_fifo_heads": (1, 0),
    # --- Writes that return a row to PENDING: deliberately UNGUARDED (C1). ---
    "release_claimed": (1, 0),
    "reschedule_claimed": (1, 0),
    "reset_stale_inflight": (1, 0),
    # --- TERMINAL resolves: fail-OPEN guarded through _resolve_guard (Inc 3). ---
    "dead_letter_now": (1, 1),
    "mark_done": (1, 1),
    "mark_batch_done": (1, 1),
    "complete_with_response": (1, 1),
    "ingress_handoff": (2, 2),  # both DEAD branches; the success path ADMITS and is not guarded
    "mark_failed": (1, 1),  # one statement, suffix "" on the retry branch
    "mark_batch_failed": (1, 1),
    "dead_letter_batch": (1, 1),
    # --- Bring-up sweeps + operator paths: unguarded, allowlisted. ---
    "dead_letter_missing_destinations": (1, 0),
    "dead_letter_missing_handlers": (1, 0),
    "dead_letter_missing_inbounds": (1, 0),
    "replay": (1, 0),
    "replay_dead": (1, 0),
    "cancel_queued": (1, 0),
}

_RESOLVE_FENCED = frozenset(
    {
        "dead_letter_now",
        "mark_done",
        "mark_batch_done",
        "complete_with_response",
        "ingress_handoff",
        "mark_failed",
        "mark_batch_failed",
        "dead_letter_batch",
    }
)

_UNGUARDED_REASONS: dict[str, str] = {
    "release_claimed": (
        "C1: re-pends an INFLIGHT row. Fencing it would leave the row INFLIGHT, which is a strand on a"
        " backend with no periodic recovery. It is also D1's own recovery write."
    ),
    "reschedule_claimed": "C1: as release_claimed, with a durable backoff deadline instead.",
    "reset_stale_inflight": (
        "Startup and promotion recovery. On promotion it runs on the successor, by definition unfenced,"
        " and it is the backstop when D1's re-pend fails."
    ),
    "dead_letter_missing_destinations": (
        "ADR 0157 D11: writes over PENDING rows, where D1's re-pend is meaningless. Runs only from"
        " _start_graph, and the successor re-runs the identical sweep."
    ),
    "dead_letter_missing_handlers": "ADR 0157 D11: the twin of dead_letter_missing_destinations.",
    "dead_letter_missing_inbounds": (
        "ADR 0157 D11: the third lane key, same standing as its two siblings, same _start_graph caller."
    ),
    "replay": "Operator action. Guarding it would leave an operator on a standby unable to act.",
    "replay_dead": "Operator action: revives a DEAD row to PENDING, which is re-pend direction.",
    "cancel_queued": "Operator action; binds PENDING rows only, never a claimed row.",
    "claim_next_fifo": (
        "The H2 skip-and-complete beside the guarded claim. It is reachable only because the guarded"
        " claim UPDATE already matched, in the same transaction."
    ),
    "claim_fifo_heads": (
        "The H2 skip-and-complete, as claim_next_fifo. The guarded claim is in _fifo_heads_steps. A"
        " cancel can COMMIT this method's claim through its shielded LOCK_TIMEOUT reset, but what it"
        " commits was epoch-checked inside the claim statement, so the fence needs nothing more here."
    ),
}


# --- half 1: the structural gate --------------------------------------------------------------


def test_every_queue_status_write_is_classified() -> None:
    assert _observed() == _EXPECTED


def test_every_unguarded_status_write_carries_a_written_reason() -> None:
    unguarded = {name for name, (writes, guarded) in _EXPECTED.items() if guarded < writes}
    assert unguarded == set(_UNGUARDED_REASONS)
    assert all(len(reason) > 40 for reason in _UNGUARDED_REASONS.values())


def test_every_fenced_terminal_resolve_inspects_the_rowcount_and_catches_the_sentinel() -> None:
    """Splicing the guard is a third of it. The rowcount must be read (``_exec_terminal``) or the
    guard can never fire, and the sentinel must be caught (``_fence_scope``) or it escapes the store
    as an exception instead of becoming a counted, re-pended no-op."""
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    seen: set[str] = set()
    for fn in ast.walk(tree):
        if isinstance(fn, ast.AsyncFunctionDef) and fn.name in _RESOLVE_FENCED:
            seen.add(fn.name)
            assert _calls_self(fn, "_resolve_guard"), f"{fn.name} does not splice the guard"
            assert _calls_self(fn, "_exec_terminal"), f"{fn.name} never inspects the rowcount"
            assert _calls_self(fn, "_fence_scope"), f"{fn.name} never catches _FencedWrite"
    assert seen == set(_RESOLVE_FENCED)


def test_each_guard_is_referenced_only_by_its_own_sites() -> None:
    """C2: the two polarities are opposite, so using the wrong one is the hazard."""
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    referrers: dict[str, set[str]] = {"_EPOCH_GUARD_CLAIM": set(), "_EPOCH_GUARD_RESOLVE": set()}
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            for node in ast.walk(fn):
                if isinstance(node, ast.Name) and node.id in referrers:
                    referrers[node.id].add(fn.name)
    assert referrers["_EPOCH_GUARD_CLAIM"] == {
        "claim_ready",
        "claim_next_fifo",
        "claim_next_fifo_batch",
        "claim_fifo_heads",
    }
    assert referrers["_EPOCH_GUARD_RESOLVE"] == {"_resolve_guard"}


def test_guard_polarity_is_pinned() -> None:
    """CLAIM fails closed on a missing lease row; RESOLVE fails open. ``ISNULL``, never
    ``COALESCE``, because SQL Server evaluates a subquery inside ``COALESCE`` twice."""
    assert "ISNULL" in _EPOCH_GUARD_RESOLVE and "COALESCE" not in _EPOCH_GUARD_RESOLVE
    assert "ISNULL" not in _EPOCH_GUARD_CLAIM and "COALESCE" not in _EPOCH_GUARD_CLAIM
    assert "status" not in _EPOCH_GUARD_CLAIM and "status" not in _EPOCH_GUARD_RESOLVE
    assert _EPOCH_GUARD_CLAIM.count("?") == 2
    assert _EPOCH_GUARD_RESOLVE.count("?") == 3


def test_extracting_the_claim_guard_changed_no_emitted_sql() -> None:
    """The three FIFO claims carried this literal inline before Inc 3 extracted it."""
    assert _EPOCH_GUARD_CLAIM == (
        " AND (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=?) <= ?"
    )


# --- half 2: behaviour against fake cursors ---------------------------------------------------

_LEASE_KEY = "mefor_cluster_leader"
_SELECT_ROW: dict[str, tuple[Any, ...]] = {
    "SELECT message_id, destination_name, handler_name, attempts FROM queue": (
        "m1",
        "OB1",
        None,
        1,
    ),
    "SELECT message_id, destination_name, attempts FROM queue WHERE id=?": ("m1", "OB1", 3),
    "SELECT message_id, destination_name FROM queue WHERE id=?": ("m1", "OB1"),
    # ingress_handoff's guard read: a payload that is not a three-part ref takes the corrupt-ref
    # DEAD branch, which is one of the two fenced writes there.
    "SELECT message_id, payload FROM queue WHERE id=? AND stage=? AND status=?": ("m1", "bad-ref"),
}


class _NoRowcount(AssertionError):
    pass


class _Cursor:
    """Records every statement. ``rowcount`` answers for the last one: ``update_rowcount`` after a
    queue status UPDATE, and it RAISES when ``read_forbidden`` is set, which is how a test proves the
    unfenced path never reads it."""

    def __init__(self, *, update_rowcount: int = 1, read_forbidden: bool = False) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.update_rowcount = update_rowcount
        self.read_forbidden = read_forbidden
        self._last = ""

    async def execute(self, sql: str, params: Any = ()) -> None:
        self.calls.append((sql, tuple(params)))
        self._last = sql

    @property
    def rowcount(self) -> int:
        if self.read_forbidden:
            raise _NoRowcount(f"rowcount read after {self._last!r}")
        return self.update_rowcount if self._last.startswith("UPDATE queue SET status") else 1

    async def fetchone(self) -> Any:
        for prefix, row in _SELECT_ROW.items():
            if self._last.startswith(prefix):
                return row
        return None

    async def close(self) -> None:
        pass


class _Conn:
    def __init__(self) -> None:
        self.commits = 0
        self.rollbacks = 0

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


def _store(cur: _Cursor, conn: _Conn, *, epoch: int | None) -> tuple[SqlServerStore, list[Any]]:
    """A store built without a pool. ``release_claimed`` is recorded rather than run, so the D1
    re-pend is observable; the ledger, event and finalize helpers are no-ops."""
    store = object.__new__(SqlServerStore)
    store._settings = StoreSettings()
    store._cipher = IdentityCipher()
    store.committed_txns = 0
    store.body_copies = 0
    store.fenced_writes = 0
    store._leader_epoch = epoch
    store._lease_key = _LEASE_KEY if epoch is not None else None

    @asynccontextmanager
    async def acquire() -> Any:
        yield conn

    @asynccontextmanager
    async def cursor(_conn: Any) -> Any:
        yield cur

    released: list[Any] = []

    async def release_claimed(ids: Any, now: float | None = None) -> None:
        released.append(list(ids))

    async def noop(*_a: Any, **_k: Any) -> None:
        return None

    store._acquire = acquire  # type: ignore[method-assign]
    store._cursor = cursor  # type: ignore[method-assign]
    store.release_claimed = release_claimed  # type: ignore[method-assign]
    store._record_delivered_key = noop  # type: ignore[method-assign]
    store._event = noop  # type: ignore[method-assign]
    store._maybe_finalize = noop  # type: ignore[method-assign]
    return store, released


def _updates(cur: _Cursor) -> list[tuple[str, tuple[Any, ...]]]:
    return [(s, p) for s, p in cur.calls if s.startswith("UPDATE queue SET status")]


async def test_a_rejected_mark_done_rolls_back_repends_and_counts_once() -> None:
    """C3 + D1. Mutation that must break it: drop ``checked=bool(guard)`` to ``False`` in mark_done,
    and the zero-row write commits as if it landed."""
    cur, conn = _Cursor(update_rowcount=0), _Conn()
    store, released = _store(cur, conn, epoch=5)

    assert await store.mark_done("row-1", now=1.0) is None  # a fenced write is NOT an exception

    assert conn.commits == 0 and conn.rollbacks == 1
    assert released == [["row-1"]]
    assert store.fenced_writes == 1
    sql, params = _updates(cur)[0]
    assert sql.endswith(_EPOCH_GUARD_RESOLVE)
    assert params[-3:] == (_LEASE_KEY, 5, 5)
    assert cur.calls[-1][0] == sql  # nothing ran after the rejected UPDATE


async def test_a_landing_mark_done_under_an_armed_epoch_commits() -> None:
    """The negative twin: the true leader's write lands. Either test alone passes an always-on or an
    always-off fence; the pair does not."""
    cur, conn = _Cursor(update_rowcount=1), _Conn()
    store, released = _store(cur, conn, epoch=5)

    await store.mark_done("row-1", now=1.0)

    assert conn.commits == 1 and conn.rollbacks == 0
    assert released == [] and store.fenced_writes == 0


async def test_an_unknown_rowcount_lets_the_write_stand() -> None:
    """Only an exact 0 is a rejection. The DB-API ``-1`` means "not reported", and treating it as a
    rejection would re-pend every delivered row: fail open."""
    cur, conn = _Cursor(update_rowcount=-1), _Conn()
    store, released = _store(cur, conn, epoch=5)

    await store.mark_done("row-1", now=1.0)

    assert conn.commits == 1 and released == [] and store.fenced_writes == 0


async def test_unfenced_terminal_sql_is_character_identical_and_never_reads_the_rowcount() -> None:
    """The single-node parity anchor. With no epoch armed the statement and params are exactly
    pre-Inc-3, and the rowcount is not consulted at all."""
    cur, conn = _Cursor(read_forbidden=True), _Conn()
    store, _ = _store(cur, conn, epoch=None)

    await store.mark_done("row-1", now=1.0)

    assert _updates(cur) == [
        (
            "UPDATE queue SET status=?, last_error=NULL, updated_at=? WHERE id=?",
            (OutboxStatus.DONE.value, 1.0, "row-1"),
        )
    ]
    assert conn.commits == 1


async def test_mark_failed_fences_the_dead_branch_and_leaves_the_retry_branch_unguarded() -> None:
    """C1's split. The seeded row has 3 attempts. ``max_attempts=1`` takes the DEAD branch, which is
    fenced; retry-forever takes the PENDING branch, whose rowcount must never be read."""
    cur, conn = _Cursor(update_rowcount=0), _Conn()
    store, released = _store(cur, conn, epoch=5)
    assert await store.mark_failed("row-1", "boom", RetryPolicy(max_attempts=1), now=1.0) is None
    assert released == [["row-1"]] and store.fenced_writes == 1 and conn.commits == 0

    cur2, conn2 = _Cursor(read_forbidden=True), _Conn()
    store2, released2 = _store(cur2, conn2, epoch=5)
    next_at = await store2.mark_failed("row-2", "x", RetryPolicy(max_attempts=None), now=1.0)
    assert isinstance(next_at, float)
    (sql, params), *_ = _updates(cur2)
    assert "leader_lease" not in sql and _LEASE_KEY not in params
    assert released2 == [] and store2.fenced_writes == 0 and conn2.commits == 1


async def test_a_rejected_batch_repends_every_member_including_those_never_walked() -> None:
    """The fence fires on the first member, so members 2 and 3 are never UPDATEd. They are still
    INFLIGHT from the claim, so D1 must carry all three. Mutation: pass ``(outbox_id,)`` instead of
    ``tuple(outbox_ids)`` and this fails."""
    for method, args in (
        ("mark_batch_done", ()),
        ("dead_letter_batch", ("boom",)),
        ("mark_batch_failed", ("boom", RetryPolicy(max_attempts=1))),
    ):
        cur, conn = _Cursor(update_rowcount=0), _Conn()
        store, released = _store(cur, conn, epoch=5)
        await getattr(store, method)(["a", "b", "c"], *args, now=1.0)
        assert released == [["a", "b", "c"]], method
        assert store.fenced_writes == 1, method  # once per CALL, not once per member
        assert len(_updates(cur)) == 1 and conn.commits == 0, method


async def test_every_single_row_resolve_is_fenced_and_returns_its_no_op_value() -> None:
    expected: dict[str, tuple[tuple[Any, ...], dict[str, Any], Any]] = {
        "dead_letter_now": (("row-1", "boom"), {}, None),
        "complete_with_response": (("row-1",), {"body": "AA", "outcome": "ok"}, None),
        "ingress_handoff": (
            (),
            {
                "response_row_id": "row-1",
                "loopback_channel_id": "LOOP",
                "correlation_depth_cap": 8,
                "control_id": None,
                "message_type": None,
                "summary": None,
            },
            False,
        ),
    }
    for method, (args, kwargs, no_op) in expected.items():
        cur, conn = _Cursor(update_rowcount=0), _Conn()
        store, released = _store(cur, conn, epoch=5)
        assert await getattr(store, method)(*args, now=1.0, **kwargs) is no_op, method
        assert released == [["row-1"]] and store.fenced_writes == 1, method
        assert conn.commits == 0, method


async def test_a_failed_repend_is_logged_and_never_raises(caplog: pytest.LogCaptureFixture) -> None:
    """D1 is best-effort. If it raises, the row stays INFLIGHT for the next promotion's
    ``reset_stale_inflight``, and the caller still sees the ordinary no-op."""
    cur, conn = _Cursor(update_rowcount=0), _Conn()
    store, _ = _store(cur, conn, epoch=5)

    async def boom(ids: Any, now: float | None = None) -> None:
        raise RuntimeError("pool exhausted")

    store.release_claimed = boom  # type: ignore[method-assign]
    await store.mark_done("row-1", now=1.0)
    assert store.fenced_writes == 1
    assert "re-pend failed" in caplog.text


async def test_the_fence_scope_swallows_only_its_own_sentinel() -> None:
    """An ordinary error and a cancellation must both propagate unchanged."""
    store, released = _store(_Cursor(), _Conn(), epoch=5)
    for exc in (RuntimeError("real failure"), asyncio.CancelledError()):
        with pytest.raises(type(exc)):
            async with store._fence_scope():
                raise exc
    async with store._fence_scope():
        raise _FencedWrite("m", ("x",))
    assert released == [["x"]] and store.fenced_writes == 1


# --- claim_ready (C5) -------------------------------------------------------------------------


class _ClaimCursor(_Cursor):
    description: list[tuple[str]] = []

    async def fetchall(self) -> list[Any]:
        return []


_PRE_INC3_CLAIM_READY = (
    "WITH due AS (SELECT TOP (?) * FROM queue WITH (READPAST, UPDLOCK, ROWLOCK)"
    " WHERE stage=? AND status=? AND next_attempt_at<=? ORDER BY next_attempt_at)"
    " UPDATE due SET status=?, attempts=attempts+1, updated_at=?,"
    " owner=NULL, lease_expires_at=NULL"
    " OUTPUT inserted.id, inserted.message_id, inserted.channel_id,"
    " inserted.destination_name, inserted.handler_name, inserted.payload,"
    " inserted.attempts"
)


async def test_claim_ready_is_unchanged_unfenced_and_fenced_when_armed() -> None:
    """C5. Before Inc 3 this claim carried no epoch guard on SQL Server at all, so a demoted node
    kept claiming every UNORDERED lane. Unfenced it must stay character-identical."""
    cur = _ClaimCursor()
    store, _ = _store(cur, _Conn(), epoch=None)
    assert await store.claim_ready(limit=5, now=2.0) == []
    assert cur.calls == [
        (_PRE_INC3_CLAIM_READY, (5, "outbound", "pending", 2.0, "inflight", 2.0)),
    ]

    cur = _ClaimCursor()
    store, _ = _store(cur, _Conn(), epoch=7)
    await store.claim_ready(limit=5, now=2.0)
    sql, params = cur.calls[0]
    assert sql == (
        _PRE_INC3_CLAIM_READY
        + " WHERE (SELECT ll.leader_epoch FROM leader_lease ll WHERE ll.lease_key=?) <= ?"
    )
    assert params == (5, "outbound", "pending", 2.0, "inflight", 2.0, _LEASE_KEY, 7)
