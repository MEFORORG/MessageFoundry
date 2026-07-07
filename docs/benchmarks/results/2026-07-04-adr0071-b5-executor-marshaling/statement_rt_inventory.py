# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0071 (B5) — per-hop SQL statement / network round-trip inventory (Lane 3a).

Sibling analysis to ``b5_microbench.py``. Where that bench measures *executor->loop crossings*
per message (the ProactorEventLoop marshaling wall), THIS module measures a DIFFERENT quantity on
the SAME staged handoffs: how many **SQL statements** and **pyodbc network round-trips** each
SQL Server hop issues, and how far a per-hop **statement batch** (folding the multi-statement body
into 1-2 ``pyodbc.execute()`` batches) could collapse the round-trips *without moving a commit
boundary or changing the logical (sql, params) sequence*.

Why this exists — evidence for the statement-batching ADR decision.
------------------------------------------------------------------
The owner HELD the "SQL statement-batching per hop" build-go on a framing that per-hop batching is
"invariant-blocked" by the ADR 0069 transaction-fusion fence. This bench answers ONE narrow
question — is per-hop batching invariant-blocked? — and the answer is NO:

  * Intra-hop statement batching moves **NO commit boundary**. Each staged handoff still commits
    exactly once, so ``commits/msg`` stays **2.000** (route_handoff + transform_handoff). Only
    CROSS-LANE handoff batching (folding two hops' commits into one) would approach the ADR 0069
    fence — that is a different lever and is NOT what this measures.
  * A batched hop emits the **identical LOGICAL (sql, params) sequence** — same statements, same
    order, same params — it just groups consecutive statements into fewer wire round-trips. The
    shipped code already does exactly this for the finalize applock (``_SQL_APPLOCK`` is a
    4-statement T-SQL batch sent as ONE round-trip); per-hop batching extends that same technique
    to the rest of the body.

So per-hop batching is a **latency (round-trip) optimization**, not an invariant breach — that part
is unconditional. What this bench does NOT deliver is an unconditional GO. The SIZE of the win is a
**range, 27–50% fewer round-trips per hop**, and whether it clears a ≥40% bar is **CONDITIONAL on
one modelling choice** (whether the finalize ``sp_getapplock`` rc-check folds into the trailing
batch — see "Conditional ≥40% verdict" below). A real GO/NO-GO needs the Wave-2 live-rig end-to-end
A/B (round-trip savings are one input to throughput, not throughput itself); this module quantifies
the opportunity and its conditionality only, and does NOT build the engine change.

What is MEASURED vs DERIVED (honesty labels).
--------------------------------------------
MEASURED (runnable here, no live SQL Server, no pyodbc/aioodbc extra): the exact ordered
``(sql, params)`` sequence each hop issues, obtained by driving the **real shipped store methods**
(``SqlServerStore.route_handoff_sync`` / ``transform_handoff_sync`` / ``mark_done``) against a
**recording fake cursor** — the same offline harness style as
``tests/test_sqlserver_sync_handoff_offline.py``. The statement count, the ``execute()`` count, and
the commit count are read straight off that real sequence.

DERIVED (a model on top of the measured sequence):
  * round-trips == ``execute()`` calls + ``commit()`` calls. Each ``cur.execute(...)`` submits a
    batch to the server (one round-trip); ``commit()`` is its own round-trip. ``fetchone()`` /
    ``fetchall()`` on the small immediate result of a just-executed statement are **buffered reads**
    of the response already streamed with the execute — they add no guaranteed round-trip (a
    separate SQLFetch round-trip only occurs for result sets larger than the driver row buffer,
    which none of these are). They are reported separately as "client reads".
  * the batched round-trip count, from a stated batching model (below).

Batching model (stated so the % drop is auditable).
--------------------------------------------------
Preserve every ``(sql, params)`` in identical order and the single per-hop COMMIT. Cut a new
round-trip only at a **hard client-branch boundary** — a statement whose returned result the
client must read *before it can build the SQL/params of a later statement, or decide whether to run
later statements at all* (control flow the client implements in Python, not T-SQL). A boundary
statement is the LAST statement of its round-trip (its result streams back, the client reads it,
then sends the next batch). Everything between two boundaries folds into one round-trip.

Hard boundaries (result feeds later SQL/params or a Python branch):
  * the guard ``DELETE ... OUTPUT`` (idempotent no-op decision: skip the whole rest of the hop);
  * the finalize ``GROUP BY`` count (chooses the UPDATE target status / whether to UPDATE / whether
    to also read messages.status) and the messages.status read on its no-rows branch;
  * ``mark_done``'s opening ``SELECT`` (missing-row early return + supplies message_id/dest/handler/
    attempts as params for every later statement);
  * the H2 ledger ``SELECT``s in ``_record_delivered_key`` (exists-early-return; control_id feeds the
    delivery key; COUNT feeds the sequence — all feed the ledger INSERT's params);
  * the PT lineage ``SELECT metadata`` (feeds child depth).

SOFT (foldable) — the finalize ``sp_getapplock`` rc: the client only *validates* it (raise on
rc<0), it never changes *which* SQL/params come next. Folding it into the trailing batch is
net-identical: on rc<0 the whole transaction rolls back, so an UPDATE/event that ran server-side
before the client read rc is never committed and is invisible to any other session. This is the one
judgment call in the model, so both variants are reported (``applock_soft`` = fold; the strict
``applock_hard`` = treat the rc as a client-side gate) to bound the sensitivity.

Conditional ≥40% verdict (READ BEFORE citing a "cleared the bar" number).
------------------------------------------------------------------------
The ≥40% round-trip-drop assessment is **CONDITIONAL on the applock-fold** and must never be quoted
without its condition:

  * applock_soft (rc folded into the trailing batch — technically sound, see above): route_handoff
    50.0%, transform_handoff 42.9%, route+transform pair 46.2% CLEAR ≥40%; mark_done 36.4% does NOT.
  * applock_hard (strict — rc validated as a client-side gate): route_handoff 33.3%, transform_handoff
    28.6%, mark_done 27.3%, pair 30.8% — **NOTHING clears ≥40%.**

So there is NO interpretation-independent ≥40% result. The honest headline is "**27–50% per-hop
round-trip opportunity; ≥40% only under the applock-fold; strict interpretation 27–33%, clears
nothing**". Both floors are asserted by the gate so neither can be quoted in isolation. Anyone
reading a "≥40% → GO" must also see the strict 27–33% floor and the "rig e2e A/B required" caveat.

Run:  python docs/benchmarks/.../statement_rt_inventory.py
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import MessageStatus
from messagefoundry.store import sqlserver as ss
from messagefoundry.store.crypto import IdentityCipher
from messagefoundry.store.sqlserver import SqlServerStore


# ---------------------------------------------------------------------------
# Canned fetch results — steer the real handoff control flow down the common
# "delivered / PROCESSED" hot path so the FULL statement sequence is exercised.
# Keyed identically to tests/test_sqlserver_sync_handoff_offline.py where the
# constants overlap, extended for mark_done's inline ledger + queue SELECTs.
# ---------------------------------------------------------------------------
def _fetchone_for(sql: str) -> Any:
    if "sp_getapplock" in sql:
        return (0,)  # rc = 0 -> lock acquired, proceed
    if sql == ss._SQL_DELETE_GUARD:
        return ("consumed-row-id",)  # non-None -> guard proceeds (not the idempotent no-op)
    if sql == ss._SQL_SELECT_METADATA:
        return (None,)  # no parent metadata -> depth 0
    if sql == ss._SQL_SELECT_MESSAGE_EXISTS:
        return None
    if sql.startswith("SELECT message_id, destination_name, handler_name"):
        return ("m-1", "OB1", "H1", 1)  # mark_done: outbound row (dest non-None -> ledger writes)
    if "FROM delivered_keys WHERE outbox_id=?" in sql:
        return None  # no prior ledger row for this outbox -> write it
    if sql.startswith("SELECT control_id FROM messages"):
        return ("CTRL1",)
    if sql.startswith("SELECT COUNT(*) FROM delivered_keys"):
        return (0,)  # -> delivery_seq = 1
    return None


def _fetchall_for(sql: str) -> Any:
    if sql == ss._SQL_FINALIZE_COUNT:
        return [("outbound", "done", 1)]  # -> PROCESSED -> the finalizer UPDATE fires
    if sql == ss._SQL_SELECT_MESSAGE_STATUS:
        return [("routed",)]
    return []


# ---------------------------------------------------------------------------
# Recording fakes — capture every (sql, params) plus commit/rollback/read counts.
# ---------------------------------------------------------------------------
@dataclass
class _Rec:
    """Shared recorder for one hop run."""

    calls: list[tuple[str, tuple[Any, ...]]] = field(default_factory=list)
    reads: list[tuple[str, str]] = field(default_factory=list)  # (kind, sql)
    commits: int = 0
    rollbacks: int = 0


class _SyncRecCursor:
    def __init__(self, rec: _Rec) -> None:
        self._rec = rec
        self._last = ""

    def execute(self, sql: str, params: Any = ()) -> None:
        self._rec.calls.append((sql, tuple(params)))
        self._last = sql

    def fetchone(self) -> Any:
        self._rec.reads.append(("fetchone", self._last))
        return _fetchone_for(self._last)

    def fetchall(self) -> Any:
        self._rec.reads.append(("fetchall", self._last))
        return _fetchall_for(self._last)

    def close(self) -> None:
        pass


class _SyncRecConn:
    def __init__(self, rec: _Rec) -> None:
        self._rec = rec
        self._cur = _SyncRecCursor(rec)

    def cursor(self) -> _SyncRecCursor:
        return self._cur

    def commit(self) -> None:
        self._rec.commits += 1

    def rollback(self) -> None:
        self._rec.rollbacks += 1


class _AsyncRecCursor:
    def __init__(self, rec: _Rec) -> None:
        self._rec = rec
        self._last = ""

    async def execute(self, sql: str, params: Any = ()) -> None:
        self._rec.calls.append((sql, tuple(params)))
        self._last = sql

    async def fetchone(self) -> Any:
        self._rec.reads.append(("fetchone", self._last))
        return _fetchone_for(self._last)

    async def fetchall(self) -> Any:
        self._rec.reads.append(("fetchall", self._last))
        return _fetchall_for(self._last)

    async def close(self) -> None:
        pass


class _AsyncRecConn:
    def __init__(self, rec: _Rec) -> None:
        self._rec = rec

    async def commit(self) -> None:
        self._rec.commits += 1

    async def rollback(self) -> None:
        self._rec.rollbacks += 1


def _bare_store(command_timeout: int = 30) -> SqlServerStore:
    """A SqlServerStore built WITHOUT opening a pool/DB — just enough state for the handoffs.

    Same construction as the offline handoff tests: bypass ``__init__`` (which would open aioodbc)
    and set only the attributes the handoff bodies touch.
    """
    store = object.__new__(SqlServerStore)
    store._settings = StoreSettings(command_timeout=command_timeout)
    store._cipher = IdentityCipher()
    store._state_cache = {}
    store._sync_pools = {}
    return store


def _acm(value: Any) -> Any:
    @asynccontextmanager
    async def cm(*_args: Any, **_kwargs: Any) -> Any:
        yield value

    return cm


# ---------------------------------------------------------------------------
# Drive the REAL shipped hop methods against the recorder (MEASURED sequence).
# ---------------------------------------------------------------------------
def record_route_handoff(n_handlers: int = 1) -> _Rec:
    rec = _Rec()
    handlers = [(f"H{i}", f"p{i}") for i in range(n_handlers)]
    ok = _bare_store().route_handoff_sync(
        _SyncRecConn(rec),
        ingress_id="ing-1",
        message_id="m-1",
        channel_id="IB",
        handlers=handlers,
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    assert ok is True, "route_handoff_sync should proceed on a non-empty guard"
    return rec


def record_transform_handoff(n_deliveries: int = 1, n_state: int = 0) -> _Rec:
    rec = _Rec()
    deliveries = [(f"OB{i}", f"b{i}") for i in range(n_deliveries)]
    state_ops = [(f"ns{i}", f"k{i}", {"v": i}) for i in range(n_state)]
    handed_off, _applied = _bare_store().transform_handoff_sync(
        _SyncRecConn(rec),
        routed_id="rtd-1",
        message_id="m-1",
        channel_id="IB",
        deliveries=deliveries,
        state_ops=state_ops,
        pt_deliveries=(),
        now=100.0,
    )
    assert handed_off is True
    return rec


def record_mark_done() -> _Rec:
    """mark_done has no sync twin (it is a delivery-lane method); drive the async method through the
    recorder by monkeypatching the store's _acquire/_cursor to yield the fakes (offline-test style)."""
    rec = _Rec()
    store = _bare_store()
    store._acquire = _acm(_AsyncRecConn(rec))  # type: ignore[method-assign]
    store._cursor = _acm(_AsyncRecCursor(rec))  # type: ignore[method-assign]
    asyncio.run(store.mark_done("outbox-1", now=100.0))
    return rec


# ---------------------------------------------------------------------------
# Statement counting + the batching model.
# ---------------------------------------------------------------------------
def count_tsql_statements(sql: str) -> int:
    """Logical T-SQL statements in one execute() body. The finalize applock is a 4-statement batch
    (``SET NOCOUNT ON; DECLARE; EXEC sp_getapplock; SELECT @rc``) already sent as ONE round-trip;
    every other handoff literal is a single statement (a trailing ``;`` on the MERGE is not a
    separator)."""
    return sum(1 for part in sql.split(";") if part.strip())


def is_hard_boundary(sql: str, *, applock_soft: bool = True) -> bool:
    """True iff this statement's returned result must reach the client before the NEXT statement's
    SQL/params can be built or a Python branch taken — i.e. it must be the last statement of its
    round-trip. See the module docstring for the classification rationale."""
    if "sp_getapplock" in sql:
        return not applock_soft  # rc is validate-then-continue; foldable unless the strict variant
    if sql == ss._SQL_DELETE_GUARD:
        return True
    if sql == ss._SQL_FINALIZE_COUNT or sql == ss._SQL_SELECT_MESSAGE_STATUS:
        return True
    if sql == ss._SQL_SELECT_METADATA:
        return True
    if sql.startswith("SELECT message_id, destination_name, handler_name"):
        return True
    if "FROM delivered_keys WHERE outbox_id=?" in sql:
        return True
    if sql.startswith("SELECT control_id FROM messages"):
        return True
    if sql.startswith("SELECT COUNT(*) FROM delivered_keys"):
        return True
    return False


def partition_round_trips(
    calls: list[tuple[str, tuple[Any, ...]]], *, applock_soft: bool = True
) -> list[list[int]]:
    """Group statement indices into batched round-trips per the model. A hard-boundary statement
    closes its group (it is the last statement in that round-trip)."""
    groups: list[list[int]] = []
    cur: list[int] = []
    for i, (sql, _params) in enumerate(calls):
        cur.append(i)
        if is_hard_boundary(sql, applock_soft=applock_soft):
            groups.append(cur)
            cur = []
    if cur:
        groups.append(cur)
    return groups


@dataclass
class HopInventory:
    name: str
    executes: int  # pyodbc execute() calls (unbatched round-trips, ex-commit)
    commits: int
    statements: int  # logical T-SQL statements issued (batching-invariant)
    client_reads: int  # fetchone/fetchall on immediate results (no guaranteed extra round-trip)
    rt_unbatched: int  # executes + commits
    rt_batched_soft: int  # batched round-trips (applock folded) + commits
    rt_batched_hard: int  # batched round-trips (applock as a client gate) + commits
    calls: list[tuple[str, tuple[Any, ...]]]

    @property
    def drop_soft(self) -> float:
        return (self.rt_unbatched - self.rt_batched_soft) / self.rt_unbatched

    @property
    def drop_hard(self) -> float:
        return (self.rt_unbatched - self.rt_batched_hard) / self.rt_unbatched


def _inventory(name: str, rec: _Rec) -> HopInventory:
    executes = len(rec.calls)
    statements = sum(count_tsql_statements(sql) for sql, _ in rec.calls)
    rt_unbatched = executes + rec.commits
    groups_soft = partition_round_trips(rec.calls, applock_soft=True)
    groups_hard = partition_round_trips(rec.calls, applock_soft=False)
    return HopInventory(
        name=name,
        executes=executes,
        commits=rec.commits,
        statements=statements,
        client_reads=len(rec.reads),
        rt_unbatched=rt_unbatched,
        rt_batched_soft=len(groups_soft) + rec.commits,
        rt_batched_hard=len(groups_hard) + rec.commits,
        calls=list(rec.calls),
    )


def build_inventory() -> dict[str, HopInventory]:
    """The per-hop inventory for the throughput-relevant hot path (1 handler / 1 delivery / 0 state).

    This is the dict the CI gate (``tests/test_adr0071_statement_rt_inventory.py``) asserts on.
    """
    return {
        "route_handoff": _inventory("route_handoff", record_route_handoff(n_handlers=1)),
        "transform_handoff": _inventory(
            "transform_handoff", record_transform_handoff(n_deliveries=1, n_state=0)
        ),
        "mark_done": _inventory("mark_done", record_mark_done()),
    }


def flatten_groups(
    calls: list[tuple[str, tuple[Any, ...]]], groups: list[list[int]]
) -> list[tuple[str, tuple[Any, ...]]]:
    """Reconstruct the ordered ``(sql, params)`` stream a batched execution would logically issue:
    emit ``calls[i]`` for each grouped index, in round-trip order and within-round-trip order.

    This is a **content-based** reconstruction (it carries the actual sql text + params, not just
    indices), so a grouping that REORDERED, DROPPED, DUPLICATED, or MUTATED any statement produces a
    reconstruction that differs from the original ``calls`` — which is what makes
    :func:`verify_logical_sequence_preserved` a real check rather than a tautology. It accepts an
    arbitrary ``groups`` argument precisely so a negative control (a deliberately reordered grouping)
    can exercise the failure path; see ``test_regroup_check_has_teeth``.
    """
    return [calls[i] for g in groups for i in g]


def verify_logical_sequence_preserved(inv: HopInventory, *, applock_soft: bool = True) -> bool:
    """True iff the batching model's round-trip grouping is **regroup-only** for this hop: the
    content-based reconstruction (:func:`flatten_groups`) of the batched groups equals the original
    unbatched ``(sql, params)`` sequence byte-for-byte (no reorder, drop, duplication, or param
    mutation), AND the grouping is a true partition (every statement index used exactly once).

    This documents the regroup-only property for the ACTUAL partition the model produces; the proof
    that the check has teeth (i.e. that a reordered grouping WOULD fail) is the negative control in
    the gate, which feeds :func:`flatten_groups` a hand-corrupted grouping.
    """
    groups = partition_round_trips(inv.calls, applock_soft=applock_soft)
    indices = sorted(i for g in groups for i in g)
    if indices != list(range(len(inv.calls))):
        return False  # a statement was dropped or duplicated (grouping is not a true partition)
    return flatten_groups(inv.calls, groups) == inv.calls


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def _fmt_pct(x: float) -> str:
    return f"{x * 100:5.1f}%"


def main() -> int:
    inv = build_inventory()

    print("=" * 100)
    print("ADR 0071 B5 - per-hop SQL statement / network round-trip inventory (Lane 3a)")
    print("MEASURED: (sql, params) sequences driven through the REAL shipped store methods")
    print(
        "          (route_handoff_sync / transform_handoff_sync / mark_done) - no live SQL Server."
    )
    print("DERIVED : round-trips = execute() + commit(); batched round-trips per the stated model.")
    print("=" * 100)

    print(
        "\nHot path = 1 handler / 1 delivery / 0 state ops (the throughput-relevant common case).\n"
    )
    hdr = (
        f"{'hop':<20}{'exec':>6}{'commit':>8}{'stmts':>7}{'reads':>7}"
        f"{'RT(now)':>9}{'RT(batch)':>11}{'drop':>8}{'RT(strict)':>12}{'drop':>8}"
    )
    print(hdr)
    print("-" * len(hdr))
    for name in ("route_handoff", "transform_handoff", "mark_done"):
        h = inv[name]
        print(
            f"{h.name:<20}{h.executes:>6}{h.commits:>8}{h.statements:>7}{h.client_reads:>7}"
            f"{h.rt_unbatched:>9}{h.rt_batched_soft:>11}{_fmt_pct(h.drop_soft):>8}"
            f"{h.rt_batched_hard:>12}{_fmt_pct(h.drop_hard):>8}"
        )

    # Aggregate over the two pipeline handoff hops (the commits/msg == 2.000 identity pair).
    route = inv["route_handoff"]
    trans = inv["transform_handoff"]
    pipe_now = route.rt_unbatched + trans.rt_unbatched
    pipe_soft = route.rt_batched_soft + trans.rt_batched_soft
    pipe_hard = route.rt_batched_hard + trans.rt_batched_hard
    pipe_commits = route.commits + trans.commits
    print("-" * len(hdr))
    print(
        f"{'route+transform':<20}{'':>6}{pipe_commits:>8}{'':>7}{'':>7}"
        f"{pipe_now:>9}{pipe_soft:>11}{_fmt_pct((pipe_now - pipe_soft) / pipe_now):>8}"
        f"{pipe_hard:>12}{_fmt_pct((pipe_now - pipe_hard) / pipe_now):>8}"
    )

    print("\n" + "=" * 100)
    print("INVARIANT CHECKS")
    print("=" * 100)

    # (1) commits/msg identity: the two pipeline hops commit exactly once each -> 2.000/msg, UNCHANGED
    #     by batching (batching moves no commit boundary).
    identity_ok = route.commits == 1 and trans.commits == 1 and pipe_commits == 2
    print(
        f"commits/msg identity: route={route.commits} + transform={trans.commits} = {pipe_commits} "
        f"(== 2.000)  -> {'PASS' if identity_ok else 'FAIL'}"
    )
    print("  batching keeps 1 commit/hop -> commits/msg stays 2.000 (NOT the ADR 0069 fence).")

    # (2) identical logical (sql, params) sequence under batching, both variants.
    seq_ok = all(
        verify_logical_sequence_preserved(inv[n], applock_soft=soft)
        for n in inv
        for soft in (True, False)
    )
    print(
        f"logical (sql,params) sequence preserved by batching (regroup-only): "
        f"{'PASS' if seq_ok else 'FAIL'}"
    )

    print("\n" + "=" * 100)
    print("BATCHED-COLLAPSE ASSESSMENT - the >= 40% claim is CONDITIONAL on the applock-fold")
    print("=" * 100)
    print(
        "  Two columns because there is NO interpretation-independent result. 'fold' = the finalize\n"
        "  sp_getapplock rc folds into the trailing batch (net-identical: rc<0 rolls the whole txn\n"
        "  back); 'strict' = the rc is validated as a client-side gate. NEITHER is a GO on its own -\n"
        "  a real GO/NO-GO needs the Wave-2 live-rig end-to-end A/B.\n"
    )
    agg_soft = (pipe_now - pipe_soft) / pipe_now
    agg_hard = (pipe_now - pipe_hard) / pipe_now

    def _bar(drop: float) -> str:
        return "OK>=40" if drop >= 0.40 else "<40"

    def _row(label: str, rt_now: int, rt_s: int, drop_s: float, rt_h: int, drop_h: float) -> str:
        fold = f"{rt_s} ({_fmt_pct(drop_s)})"
        strict = f"{rt_h} ({_fmt_pct(drop_h)})"
        return (
            f"  {label:<18}{rt_now:>5}   {fold:>12} {_bar(drop_s):<7}{strict:>12} {_bar(drop_h):<7}"
        )

    print(
        f"  {'hop':<18}{'RT':>5}   {'fold (drop)':>12} {'bar':<7}{'strict (drop)':>12} {'bar':<7}"
    )
    print("  " + "-" * 60)
    for name in ("route_handoff", "transform_handoff", "mark_done"):
        h = inv[name]
        print(
            _row(
                h.name,
                h.rt_unbatched,
                h.rt_batched_soft,
                h.drop_soft,
                h.rt_batched_hard,
                h.drop_hard,
            )
        )
    print(_row("route+transform", pipe_now, pipe_soft, agg_soft, pipe_hard, agg_hard))
    print(
        "\n  Verdict: per-hop round-trip opportunity is 27-50% (this is real and reproducible). Under\n"
        "  the applock-FOLD, route_handoff (50.0%), transform_handoff (42.9%) and the route+transform\n"
        "  pair (46.2%) clear >=40%; mark_done (36.4%) does not. Under the STRICT interpretation the\n"
        "  drops are 27.3-33.3% and NOTHING clears >=40%. So '>=40% -> un-hold' is valid ONLY with the\n"
        "  applock-fold stated; the strict floor (27-33%, clears nothing) must be quoted alongside it.\n"
        "  Unconditional across BOTH: commits/msg stays 2.000 and the logical (sql,params) sequence is\n"
        "  preserved -> per-hop batching is a round-trip optimization, NOT invariant-blocked. It is NOT,\n"
        "  on this evidence alone, an unconditional throughput GO."
    )

    print("\nDONE.")
    return 0 if (identity_ok and seq_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
