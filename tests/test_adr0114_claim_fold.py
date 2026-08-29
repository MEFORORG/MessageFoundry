# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0114 sub-lever C (``fifo_claim_fold_reset``): the INGRESS/ROUTED reset fold.

Offline (no SQL Server): the store is built bare (``object.__new__``) or through the real
``__init__`` and driven through recording fakes — the ADR 0075 harness recipe — so every
control-flow branch the ADR names is exercised in normal CI. What this file freezes:

- **AC-1** flags-off byte-identity: the claim batch's SQL text (pinned SHA-256 per lane family ×
  N ∈ {1, 4, 64} × epoch on/off), parameter tuple, 4-wire-op sequence, and A1 commit count are the
  shipped construction byte-for-byte. The hashes were generated from the pre-ADR-0114 code at
  commit f1411f3b — any drift in the shipped batch fails here (and the batch and the ADR 0114 proc
  bodies must be edited together, forever).
- **AC-2** fold scoping: fold ON appends exactly one trailing ``SET LOCK_TIMEOUT -1;`` at
  INGRESS/ROUTED (args unchanged); OUTBOUND/RESPONSE stay byte-identical (never fold).
- **AC-3** the verbatim shielded guard runs on EVERY non-clean exit: 1222, kept≠claimed, commit#1
  failure, cancellation at a body await (no rollback on that path — the ADR §2 nuance), and
  cancellation during the finally's own awaits (shield completes the reset before re-raise) —
  including both swallow-and-log arms (a guard reset failure never masks the real outcome).
- **AC-4** code shape: ``reset_committed`` has exactly one assignment site besides its init,
  immediately after commit#1's await with no intervening await; the finally body is exactly the
  ``if not reset_committed:`` skip around the guard, whose dedented source is hash-pinned.
- **AC-5** the runtime guard on the fold's H2-noop premise: a claimed row with a non-NULL
  ``destination_name`` at a folded stage (INGRESS and ROUTED) raises a contract violation before
  the H2 branch is entered, with an ERROR log naming the row; the same row with fold OFF takes the
  shipped H2 path (the non-vacuousness control).
- **§6** read-once wiring: a store built through the real ``__init__`` snapshots the settings flag
  and the fold engages/disengages accordingly (the settings→behavior path, not a hand-set attr).

Deferred to the ADR §8 bench battery on a live SQL Server (env-gated / the bench box, NOT here):
the post-run ``@@LOCK_TIMEOUT = -1`` pool assay, the differential store-primitive run over
identical DB states, and the forced-contention/cancellation micro-arms.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import hashlib
import inspect
import logging
import textwrap
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.crypto import IdentityCipher
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import ClaimAbortPhase, ClaimedHeads, ClaimLockTimeout

# --- AC-1 goldens: SHA-256 of the shipped batch text, per (lane family, N, epoch on/off), -------
# generated from the pre-ADR-0114 construction (commit f1411f3b) with now=1700000000.0.
# ingress/routed/response share one text (the channel_id lane family); outbound is the
# destination_name family. The text does not depend on `now` (a parameter), only on N and epoch.
_GOLDEN_SQL_SHA256 = {
    # (lane_family, n_lanes, epoch_on): sha256(batch_text)
    ("cid", 1, False): "e2ceb6620079c88945bab0bd4e929b5bcf8a028054ad84155f851192b9b1e372",
    ("cid", 1, True): "b45614c72d4573577c0ac66429df7f2a0401205b5376ea6bdb86ed75527a8c7b",
    ("cid", 4, False): "5ea62e8043cf068d4927a1eab07d0beb7973d381ac4aa2da573cd9e78ef3013c",
    ("cid", 4, True): "b60ea275be97c9feae09f45712b14444aed34e0b351d190d24607695df546d5f",
    ("cid", 64, False): "539b3681c39e04a793cd62d26fee7a5d8a7c1dafabef6f4a125990e73e610d52",
    ("cid", 64, True): "38a86a9a625f1d0c8a6e3a95ae8bfad8e8aefd7d385e39525a61d0a51dfb1e6a",
    ("dst", 1, False): "ecae73ad37445af836553a0061bca31f3150dbd71242526271472dda6e40fb04",
    ("dst", 1, True): "f38905200260f64a68f290c999e2725e955259eccd1d69bb109580d87305d519",
    ("dst", 4, False): "1b7b3f0791ddf2d831703b0bc94366cdb9bf4a25a1bcb530e6fdd4db446e6148",
    ("dst", 4, True): "bbfefad20d19619d09188b9b8eaec31714c33867dc415cec8babaaf2c64a32f3",
    ("dst", 64, False): "f93bd59f70d0b867b58589b996cfb8b06f76a6259e27f65c4d92fb5f409b1945",
    ("dst", 64, True): "d597ce4af4702216d24aa52b425b2d89948aef494413c792ca4c877424c3d243",
}
_FAMILY = {"ingress": "cid", "routed": "cid", "response": "cid", "outbound": "dst"}
_TRAILING_RESET = " SET LOCK_TIMEOUT -1;"
_NOW = 1700000000.0

# AC-4: pinned dedented source of the finally's `if not reset_committed:` guard block — the
# byte-for-byte freeze of the shipped shielded guard (B1/M-6). Any edit to the guard (code OR its
# load-bearing comments) fails here and requires a design review per ADR 0114 §2.
_GUARD_BODY_SHA256 = "2d3bc173089d3d7d360b7fb2a35412295ba77686cb3b574dd49c6a3ed3f95566"

_COLS = (
    "keep_id",
    "id",
    "message_id",
    "channel_id",
    "destination_name",
    "handler_name",
    "payload",
    "attempts",
    "seq",
    "created_at",
)

# The wire-op record: ("execute-batch"|"execute-reset"|"execute-h2-probe", sql, params) or
# ("commit"|"commit-failed"|"rollback",) — heterogeneous, hence tuple[Any, ...].
_Ops = list[tuple[Any, ...]]


def _row(
    rid: str,
    *,
    message_id: str = "m1",
    channel_id: str = "IB_X",
    destination_name: str | None = None,
    payload: str = "P",
) -> tuple[Any, ...]:
    """A claimed row in the sole result set's 10-column shape (keep_id LEFT-joined twin)."""
    return (rid, rid, message_id, channel_id, destination_name, None, payload, 1, 1, _NOW)


def _null_twin(rid: str) -> tuple[Any, ...]:
    """A kept row whose claimed twin is NULL — the kept≠claimed defensive signal."""
    return (rid, None, None, None, None, None, None, None, None, None)


class _FakeODBCError(Exception):
    """Shape-compatible with pyodbc.Error: args = (sqlstate, message); the driver embeds the
    SQL Server native code in the message text (the `_is_lock_timeout` contract)."""

    def __init__(self, sqlstate: str, message: str) -> None:
        super().__init__(sqlstate, message)


def _lock_timeout_error() -> _FakeODBCError:
    return _FakeODBCError(
        "HY000",
        "[Microsoft][ODBC Driver 18 for SQL Server]Lock request time out period exceeded. (1222)",
    )


class _FakeCursor:
    """Records every execute; programmable rows, per-statement failures, and a blocking gate for
    the cancellation-during-finally leg. ``ops`` is shared with the connection so the test sees the
    full interleaved wire-op sequence."""

    def __init__(
        self,
        ops: _Ops,
        *,
        rows: list[tuple[Any, ...]] | None = None,
        fail_batch: BaseException | None = None,
        fail_reset: BaseException | None = None,
        fail_h2_update: BaseException | None = None,
        h2_already_delivered: bool = False,
        reset_started: asyncio.Event | None = None,
        reset_release: asyncio.Event | None = None,
        tag: str = "",
    ) -> None:
        self.ops = ops
        self._rows = rows or []
        self._fail_batch = fail_batch
        self._fail_reset = fail_reset
        # BACKLOG #1270: the H2 skip-and-complete leg. `h2_already_delivered` makes the
        # `delivered_keys` probe report a hit so the in-store finalize DML actually runs;
        # `fail_h2_update` then raises on that UPDATE. Together they reach the SECOND population
        # that lands in the same lock-timeout handler as the claim batch — a contended FINALIZE row,
        # which is not a queue head at all. Both default off, so every existing driver is unchanged
        # (the probe keeps reporting "not delivered" and the UPDATE is unreachable).
        self._fail_h2_update = fail_h2_update
        self._h2_already_delivered = h2_already_delivered
        self._reset_started = reset_started
        self._reset_release = reset_release
        # Optional connection-identity tag ("kind@tag" in the op records) so a multi-connection
        # rig (the sub-lever B dedicated holders) can assert WHICH cursor an op ran on — a guard
        # running on the wrong connection must be distinguishable, not byte-identical.
        self._tag = tag
        self.description: list[tuple[str, ...]] | None = None

    def _kind(self, kind: str) -> str:
        return f"{kind}@{self._tag}" if self._tag else kind

    async def execute(self, sql: str, params: Any = ()) -> None:
        if sql.startswith("SET LOCK_TIMEOUT -1"):
            self.ops.append((self._kind("execute-reset"), sql, tuple(params)))
            if self._reset_started is not None:
                self._reset_started.set()
            if self._reset_release is not None:
                await self._reset_release.wait()
            if self._fail_reset is not None:
                raise self._fail_reset
            return
        if "delivered_keys" in sql:
            self.ops.append((self._kind("execute-h2-probe"), sql, tuple(params)))
            return
        if sql.startswith("UPDATE queue SET status"):
            # The H2 skip-and-complete DML, reachable only via `h2_already_delivered` (the probe
            # otherwise reports a miss), so this branch cannot perturb any pre-existing driver.
            self.ops.append((self._kind("execute-h2-update"), sql, tuple(params)))
            if self._fail_h2_update is not None:
                raise self._fail_h2_update
            return
        self.ops.append((self._kind("execute-batch"), sql, tuple(params)))
        if self._fail_batch is not None:
            raise self._fail_batch
        self.description = [(c,) for c in _COLS]

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows

    async def fetchone(self) -> Any:
        # H2 delivered_keys probe: "not already delivered" unless the driver asked for a hit.
        return (1,) if self._h2_already_delivered else None

    async def close(self) -> None:
        pass


class _FakeConn:
    def __init__(
        self,
        ops: _Ops,
        *,
        fail_first_commit: bool = False,
        first_commit_error: BaseException | None = None,
        tag: str = "",
    ) -> None:
        self.ops = ops
        # BACKLOG #1270: `first_commit_error` fails commit#1 with a CHOSEN exception, so a 1222 can
        # be raised there — the ordinary path where the H2 probe MISSED and no finalize DML ran.
        # `fail_first_commit=True` keeps its shipped RuntimeError, so every existing driver is
        # unchanged; passing an error implies the failure, so the two knobs cannot disagree.
        self._fail_first_commit = fail_first_commit or first_commit_error is not None
        self._first_commit_error = first_commit_error or RuntimeError("injected commit#1 failure")
        self._tag = tag

    def _kind(self, kind: str) -> str:
        return f"{kind}@{self._tag}" if self._tag else kind

    async def commit(self) -> None:
        if self._fail_first_commit:
            self._fail_first_commit = False
            self.ops.append((self._kind("commit-failed"),))
            raise self._first_commit_error
        self.ops.append((self._kind("commit"),))

    async def rollback(self) -> None:
        self.ops.append((self._kind("rollback"),))


def _acm(obj: Any) -> Any:
    @asynccontextmanager
    async def cm(*_a: Any, **_k: Any) -> Any:
        yield obj

    return cm


def _bare_store(*, fold: bool = False, epoch: bool = False) -> SqlServerStore:
    store = object.__new__(SqlServerStore)
    store._settings = StoreSettings(command_timeout=30)
    store._cipher = IdentityCipher()
    store._state_cache = {}
    store._sync_pools = {}
    store._batch_handoff_statements = False
    store._fifo_claim_fold_reset = fold
    store._fifo_claim_proc = False
    store._claim_proc_effective = False
    store._claim_proc_degraded_reason = None
    store._claim_proc_input_sizes = None
    store._claim_proc_setinputsizes_warned = False
    store._fifo_claim_prepared = False
    store._claim_prepared_effective = False
    store._claim_prepared_degraded_reason = None
    store._claim_prepared_input_sizes = None
    store._claim_holders = {}
    store._claim_holders_closed = False
    store._claim_holders_open = 0
    store._claim_holders_opened_total = 0
    store._claim_holders_discarded_total = 0
    store._message_events = "all"
    store._audit_mac_key = None
    store._audit_keyed_from = None
    store._leader_epoch = None
    store._lease_key = None
    store.committed_txns = 0
    store.body_copies = 0
    if epoch:
        store.set_leader_epoch(7, lease_key="lease-key-golden")
    return store


def _init_store(*, fold: bool) -> SqlServerStore:
    """A store built through the REAL __init__ (the §6 read-once settings→attr wiring), with a
    dummy pool object — __init__ performs no I/O."""
    return SqlServerStore(object(), StoreSettings(fifo_claim_fold_reset=fold, command_timeout=30))


def _wire(store: SqlServerStore, cur: _FakeCursor, conn: _FakeConn) -> None:
    def _acquire_cm() -> Any:
        return _acm(conn)()

    def _cursor_cm(_conn: Any) -> Any:
        return _acm(cur)(_conn)

    store._acquire = _acquire_cm  # type: ignore[method-assign]
    store._cursor = _cursor_cm  # type: ignore[method-assign, assignment]


async def _drive(
    stage: str,
    n_lanes: int,
    *,
    fold: bool = False,
    epoch: bool = False,
    rows: list[tuple[Any, ...]] | None = None,
    fail_batch: BaseException | None = None,
    fail_reset: BaseException | None = None,
    fail_h2_update: BaseException | None = None,
    h2_already_delivered: bool = False,
    fail_first_commit: bool = False,
    first_commit_error: BaseException | None = None,
    per_lane_limit: int = 1,
    store: SqlServerStore | None = None,
) -> tuple[_Ops, SqlServerStore, ClaimedHeads]:
    ops: _Ops = []
    store = store if store is not None else _bare_store(fold=fold, epoch=epoch)
    cur = _FakeCursor(
        ops,
        rows=rows,
        fail_batch=fail_batch,
        fail_reset=fail_reset,
        fail_h2_update=fail_h2_update,
        h2_already_delivered=h2_already_delivered,
    )
    conn = _FakeConn(
        ops, fail_first_commit=fail_first_commit, first_commit_error=first_commit_error
    )
    _wire(store, cur, conn)
    lanes = [f"lane-{i:03d}" for i in range(n_lanes)]
    result = await store.claim_fifo_heads(stage, lanes, now=_NOW, per_lane_limit=per_lane_limit)
    return ops, store, result


def _op_kinds(ops: _Ops) -> list[str]:
    return [str(op[0]) for op in ops]


def _guard_ran(ops: _Ops) -> bool:
    """The shielded guard's signature on the wire: a standalone reset execute followed by a commit."""
    kinds = _op_kinds(ops)
    return "execute-reset" in kinds and kinds.index("execute-reset") < len(kinds) - 1


# --- AC-1: flags-off byte-identity (text, args, wire ops, A1 count) ------------------------------


@pytest.mark.parametrize("stage", ["ingress", "routed", "outbound", "response"])
@pytest.mark.parametrize("n_lanes", [1, 4, 64])
@pytest.mark.parametrize("epoch", [False, True])
async def test_ac1_flags_off_batch_text_and_args_byte_identical(
    stage: str, n_lanes: int, epoch: bool
) -> None:
    # per_lane_limit=2 makes the HARD-1 clamp observable in the args: k=2 survives at
    # INGRESS/ROUTED, is clamped to 1 at OUTBOUND/RESPONSE.
    ops, store, _ = await _drive(stage, n_lanes, fold=False, epoch=epoch, per_lane_limit=2)
    kind, sql, params = ops[0]
    assert kind == "execute-batch"
    assert (
        hashlib.sha256(sql.encode()).hexdigest()
        == _GOLDEN_SQL_SHA256[(_FAMILY[stage], n_lanes, epoch)]
    ), f"claim batch text drifted from the pre-ADR-0114 shipped construction ({stage})"
    # Parameter tuple: 5 scalars + N lanes (+ the epoch pair twice — probe AND UPDATE guards).
    expected_k = 1 if stage in ("outbound", "response") else 2
    expected_params: tuple[Any, ...] = (
        _NOW,
        stage,
        expected_k,
        "pending",
        "inflight",
        *[f"lane-{i:03d}" for i in range(n_lanes)],
    )
    if epoch:
        expected_params = (*expected_params, "lease-key-golden", 7, "lease-key-golden", 7)
    assert params == expected_params
    # Wire-op sequence: execute(batch), commit#1, execute(reset), commit#2 — 4 ops, always.
    assert _op_kinds(ops) == ["execute-batch", "commit", "execute-reset", "commit"]
    assert store.committed_txns == 2  # A1: both commits ride _commit (the counted write currency)


async def test_ac1_flags_off_no_trailing_reset_in_batch() -> None:
    ops, _, _ = await _drive("ingress", 4, fold=False)
    sql = ops[0][1]
    assert not sql.endswith(_TRAILING_RESET)
    # The reset exists ONLY as the guard's standalone statement (wire op 3).
    assert ops[2][0] == "execute-reset" and ops[2][1] == "SET LOCK_TIMEOUT -1;"


# --- §6: the read-once settings→attr wiring (the real __init__, not a hand-set attr) -------------


@pytest.mark.parametrize("flag", [False, True])
def test_init_snapshots_the_flag_from_settings(flag: bool) -> None:
    store = _init_store(fold=flag)
    assert store._fifo_claim_fold_reset is flag


@pytest.mark.parametrize("flag", [False, True])
async def test_init_constructed_store_folds_end_to_end(flag: bool) -> None:
    # The settings→behavior path: a store built through the REAL __init__ with the flag in
    # StoreSettings must engage (or not engage) the fold — no hand-injected attribute anywhere.
    ops, store, _ = await _drive("ingress", 2, store=_init_store(fold=flag))
    kinds = _op_kinds(ops)
    if flag:
        assert kinds == ["execute-batch", "commit"]
        assert ops[0][1].endswith(_TRAILING_RESET)
        assert store.committed_txns == 1
    else:
        assert kinds == ["execute-batch", "commit", "execute-reset", "commit"]
        assert not ops[0][1].endswith(_TRAILING_RESET)
        assert store.committed_txns == 2


# --- AC-2: fold scoping — INGRESS/ROUTED fold; OUTBOUND/RESPONSE never ---------------------------


@pytest.mark.parametrize("stage", ["ingress", "routed"])
@pytest.mark.parametrize("n_lanes", [1, 4, 64])
@pytest.mark.parametrize("epoch", [False, True])
async def test_ac2_fold_appends_exactly_one_trailing_reset(
    stage: str, n_lanes: int, epoch: bool
) -> None:
    ops, store, _ = await _drive(stage, n_lanes, fold=True, epoch=epoch)
    _, sql, params = ops[0]
    assert sql.endswith(_TRAILING_RESET)
    # Strictly additive: stripping the trailing reset yields the shipped text byte-for-byte.
    stripped = sql[: -len(_TRAILING_RESET)]
    assert (
        hashlib.sha256(stripped.encode()).hexdigest()
        == _GOLDEN_SQL_SHA256[(_FAMILY[stage], n_lanes, epoch)]
    )
    assert sql.count("SET LOCK_TIMEOUT -1") == 1
    # Args are unchanged by the fold (the trailing SET is parameterless).
    baseline_ops, _, _ = await _drive(stage, n_lanes, fold=False, epoch=epoch)
    assert params == baseline_ops[0][2]
    # Clean folded path: 2 wire ops (execute, commit#1), no guard, ONE counted commit (A1 shift).
    assert _op_kinds(ops) == ["execute-batch", "commit"]
    assert store.committed_txns == 1


@pytest.mark.parametrize("stage", ["outbound", "response"])
@pytest.mark.parametrize("epoch", [False, True])
async def test_ac2_outbound_response_never_fold(stage: str, epoch: bool) -> None:
    ops, store, _ = await _drive(stage, 4, fold=True, epoch=epoch)
    _, sql, _params = ops[0]
    # Byte-identical to the shipped batch — the fold flag must not touch these stages.
    assert (
        hashlib.sha256(sql.encode()).hexdigest() == _GOLDEN_SQL_SHA256[(_FAMILY[stage], 4, epoch)]
    )
    assert _op_kinds(ops) == ["execute-batch", "commit", "execute-reset", "commit"]
    assert store.committed_txns == 2


async def test_fold_clean_path_with_claimed_row() -> None:
    # ADR §1 exit-table row 1 with a real claimed row (not just the zero-row shape): the row is
    # returned, the guard is skipped, ONE commit.
    ops, store, result = await _drive("ingress", 1, fold=True, rows=[_row("r1")])
    assert _op_kinds(ops) == ["execute-batch", "commit"]
    assert store.committed_txns == 1
    assert [i.id for items in result.by_lane.values() for i in items] == ["r1"]


# --- AC-3: the verbatim shielded guard runs on EVERY non-clean exit ------------------------------


@pytest.mark.parametrize("fold", [False, True])
async def test_ac3_1222_yields_empty_all_and_guard_runs(fold: bool) -> None:
    ops, store, result = await _drive("ingress", 4, fold=fold, fail_batch=_lock_timeout_error())
    # BACKLOG #1270: the EMPTY-all contract is unchanged — `by_lane` and `rearm` are still empty and
    # no row moves. What is new is that the ATTEMPT is reported: the claim says it aborted on a lock
    # timeout, which is what a caller cannot otherwise tell apart from a genuinely empty lane.
    # WHOLE-OBJECT equality, not a per-field probe: it pins the two unchanged fields AND any field a
    # future revision adds, which is exactly how #1270's first attempt shipped a fabricated lane set
    # past a green suite. The report is attempt-level and names no lane — see ClaimLockTimeout.
    assert result == ClaimedHeads(
        by_lane={},
        rearm=frozenset(),
        lock_timeout=ClaimLockTimeout(phase=ClaimAbortPhase.HEAD, lanes_in_claim=4),
    )
    kinds = _op_kinds(ops)
    assert "rollback" in kinds
    assert _guard_ran(ops), "the shielded guard must run on the 1222 exit (reset_committed False)"
    assert kinds[-1] == "commit"  # the guard's own commit closes the reset's implicit txn (M-6)


# --- BACKLOG #1270: what a lock-timeout yield is allowed to CLAIM to know -------------------------


def _lanes_named_at(value: Any, requested: set[str], path: str) -> dict[str, list[str]]:
    """Every place in ``value`` that names a requested lane, keyed by DOTTED path.

    Recurses through dataclasses and through containers' elements, so a lane name is found wherever
    it is sited — ``rearm`` at the top level, ``lock_timeout.contended_lanes`` one level down, or a
    bare ``str`` field. A walk that stops at the top level reports the same clean result for a
    structure that hides the fabrication in a nested field, which is the shape #1270 itself
    introduced (``ClaimedHeads.lock_timeout`` is a dataclass, so the original walk skipped it)."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        found: dict[str, list[str]] = {}
        for f in dataclasses.fields(value):
            child = f"{path}.{f.name}" if path else f.name
            found |= _lanes_named_at(getattr(value, f.name), requested, child)
        return found
    if isinstance(value, str):  # BEFORE the container check — a str is iterable, by CHARACTER
        return {path: [value]} if value in requested else {}
    if isinstance(value, frozenset | set | list | tuple | dict):
        # `set(dict)` is its KEYS, which is where by_lane sites a lane name.
        found = {path: sorted(requested & set(value))} if requested & set(value) else {}
        elements = value.values() if isinstance(value, dict) else value
        for i, element in enumerate(elements):
            # Strings are already covered by the intersection above; recursing into them too would
            # report the same 256 names once as a container and 256 times again as elements, and
            # bury the ONE path a reader needs under its own restatement.
            if not isinstance(element, str):
                found |= _lanes_named_at(element, requested, f"{path}[{i}]")
        return found
    return {}


async def test_a_lock_timeout_never_names_a_lane_the_claim_never_observed() -> None:
    """The regression test for BACKLOG #1270's first shipped attempt.

    THE DEFECT. The batch aborts, the whole transaction rolls back, and NOT ONE ROW WAS EVER READ —
    ``fetchall`` does not run. The first fix nevertheless returned the caller's own requested lane
    list as an observation ("these lanes were contended"), so at the production-default chunk of 256
    a single lock timeout asserted 256 findings the store had established nothing about. Programming
    the fake cursor WITH a row changes the output not at all, which is the proof: the field was a
    copy of the REQUEST, never a reading.

    THE PROPERTY, and why it is stated over the WHOLE object rather than one field. Nothing was
    claimed here, so a lane name appearing ANYWHERE in the result is a fabrication by construction —
    ``by_lane`` is the only field entitled to carry one and it is empty. Walking the whole object
    keeps this pinned against a future field that re-introduces the same claim under a new name,
    which a single-field assertion would not.

    THE WALK GOES ALL THE WAY DOWN, and it has to. The version this replaces walked
    ``dataclasses.fields(result)`` and kept only TOP-LEVEL containers — so ``lock_timeout``, a
    dataclass, was skipped entirely, and the guard was blind to every field inside the very object
    #1270 added. Measured: a ``ClaimLockTimeout.contended_lanes`` populated from the caller's request
    at widths above 8 sent 256 fabricated lane names out of the store at the production-default
    chunk with the whole 223-test set green — including this guard. Sited one level up, the
    identical field fails here loudly, which is the proof that what moved was the guard's REACH and
    not the property it states.

    256 IS THE POINT, not decoration. ``wiring_runner`` computes the pooled chunk as
    ``min(pooled_claim_lane_chunk, backend_chunk)`` = ``min(256, 500)`` on SQL Server, and pooled is
    the default claim mode — so this is the default path at its default width. At 1 or 4 lanes (what
    the pre-existing arms use) naming every requested lane is indistinguishable from correct — and a
    width-gated fabrication that only arms above those widths is invisible to every equality
    assertion in this file, which all drive 1 or 4 lanes."""
    chunk = 256
    requested = {f"lane-{n:03d}" for n in range(chunk)}

    # POSITIVE CONTROL, first, because a walk that finds nothing ANYWHERE is indistinguishable from a
    # clean result — the guard's green would then be an artefact of the instrument, not a reading.
    # This is the exact failure the version it replaces had: it walked only top-level fields and so
    # reported clean for a nested siting, silently. Each of the three shapes below is a real
    # regression shape, and the walk must name each by its dotted path.
    @dataclasses.dataclass(frozen=True)
    class _Inner:
        lanes: frozenset[str]

    @dataclasses.dataclass(frozen=True)
    class _Probe:
        top: frozenset[str]
        inner: _Inner
        bare: str

    probe = _lanes_named_at(
        _Probe(top=frozenset({"lane-000"}), inner=_Inner(frozenset({"lane-001"})), bare="lane-002"),
        requested,
        "",
    )
    assert probe == {
        "top": ["lane-000"],
        "inner.lanes": ["lane-001"],
        "bare": ["lane-002"],
    }, (
        f"the walk cannot see the sitings it exists to catch, so its clean result proves nothing: {probe}"
    )

    _ops, _store, result = await _drive("ingress", chunk, fail_batch=_lock_timeout_error())
    assert result.by_lane == {} and result.rearm == frozenset(), "sanity: nothing was claimed"
    named = _lanes_named_at(result, requested, "")
    assert not named, (
        f"the claim named lane(s) it never observed: { {k: len(v) for k, v in named.items()} } of"
        f" {chunk} requested. The batch raised before fetchall ran, so the store read no row and"
        " cannot attribute this abort to any lane. A per-lane count that is really a copy of the"
        " request stops discriminating anything."
    )
    # What the store IS entitled to say: this ATTEMPT aborted on a lock timeout, and how wide it was.
    assert result.lock_timeout is not None, "the abort must still be reported, just not per-lane"
    assert result.lock_timeout.phase == "head"
    assert result.lock_timeout.lanes_in_claim == chunk


async def test_a_lock_timeout_reports_which_population_aborted() -> None:
    """BACKLOG #1270 finding 2: the handler covers TWO populations, so it must not label them alike.

    The ``try`` that ends in the lock-timeout handler spans the claim batch AND the H2 skip-and-
    complete's in-store finalize DML. Both run under ``SET LOCK_TIMEOUT 0``, so a finalize row lock
    held by a concurrent finalizer raises 1222 into the SAME handler — and the first fix labelled it
    "the head CONTENDED", which is a different row in a different table.

    THE FIRST ASSERTION IS THE DISCRIMINATOR. Same stage, same lane, same lane count: the only
    difference is WHICH statement aborted. If the two produce identical output they are one case
    wearing two names, which is exactly what shipped."""
    lane = "lane-000"
    _o1, _s1, head = await _drive("outbound", 1, fail_batch=_lock_timeout_error())
    ops2, _s2, finalize = await _drive(
        "outbound",
        1,
        rows=[_row("r1", destination_name=lane)],
        h2_already_delivered=True,
        fail_h2_update=_lock_timeout_error(),
    )
    assert head != finalize, (
        "a contended queue HEAD and a contended FINALIZE row are reported identically — the two"
        " populations are one case wearing two names, and any label chosen is wrong for one of them"
    )
    assert head.lock_timeout is not None and head.lock_timeout.phase == "head"
    assert finalize.lock_timeout is not None and finalize.lock_timeout.phase == "finalize"
    # Non-vacuousness: the finalize arm really did get past the claim batch into the H2 DML.
    assert _op_kinds(ops2)[:3] == ["execute-batch", "execute-h2-probe", "execute-h2-update"]
    # The EMPTY-all contract is identical on both — only the REPORTING differs, never a row.
    assert head.by_lane == {} and head.rearm == frozenset()
    assert finalize.by_lane == {} and finalize.rearm == frozenset()


async def test_an_h2_probe_that_misses_is_never_labelled_finalize() -> None:
    """BACKLOG #1270 finding 2, the case its own test did not cover.

    THE DEFECT. ``abort_phase = ClaimAbortPhase.FINALIZE`` was assigned on ENTERING the H2 branch —
    before the ``delivered_keys`` probe, and therefore before it is known whether any finalize DML
    will run at all. The probe MISSES on the ordinary outbound path (the row has not been delivered
    yet, which is why it is being claimed), so no finalize statement executes; a 1222 raised by the
    claim's own COMMIT after that point was nevertheless reported as ``finalize``. The comment
    justifying the single assignment — "once finalize DML has run in it, the finalize row locks are
    held" — states a premise that is false on exactly this path.

    WHY THIS IS THE COMMON CASE, not a corner. Every outbound claim of a not-yet-delivered row takes
    it. The one shape the suite asserted, ``h2_already_delivered=True`` with a failing UPDATE, is the
    one shape that makes the label true — so a deploying site WOULD read "a contended finalize row"
    for a contended queue head, and go looking in the wrong table.

    THE WIRE OPS ARE THE EVIDENCE, not the label. Asserting ``phase == "head"`` alone would pass on
    a build that simply never set FINALIZE anywhere; requiring that the H2 branch WAS entered and
    that no finalize statement ran makes this discriminate the fix from its absence."""
    ops, _store, result = await _drive(
        "outbound",
        1,
        rows=[_row("r1", destination_name="OB_ACME")],
        h2_already_delivered=False,  # the probe MISSES -> the finalize DML is never reached
        first_commit_error=_lock_timeout_error(),
    )
    kinds = _op_kinds(ops)
    assert "execute-h2-probe" in kinds, (
        "non-vacuousness: the H2 branch must have been ENTERED (destination_name is set), or this"
        f" asserts nothing about where the label is assigned — got {kinds}"
    )
    assert "execute-h2-update" not in kinds, (
        f"no finalize DML may have run on a probe MISS — got {kinds}"
    )
    assert result.lock_timeout is not None, "the abort must still be reported"
    assert result.lock_timeout.phase == "head", (
        "a 1222 with no finalize statement in the transaction was labelled FINALIZE. The label is"
        " per-transaction by design — a later row's abort after an earlier row's finalize IS"
        " finalize — but here nothing was finalized at all, so the report names the wrong table."
    )
    # The EMPTY-all contract is untouched on this path too: reporting changed, no row moved.
    assert result.by_lane == {} and result.rearm == frozenset()


@pytest.mark.parametrize("fold", [False, True])
async def test_ac3_kept_ne_claimed_rolls_back_and_guard_runs(fold: bool) -> None:
    # A kept id with a NULL claimed twin — the fail-closed whole-call rollback signal. Even with
    # the fold ON (the folded reset DID execute server-side and survives the rollback,
    # session-scoped), the guard still runs: reset_committed ⇔ commit#1 returned, and a doubled
    # reset is idempotent.
    ops, store, result = await _drive("ingress", 2, fold=fold, rows=[_row("a1"), _null_twin("a2")])
    assert result == ClaimedHeads(by_lane={}, rearm=frozenset())
    kinds = _op_kinds(ops)
    assert "rollback" in kinds
    assert _guard_ran(ops)
    assert store.committed_txns == 1  # only the guard's commit — commit#1 never ran


@pytest.mark.parametrize("fold", [False, True])
async def test_ac3_commit1_failure_propagates_and_guard_runs(fold: bool) -> None:
    ops: _Ops = []
    store = _bare_store(fold=fold)
    cur = _FakeCursor(ops)
    conn = _FakeConn(ops, fail_first_commit=True)
    _wire(store, cur, conn)
    with pytest.raises(RuntimeError, match="injected commit#1 failure"):
        await store.claim_fifo_heads("ingress", ["lane-0"], now=_NOW)
    kinds = _op_kinds(ops)
    assert kinds == ["execute-batch", "commit-failed", "rollback", "execute-reset", "commit"]
    assert store.committed_txns == 1  # commit#1 raised before counting; the guard's commit counted


@pytest.mark.parametrize("fold", [False, True])
async def test_ac3_cancellation_at_body_await_no_rollback_guard_runs(fold: bool) -> None:
    # The ADR §2 nuance, frozen: CancelledError derives from BaseException, so the shipped
    # `except Exception` never catches it — NO rollback runs on this path; the guard still resets
    # and commits (possibly durably committing a claim that was never returned — recovered by
    # reset_stale_inflight; at-least-once preserved). The fold must not alter this path.
    ops: _Ops = []
    store = _bare_store(fold=fold)
    cur = _FakeCursor(ops, fail_batch=asyncio.CancelledError())
    conn = _FakeConn(ops)
    _wire(store, cur, conn)
    with pytest.raises(asyncio.CancelledError):
        await store.claim_fifo_heads("ingress", ["lane-0"], now=_NOW)
    kinds = _op_kinds(ops)
    assert "rollback" not in kinds, "no rollback on the cancellation path (shipped semantics)"
    assert kinds == ["execute-batch", "execute-reset", "commit"]


@pytest.mark.parametrize("fold", [False, True])
async def test_ac3_cancellation_during_finally_shield_completes_reset(fold: bool) -> None:
    # Cancel the awaiting task while the guard's own reset is in flight: the shielded task must
    # complete the SET + commit before the CancelledError is re-raised (B1 — no LOCK_TIMEOUT 0 or
    # mid-txn connection ever returns to the pool). fold=False exercises the clean exit; fold=True
    # forces the guard via a 1222 (the folded clean exit legitimately skips the guard, so the
    # cancellation-during-finally case only exists on its non-clean exits).
    ops: _Ops = []
    started = asyncio.Event()
    release = asyncio.Event()
    store = _bare_store(fold=fold)
    cur = _FakeCursor(
        ops,
        fail_batch=_lock_timeout_error() if fold else None,
        reset_started=started,
        reset_release=release,
    )
    conn = _FakeConn(ops)
    _wire(store, cur, conn)
    task = asyncio.ensure_future(store.claim_fifo_heads("ingress", ["lane-0"], now=_NOW))
    await asyncio.wait_for(started.wait(), timeout=5)  # the guard's reset has started
    task.cancel()
    await asyncio.sleep(0)  # let the cancellation land at the shield await
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)
    kinds = _op_kinds(ops)
    # The reset COMPLETED (its commit ran) despite the cancellation.
    expected = ["execute-batch", "rollback"] if fold else ["execute-batch", "commit"]
    assert kinds == [*expected, "execute-reset", "commit"]


# --- AC-3/§2: the guard's two swallow-and-log arms (a reset failure never masks the outcome) -----


async def test_guard_reset_failure_swallowed_on_clean_exit() -> None:
    # Swallow arm 1 (`except Exception`): the guard's own reset raising must not mask the clean
    # result — the claimed rows are still returned.
    ops, store, result = await _drive(
        "ingress", 1, fold=False, rows=[_row("r1")], fail_reset=RuntimeError("reset boom")
    )
    assert [i.id for items in result.by_lane.values() for i in items] == ["r1"]
    assert _op_kinds(ops) == ["execute-batch", "commit", "execute-reset"]  # reset died pre-commit


async def test_guard_reset_failure_swallowed_on_1222_exit() -> None:
    # Swallow arm 1 on the error path: the 1222 EMPTY-all contract survives a failing guard reset.
    ops, store, result = await _drive(
        "ingress",
        2,
        fold=False,
        fail_batch=_lock_timeout_error(),
        fail_reset=RuntimeError("reset boom"),
    )
    # BACKLOG #1270: EMPTY-all is unchanged; the ATTEMPT is now reported. A failing guard reset must
    # not cost that report either. Whole-object equality — see the AC-3 1222 test for why.
    assert result == ClaimedHeads(
        by_lane={},
        rearm=frozenset(),
        lock_timeout=ClaimLockTimeout(phase=ClaimAbortPhase.HEAD, lanes_in_claim=2),
    )
    assert _op_kinds(ops) == ["execute-batch", "rollback", "execute-reset"]


async def test_guard_reset_failure_after_cancellation_still_reraises() -> None:
    # Swallow arm 2 (`except Exception` inside the CancelledError arm): a reset failure after a
    # cancellation must not mask the CancelledError — shutdown still proceeds.
    ops: _Ops = []
    started = asyncio.Event()
    release = asyncio.Event()
    store = _bare_store(fold=False)
    cur = _FakeCursor(
        ops,
        reset_started=started,
        reset_release=release,
        fail_reset=RuntimeError("reset boom after cancel"),
    )
    conn = _FakeConn(ops)
    _wire(store, cur, conn)
    task = asyncio.ensure_future(store.claim_fifo_heads("ingress", ["lane-0"], now=_NOW))
    await asyncio.wait_for(started.wait(), timeout=5)
    task.cancel()
    await asyncio.sleep(0)
    release.set()  # the shielded reset now raises
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=5)
    assert _op_kinds(ops) == ["execute-batch", "commit", "execute-reset"]


# --- AC-5: the runtime guard on the fold's H2-noop premise ---------------------------------------


@pytest.mark.parametrize("stage", ["ingress", "routed"])
async def test_ac5_folded_stage_destination_row_raises_contract_violation(
    stage: str, caplog: pytest.LogCaptureFixture
) -> None:
    rows = [_row("r1", destination_name="OB_SNEAK")]
    ops: _Ops = []
    store = _bare_store(fold=True)
    cur = _FakeCursor(ops, rows=rows)
    conn = _FakeConn(ops)
    _wire(store, cur, conn)
    with (
        caplog.at_level(logging.ERROR, logger="messagefoundry.store.sqlserver"),
        pytest.raises(RuntimeError, match="fold contract violation"),
    ):
        await store.claim_fifo_heads(stage, ["lane-0"], now=_NOW)
    kinds = _op_kinds(ops)
    # Never entered the H2 DML branch; rolled back; the shielded guard reset the session.
    assert "execute-h2-probe" not in kinds
    assert "rollback" in kinds
    assert _guard_ran(ops)
    # AC-5: an ERROR log naming the row.
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert errors, "AC-5 requires an ERROR log naming the row"
    assert any("r1" in r.getMessage() and "contract violation" in r.getMessage() for r in errors)


async def test_ac5_fold_off_same_row_takes_shipped_h2_path() -> None:
    # Non-vacuousness control: with the fold OFF the identical row takes the shipped H2 path
    # (delivered_keys probe; not-yet-delivered rows are returned normally). The guard is
    # fold-scoped — shipped behavior is untouched.
    rows = [_row("r1", destination_name="OB_SNEAK")]
    ops, store, result = await _drive("ingress", 1, fold=False, rows=rows)
    kinds = _op_kinds(ops)
    assert "execute-h2-probe" in kinds
    assert sum(len(v) for v in result.by_lane.values()) == 1


async def test_ac5_fold_on_outbound_h2_path_unaffected() -> None:
    # At OUTBOUND the fold never applies (fold computes False), so H2 runs exactly as shipped
    # even with the flag ON.
    rows = [_row("r1", destination_name="OB_X")]
    ops, store, result = await _drive("outbound", 1, fold=True, rows=rows)
    kinds = _op_kinds(ops)
    assert "execute-h2-probe" in kinds
    assert kinds[-1] == "commit"  # guard ran (4-op shape asserted elsewhere)


# --- AC-4: code shape — the sole assignment site + the skip-only finally -------------------------


def _claim_fn_source() -> str:
    return textwrap.dedent(inspect.getsource(SqlServerStore.claim_fifo_heads))


def _claim_fn_ast() -> ast.AsyncFunctionDef:
    fn = ast.parse(_claim_fn_source()).body[0]
    assert isinstance(fn, ast.AsyncFunctionDef)
    return fn


def _guard_block_source() -> str:
    """The dedented `if not reset_committed:` block — extracted by indentation scan so the pinned
    hash covers code AND comments (ast strips comments)."""
    lines = _claim_fn_source().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "if not reset_committed:")
    indent = len(lines[start]) - len(lines[start].lstrip())
    seg = [lines[start]]
    for line in lines[start + 1 :]:
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        seg.append(line)
    return textwrap.dedent("\n".join(seg))


def test_ac4_reset_committed_sole_assignment_after_commit1() -> None:
    fn = _claim_fn_ast()
    assigns = [
        node
        for node in ast.walk(fn)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "reset_committed" for t in node.targets)
    ]
    assert len(assigns) == 2, "exactly the init (False) + the sole post-commit#1 site"
    values = {type(a.value).__name__ for a in assigns}
    assert values == {"Constant", "Name"}  # False init + `= fold`
    # The `= fold` assignment must be the statement IMMEDIATELY following `await self._commit(conn)`
    # (statement adjacency == no intervening await; no suspension point can land between commit
    # success and the flag).
    try_node = next(n for n in ast.walk(fn) if isinstance(n, ast.Try))
    body = try_node.body
    commit_idx = next(
        i
        for i, stmt in enumerate(body)
        if isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Await)
        and isinstance(stmt.value.value, ast.Call)
        and isinstance(stmt.value.value.func, ast.Attribute)
        and stmt.value.value.func.attr == "_commit"
    )
    nxt = body[commit_idx + 1]
    assert (
        isinstance(nxt, ast.Assign)
        and isinstance(nxt.targets[0], ast.Name)
        and nxt.targets[0].id == "reset_committed"
        and isinstance(nxt.value, ast.Name)
        and nxt.value.id == "fold"
    ), "reset_committed = fold must immediately follow commit#1's await"


def test_ac4_finally_is_exactly_the_skip_guard() -> None:
    fn = _claim_fn_ast()
    try_node = next(n for n in ast.walk(fn) if isinstance(n, ast.Try))
    assert len(try_node.finalbody) == 1
    guard_if = try_node.finalbody[0]
    assert isinstance(guard_if, ast.If) and not guard_if.orelse
    test = guard_if.test
    assert (
        isinstance(test, ast.UnaryOp)
        and isinstance(test.op, ast.Not)
        and isinstance(test.operand, ast.Name)
        and test.operand.id == "reset_committed"
    ), "the finally body must be exactly `if not reset_committed:` around the verbatim guard"
    # The guard body retains its shipped shield discipline — BOTH swallow-and-log arms included.
    guard_src = _guard_block_source()
    for sentinel in (
        "asyncio.ensure_future(_reset_lock_timeout())",
        "await asyncio.shield(reset)",
        "except Exception:",  # swallow arm 1: a reset failure must not mask the real outcome
        "except asyncio.CancelledError:",
        "await reset",  # the shield-completion wait
        "raise",
    ):
        assert sentinel in guard_src, f"guard body lost its shipped shield discipline: {sentinel}"


def test_ac4_guard_body_hash_pinned() -> None:
    # The byte-for-byte freeze (modulo the uniform dedent): ANY edit to the guard block — code or
    # its load-bearing comments — fails here and requires an ADR 0114 §2 design review.
    got = hashlib.sha256(_guard_block_source().encode()).hexdigest()
    assert got == _GUARD_BODY_SHA256, (
        "the shielded finally-guard's source changed; ADR 0114 §2 freezes it verbatim —"
        f" if this edit passed design review, re-pin to {got}"
    )


def test_ac4_review_anchor_sentinel_present() -> None:
    source = inspect.getsource(SqlServerStore.claim_fifo_heads)
    assert "ADR 0114 AC-4 review anchor" in source
    assert "ADR 0114 AC-4 sentinel: reset_committed's SOLE assignment site" in source


# --- sentinel positive control (complements AC-6's negative in test_adr0114_claim_flags) ---------


def test_sqlserver_reads_the_fold_flag() -> None:
    import messagefoundry.store.sqlserver as ss

    source = inspect.getsource(ss)
    assert "settings.fifo_claim_fold_reset" in source
    assert "_fifo_claim_fold_reset" in inspect.getsource(SqlServerStore.claim_fifo_heads)
