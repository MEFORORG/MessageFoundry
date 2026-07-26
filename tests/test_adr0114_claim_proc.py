"""ADR 0114 sub-lever A (``fifo_claim_proc``): the two lane-family versioned claim procedures.

Offline (no SQL Server; pyodbc never imported): the DDL is lint-checked as text, the startup gate
is driven through a stubbed ``_fetchone``, and the ``{CALL}`` dispatch through the recording fakes
of the sub-lever C suite. What this file freezes:

- **the dual-copy rule**: the proc bodies and the ad-hoc batch render from the SAME
  ``_fifo_heads_steps`` fragments (the DDL-vs-batch lint the ADR names) — the batch text is
  reconstructed independently and matched against what ``claim_fifo_heads`` actually executes, and
  each proc body is matched against its header + fragments + tail.
- **AC-8** proc-body hard rules: no ``BEGIN/COMMIT/ROLLBACK``, no ``TRY/CATCH``, no
  ``SET XACT_ABORT``; ``SET LOCK_TIMEOUT`` appears ONLY as the opener (0) and the conditional
  ``@fold_reset`` tail (-1), the tail is the final statement.
- **AC-7** startup gate: accept (whitespace-tolerant body hash), degrade on missing proc /
  hand-edited body / compat < 130 — each with a WARNING naming the reason, the degraded gauge set,
  and the claim staying on the batch path (never a lane outage).
- **AC-9** the proc result contract: column-identical 10-column result; the post-``execute`` code
  path (drain, kept==claimed adjudication, H2, commit, guard) is the SAME code — differential
  drive proc-vs-batch over identical fake rows yields identical results and identical
  post-execute wire ops.
- **AC-10** guarded DDL: both statements ride ``_SCHEMA`` (the ADR 0064 content hash) in the
  self-no-op'ing guarded ``EXEC(N'...')`` form (compat + CREATE-PROCEDURE permission +
  CREATE-OR-ALTER availability), so a flag-OFF open can never fail on proc DDL.
- **AC-11** lane-set encoding: one JSON parameter, hostile names round-trip, >256-char lane names
  are skipped client-side with a WARNING (no-match parity), request-order dedupe + the 500-lane
  chunk clamp are preserved.
- **AC-12** flagged-path semantics: in-proc 1222 reaches the same ``"(1222)"`` translation
  (EMPTY-all), kept≠claimed rolls the whole call back, the H1 fence rides the fixed nullable
  parameter pair (None/None = fence off) at fixed arity 9.

Deferred to the env-gated live legs (test_adr0114_claim_proc_live.py) — what only a real server
can show: the ``@@TRANCOUNT`` entry==exit probe, the live differential run, the fenced-ex-leader
claims-zero leg (AC-12), the oversized-lane no-match parity leg (AC-11), and the tamper-degrade
leg. Deferred further to the ADR §8 bench battery / live infrastructure: G-A0 plan-shape checks,
the describe-traffic trace, and AC-10's two live open() scenarios (a compat-120 database; a
CREATE-PROCEDURE-or-schema-ALTER-denied principal) — the guarded-DDL TEXT for both is frozen
here, the live no-op behavior needs a purpose-configured server.
"""

from __future__ import annotations

import inspect
import json
import logging
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import sqlserver as ss
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import ClaimedHeads
from tests.test_adr0114_claim_fold import (
    _NOW,
    _bare_store,
    _FakeConn,
    _FakeCursor,
    _lock_timeout_error,
    _null_twin,
    _op_kinds,
    _Ops,
    _row,
    _wire,
)

_CALL_CID = "{CALL dbo.mefor_claim_fifo_heads_cid_v1 (?,?,?,?,?,?,?,?,?)}"
_CALL_DST = "{CALL dbo.mefor_claim_fifo_heads_dst_v1 (?,?,?,?,?,?,?,?,?)}"

_FAKE_PINS = [(1, 0, 0)] * 9  # stands in for _claim_proc_param_pins() (pyodbc-free CI)


def _proc_store(
    *,
    proc: bool = True,
    effective: bool = True,
    fold: bool = False,
    epoch: bool = False,
    pins: list[tuple[int, int, int]] | None = None,
) -> SqlServerStore:
    store = _bare_store(fold=fold, epoch=epoch)
    store._fifo_claim_proc = proc
    store._claim_proc_effective = effective
    store._claim_proc_input_sizes = pins
    return store


async def _drive_proc(
    stage: str,
    lanes: list[str],
    *,
    store: SqlServerStore | None = None,
    rows: list[tuple[Any, ...]] | None = None,
    fail_batch: BaseException | None = None,
    per_lane_limit: int = 1,
) -> tuple[_Ops, SqlServerStore, ClaimedHeads]:
    ops: _Ops = []
    store = store if store is not None else _proc_store()
    cur = _FakeCursor(ops, rows=rows, fail_batch=fail_batch)
    conn = _FakeConn(ops)
    _wire(store, cur, conn)
    result = await store.claim_fifo_heads(stage, lanes, now=_NOW, per_lane_limit=per_lane_limit)
    return ops, store, result


# --- the dual-copy rule: DDL-vs-batch lint (both render from _fifo_heads_steps) ------------------


async def test_lint_batch_renders_from_the_shared_fragments() -> None:
    # Reconstruct the batch text independently from the fragments and match it against what
    # claim_fifo_heads actually executes (via the C suite's golden-pinned drive) — statement-
    # sequence identity between the shared render and the shipped batch.
    expected = (
        "SET NOCOUNT ON;"
        " SET LOCK_TIMEOUT 0;"
        " DECLARE @now FLOAT = ?, @stage NVARCHAR(16) = ?, @k INT = ?,"
        " @pending NVARCHAR(32) = ?, @inflight NVARCHAR(32) = ?;"
        + ss._fifo_heads_steps(lane_col="channel_id", lane_source="(VALUES (?))", epoch_guard="")
    )
    ops: _Ops = []
    store = _bare_store()
    cur = _FakeCursor(ops)
    conn = _FakeConn(ops)
    _wire(store, cur, conn)
    result = await store.claim_fifo_heads("ingress", ["lane-0"], now=_NOW)
    assert result == ClaimedHeads(by_lane={}, rearm=frozenset())
    assert ops[0][1] == expected


@pytest.mark.parametrize(
    ("proc_name", "lane_col"),
    [
        ("mefor_claim_fifo_heads_cid_v1", "channel_id"),
        ("mefor_claim_fifo_heads_dst_v1", "destination_name"),
    ],
)
def test_lint_proc_body_is_header_plus_fragments_plus_tail(proc_name: str, lane_col: str) -> None:
    body = ss._claim_proc_body(proc_name, lane_col)
    expected = (
        f"CREATE OR ALTER PROCEDURE dbo.{proc_name}"
        " @now FLOAT, @stage NVARCHAR(16), @k INT,"
        " @pending NVARCHAR(32), @inflight NVARCHAR(32),"
        " @lanes NVARCHAR(MAX),"
        " @lease_key NVARCHAR(256) = NULL,"
        " @leader_epoch BIGINT = NULL,"
        " @fold_reset BIT = 0"
        " AS"
        " SET NOCOUNT ON;"
        " SET LOCK_TIMEOUT 0;"
        + ss._fifo_heads_steps(
            lane_col=lane_col,
            lane_source=ss._CLAIM_PROC_LANE_SOURCE,
            epoch_guard=ss._CLAIM_PROC_EPOCH_GUARD,
        )
        + " IF @fold_reset = 1 SET LOCK_TIMEOUT -1;"
    )
    assert body == expected


def test_lint_lane_col_appears_at_exactly_the_two_predicate_sites() -> None:
    cid = ss._claim_proc_body("mefor_claim_fifo_heads_cid_v1", "channel_id")
    dst = ss._claim_proc_body("mefor_claim_fifo_heads_dst_v1", "destination_name")
    for body, col in ((cid, "channel_id"), (dst, "destination_name")):
        assert f"AND {col} = l.lane" in body  # STEP-1 discovery predicate
        assert f"qq.{col} = L.lane" in body  # STEP-3 probe predicate
    # The OTHER family's lane column never appears at a predicate site (the @claimed table's
    # column list legitimately names both).
    assert "qq.destination_name" not in cid
    assert "qq.channel_id" not in dst
    assert "AND destination_name = l.lane" not in cid
    assert "AND channel_id = l.lane" not in dst


def test_lint_epoch_guard_fixed_nullable_on_both_sites() -> None:
    body = ss._claim_proc_body("mefor_claim_fifo_heads_cid_v1", "channel_id")
    assert body.count(ss._CLAIM_PROC_EPOCH_GUARD) == 2  # STEP-3 probe AND STEP-5 UPDATE
    assert "@leader_epoch IS NULL OR" in ss._CLAIM_PROC_EPOCH_GUARD


def test_ac8_proc_body_hard_rules() -> None:
    for proc_name, lane_col in (
        ("mefor_claim_fifo_heads_cid_v1", "channel_id"),
        ("mefor_claim_fifo_heads_dst_v1", "destination_name"),
    ):
        body = ss._claim_proc_body(proc_name, lane_col)
        upper = body.upper()
        # No transaction statements (the proc runs inside the client's autocommit=False txn),
        # no TRY/CATCH (an attention signal must abort exactly like the batch), no XACT_ABORT.
        for forbidden in (
            "BEGIN TRAN",
            "COMMIT",
            "ROLLBACK",
            "BEGIN TRY",
            "BEGIN CATCH",
            "XACT_ABORT",
        ):
            assert forbidden not in upper, f"{proc_name}: forbidden token {forbidden}"
        # SET LOCK_TIMEOUT appears ONLY as the opener (0) and the conditional fold tail (-1).
        assert upper.count("SET LOCK_TIMEOUT") == 2
        assert " SET LOCK_TIMEOUT 0;" in body
        assert body.endswith(" IF @fold_reset = 1 SET LOCK_TIMEOUT -1;")
        # No single quotes in the body: the EXEC(N'...') embedding and OBJECT_DEFINITION hash
        # comparison stay exact (the escaping in _claim_proc_ddl is defensive, not load-bearing).
        assert "'" not in body


def test_ac10_guarded_ddl_rides_schema() -> None:
    cid_ddl = ss._claim_proc_ddl("mefor_claim_fifo_heads_cid_v1", "channel_id")
    dst_ddl = ss._claim_proc_ddl("mefor_claim_fifo_heads_dst_v1", "destination_name")
    assert cid_ddl in ss._SCHEMA and dst_ddl in ss._SCHEMA  # rides the ADR 0064 content hash
    for ddl in (cid_ddl, dst_ddl):
        # Self-no-op'ing guard: compat floor + CREATE PROCEDURE permission + CREATE OR ALTER
        # availability (2016 SP1 on-prem; EngineEdition >= 5 = the Azure family), then dynamic
        # EXEC (defers the OPENJSON parse below compat 130; satisfies the batch-initial rule).
        assert ddl.startswith(
            "IF (SELECT compatibility_level FROM sys.databases WHERE name = DB_NAME()) >= 130"
        )
        assert "HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CREATE PROCEDURE') = 1" in ddl
        assert "HAS_PERMS_BY_NAME('dbo', 'SCHEMA', 'ALTER') = 1" in ddl
        assert "SERVERPROPERTY('EngineEdition')" in ddl
        assert "13.0.4001".replace(".", "") or True  # documentation anchor; version parse below
        assert "PARSENAME" in ddl and "4001" in ddl
        assert " EXEC(N'" in ddl and ddl.endswith("')")
    # The guarded DDL statements are the LAST two _SCHEMA entries (tables/indexes first — the proc
    # bodies reference queue/leader_lease by deferred name resolution, but keeping them last makes
    # the reading order honest).
    assert ss._SCHEMA[-2:] == [cid_ddl, dst_ddl]


# --- AC-7: the startup gate (stubbed _fetchone; no server) ---------------------------------------


def _gate_rows(
    *,
    compat: int = 150,
    cid_body: str | None = "SHIPPED",
    dst_body: str | None = "SHIPPED",
) -> dict[str, dict[str, Any] | None]:
    """Build the _fetchone stub's answers. "SHIPPED" resolves to the real shipped body text."""
    if cid_body == "SHIPPED":
        cid_body = ss._claim_proc_body("mefor_claim_fifo_heads_cid_v1", "channel_id")
    if dst_body == "SHIPPED":
        dst_body = ss._claim_proc_body("mefor_claim_fifo_heads_dst_v1", "destination_name")
    return {
        "compat": {"compatibility_level": compat},
        "dbo.mefor_claim_fifo_heads_cid_v1": {"body": cid_body},
        "dbo.mefor_claim_fifo_heads_dst_v1": {"body": dst_body},
    }


def _stub_fetchone(store: SqlServerStore, answers: dict[str, dict[str, Any] | None]) -> None:
    # The stub pins the EXACT probe SQL (not substrings): a typo'd probe would KeyError here
    # rather than silently matching.
    async def fake_fetchone(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        if sql == "SELECT compatibility_level FROM sys.databases WHERE name = DB_NAME()":
            return answers["compat"]
        assert sql == "SELECT OBJECT_DEFINITION(OBJECT_ID(?)) AS body", f"unexpected probe: {sql}"
        return answers[params[0]]

    store._fetchone = fake_fetchone  # type: ignore[method-assign]


async def _gate(
    answers: dict[str, dict[str, Any] | None],
    monkeypatch: pytest.MonkeyPatch,
    *,
    fold: bool = False,
) -> SqlServerStore:
    store = _proc_store(effective=False, fold=fold, pins=None)
    _stub_fetchone(store, answers)
    # _claim_proc_param_pins imports pyodbc (absent in CI) — substitute the fake pins.
    monkeypatch.setattr(ss, "_claim_proc_param_pins", lambda: _FAKE_PINS)
    await store._gate_claim_proc()
    return store


async def test_ac7_gate_accepts_shipped_bodies(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="messagefoundry.store.sqlserver"):
        store = await _gate(_gate_rows(), monkeypatch)
    assert store.claim_proc_effective is True
    assert store.claim_proc_degraded_reason is None
    assert store._claim_proc_input_sizes == _FAKE_PINS
    assert any("startup gate PASSED" in r.getMessage() for r in caplog.records)


async def test_ac7_gate_tolerates_whitespace_differences(monkeypatch: pytest.MonkeyPatch) -> None:
    # OBJECT_DEFINITION may differ in line endings / whitespace across deployment paths — the
    # comparison is over the NORMALIZED text (ADR §4 "normalized").
    shipped = ss._claim_proc_body("mefor_claim_fifo_heads_cid_v1", "channel_id")
    mangled = shipped.replace(" SET LOCK_TIMEOUT 0;", "\r\n  SET  LOCK_TIMEOUT   0;\n")
    store = await _gate(_gate_rows(cid_body=mangled), monkeypatch)
    assert store.claim_proc_effective is True


@pytest.mark.parametrize(
    ("answers_kw", "reason_fragment"),
    [
        ({"cid_body": None}, "is missing"),
        ({"dst_body": None}, "is missing"),
        (
            {
                "cid_body": "CREATE OR ALTER PROCEDURE dbo.mefor_claim_fifo_heads_cid_v1 AS SELECT 1;"
            },
            "does not match the shipped definition",
        ),
        ({"compat": 120}, "compatibility_level 120 < 130"),
    ],
)
async def test_ac7_gate_degrades_loudly(
    answers_kw: dict[str, Any],
    reason_fragment: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.sqlserver"):
        store = await _gate(_gate_rows(**answers_kw), monkeypatch)
    assert store.claim_proc_effective is False
    assert store.claim_proc_degraded_reason is not None
    assert reason_fragment in store.claim_proc_degraded_reason
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("DEGRADED to the shipped ad-hoc batch" in r.getMessage() for r in warnings)
    # Degraded => the claim stays on the batch path (never a lane outage).
    ops, _, _ = await _drive_proc("ingress", ["lane-0"], store=store)
    assert ops[0][1].startswith("SET NOCOUNT ON;")


async def test_ac7_no_error_2812_handling_on_the_hot_path() -> None:
    # The hot path carries no missing-proc (error 2812) handling: the gate decides at open, the
    # claim never falls back mid-flight.
    source = inspect.getsource(SqlServerStore.claim_fifo_heads)
    assert "2812" not in source


async def test_ac7_gate_probe_failure_degrades_never_fails_open(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # §4's rule is total: ANY gate failure — including a raising probe — degrades loudly to the
    # batch; it never propagates into open() (which would be a startup outage the ADR forbids).
    store = _proc_store(effective=False, pins=None)

    async def boom(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        raise RuntimeError("transient metadata read failure")

    store._fetchone = boom  # type: ignore[method-assign]
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.sqlserver"):
        await store._gate_claim_proc()  # must NOT raise
    assert store.claim_proc_effective is False
    assert store.claim_proc_degraded_reason is not None
    assert "startup-gate probe failed" in store.claim_proc_degraded_reason


def test_ac9_no_proc_branch_after_execute() -> None:
    # AC-9's structural half: everything after cur.execute is the SAME code on both paths — the
    # method must not branch on use_proc after the execute statement (the setinputsizes pin is
    # legitimately before it).
    source = inspect.getsource(SqlServerStore.claim_fifo_heads)
    execute_at = source.index("await cur.execute(sql, args)")
    assert "use_proc" not in source[execute_at:], (
        "AC-9: no use_proc-conditional code may exist after the execute — the drain,"
        " adjudication, H2, commit, and guard are one shared path"
    )


# Golden pins for the two proc BODIES (the OBJECT_DEFINITION-comparable text): any drift in the
# shared fragments, the OPENJSON lane source, the fixed-nullable epoch guard, the signature, or
# the @fold_reset tail fails here and must be a reviewed, deliberate change (re-pin + the ADR 0064
# hash re-applies the DDL; the startup gate's expected hashes follow automatically).
_GOLDEN_PROC_BODY_SHA256 = {
    "mefor_claim_fifo_heads_cid_v1": "9c685181b413be4936746312745f3c8e43830d7dc22e6ab2cfc8ba9443bb43e2",
    "mefor_claim_fifo_heads_dst_v1": "0eaf2de29ae5ca09764bdabd2d3c40bca7c7feef8f347e6bab0800e5a3a97052",
}


@pytest.mark.parametrize(
    ("proc_name", "lane_col"),
    [
        ("mefor_claim_fifo_heads_cid_v1", "channel_id"),
        ("mefor_claim_fifo_heads_dst_v1", "destination_name"),
    ],
)
def test_proc_body_golden_pin(proc_name: str, lane_col: str) -> None:
    import hashlib

    got = hashlib.sha256(ss._claim_proc_body(proc_name, lane_col).encode()).hexdigest()
    assert got == _GOLDEN_PROC_BODY_SHA256[proc_name], (
        f"the shipped {proc_name} body drifted — if this change passed design review (the batch"
        f" and the proc bodies are edited together, forever), re-pin to {got}"
    )


# --- the {CALL} dispatch: fixed arity, lane JSON, fence, fold composition ------------------------


@pytest.mark.parametrize(
    ("stage", "call_text"),
    [
        ("ingress", _CALL_CID),
        ("routed", _CALL_CID),
        ("response", _CALL_CID),
        ("outbound", _CALL_DST),
    ],
)
async def test_call_text_per_lane_family(stage: str, call_text: str) -> None:
    ops, _, _ = await _drive_proc(stage, ["lane-0"])
    assert ops[0][1] == call_text


@pytest.mark.parametrize("n_lanes", [1, 4, 64])
@pytest.mark.parametrize("epoch", [False, True])
async def test_fixed_arity_nine_at_every_lane_count(n_lanes: int, epoch: bool) -> None:
    store = _proc_store(epoch=epoch)
    lanes = [f"lane-{i:03d}" for i in range(n_lanes)]
    ops, _, _ = await _drive_proc("ingress", lanes, store=store, per_lane_limit=2)
    params = ops[0][2]
    assert len(params) == 9
    assert params[0] == _NOW and params[1] == "ingress" and params[2] == 2
    assert params[3] == "pending" and params[4] == "inflight"
    assert json.loads(params[5]) == lanes  # request order preserved
    if epoch:
        assert params[6] == "lease-key-golden" and params[7] == 7
    else:
        assert params[6] is None and params[7] is None  # fence off = NULL pair (fixed arity)
    assert params[8] == 0  # fold flag OFF


@pytest.mark.parametrize(
    ("stage", "fold", "expected_fold_reset"),
    [
        ("ingress", True, 1),
        ("routed", True, 1),
        ("outbound", True, 0),  # OUTBOUND/RESPONSE never set @fold_reset
        ("response", True, 0),
        ("ingress", False, 0),
    ],
)
async def test_fold_reset_composition(stage: str, fold: bool, expected_fold_reset: int) -> None:
    ops, _, _ = await _drive_proc(stage, ["lane-0"], store=_proc_store(fold=fold))
    assert ops[0][2][8] == expected_fold_reset


async def test_proc_clean_path_wire_ops_fold_off_and_on() -> None:
    # fold OFF: the reset is NOT folded — the shielded guard still does its 2 wire ops.
    ops, store, _ = await _drive_proc("ingress", ["lane-0"], store=_proc_store(fold=False))
    assert _op_kinds(ops) == ["execute-batch", "commit", "execute-reset", "commit"]
    assert store.committed_txns == 2
    # fold ON at a folded stage: @fold_reset=1 rides the proc; commit#1 covers the reset; guard
    # skipped — 2 wire ops, one counted commit (the A1 shift, same as the batch fold).
    ops, store, _ = await _drive_proc("ingress", ["lane-0"], store=_proc_store(fold=True))
    assert _op_kinds(ops) == ["execute-batch", "commit"]
    assert store.committed_txns == 1


class _PyodbcImpl:
    """The underlying pyodbc cursor surface: SYNC setinputsizes (pure client-side state)."""

    def __init__(self) -> None:
        self.pins: list[Any] = []

    def setinputsizes(self, sizes: Any) -> None:
        self.pins.append(sizes)


class _AioodbcShapedCursor(_FakeCursor):
    """Mirrors the PINNED aioodbc 0.5.0 cursor shape (the adversarial-review finding): an
    ``async def setinputsizes`` wrapper (cursor.py:148 — calling it synchronously creates a
    never-awaited coroutine and applies NOTHING) over a sync pyodbc ``_impl``."""

    def __init__(self, ops: _Ops, **kwargs: Any) -> None:
        super().__init__(ops, **kwargs)
        self._impl = _PyodbcImpl()
        self.wrapper_calls = 0

    async def setinputsizes(self, sizes: Any = None) -> None:  # pragma: no cover - must not run
        self.wrapper_calls += 1


async def test_setinputsizes_pins_via_impl_on_the_aioodbc_shape() -> None:
    # THE production stack: the pins must land on the sync pyodbc _impl, and the async wrapper
    # must never be touched (a sync call on it would silently create a dead coroutine).
    ops: _Ops = []
    store = _proc_store(pins=_FAKE_PINS)
    cur = _AioodbcShapedCursor(ops)
    conn = _FakeConn(ops)
    _wire(store, cur, conn)
    await store.claim_fifo_heads("ingress", ["lane-0"], now=_NOW)
    assert cur._impl.pins == [_FAKE_PINS]
    assert cur.wrapper_calls == 0, "the async aioodbc wrapper must never be called synchronously"
    assert ops[0][1] == _CALL_CID


async def test_setinputsizes_direct_sync_surface_used_without_impl() -> None:
    # A bare pyodbc-like cursor (sync setinputsizes, no _impl): used directly, before execute.
    calls: list[Any] = []

    class _PinningCursor(_FakeCursor):
        def setinputsizes(self, sizes: Any) -> None:
            calls.append(("pin", sizes, len(self.ops)))  # len(ops) == executes seen so far

    ops: _Ops = []
    store = _proc_store(pins=_FAKE_PINS)
    cur = _PinningCursor(ops)
    conn = _FakeConn(ops)
    _wire(store, cur, conn)
    await store.claim_fifo_heads("ingress", ["lane-0"], now=_NOW)
    assert calls and calls[0][1] == _FAKE_PINS
    assert calls[0][2] == 0, "setinputsizes must be applied BEFORE the CALL executes"


async def test_setinputsizes_async_only_surface_warns_once_and_proceeds(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # An async-only setinputsizes with NO _impl (a hypothetical wrapper): the coroutine function
    # is rejected (never called sync), one WARNING, the claim proceeds unpinned.
    class _AsyncOnlyCursor(_FakeCursor):
        async def setinputsizes(self, sizes: Any = None) -> None:  # pragma: no cover
            raise AssertionError("must never be invoked")

    store = _proc_store(pins=_FAKE_PINS)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.sqlserver"):
        for _ in range(2):
            ops: _Ops = []
            cur = _AsyncOnlyCursor(ops)
            conn = _FakeConn(ops)
            _wire(store, cur, conn)
            await store.claim_fifo_heads("ingress", ["lane-0"], now=_NOW)
            assert ops[0][1] == _CALL_CID
    warnings = [r for r in caplog.records if "no synchronous setinputsizes" in r.getMessage()]
    assert len(warnings) == 1


async def test_setinputsizes_unreachable_warns_once_and_proceeds(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Neither the cursor nor an _impl exposes setinputsizes: warn ONCE, never fail the claim.
    store = _proc_store(pins=_FAKE_PINS)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.sqlserver"):
        ops1, _, _ = await _drive_proc("ingress", ["lane-0"], store=store)
        ops2, _, _ = await _drive_proc("ingress", ["lane-0"], store=store)
    assert ops1[0][1] == _CALL_CID and ops2[0][1] == _CALL_CID
    warnings = [r for r in caplog.records if "no synchronous setinputsizes" in r.getMessage()]
    assert len(warnings) == 1


async def test_batch_path_never_touches_setinputsizes() -> None:
    calls: list[Any] = []

    class _PinningCursor(_FakeCursor):
        def setinputsizes(self, sizes: Any) -> None:  # pragma: no cover - must not be called
            calls.append(sizes)

    ops: _Ops = []
    store = _proc_store(proc=False, effective=False, pins=_FAKE_PINS)
    cur = _PinningCursor(ops)
    conn = _FakeConn(ops)
    _wire(store, cur, conn)
    await store.claim_fifo_heads("ingress", ["lane-0"], now=_NOW)
    assert not calls


# --- AC-11: lane-set encoding ---------------------------------------------------------------------


async def test_ac11_hostile_lane_names_round_trip() -> None:
    hostile = [
        'lane "with" quotes',
        "lane,with,commas",
        "lane]with[brackets{and}braces",
        "lane\\with\\backslashes",
        "lane\twith\ncontrol",
        "läne-ünïcode-⚕",
        "a" * 256,  # the exact NVARCHAR(256) maximum survives
    ]
    ops, _, _ = await _drive_proc("ingress", hostile)
    assert json.loads(ops[0][2][5]) == hostile


async def test_ac11_oversized_lane_skipped_with_warning(caplog: pytest.LogCaptureFixture) -> None:
    lanes = ["ok-lane", "x" * 257, "another-ok"]
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.sqlserver"):
        ops, _, result = await _drive_proc("ingress", lanes)
    assert json.loads(ops[0][2][5]) == ["ok-lane", "another-ok"]  # no-match parity, loudly
    assert any("257-UTF-16-unit requested lane name" in r.getMessage() for r in caplog.records)
    assert result == ClaimedHeads(by_lane={}, rearm=frozenset())


async def test_ac11_oversized_measured_in_utf16_units_not_code_points(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # NVARCHAR capacity is UTF-16 CODE UNITS: 200 astral characters are 200 Python code points
    # but 400 units — the server-side CAST would silently right-truncate at 256 units (possibly
    # mid-surrogate) and the truncated prefix could match a REAL lane (the §4 shard-safety
    # hazard). The skip must therefore measure units, not len().
    astral = "\U0001f3e5" * 200  # 200 code points, 400 UTF-16 units
    exactly_256_units = "\U0001f3e5" * 128  # 128 code points, exactly 256 units — survives
    over_by_one_pair = "\U0001f3e5" * 129  # 258 units — skipped
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.sqlserver"):
        ops, _, _ = await _drive_proc(
            "ingress", ["ok-lane", astral, exactly_256_units, over_by_one_pair]
        )
    assert json.loads(ops[0][2][5]) == ["ok-lane", exactly_256_units]
    skipped = [r for r in caplog.records if "UTF-16-unit requested lane name" in r.getMessage()]
    assert len(skipped) == 2  # the 400-unit and the 258-unit names, loudly


async def test_ac11_dedupe_and_chunk_clamp_preserved() -> None:
    # Request-order dedupe + the 500-lane chunk clamp happen BEFORE the encode (client-side,
    # unchanged from the batch path).
    lanes = ["b", "a", "b", "c"] + [f"bulk-{i:04d}" for i in range(600)]
    ops, _, _ = await _drive_proc("ingress", lanes)
    encoded = json.loads(ops[0][2][5])
    assert encoded[:3] == ["b", "a", "c"]
    assert len(encoded) == 500  # _FIFO_HEADS_LANE_CHUNK


# --- AC-9 / AC-12: same post-execute code, same failure translations ------------------------------


async def test_ac9_differential_proc_vs_batch_identical_results_and_post_execute_ops() -> None:
    rows = [
        _row("r1", message_id="m1", channel_id="IB_A"),
        _row("r2", message_id="m2", channel_id="IB_A"),
        _row("r3", message_id="m3", channel_id="IB_B"),
    ]
    proc_ops, _, proc_result = await _drive_proc("ingress", ["IB_A", "IB_B"], rows=rows)
    batch_ops, _, batch_result = await _drive_proc(
        "ingress", ["IB_A", "IB_B"], store=_proc_store(proc=False, effective=False), rows=rows
    )
    assert proc_result == batch_result
    # Identical post-execute wire behavior (everything after op 0 is the same code path).
    assert _op_kinds(proc_ops)[1:] == _op_kinds(batch_ops)[1:]


async def test_ac12_in_proc_1222_translates_to_empty_all() -> None:
    ops, store, result = await _drive_proc("ingress", ["lane-0"], fail_batch=_lock_timeout_error())
    assert ops[0][1] == _CALL_CID  # the failure came from the CALL
    assert result == ClaimedHeads(by_lane={}, rearm=frozenset())
    kinds = _op_kinds(ops)
    assert "rollback" in kinds and kinds[-1] == "commit"  # guard ran


async def test_ac12_kept_ne_claimed_rolls_back_on_the_proc_path() -> None:
    ops, _, result = await _drive_proc("ingress", ["lane-0"], rows=[_row("a1"), _null_twin("a2")])
    assert result == ClaimedHeads(by_lane={}, rearm=frozenset())
    assert "rollback" in _op_kinds(ops)


async def test_ac5_runtime_guard_active_on_the_proc_path() -> None:
    # The AC-5 H2-noop runtime guard binds sub-lever A's @fold_reset composition too (§4): a
    # destination-bearing row at a folded stage is a contract violation on EITHER path.
    with pytest.raises(RuntimeError, match="fold contract violation"):
        await _drive_proc(
            "ingress",
            ["lane-0"],
            store=_proc_store(fold=True),
            rows=[_row("r1", destination_name="OB_SNEAK")],
        )


# --- wiring: __init__ snapshot + flag-off inertness ----------------------------------------------


@pytest.mark.parametrize("flag", [False, True])
def test_init_snapshots_the_proc_flag(flag: bool) -> None:
    store = SqlServerStore(object(), StoreSettings(fifo_claim_proc=flag, command_timeout=30))
    assert store._fifo_claim_proc is flag
    # The flag alone is never sufficient: the gate must pass first (open() runs it).
    assert store.claim_proc_effective is False


async def test_flag_on_but_gate_not_run_stays_on_the_batch() -> None:
    store = SqlServerStore(object(), StoreSettings(fifo_claim_proc=True, command_timeout=30))
    ops: _Ops = []
    cur = _FakeCursor(ops)
    conn = _FakeConn(ops)
    _wire(store, cur, conn)
    await store.claim_fifo_heads("ingress", ["lane-0"], now=_NOW)
    assert ops[0][1].startswith("SET NOCOUNT ON;")  # batch, not CALL


def test_sqlserver_reads_the_proc_flag() -> None:
    source = inspect.getsource(ss)
    assert "settings.fifo_claim_proc" in source
