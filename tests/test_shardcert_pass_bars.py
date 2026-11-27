# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The co-located shard-certification pass bars and store reset fail closed (BACKLOG #5575, #5576).

Unit tests over synthetic counters and a fake store: no load run, no database.
"""

from __future__ import annotations

import dataclasses
import textwrap
import types
from pathlib import Path
from typing import Any

import pytest

from harness.config.shardcert._shape import (
    BROADCAST,
    destinations_for_seq,
    fifo_lane,
    fifo_lane_destination,
)
from harness.load import shardcert
from harness.load.failover_track import FailoverTracker
from harness.load.shardcert import ShardCertReport, ShardCertStepRecord, StoreResetFailed


def _report(**over: object) -> ShardCertReport:
    """A healthy broadcast fan-out report: 1000 ACKed messages, D = 8, every copy arrived."""
    base: dict[str, object] = {
        "shards": ("s1", "s2"),
        "owned": {"s1": ["OB_1"], "s2": ["OB_2"]},
        "killed_shard": None,
        "sent": 1000,
        "acked": 1000,
        "delivered_distinct": 1000,
        "sink_received": 8000,
        "acked_not_delivered": 0,
        "lane_inversions": 0,
        "lanes_observed": 16,
        "lane_repeats": 0,
        "engine_done": 9000,
        "engine_dead": 0,
        "in_pipeline_final": 0,
        "drained": True,
        "drain_seconds": 2.0,
        "stranded_nonterminal": 0,
        "queue_breakdown": "",
        "offered": 1000,
        "achieved_intake": 1000,
        "dests": 8,
        "handlers": 8,
        "delivering": 8,
        "acked_copies_missing": 0,
        "dead_total": 0,
    }
    base.update(over)
    return ShardCertReport(**base)  # type: ignore[arg-type]


def test_healthy_fanout_report_passes() -> None:
    rep = _report()
    assert rep.copies_ok is True
    assert rep.ok is True
    assert ShardCertStepRecord.from_report(16.0, rep).no_loss is True


def test_fanout_run_that_lost_most_copies_fails() -> None:
    """BACKLOG #5575: one copy of each message reached a sink, so `acked_not_delivered` is 0, but 7 of the
    8 copies per message were lost. The old bars certified this PASS."""
    tracker = FailoverTracker()
    for seq in range(1000):
        tracker.on_ack(seq)
        tracker.on_delivery(fifo_lane("s1", 0), seq)  # only destination 0 ever arrives
    missing = tracker.acked_copies_missing(
        lambda seq: destinations_for_seq(seq, routing=BROADCAST, dests=8, fanout=8),
        fifo_lane_destination,
    )
    assert tracker.acked_not_delivered() == 0
    assert missing == 7000
    rep = _report(sink_received=1000, acked_copies_missing=missing)
    assert rep.acked_not_delivered == 0
    assert rep.copies_ok is False
    assert rep.ok is False
    assert ShardCertStepRecord.from_report(16.0, rep).no_loss is False
    assert "LOSS" in rep.render()
    assert rep.to_json_dict()["correctness"]["acked_copies_missing"] == 7000  # type: ignore[index]


@pytest.mark.parametrize(
    "over",
    [
        {"acked_copies_missing": -1},  # not measured
        {"delivering": -1},  # fan-out unknown
        {"delivering": 0},
    ],
)
def test_unmeasured_copy_check_fails_closed(over: dict[str, int]) -> None:
    rep = _report(**over)
    assert rep.copies_ok is False
    assert rep.ok is False
    assert ShardCertStepRecord.from_report(16.0, rep).no_loss is False


def test_report_default_is_unmeasured() -> None:
    """A caller that never supplies the copy count gets a FAIL, never a silent PASS."""
    fields = {k: v for k, v in _report().__dict__.items() if k != "acked_copies_missing"}
    rep = ShardCertReport(**fields)
    assert rep.acked_copies_missing == -1
    assert rep.ok is False


# --- BACKLOG #5576: _reset_store fails closed ---------------------------------------------------------


class _FakeCursor:
    def __init__(self, *, fail_on: str | None, leftover: dict[str, int]) -> None:
        self.fail_on = fail_on
        self.leftover = leftover
        self.executed: list[str] = []
        self._last: str = ""

    async def execute(self, sql: str) -> None:
        self.executed.append(sql)
        self._last = sql
        if self.fail_on is not None and "DELETE" in sql and f"FROM {self.fail_on}" in sql:
            raise RuntimeError("synthetic driver error")

    async def fetchall(self) -> list[tuple[str]]:
        """The verify query's result: the tables still holding rows, the ones it names."""
        return [(t,) for t, n in self.leftover.items() if n and f"FROM {t})" in self._last]


class _FakeConn:
    def __init__(self, cur: _FakeCursor) -> None:
        self.cur = cur
        self.commits = 0

    async def cursor(self) -> _FakeCursor:
        return self.cur

    async def commit(self) -> None:
        self.commits += 1

    async def __aenter__(self) -> _FakeConn:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None


class _FakeStore:
    def __init__(self, conn: _FakeConn) -> None:
        self._pool = types.SimpleNamespace(acquire=lambda: conn)
        self.closed = False

    async def close(self) -> None:
        self.closed = True


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_on: str | None = None,
    leftover: dict[str, int] | None = None,
) -> _FakeStore:
    import messagefoundry.config.settings as settings_mod
    from messagefoundry.store import sqlserver

    cur = _FakeCursor(fail_on=fail_on, leftover=leftover or {})
    store = _FakeStore(_FakeConn(cur))

    async def fake_open(*_a: Any, **_k: Any) -> _FakeStore:
        return store

    monkeypatch.setattr(
        settings_mod, "load_settings", lambda **_k: types.SimpleNamespace(store=None)
    )
    monkeypatch.setattr(sqlserver.SqlServerStore, "open", fake_open)
    # pyodbc is the optional `sqlserver` extra; the fake cursor raises RuntimeError as the driver error.
    monkeypatch.setattr(shardcert, "_store_driver_error", lambda: RuntimeError)
    return store


async def test_reset_store_clears_every_table(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _install(monkeypatch)
    await shardcert._reset_store({})
    cur = store._pool.acquire().cur
    deletes = [s for s in cur.executed if "DELETE" in s]
    assert len(deletes) == len(shardcert._RESET_TABLES)
    assert store.closed


def test_reset_store_covers_every_table_the_scanned_sql_names() -> None:
    """BACKLOG #5576: a table a verdict reads that the reset does not empty would carry an earlier
    run's rows into this one. This scans the SQL of this module, of the two store methods the
    engine's ``/stats`` answer is built from (``SqlServerStore.stats`` and ``in_pipeline_depth``),
    and of ``SqlServerStore.connection_metrics``, which the poller's ``/connections`` read counts
    from, and every table a ``FROM`` or ``JOIN`` there names must be reset. SQL elsewhere is not
    scanned. That includes the ``/status`` read's ``db_status``, whose row counts name their table
    through a variable and include ``message_events`` and ``audit_log``, which the reset leaves; the
    poller's sample takes only the database size and journal settings from it."""
    import ast
    import inspect
    import re

    from messagefoundry.store.sqlserver import SqlServerStore

    sql_start = ("SELECT", "DELETE", "INSERT", "UPDATE", "WITH", "SET ", "IF ")

    def tables(source: str) -> set[str]:
        found: set[str] = set()
        tree = ast.parse(source)
        # Docstrings are prose, even one that opens with "DELETE".
        docstrings = {
            id(body[0].value)
            for owner in ast.walk(tree)
            if isinstance(owner, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and (body := owner.body)
            and isinstance(body[0], ast.Expr)
        }
        for node in ast.walk(tree):
            # Only string pieces that open as SQL, so other prose is not read either.
            if (
                id(node) not in docstrings
                and isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.lstrip().upper().startswith(sql_start)
            ):
                found.update(re.findall(r"(?i)\b(?:FROM|JOIN)\s+([A-Za-z_][\w.]*)", node.value))
        # The reset's own f-strings splice `{table}`/`{t}`, which leave no literal name here, and
        # SQL Server's catalog views are no store table.
        return {t for t in found if not t.lower().startswith("sys.")}

    # Negative controls: the instrument sees a name in either keyword and either case.
    assert tables('x = "SELECT a FROM not_reset JOIN other ON 1=1"') == {"not_reset", "other"}
    assert tables('x = "select a from lower_case"') == {"lower_case"}
    assert tables('"""DELETE the rows: a docstring that reads from a table."""') == set()

    read = tables(Path(inspect.getfile(shardcert)).read_text(encoding="utf-8"))
    for method in (
        SqlServerStore.stats,
        SqlServerStore.in_pipeline_depth,
        SqlServerStore.connection_metrics,
    ):
        read |= tables(textwrap.dedent(inspect.getsource(method)))
    # The instrument finds the store-truth scan and the /connections counts it is meant to see.
    assert {"queue", "messages"} <= read, read
    assert read <= set(shardcert._RESET_TABLES), read - set(shardcert._RESET_TABLES)


async def test_reset_store_raises_on_a_delete_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #5576: the old reset suppressed every DELETE error, so a table it failed to clear kept the
    previous run's rows for this run to certify against."""
    store = _install(monkeypatch, fail_on="response")
    with pytest.raises(StoreResetFailed, match="response"):
        await shardcert._reset_store({})
    assert store.closed


async def test_reset_store_lets_a_non_driver_error_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the driver's error is relabelled a failed reset; a harness bug keeps its own type."""
    _install(monkeypatch, fail_on="queue")
    monkeypatch.setattr(shardcert, "_store_driver_error", lambda: KeyError)
    with pytest.raises(RuntimeError, match="synthetic driver error") as info:
        await shardcert._reset_store({})
    assert not isinstance(info.value, StoreResetFailed)


async def test_reset_store_raises_when_rows_remain(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _install(monkeypatch, leftover={"messages": 3})
    with pytest.raises(StoreResetFailed, match="messages"):
        await shardcert._reset_store({})
    assert store.closed
    verify = store._pool.acquire().cur.executed[-1]
    # Each table's EXISTS sits in its own nested IF, so a missing table is skipped, never error 208.
    assert "IS NOT NULL IF EXISTS (SELECT 1 FROM messages)" in verify
    assert " AND EXISTS" not in verify


def test_cli_exits_setup_code_when_the_reset_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed reset is a setup failure (exit 2), never a bench result (exit 1) or a traceback."""
    import harness.__main__ as cli

    for key in (
        "MEFOR_SHARDCERT_SHARDS",
        "MEFOR_SHARDCERT_LANES_PER_SHARD",
        "MEFOR_SHARDCERT_PERSISTENT",
        "MEFOR_SHARDCERT_ROUTING",
    ):
        monkeypatch.setenv(
            key, ""
        )  # the CLI writes these; setenv restores the original at teardown
    monkeypatch.setenv("MEFOR_STORE_BACKEND", "sqlserver")

    async def refuse(**_k: object) -> None:
        raise StoreResetFailed("store reset left rows in ['messages'] after the DELETE")

    monkeypatch.setattr(shardcert, "run_shardcert", refuse)
    assert cli._run_shardcert([]) == 2


def test_colocated_ladder_with_lost_copies_fails_exit_1() -> None:
    """Store-truth loss (copies missing) on a co-located ladder rung is a correctness FAIL, exit 1."""
    rec = ShardCertStepRecord.from_report(
        16.0, _report(sink_received=1000, acked_copies_missing=7000)
    )
    ladder = shardcert.ShardCertLadderReport(records=[rec])
    assert ladder.ok is False
    assert ladder.exit_code == 1
    assert ladder.result_label == "FAIL"


def test_driver_report_with_lost_copies_fails() -> None:
    """The two-box driver half, which tallies behind its own drain, still FAILs on missing copies."""
    rep = shardcert.ShardCertDriverReport(
        shards=("s1", "s2"),
        killed_shard=None,
        sent=1000,
        acked=1000,
        delivered_distinct=1000,
        sink_received=1000,
        acked_not_delivered=0,
        lane_inversions=0,
        lanes_observed=16,
        lane_repeats=0,
        engine_done=9000,
        engine_dead=0,
        in_pipeline_final=0,
        drained=True,
        drain_seconds=1.0,
        delivering=8,
        routing=BROADCAST,
        acked_copies_missing=7000,
    )
    assert rep.ok is False
    assert "LOSS" in rep.render()


async def test_colocated_ladder_keeps_measured_rungs_when_a_reset_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5576 (note 3): a later rung's StoreResetFailed stops the climb but keeps the rungs already
    measured, and the run reads SETUP_DEGRADED (exit 2), not a clean PASS and not a lost report."""
    good = ShardCertStepRecord.from_report(8.0, _report(), hold_seconds=1.0)
    calls: list[float] = []

    async def step(*, rate: float, **_k: object) -> ShardCertStepRecord:
        calls.append(rate)
        if len(calls) == 2:
            raise StoreResetFailed("store reset left rows in ['nodes'] after the DELETE")
        return dataclasses.replace(good, aggregate_rate=rate)

    monkeypatch.setattr(shardcert, "_run_ladder_step", step)
    ladder = await shardcert.run_shardcert_ladder(rates=[8.0, 16.0, 32.0])
    assert calls == [8.0, 16.0]
    assert [r.aggregate_rate for r in ladder.records] == [8.0]
    assert ladder.aborted_reason is not None and "16" in ladder.aborted_reason
    assert ladder.exit_code == 2
    assert ladder.to_json_dict()["aborted_reason"] == ladder.aborted_reason


def test_colocated_ladder_abort_on_the_first_rung_is_setup_not_fail() -> None:
    """A reset that fails before ANY rung ran is a setup failure (exit 2), not a correctness FAIL."""
    ladder = shardcert.ShardCertLadderReport(
        aborted_reason="store reset failed before the 8 msg/s rung"
    )
    assert ladder.exit_code == 2
    assert ladder.result_label == "SETUP_DEGRADED"
    assert "ABORTED" in ladder.render()
    assert "raise the top rate" not in ladder.render()


async def test_engine_posts_setup_failed_and_keeps_its_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """The engine half tells the drive (ENGINE_SETUP_FAILED) and re-raises StoreResetFailed; a coord
    write error must not replace it."""
    from harness.load.coord import FileDropCoord

    async def failing_reset(_env: object) -> None:
        raise StoreResetFailed("store reset left rows in ['nodes'] after the DELETE")

    monkeypatch.setattr(shardcert, "_reset_store", failing_reset)
    c = FileDropCoord(tmp_path, run_id="r")
    with pytest.raises(StoreResetFailed):
        await shardcert._reset_store_or_signal(c, {})
    posted = c.read(shardcert.ENGINE_SETUP_FAILED)
    # A fixed reason crosses the shared directory, never the driver's text (server, database, table).
    assert posted is not None and "nodes" not in str(posted["reason"])
    assert "store reset failed" in str(posted["reason"])

    def broken_post(*_a: object, **_k: object) -> None:
        raise OSError("coord share unreachable")

    monkeypatch.setattr(c, "post", broken_post)
    with pytest.raises(StoreResetFailed):
        await shardcert._reset_store_or_signal(c, {})


async def test_engine_setup_reason_is_escaped(tmp_path: Any) -> None:
    """The reason is another box's text from a shared directory, so control bytes never reach a terminal."""
    from harness.load.coord import FileDropCoord

    c = FileDropCoord(tmp_path, run_id="r")
    c.post(shardcert.ENGINE_SETUP_FAILED, {"reason": "bad\x1b[2Jreset\nline"})
    with pytest.raises(shardcert.EngineSetupFailed) as info:
        await shardcert._await_shards_ready(c, timeout=5.0)
    assert "\x1b" not in str(info.value)
    assert "\n" not in str(info.value)
