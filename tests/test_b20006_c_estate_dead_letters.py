# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The estate zero-loss check sees dead-letters outside the outbound connections view (BACKLOG #5436).

Two gaps the row named, after engine PR 3172 made a rise in the outbound dead count fail the step:

* an ingress or routed dead-letter leaves no outbound row, so ``out_dead`` stays 0. The inbound
  ``errored`` count on ``/connections`` (messages whose disposition is ERROR) sees it, and the
  poller now carries it as ``EngineSample.in_errored``;
* a per-outbound stats reset lowers ``out_dead`` while the rows stay dead, so a reset can cancel a
  new dead-letter. The store's own dead count (``EngineSample.dead``, from ``/stats``) is not offset.

A NAK on an otherwise delivered run is an open owner question, so the errored arm takes out every
send the client saw NAKed or never saw answered; those cases are pinned here as unchanged.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from harness.load import enginepoll
from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.estate.report import NoLoss
from harness.load.estate.runner import _reconcile
from harness.load.metrics import Counters
from messagefoundry.api.models import ConnectionRow


def _sample(
    *, read: int, written: int, dead: int = 0, out_dead: int = 0, in_errored: int = 0
) -> EngineSample:
    return EngineSample(
        elapsed_s=1.0,
        pending=0,
        inflight=0,
        done=written,
        dead=dead,
        read=read,
        written=written,
        out_dead=out_dead,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=1.0,
        in_errored=in_errored,
    )


_BASE = _sample(read=0, written=0)


def _judge(
    c: Counters,
    final: EngineSample,
    *,
    base: EngineSample = _BASE,
    counter_reset: str | None = None,
) -> NoLoss:
    return _reconcile(
        c,
        base,
        final,
        unconfirmed_budget=2,
        drain_seconds=1.0,
        counter_reset=counter_reset,
    )


# --- ingress and routed dead-letters, through the inbound errored count -------------------------


def test_a_routed_dead_letter_is_a_loss() -> None:
    # 100 accepted and ACKed; 60 dead-lettered in routing, so 40 written. Intake and delivery both
    # balance, and nothing is outbound-dead, so on main this read as zero loss.
    c = Counters(sent=100, acked=100, sink_received=40)
    result = _judge(c, _sample(read=100, written=40, in_errored=60))
    assert not result.ok and not result.inconclusive, result.detail
    assert "60 message(s) took an ERROR disposition" in result.detail


def test_a_single_ingress_dead_letter_beside_a_fanout_surplus_is_a_loss() -> None:
    # Hub fan-out writes more than it reads, so `written` cannot show the one message that died.
    c = Counters(sent=100, acked=100, sink_received=495)
    result = _judge(c, _sample(read=100, written=495, in_errored=1))
    assert not result.ok and not result.inconclusive, result.detail


def test_errors_the_client_saw_nakked_are_not_judged() -> None:
    # The NAK question is the owner's: a refused frame is recorded ERROR and NAKed, and this arm
    # does not decide whether it is a loss, so a run with only those reads as on main.
    c = Counters(sent=100, acked=97, nak=3, sink_received=97)
    result = _judge(c, _sample(read=100, written=97, in_errored=3))
    assert result.ok, result.detail
    # Not silent: the detail says the errors were seen and why they were not judged.
    assert "3 message(s) took an ERROR disposition" in result.detail
    assert "not judged" in result.detail


def test_an_unconfirmed_send_may_be_a_nak_the_client_missed() -> None:
    c = Counters(sent=100, acked=99, timeouts=1, sink_received=99)
    result = _judge(c, _sample(read=100, written=99, in_errored=1))
    assert result.ok, result.detail


def test_an_error_beyond_the_naks_and_unconfirmed_sends_is_a_loss() -> None:
    c = Counters(sent=100, acked=96, nak=2, timeouts=1, sink_received=95)
    result = _judge(c, _sample(read=100, written=95, in_errored=4))
    assert not result.ok and not result.inconclusive, result.detail
    assert "1 more than the 2 NAKed and 1 unconfirmed" in result.detail


def test_errors_from_before_the_step_do_not_count() -> None:
    c = Counters(sent=36, acked=36, sink_received=36)
    base = _sample(read=0, written=0, in_errored=9)
    result = _judge(c, _sample(read=36, written=36, in_errored=9), base=base)
    assert result.ok, result.detail


def test_an_errored_count_that_fell_is_inconclusive() -> None:
    # A replay of an errored message, or a per-inbound stats reset, lowers it and could hide a
    # new error: 5 removed, 1 new.
    c = Counters(sent=36, acked=36, sink_received=36)
    base = _sample(read=0, written=0, in_errored=5)
    result = _judge(c, _sample(read=36, written=36, in_errored=1), base=base)
    assert not result.ok and result.inconclusive, result.detail
    assert "inbound errored count fell by 4" in result.detail


def test_the_errored_arm_is_not_judged_across_a_counter_reset() -> None:
    # It is offset by a stats reset like `read`, so a reset leaves the step INCONCLUSIVE, as before.
    c = Counters(sent=36, acked=36, sink_received=36)
    result = _judge(
        c, _sample(read=36, written=36, in_errored=5), counter_reset="the engine restarted mid-run"
    )
    assert not result.ok and result.inconclusive, result.detail
    assert "ERROR disposition" not in result.detail


# --- the store's dead rows, which a stats reset does not move ------------------------------------


def test_a_stats_reset_that_cancels_a_new_dead_letter_in_out_dead_is_still_a_loss() -> None:
    # #8332 item 5: the outbound's stats reset took 1 off `out_dead` as one new row died, so
    # `out_dead` is unmoved, the step's written/read deltas still look sound, and main passed it.
    c = Counters(sent=36, acked=36, sink_received=35)
    base = _sample(read=0, written=0, dead=4, out_dead=4)
    final = _sample(read=36, written=35, dead=5, out_dead=4, in_errored=0)
    result = _judge(c, final, base=base)
    assert not result.ok and not result.inconclusive, result.detail
    assert "the store holds 1 more dead outbound row(s)" in result.detail


def test_the_store_dead_arm_is_not_judged_across_a_counter_reset() -> None:
    # Like every engine arm it waits for a clean read: the store is shared, so a reset step's rise
    # is not taken as this step's loss. The step fails INCONCLUSIVE, as it did before.
    c = Counters(sent=36, acked=36, sink_received=36)
    result = _judge(
        c, _sample(read=36, written=36, dead=2), counter_reset="the engine restarted mid-run"
    )
    assert not result.ok and result.inconclusive, result.detail
    assert "the store holds" not in result.detail


def test_the_store_dead_text_is_not_repeated_beside_the_same_outbound_count() -> None:
    c = Counters(sent=36, acked=36, sink_received=33)
    result = _judge(c, _sample(read=36, written=33, dead=3, out_dead=3))
    assert not result.ok and not result.inconclusive, result.detail
    assert "3 outbound row(s) dead-lettered" in result.detail
    assert "the store holds" not in result.detail


def test_a_real_outbound_dead_letter_moves_all_three_counts_and_is_one_loss() -> None:
    # The shape the engine produces: a dead outbound row raises `out_dead` and the store's dead
    # rows, and the finalizer gives its message an ERROR disposition.
    c = Counters(sent=36, acked=36, sink_received=33)
    result = _judge(c, _sample(read=36, written=33, dead=3, out_dead=3, in_errored=3))
    assert not result.ok and not result.inconclusive, result.detail
    assert "3 outbound row(s) dead-lettered" in result.detail
    assert "the store holds" not in result.detail
    assert "3 message(s) took an ERROR disposition" in result.detail


def test_a_store_dead_count_that_fell_is_inconclusive() -> None:
    c = Counters(sent=36, acked=36, sink_received=36)
    base = _sample(read=0, written=0, dead=6)
    result = _judge(c, _sample(read=36, written=36, dead=2), base=base)
    assert not result.ok and result.inconclusive, result.detail
    assert "store's outbound dead rows fell by 4" in result.detail


def test_missing_metrics_judge_no_dead_arm() -> None:
    c = Counters(sent=36, acked=36, sink_received=36)
    result = _reconcile(c, None, None, unconfirmed_budget=2, drain_seconds=1.0, counter_reset=None)
    assert not result.ok and result.inconclusive, result.detail
    assert "dead" not in result.detail


def test_a_clean_step_still_passes() -> None:
    c = Counters(sent=36, acked=36, sink_received=36)
    result = _judge(c, _sample(read=36, written=36))
    assert result.ok
    assert result.detail == "read>=sent, sink_received>=written, backlog drained"


# --- the poller carries the inbound errored count -----------------------------------------------


def _row(**kw: Any) -> ConnectionRow:
    base: dict[str, Any] = {
        "role": "source",
        "channel_id": "IB_A",
        "channel_name": "IB_A",
        "destination": None,
        "name": "IB_A in",
        "status": "running",
        "direction": "in",
        "method": "MLLP",
        "peer": None,
        "port": None,
        "queue_depth": None,
        "idle_seconds": None,
        "alerts_active": 0,
        "errored": 0,
        "read": None,
        "written": None,
        "backlog_seconds": None,
        "delivered_age_seconds": None,
    }
    base.update(kw)
    return ConnectionRow(**base)


class _Client:
    """The three reads ``_sample_shard`` makes, answered with fixed values."""

    def __init__(self, rows: list[ConnectionRow]) -> None:
        self._rows = rows

    def stats(self) -> Any:
        return _Obj(outbox_by_status={"dead": 0}, in_pipeline=0)

    def connections(self) -> list[ConnectionRow]:
        return self._rows

    def status(self) -> Any:
        return _Obj(
            db=_Obj(size_bytes=0, journal_mode="wal", synchronous="normal"),
            engine=_Obj(uptime_seconds=5.0),
        )


class _Obj:
    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)


def test_the_poller_sums_inbound_errored_apart_from_outbound_dead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shards = [
        _Client(
            [
                _row(read=50, errored=3),
                _row(role="destination", direction="out", written=40, errored=7, queue_depth=0),
            ]
        ),
        _Client([_row(channel_id="IB_B", read=20, errored=2)]),
    ]
    poller = EnginePoller(["http://shard-a", "http://shard-b"], None, origin=time.perf_counter())
    poller._clients = shards  # type: ignore[assignment]  # duck-typed EngineClients
    monkeypatch.setattr(enginepoll.EnginePoller, "_counted", lambda self, index, call: call())
    sample = asyncio.run(poller.sample_once())
    assert sample is not None
    assert sample.in_errored == 5  # inbound rows only, summed per engine shard
    assert sample.out_dead == 7  # the outbound row's `errored` stays where it was
