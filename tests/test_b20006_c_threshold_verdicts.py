# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The stranding budget and ``no_sends`` are thresholds, not proof (BACKLOG #5574 item 9).

In the connscale and estate rig reconciles they made a step LOSS even with the engine metrics
missing or after a counter reset, where no arm can say whether the sends they name were lost. They
now make it INCONCLUSIVE there. That is a label only: every case below still FAILS the step, and
with the engine arms judged they stay LOSS as before.
"""

from __future__ import annotations

import pytest

from harness.load.connscale.runner import _reconcile as connscale_reconcile
from harness.load.connscale.runner import _ReloadAccount
from harness.load.enginepoll import EngineSample
from harness.load.estate.runner import _reconcile as estate_reconcile
from harness.load.metrics import Counters

_RESET = "the engine restarted mid-run"
_SUFFIX = "a threshold and not on its own proof of a loss"


def _sample(*, read: int, written: int) -> EngineSample:
    return EngineSample(
        elapsed_s=1.0,
        pending=0,
        inflight=0,
        done=written,
        dead=0,
        read=read,
        written=written,
        out_dead=0,
        queue_depth=0,
        in_pipeline=0,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=1.0,
    )


_BASE = _sample(read=0, written=0)
_FLOOD = Counters(sent=36, acked=0, timeouts=36)
# 33 of 36 stranded by the reload probe and nothing sent after every connection came back.
_NO_SENDS = Counters(sent=36, acked=3, timeouts=33, sink_received=15)


def _no_sends_reload() -> _ReloadAccount:
    return _ReloadAccount(
        seconds=0.5,
        stranded=33,
        not_reconnected=0,
        extra_hold_s=0.0,
        after=Counters(sent=36, acked=3, timeouts=33),
    )


@pytest.mark.parametrize(
    ("counter_reset", "final"),
    [(_RESET, _sample(read=30, written=30)), (None, None)],
    ids=["counter_reset", "metrics_missing"],
)
def test_a_stranding_flood_without_engine_arms_fails_inconclusive(
    counter_reset: str | None, final: EngineSample | None
) -> None:
    base = _sample(read=100, written=100) if final is not None else None
    for result in (
        connscale_reconcile(
            _FLOOD,
            base,
            final,
            unconfirmed_budget=2,
            drain_seconds=1.0,
            counter_reset=counter_reset,
        ),
        estate_reconcile(
            _FLOOD,
            base,
            final,
            unconfirmed_budget=2,
            drain_seconds=1.0,
            counter_reset=counter_reset,
        ),
    ):
        assert not result.ok and result.inconclusive, result.detail
        assert "systemic no-ACK fault" in result.detail
        assert _SUFFIX in result.detail


def test_a_stranding_flood_beside_a_clean_engine_read_stays_loss() -> None:
    # The control: with the engine arms judged the budget is LOSS, as before item 9.
    final = _sample(read=36, written=36)
    for result in (
        connscale_reconcile(
            _FLOOD, _BASE, final, unconfirmed_budget=2, drain_seconds=1.0, counter_reset=None
        ),
        estate_reconcile(
            _FLOOD, _BASE, final, unconfirmed_budget=2, drain_seconds=1.0, counter_reset=None
        ),
    ):
        assert not result.ok and not result.inconclusive, result.detail
        assert "systemic no-ACK fault" in result.detail
        assert _SUFFIX not in result.detail


def test_no_sends_after_the_reload_across_a_counter_reset_fails_inconclusive() -> None:
    result = connscale_reconcile(
        _NO_SENDS,
        _sample(read=100, written=100),
        _sample(read=15, written=15),
        unconfirmed_budget=12,
        drain_seconds=1.0,
        counter_reset=_RESET,
        reload=_no_sends_reload(),
    )
    assert not result.ok and result.inconclusive, result.detail
    assert "nothing was sent after the reload probe" in result.detail
    assert _SUFFIX in result.detail


def test_no_sends_after_the_reload_without_engine_metrics_fails_inconclusive() -> None:
    result = connscale_reconcile(
        _NO_SENDS,
        None,
        None,
        unconfirmed_budget=12,
        drain_seconds=1.0,
        counter_reset=None,
        reload=_no_sends_reload(),
    )
    assert not result.ok and result.inconclusive, result.detail
    assert "nothing was sent after the reload probe" in result.detail
    assert _SUFFIX in result.detail


def test_no_sends_after_the_reload_with_the_engine_read_stays_loss() -> None:
    result = connscale_reconcile(
        _NO_SENDS,
        _BASE,
        _sample(read=15, written=15),
        unconfirmed_budget=12,
        drain_seconds=1.0,
        counter_reset=None,
        reload=_no_sends_reload(),
    )
    assert not result.ok and not result.inconclusive, result.detail
    assert _SUFFIX not in result.detail


def test_a_reload_signature_that_is_not_a_threshold_stays_loss_across_a_reset() -> None:
    # Item 9 names only the budget and no_sends: a connection that never came back is still LOSS.
    reload = _ReloadAccount(
        seconds=0.5,
        stranded=30,
        not_reconnected=4,
        extra_hold_s=0.0,
        after=Counters(sent=30, acked=0, timeouts=30),
    )
    result = connscale_reconcile(
        Counters(sent=36, acked=6, timeouts=30, sink_received=18),
        _sample(read=100, written=100),
        _sample(read=18, written=18),
        unconfirmed_budget=12,
        drain_seconds=1.0,
        counter_reset=_RESET,
        reload=reload,
    )
    assert not result.ok and not result.inconclusive, result.detail
