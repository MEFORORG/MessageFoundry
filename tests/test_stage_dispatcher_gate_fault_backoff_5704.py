# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A pre-claim gate that keeps raising logs on a backoff, not once per re-check (vault BACKLOG
#5704 items 16, 27 and 34).

``StageDispatcher._lane_may_claim`` parks a lane whose gate raised on a timer of
``_LANE_ERROR_BACKOFF_SECONDS`` and asks again when it ends. It logged an ERROR on every ask, so a
gate that stays broken wrote one record per lane per backoff. The dispatcher's other per-lane and
per-claimer faults log through ``messagefoundry.log_backoff.FailureRun`` (BACKLOG #1844); the gate
fault now does too, one run per lane, which writes one recovery line when the gate answers for
that lane again and is closed by ``stop()`` if still open.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.pipeline import stage_dispatcher
from messagefoundry.store.store import Stage

_LOGGER = "messagefoundry.pipeline.stage_dispatcher"


class _Handle:
    def cancel(self) -> None:
        pass


def _dispatcher(gate: Callable[[str], bool]) -> stage_dispatcher.StageDispatcher:
    def call_later(delay: float, cb: Callable[[], object]) -> Any:
        return _Handle()

    return stage_dispatcher.StageDispatcher(
        Stage.ROUTED,
        None,  # type: ignore[arg-type]  # chunk assembly touches no store
        process_item=None,  # type: ignore[arg-type]  # assembly runs no body
        lane_provider=set,
        per_lane_limit=1,
        may_claim=gate,
        call_later=call_later,
    )


def _ask(dispatcher: stage_dispatcher.StageDispatcher, lane: str) -> list[str]:
    """One re-check of ``lane``'s gate, as its timed park ending and the claimer reaching it."""
    st = dispatcher._states.get(lane)
    if st is not None and st.phase is stage_dispatcher._LanePhase.PARKED:
        dispatcher._cancel_timer(lane)
        st.phase = stage_dispatcher._LanePhase.IDLE
    dispatcher.mark_ready(lane)
    return dispatcher._assemble_chunk(dispatcher._claimers[0])


def _gate_errors(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == _LOGGER and r.levelno >= logging.ERROR and "may_claim raised" in r.getMessage()
    ]


def test_a_gate_that_keeps_raising_logs_on_a_backoff(caplog: pytest.LogCaptureFixture) -> None:
    def gate(lane: str) -> bool:
        raise KeyError(lane)

    dispatcher = _dispatcher(gate)
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        for _ in range(8):
            assert _ask(dispatcher, "bad") == []
    errors = _gate_errors(caplog)
    # The 1st, 2nd, 4th and 8th of one cause, each carrying the run's count and the traceback.
    assert [r.getMessage().rsplit("(", 1)[1] for r in errors] == [
        "consecutive failures: 1)",
        "consecutive failures: 2)",
        "consecutive failures: 4)",
        "consecutive failures: 8)",
    ]
    assert all(r.exc_info is not None for r in errors)
    dispatcher._cancel_timer("bad")


def test_one_lane_answering_does_not_close_another_lanes_run(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The gate is a per-lane predicate: lane ``ok`` answering says nothing about lane ``bad``."""

    def gate(lane: str) -> bool:
        if lane == "bad":
            raise KeyError(lane)
        return True

    dispatcher = _dispatcher(gate)
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        for _ in range(16):
            _ask(dispatcher, "bad")
            _ask(dispatcher, "ok")
    # 16 faults of lane bad: records at 1, 2, 4, 8 and 16, and no recovery line, since bad never
    # answered. A run shared with ok would close at each of ok's answers and log all 16.
    assert len(_gate_errors(caplog)) == 5
    assert not [r for r in caplog.records if "recovered after" in r.getMessage()]
    dispatcher._cancel_timer("bad")


def test_each_lane_keeps_its_own_run(caplog: pytest.LogCaptureFixture) -> None:
    def gate(lane: str) -> bool:
        raise RuntimeError("the same gate fault")

    dispatcher = _dispatcher(gate)
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        for _ in range(4):
            _ask(dispatcher, "a")
        _ask(dispatcher, "b")
    # Lane a's run is at 4 (records at 1, 2, 4); lane b's first fault is its own first record. A run
    # shared with a would be at 5 and hold it back.
    errors = _gate_errors(caplog)
    assert len(errors) == 4
    assert "lane b" in errors[-1].getMessage()
    assert errors[-1].getMessage().endswith("(consecutive failures: 1)")
    dispatcher._cancel_timer("a")
    dispatcher._cancel_timer("b")


def test_the_gate_answering_again_closes_the_run_once(caplog: pytest.LogCaptureFixture) -> None:
    broken = [True]

    def gate(lane: str) -> bool:
        if broken[0]:
            raise RuntimeError("a gate fault")
        return True

    dispatcher = _dispatcher(gate)
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        for _ in range(3):
            _ask(dispatcher, "lane")
        broken[0] = False
        assert _ask(dispatcher, "lane") == ["lane"]
    recovered = [r for r in caplog.records if "recovered after 3" in r.getMessage()]
    assert len(recovered) == 1
    assert recovered[0].levelno == logging.WARNING
    assert dispatcher._states["lane"].gate_faults.count == 0


async def test_stop_closes_an_open_run(caplog: pytest.LogCaptureFixture) -> None:
    def gate(lane: str) -> bool:
        raise RuntimeError("a gate fault")

    dispatcher = _dispatcher(gate)
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        for _ in range(3):
            _ask(dispatcher, "lane")
        dispatcher._cancel_timer("lane")
        await dispatcher.stop()
    closed = [
        r for r in caplog.records if "may_claim for lane lane: stopped with 3" in r.getMessage()
    ]
    assert len(closed) == 1
