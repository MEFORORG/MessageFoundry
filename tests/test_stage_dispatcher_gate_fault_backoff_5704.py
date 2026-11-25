# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A pre-claim gate that keeps raising logs on a backoff, not once per re-check (vault BACKLOG
#5704 items 16, 27 and 34).

``StageDispatcher._lane_may_claim`` parks a lane whose gate raised on a timer of
``_LANE_ERROR_BACKOFF_SECONDS`` and asks again when it ends. It logged an ERROR on every ask, so a
gate that stays broken wrote one record per lane per backoff. The dispatcher's other per-lane and
per-claimer faults log through ``messagefoundry.log_backoff.FailureRun`` (BACKLOG #1844); the gate
fault now does too, per lane, and writes one recovery line when the gate answers again.
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


def test_lanes_share_one_run(caplog: pytest.LogCaptureFixture) -> None:
    """The runner's gate reads runner-wide state, so one fault is every lane's. A run per lane would
    write lanes x log2(asks) records; one run writes log2 of all the asks."""

    def gate(lane: str) -> bool:
        raise RuntimeError("the same gate fault")

    dispatcher = _dispatcher(gate)
    lanes = [f"lane-{i}" for i in range(16)]
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        for lane in lanes:
            _ask(dispatcher, lane)
    # 16 faults of one cause: records at 1, 2, 4, 8 and 16. A run per lane would write 16.
    assert len(_gate_errors(caplog)) == 5
    for lane in lanes:
        dispatcher._cancel_timer(lane)


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
    assert dispatcher._gate_faults.count == 0


async def test_stop_closes_an_open_run(caplog: pytest.LogCaptureFixture) -> None:
    def gate(lane: str) -> bool:
        raise RuntimeError("a gate fault")

    dispatcher = _dispatcher(gate)
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        for _ in range(3):
            _ask(dispatcher, "lane")
        dispatcher._cancel_timer("lane")
        await dispatcher.stop()
    closed = [r for r in caplog.records if "may_claim: stopped with 3" in r.getMessage()]
    assert len(closed) == 1
    assert dispatcher._gate_faults.count == 0
