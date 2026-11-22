# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Does the residency tool's concurrency figure hold, and refuse when its premise does not?

BACKLOG #5868. ``n_outbound_rows`` counts ``transformed`` as the birth of one outbound row and
``delivered`` as its death. All three stores write ONE ``transformed`` per handler handoff, however
many destinations that handoff produced, so the premise holds only where each handler delivers once.
These arms run the tool's real SQL against an in-memory ``message_events`` table.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import aiosqlite
import pytest

ROOT = Path(__file__).resolve().parents[1]

Event = tuple[str, str, float, str | None]


def _load() -> ModuleType:
    """By path: ``scripts/bench`` is not a package. Registered first, because ``@dataclass`` reads
    the module back out of ``sys.modules`` while the class body is built."""
    spec = importlib.util.spec_from_file_location(
        "stage_residency_under_test", ROOT / "scripts" / "bench" / "stage_residency.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sr = _load()


def _message(mid: str, at: float, *, births: int, deaths: int, step: float = 0.01) -> list[Event]:
    """One message's events: ``births`` transformed stamps, then ``deaths`` delivered stamps."""
    events: list[Event] = [(mid, "received", at, None), (mid, "routed", at + 0.1, None)]
    events += [(mid, "transformed", at + 0.2 + i * step, None) for i in range(births)]
    events += [(mid, "delivered", at + 0.5 + i * step, f"OB_{i:02d}") for i in range(deaths)]
    return events


def _report(events: list[Event], *, trim_tail_s: float = 0.0) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        async with aiosqlite.connect(":memory:") as db:
            await db.execute(
                "CREATE TABLE message_events (message_id TEXT, event TEXT, ts REAL, destination TEXT)"
            )
            await db.executemany("INSERT INTO message_events VALUES (?, ?, ?, ?)", events)
            report: dict[str, Any] = await sr._window_report(
                SimpleNamespace(_db=db),
                since=None,
                until=None,
                trim_head_s=0.0,
                trim_tail_s=trim_tail_s,
                expect_t=None,
                expect_d=None,
                full_only=False,
                limit=None,
                service_ms=24.42,
                label="window",
            )
            return report

    return asyncio.run(run())


def _ladder() -> list[Event]:
    """The 8-handlers, one-delivery-each shape, 20 messages one second apart."""
    events: list[Event] = []
    for i in range(20):
        events += _message(f"m{i}", 100.0 + i, births=8, deaths=8)
    return events


def test_at_lo_is_the_level_when_no_mark_falls_after_the_window_start() -> None:
    """RED when: two rows alive across the whole window report ``at_lo`` 0.0."""
    assert sr._counting_n([1.0, 2.0], [], 5.0, 10.0) == {
        "time_avg": 2.0,
        "peak": 2.0,
        "at_lo": 2.0,
        "at_hi": 2.0,
    }


def test_at_lo_with_marks_on_both_sides_of_the_window_start() -> None:
    """The control: the case the old code already answered must keep its answer."""
    result = sr._counting_n([1.0, 2.0, 6.0], [7.0], 5.0, 10.0)
    assert result["at_lo"] == 2.0
    assert result["at_hi"] == 2.0
    assert result["peak"] == 3.0


def test_the_eight_handler_ladder_figures_are_unchanged() -> None:
    """THE CONTROL. These values were read from the tool BEFORE this fix, on this same fixture."""
    assert _report(_ladder())["concurrency"]["n_outbound_rows"] == {
        "time_avg": 2.4,
        "peak": 8.0,
        "at_lo": 0.0,
        "at_hi": 0.0,
    }


@pytest.mark.parametrize(
    ("births", "deaths"),
    [
        pytest.param(1, 3, id="one-handoff-three-destinations"),
        pytest.param(1, 0, id="one-handoff-no-destination"),
        pytest.param(8, 9, id="a-redelivery-adds-a-death"),
        pytest.param(0, 2, id="a-delivery-with-no-transform"),
    ],
)
def test_a_parity_mismatch_emits_none_rather_than_a_number(births: int, deaths: int) -> None:
    """RED when: a message whose births and deaths differ still yields a figure."""
    events = _ladder() + _message("odd", 110.5, births=births, deaths=deaths)

    concurrency = _report(events)["concurrency"]

    assert concurrency["n_outbound_rows"] is None
    assert concurrency["n_outbound_parity"] == {"mismatched_messages": 1, "messages": 21}
    # The message-level count does not use the birth premise, so the refusal must not void it.
    assert concurrency["n_messages_in_flight"]["peak"] >= 1.0


def test_a_redelivery_offsetting_an_undelivered_row_voids_the_figure() -> None:
    """RED when: 8 births and 8 deaths over 7 destinations passes, with one row still alive."""
    odd = _message("odd", 110.5, births=8, deaths=7)
    odd.append(("odd", "delivered", 111.5, "OB_00"))

    concurrency = _report(_ladder() + odd)["concurrency"]

    assert concurrency["n_outbound_rows"] is None
    assert concurrency["n_outbound_parity"]["mismatched_messages"] == 1


def test_a_delivered_row_with_no_destination_voids_the_figure() -> None:
    """RED when: parity counts a death that the death stream, which needs a destination, lacks."""
    odd = _message("odd", 110.5, births=1, deaths=0)
    odd.append(("odd", "delivered", 111.0, None))

    assert _report(_ladder() + odd)["concurrency"]["n_outbound_rows"] is None


def test_a_mismatch_received_after_the_trimmed_window_keeps_the_figure() -> None:
    """RED when: a message wholly past ``hi`` erases a figure it contributes nothing to."""
    clean = _report(_ladder(), trim_tail_s=5.0)["concurrency"]
    edged = _report(_ladder() + _message("late", 118.5, births=1, deaths=0), trim_tail_s=5.0)

    assert edged["concurrency"]["n_outbound_parity"]["mismatched_messages"] == 0
    assert edged["concurrency"]["n_outbound_rows"] is not None
    assert clean["n_outbound_rows"] is not None


def test_a_message_with_no_transform_and_no_delivery_keeps_parity() -> None:
    """A router-filtered message has no birth and no death, so it is not a mismatch."""
    events = [
        *_ladder(),
        ("filtered", "received", 110.5, None),
        ("filtered", "routed", 110.6, None),
    ]

    concurrency = _report(events)["concurrency"]

    assert concurrency["n_outbound_rows"] is not None
    assert concurrency["n_outbound_parity"] == {"mismatched_messages": 0, "messages": 21}


def test_the_report_renders_when_the_figure_is_none() -> None:
    """RED when: formatting the None crashes the run after the JSON was written."""
    events = _ladder() + _message("odd", 110.5, births=1, deaths=3)

    text = "\n".join(sr._render_concurrency(_report(events)["concurrency"]))

    assert "N_outbound_rows   UNAVAILABLE" in text
    assert "1 of 21" in text
