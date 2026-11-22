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


def _report(
    events: list[Event],
    *,
    trim_head_s: float = 0.0,
    trim_tail_s: float = 0.0,
    expect: tuple[int, int] | None = None,
) -> dict[str, Any]:
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
                trim_head_s=trim_head_s,
                trim_tail_s=trim_tail_s,
                expect_t=expect[0] if expect else None,
                expect_d=expect[1] if expect else None,
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


def _two_then_zero(mid: str, at: float) -> list[Event]:
    """Handlers delivering 2 and 0: both deliveries land before the second handler's stamp."""
    return [
        (mid, "received", at, None),
        (mid, "routed", at + 0.1, None),
        (mid, "transformed", at + 0.2, None),
        (mid, "delivered", at + 0.3, "OB_00"),
        (mid, "delivered", at + 0.4, "OB_01"),
        (mid, "transformed", at + 0.9, None),
    ]


def test_deliveries_before_the_last_transform_void_the_figure() -> None:
    """RED when: an armed gate prints OK on a negative row count that cannot be true."""
    events: list[Event] = []
    for i in range(5):
        events += _two_then_zero(f"m{i}", 100.0 + i)

    report = _report(events, expect=(2, 2))

    assert report["concurrency"]["n_outbound_rows"] is None
    assert report["concurrency"]["n_outbound_parity"]["mismatched_messages"] == 5
    assert report["census"]["ok"] is None
    assert report["census"]["unmeasured"] == ["n_outbound_rows"]


def test_a_dip_hidden_by_a_concurrent_message_voids_the_figure() -> None:
    """RED when: a message's own count goes negative, its last delivery is after its last
    transform, and another message's live row keeps the pooled count at or above zero."""
    mid = "dip"
    events: list[Event] = [
        (mid, "received", 100.0, None),
        (mid, "routed", 100.1, None),
        (mid, "transformed", 100.2, None),
        (mid, "delivered", 100.3, "OB_00"),
        (mid, "delivered", 100.4, "OB_01"),
        (mid, "transformed", 100.5, None),
        (mid, "transformed", 100.6, None),
        (mid, "delivered", 100.7, "OB_02"),
        ("live", "received", 100.0, None),
        ("live", "routed", 100.05, None),
        ("live", "transformed", 100.1, None),
        ("live", "delivered", 100.8, "OB_03"),
    ]

    concurrency = _report(events)["concurrency"]

    assert concurrency["n_outbound_parity"]["mismatched_messages"] == 1
    assert concurrency["n_outbound_rows"] is None
    assert "more deliveries than transforms" in "\n".join(sr._render_concurrency(concurrency))


def test_a_delivery_stamped_in_the_same_tick_as_its_transform_keeps_the_figure() -> None:
    """The control: a tie is a row born and delivered at one clock reading, not a negative count."""
    events: list[Event] = [
        ("tie", "received", 100.0, None),
        ("tie", "routed", 100.1, None),
        ("tie", "transformed", 100.2, None),
        ("tie", "delivered", 100.2, "OB_00"),
    ]

    concurrency = _report(events)["concurrency"]

    assert concurrency["n_outbound_parity"]["mismatched_messages"] == 0
    assert concurrency["n_outbound_rows"] is not None


def test_a_dip_in_a_message_past_the_trimmed_window_keeps_the_figure() -> None:
    """The control: the stop edge a tail trim excludes must not erase the rung's figure."""
    report = _report(_ladder() + _two_then_zero("late", 118.5), trim_tail_s=5.0)

    assert report["concurrency"]["n_outbound_parity"]["mismatched_messages"] == 0
    assert report["concurrency"]["n_outbound_rows"] is not None


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


def _census_text(report: dict[str, Any]) -> str:
    return "\n".join(sr._render_census(report["census"], report["population"]))


def _one_handoff_three_destinations() -> list[Event]:
    """Every message matches an armed (1, 3) topology, and every one breaks the birth premise."""
    events: list[Event] = []
    for i in range(20):
        events += _message(f"m{i}", 100.0 + i, births=1, deaths=3)
    return events


def _clean_window_with_a_mismatch_in_the_head_trim() -> list[Event]:
    """The census reads only the trimmed window. Parity also reads the head, so only it sees this."""
    return _ladder() + _message("early", 100.5, births=1, deaths=3)


@pytest.mark.parametrize(
    ("events", "expect", "trim_head_s"),
    [
        pytest.param(_one_handoff_three_destinations(), (1, 3), 0.0, id="armed-fan-out-topology"),
        pytest.param(
            _clean_window_with_a_mismatch_in_the_head_trim(), (8, 8), 2.0, id="mismatch-in-head"
        ),
    ],
)
def test_a_void_figure_is_no_verdict_rather_than_a_passed_gate(
    events: list[Event], expect: tuple[int, int], trim_head_s: float
) -> None:
    """RED when: a rung prints gate OK and passes --strict with its figure refused."""
    report = _report(events, expect=expect, trim_head_s=trim_head_s)
    census = report["census"]

    assert report["concurrency"]["n_outbound_rows"] is None
    # The census's own four checks passed, so this is the void figure's doing and nothing else's.
    assert census["modal_ok"] is True
    assert census["censored"] == 0
    assert census["ok"] is None
    assert census["unmeasured"] == ["n_outbound_rows"]

    text = _census_text(report)
    assert "gate: OK" not in text
    assert "GATE FAILED" not in text
    assert "gate: NO VERDICT" in text

    assert sr._gate_failures({"mode": "window", **report}) == [
        "window (NO VERDICT: n_outbound_rows unmeasured)"
    ]
    assert sr._gate_failures({"mode": "per-rung", "rungs": [report]}) != []


def test_a_good_figure_still_passes_the_gate_and_keeps_its_values() -> None:
    """THE CONTROL: the no-verdict arm must be able to answer OK, on the pre-fix ladder figures."""
    report = _report(_ladder(), expect=(8, 8))
    census = report["census"]

    assert report["concurrency"]["n_outbound_rows"] == {
        "time_avg": 2.4,
        "peak": 8.0,
        "at_lo": 0.0,
        "at_hi": 0.0,
    }
    assert census["ok"] is True
    assert census["unmeasured"] == []
    assert "gate: OK" in _census_text(report)
    assert sr._gate_failures({"mode": "window", **report}) == []


def test_a_failed_census_stays_failed_when_the_figure_is_also_void() -> None:
    """RED when: the void figure softens a real refutation into a no-verdict."""
    events = _ladder() + _message("odd", 110.5, births=1, deaths=3)

    report = _report(events, expect=(8, 8))

    assert report["concurrency"]["n_outbound_rows"] is None
    assert report["census"]["ok"] is False
    assert "GATE FAILED" in _census_text(report)
    assert sr._gate_failures({"mode": "window", **report}) == ["window"]


def test_an_unarmed_gate_is_not_reported_as_an_unmeasured_figure() -> None:
    """RED when: an UNGATED report with a void figure claims a verdict state it never reached."""
    report = _report(_one_handoff_three_destinations())

    assert report["census"]["ok"] is None
    assert report["census"]["expected"] is None
    text = _census_text(report)
    assert "NO VERDICT" not in text
    assert "UNGATED" in text
    assert "NO VERDICT" not in sr._failure_label(report)
