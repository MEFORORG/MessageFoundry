# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connector coverage gate (vault BACKLOG #2681).

Every (connector kind, direction) the engine registers must have a registered harness scenario or
an entry, with a reason, in ``harness.coverage.EXEMPT``. The gate reads the engine's LIVE connector
registries and the LIVE scenario registry -- no list kept here -- so a new connector kind, or a new
direction on an old one, reds this test until someone writes a scenario or a reasoned exemption.
The controls below prove each refusal fires; a gate that cannot fail measures nothing.
"""

from __future__ import annotations

import pytest

from harness import coverage
from harness.__main__ import main
from harness.coverage import coverage_gaps, coverage_rows, registered_kinds
from harness.scenarios import SCENARIOS, BaseScenario, ScenarioContext, ScenarioResult


class _Claims(BaseScenario):
    """A scenario that only claims coverage; the gate never runs one."""

    description = ""

    def __init__(self, name: str, *pairs: tuple[str, str]) -> None:
        self.name = name
        self._pairs = frozenset(pairs)

    @property
    def covers(self) -> frozenset[tuple[str, str]]:
        return self._pairs

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        raise AssertionError("the coverage gate never runs a scenario")


def test_every_registered_kind_and_direction_has_a_scenario_or_a_reason() -> None:
    live = registered_kinds()
    rows = coverage_rows(live, SCENARIOS.values())
    # Liveness: the walk saw the whole registry, not an empty one that would pass by construction.
    assert sum(r.registered for r in rows) == len(live["inbound"]) + len(live["outbound"]) >= 20
    assert coverage_gaps(rows) == []


def test_the_cli_gate_agrees(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--coverage"]) == 0
    out = capsys.readouterr().out
    assert "GAP:" not in out
    assert any(ln.split()[:3] == ["outbound", "direct", "EXEMPT:"] for ln in out.splitlines())


# --- controls: each refusal fires ------------------------------------------------------------------


def test_the_gate_reds_on_a_registered_kind_nobody_covers() -> None:
    """The control the row asks for: inject an uncovered kind and the gate must refuse it."""
    live = {d: set(kinds) for d, kinds in registered_kinds().items()}
    live["inbound"].add("kafka")
    rows = coverage_rows({d: frozenset(k) for d, k in live.items()}, SCENARIOS.values())
    assert coverage_gaps(rows) == ["inbound kafka: no scenario and no exemption"]


def test_the_gate_reds_on_a_new_direction_of_an_existing_kind() -> None:
    live = {d: set(kinds) for d, kinds in registered_kinds().items()}
    live["outbound"].add("timer")  # timer is inbound-only today
    rows = coverage_rows({d: frozenset(k) for d, k in live.items()}, SCENARIOS.values())
    assert coverage_gaps(rows) == ["outbound timer: no scenario and no exemption"]


def test_the_gate_reds_on_a_stale_exemption() -> None:
    """An exemption must not outlive its reason: once the pair is covered, or is gone from the
    registry, the entry itself is a gap."""
    live = registered_kinds()
    covered = [*SCENARIOS.values(), _Claims("now_covers_direct", ("direct", "outbound"))]
    gaps = coverage_gaps(coverage_rows(live, covered))
    assert gaps == ["outbound direct: exempt, but covered by now_covers_direct"]

    gone = {d: frozenset(k - {"direct"}) for d, k in live.items()}
    gaps = coverage_gaps(coverage_rows(gone, SCENARIOS.values()))
    assert gaps == ["outbound direct: exempt, but not a registered (kind, direction)"]


def test_the_gate_reds_on_a_claim_the_engine_does_not_register() -> None:
    claims = [*SCENARIOS.values(), _Claims("claims_kafka", ("kafka", "outbound"))]
    gaps = coverage_gaps(coverage_rows(registered_kinds(), claims))
    assert gaps == ["outbound kafka: claimed by claims_kafka but not registered"]


def test_the_gate_reds_on_a_reason_that_says_nothing() -> None:
    rows = coverage_rows({"inbound": frozenset({"smoke"}), "outbound": frozenset()}, [])
    for reason in ("  ", "later", "covered by another suite one day"):
        assert coverage_gaps(rows, {("smoke", "inbound"): reason}) == [
            "inbound smoke: exemption gives no real reason"
        ], reason
    long_enough = "this kind needs a server the harness cannot stand up in a test"
    assert coverage_gaps(rows, {("smoke", "inbound"): long_enough}) == []


def test_the_cli_exits_1_on_a_gap(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = registered_kinds()
    monkeypatch.setattr(
        coverage,
        "registered_kinds",
        lambda: {**real, "inbound": real["inbound"] | {"kafka"}},
    )
    assert main(["--coverage"]) == 1
    assert "GAP: inbound kafka: no scenario and no exemption" in capsys.readouterr().out
