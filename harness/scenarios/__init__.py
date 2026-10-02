# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Headless scenarios: send traffic through a driver, then assert the engine's disposition (or
dead-lettering) over the API and, where a scenario names a sink, what an outbound delivered.

Scenarios live one family per module in this package (``mllp.py``, ``file.py``, ...), each
exporting a ``SCENARIOS`` tuple. They are discovered, so a new family is a new file, and a name
claimed twice is an error. The built-in scenarios target the ``harness/config`` graphs; serve them,
then ``python -m harness --scenario <name>``. Shared machinery is in :mod:`harness.scenarios._core`.

This package deliberately imports no PySide6, so it runs on a headless runner.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import cache
from types import MappingProxyType

from harness._discover import family_modules
from harness.scenarios._core import (
    DIRECTIONS,
    INBOUND,
    OUTBOUND,
    BaseScenario,
    Coverage,
    Scenario,
    ScenarioContext,
    ScenarioResult,
    _verify_dead_letter,
    _verify_disposition,
    control_id_of,
    run_scenario,
)

__all__ = [
    "DIRECTIONS",
    "INBOUND",
    "OUTBOUND",
    "SCENARIOS",
    "BaseScenario",
    "Coverage",
    "Scenario",
    "ScenarioContext",
    "ScenarioResult",
    "_verify_dead_letter",
    "_verify_disposition",
    "control_id_of",
    "registry",
    "run_scenario",
]


@cache
def registry() -> Mapping[str, BaseScenario]:
    """Every scenario by name, in family-module order then declaration order."""
    found: dict[str, BaseScenario] = {}
    for module in family_modules(__name__):
        for scenario in getattr(module, "SCENARIOS", ()):
            if scenario.name in found:
                raise ValueError(
                    f"scenario name {scenario.name!r} is declared twice "
                    f"(again in {module.__name__})"
                )
            found[scenario.name] = scenario
    return MappingProxyType(found)


SCENARIOS: Mapping[str, BaseScenario] = registry()
