# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Connector coverage: which registered connector kinds, in which direction, a scenario exercises.

``python -m harness --coverage`` prints the join of two live sources and no hand-kept list: the
engine's connector registries (what kinds exist, and whether each is an inbound, an outbound or
both) and the scenario registry (what each scenario declares it covers). A scenario that claims a
pair the engine does not register is reported too, since a stale claim reads as coverage that is
not there.

THIS IS THE ONE HARNESS MODULE THAT IMPORTS ``messagefoundry.transports``, and it is named in
``tests/test_dependency_boundaries.py``'s ``_CLIENT_ALLOWED`` for exactly that. The import is
read-only -- it builds no connector and opens no socket -- and it takes only the public
``registered_kinds`` accessor, never the private tables behind it (the import shape is pinned in
``tests/test_harness_scenarios.py``). Nothing else in the harness may reach ``transports/``; a new
need goes through the same allow-list review.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from harness.scenarios import DIRECTIONS, INBOUND, OUTBOUND, BaseScenario, Coverage


@dataclass(frozen=True)
class CoverageRow:
    kind: str
    direction: str
    scenarios: tuple[str, ...]
    registered: bool = True

    @property
    def covered(self) -> bool:
        return bool(self.scenarios)


def registered_kinds() -> dict[str, frozenset[str]]:
    """The engine's live connector registries: direction to the set of connector kind values.

    Imported from the package, not from ``transports.base``: the package import is what registers
    every built-in connector, and the accessor's docstring says why the spelling matters."""
    from messagefoundry.transports import registered_kinds as engine_registered_kinds

    live = engine_registered_kinds()
    return {
        INBOUND: frozenset(kind.value for kind in live.sources),
        OUTBOUND: frozenset(kind.value for kind in live.destinations),
    }


def coverage_rows(
    registered: Mapping[str, frozenset[str]], scenarios: Iterable[BaseScenario]
) -> list[CoverageRow]:
    """One row per registered (kind, direction), plus one per claimed pair that is not registered."""
    claims: dict[Coverage, list[str]] = {}
    for scenario in scenarios:
        for pair in scenario.covers:
            claims.setdefault(pair, []).append(scenario.name)
    rows: list[CoverageRow] = []
    for direction in DIRECTIONS:
        for kind in sorted(registered.get(direction, frozenset())):
            names = tuple(sorted(claims.pop((kind, direction), [])))
            rows.append(CoverageRow(kind, direction, names))
    for (kind, direction), claimed in sorted(claims.items()):
        rows.append(CoverageRow(kind, direction, tuple(sorted(claimed)), registered=False))
    return rows


def format_report(rows: list[CoverageRow]) -> str:
    """The plain-text report ``--coverage`` prints. One line per row, ``direction kind: ...``."""
    live = [r for r in rows if r.registered]
    lines = ["connector coverage (live registries; scenarios from harness/scenarios/)"]
    for row in rows:
        if not row.registered:
            status = "NOT REGISTERED, claimed by " + ", ".join(row.scenarios)
        elif row.covered:
            status = ", ".join(row.scenarios)
        else:
            status = "NONE"
        lines.append(f"  {row.direction:<8} {row.kind:<11} {status}")
    covered = sum(r.covered for r in live)
    lines.append(f"{covered} of {len(live)} registered (kind, direction) pairs have a scenario")
    return "\n".join(lines)
