# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Connector coverage: which registered connector kinds, in which direction, a scenario exercises.

``python -m harness --coverage`` prints the join of two live sources: the engine's connector
registries (what kinds exist, and whether each is an inbound, an outbound or both) and the scenario
registry (what each scenario declares it covers). The one list kept by hand is :data:`EXEMPT`, the
pairs with no scenario and why, and the gate refuses an entry there that has gone stale. A scenario that claims a
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
from types import MappingProxyType

from harness.scenarios import DIRECTIONS, INBOUND, OUTBOUND, BaseScenario, Coverage

#: The registered (kind, direction) pairs that have NO registered scenario, each with the reason.
#: Written once, when the per-family rows had all landed (vault BACKLOG #2681). The gate
#: (:func:`coverage_gaps`, run by ``tests/test_harness_coverage_gate.py``) fails on a registered pair
#: with neither a scenario nor an entry here, and equally on an entry that has gone stale -- its pair
#: gained a scenario or is no longer registered -- so the list cannot quietly outlive its reason.
EXEMPT: Mapping[Coverage, str] = MappingProxyType(
    {
        (
            "direct",
            OUTBOUND,
        ): "the Direct outbound needs per-partner S/MIME keys and certificates on disk to build, "
        "so its graph cannot sit in the shared harness/config; tests/test_harness_email.py serves "
        "harness/config/direct/ with test-minted PKI and proves the STARTTLS + sign-then-encrypt "
        "round trip there, but no registered scenario runs it",
    }
)


#: The fewest words an exemption's reason may have. A word count is a crude test, but it refuses
#: the empty and the token ("n/a", "later") reasons, which are what an exemption list decays into.
MIN_REASON_WORDS = 8


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


def coverage_gaps(rows: list[CoverageRow], exempt: Mapping[Coverage, str] = EXEMPT) -> list[str]:
    """Everything the coverage gate refuses, one line each; empty when the gate passes.

    - a registered pair with neither a scenario nor an exemption;
    - an exemption whose pair now HAS a scenario, or is not registered at all (stale);
    - a scenario claiming a pair the engine does not register;
    - an exemption whose reason is shorter than :data:`MIN_REASON_WORDS` words."""
    gaps: list[str] = []
    registered = {(r.kind, r.direction) for r in rows if r.registered}
    for row in rows:
        pair = (row.kind, row.direction)
        if not row.registered:
            gaps.append(
                f"{row.direction} {row.kind}: claimed by {', '.join(row.scenarios)} "
                "but not registered"
            )
        elif not row.covered and pair not in exempt:
            gaps.append(f"{row.direction} {row.kind}: no scenario and no exemption")
        elif row.covered and pair in exempt:
            gaps.append(
                f"{row.direction} {row.kind}: exempt, but covered by {', '.join(row.scenarios)}"
            )
    for (kind, direction), reason in sorted(exempt.items()):
        if (kind, direction) not in registered:
            gaps.append(f"{direction} {kind}: exempt, but not a registered (kind, direction)")
        if len(reason.split()) < MIN_REASON_WORDS:
            gaps.append(f"{direction} {kind}: exemption gives no real reason")
    return gaps


def format_report(rows: list[CoverageRow], exempt: Mapping[Coverage, str] = EXEMPT) -> str:
    """The plain-text report ``--coverage`` prints. One line per row, ``direction kind: ...``."""
    live = [r for r in rows if r.registered]
    lines = ["connector coverage (live registries; scenarios from harness/scenarios/)"]
    for row in rows:
        if not row.registered:
            status = "NOT REGISTERED, claimed by " + ", ".join(row.scenarios)
        elif row.covered:
            status = ", ".join(row.scenarios)
        elif (row.kind, row.direction) in exempt:
            status = "EXEMPT: " + exempt[(row.kind, row.direction)]
        else:
            status = "NONE"
        lines.append(f"  {row.direction:<8} {row.kind:<11} {status}")
    covered = sum(r.covered for r in live)
    exempted = sum(not r.covered and (r.kind, r.direction) in exempt for r in live)
    lines.append(
        f"{covered} of {len(live)} registered (kind, direction) pairs have a scenario; "
        f"{exempted} exempt with a reason"
    )
    gaps = coverage_gaps(rows, exempt)
    lines.extend(f"GAP: {gap}" for gap in gaps)
    return "\n".join(lines)
