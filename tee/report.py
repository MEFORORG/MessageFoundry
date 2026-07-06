# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Parity report for ``tee compare`` (#14) — composes correlate + compare into a PHI-safe summary.

:func:`build_report` correlates MEFOR outputs to Corepoint outputs (:mod:`tee.correlate`) and diffs each
matched pair (:mod:`tee.compare`), tallying counts. The **summary is PHI-safe** — counts only, no bodies
or patient ids. The optional per-pair ``diffs`` carry field values (PHI) and are included **only** when
``include_diffs=True``: the test-data-only guardrail (never commit them or send them to CI, same as
``--capture-bodies``/dryrun). Pure: no I/O, no ``messagefoundry`` import.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from tee.compare import CompareConfig, compare
from tee.correlate import CorepointOutput, CorrelateConfig, MeforOutput, correlate


def build_report(
    mefor_outputs: list[MeforOutput],
    corepoint_outputs: list[CorepointOutput],
    *,
    correlate_config: CorrelateConfig | None = None,
    compare_config: CompareConfig | None = None,
    include_diffs: bool = False,
) -> dict[str, Any]:
    """Correlate + diff. Returns ``{"summary": {...}}`` (PHI-safe counts) plus, when ``include_diffs``,
    a ``"diffs"`` list of per-pair field differences (PHI — test-data-only)."""
    pairs = correlate(mefor_outputs, corepoint_outputs, correlate_config)
    kinds: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    missing_on_corepoint = 0
    missing_on_mefor = 0
    diffs: list[dict[str, Any]] = []

    for pair in pairs:
        if pair.mefor is not None and pair.corepoint is not None:
            result = compare(pair.mefor.payload, pair.corepoint.raw, compare_config)
            kinds[result.kind] += 1
            methods[pair.method] += 1
            if include_diffs and result.diffs:
                diffs.append(
                    {
                        "control_id": pair.source_control_id,
                        "destination": list(pair.destination) if pair.destination else None,
                        "method": pair.method,
                        "kind": result.kind,
                        "field_diffs": [
                            {
                                "location": d.location,
                                "left": d.left,
                                "right": d.right,
                                "ignored": d.ignored,
                            }
                            for d in result.diffs
                        ],
                    }
                )
        elif pair.mefor is not None:
            missing_on_corepoint += 1
        else:
            missing_on_mefor += 1

    summary: dict[str, Any] = {
        "mefor_outputs": len(mefor_outputs),
        "corepoint_outputs": len(corepoint_outputs),
        "matched": kinds["exact"] + kinds["semantic"] + kinds["mismatch"],
        "exact": kinds["exact"],
        "semantic": kinds["semantic"],
        "mismatch": kinds["mismatch"],
        "missing_on_corepoint": missing_on_corepoint,  # MEFOR produced it, Corepoint did not
        "missing_on_mefor": missing_on_mefor,  # Corepoint produced it, MEFOR did not
        "match_methods": dict(methods),
    }
    report: dict[str, Any] = {"summary": summary}
    if include_diffs:
        report["diffs"] = diffs
    return report
