# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Render verify results — console summary, Markdown, JSON. Dependency-free (stdlib only)."""

from __future__ import annotations

import json
from collections import Counter
from typing import Sequence

from messagefoundry.verify.model import FAILING, CheckResult, Status


def summarize(results: Sequence[CheckResult]) -> Counter[Status]:
    """Count results by status."""
    return Counter(r.status for r in results)


def exit_code(results: Sequence[CheckResult]) -> int:
    """0 unless a check FAILed or ERRORed (MANUAL/SKIP never fail the run)."""
    return 1 if any(r.status in FAILING for r in results) else 0


def render_console(results: Sequence[CheckResult]) -> str:
    """A compact, aligned one-line-per-check summary for stdout."""
    counts = summarize(results)
    lines = [
        f"{r.status.value:<6} {r.id:<14} {r.title}" + (f"  [{r.detail}]" if r.detail else "")
        for r in results
    ]
    tally = "  ".join(f"{s.value}={counts.get(s, 0)}" for s in Status)
    lines += ["", f"  {tally}   (exit {exit_code(results)})"]
    return "\n".join(lines)


def render_markdown(results: Sequence[CheckResult]) -> str:
    """A Markdown table report."""
    counts = summarize(results)
    out = [
        "# MessageFoundry — deployment verify",
        "",
        "Tally: "
        + " · ".join(f"**{s.value}** {counts.get(s, 0)}" for s in Status)
        + f" · exit `{exit_code(results)}`",
        "",
        "| Check | Title | Status | Detail |",
        "|---|---|---|---|",
    ]
    for r in results:
        detail = (r.detail or "").replace("|", "\\|")
        title = r.title.replace("|", "\\|")
        out.append(f"| {r.id} | {title} | {r.status.value} | {detail} |")
    return "\n".join(out) + "\n"


def render_json(results: Sequence[CheckResult]) -> str:
    """A JSON document: per-check results + tally + exit code."""
    counts = summarize(results)
    payload = {
        "results": [
            {
                "id": r.id,
                "title": r.title,
                "status": r.status.value,
                "detail": r.detail,
                "evidence": r.evidence,
            }
            for r in results
        ],
        "tally": {s.value: counts.get(s, 0) for s in Status},
        "exit_code": exit_code(results),
    }
    return json.dumps(payload, indent=2)
