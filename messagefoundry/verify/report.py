# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Render verify results — console summary, Markdown, JSON. Dependency-free (stdlib only)."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence

from messagefoundry.terminal_text import escape_for_terminal
from messagefoundry.verify.model import FAILING, CheckResult, Status


def summarize(results: Sequence[CheckResult]) -> Counter[Status]:
    """Count results by status."""
    return Counter(r.status for r in results)


def exit_code(results: Sequence[CheckResult]) -> int:
    """0 unless a check FAILed or ERRORed (MANUAL/SKIP never fail the run)."""
    return 1 if any(r.status in FAILING for r in results) else 0


def _shown(text: str) -> str:
    # A detail can carry what a peer wrote: a JWKS key id, an ACK, an exception naming a peer's
    # reply. Escaped HERE, at the one console sink, and not in CheckResult, so the Markdown and JSON
    # reports keep the value as it was (they are data, not a terminal). Every field gets the same
    # rule, so a detail added later is covered without anyone deciding it is peer text. One line per
    # check, so a newline is escaped too, or a peer's text could start a line reading as a check that
    # passed; printable Unicode is kept, so the engine's own em dashes print as themselves.
    return escape_for_terminal(text, single_line=True, keep_printable_unicode=True)


def render_console(results: Sequence[CheckResult]) -> str:
    """A compact, aligned one-line-per-check summary for stdout, peer text escaped (ASVS 1.1.2)."""
    counts = summarize(results)
    lines = [
        f"{r.status.value:<6} {_shown(r.id):<14} {_shown(r.title)}"
        + (f"  [{_shown(r.detail)}]" if r.detail else "")
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
