# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Engine-authored log and error text never holds two adjacent ALL-CAPS words.

The PHI redaction (``messagefoundry.redaction._NAME_RUN``) scrubs two to four adjacent ALL-CAPS tokens
as a possible patient name. It cannot tell ``DOE JANE`` from ``SMTP AUTH``, so engine text written that
way shipped as ``refusing [redacted] over an unencrypted channel`` and lost the words an operator
needed. Loosening the redaction to keep protocol words was tried and leaked identifiers through
multi-pass pipelines, so the fix is at the source: engine text is worded so the heuristic never fires
on it. This test holds every logging call and raise constructor to that, so a new message cannot
regress it.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from messagefoundry import redaction

_ENGINE = Path(__file__).resolve().parents[1] / "messagefoundry"
_LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical"})

#: The ALL-CAPS arm of `_NAME_RUN`, read from the shipped pattern so this test cannot drift from it.
_CAPS_RUN = re.compile(redaction._NAME_RUN.pattern.split("|", 1)[1])


def _message_literals(tree: ast.AST) -> list[tuple[int, str]]:
    """Every string literal inside the first argument of a logging call or a raised exception."""
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        first: ast.expr | None = None
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in _LOG_METHODS and node.args:
                first = node.args[0]
        elif isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and node.exc.args:
            first = node.exc.args[0]
        if first is None:
            continue
        out.extend(
            (node.lineno, sub.value)
            for sub in ast.walk(first)
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str)
        )
    return out


def _caps_runs(source: str) -> list[tuple[int, str]]:
    return [
        (line, m.group(0))
        for line, text in _message_literals(ast.parse(source))
        for m in _CAPS_RUN.finditer(text)
    ]


def test_the_scan_fires_on_a_planted_message() -> None:
    # CONTROL: the detector finds the shape it guards against, in both call forms, and skips prose.
    planted = (
        "logger.warning('refusing SMTP AUTH over %s', x)\n"
        "raise ValueError(f'TLS DISABLED for {host}')\n"
        "logger.info('verified TLS on SMTP')\n"
    )
    assert sorted(run for _, run in _caps_runs(planted)) == ["SMTP AUTH", "TLS DISABLED"]


def test_the_caps_arm_is_the_shipped_one() -> None:
    assert _CAPS_RUN.pattern == r"\b[A-Z]{2,}(?:\s+[A-Z]{2,}){1,3}\b"


@pytest.mark.parametrize(
    "path", sorted(_ENGINE.rglob("*.py")), ids=lambda p: p.relative_to(_ENGINE).as_posix()
)
def test_engine_message_text_holds_no_all_caps_run(path: Path) -> None:
    hits = _caps_runs(path.read_text(encoding="utf-8"))
    assert not hits, (
        f"{path.name}: {hits} -- the PHI redaction scrubs two adjacent ALL-CAPS words, so this "
        "message would reach the log with those words replaced by [redacted]. Reword it: lower-case "
        "the words that are not acronyms, or separate two acronyms, e.g. 'TLS on SMTP'."
    )
