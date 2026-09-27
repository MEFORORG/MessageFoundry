# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Engine-authored message text never holds two adjacent ALL-CAPS words.

The PHI redaction (``messagefoundry.redaction._NAME_RUN``) scrubs two to four adjacent ALL-CAPS tokens
as a possible patient name. It cannot tell ``DOE JANE`` from ``SMTP AUTH``, so engine text written that
way shipped as ``refusing [redacted] over an unencrypted channel`` and lost the words an operator
needed. Loosening the redaction to keep protocol words was tried and leaked identifiers through
multi-pass pipelines, so the fix is at the source: engine text is worded so the heuristic never fires
on it. This test holds the shapes :func:`_message_literals` names to that.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from messagefoundry import redaction

_ENGINE = Path(__file__).resolve().parents[1] / "messagefoundry"
_LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical"})

#: Keyword arguments that carry a label a transport or guard later interpolates into a message.
_LABEL_KEYWORDS = frozenset(
    {"transport", "description", "cell", "connector", "detail", "label", "crossing"}
)

#: The ALL-CAPS arm of `_NAME_RUN`, read from the shipped pattern so this test cannot drift from it.
_CAPS_RUN = re.compile(redaction._NAME_RUN.pattern.split("|", 1)[1])


def _call_name(node: ast.Call) -> str:
    func = node.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


def _message_literals(tree: ast.AST) -> list[tuple[int, str]]:
    """Every string literal in a shape that reaches an operator as message text.

    At least these shapes: the message argument of a logging call (``logger.log`` included), the first
    argument of any call to an ``*Error`` / ``*Exception`` / ``*Refused`` class whether or not it is
    raised on the spot, anything inside a ``raise`` expression, and a label keyword
    (:data:`_LABEL_KEYWORDS`) a guard later interpolates. NOT covered, and named so nobody reads this as
    complete: text returned by a helper, text held in a module constant (mostly SQL here), and the
    Title-case arm of ``_NAME_RUN`` (``Backend Services``), which this test does not check."""
    firsts: list[ast.expr] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in _LOG_METHODS and node.args:
                firsts.append(node.args[0])
            elif name == "log" and len(node.args) >= 2:
                firsts.append(node.args[1])
            elif name.endswith(("Error", "Exception", "Refused")) and node.args:
                firsts.append(node.args[0])
            if name != "Field":  # a pydantic Field's description is schema text, not a message
                firsts.extend(k.value for k in node.keywords if k.arg in _LABEL_KEYWORDS)
        elif isinstance(node, ast.Raise) and node.exc is not None:
            firsts.append(node.exc)
    found: dict[tuple[int, int], tuple[int, str]] = {}
    for first in firsts:
        for sub in ast.walk(first):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                found[(sub.lineno, sub.col_offset)] = (sub.lineno, sub.value)
    return list(found.values())


def _caps_runs(source: str) -> list[tuple[int, str]]:
    return [
        (line, m.group(0))
        for line, text in _message_literals(ast.parse(source))
        for m in _CAPS_RUN.finditer(text)
    ]


def test_the_scan_fires_on_every_shape_it_claims() -> None:
    # CONTROL: one planted run per covered shape, plus two it must skip (prose, a module constant).
    planted = "\n".join(
        [
            "logger.warning('refusing SMTP AUTH over %s', x)",
            "raise ValueError(f'TLS DISABLED for {host}')",
            "exc = RuntimeError('will not ALTER DATABASE')",
            "raise (classify(x) or DeliveryError('FHIR HTTP 500'))",
            "logger.log(logging.WARNING, 'MLLP NAK dropped')",
            "guard(transport='DICOM SCP source')",
            "logger.info('verified TLS on SMTP')",
            "SQL = 'ALTER DATABASE x'",
        ]
    )
    assert sorted(run for _, run in _caps_runs(planted)) == [
        "ALTER DATABASE",
        "DICOM SCP",
        "FHIR HTTP",
        "MLLP NAK",
        "SMTP AUTH",
        "TLS DISABLED",
    ]


def test_the_caps_arm_is_the_shipped_one() -> None:
    assert _CAPS_RUN.pattern == r"\b[A-Z]{2,}(?:\s+[A-Z]{2,}){1,3}\b"


_SOURCES = sorted(_ENGINE.rglob("*.py"))


def test_the_scan_has_a_population() -> None:
    # A moved `_ENGINE` path would parametrize nothing and pass. A floor well under the real counts
    # still catches an empty or wrong root.
    assert len(_SOURCES) > 200
    literals = sum(
        len(_message_literals(ast.parse(p.read_text(encoding="utf-8")))) for p in _SOURCES
    )
    assert literals > 2000


@pytest.mark.parametrize("path", _SOURCES, ids=lambda p: p.relative_to(_ENGINE).as_posix())
def test_engine_message_text_holds_no_all_caps_run(path: Path) -> None:
    hits = _caps_runs(path.read_text(encoding="utf-8"))
    assert not hits, (
        f"{path.name}: {hits} -- the PHI redaction scrubs two adjacent ALL-CAPS words, so this "
        "text would reach the log with those words replaced by [redacted]. Reword it: lower-case "
        "the words that are not acronyms, or separate two acronyms, e.g. 'TLS on SMTP'."
    )
