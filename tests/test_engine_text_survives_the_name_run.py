# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Engine-authored message text never holds a run the PHI name heuristic scrubs.

The PHI redaction (``messagefoundry.redaction._NAME_RUN``) scrubs two to four adjacent ALL-CAPS tokens,
or two to four adjacent Title-case tokens, as a possible patient name. It cannot tell ``DOE JANE`` from
``SMTP AUTH``, or ``Jane Doe`` from ``Backend Services``, so engine text written that way shipped as
``refusing [redacted] over an unencrypted channel`` and ``SMART [redacted] and OAuth2``, and lost the
words an operator needed. Loosening the redaction to keep protocol words was tried and leaked
identifiers through multi-pass pipelines, so the fix is at the source: engine text is worded so the
heuristic never fires on it. This test holds the shapes :func:`_message_literals` names to that, for
both arms.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from messagefoundry import redaction
from tests._ast_sites import callee_name

_ENGINE = Path(__file__).resolve().parents[1] / "messagefoundry"
_LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical"})

#: Keyword arguments that carry a label a transport or guard later interpolates into a message.
_LABEL_KEYWORDS = frozenset(
    {"transport", "description", "cell", "connector", "detail", "label", "crossing"}
)

#: Calls whose label keywords are not messages. A pydantic ``Field`` description is schema text, and a
#: tray ``MenuItem`` label is a menu caption handed to ``AppendMenuW``; neither is ever logged.
_NOT_MESSAGES = frozenset({"Field", "MenuItem"})

#: The two arms of `_NAME_RUN`, read from the shipped pattern so this test cannot drift from it.
_TITLE_ARM, _CAPS_ARM = redaction._NAME_RUN.pattern.split("|", 1)
_ARMS = {"title": re.compile(_TITLE_ARM), "caps": re.compile(_CAPS_ARM)}


def _message_literals(tree: ast.AST) -> list[tuple[int, str]]:
    """Every string literal in a shape that reaches an operator as message text.

    At least these shapes: the message argument of a logging call (``logger.log`` included), the first
    argument of any call to an ``*Error`` / ``*Exception`` / ``*Refused`` class whether or not it is
    raised on the spot, anything inside a ``raise`` expression, and a label keyword
    (:data:`_LABEL_KEYWORDS`) a guard later interpolates, except on a call in :data:`_NOT_MESSAGES`.

    It is a lexical scan, so it CANNOT see text built anywhere else. At least these reach a log unseen:
    a helper's return value, a local variable assigned and then logged, a label appended to a list and
    joined later, and a module constant. Those were reworded by hand, and a new one can regress with
    this test green. :func:`test_the_tables_the_scan_cannot_see_survive_redaction` pins the ones found."""
    firsts: list[ast.expr] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = callee_name(node) or ""
            if name in _LOG_METHODS and node.args:
                firsts.append(node.args[0])
            elif name == "log" and len(node.args) >= 2:
                firsts.append(node.args[1])
            elif name.endswith(("Error", "Exception", "Refused")) and node.args:
                firsts.append(node.args[0])
            if name not in _NOT_MESSAGES:
                firsts.extend(k.value for k in node.keywords if k.arg in _LABEL_KEYWORDS)
        elif isinstance(node, ast.Raise) and node.exc is not None:
            firsts.append(node.exc)
    found: dict[tuple[int, int], tuple[int, str]] = {}
    for first in firsts:
        for sub in ast.walk(first):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                found[(sub.lineno, sub.col_offset)] = (sub.lineno, sub.value)
    return list(found.values())


def _runs(source: str, arm: str) -> list[tuple[int, str]]:
    return [
        (line, m.group(0))
        for line, text in _message_literals(ast.parse(source))
        for m in _ARMS[arm].finditer(text)
    ]


def test_the_scan_fires_on_every_shape_it_claims_caps_arm() -> None:
    # CONTROL: one planted run per covered shape, each reachable ONLY through its own arm, plus four
    # it must skip (prose, a module constant, a Field description, a MenuItem label).
    planted = "\n".join(
        [
            "logger.warning('refusing SMTP AUTH over %s', x)",  # a logging call
            "logger.log(logging.WARNING, 'MLLP NAK dropped')",  # logger.log
            "exc = RuntimeError('will not ALTER DATABASE')",  # *Error, not raised here
            "exc = OSException('CONTROL SERVER missing')",  # *Exception
            "exc = HopRefused('LDAP SIMPLE bind')",  # *Refused
            "raise build('FHIR HTTP 500')",  # the raise arm: build() matches no other arm
            "guard(transport='DICOM SCP source')",  # a label keyword
            "logger.info('verified TLS on SMTP')",
            "SQL = 'ALTER DATABASE x'",
            "Field(description='INGRESS ROUTED claim')",
            "MenuItem(label='STOP SERVICE')",
        ]
    )
    assert sorted(run for _, run in _runs(planted, "caps")) == [
        "ALTER DATABASE",
        "CONTROL SERVER",
        "DICOM SCP",
        "FHIR HTTP",
        "LDAP SIMPLE",
        "MLLP NAK",
        "SMTP AUTH",
    ]


def test_the_scan_fires_on_every_shape_it_claims_title_arm() -> None:
    # CONTROL: the same shapes planted with Title-case runs, plus the same four skips. A sentence start
    # counts ("Set Foo"), because the redaction cannot tell it from a name either.
    planted = "\n".join(
        [
            "logger.warning('refusing Backend Services over %s', x)",  # a logging call
            "logger.log(logging.WARNING, 'Always On dropped')",  # logger.log
            "exc = RuntimeError('will not reach Vault Transit')",  # *Error, not raised here
            "exc = OSException('Test Bench missing')",  # *Exception
            "exc = HopRefused('Set Foo first')",  # *Refused, a sentence start
            "raise build('Browser Forum rule')",  # the raise arm: build() matches no other arm
            "guard(transport='Authenticated Users group')",  # a label keyword
            "logger.info('verified the test bench')",
            "NAME = 'Jane Doe'",
            "Field(description='Read Field row')",
            "MenuItem(label='Stop Service')",
        ]
    )
    assert sorted(run for _, run in _runs(planted, "title")) == [
        "Always On",
        "Authenticated Users",
        "Backend Services",
        "Browser Forum",
        "Set Foo",
        "Test Bench",
        "Vault Transit",
    ]


def test_the_arms_are_the_shipped_ones() -> None:
    assert _ARMS["title"].pattern == r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b"
    assert _ARMS["caps"].pattern == r"\b[A-Z]{2,}(?:\s+[A-Z]{2,}){1,3}\b"


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
    hits = _runs(path.read_text(encoding="utf-8"), "caps")
    assert not hits, (
        f"{path.name}: {hits} -- the PHI redaction scrubs two adjacent ALL-CAPS words, so this "
        "text would reach the log with those words replaced by [redacted]. Reword it: lower-case "
        "the words that are not acronyms, or separate two acronyms, e.g. 'TLS on SMTP'."
    )


@pytest.mark.parametrize("path", _SOURCES, ids=lambda p: p.relative_to(_ENGINE).as_posix())
def test_engine_message_text_holds_no_title_case_run(path: Path) -> None:
    hits = _runs(path.read_text(encoding="utf-8"), "title")
    assert not hits, (
        f"{path.name}: {hits} -- the PHI redaction scrubs two adjacent Title-case words as a "
        "possible patient name, so this text would reach the log with those words replaced by "
        "[redacted]. Reword it: lower-case the words that are not proper nouns, or restructure so "
        "two capitalised words never sit side by side, e.g. 'SMART backend services'."
    )


def _out_of_scan_texts() -> list[tuple[str, str]]:
    """Text the lexical scan cannot see that a refusal, alert or log line renders verbatim."""
    from messagefoundry.auth import anchor_path
    from messagefoundry.pipeline import secret_rotation
    from messagefoundry.store import keyprovider_vault
    from messagefoundry.transports import http_auth, smart

    texts = [
        (f"describe_sid({sid})", anchor_path.describe_sid(sid))
        for sid in anchor_path._WELL_KNOWN_NAMES
    ]
    texts += [(f"secret class {n}", label) for n, label in secret_rotation._ENV_SECRET_CLASSES]
    texts.append(("vault transit connector", keyprovider_vault._VAULT_TRANSIT_CONNECTOR))
    texts.append(("SMART missing url", smart.SmartBackendTokenProvider._MISSING_URL))
    texts.append(("OAuth2 missing url", http_auth.OAuth2ClientCredentialsProvider._MISSING_URL))
    return texts


@pytest.mark.parametrize("where,text", _out_of_scan_texts())
def test_the_tables_the_scan_cannot_see_survive_redaction(where: str, text: str) -> None:
    assert redaction.redact(text) == text, f"{where}: {text!r} -> {redaction.redact(text)!r}"


def test_the_out_of_scan_probe_can_fail() -> None:
    # CONTROL: the probe above compares redact() to identity, so a name-shaped label must come back
    # changed. If redact() stopped scrubbing, every row above would pass for the wrong reason.
    assert redaction.redact("NT AUTHORITY\\Authenticated Users (S-1-5-11)") != (
        "NT AUTHORITY\\Authenticated Users (S-1-5-11)"
    )
