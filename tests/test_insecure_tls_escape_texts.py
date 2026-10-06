# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every runtime text that names the insecure-TLS escape also names the posture it needs (vault
BACKLOG #2637).

``MEFOR_ALLOW_INSECURE_TLS`` is honoured only on an instance at ``[security].enforcement = warn``
(:func:`~messagefoundry.config.settings.weakened_tls_escape_permitted`). Under ``enforce``, the
default, and with no posture it changes nothing. A refusal that told an operator to set it without
saying so sent them to set a variable that does nothing on a default instance.

**Scope.** A "runtime text" here is the string arguments of one call -- a ``raise X(...)`` or a
``logger.warning(...)`` -- that either spells the variable in a literal, interpolates
``INSECURE_TLS_ESCAPE_ENV`` into an f-string, or passes it to a logging call as a ``%s``
argument. Docstrings and comments are not calls and are not checked. Neither is a text built
outside a call's arguments, such as a tuple handed to ``list.append``; at least the
``[security].enforcement`` loosening row in ``config/settings.py`` is built that way, and it
names the posture in its own words.

**The positive controls are planted and pinned.** The scanner is proved on two planted sources,
one that must be flagged and one that must pass. The tree walk is proved by pinning the files it
must find, so a scanner that silently matches nothing cannot pass by finding nothing to judge."""

from __future__ import annotations

import ast
from pathlib import Path

from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV

_PACKAGE = Path(__file__).resolve().parent.parent / "messagefoundry"
_NAME = "INSECURE_TLS_ESCAPE_ENV"
_POSTURE = "[security].enforcement = warn"
_LOG_METHODS = frozenset({"debug", "info", "warning", "error", "critical", "exception"})

#: Files that must each hold at least one checked text. Pinned so a scanner that matches nothing
#: fails here instead of passing vacuously.
_MUST_FIND = frozenset(
    {
        "auth/ldap.py",
        "pipeline/alert_sinks.py",
        "store/postgres.py",
        "store/sqlserver.py",
        "transports/ai_broker.py",
        "transports/database.py",
        "transports/direct.py",
        "transports/email.py",
        "transports/mllp.py",
        "transports/remotefile.py",
    }
)


def _names_the_escape_name(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == _NAME


def _text_of(node: ast.AST) -> tuple[str, bool] | None:
    """The literal text of a string argument, and whether it names the escape; else ``None``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, INSECURE_TLS_ESCAPE_ENV in node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        names = False
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue) and _names_the_escape_name(value.value):
                parts.append(INSECURE_TLS_ESCAPE_ENV)
                names = True
            else:
                parts.append("{}")
        text = "".join(parts)
        return text, names or INSECURE_TLS_ESCAPE_ENV in text
    return None


def _is_log_call(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Attribute) and call.func.attr in _LOG_METHODS


def escape_texts_without_posture(source: str) -> tuple[list[int], int]:
    """Line numbers of calls whose text names the escape but not the posture, and how many calls
    named the escape at all."""
    unposted: list[int] = []
    seen = 0
    for call in ast.walk(ast.parse(source)):
        if not isinstance(call, ast.Call):
            continue
        texts: list[str] = []
        names = False
        for arg in call.args:
            found = _text_of(arg)
            if found is not None:
                texts.append(found[0])
                names = names or found[1]
            elif _names_the_escape_name(arg) and _is_log_call(call):
                names = True
        if not names or not texts:
            continue
        seen += 1
        if _POSTURE not in "".join(texts):
            unposted.append(call.lineno)
    return unposted, seen


def test_the_scanner_flags_a_text_that_omits_the_posture() -> None:
    planted = (
        "def f():\n"
        "    raise ValueError(\n"
        '        f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set (dev only)"\n'
        "    )\n"
        "    log.warning('allowed because %s is set', INSECURE_TLS_ESCAPE_ENV)\n"
        "    raise ValueError('set MEFOR_ALLOW_INSECURE_TLS=1 to allow it')\n"
    )
    unposted, seen = escape_texts_without_posture(planted)
    assert seen == 3
    assert unposted == [2, 5, 6]


def test_the_scanner_passes_a_text_that_names_the_posture() -> None:
    planted = (
        "def f():\n"
        "    raise ValueError(\n"
        '        f"refused unless {INSECURE_TLS_ESCAPE_ENV} is set on an instance at "\n'
        '        "[security].enforcement = warn"\n'
        "    )\n"
        "    log.warning(\n"
        "        'allowed because %s is set at [security].enforcement = warn',\n"
        "        INSECURE_TLS_ESCAPE_ENV,\n"
        "    )\n"
        "    os.environ.get(INSECURE_TLS_ESCAPE_ENV, '')\n"
    )
    unposted, seen = escape_texts_without_posture(planted)
    assert seen == 2
    assert unposted == []


def test_every_runtime_text_naming_the_escape_names_the_posture() -> None:
    failures: list[str] = []
    found: set[str] = set()
    for path in sorted(_PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if _NAME not in source and INSECURE_TLS_ESCAPE_ENV not in source:
            continue
        rel = path.relative_to(_PACKAGE).as_posix()
        unposted, seen = escape_texts_without_posture(source)
        if seen:
            found.add(rel)
        failures.extend(f"{rel}:{line}" for line in unposted)
    missing = _MUST_FIND - found
    assert not missing, f"the scan found no escape text in {sorted(missing)}"
    assert not failures, (
        f"these texts name {INSECURE_TLS_ESCAPE_ENV} without saying it works only at "
        f"{_POSTURE!r}: {failures}"
    )
